use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use wiretap_core::{
    CaptureSource, EventId, EventMetadata, Flow, FlowId, FlowTiming, HttpHeader, HttpRequest,
    HttpResponse, HttpVersion, Inspection, NetworkEvent, Protocol, Session, SessionId, Timestamp,
    Uuid,
};
use wiretap_protocol::{Head, Parse, parse_head};

use crate::http::{Asset, Auth, Reject, Route, route};
use crate::message::{Message, Stats};
use crate::server::{Config, Running, start};

// ---------------------------------------------------------------------------------------------
// Router

fn head(raw: &str) -> Head {
    match parse_head(raw.as_bytes()) {
        Parse::Complete(h) => h,
        other => panic!("{other:?}"),
    }
}

const AUTH: Auth<'static> = Auth {
    host: "127.0.0.1:5000",
    token: "secret",
    feed_key: Some("feedkey"),
};

fn req(line: &str, headers: &str) -> Result<Route, Reject> {
    route(
        &head(&format!(
            "{line} HTTP/1.1\r\nHost: 127.0.0.1:5000\r\n{headers}\r\n"
        )),
        &AUTH,
    )
}

#[test]
fn router_enforces_token_cookie_host_and_origin() {
    let cookie = "Cookie: other=1; wiretap=secret\r\n";
    let origin = "Origin: http://127.0.0.1:5000\r\n";
    assert_eq!(req("GET /?t=secret", ""), Ok(Route::Login));
    assert_eq!(req("GET /?t=wrong", ""), Err(Reject::Forbidden));
    assert_eq!(req("GET /", ""), Err(Reject::Forbidden), "no cookie");
    assert_eq!(
        req("GET /", "Cookie: wiretap=secreT\r\n"),
        Err(Reject::Forbidden)
    );
    assert_eq!(req("GET /", cookie), Ok(Route::Asset(Asset::Index)));
    assert_eq!(req("GET /app.js", cookie), Ok(Route::Asset(Asset::Script)));
    assert_eq!(req("GET /api/sessions", cookie), Ok(Route::Sessions));
    assert_eq!(
        req("POST /api/rules", cookie),
        Err(Reject::Forbidden),
        "POST without Origin"
    );
    assert_eq!(
        req(
            "POST /api/rules",
            &format!("{cookie}Origin: http://evil.example\r\n")
        ),
        Err(Reject::Forbidden)
    );
    assert_eq!(
        req("POST /api/rules", &format!("{cookie}{origin}")),
        Ok(Route::SaveRules)
    );
    assert_eq!(req("PUT /api/rules", cookie), Err(Reject::MethodNotAllowed));
    assert_eq!(req("GET /nope", cookie), Err(Reject::NotFound));
    assert_eq!(
        req("GET /api/sessions/not-a-uuid/flows", cookie),
        Err(Reject::NotFound)
    );
    let id = Uuid::now_v7();
    assert_eq!(
        req(
            &format!("GET /api/sessions/{id}/flows?after=12_{id}"),
            cookie
        ),
        Ok(Route::Flows(SessionId(id), Some((Timestamp(12), id))))
    );
    assert_eq!(
        req(&format!("GET /api/sessions/{id}/events?after=bad"), cookie),
        Err(Reject::BadRequest)
    );
    // DNS rebinding: any other Host is refused, even with a valid cookie.
    let rebinding = head(&format!(
        "GET /api/sessions HTTP/1.1\r\nHost: attacker.example:5000\r\n{cookie}\r\n"
    ));
    assert_eq!(route(&rebinding, &AUTH), Err(Reject::Forbidden));
    let twice = head(&format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nHost: 127.0.0.1:5000\r\n{cookie}\r\n"
    ));
    assert_eq!(route(&twice, &AUTH), Err(Reject::BadRequest));
}

#[test]
fn router_feed_needs_its_own_key() {
    assert_eq!(
        req("POST /internal/feed", "Authorization: Bearer feedkey\r\n"),
        Ok(Route::Feed)
    );
    assert_eq!(
        req("POST /internal/feed", "Authorization: Bearer secret\r\n"),
        Err(Reject::Forbidden)
    );
    assert_eq!(
        req("GET /internal/feed", "Authorization: Bearer feedkey\r\n"),
        Err(Reject::Forbidden)
    );
    let none = Auth {
        feed_key: None,
        ..AUTH
    };
    let h = head(
        "POST /internal/feed HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nAuthorization: Bearer feedkey\r\n\r\n",
    );
    assert_eq!(
        route(&h, &none),
        Err(Reject::Forbidden),
        "no capture is starting"
    );
}

// ---------------------------------------------------------------------------------------------
// Server

struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Client {
    addr: String,
    cookie: String,
}

struct Reply {
    status: u16,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

fn exchange(addr: &str, raw: &str) -> Reply {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let Parse::Complete(h) = parse_head(&out) else {
        panic!("bad response: {}", String::from_utf8_lossy(&out))
    };
    let wiretap_protocol::StartLine::Response { status, .. } = h.start else {
        panic!()
    };
    Reply {
        status,
        headers: h.headers.clone(),
        body: out[h.len..].to_vec(),
    }
}

impl Client {
    fn get(&self, path: &str) -> Reply {
        exchange(
            &self.addr,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: {}\r\nCookie: wiretap={}\r\n\r\n",
                self.addr, self.cookie
            ),
        )
    }
    fn post(&self, path: &str, body: &str) -> Reply {
        exchange(
            &self.addr,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: {0}\r\nCookie: wiretap={1}\r\nOrigin: http://{0}\r\nContent-Type: application/json\r\nContent-Length: {2}\r\n\r\n{body}",
                self.addr,
                self.cookie,
                body.len()
            ),
        )
    }
}

fn server() -> (Temp, Running, Client, Session) {
    let dir = Temp(std::env::temp_dir().join(format!("wiretap-ui-test-{}", Uuid::now_v7())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let db = dir.0.join("ui.db");
    let session = Session::new("seeded");
    {
        let mut store = wiretap_storage::Store::open(&db, wiretap_storage::DEFAULT_QUOTA).unwrap();
        store.insert_session(&session).unwrap();
        let body = store
            .insert_payload(
                session.id,
                b"{\"user\":\"ada\"}",
                14,
                wiretap_core::PayloadEncryption::Cleartext,
            )
            .unwrap();
        store
            .upsert_flows(&[seeded_flow(session.id, Some(body))])
            .unwrap();
    }
    let running = start(Config {
        db,
        exe: PathBuf::from("wiretap.exe"),
        open_window: false,
    })
    .unwrap();
    let url = running.url();
    let addr = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    // Log in like the browser does.
    let login = exchange(
        &addr,
        &format!(
            "GET /{} HTTP/1.1\r\nHost: {addr}\r\n\r\n",
            url.split('/').nth(3).unwrap()
        ),
    );
    assert_eq!(login.status, 303);
    let cookie = login.header("set-cookie").unwrap().to_owned();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    let token = cookie
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("wiretap=")
        .to_owned();
    (
        dir,
        running,
        Client {
            addr,
            cookie: token,
        },
        session,
    )
}

fn seeded_flow(session: SessionId, body: Option<wiretap_core::PayloadReference>) -> Flow {
    Flow {
        id: FlowId::generate(),
        session_id: session,
        source: CaptureSource::ExplicitProxy,
        process: None,
        client: None,
        server: None,
        request: Some(HttpRequest {
            method: "GET".into(),
            url: "http://api.example.com/me".into(),
            version: HttpVersion::Http11,
            headers: vec![],
            body: None,
        }),
        response: Some(HttpResponse {
            status: 200,
            reason: "OK".into(),
            version: HttpVersion::Http11,
            headers: vec![HttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            }],
            body,
        }),
        timing: FlowTiming {
            started: Timestamp(1),
            request_complete: None,
            response_started: None,
            response_complete: None,
        },
        tags: vec![],
    }
}

#[test]
fn serves_assets_and_api_with_security_headers() {
    let (_dir, running, client, session) = server();
    let index = client.get("/");
    assert_eq!(index.status, 200);
    assert!(String::from_utf8_lossy(&index.body).contains("<title>Wiretap</title>"));
    let csp = index.header("content-security-policy").unwrap();
    assert!(
        csp.contains("script-src 'self'")
            && csp.contains("frame-ancestors 'none'")
            && !csp.contains("unsafe"),
        "{csp}"
    );
    assert_eq!(index.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(
        client.get("/app.js").header("content-type"),
        Some("text/javascript; charset=utf-8")
    );

    let unauthenticated = exchange(
        &client.addr,
        &format!(
            "GET /api/sessions HTTP/1.1\r\nHost: {}\r\n\r\n",
            client.addr
        ),
    );
    assert_eq!(unauthenticated.status, 403);
    let sessions = client.get("/api/sessions").json();
    assert_eq!(sessions[0]["id"], session.id.to_string());
    let flows = client
        .get(&format!("/api/sessions/{}/flows", session.id))
        .json();
    assert_eq!(flows["items"].as_array().unwrap().len(), 1);
    let body_id = flows["items"][0]["response"]["body"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        client.get(&format!("/api/payloads/{body_id}")).body,
        b"{\"user\":\"ada\"}"
    );
    // Content codings are undone on request; a body that does not decode comes back as stored,
    // with the reason.
    let identity = client.get(&format!("/api/payloads/{body_id}?coding=identity"));
    assert_eq!(identity.body, b"{\"user\":\"ada\"}");
    assert_eq!(identity.header("x-wiretap-decoded"), Some("full"));
    let not_gzip = client.get(&format!("/api/payloads/{body_id}?coding=gzip"));
    assert_eq!(not_gzip.body, b"{\"user\":\"ada\"}");
    assert!(
        not_gzip
            .header("x-wiretap-decode-error")
            .is_some_and(|e| e.contains("not valid"))
    );
    for bad in ["GZIP", "gzip%0d%0aX:%201", ""] {
        let path = format!("/api/payloads/{body_id}?coding={bad}");
        assert_eq!(client.get(&path).status, 400, "{bad}");
    }
    let state = client.get("/api/state").json();
    assert_eq!(state["capture"], "idle");
    assert_eq!(
        client.post("/api/capture/stop", "").status,
        200,
        "stopping while idle is harmless"
    );
    assert_eq!(
        client.post("/api/capture/stop", "{}").status,
        413,
        "actions take no body"
    );
    assert_eq!(client.post("/api/rules", &"x".repeat(10)).status, 400);
    running.shutdown();
}

#[test]
fn ui_script_posts_body_less_actions_without_a_body() {
    // Regression: the script sent `{}` to these routes, whose body limit is 0 (HTTP 413).
    let script = include_str!("../web/app.js");
    for call in [
        "'/api/capture/start', null)",
        "'/api/capture/stop', null)",
        "'/api/tls/disable' : '/api/tls/enable', null)",
        "'/api/browser', null)",
        "/delete`, null)",
    ] {
        assert!(script.contains(call), "missing {call}");
    }
    // Column tooltips use `tip`: a second `title` key would replace the header text.
    assert!(!script.contains("title: r =>"));
    // No browser dialogs: confirmations are in-app.
    assert!(
        !script.contains("confirm(") && !script.contains("alert(") && !script.contains("prompt(")
    );
}

#[test]
fn rules_api_validates_creates_from_flows_and_tests() {
    let (_dir, running, client, session) = server();
    let flow_id = client
        .get(&format!("/api/sessions/{}/flows", session.id))
        .json()["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rule = client.post(
        "/api/rules/from-flow",
        &format!("{{\"flow\":\"{flow_id}\"}}"),
    );
    assert_eq!(rule.status, 200);
    let rule = rule.json();
    assert_eq!(rule["response"]["status"], 200);
    assert_eq!(
        rule["response"]["body"]["text"], "{\"user\":\"ada\"}",
        "original response body is the default"
    );

    let matches = client
        .post(
            "/api/rules/test",
            &format!("{{\"rule\":{rule},\"session\":\"{}\"}}", session.id),
        )
        .json();
    assert_eq!(matches.as_array().unwrap().len(), 1);

    assert_eq!(client.post("/api/rules", &format!("[{rule}]")).status, 200);
    assert_eq!(client.get("/api/rules").json()[0]["id"], rule["id"]);
    let mut invalid = rule.clone();
    invalid["response"]["status"] = 101.into();
    let rejected = client.post("/api/rules", &format!("[{invalid}]"));
    assert_eq!(rejected.status, 400);
    assert!(
        rejected.json()["error"]
            .as_str()
            .unwrap()
            .contains("status")
    );
    assert_eq!(
        client.get("/api/rules").json()[0]["response"]["status"],
        200,
        "invalid save changes nothing"
    );
    running.shutdown();
}

fn live(client: &Client) -> impl Iterator<Item = Value> {
    let mut s = TcpStream::connect(&client.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET /api/live HTTP/1.1\r\nHost: {}\r\nCookie: wiretap={}\r\n\r\n",
        client.addr, client.cookie
    )
    .unwrap();
    BufReader::new(s)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| {
            l.strip_prefix("data: ")
                .and_then(|d| serde_json::from_str(d).ok())
        })
}

#[test]
fn feed_messages_are_validated_and_relayed_live() {
    let (_dir, running, client, _session) = server();
    let mut events = live(&client);
    assert_eq!(events.next().unwrap()["state"]["capture"], "idle");

    // Pretend an elevated capture process was started with this key.
    running.app().test_starting("k3y");
    let mut feed = TcpStream::connect(&client.addr).unwrap();
    write!(
        feed,
        "POST /internal/feed HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer k3y\r\n\r\n",
        client.addr
    )
    .unwrap();
    let mut ack = [0u8; 12];
    feed.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"HTTP/1.1 200");

    let session = Session::new("capture");
    let mut event = NetworkEvent {
        id: EventId::generate(),
        session_id: session.id,
        timestamp: Timestamp::now(),
        source: CaptureSource::Driver,
        protocol: Protocol::Tcp,
        direction: wiretap_core::Direction::Outbound,
        process: None,
        local_endpoint: None,
        remote_endpoint: None,
        payload: None,
        metadata: EventMetadata {
            inspection: Inspection::Metadata,
            flow_id: None,
            attributes: Default::default(),
        },
    };
    let mut lines = vec![serde_json::to_string(&Message::Session(session.clone())).unwrap()];
    lines.push(serde_json::to_string(&Message::Event(event.clone())).unwrap());
    event.metadata.inspection = Inspection::Intercepted; // invalid for a driver source
    lines.push(serde_json::to_string(&Message::Event(event)).unwrap());
    lines.push("not json".into());
    lines.push(
        serde_json::to_string(&Message::Stats(Stats {
            observations: 1,
            dropped: 0,
            rejected: 0,
        }))
        .unwrap(),
    );
    for line in &lines {
        writeln!(feed, "{line}").unwrap();
    }
    let mut seen = Vec::new();
    for v in events.by_ref() {
        if v.get("stats").is_some() {
            break;
        }
        seen.push(v);
    }
    // Joined but not yet capturing, then running once the capture's first statistics arrive.
    let states: Vec<_> = seen
        .iter()
        .filter_map(|v| v["state"]["capture"].as_str())
        .collect();
    assert!(
        states.contains(&"starting") && states.last() == Some(&"running"),
        "{states:?}"
    );
    assert!(
        seen.iter()
            .any(|v| v["session"]["id"] == session.id.to_string())
    );
    let relayed: Vec<_> = seen.iter().filter(|v| v.get("event").is_some()).collect();
    assert_eq!(relayed.len(), 1, "the invalid event was dropped");

    drop(feed); // capture process exits
    assert!(events.any(|v| v["state"]["capture"] == "idle"));
    running.shutdown();
}

/// Upstream HTTP server counting hits.
fn upstream() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&hits);
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            count.fetch_add(1, Ordering::SeqCst);
            let _ = wiretap_protocol::read_head(&mut s);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"live\":1}\n");
        }
    });
    (addr, hits)
}

fn through(proxy_port: u64, url: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", u16::try_from(proxy_port).unwrap())).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {url} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn proxy_auto_reply_end_to_end_through_the_api() {
    let (_dir, running, client, _session) = server();
    let (upstream, hits) = upstream();
    // The proxy is always on.
    let state = client.get("/api/state").json();
    let port = state["proxy"]["port"].as_u64().unwrap();
    assert_eq!(
        state["https"], false,
        "HTTPS decryption needs the user's consent"
    );
    let proxy_session = state["session"].as_str().unwrap().to_owned();
    let url = format!("http://{upstream}/user");

    let original = through(port, &url);
    assert!(original.ends_with("{\"live\":1}\n"), "{original}");
    // The exchange is stored with its body.
    let deadline = Instant::now() + Duration::from_secs(10);
    let flow_id = loop {
        let flows = client
            .get(&format!("/api/sessions/{proxy_session}/flows"))
            .json();
        if let Some(id) = flows["items"][0]["id"].as_str() {
            break id.to_owned();
        }
        assert!(Instant::now() < deadline, "flow not recorded");
        thread::sleep(Duration::from_millis(20));
    };
    // Create a rule from it (original response by default), save it, request again.
    let rule = client
        .post(
            "/api/rules/from-flow",
            &format!("{{\"flow\":\"{flow_id}\"}}"),
        )
        .json();
    assert_eq!(client.post("/api/rules", &format!("[{rule}]")).status, 200);
    let replayed = through(port, &url);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "auto-reply answered without contacting the server"
    );
    assert!(
        replayed.starts_with("HTTP/1.1 200 OK") && replayed.ends_with("{\"live\":1}\n"),
        "{replayed}"
    );

    assert_eq!(
        client.post("/api/proxy/stop", "").status,
        404,
        "the proxy cannot be stopped"
    );
    assert_eq!(
        client.get("/api/tls/root.cer").status,
        404,
        "no root while decryption is off"
    );
    running.shutdown();
}

/// Browsers export WebSocket messages in `_webSocketMessages`; Wiretap imports them as message
/// events of the flow and exports them back unchanged.
#[test]
fn websocket_messages_round_trip_through_har() {
    let (_dir, running, client, _) = server();
    let messages = serde_json::json!([
        { "type": "send", "time": 1_762_683_333.5, "opcode": 1, "data": "{\"hello\":1}" },
        { "type": "receive", "time": 1_762_683_333.75, "opcode": 2, "data": "AAEC/w==" },
        { "type": "receive", "time": 1_762_683_334.0, "opcode": 99, "data": "not a message" },
    ]);
    let har = serde_json::json!({ "log": { "version": "1.2", "entries": [{
        "startedDateTime": "2026-11-09T10:15:33.492Z", "time": 1,
        "request": { "method": "GET", "url": "wss://chat.example.com/socket", "httpVersion": "HTTP/1.1", "headers": [] },
        "response": { "status": 101, "statusText": "Switching Protocols", "httpVersion": "HTTP/1.1", "headers": [], "content": { "size": 0 } },
        "_webSocketMessages": messages,
    }]}});
    let imported = client.post("/api/har", &har.to_string()).json();
    let id = imported["session"]["id"].as_str().unwrap();
    let flow = client.get(&format!("/api/sessions/{id}/flows")).json()["items"][0].clone();
    assert!(
        flow["tags"]
            .as_array()
            .unwrap()
            .contains(&"websocket".into())
    );
    let events = client.get(&format!("/api/sessions/{id}/events")).json()["items"].clone();
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 2, "the unknown opcode is skipped");
    assert_eq!(
        (
            events[0]["protocol"].as_str(),
            events[0]["direction"].as_str()
        ),
        (Some("websocket"), Some("outbound"))
    );
    assert_eq!(events[0]["metadata"]["flow_id"], flow["id"]);
    assert_eq!(
        events[0]["metadata"]["attributes"]["preview"],
        "{\"hello\":1}"
    );
    let binary = events[1]["payload"]["id"].as_str().unwrap();
    assert_eq!(
        client.get(&format!("/api/payloads/{binary}")).body,
        [0, 1, 2, 255]
    );
    let exported: Value =
        serde_json::from_slice(&client.get(&format!("/api/sessions/{id}/har")).body).unwrap();
    let mut expected = messages.as_array().unwrap().clone();
    expected.pop();
    assert_eq!(
        exported["log"]["entries"][0]["_webSocketMessages"],
        Value::Array(expected)
    );
    running.shutdown();
}

#[test]
fn sessions_round_trip_through_har() {
    let (_dir, running, client, session) = server();
    let har = client.get(&format!("/api/sessions/{}/har", session.id));
    assert_eq!(har.status, 200);
    assert!(
        har.header("content-disposition")
            .unwrap()
            .ends_with(".har\"")
    );
    let doc: Value = serde_json::from_slice(&har.body).unwrap();
    assert_eq!(doc["log"]["version"], "1.2");
    assert_eq!(
        doc["log"]["entries"][0]["response"]["content"]["text"],
        "{\"user\":\"ada\"}"
    );
    let imported = client
        .post("/api/har", &String::from_utf8(har.body.clone()).unwrap())
        .json();
    assert_eq!(
        (imported["imported"].as_u64(), imported["skipped"].as_u64()),
        (Some(1), Some(0))
    );
    let id = imported["session"]["id"].as_str().unwrap();
    let flows = client.get(&format!("/api/sessions/{id}/flows")).json();
    let flow = &flows["items"][0];
    assert_eq!(flow["request"]["url"], "http://api.example.com/me");
    assert_eq!(flow["source"], "import");
    let body_id = flow["response"]["body"]["id"].as_str().unwrap();
    assert_eq!(
        client.get(&format!("/api/payloads/{body_id}")).body,
        b"{\"user\":\"ada\"}"
    );
    assert_eq!(client.post("/api/har", "{\"not\":\"har\"}").status, 400);
    running.shutdown();
}
