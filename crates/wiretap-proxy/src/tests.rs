use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;

use std::collections::HashMap;

use wiretap_autoreply::{Body, Condition, Op, Redirect, ResponseTemplate, Rule, RuleSet, Text};

use super::*;

#[derive(Default)]
struct TestHooks {
    rules: Mutex<Arc<RuleSet>>,
    recorded: Mutex<Vec<Exchange>>,
    events: Mutex<Vec<(NetworkEvent, Vec<u8>, u64)>>,
    tls: Mutex<Option<Arc<dyn Tls>>>,
    redirect: Mutex<Option<SocketAddr>>,
    /// Application of redirected connections (default `msedge.exe`).
    app: Mutex<Option<&'static str>>,
    /// Whether processes run outside the user's session ([`Hooks::foreign`]).
    foreign: AtomicBool,
    /// Events describing redirected connections (no flow), kept apart from flow events.
    connections: Mutex<Vec<NetworkEvent>>,
}

impl Hooks for TestHooks {
    fn rules(&self) -> Arc<RuleSet> {
        Arc::clone(&self.rules.lock().unwrap())
    }
    fn process(&self, _client: SocketAddr, _proxy: SocketAddr) -> Option<ProcessInfo> {
        Some(ProcessInfo {
            pid: 4242,
            name: Some("curl.exe".into()),
            path: None,
            started: None,
        })
    }
    fn record(&self, exchange: Exchange) {
        exchange
            .flow
            .validate()
            .expect("recorded flows are valid model data");
        self.recorded.lock().unwrap().push(exchange);
    }
    fn event(&self, event: NetworkEvent, payload: Vec<u8>, size: u64) {
        event
            .validate()
            .expect("recorded events are valid model data");
        // Storage keeps a payload only if it is a prefix of its declared full size.
        assert!(
            payload.len() as u64 <= size,
            "payload longer than its size: {event:?}"
        );
        if event.metadata.flow_id.is_none() {
            self.connections.lock().unwrap().push(event);
        } else {
            self.events.lock().unwrap().push((event, payload, size));
        }
    }
    fn tls(&self) -> Option<Arc<dyn Tls>> {
        self.tls.lock().unwrap().clone()
    }
    fn foreign(&self, _pid: u32) -> bool {
        self.foreign.load(Ordering::SeqCst)
    }
    fn redirected(&self, _client: &TcpStream) -> Option<Redirected> {
        let addr = (*self.redirect.lock().unwrap())?;
        let app = self.app.lock().unwrap().unwrap_or("msedge.exe");
        Some(Redirected {
            addr,
            process: Some(ProcessInfo {
                pid: 77,
                name: Some(app.into()),
                path: None,
                started: None,
            }),
        })
    }
}

impl TestHooks {
    fn set_rules(&self, rules: Vec<Rule>) {
        *self.rules.lock().unwrap() = Arc::new(RuleSet::new(rules).unwrap());
    }
    fn wait_events(&self, n: usize) -> Vec<(NetworkEvent, Vec<u8>, u64)> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.events.lock().unwrap().len() < n && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        self.events.lock().unwrap().clone()
    }
    fn wait_recorded(&self, n: usize) -> Vec<Exchange> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let got = self.recorded.lock().unwrap().clone();
            if got.len() >= n || Instant::now() > deadline {
                return got;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Minimal upstream server: answers by path and remembers the raw requests it received.
struct Upstream {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    hits: Arc<AtomicUsize>,
}

fn upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicUsize::new(0));
    let (log, count) = (Arc::clone(&requests), Arc::clone(&hits));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            count.fetch_add(1, Ordering::SeqCst);
            let (head, mut rest) = read_head(&mut s).unwrap();
            let StartLine::Request { target, .. } = &head.start else {
                continue;
            };
            if let Some(Framing::Length(n)) = framing(&head, None) {
                while rest.len() < usize::try_from(n).unwrap() {
                    let mut b = [0u8; 1024];
                    let k = s.read(&mut b).unwrap();
                    rest.extend_from_slice(&b[..k]);
                }
            }
            let raw = format!(
                "{target}\n{}\n\n{}",
                head.headers
                    .iter()
                    .map(|h| format!("{}: {}", h.name, h.value))
                    .collect::<Vec<_>>()
                    .join("\n"),
                String::from_utf8_lossy(&rest)
            );
            log.lock().unwrap().push(raw);
            let reply: Vec<u8> = match target.as_str() {
                "/hello" => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nSet-Cookie: s=1\r\n\r\nhello".to_vec(),
                "/chunked" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".to_vec(),
                "/continue" => b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n".to_vec(),
                "/echo" => format!("HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n", rest.len()).into_bytes().into_iter().chain(rest).collect(),
                _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            };
            let _ = s.write_all(&reply);
        }
    });
    Upstream {
        addr,
        requests,
        hits,
    }
}

fn proxy(hooks: &Arc<TestHooks>) -> Handle {
    let hooks: Arc<dyn Hooks> = Arc::clone(hooks) as Arc<dyn Hooks>;
    start("127.0.0.1:0".parse().unwrap(), SessionId::generate(), hooks).unwrap()
}

fn send(proxy: &Handle, request: &[u8]) -> String {
    let mut s = TcpStream::connect(proxy.addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(request).unwrap();
    read_response(&mut s, request.starts_with(b"HEAD "))
}

/// One whole response as text, as framed (kept-alive connections stay open after it); a HEAD
/// response (`head_only`) has no body.
fn read_response(r: &mut impl Read, head_only: bool) -> String {
    let (mut out, mut buf) = (Vec::new(), [0u8; 4096]);
    let complete = |raw: &[u8]| {
        let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
        let body = &raw[end + 4..];
        let length = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .and_then(|n| n.trim().parse::<usize>().ok());
        if head.contains("\r\nconnection: close") {
            false // to the end
        } else if head_only || head.starts_with("http/1.1 204") || head.starts_with("http/1.1 304")
        {
            true
        } else if let Some(n) = length {
            body.len() >= n
        } else {
            head.contains("transfer-encoding: chunked") && body.ends_with(b"0\r\n\r\n")
        }
    };
    while !complete(&out) {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn forwards_and_records_plain_http() {
    let (up, hooks) = (upstream(), Arc::new(TestHooks::default()));
    let p = proxy(&hooks);
    let request = format!(
        "GET http://{}/hello HTTP/1.1\r\nHost: {}\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n",
        up.addr, up.addr
    );
    let response = send(&p, request.as_bytes());
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        !response.contains("Connection: close") && response.ends_with("\r\n\r\nhello"),
        "kept alive: {response}"
    );

    let seen = up.requests.lock().unwrap()[0].clone();
    assert!(seen.starts_with("/hello\n"), "origin-form target: {seen}");
    assert!(
        !seen.contains("Proxy-Connection")
            && !seen.contains("Connection:")
            && seen.contains("Accept: */*"),
        "{seen}"
    );

    let [exchange] = &hooks.wait_recorded(1)[..] else {
        panic!("one exchange")
    };
    let flow = &exchange.flow;
    assert_eq!(flow.source, CaptureSource::ExplicitProxy);
    assert_eq!(flow.response.as_ref().unwrap().status, 200);
    assert_eq!(flow.server.unwrap().port, Some(up.addr.port()));
    assert_eq!(
        flow.process.as_ref().unwrap().name.as_deref(),
        Some("curl.exe")
    );
    assert_eq!(
        (exchange.response_body.as_slice(), exchange.response_size),
        (&b"hello"[..], 5)
    );
    assert!(flow.timing.response_complete.is_some());
    p.stop();
}

/// HTTP/1.1 keep-alive: requests (pipelined ones too) share the client connection and the
/// server connection, each recorded as its own flow as soon as it ends; `Connection: close`
/// ends both.
#[test]
fn http1_connections_are_kept_alive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&connections);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { continue };
            count.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let mut reader = io::BufReader::new(s.try_clone().unwrap());
                let mut s = s;
                while let Ok((head, rest)) = read_head(&mut reader) {
                    assert!(rest.is_empty() || head.header("content-length").is_some());
                    let StartLine::Request { target, .. } = &head.start else {
                        return;
                    };
                    let mut body = rest;
                    if let Some(Framing::Length(n)) = framing(&head, None) {
                        let (n, have) = (usize::try_from(n).unwrap(), body.len());
                        body.resize(n, 0);
                        reader.read_exact(&mut body[have..]).unwrap();
                    }
                    let reply = format!("{target} {}", String::from_utf8_lossy(&body));
                    write!(
                        s,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{reply}",
                        reply.len()
                    )
                    .unwrap();
                }
            });
        }
    });
    let hooks = Arc::new(TestHooks::default());
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(c, "GET http://{addr}/a HTTP/1.1\r\nHost: {addr}\r\n\r\n").unwrap();
    assert!(read_response(&mut c, false).ends_with("/a "));
    let first = hooks.wait_recorded(1).remove(0).flow;
    assert!(first.timing.response_complete.is_some(), "recorded at once");
    // Two pipelined requests in one write, the second asking to close.
    write!(
        c,
        "POST http://{addr}/b HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 2\r\n\r\nhi\
         GET http://{addr}/c HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let second = read_response(&mut c, false);
    assert!(second.ends_with("/b hi"), "{second}");
    let last = read_response(&mut c, false);
    assert!(
        last.contains("Connection: close") && last.ends_with("/c "),
        "{last}"
    );
    let mut rest = Vec::new();
    assert_eq!(c.read_to_end(&mut rest).unwrap_or(1), 0, "closed after it");
    let flows: Vec<_> = hooks.wait_recorded(3).into_iter().map(|x| x.flow).collect();
    let urls: Vec<_> = flows
        .iter()
        .map(|f| f.request.as_ref().unwrap().url.clone())
        .collect();
    assert_eq!(
        urls,
        ["/a", "/b", "/c"].map(|p| format!("http://{addr}{p}"))
    );
    assert!(flows[0].id != flows[1].id && flows[1].id != flows[2].id);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "one server connection"
    );
}

/// A server that closes its kept connection between requests: the next request goes out again
/// on a new connection, unnoticed by the client.
#[test]
fn server_connections_closed_meanwhile_are_retried() {
    let (up, hooks) = (upstream(), Arc::new(TestHooks::default())); // one request per connection
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    for _ in 0..3 {
        write!(
            c,
            "GET http://{0}/hello HTTP/1.1\r\nHost: {0}\r\n\r\n",
            up.addr
        )
        .unwrap();
        let response = read_response(&mut c, false);
        assert!(response.ends_with("\r\n\r\nhello"), "{response}");
    }
    assert_eq!(up.hits.load(Ordering::SeqCst), 3);
    assert_eq!(hooks.wait_recorded(3).len(), 3);
}

#[test]
fn chunked_responses_are_relayed_raw_and_stored_decoded() {
    let (up, hooks) = (upstream(), Arc::new(TestHooks::default()));
    let p = proxy(&hooks);
    let response = send(
        &p,
        format!("GET http://{}/chunked HTTP/1.1\r\nHost: x\r\n\r\n", up.addr).as_bytes(),
    );
    assert!(
        response.ends_with("3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"),
        "{response}"
    );
    let exchange = hooks.wait_recorded(1).remove(0);
    assert_eq!(
        (exchange.response_body.as_slice(), exchange.response_size),
        (&b"abcde"[..], 5)
    );

    let interim = send(
        &p,
        format!(
            "GET http://{}/continue HTTP/1.1\r\nHost: x\r\n\r\n",
            up.addr
        )
        .as_bytes(),
    );
    assert!(
        interim.starts_with("HTTP/1.1 204 No Content"),
        "interim responses are skipped: {interim}"
    );
}

#[test]
fn request_bodies_are_forwarded_with_explicit_length() {
    let (up, hooks) = (upstream(), Arc::new(TestHooks::default()));
    let p = proxy(&hooks);
    let fixed = send(
        &p,
        format!(
            "POST http://{}/echo HTTP/1.1\r\nHost: x\r\nContent-Length: 7\r\n\r\npayload",
            up.addr
        )
        .as_bytes(),
    );
    assert!(
        fixed.starts_with("HTTP/1.1 201") && fixed.ends_with("payload"),
        "{fixed}"
    );
    let chunked = send(
        &p,
        format!("POST http://{}/echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nchun\r\n3\r\nked\r\n0\r\n\r\n", up.addr).as_bytes(),
    );
    assert!(chunked.ends_with("chunked"), "{chunked}");
    let seen = up.requests.lock().unwrap()[1].clone();
    assert!(
        seen.contains("Content-Length: 7") && !seen.contains("Transfer-Encoding"),
        "re-framed: {seen}"
    );
    let recorded = hooks.wait_recorded(2);
    assert!(recorded.iter().any(|e| e.request_body == b"chunked"));
}

#[test]
fn auto_reply_defaults_to_the_original_response_and_is_customizable() {
    let (up, hooks) = (upstream(), Arc::new(TestHooks::default()));
    let p = proxy(&hooks);
    let request = format!("GET http://{}/hello HTTP/1.1\r\nHost: x\r\n\r\n", up.addr);
    let original = send(&p, request.as_bytes());
    let captured = hooks.wait_recorded(1).remove(0);

    // A rule made from the captured request replays the original response; the server is
    // no longer contacted.
    let mut rule = Rule::from_flow(&captured.flow, Some(&captured.response_body)).unwrap();
    hooks.set_rules(vec![rule.clone()]);
    let replayed = send(&p, request.as_bytes());
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        1,
        "auto-reply must not reach the server"
    );
    assert!(
        replayed.starts_with("HTTP/1.1 200 OK\r\n") && replayed.ends_with("\r\n\r\nhello"),
        "{replayed}"
    );
    assert!(replayed.contains("Set-Cookie: s=1") && replayed.contains("Content-Type: text/plain"));
    assert!(original.ends_with("hello"));
    let replay = hooks.wait_recorded(2).remove(1);
    assert!(replay.flow.tags.contains(&"auto-reply".into()));
    assert!(replay.flow.tags.contains(&format!("rule:{}", rule.id)));

    // Everything is editable: status, reason, headers, body with variables, delay.
    rule.response.status = 503;
    rule.response.reason = "Maintenance".into();
    rule.response.headers.push(HttpHeader {
        name: "Retry-After".into(),
        value: "120".into(),
    });
    rule.response.body = Body::Text {
        text: "{{request.method}} {{request.path}} is mocked".into(),
    };
    rule.response.delay_ms = 200;
    hooks.set_rules(vec![rule]);
    let start = Instant::now();
    let custom = send(&p, request.as_bytes());
    assert!(
        start.elapsed() >= Duration::from_millis(200),
        "delay honoured"
    );
    assert!(
        custom.starts_with("HTTP/1.1 503 Maintenance\r\n")
            && custom.contains("Retry-After: 120\r\n"),
        "{custom}"
    );
    assert!(custom.ends_with("GET /hello is mocked"), "{custom}");
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);

    let head = send(
        &p,
        format!("HEAD http://{}/hello HTTP/1.1\r\nHost: x\r\n\r\n", up.addr).as_bytes(),
    );
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        2,
        "the HEAD request does not match the GET rule"
    );
    assert!(head.starts_with("HTTP/1.1 200"));
}

#[test]
fn rules_can_match_on_the_client_process() {
    let (up, hooks) = (upstream(), Arc::new(TestHooks::default()));
    let p = proxy(&hooks);
    let mut rule = Rule::from_flow(
        &Flow {
            request: Some(HttpRequest {
                method: "GET".into(),
                url: "x".into(),
                version: HttpVersion::Http11,
                headers: vec![],
                body: None,
            }),
            ..hooks_flow()
        },
        None,
    )
    .unwrap();
    rule.condition = Condition::Process(Text {
        op: Op::Equals,
        value: "CURL.EXE".into(),
        case_sensitive: false,
    });
    rule.response.status = 418;
    hooks.set_rules(vec![rule]);
    let response = send(
        &p,
        format!(
            "GET http://{}/anything HTTP/1.1\r\nHost: x\r\n\r\n",
            up.addr
        )
        .as_bytes(),
    );
    assert!(response.starts_with("HTTP/1.1 418"), "{response}");
}

fn hooks_flow() -> Flow {
    Flow {
        id: FlowId::generate(),
        session_id: SessionId::generate(),
        source: CaptureSource::ExplicitProxy,
        process: None,
        client: None,
        server: None,
        request: None,
        response: None,
        timing: FlowTiming {
            started: Timestamp(0),
            request_complete: None,
            response_started: None,
            response_complete: None,
        },
        tags: Vec::new(),
    }
}

#[test]
fn redirect_rules_send_requests_elsewhere_without_touching_the_original() {
    let (up, hooks) = (upstream(), Arc::new(TestHooks::default()));
    hooks.set_rules(vec![Rule {
        id: wiretap_core::RuleId::generate(),
        name: "to local".into(),
        enabled: true,
        condition: Condition::Host(Text {
            op: Op::Equals,
            value: "original.invalid".into(),
            case_sensitive: false,
        }),
        response: ResponseTemplate::ok(),
        group: "original.invalid".into(),
        redirect: Some(Redirect {
            to: format!("http://{}", up.addr),
            keep_host: false,
        }),
    }]);
    let p = proxy(&hooks);
    // `original.invalid` does not even resolve: only the redirect target is contacted.
    let response = send(
        &p,
        b"GET http://original.invalid/hello HTTP/1.1\r\nHost: original.invalid\r\n\r\n",
    );
    assert!(response.ends_with("\r\n\r\nhello"), "{response}");
    let seen = up.requests.lock().unwrap()[0].clone();
    assert!(seen.starts_with("/hello\n"), "{seen}");
    assert!(
        seen.contains(&format!("Host: {}", up.addr)) && !seen.contains("original.invalid"),
        "{seen}"
    );
    let flow = hooks.wait_recorded(1).remove(0).flow;
    assert_eq!(
        flow.request.unwrap().url,
        "http://original.invalid/hello",
        "the client's URL is kept"
    );
    assert!(
        flow.tags.contains(&"redirect".into())
            && flow.tags.contains(&format!("to:http://{}/hello", up.addr)),
        "{:?}",
        flow.tags
    );
}
#[test]
fn websocket_messages_are_decoded_and_recorded() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let (mut s, _) = server.accept().unwrap();
        read_head(&mut s).unwrap();
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n\r\n").unwrap();
        let mut hello = [0u8; 11];
        s.read_exact(&mut hello).unwrap();
        // RFC 7692 "Hello" (compressed), then a close with status 1000 and a reason.
        s.write_all(&[0xC1, 0x07, 0xF2, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00])
            .unwrap();
        s.write_all(b"\x88\x05\x03\xE8bye").unwrap();
        thread::sleep(Duration::from_millis(200));
    });
    let hooks = Arc::new(TestHooks::default());
    let proxy = proxy(&hooks);
    let mut c = TcpStream::connect(proxy.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(c, "GET http://{addr}/chat HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
    let (head, _) = read_head(&mut c).unwrap();
    assert!(matches!(
        head.start,
        StartLine::Response { status: 101, .. }
    ));
    let open = hooks.wait_recorded(1).remove(0).flow; // recorded while the socket is open
    assert!(open.tags.contains(&"websocket".into()) && open.timing.response_complete.is_none());
    c.write_all(&[
        0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58,
    ])
    .unwrap(); // RFC 6455 masked "Hello"
    let events = hooks.wait_events(3);
    let seen: Vec<_> = events
        .iter()
        .map(|(e, payload, size)| {
            assert_eq!(
                (e.protocol, e.metadata.flow_id, e.source),
                (
                    Protocol::Websocket,
                    Some(open.id),
                    CaptureSource::ExplicitProxy
                )
            );
            (
                e.direction,
                e.metadata.attributes.get("opcode").cloned(),
                payload.clone(),
                *size,
            )
        })
        .collect();
    assert!(
        seen.contains(&(
            Direction::Outbound,
            Some("text".into()),
            b"Hello".to_vec(),
            5
        )),
        "{seen:?}"
    );
    assert!(
        seen.contains(&(
            Direction::Inbound,
            Some("text".into()),
            b"Hello".to_vec(),
            5
        )),
        "{seen:?}"
    );
    let attributes = |opcode: &str| {
        events
            .iter()
            .find(|(e, ..)| {
                e.direction == Direction::Inbound
                    && e.metadata.attributes.get("opcode").map(String::as_str) == Some(opcode)
            })
            .map(|(e, ..)| e.metadata.attributes.clone())
            .unwrap()
    };
    assert_eq!(
        attributes("text").get("wire_size").map(String::as_str),
        Some("7")
    );
    assert_eq!(
        attributes("text").get("preview").map(String::as_str),
        Some("Hello")
    );
    let close = attributes("close");
    assert_eq!(
        (
            close.get("close_code").map(String::as_str),
            close.get("close_reason").map(String::as_str)
        ),
        (Some("1000"), Some("bye"))
    );
    // The client's bytes reached the server untouched (it read them and answered).
    let mut reply = [0u8; 9];
    c.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 0xC1);
    drop(c);
    let done = hooks.wait_recorded(2).remove(1).flow;
    assert_eq!(done.id, open.id);
    assert!(done.timing.response_complete.is_some());
}

/// Regression: connections relayed without decoding (not HTTP, or TLS passed through) were
/// recorded with an empty method, which storage rejects, so they silently vanished.
/// The WebSocket lab (examples/ws_lab.rs) through the explicit proxy: every protocol version,
/// with and without permessage-deflate. The client checks each echo; Wiretap must decode every
/// message of both directions without a problem.
/// Server-Sent Events over HTTP/1.1 (chunked, events split across chunks): the stream is
/// recorded while open and each event becomes a message of it.
#[test]
fn server_sent_events_are_decoded_live() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = read_head(&mut s).unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        let chunk = |s: &mut TcpStream, data: &[u8]| {
            write!(s, "{:x}\r\n", data.len()).unwrap();
            s.write_all(data).unwrap();
            s.write_all(b"\r\n").unwrap();
        };
        chunk(&mut s, b"id: 1\ndata: hello");
        wait.recv().unwrap(); // the stream is open now
        chunk(&mut s, b"\n: ping\n\ndata: world");
        chunk(&mut s, b"\n\n");
        s.write_all(b"0\r\n\r\n").unwrap();
    });
    let hooks = Arc::new(TestHooks::default());
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        c,
        "GET http://{addr}/events HTTP/1.1\r\nHost: {addr}\r\nAccept: text/event-stream\r\n\r\n"
    )
    .unwrap();
    let open = hooks.wait_recorded(1).remove(0).flow;
    assert!(open.tags.contains(&"sse".into()), "{:?}", open.tags);
    assert!(
        open.timing.response_complete.is_none(),
        "recorded while open"
    );
    go.send(()).unwrap();
    let body = read_response(&mut c, false);
    assert!(body.contains("data: world"), "relayed untouched");
    let events = hooks.wait_events(2);
    let got: Vec<_> = events
        .iter()
        .map(|(e, p, _)| (attribute(e, "id").to_owned(), p.clone()))
        .collect();
    assert_eq!(
        got,
        [
            ("1".to_owned(), b"hello".to_vec()),
            ("1".to_owned(), b"world".to_vec())
        ]
    );
    assert!(
        events
            .iter()
            .all(|(e, ..)| e.protocol == Protocol::Sse && e.metadata.flow_id == Some(open.id))
    );
}
#[test]
fn websocket_lab_passes_through_the_proxy_in_every_version() {
    use crate::wslab::{Client, run, serve};
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    thread::spawn(move || serve(server, None));
    let client = |version, deflate, proxy: Option<String>| Client {
        url: format!("ws://{addr}/lab"),
        proxy,
        deflate,
        version,
        tls: None,
    };
    run(&client(13, true, None)).expect("the lab works directly");
    let hooks = Arc::new(TestHooks::default());
    let p = proxy(&hooks);
    let mut expected = 0;
    for (version, deflate) in [(13, false), (13, true), (8, false), (7, true)] {
        let log = run(&client(version, deflate, Some(p.addr().to_string())))
            .unwrap_or_else(|e| panic!("version {version}, deflate {deflate}: {e}"));
        assert!(
            log.iter()
                .any(|l| l.contains(&format!("permessage-deflate {deflate}"))),
            "{log:?}"
        );
        expected += if deflate { 16 } else { 14 }; // messages of both directions
    }
    let events = hooks.wait_events(expected);
    assert_eq!(events.len(), expected);
    for (e, ..) in &events {
        let a = &e.metadata.attributes;
        assert!(
            !a.contains_key("error") && !a.contains_key("problem"),
            "{a:?}"
        );
    }
    // Server echoes and the client's compressed message, in the two deflate runs.
    assert_eq!(
        events
            .iter()
            .filter(|(e, ..)| e.metadata.attributes.contains_key("wire_size"))
            .count(),
        14
    );
    let flows = hooks.wait_recorded(8);
    assert!(
        flows
            .iter()
            .all(|x| x.flow.tags.contains(&"websocket".into())
                && x.flow.request.as_ref().unwrap().url == format!("http://{addr}/lab"))
    );
}

/// Hixie-76 (the 2010 pre-standard protocol: key bytes after the request, `0x00 ... 0xFF`
/// frames) is not decoded, but it must still pass through untouched.
#[test]
fn hixie76_websockets_are_relayed_untouched() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let (mut s, _) = server.accept().unwrap();
        let (_, mut rest) = read_head(&mut s).unwrap();
        fn fill(s: &mut TcpStream, rest: &mut Vec<u8>, n: usize) {
            while rest.len() < n {
                let mut b = [0u8; 64];
                let k = s.read(&mut b).unwrap();
                rest.extend_from_slice(&b[..k]);
            }
        }
        fill(&mut s, &mut rest, 8);
        assert_eq!(&rest[..8], b"^n:ds[4U", "the key bytes reached the server");
        s.write_all(b"HTTP/1.1 101 WebSocket Protocol Handshake\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\n8jKS'y:G*Co,Wxa-").unwrap();
        fill(&mut s, &mut rest, 8 + 7);
        s.write_all(&rest[8..]).unwrap(); // echo the 0x00 ... 0xFF frame
        thread::sleep(Duration::from_millis(300));
    });
    let hooks = Arc::new(TestHooks::default());
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(c, "CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n").unwrap();
    read_head(&mut c).unwrap();
    write!(c, "GET /demo HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key1: 4 @1  46546xW%0l 1 5\r\nSec-WebSocket-Key2: 12998 5 Y3 1  .P00\r\n\r\n^n:ds[4U").unwrap();
    c.write_all(b"\x00hello\xFF").unwrap();
    let (head, mut rest) = read_head(&mut c).unwrap();
    assert!(matches!(
        head.start,
        StartLine::Response { status: 101, .. }
    ));
    while rest.len() < 16 + 7 {
        let mut b = [0u8; 64];
        let n = c.read(&mut b).unwrap();
        rest.extend_from_slice(&b[..n]);
    }
    assert_eq!(&rest[..], b"8jKS'y:G*Co,Wxa-\x00hello\xFF");
    // Both directions report that they are not RFC 6455 frames.
    let events = hooks.wait_events(2);
    assert!(
        events
            .iter()
            .all(|(e, ..)| e.metadata.attributes.contains_key("error")),
        "{events:?}"
    );
}

/// Refusal evidence rules (see `Trust`): alerts count at once, hang-ups twice in a row, and
/// never for a pair that already sent a request; a client gone mid-handshake refused nothing.
#[test]
fn certificate_refusals_need_real_evidence() {
    let mut trust = Trust::default();
    assert!(!trust.strike("app|a.test"), "one hang-up");
    assert!(trust.strike("app|a.test"), "two in a row");
    trust.accept("app|b.test");
    assert!(
        !trust.strike("app|b.test") && !trust.strike("app|b.test") && !trust.strike("app|b.test")
    );
    assert!(!trust.strike("app|c.test"));
    trust.accept("app|c.test"); // a request in between resets the count
    assert!(!trust.strike("app|c.test"));
    for kind in [
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::TimedOut,
    ] {
        assert!(gone(&io::Error::from(kind)), "{kind:?}");
    }
    assert!(
        !gone(&io::Error::other("TLS handshake failed (0x80090326)")),
        "an alert reported by SChannel"
    );
}

#[test]
fn relayed_connections_are_recorded_as_valid_tunnels() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let (mut s, _) = server.accept().unwrap();
        let mut b = [0u8; 8];
        s.read_exact(&mut b).unwrap();
        s.write_all(&b).unwrap();
    });
    let hooks = Arc::new(TestHooks::default());
    *hooks.redirect.lock().unwrap() = Some(addr);
    let proxy = proxy(&hooks);
    let mut c = TcpStream::connect(proxy.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"\x00\x01binary").unwrap();
    let mut echo = [0u8; 8];
    c.read_exact(&mut echo).unwrap();
    drop(c);
    let flow = hooks.wait_recorded(1).remove(0).flow; // the hook checks flow.validate()
    assert!(flow.tags.contains(&"tunnel".into()), "{:?}", flow.tags);
    assert_eq!(flow.request.unwrap().method, "CONNECT");
    let (event, ..) = hooks.wait_events(1).remove(0);
    assert_eq!(event.protocol, Protocol::Tcp);
    assert_eq!(attribute(&event, "relay.reason"), "opaque");
    assert_eq!(attribute(&event, "relay.sent"), "8");
    assert_eq!(attribute(&event, "relay.received"), "8");
}

fn attribute<'a>(event: &'a NetworkEvent, key: &str) -> &'a str {
    event
        .metadata
        .attributes
        .get(key)
        .map_or("", String::as_str)
}

/// Test-only HTTP/2 framing: one frame.
fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut out = vec![len[1], len[2], len[3], kind, flags];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A header block of literal fields (HPACK, no indexing, no Huffman).
fn h2_block(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in fields {
        out.extend([0, u8::try_from(name.len()).unwrap()]);
        out.extend_from_slice(name.as_bytes());
        out.push(u8::try_from(value.len()).unwrap());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// A scripted HTTP/2 connection in two rounds (client bytes, then the server's answer): GET /a
/// and POST /upload multiplexed (answers interleaved, trailers on the upload), and a WebSocket
/// over HTTP/2 on /chat whose messages follow the server's 200.
fn h2_script(scheme: &str, authority: &str) -> [Vec<u8>; 4] {
    let head = |method, path| {
        h2_block(&[
            (":method", method),
            (":scheme", scheme),
            (":path", path),
            (":authority", authority),
        ])
    };
    let mut client1 = wiretap_protocol::http2::PREFACE.to_vec();
    client1.extend(h2_frame(4, 0, 0, &[]));
    client1.extend(h2_frame(1, 0x05, 1, &head("GET", "/a"))); // END_HEADERS | END_STREAM
    client1.extend(h2_frame(1, 0x04, 3, &head("POST", "/upload")));
    client1.extend(h2_frame(0, 0, 3, b"part1"));
    client1.extend(h2_frame(0, 0x01, 3, b"part2"));
    let mut chat = h2_block(&[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", scheme),
        (":path", "/chat"),
        (":authority", authority),
    ]);
    chat.extend(h2_block(&[("sec-websocket-version", "13")]));
    client1.extend(h2_frame(1, 0x04, 5, &chat));
    client1.extend(h2_frame(1, 0x05, 7, &head("GET", "/events")));
    let mut server1 = h2_frame(4, 0, 0, &[]);
    server1.extend(h2_frame(4, 0x01, 0, &[])); // SETTINGS ACK
    server1.extend(h2_frame(1, 0x04, 3, &h2_block(&[(":status", "201")])));
    server1.extend(h2_frame(
        1,
        0x04,
        1,
        &h2_block(&[(":status", "200"), ("content-type", "text/plain")]),
    ));
    server1.extend(h2_frame(0, 0x01, 1, b"hello"));
    server1.extend(h2_frame(0, 0, 3, b"ok"));
    server1.extend(h2_frame(1, 0x05, 3, &h2_block(&[("grpc-status", "0")]))); // trailers
    server1.extend(h2_frame(1, 0x04, 5, &h2_block(&[(":status", "200")])));
    // Server-Sent Events on stream 7, one event split across two DATA frames.
    server1.extend(h2_frame(
        1,
        0x04,
        7,
        &h2_block(&[(":status", "200"), ("content-type", "text/event-stream")]),
    ));
    server1.extend(h2_frame(0, 0, 7, b"data: one\n\nevent: tick\nda"));
    server1.extend(h2_frame(0, 0x01, 7, b"ta: two\n\n"));
    // RFC 6455 5.7: a masked "Hello" from the client, an unmasked one from the server.
    let mut client2 = h2_frame(
        0,
        0,
        5,
        &[
            0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58,
        ],
    );
    client2.extend(h2_frame(0, 0x01, 5, &[]));
    let mut server2 = h2_frame(0, 0, 5, b"\x81\x05Hello");
    server2.extend(h2_frame(0, 0x01, 5, &[]));
    [client1, server1, client2, server2]
}

/// Plays the server side of [`h2_script`] on `io`, then waits for the client to close.
fn h2_serve(io: &mut dyn Stream, script: &[Vec<u8>; 4]) {
    let [client1, server1, client2, server2] = script;
    for (expect, answer) in [(client1, server1), (client2, server2)] {
        let mut got = vec![0u8; expect.len()];
        io.read_exact(&mut got).unwrap();
        assert_eq!(
            &got, expect,
            "the proxy relays the client's bytes untouched"
        );
        io.write_all(answer).unwrap();
        io.flush().unwrap();
    }
    let _ = io.read(&mut [0u8; 1]);
}

/// Plays the client side of [`h2_script`] on `io`.
fn h2_talk(io: &mut dyn Stream, script: &[Vec<u8>; 4]) {
    let [client1, server1, client2, server2] = script;
    for (send, expect) in [(client1, server1), (client2, server2)] {
        io.write_all(send).unwrap();
        io.flush().unwrap();
        let mut got = vec![0u8; expect.len()];
        io.read_exact(&mut got).unwrap();
        assert_eq!(
            &got, expect,
            "the proxy relays the server's bytes untouched"
        );
    }
}

/// What a relayed [`h2_script`] must have recorded: one exchange per stream (final records),
/// the WebSocket messages, and the connection row. `base` is `scheme://authority`.
fn assert_h2_recorded(hooks: &TestHooks, base: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let finished = |url: &str| {
        hooks
            .recorded
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|x| {
                x.flow.request.as_ref().is_some_and(|r| r.url == url)
                    && x.flow.timing.response_complete.is_some()
            })
            .cloned()
    };
    while finished(&format!("{base}/chat")).is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let get = finished(&format!("{base}/a")).expect("GET /a");
    let request = get.flow.request.as_ref().unwrap();
    assert_eq!(
        (request.method.as_str(), request.version),
        ("GET", HttpVersion::Http2)
    );
    assert_eq!(get.flow.response.as_ref().unwrap().status, 200);
    assert_eq!(get.response_body, b"hello");
    assert!(get.flow.tags.contains(&"h2".into()), "{:?}", get.flow.tags);
    let upload = finished(&format!("{base}/upload")).expect("POST /upload");
    assert_eq!(
        (upload.request_body.as_slice(), upload.request_size),
        (&b"part1part2"[..], 10)
    );
    let response = upload.flow.response.as_ref().unwrap();
    assert_eq!(
        (response.status, upload.response_body.as_slice()),
        (201, &b"ok"[..])
    );
    assert!(
        response
            .headers
            .iter()
            .any(|h| h.name == "grpc-status" && h.value == "0"),
        "trailers"
    );
    let chat = finished(&format!("{base}/chat")).expect("WebSocket /chat");
    assert!(
        chat.flow.tags.contains(&"websocket".into()),
        "{:?}",
        chat.flow.tags
    );
    let events = hooks.wait_events(4);
    let messages: Vec<_> = events
        .iter()
        .filter(|(e, ..)| e.metadata.flow_id == Some(chat.flow.id))
        .collect();
    assert_eq!(messages.len(), 2, "{events:?}");
    let stream = finished(&format!("{base}/events")).expect("SSE /events");
    assert!(
        stream.flow.tags.contains(&"sse".into()),
        "{:?}",
        stream.flow.tags
    );
    let sse: Vec<_> = events
        .iter()
        .filter(|(e, ..)| e.metadata.flow_id == Some(stream.flow.id))
        .collect();
    assert_eq!(
        sse.iter().map(|(_, p, _)| p.as_slice()).collect::<Vec<_>>(),
        [&b"one"[..], b"two"]
    );
    assert!(
        sse.iter()
            .all(|(e, ..)| e.protocol == Protocol::Sse && e.direction == Direction::Inbound)
    );
    assert_eq!(attribute(&sse[1].0, "event"), "tick");
    assert!(
        messages
            .iter()
            .all(|(e, payload, _)| payload == b"Hello" && e.protocol == Protocol::Websocket)
    );
    // The connection itself is recorded when it closes.
    let connection = || {
        hooks
            .recorded
            .lock()
            .unwrap()
            .iter()
            .any(|x| x.flow.tags.contains(&"h2-connection".into()))
    };
    while !connection() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connection(), "the connection itself is recorded too");
}

/// HTTP/2 with prior knowledge (h2c) on a redirected connection: relayed byte for byte, every
/// stream recorded (it was answered 502 as malformed HTTP/1.1 before).
#[test]
fn cleartext_http2_streams_are_relayed_and_recorded() {
    let script = h2_script("http", "h2c.test");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_script = script.clone();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        h2_serve(&mut s, &server_script);
    });
    let hooks = Arc::new(TestHooks::default());
    *hooks.redirect.lock().unwrap() = Some(addr);
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    h2_talk(&mut c, &script);
    drop(c);
    assert_h2_recorded(&hooks, "http://h2c.test");
}

/// A unary gRPC call over HTTP/2 (grpc/grpc `doc/PROTOCOL-HTTP2.md`): the request message split
/// across DATA frames, the response message, then the status in trailers. Each message is an
/// event with its protobuf view, the status the last one.
#[test]
fn grpc_calls_are_shown_message_by_message() {
    let grpc = |data: &[u8]| {
        [
            &[0u8][..],
            &u32::try_from(data.len()).unwrap().to_be_bytes(),
            data,
        ]
        .concat()
    };
    let request = grpc(b"\x08\x96\x01");
    let mut client = wiretap_protocol::http2::PREFACE.to_vec();
    client.extend(h2_frame(4, 0, 0, &[]));
    let head = h2_block(&[
        (":method", "POST"),
        (":scheme", "http"),
        (":path", "/test.Echo/Say"),
        (":authority", "grpc.test"),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
    ]);
    client.extend(h2_frame(1, 0x04, 1, &head));
    client.extend(h2_frame(0, 0, 1, &request[..3]));
    client.extend(h2_frame(0, 0x01, 1, &request[3..]));
    let mut server = h2_frame(4, 0, 0, &[]);
    server.extend(h2_frame(
        1,
        0x04,
        1,
        &h2_block(&[
            (":status", "200"),
            ("content-type", "application/grpc+proto"),
        ]),
    ));
    server.extend(h2_frame(0, 0, 1, &grpc(b"\x12\x07testing")));
    server.extend(h2_frame(
        1,
        0x05,
        1,
        &h2_block(&[("grpc-status", "0"), ("grpc-message", "all%20good")]),
    ));
    let script = [client, server, Vec::new(), Vec::new()];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = script.clone();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        h2_serve(&mut s, &served);
    });
    let hooks = Arc::new(TestHooks::default());
    *hooks.redirect.lock().unwrap() = Some(addr);
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    h2_talk(&mut c, &script);
    let events = hooks.wait_events(3);
    let shown: Vec<_> = events
        .iter()
        .map(|(e, ..)| {
            let a = &e.metadata.attributes;
            (
                e.protocol,
                e.direction,
                a.get("preview")
                    .or(a.get("status"))
                    .cloned()
                    .unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        shown,
        [
            (Protocol::Grpc, Direction::Outbound, "1: 150".to_owned()),
            (
                Protocol::Grpc,
                Direction::Inbound,
                "2: \"testing\"".to_owned()
            ),
            (Protocol::Grpc, Direction::Inbound, "0 OK".to_owned()),
        ]
    );
    assert_eq!(attribute(&events[2].0, "grpc-message"), "all good");
    assert_eq!(events[0].1, b"1: 150\n", "the readable view is the payload");
    drop(c);
    let flow = hooks
        .wait_recorded(2)
        .into_iter()
        .map(|x| x.flow)
        .find(|f| f.tags.contains(&"grpc".into()))
        .unwrap();
    assert_eq!(flow.request.unwrap().url, "http://grpc.test/test.Echo/Say");
}

/// A minimal cleartext HTTP/2 server: answers each request with 200, `x-served-by: origin` and
/// the path as body; reports the paths it was asked for.
fn h2_origin() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let log = Arc::clone(&log);
            thread::spawn(move || h2_answer(&mut s, &log));
        }
    });
    (addr, seen)
}

/// Serves one HTTP/2 connection as [`h2_origin`] does.
fn h2_answer(s: &mut dyn Stream, log: &Mutex<Vec<String>>) {
    use wiretap_protocol::http2::{Decoder as H2, Event};
    s.write_all(&h2_frame(4, 0, 0, &[])).unwrap();
    let (mut decoder, mut paths) = (H2::new(true), HashMap::new());
    let mut buf = [0u8; 16 * 1024];
    while let Ok(n @ 1..) = s.read(&mut buf) {
        for event in decoder.feed(&buf[..n]) {
            let done = match event {
                Event::Settings(_) => {
                    s.write_all(&h2_frame(4, 1, 0, &[])).unwrap();
                    None
                }
                Event::Headers {
                    stream,
                    fields,
                    end_stream,
                } => {
                    let path = fields
                        .iter()
                        .find(|(n, _)| n == ":path")
                        .map(|(_, v)| v.clone());
                    paths.insert(stream, path.unwrap_or_default());
                    end_stream.then_some(stream)
                }
                Event::Data {
                    stream,
                    end_stream: true,
                    ..
                } => Some(stream),
                _ => None,
            };
            if let Some(stream) = done {
                let path = paths.remove(&stream).unwrap_or_default();
                log.lock().unwrap().push(path.clone());
                let head = h2_block(&[(":status", "200"), ("x-served-by", "origin")]);
                s.write_all(&h2_frame(1, 0x04, stream, &head)).unwrap();
                s.write_all(&h2_frame(0, 0x01, stream, path.as_bytes()))
                    .unwrap();
            }
        }
    }
}
/// What a test client received on one stream: header fields, body.
type Received = (Vec<(String, String)>, Vec<u8>);

/// Reads HTTP/2 frames from the proxy until `streams` streams ended (or a GOAWAY when
/// `until_goaway`): each stream's fields and body.
fn h2_read(
    io: &mut dyn Stream,
    streams: usize,
    until_goaway: bool,
) -> (HashMap<u32, Received>, Option<u32>) {
    use wiretap_protocol::http2::{Decoder as H2, Event};
    let (mut decoder, mut out, mut ended) = (H2::new(false), HashMap::new(), 0);
    let mut buf = [0u8; 16 * 1024];
    let deadline = Instant::now() + Duration::from_secs(10);
    while (ended < streams || until_goaway) && Instant::now() < deadline {
        let Ok(n @ 1..) = io.read(&mut buf) else {
            break;
        };
        for event in decoder.feed(&buf[..n]) {
            match event {
                Event::Settings(_) => io.write_all(&h2_frame(4, 1, 0, &[])).unwrap(),
                Event::Headers {
                    stream,
                    fields,
                    end_stream,
                } => {
                    out.entry(stream)
                        .or_insert_with(|| (Vec::new(), Vec::new()))
                        .0
                        .extend(fields);
                    ended += usize::from(end_stream);
                }
                Event::Data {
                    stream,
                    data,
                    end_stream,
                    ..
                } => {
                    out.entry(stream)
                        .or_insert_with(|| (Vec::new(), Vec::new()))
                        .1
                        .extend(data);
                    ended += usize::from(end_stream);
                }
                Event::Reset { .. } => ended += 1,
                Event::GoAway { last, .. } => return (out, Some(last)),
                _ => {}
            }
        }
    }
    (out, None)
}

fn reply_rule(condition: Condition, headers: &[(&str, &str)], body: &str, delay_ms: u32) -> Rule {
    Rule {
        id: wiretap_core::RuleId::generate(),
        name: "reply".into(),
        enabled: true,
        condition,
        response: ResponseTemplate {
            headers: headers
                .iter()
                .map(|(n, v)| HttpHeader {
                    name: (*n).into(),
                    value: (*v).into(),
                })
                .collect(),
            body: Body::Text { text: body.into() },
            delay_ms,
            ..ResponseTemplate::ok()
        },
        group: String::new(),
        redirect: None,
    }
}

fn path_is(path: &str) -> Condition {
    Condition::Path(Text {
        op: Op::Equals,
        value: path.into(),
        case_sensitive: true,
    })
}

/// HTTP/2 to a host rules target: each stream is answered by a rule, redirected (to an
/// HTTP/1.1 server), or forwarded; the origin never sees the answered or redirected requests.
/// A rule on the body decides once the body arrived (in two DATA frames here).
#[test]
fn http2_rules_answer_redirect_and_forward_streams() {
    let ((origin, seen), up) = (h2_origin(), upstream());
    let hooks = Arc::new(TestHooks::default());
    let secret = Condition::Body(Text {
        op: Op::Contains,
        value: "secret".into(),
        case_sensitive: true,
    });
    let mut moved = reply_rule(path_is("/hello"), &[], "", 0);
    moved.redirect = Some(Redirect {
        to: format!("http://{}", up.addr),
        keep_host: false,
    });
    hooks.set_rules(vec![
        reply_rule(path_is("/mocked"), &[("X-Mock", "yes")], "mocked!", 0),
        moved,
        reply_rule(secret, &[], "caught", 0),
    ]);
    *hooks.redirect.lock().unwrap() = Some(origin);
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = |method, path| {
        h2_block(&[
            (":method", method),
            (":scheme", "http"),
            (":path", path),
            (":authority", "h2c.test"),
        ])
    };
    let mut wire = wiretap_protocol::http2::PREFACE.to_vec();
    wire.extend(h2_frame(4, 0, 0, &[]));
    wire.extend(h2_frame(1, 0x05, 1, &head("GET", "/mocked")));
    wire.extend(h2_frame(1, 0x05, 3, &head("GET", "/hello")));
    wire.extend(h2_frame(1, 0x05, 5, &head("GET", "/real")));
    wire.extend(h2_frame(1, 0x04, 7, &head("POST", "/gql")));
    wire.extend(h2_frame(0, 0, 7, b"{\"q\":\"sec"));
    wire.extend(h2_frame(0, 0x01, 7, b"ret\"}"));
    wire.extend(h2_frame(1, 0x04, 9, &head("POST", "/gql")));
    wire.extend(h2_frame(0, 0x01, 9, b"{\"q\":\"public\"}"));
    c.write_all(&wire).unwrap();
    let (got, _) = h2_read(&mut c, 5, false);
    let field = |s: u32, name: &str| {
        got[&s]
            .0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    let body = |s: u32| String::from_utf8_lossy(&got[&s].1).into_owned();
    assert_eq!(
        (
            field(1, ":status").as_deref(),
            field(1, "x-mock").as_deref(),
            body(1).as_str()
        ),
        (Some("200"), Some("yes"), "mocked!")
    );
    assert_eq!(body(3), "hello", "redirected to the HTTP/1.1 server");
    assert_eq!(
        (field(5, "x-served-by").as_deref(), body(5).as_str()),
        (Some("origin"), "/real")
    );
    assert_eq!(body(7), "caught", "decided on the whole body");
    assert_eq!(body(9), "/gql", "the other body is forwarded");
    let mut asked = seen.lock().unwrap().clone();
    asked.sort();
    assert_eq!(
        asked,
        ["/gql", "/real"],
        "the origin never sees answered or redirected requests"
    );
    assert_eq!(up.requests.lock().unwrap().len(), 1);
    drop(c);
    let deadline = Instant::now() + Duration::from_secs(10);
    let tagged = |path: &str, tag: &str| {
        hooks.recorded.lock().unwrap().iter().any(|x| {
            x.flow.request.as_ref().is_some_and(|r| {
                r.url == format!("http://h2c.test{path}") && r.version == HttpVersion::Http2
            }) && x.flow.tags.iter().any(|t| t == tag)
                && x.flow.timing.response_complete.is_some()
        })
    };
    while !(tagged("/mocked", "auto-reply") && tagged("/hello", "redirect"))
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        tagged("/mocked", "auto-reply") && tagged("/hello", "redirect") && tagged("/real", "h2")
    );
}

/// A rule added while an app keeps an HTTP/2 connection open: the relayed connection asks the
/// app (graceful GOAWAY, no stream refused) to open a new one, which the rules then apply to.
#[test]
fn new_rules_move_open_http2_connections() {
    let (origin, _) = h2_origin();
    let hooks = Arc::new(TestHooks::default());
    *hooks.redirect.lock().unwrap() = Some(origin);
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut wire = wiretap_protocol::http2::PREFACE.to_vec();
    wire.extend(h2_frame(4, 0, 0, &[]));
    c.write_all(&wire).unwrap();
    thread::sleep(Duration::from_millis(300)); // relayed: no rule yet
    hooks.set_rules(vec![reply_rule(path_is("/mocked"), &[], "mocked!", 0)]);
    let (_, goaway) = h2_read(&mut c, 0, true);
    assert_eq!(
        goaway,
        Some(0x7FFF_FFFF),
        "graceful: no open stream refused"
    );
}

/// A rule's delay holds only its own stream: the other requests of the connection go on.
#[test]
fn delayed_http2_replies_do_not_hold_other_streams() {
    let (origin, _) = h2_origin();
    let hooks = Arc::new(TestHooks::default());
    hooks.set_rules(vec![reply_rule(path_is("/slow"), &[], "late", 800)]);
    *hooks.redirect.lock().unwrap() = Some(origin);
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = |path| {
        h2_block(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", path),
            (":authority", "h2c.test"),
        ])
    };
    let mut wire = wiretap_protocol::http2::PREFACE.to_vec();
    wire.extend(h2_frame(4, 0, 0, &[]));
    wire.extend(h2_frame(1, 0x05, 1, &head("/slow")));
    wire.extend(h2_frame(1, 0x05, 3, &head("/fast")));
    let started = Instant::now();
    c.write_all(&wire).unwrap();
    let (fast, _) = h2_read(&mut c, 1, false);
    assert!(fast.contains_key(&3) && !fast.contains_key(&1), "{fast:?}");
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "{:?}",
        started.elapsed()
    );
    let (slow, _) = h2_read(&mut c, 1, false);
    assert_eq!(slow[&1].1, b"late");
    assert!(started.elapsed() >= Duration::from_millis(800));
}

/// TLS for paths that must never decrypt: every use fails.
struct NoTls;

impl Tls for NoTls {
    fn accept(&self, _: TcpStream, _: &str, _: Vec<u8>, _: &[&str]) -> io::Result<Box<dyn Stream>> {
        Err(io::Error::other("must not intercept"))
    }
    fn connect(&self, _: TcpStream, _: &str, _: &[&str]) -> io::Result<Box<dyn Stream>> {
        Err(io::Error::other("must not intercept"))
    }
}

/// A TLS server stand-in: answers each ClientHello with a TLS 1.3 ServerHello
/// (`TLS_AES_128_GCM_SHA256`), then echoes what follows. Returns its address and the hello.
fn tls13_server() -> (SocketAddr, Vec<u8>) {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[9; 32]); // random
    body.extend_from_slice(&[0, 0x13, 0x01, 0, 0, 6, 0, 43, 0, 2, 3, 4]); // suite, supported_versions
    let len = u8::try_from(body.len()).unwrap();
    let hello = [&[22, 3, 3, 0, len + 4, 2, 0, 0, len][..], &body].concat();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    let reply = hello.clone();
    thread::spawn(move || {
        for mut s in server.incoming().flatten() {
            let mut buf = [0u8; 4096];
            if s.read(&mut buf).unwrap_or(0) == 0 || s.write_all(&reply).is_err() {
                continue;
            }
            let mut data = [0u8; 4];
            if s.read_exact(&mut data).is_ok() {
                let _ = s.write_all(&data);
            }
        }
    });
    (addr, hello)
}

/// Sends `hello` through the (redirecting) proxy, then 4 bytes; returns what came back.
fn tls_through(proxy: &Handle, hello: &[u8], reply: usize) -> Vec<u8> {
    let mut c = TcpStream::connect(proxy.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(hello).unwrap();
    let mut back = vec![0u8; reply + 4];
    c.read_exact(&mut back[..reply]).unwrap();
    c.write_all(b"data").unwrap();
    c.read_exact(&mut back[reply..]).unwrap();
    back
}

/// Apps known to pin their certificates are relayed untouched from their first connection,
/// and relayed connections are still described: the cleartext handshake, the bytes each way
/// and why nothing was decrypted.
#[test]
fn pinned_apps_are_relayed_untouched_and_described() {
    let (server, server_hello) = tls13_server();
    let hooks = Arc::new(TestHooks::default());
    *hooks.redirect.lock().unwrap() = Some(server);
    *hooks.app.lock().unwrap() = Some("MsMpEng.exe");
    *hooks.tls.lock().unwrap() = Some(Arc::new(NoTls)); // decryption on, never used
    let p = proxy(&hooks);
    let hello = client_hello("pinned.test", &[]);
    let back = tls_through(&p, &hello, server_hello.len());
    assert_eq!(back, [&server_hello[..], b"data"].concat(), "untouched");
    let open = hooks.wait_recorded(1).remove(0).flow;
    for tag in ["tunnel", "passthrough", "pinned"] {
        assert!(open.tags.contains(&tag.into()), "{:?}", open.tags);
    }
    let url = format!("https://pinned.test:{}", server.port());
    assert_eq!(open.request.as_ref().unwrap().url, url);
    let events = hooks.wait_events(2);
    let [(handshake, ..), (closed, ..)] = &events[..] else {
        panic!("{events:?}")
    };
    for e in [handshake, closed] {
        assert_eq!(
            (e.protocol, e.metadata.inspection, e.metadata.flow_id),
            (Protocol::Tls, Inspection::Metadata, Some(open.id))
        );
        assert_eq!(attribute(e, "relay.reason"), "pinned");
    }
    assert_eq!(attribute(handshake, "tls.sni"), "pinned.test");
    assert_eq!(attribute(handshake, "tls.version"), "TLS 1.3");
    assert_eq!(
        attribute(handshake, "tls.cipher_suite"),
        "TLS_AES_128_GCM_SHA256"
    );
    assert_eq!(
        attribute(closed, "relay.sent"),
        (hello.len() + 4).to_string()
    );
    assert_eq!(
        attribute(closed, "relay.received"),
        (server_hello.len() + 4).to_string()
    );

    // With HTTPS decryption off, connections are described the same way, named by their SNI.
    *hooks.tls.lock().unwrap() = None;
    *hooks.app.lock().unwrap() = None;
    let hello = client_hello("plain.test", &["h2", "http/1.1"]);
    tls_through(&p, &hello, server_hello.len());
    let events = hooks.wait_events(4);
    let off: Vec<_> = events[2..].iter().map(|(e, ..)| e).collect();
    assert!(off.iter().all(|e| attribute(e, "relay.reason") == "off"));
    assert_eq!(attribute(off[0], "tls.alpn_offered"), "h2,http/1.1");
    let flow = hooks
        .wait_recorded(4)
        .into_iter()
        .map(|x| x.flow)
        .find(|f| f.request.as_ref().unwrap().url.contains("plain.test"))
        .unwrap();
    assert!(
        !flow
            .tags
            .iter()
            .any(|t| t == "passthrough" || t == "pinned")
    );

    // Services (and other users' apps) do not trust the per-user Wiretap root: relayed too.
    *hooks.tls.lock().unwrap() = Some(Arc::new(NoTls));
    hooks.foreign.store(true, Ordering::SeqCst);
    let hello = client_hello("update.test", &[]);
    tls_through(&p, &hello, server_hello.len());
    let events = hooks.wait_events(6);
    assert!(
        events[4..]
            .iter()
            .all(|(e, ..)| attribute(e, "relay.reason") == "service"),
        "{events:?}"
    );
    let flow = hooks
        .wait_recorded(5)
        .into_iter()
        .map(|x| x.flow)
        .find(|f| f.request.as_ref().unwrap().url.contains("update.test"))
        .unwrap();
    assert!(flow.tags.contains(&"passthrough".into()), "{:?}", flow.tags);
}

/// Stopping a capture stops its listener; the exchanges already open go on until an endpoint
/// ends them, however long the server takes (a long poll here). Clients that stop waiting end
/// their server connection too.
#[test]
fn stopped_captures_let_open_exchanges_finish() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let hooks = Arc::new(TestHooks::default());
    *hooks.redirect.lock().unwrap() = Some(server.local_addr().unwrap());
    let proxy = proxy(&hooks);
    let transparent = proxy.transparent().unwrap();
    assert_ne!(transparent.port_v4(), proxy.addr().port());
    let ask = |c: &mut TcpStream| {
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"GET /poll HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap();
        let (mut s, _) = server.accept().unwrap();
        let _ = read_head(&mut s).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s
    };
    let connect = || TcpStream::connect(("127.0.0.1", transparent.port_v4())).unwrap();
    let mut s = ask(&mut connect()); // the client leaves at once
    let mut buf = [0u8; 16];
    assert_eq!(s.read(&mut buf).unwrap_or(1), 0, "the server sees the end");
    let flow = hooks.wait_recorded(1).remove(0).flow;
    assert!(flow.tags.contains(&"client-gone".into()), "{:?}", flow.tags);

    let mut c = connect();
    let mut s = ask(&mut c);
    transparent.close();
    thread::sleep(Duration::from_millis(800)); // quiet for several polls
    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .unwrap();
    let mut reply = String::new();
    let _ = c.read_to_string(&mut reply);
    assert!(
        reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("ok"),
        "{reply}"
    );
    // The explicit proxy keeps working (these test hooks report every connection as redirected).
    *hooks.redirect.lock().unwrap() = None;
    assert!(
        send(
            &proxy,
            b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
        )
        .starts_with("HTTP/1.1 502")
    );
}

/// HTTP/2 connections of a stopped capture are asked to move (graceful GOAWAY: new requests go
/// straight to the server, open streams finish), relayed or terminated alike.
#[test]
fn stopped_captures_move_http2_connections_gracefully() {
    for terminated in [false, true] {
        let (origin, _) = h2_origin();
        let hooks = Arc::new(TestHooks::default());
        if terminated {
            hooks.set_rules(vec![reply_rule(path_is("/mocked"), &[], "mocked!", 0)]);
        }
        *hooks.redirect.lock().unwrap() = Some(origin);
        let proxy = proxy(&hooks);
        let transparent = proxy.transparent().unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", transparent.port_v4())).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut wire = wiretap_protocol::http2::PREFACE.to_vec();
        wire.extend(h2_frame(4, 0, 0, &[]));
        let head = h2_block(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/real"),
            (":authority", "h2c.test"),
        ]);
        wire.extend(h2_frame(1, 0x05, 1, &head));
        c.write_all(&wire).unwrap();
        let (answered, _) = h2_read(&mut c, 1, false);
        assert!(answered.contains_key(&1), "{answered:?}");
        transparent.close();
        let (_, goaway) = h2_read(&mut c, 0, true);
        assert_eq!(goaway, Some(0x7FFF_FFFF), "terminated: {terminated}");
    }
}

/// Event streams stay open while both ends do, through any silence, and end when the client
/// leaves (its server connection is closed too).
#[test]
fn quiet_event_streams_last_until_an_end_leaves() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, closed) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = read_head(&mut s).unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: one\n\n")
            .unwrap();
        thread::sleep(Duration::from_millis(800)); // quiet for several polls
        s.write_all(b"data: two\n\n").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 16];
        tx.send(s.read(&mut buf).unwrap_or(1)).unwrap();
    });
    let hooks = Arc::new(TestHooks::default());
    let p = proxy(&hooks);
    let mut c = TcpStream::connect(p.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        c,
        "GET http://{addr}/events HTTP/1.1\r\nHost: {addr}\r\n\r\n"
    )
    .unwrap();
    let events = hooks.wait_events(2);
    assert_eq!(events[1].1, b"two");
    drop(c);
    assert_eq!(
        closed.recv_timeout(Duration::from_secs(5)),
        Ok(0),
        "the server sees the end"
    );
    let flow = hooks.wait_recorded(2).remove(1).flow;
    assert!(flow.timing.response_complete.is_some(), "closed");
}
/// Redirected connections are shown in the connections list as the driver shows the others: the
/// app's endpoint and its real destination at once (TCP), then the ClientHello (TLS), live.
#[test]
fn redirected_connections_are_described_for_the_connections_list() {
    let (server, server_hello) = tls13_server();
    let hooks = Arc::new(TestHooks::default());
    *hooks.redirect.lock().unwrap() = Some(server);
    let p = proxy(&hooks);
    let hello = client_hello("shop.test", &["h2"]);
    tls_through(&p, &hello, server_hello.len());
    let deadline = Instant::now() + Duration::from_secs(10);
    while hooks.connections.lock().unwrap().len() < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let seen = hooks.connections.lock().unwrap().clone();
    let protocols: Vec<_> = seen.iter().map(|e| e.protocol).collect();
    assert_eq!(protocols, [Protocol::Tcp, Protocol::Tls], "{seen:?}");
    assert!(seen.iter().all(|e| {
        e.source == CaptureSource::TransparentProxy
            && e.remote_endpoint
                .is_some_and(|r| r.port == Some(server.port()))
            && e.process.as_ref().and_then(|p| p.name.as_deref()) == Some("msedge.exe")
    }));
    assert_eq!(attribute(&seen[1], "tls.sni"), "shop.test");
}
#[test]
fn connect_tunnels_relay_bytes() {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        let (mut s, _) = echo.accept().unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        s.write_all(&buf).unwrap();
    });
    let hooks = Arc::new(TestHooks::default());
    let p = proxy(&hooks);
    let mut s = TcpStream::connect(p.addr()).unwrap();
    s.write_all(format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .unwrap();
    let mut reply = [0u8; 39];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    s.write_all(b"ping").unwrap();
    let mut echoed = [0u8; 4];
    s.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"ping");
    drop(s);
    let flow = hooks.wait_recorded(1).remove(0).flow;
    assert!(flow.tags.contains(&"tunnel".into()));
    assert_eq!(flow.request.unwrap().url, format!("https://{addr}"));
}

#[test]
fn errors_are_reported_and_recorded() {
    let hooks = Arc::new(TestHooks::default());
    let p = proxy(&hooks);
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap(); // listener dropped
    let unreachable = send(
        &p,
        format!("GET http://{closed}/ HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
    );
    assert!(
        unreachable.starts_with("HTTP/1.1 502 Bad Gateway")
            && unreachable.contains("cannot connect"),
        "{unreachable}"
    );
    let looped = send(
        &p,
        format!("GET http://{}/ HTTP/1.1\r\nHost: x\r\n\r\n", p.addr()).as_bytes(),
    );
    assert!(looped.contains("loops back"), "{looped}");
    let origin_form = send(&p, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        origin_form.starts_with("HTTP/1.1 502") && origin_form.contains("absolute"),
        "{origin_form}"
    );
    let malformed = send(&p, b"GET http://x/ HTTP/1.1\r\nBad Header\r\n\r\n");
    assert!(malformed.starts_with("HTTP/1.1 400"), "{malformed}");
    let huge = send(
        &p,
        format!(
            "POST http://{closed}/ HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY + 1
        )
        .as_bytes(),
    );
    assert!(huge.contains("too large"), "{huge}");
    let recorded = hooks.wait_recorded(4);
    assert!(
        recorded
            .iter()
            .all(|e| e.flow.tags.contains(&"proxy-error".into()))
    );
}

/// A minimal TLS 1.2 ClientHello record offering one suite, with SNI `host`.
fn client_hello(host: &str, alpn: &[&str]) -> Vec<u8> {
    let name = host.as_bytes();
    let n = u16::try_from(name.len()).unwrap();
    let mut sni = vec![0u8];
    sni.extend_from_slice(&n.to_be_bytes());
    sni.extend_from_slice(name);
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(u16::try_from(sni.len()).unwrap() + 2).to_be_bytes());
    ext.extend_from_slice(&u16::try_from(sni.len()).unwrap().to_be_bytes());
    ext.extend_from_slice(&sni);
    if !alpn.is_empty() {
        let list: Vec<u8> = alpn
            .iter()
            .flat_map(|p| std::iter::once(u8::try_from(p.len()).unwrap()).chain(p.bytes()))
            .collect();
        ext.extend_from_slice(&[0, 0x10]);
        ext.extend_from_slice(&(u16::try_from(list.len()).unwrap() + 2).to_be_bytes());
        ext.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
        ext.extend_from_slice(&list);
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]); // random
    body.extend_from_slice(&[0, 0, 2, 0xC0, 0x2F, 1, 0]); // session id, one suite, null compression
    body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&ext);
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut handshake = vec![1, len[1], len[2], len[3]];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&handshake);
    assert!(
        matches!(parse_client_hello(&record), Parse::Complete(h) if h.server_name.as_deref() == Some(host))
    );
    record
}

#[cfg(windows)]
mod https {
    use wiretap_tls::{Authority, Upstream as TlsClient};

    use super::*;

    /// A throwaway CA with its own CNG keys. Never trusted by Windows; its keys are deleted by
    /// [`Cleanup`] even while server threads still hold it.
    struct TestCa(Authority, String);
    impl TestCa {
        fn new() -> Self {
            let name = format!("Wiretap Test {}", FlowId::generate());
            Self(Authority::open(&name).unwrap(), name)
        }
        fn get(&self) -> &Authority {
            &self.0
        }
    }
    /// Deletes the named test keys when the test ends (also on failure).
    struct Cleanup(Vec<String>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for name in &self.0 {
                let _ = Authority::open(name).and_then(Authority::delete);
            }
        }
    }
    /// A decrypted TLS side as a proxy [`Stream`] (timeouts go to its own socket).
    struct Side(wiretap_tls::TlsStream);

    impl Read for Side {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Side {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl Stream for Side {
        fn socket(&self) -> &TcpStream {
            self.0.socket()
        }
        fn alpn(&self) -> Option<&str> {
            self.0.alpn()
        }
    }
    struct Interceptor {
        ca: Arc<TestCa>,
        upstream: TlsClient,
    }
    impl Tls for Interceptor {
        fn accept(
            &self,
            client: TcpStream,
            host: &str,
            hello: Vec<u8>,
            alpn: &[&str],
        ) -> io::Result<Box<dyn Stream>> {
            Ok(Box::new(Side(
                self.ca.get().accept(client, host, hello, alpn)?,
            )))
        }
        fn connect(
            &self,
            server: TcpStream,
            host: &str,
            alpn: &[&str],
        ) -> io::Result<Box<dyn Stream>> {
            Ok(Box::new(Side(self.upstream.connect(server, host, alpn)?)))
        }
    }

    /// HTTPS server for `localhost`: answers with the request line and body it received.
    fn https_server(ca: &Arc<TestCa>) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ca, hits) = (Arc::clone(ca), Arc::new(AtomicUsize::new(0)));
        let count = Arc::clone(&hits);
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                count.fetch_add(1, Ordering::SeqCst);
                let Ok(mut tls) = ca.get().accept(tcp, "localhost", Vec::new(), &[]) else {
                    continue;
                };
                // Like a real server, tolerate connections that close without a request
                // (Wiretap's verification attempts, clients refusing a certificate).
                let Ok((head, mut body)) = read_head(&mut tls) else {
                    continue;
                };
                let Some(Framing::Length(n)) = framing(&head, None) else {
                    panic!()
                };
                while body.len() < usize::try_from(n).unwrap() {
                    let mut b = [0u8; 1024];
                    let k = tls.read(&mut b).unwrap();
                    body.extend_from_slice(&b[..k]);
                }
                let StartLine::Request { method, target, .. } = &head.start else {
                    panic!()
                };
                let reply = format!(
                    "{{\"seen\":\"{method} {target}\",\"body\":{}}}",
                    String::from_utf8_lossy(&body)
                );
                let _ = write!(
                    tls,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}",
                    reply.len()
                );
            }
        });
        (addr, hits)
    }

    /// CONNECTs through the proxy, then speaks TLS trusting only `root`.
    fn https_request(
        proxy: &Handle,
        server: SocketAddr,
        root: &[u8],
        request: &str,
    ) -> io::Result<String> {
        let mut tcp = TcpStream::connect(proxy.addr())?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
        write!(
            tcp,
            "CONNECT localhost:{0} HTTP/1.1\r\nHost: localhost:{0}\r\n\r\n",
            server.port()
        )?;
        let mut established = [0u8; 39];
        tcp.read_exact(&mut established)?;
        assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let mut tls = TlsClient::trusting(root)?.connect(tcp, "localhost", &[])?;
        tls.write_all(request.as_bytes())?;
        Ok(read_response(&mut tls, request.starts_with("HEAD ")))
    }

    /// The WebSocket lab over wss:// through HTTPS decryption, in every version.
    #[test]
    fn websocket_lab_over_tls_is_decrypted_in_every_version() {
        use crate::wslab::{Client, Io, run, serve};
        let (server_ca, proxy_ca) = (Arc::new(TestCa::new()), Arc::new(TestCa::new()));
        let _cleanup = Cleanup(vec![server_ca.1.clone(), proxy_ca.1.clone()]);
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let ca = Arc::clone(&server_ca);
        let wrap: crate::wslab::Wrap = Arc::new(move |tcp, host| {
            Ok(Box::new(ca.get().accept(tcp, host, Vec::new(), &[])?) as Box<dyn Io>)
        });
        thread::spawn(move || serve(server, Some((wrap, "localhost".into()))));
        let hooks = Arc::new(TestHooks::default());
        *hooks.tls.lock().unwrap() = Some(Arc::new(Interceptor {
            ca: Arc::clone(&proxy_ca),
            upstream: TlsClient::trusting(server_ca.get().certificate()).unwrap(),
        }));
        let p = proxy(&hooks);
        let trust = Arc::new(TlsClient::trusting(proxy_ca.get().certificate()).unwrap());
        let tls: crate::wslab::Wrap =
            Arc::new(move |tcp, host| Ok(Box::new(trust.connect(tcp, host, &[])?) as Box<dyn Io>));
        for (version, deflate) in [(13, true), (8, false)] {
            let client = Client {
                url: format!("wss://localhost:{port}/secure"),
                proxy: Some(p.addr().to_string()),
                deflate,
                version,
                tls: Some(Arc::clone(&tls)),
            };
            run(&client).unwrap_or_else(|e| panic!("wss version {version}: {e}"));
        }
        let events = hooks.wait_events(30);
        assert_eq!(events.len(), 30);
        assert!(
            events
                .iter()
                .all(|(e, ..)| !e.metadata.attributes.contains_key("problem")
                    && !e.metadata.attributes.contains_key("error"))
        );
        let flow = hooks.wait_recorded(1).remove(0).flow;
        assert_eq!(
            flow.request.unwrap().url,
            format!("https://localhost:{port}/secure")
        );
    }

    /// WebSockets over decrypted TLS (how browsers reach `wss://` sites through Wiretap).
    #[test]
    fn websockets_over_decrypted_tls_are_recorded() {
        let (server_ca, proxy_ca) = (Arc::new(TestCa::new()), Arc::new(TestCa::new()));
        let _cleanup = Cleanup(vec![server_ca.1.clone(), proxy_ca.1.clone()]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let ca = Arc::clone(&server_ca);
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let Ok(mut tls) = ca.get().accept(tcp, "localhost", Vec::new(), &[]) else {
                    continue;
                };
                let Ok(_) = read_head(&mut tls) else { continue };
                tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").unwrap();
                let mut frame = [0u8; 11];
                tls.read_exact(&mut frame).unwrap();
                tls.write_all(b"\x81\x05Hello").unwrap();
                thread::sleep(Duration::from_millis(300));
            }
        });
        let hooks = Arc::new(TestHooks::default());
        *hooks.tls.lock().unwrap() = Some(Arc::new(Interceptor {
            ca: Arc::clone(&proxy_ca),
            upstream: TlsClient::trusting(server_ca.get().certificate()).unwrap(),
        }));
        let p = proxy(&hooks);
        let mut tcp = TcpStream::connect(p.addr()).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            tcp,
            "CONNECT localhost:{0} HTTP/1.1\r\nHost: localhost:{0}\r\n\r\n",
            server.port()
        )
        .unwrap();
        let mut established = [0u8; 39];
        tcp.read_exact(&mut established).unwrap();
        let mut tls = TlsClient::trusting(proxy_ca.get().certificate())
            .unwrap()
            .connect(tcp, "localhost", &[])
            .unwrap();
        write!(tls, "GET /socket HTTP/1.1\r\nHost: localhost:{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", server.port()).unwrap();
        let (head, _) = read_head(&mut tls).unwrap();
        assert!(matches!(
            head.start,
            StartLine::Response { status: 101, .. }
        ));
        let open = hooks.wait_recorded(1).remove(0).flow;
        assert!(open.tags.contains(&"websocket".into()), "{:?}", open.tags);
        tls.write_all(&[
            0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58,
        ])
        .unwrap();
        let mut echo = [0u8; 7];
        tls.read_exact(&mut echo).unwrap();
        let events = hooks.wait_events(2);
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(
            events
                .iter()
                .all(|(e, payload, _)| e.metadata.flow_id == Some(open.id) && payload == b"Hello")
        );
    }

    #[test]
    fn https_is_decrypted_recorded_with_bodies_and_auto_replied() {
        let (server_ca, proxy_ca) = (Arc::new(TestCa::new()), Arc::new(TestCa::new()));
        let _cleanup = Cleanup(vec![server_ca.1.clone(), proxy_ca.1.clone()]);
        let (server, hits) = https_server(&server_ca);
        let hooks = Arc::new(TestHooks::default());
        *hooks.tls.lock().unwrap() = Some(Arc::new(Interceptor {
            ca: Arc::clone(&proxy_ca),
            upstream: TlsClient::trusting(server_ca.get().certificate()).unwrap(),
        }));
        let p = proxy(&hooks);
        let root = proxy_ca.get().certificate().to_vec();

        // A decrypted round trip: the client only trusts the Wiretap (proxy) root.
        let body = r#"{"user":"ada"}"#;
        let request = format!(
            "POST /api/login?x=1 HTTP/1.1\r\nHost: localhost:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            server.port(),
            body.len()
        );
        let response = https_request(&p, server, &root, &request).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.ends_with(r#"{"seen":"POST /api/login?x=1","body":{"user":"ada"}}"#),
            "{response}"
        );
        let [exchange] = &hooks.wait_recorded(1)[..] else {
            panic!("one exchange")
        };
        let request = exchange.flow.request.as_ref().unwrap();
        assert_eq!(
            (request.method.as_str(), request.url.as_str()),
            (
                "POST",
                format!("https://localhost:{}/api/login?x=1", server.port()).as_str()
            )
        );
        assert!(
            exchange.flow.tags.contains(&"decrypted".into()),
            "{:?}",
            exchange.flow.tags
        );
        assert_eq!(exchange.request_body, body.as_bytes());
        assert!(
            String::from_utf8_lossy(&exchange.response_body)
                .contains(r#""seen":"POST /api/login?x=1""#)
        );
        assert_eq!(exchange.flow.response.as_ref().unwrap().status, 200);

        // Auto-replies apply to HTTPS too, without contacting the server.
        let mut rule =
            wiretap_autoreply::Rule::from_flow(&exchange.flow, Some(b"{\"mocked\":true}")).unwrap();
        rule.condition = Condition::Url(Text {
            op: Op::Contains,
            value: "/mock".into(),
            case_sensitive: false,
        });
        hooks.set_rules(vec![rule]);
        let before = hits.load(Ordering::SeqCst);
        let mocked = https_request(
            &p,
            server,
            &root,
            &format!(
                "GET /mock HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
                server.port()
            ),
        )
        .unwrap();
        assert!(mocked.ends_with("{\"mocked\":true}"), "{mocked}");
        assert_eq!(hits.load(Ordering::SeqCst), before, "answered by the rule");
        assert!(
            hooks.wait_recorded(2)[1]
                .flow
                .tags
                .contains(&"auto-reply".into())
        );

        // A client that does not trust the Wiretap root hangs up right after the handshake. This
        // application already sent requests through it, so that is no refusal: however often it
        // happens, its next connections are still decrypted.
        for _ in 0..3 {
            let hang_up = https_request(
                &p,
                server,
                server_ca.get().certificate(),
                "GET / HTTP/1.1\r\n\r\n",
            );
            assert!(hang_up.is_err());
        }
        let recorded = hooks.wait_recorded(5);
        assert!(
            recorded[2..5]
                .iter()
                .all(|x| x.flow.tags.contains(&"client-closed".into()))
        );
        let again = https_request(
            &p,
            server,
            &root,
            "POST /again HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert!(again.contains(r#""seen":"POST /again""#), "{again}");
        assert!(
            hooks.wait_recorded(6)[5]
                .flow
                .tags
                .contains(&"decrypted".into())
        );
    }

    /// An application that never got a request through the Wiretap certificate and hangs up
    /// right after the handshake twice in a row is treated as refusing it: its next connections
    /// meet the real server untouched.
    #[test]
    fn repeated_hang_ups_from_new_clients_are_refusals() {
        let (server_ca, proxy_ca) = (Arc::new(TestCa::new()), Arc::new(TestCa::new()));
        let _cleanup = Cleanup(vec![server_ca.1.clone(), proxy_ca.1.clone()]);
        let (server, _) = https_server(&server_ca);
        let hooks = Arc::new(TestHooks::default());
        *hooks.tls.lock().unwrap() = Some(Arc::new(Interceptor {
            ca: Arc::clone(&proxy_ca),
            upstream: TlsClient::trusting(server_ca.get().certificate()).unwrap(),
        }));
        let p = proxy(&hooks);
        let real_root = server_ca.get().certificate();
        let hang_up =
            || assert!(https_request(&p, server, real_root, "GET / HTTP/1.1\r\n\r\n").is_err());
        hang_up();
        assert!(
            hooks.wait_recorded(1)[0]
                .flow
                .tags
                .contains(&"client-closed".into()),
            "one hang-up is not a refusal"
        );
        hang_up();
        let refused = hooks.wait_recorded(2).remove(1).flow;
        assert!(
            refused.tags.contains(&"tls-error".into()),
            "{:?}",
            refused.tags
        );
        let direct = https_request(
            &p,
            server,
            real_root,
            "POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert!(direct.contains(r#""seen":"POST /x""#), "{direct}");
        assert!(
            hooks.wait_recorded(3)[2]
                .flow
                .tags
                .contains(&"passthrough".into())
        );
    }
    /// Decrypted HTTP/2: Wiretap offers the server what the client offered, gives the client
    /// the server's choice (h2), relays the frames untouched and records every stream. Hosts an
    /// auto-reply rule targets stay HTTP/1.1, so rules can answer.
    #[test]
    fn decrypted_http2_is_negotiated_relayed_and_recorded() {
        let (server_ca, proxy_ca) = (Arc::new(TestCa::new()), Arc::new(TestCa::new()));
        let _cleanup = Cleanup(vec![server_ca.1.clone(), proxy_ca.1.clone()]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let script = h2_script("https", &format!("localhost:{port}"));
        let (ca, server_script) = (Arc::clone(&server_ca), script.clone());
        let served = AtomicBool::new(false);
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let Ok(tls) = ca.get().accept(tcp, "localhost", Vec::new(), &["h2"]) else {
                    continue;
                };
                assert_eq!(
                    tls.alpn(),
                    Some("h2"),
                    "Wiretap offers the client's protocols"
                );
                let mut side = Side(tls);
                side.socket()
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                // The scripted connection first, then an origin answering by path.
                if served.swap(true, Ordering::SeqCst) {
                    h2_answer(&mut side, &Mutex::default());
                } else {
                    h2_serve(&mut side, &server_script);
                }
            }
        });
        let hooks = Arc::new(TestHooks::default());
        *hooks.tls.lock().unwrap() = Some(Arc::new(Interceptor {
            ca: Arc::clone(&proxy_ca),
            upstream: TlsClient::trusting(server_ca.get().certificate()).unwrap(),
        }));
        let p = proxy(&hooks);
        let connect = || {
            let mut tcp = TcpStream::connect(p.addr()).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            write!(
                tcp,
                "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
            )
            .unwrap();
            let mut established = [0u8; 39];
            tcp.read_exact(&mut established).unwrap();
            TlsClient::trusting(proxy_ca.get().certificate())
                .unwrap()
                .connect(tcp, "localhost", &["h2", "http/1.1"])
                .unwrap()
        };
        let tls = connect();
        assert_eq!(tls.alpn(), Some("h2"), "the server's choice");
        let mut side = Side(tls);
        h2_talk(&mut side, &script);
        drop(side);
        let base = format!("https://localhost:{port}");
        assert_h2_recorded(&hooks, &base);
        let get = hooks
            .wait_recorded(1)
            .into_iter()
            .find(|x| {
                x.flow
                    .request
                    .as_ref()
                    .is_some_and(|r| r.url == format!("{base}/a"))
            })
            .unwrap();
        assert!(
            get.flow.tags.contains(&"decrypted".into()),
            "{:?}",
            get.flow.tags
        );
        let mock = Condition::Url(Text {
            op: Op::Contains,
            value: "/mock".into(),
            case_sensitive: false,
        });
        let rule = reply_rule(mock, &[("Content-Type", "text/plain")], "mocked", 0);
        hooks.set_rules(vec![rule]);
        // Hosts rules target are terminated: still HTTP/2, the rule answers its stream and the
        // other one reaches the server.
        let tls = connect();
        assert_eq!(tls.alpn(), Some("h2"));
        let mut side = Side(tls);
        let head = |path| {
            h2_block(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", path),
                (":authority", "localhost"),
            ])
        };
        let mut wire = wiretap_protocol::http2::PREFACE.to_vec();
        wire.extend(h2_frame(4, 0, 0, &[]));
        wire.extend(h2_frame(1, 0x05, 1, &head("/mock")));
        wire.extend(h2_frame(1, 0x05, 3, &head("/other")));
        side.write_all(&wire).unwrap();
        let (got, _) = h2_read(&mut side, 2, false);
        assert_eq!(got[&1].1, b"mocked", "{got:?}");
        assert_eq!(got[&3].1, b"/other", "{got:?}");
    }

    /// Clients offering only protocols Wiretap does not decode (neither HTTP/1.1 nor HTTP/2)
    /// are relayed untouched from the first connection, without contacting the server first.
    #[test]
    fn clients_offering_only_other_protocols_are_relayed_untouched() {
        let proxy_ca = Arc::new(TestCa::new());
        let _cleanup = Cleanup(vec![proxy_ca.1.clone()]);
        let hooks = Arc::new(TestHooks::default());
        *hooks.tls.lock().unwrap() = Some(Arc::new(Interceptor {
            ca: Arc::clone(&proxy_ca),
            upstream: TlsClient::system().unwrap(),
        }));
        let p = proxy(&hooks);
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = echo.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).unwrap();
            s.write_all(&buf[..n]).unwrap();
        });
        let hello = client_hello("mail.test", &["imap"]);
        let mut tcp = TcpStream::connect(p.addr()).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(tcp, "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n").unwrap();
        let mut established = [0u8; 39];
        tcp.read_exact(&mut established).unwrap();
        tcp.write_all(&hello).unwrap();
        let mut back = vec![0u8; hello.len()];
        tcp.read_exact(&mut back).unwrap();
        assert_eq!(back, hello);
        drop(tcp);
        let flow = hooks.wait_recorded(1).remove(0).flow;
        assert!(flow.tags.contains(&"passthrough".into()), "{:?}", flow.tags);
    }

    /// Traffic without an auto-reply always reaches its server: one Wiretap cannot verify is
    /// relayed untouched, so the client meets the real server and decides itself.
    #[test]
    fn servers_that_cannot_be_verified_are_reached_untouched() {
        let (trusted_ca, other_ca, proxy_ca) = (
            Arc::new(TestCa::new()),
            Arc::new(TestCa::new()),
            Arc::new(TestCa::new()),
        );
        let _cleanup = Cleanup(vec![
            trusted_ca.1.clone(),
            other_ca.1.clone(),
            proxy_ca.1.clone(),
        ]);
        let (server, hits) = https_server(&other_ca); // not trusted by the proxy
        let hooks = Arc::new(TestHooks::default());
        *hooks.tls.lock().unwrap() = Some(Arc::new(Interceptor {
            ca: Arc::clone(&proxy_ca),
            upstream: TlsClient::trusting(trusted_ca.get().certificate()).unwrap(),
        }));
        let p = proxy(&hooks);
        let request =
            "POST /self-signed HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}";
        // The client trusts the server's own root, as it would without Wiretap.
        let response = https_request(&p, server, other_ca.get().certificate(), request).unwrap();
        assert!(
            response.contains(r#""seen":"POST /self-signed""#),
            "{response}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "a verification attempt, then the relayed connection"
        );
        let flow = hooks.wait_recorded(1).remove(0).flow;
        assert!(flow.tags.contains(&"passthrough".into()), "{:?}", flow.tags);
    }

    /// Driver-redirected connections: plain HTTP, WebSocket upgrades and TLS, attributed to
    /// the process the driver reported.
    #[test]
    fn redirected_connections_are_recorded_decrypted_and_upgraded() {
        let (server_ca, proxy_ca) = (Arc::new(TestCa::new()), Arc::new(TestCa::new()));
        let _cleanup = Cleanup(vec![server_ca.1.clone(), proxy_ca.1.clone()]);
        let (server, _) = https_server(&server_ca);
        let hooks = Arc::new(TestHooks::default());
        *hooks.tls.lock().unwrap() = Some(Arc::new(Interceptor {
            ca: Arc::clone(&proxy_ca),
            upstream: TlsClient::trusting(server_ca.get().certificate()).unwrap(),
        }));
        let p = proxy(&hooks);
        let redirect = |to: SocketAddr| *hooks.redirect.lock().unwrap() = Some(to);

        // TLS straight to the proxy, as if the app had connected to the server.
        redirect(server);
        let mut tls = TlsClient::trusting(proxy_ca.get().certificate())
            .unwrap()
            .connect(TcpStream::connect(p.addr()).unwrap(), "localhost", &[])
            .unwrap();
        tls.write_all(b"POST /t HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n42")
            .unwrap();
        let out = read_response(&mut tls, false);
        assert!(out.ends_with(r#"{"seen":"POST /t","body":42}"#), "{out}");
        let flow = hooks.wait_recorded(1).remove(0).flow;
        assert_eq!(flow.source, CaptureSource::TransparentProxy);
        assert_eq!(
            flow.request.unwrap().url,
            format!("https://localhost:{}/t", server.port())
        );
        assert_eq!(
            flow.process.unwrap().name.as_deref(),
            Some("msedge.exe"),
            "from the driver"
        );

        // A WebSocket upgrade over plain HTTP: 101, then frames relayed both ways.
        let ws = TcpListener::bind("127.0.0.1:0").unwrap();
        let ws_addr = ws.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = ws.accept().unwrap();
            let (head, _) = read_head(&mut s).unwrap();
            assert_eq!(head.header("upgrade"), Some("websocket"));
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").unwrap();
            let mut frame = [0u8; 4];
            s.read_exact(&mut frame).unwrap();
            s.write_all(&frame).unwrap();
        });
        redirect(ws_addr);
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"GET /chat HTTP/1.1\r\nHost: chat.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").unwrap();
        let (head, _) = read_head(&mut c).unwrap();
        assert!(matches!(
            head.start,
            StartLine::Response { status: 101, .. }
        ));
        c.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        c.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");
        drop(c);
        let flow = hooks.wait_recorded(2).remove(1).flow;
        assert!(flow.tags.contains(&"websocket".into()), "{:?}", flow.tags);
        assert_eq!(flow.request.unwrap().url, "http://chat.test/chat");
    }
}
