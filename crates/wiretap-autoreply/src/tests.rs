use std::net::IpAddr;

use wiretap_core::{
    CaptureSource, Flow, FlowId, FlowTiming, HttpHeader, HttpRequest, HttpResponse, HttpVersion,
    SessionId, Timestamp,
};

use super::*;

fn header(name: &str, value: &str) -> HttpHeader {
    HttpHeader {
        name: name.into(),
        value: value.into(),
    }
}

fn text(op: Op, value: &str) -> Text {
    Text {
        op,
        value: value.into(),
        case_sensitive: false,
    }
}

fn rule(name: &str, condition: Condition, status: u16) -> Rule {
    Rule {
        id: RuleId::generate(),
        name: name.into(),
        enabled: true,
        group: String::new(),
        redirect: None,
        condition,
        response: ResponseTemplate {
            status,
            ..ResponseTemplate::ok()
        },
    }
}

struct Req {
    method: &'static str,
    url: &'static str,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
}

impl Req {
    fn get(url: &'static str) -> Self {
        Self {
            method: "GET",
            url,
            headers: vec![header("Host", "api.example.com")],
            body: Vec::new(),
        }
    }
    fn view(&self) -> Request<'_> {
        Request {
            method: self.method,
            url: self.url,
            headers: &self.headers,
            body: &self.body,
            process: Some("chrome.exe"),
            client: Some(IpAddr::from([127, 0, 0, 1])),
            server: Some(IpAddr::from([93, 184, 216, 34])),
        }
    }
}

fn matches(condition: Condition, req: &Req) -> bool {
    RuleSet::new(vec![rule("t", condition, 200)])
        .unwrap()
        .reply(req.view())
        .is_some()
}

#[test]
fn every_field_can_be_matched() {
    let mut req = Req::get("https://API.example.com:8443/v1/items?page=2&sort=asc#frag");
    req.method = "POST";
    req.headers
        .push(header("Content-Type", "application/json; charset=utf-8"));
    req.headers
        .push(header("Cookie", "session=abc123; theme=dark"));
    req.body = br#"{"name":"widget","qty":3}"#.to_vec();
    let yes = [
        Condition::Method(text(Op::Equals, "post")),
        Condition::Url(text(Op::StartsWith, "https://api.example.com")),
        Condition::Host(text(Op::Equals, "api.example.com")),
        Condition::Path(text(Op::Equals, "/v1/items")),
        Condition::Query(text(Op::Contains, "page=2")),
        Condition::Header {
            name: "content-type".into(),
            value: Some(text(Op::Contains, "json")),
        },
        Condition::Header {
            name: "Cookie".into(),
            value: None,
        },
        Condition::Cookie {
            name: "theme".into(),
            value: Some(text(Op::Equals, "dark")),
        },
        Condition::Cookie {
            name: "session".into(),
            value: None,
        },
        Condition::Body(text(Op::Contains, "\"qty\":3")),
        Condition::ContentType(text(Op::StartsWith, "application/json")),
        Condition::Process(text(Op::Equals, "CHROME.EXE")),
        Condition::ClientIp(text(Op::Equals, "127.0.0.1")),
        Condition::ServerIp(text(Op::Wildcard, "93.184.*")),
        Condition::ServerPort(8443),
    ];
    for c in yes {
        assert!(matches(c.clone(), &req), "{c:?}");
    }
    let no = [
        Condition::Method(text(Op::Equals, "GET")),
        Condition::Path(text(Op::Equals, "/v1")),
        Condition::Header {
            name: "X-Missing".into(),
            value: None,
        },
        Condition::Cookie {
            name: "Theme".into(),
            value: None,
        },
        Condition::Body(text(Op::Contains, "gadget")),
        Condition::ServerPort(443),
        Condition::Process(text(Op::Equals, "firefox.exe")),
    ];
    for c in no {
        assert!(!matches(c.clone(), &req), "{c:?}");
    }
}

#[test]
fn url_parts_and_default_ports() {
    let cases = [
        ("http://h/", ("h", 80, "/", "")),
        ("https://h", ("h", 443, "/", "")),
        ("http://user:pw@h:81/p?q", ("h", 81, "/p", "q")),
        ("http://[::1]:8080/x?y=1", ("::1", 8080, "/x", "y=1")),
        ("http://h?only=query", ("h", 80, "/", "only=query")),
    ];
    for (url, expected) in cases {
        assert_eq!(condition::split_url(url), expected, "{url}");
    }
}

#[test]
fn logic_combinators() {
    let req = Req::get("http://api.example.com/a");
    let t = || Condition::Method(text(Op::Equals, "GET"));
    let f = || Condition::Method(text(Op::Equals, "PUT"));
    assert!(
        matches(Condition::All(vec![]), &req),
        "empty AND always holds"
    );
    assert!(
        !matches(Condition::Any(vec![]), &req),
        "empty OR never holds"
    );
    assert!(matches(Condition::All(vec![t(), t()]), &req));
    assert!(!matches(Condition::All(vec![t(), f()]), &req));
    assert!(matches(Condition::Any(vec![f(), t()]), &req));
    assert!(matches(Condition::Not(Box::new(f())), &req));
    assert!(matches(
        Condition::All(vec![
            Condition::Not(Box::new(Condition::Any(vec![f()]))),
            t()
        ]),
        &req
    ));
}

#[test]
fn text_operators_and_case_sensitivity() {
    let req = Req::get("http://api.example.com/Users/42/Profile");
    let path = |op, value: &str, case_sensitive| {
        Condition::Path(Text {
            op,
            value: value.into(),
            case_sensitive,
        })
    };
    assert!(matches(path(Op::Equals, "/users/42/profile", false), &req));
    assert!(!matches(path(Op::Equals, "/users/42/profile", true), &req));
    assert!(matches(path(Op::EndsWith, "/Profile", true), &req));
    assert!(matches(path(Op::Wildcard, "/users/*/profile", false), &req));
    assert!(matches(path(Op::Wildcard, "/users/4?/*", false), &req));
    assert!(!matches(path(Op::Wildcard, "/users/?/*", false), &req));
    assert!(matches(path(Op::Wildcard, "*", false), &req));
    assert!(!matches(path(Op::Wildcard, "", false), &req));
}

#[test]
fn first_enabled_match_wins() {
    let req = Req::get("http://api.example.com/a");
    let mut disabled = rule("disabled", Condition::All(vec![]), 500);
    disabled.enabled = false;
    let specific = rule("specific", Condition::Path(text(Op::Equals, "/a")), 201);
    let catch_all = rule("catch-all", Condition::All(vec![]), 404);
    let set = RuleSet::new(vec![disabled, specific, catch_all.clone()]).unwrap();
    let reply = set.reply(req.view()).unwrap();
    assert_eq!(
        (reply.rule.name.as_str(), reply.response.status),
        ("specific", 201)
    );
    assert_eq!(
        set.matching(req.view()),
        [0, 1, 2],
        "testing reports every matching rule"
    );
    let other = Req::get("http://api.example.com/b");
    assert_eq!(set.reply(other.view()).unwrap().rule.id, catch_all.id);
}

#[test]
fn wildcard_work_is_bounded() {
    let mut req = Req::get("http://h/");
    req.body = vec![b'a'; BODY_MATCH_LIMIT * 2];
    // Pathological pattern: many stars that never match; must give up instead of hanging.
    let pattern = format!("{}b", "*a".repeat(2000));
    let rules = (0..50)
        .map(|i| {
            rule(
                &format!("r{i}"),
                Condition::Body(text(Op::Wildcard, &pattern)),
                200,
            )
        })
        .collect();
    let set = RuleSet::new(rules).unwrap();
    let start = std::time::Instant::now();
    assert!(set.reply(req.view()).is_none());
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "budget did not bound the work"
    );
}

fn captured_flow() -> Flow {
    Flow {
        id: FlowId::generate(),
        session_id: SessionId::generate(),
        source: CaptureSource::ExplicitProxy,
        process: None,
        client: None,
        server: None,
        request: Some(HttpRequest {
            method: "GET".into(),
            url: "http://api.example.com/v1/user?id=7".into(),
            version: HttpVersion::Http11,
            headers: vec![header("Host", "api.example.com")],
            body: None,
        }),
        response: Some(HttpResponse {
            status: 404,
            reason: "Not Found".into(),
            version: HttpVersion::Http11,
            headers: vec![
                header("Content-Type", "application/json"),
                header("Transfer-Encoding", "chunked"),
                header("Set-Cookie", "a=1"),
                header("Connection", "keep-alive"),
            ],
            body: None,
        }),
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
fn rule_from_flow_defaults_to_the_original_response() {
    let flow = captured_flow();
    let rule = Rule::from_flow(&flow, Some(br#"{"error":"missing"}"#)).unwrap();
    assert_eq!(rule.name, "GET http://api.example.com/v1/user?id=7");
    let t = &rule.response;
    assert_eq!((t.status, t.reason.as_str()), (404, "Not Found"));
    assert_eq!(
        t.headers,
        [
            header("Content-Type", "application/json"),
            header("Set-Cookie", "a=1")
        ],
        "framing headers dropped"
    );
    assert_eq!(
        t.body,
        Body::Text {
            text: r#"{"error":"missing"}"#.into()
        }
    );

    let set = RuleSet::new(vec![rule]).unwrap();
    let same = Req {
        method: "GET",
        url: "http://api.example.com/v1/user?id=7",
        headers: vec![],
        body: vec![],
    };
    let reply = set.reply(same.view()).unwrap();
    assert_eq!(reply.response.body, br#"{"error":"missing"}"#);
    let different = Req {
        method: "GET",
        url: "http://api.example.com/v1/user?id=8",
        headers: vec![],
        body: vec![],
    };
    assert!(
        set.reply(different.view()).is_none(),
        "the derived rule matches only the original request"
    );

    let binary = Rule::from_flow(&flow, Some(&[0x89, b'P', b'N', b'G', 0, 1])).unwrap();
    assert_eq!(
        binary.response.body,
        Body::Base64 {
            data: "iVBORwAB".into()
        }
    );
    let mut no_response = captured_flow();
    no_response.response = None;
    assert_eq!(
        Rule::from_flow(&no_response, None).unwrap().response,
        ResponseTemplate::ok()
    );
}

#[test]
fn rendering_variables_and_framing() {
    let mut r = rule("echo", Condition::All(vec![]), 200);
    r.response.headers = vec![
        header("Content-Type", "text/plain"),
        header("X-Echo", "{{request.header.X-Evil}}"),
        header("X-Unknown", "{{nope}}"),
    ];
    r.response.body = Body::Text {
        text: "{{request.method}} {{request.host}}{{request.path}}?{{request.query}} {{".into(),
    };
    let set = RuleSet::new(vec![r]).unwrap();
    let mut req = Req::get("http://api.example.com/p?x=1");
    req.headers
        .push(header("X-Evil", "a\r\nSet-Cookie: pwned=1"));
    let reply = set.reply(req.view()).unwrap();
    assert_eq!(
        String::from_utf8(reply.response.body.clone()).unwrap(),
        "GET api.example.com/p?x=1 {{"
    );
    assert_eq!(
        reply.response.headers[1].value, "aSet-Cookie: pwned=1",
        "CR/LF removed: no header injection"
    );
    assert_eq!(reply.response.headers[2].value, "{{nope}}");
    let bytes = String::from_utf8(reply.response.to_bytes(false, true)).unwrap();
    assert!(
        !String::from_utf8(reply.response.to_bytes(false, false))
            .unwrap()
            .contains("Connection")
    );
    assert!(bytes.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"));
    let framing = format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\nGET api",
        reply.response.body.len()
    );
    assert!(bytes.contains(&framing), "{bytes}");
    assert_eq!(bytes.matches("\r\n\r\n").count(), 1);

    req.method = "HEAD";
    let head = set.reply(req.view()).unwrap();
    assert!(
        head.response.body.is_empty(),
        "HEAD responses carry no body"
    );
}

#[test]
fn invalid_rules_are_rejected() {
    let base = || rule("ok", Condition::All(vec![]), 200);
    let mut cases: Vec<(Rule, &str)> = Vec::new();
    let mut r = base();
    r.name = String::new();
    cases.push((r, "name"));
    let mut r = base();
    r.response.status = 101;
    cases.push((r, "status"));
    let mut r = base();
    r.response.reason = "OK\r\nX: y".into();
    cases.push((r, "reason"));
    let mut r = base();
    r.response.headers = vec![header("Content-Length", "5")];
    cases.push((r, "framing"));
    let mut r = base();
    r.response.headers = vec![header("Bad Name", "x")];
    cases.push((r, "header name"));
    let mut r = base();
    r.response.headers = vec![header("X", "a\nb")];
    cases.push((r, "header value"));
    let mut r = base();
    r.response.body = Body::Base64 {
        data: "not base64!".into(),
    };
    cases.push((r, "base64"));
    let mut r = base();
    r.response.delay_ms = limits::DELAY_MS + 1;
    cases.push((r, "delay"));
    let mut r = base();
    r.condition =
        (0..limits::DEPTH).fold(Condition::All(vec![]), |c, _| Condition::Not(Box::new(c)));
    cases.push((r, "depth"));
    let mut r = base();
    r.condition = Condition::Any(vec![Condition::ServerPort(1); limits::NODES]);
    cases.push((r, "nodes"));
    let mut r = base();
    r.condition = Condition::Host(text(Op::Contains, &"a".repeat(limits::PATTERN + 1)));
    cases.push((r, "pattern"));
    let mut r = base();
    r.condition = Condition::Header {
        name: "Bad:Name".into(),
        value: None,
    };
    cases.push((r, "condition header name"));
    for (rule, what) in cases {
        assert!(RuleSet::new(vec![rule]).is_err(), "{what} accepted");
    }
    let dup = base();
    assert_eq!(
        RuleSet::new(vec![dup.clone(), dup]).unwrap_err().reason,
        "duplicate rule id"
    );
    assert!(RuleSet::new(vec![base(); limits::RULES + 1]).is_err());
}

#[test]
fn json_import_export_round_trip() {
    let mut r = rule(
        "json",
        Condition::Any(vec![Condition::Host(text(Op::EndsWith, ".example.com"))]),
        302,
    );
    r.response.headers = vec![header("Location", "https://example.org/")];
    r.response.delay_ms = 250;
    let set = RuleSet::new(vec![
        r,
        Rule::from_flow(&captured_flow(), Some(b"x")).unwrap(),
    ])
    .unwrap();
    let json = serde_json::to_vec(set.rules()).unwrap();
    assert_eq!(RuleSet::from_json(&json).unwrap(), set);
    let text = String::from_utf8(json).unwrap();
    assert!(
        text.contains(
            r#""condition":{"any":[{"host":{"op":"ends_with","value":".example.com"}}]}"#
        ),
        "{text}"
    );
    assert!(RuleSet::from_json(br#"[{"id":"x"}]"#).is_err());
    assert!(RuleSet::from_json(b"not json").is_err());
}

#[test]
fn base64_is_strict_and_round_trips() {
    for data in [
        &b""[..],
        b"f",
        b"fo",
        b"foo",
        b"foob",
        b"fooba",
        b"foobar",
        &[0, 255, 128, 7],
    ] {
        assert_eq!(base64::decode(&base64::encode(data)).as_deref(), Some(data));
    }
    assert_eq!(base64::encode(b"foobar"), "Zm9vYmFy");
    for bad in ["Zg", "Zg=", "Z===", "Zm9v=Zm9", "Zh==", "Zm9!", "Zm9v\n"] {
        assert_eq!(base64::decode(bad), None, "{bad}");
    }
}

#[test]
fn rules_target_the_hosts_they_could_answer() {
    let rule = |condition: Condition, enabled: bool| Rule {
        enabled,
        ..rule("t", condition, 200)
    };
    let host_only = RuleSet::new(vec![
        rule(
            Condition::All(vec![
                Condition::Host(text(Op::EndsWith, ".example.com")),
                Condition::Path(text(Op::Equals, "/x")),
            ]),
            true,
        ),
        rule(
            Condition::Url(text(Op::StartsWith, "https://api.test/v1")),
            true,
        ),
        rule(Condition::Host(text(Op::Equals, "off.test")), false),
    ])
    .unwrap();
    assert!(host_only.targets_host("www.example.com"));
    assert!(host_only.targets_host("api.test"));
    assert!(
        !host_only.targets_host("off.test"),
        "disabled rules do not count"
    );
    assert!(
        !host_only.targets_host("unrelated.test"),
        "verified first, relayed when unreachable"
    );
    // Rules that do not name a host could answer any host; `not` excludes only its host.
    let any_host = RuleSet::new(vec![rule(
        Condition::Url(text(Op::Contains, "/mock")),
        true,
    )])
    .unwrap();
    assert!(any_host.targets_host("unrelated.test"));
    let all_but = RuleSet::new(vec![rule(
        Condition::Not(Box::new(Condition::Host(text(Op::Equals, "other.test")))),
        true,
    )])
    .unwrap();
    assert!(!all_but.targets_host("other.test") && all_but.targets_host("unrelated.test"));
    // Body conditions make streaming protocols wait for the body, on the hosts they may apply to.
    let graphql = RuleSet::new(vec![rule(
        Condition::All(vec![
            Condition::Host(text(Op::Equals, "gql.test")),
            Condition::Not(Box::new(Condition::Body(text(Op::Contains, "mutation")))),
        ]),
        true,
    )])
    .unwrap();
    assert!(graphql.needs_body("gql.test") && !graphql.needs_body("other.test"));
    assert!(!any_host.needs_body("unrelated.test") && !host_only.needs_body("api.test"));
}

#[test]
fn redirects_come_first_keep_path_and_query_and_are_validated() {
    let mut redirect = rule(
        "to local",
        Condition::Host(text(Op::Equals, "api.prod.test")),
        200,
    );
    redirect.redirect = Some(Redirect {
        to: "http://localhost:3000/mock/".into(),
        keep_host: false,
    });
    redirect.group = "api.prod.test".into();
    // An auto-reply earlier in the list still loses: one outcome, redirects first.
    let reply = rule(
        "reply",
        Condition::Host(text(Op::Equals, "api.prod.test")),
        201,
    );
    let set = RuleSet::new(vec![reply, redirect]).unwrap();
    let req = Req::get("https://api.prod.test/v1/users?id=7");
    match set.decide(req.view()) {
        Some(Decision::Redirect { rule, url }) => {
            assert_eq!(rule.name, "to local");
            assert_eq!(url, "http://localhost:3000/mock/v1/users?id=7");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        set.reply(req.view()).is_none(),
        "never both redirected and answered"
    );
    let other = Req::get("https://elsewhere.test/");
    assert!(set.decide(other.view()).is_none());
    // Groups and redirects survive a JSON round trip; older rule files still load.
    let json = serde_json::to_vec(set.rules()).unwrap();
    assert_eq!(RuleSet::from_json(&json).unwrap(), set);
    let legacy = br#"[{"id":"01a1ad15-d073-71f0-9f0d-4b7142880f18","name":"old","enabled":true,"condition":{"all":[]}}]"#;
    assert!(
        RuleSet::from_json(legacy).is_ok(),
        "response defaults to 200 OK"
    );
    for bad in [
        "ftp://x",
        "http://",
        "http://a b",
        "http://h:0",
        "http://h:99999",
        "http://u@h",
        "http://h/?q",
        "localhost:3000",
    ] {
        let mut r = rule("bad", Condition::All(vec![]), 200);
        r.redirect = Some(Redirect {
            to: bad.into(),
            keep_host: false,
        });
        assert!(RuleSet::new(vec![r]).is_err(), "{bad}");
    }
}
