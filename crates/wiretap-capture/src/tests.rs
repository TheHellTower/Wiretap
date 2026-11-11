use wiretap_core::HttpVersion;
use wiretap_driver_proto::{DataRecord, FlowRecord, Record};

use super::*;

const FLOW: u64 = 0xF10;
const CURL: &str = r"\device\harddiskvolume3\windows\system32\curl.exe";

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn tracker() -> Tracker {
    Tracker::new(
        SessionId::generate(),
        vec![(r"\Device\HarddiskVolume3".into(), "C:".into())],
    )
}

fn connect(t: &mut Tracker, inbound: bool, path: &[u8]) -> Vec<Output> {
    let mut out = Vec::new();
    let record = FlowRecord {
        timestamp: 133_000_000_000_000_000,
        flow: FLOW,
        inbound,
        ipv6: false,
        pid: 4242,
        protocol: 6,
        local_port: 50_000,
        remote_port: 80,
        local_addr: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        remote_addr: [93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        path,
    };
    t.record(&Record::Flow(record), &mut out);
    out
}

fn send(t: &mut Tracker, inbound: bool, bytes: &[u8]) -> Vec<Output> {
    let mut out = Vec::new();
    let record = DataRecord {
        timestamp: 133_000_000_010_000_000,
        flow: FLOW,
        inbound,
        wire_len: u32::try_from(bytes.len()).unwrap(),
        data: bytes,
    };
    t.record(&Record::Data(record), &mut out);
    out
}

fn flows(out: &[Output]) -> Vec<&Flow> {
    out.iter()
        .filter_map(|o| {
            if let Output::Flow(f) = o {
                Some(f)
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn excluded_endpoints_are_ignored_entirely() {
    let mut t = tracker();
    t.exclude(Endpoint {
        ip: "93.184.216.34".parse().unwrap(),
        port: Some(80),
    });
    assert!(connect(&mut t, false, &[]).is_empty());
    assert!(
        send(
            &mut t,
            false,
            b"GET / HTTP/1.1\r\nCookie: wiretap=secret\r\n\r\n"
        )
        .is_empty()
    );
    // Another port of the same host is still captured.
    let mut t = tracker();
    t.exclude(Endpoint {
        ip: "93.184.216.34".parse().unwrap(),
        port: Some(443),
    });
    assert_eq!(connect(&mut t, false, &[]).len(), 1);
}

#[test]
fn excluded_processes_are_ignored_entirely() {
    let mut t = tracker();
    t.exclude_process(4242); // the pid `connect` uses
    assert!(connect(&mut t, false, &[]).is_empty());
    assert!(send(&mut t, false, b"GET / HTTP/1.1\r\n\r\n").is_empty());
    let mut t = tracker();
    t.exclude_process(7);
    assert_eq!(connect(&mut t, false, &[]).len(), 1);
}

#[test]
fn connection_event_maps_process_path() {
    let path = utf16(CURL);
    let out = connect(&mut tracker(), false, &path);
    let [Output::Event(e)] = out.as_slice() else {
        panic!("{out:?}")
    };
    let process = e.process.as_ref().unwrap();
    assert_eq!(
        process.path.as_deref(),
        Some(r"C:\windows\system32\curl.exe")
    );
    assert_eq!(process.name.as_deref(), Some("curl.exe"));
    assert_eq!(
        (e.protocol, e.direction, e.source),
        (Protocol::Tcp, Direction::Outbound, CaptureSource::Driver)
    );
    assert_eq!(
        e.remote_endpoint.unwrap().to_owned(),
        Endpoint {
            ip: "93.184.216.34".parse().unwrap(),
            port: Some(80)
        }
    );
    assert_eq!(filetime_to_timestamp(116_444_736_000_000_000), Timestamp(0));
}

#[test]
fn http_exchange_with_keep_alive() {
    let mut t = tracker();
    connect(&mut t, false, &utf16(CURL));
    let req = b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
    let out = send(&mut t, false, &req[..20]);
    assert!(out.is_empty(), "partial head");
    let out = send(&mut t, false, &req[20..]);
    let [request] = flows(&out)[..] else {
        panic!("{out:?}")
    };
    let r = request.request.as_ref().unwrap();
    assert_eq!(
        (r.method.as_str(), r.url.as_str(), r.version),
        ("POST", "http://example.com/api", HttpVersion::Http11)
    );
    assert!(request.response.is_none());

    let out = send(
        &mut t,
        false,
        b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let [second] = flows(&out)[..] else {
        panic!("body was not skipped: {out:?}")
    };
    assert_eq!(
        second.request.as_ref().unwrap().url,
        "http://example.com/next"
    );

    let out = send(&mut t, true, b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 404 Not Found\r\n\r\n");
    let [first_done, second_done] = flows(&out)[..] else {
        panic!("{out:?}")
    };
    assert_eq!(first_done.id, request.id);
    assert_eq!(first_done.response.as_ref().unwrap().status, 201);
    assert_eq!(second_done.id, second.id);
    assert_eq!(second_done.response.as_ref().unwrap().status, 404);
}

#[test]
fn server_role_uses_remote_as_client() {
    let mut t = tracker();
    connect(&mut t, true, &[]);
    let out = send(&mut t, true, b"GET / HTTP/1.0\r\n\r\n");
    let [flow] = flows(&out)[..] else {
        panic!("{out:?}")
    };
    assert_eq!(
        flow.client.unwrap().port,
        Some(80),
        "remote peer is the client"
    );
    assert_eq!(flow.request.as_ref().unwrap().url, "http://10.0.0.2:50000/");
    assert!(flow.process.as_ref().unwrap().path.is_none());
}

#[test]
fn tls_handshake_metadata() {
    let mut t = tracker();
    connect(&mut t, false, &[]);
    // Minimal ClientHello: TLS 1.2 legacy version, SNI "example.org", no ALPN.
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[0; 32]);
    hello.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    let name = b"example.org";
    let sni_len = u16::try_from(name.len()).unwrap();
    let mut sni = vec![0, 0];
    sni.extend_from_slice(&(sni_len + 5).to_be_bytes());
    sni.extend_from_slice(&(sni_len + 3).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&sni_len.to_be_bytes());
    sni.extend_from_slice(name);
    hello.extend_from_slice(&u16::try_from(sni.len()).unwrap().to_be_bytes());
    hello.extend_from_slice(&sni);
    let len = u32::try_from(hello.len()).unwrap().to_be_bytes();
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&u16::try_from(hello.len() + 4).unwrap().to_be_bytes());
    record.extend_from_slice(&[1, len[1], len[2], len[3]]);
    record.extend_from_slice(&hello);

    let out = send(&mut t, false, &record);
    let [Output::Event(e)] = out.as_slice() else {
        panic!("{out:?}")
    };
    assert_eq!(
        (e.protocol, e.metadata.inspection),
        (Protocol::Tls, Inspection::Metadata)
    );
    assert_eq!(
        e.metadata.attributes.get("tls.sni").map(String::as_str),
        Some("example.org")
    );
    assert_eq!(
        e.metadata
            .attributes
            .get("tls.versions_offered")
            .map(String::as_str),
        Some("TLS 1.2")
    );
    assert!(
        send(&mut t, false, b"\x17\x03\x03\x00\x05secret").is_empty(),
        "application data is never parsed"
    );
}

#[test]
fn opaque_and_unknown_traffic_is_ignored() {
    let mut t = tracker();
    assert!(
        send(&mut t, false, b"GET / HTTP/1.1\r\n\r\n").is_empty(),
        "no connection record"
    );
    connect(&mut t, false, &[]);
    assert!(send(&mut t, false, b"\x00\x01binary protocol").is_empty());
    assert!(
        send(&mut t, false, b"GET / HTTP/1.1\r\n\r\n").is_empty(),
        "connection already classified opaque"
    );
}

#[test]
fn buffers_are_bounded() {
    let mut t = tracker();
    connect(&mut t, false, &[]);
    let mut head = b"GET / HTTP/1.1\r\nX: ".to_vec();
    head.resize(MAX_BUFFER - 1, b'a');
    assert!(send(&mut t, false, &head).is_empty());
    assert_eq!(t.buffered, MAX_BUFFER - 1);
    assert!(
        send(&mut t, false, b"aaaa").is_empty(),
        "exceeds per-direction cap"
    );
    assert_eq!(t.buffered, 0, "buffer released once the side gives up");
    connect(&mut t, false, &[]);
    assert_eq!(t.connections.len(), 1, "reconnect replaces the old state");
}

#[test]
fn invalid_outputs_are_never_emitted() {
    let mut t = tracker();
    connect(&mut t, false, &[]);
    // Host header with a control character would produce an invalid URL; the authority falls
    // back to the server address instead of emitting invalid data.
    let out = send(
        &mut t,
        false,
        b"GET /a HTTP/1.1\r\nHost: bad\x7fhost\r\n\r\n",
    );
    for o in &out {
        if let Output::Flow(f) = o {
            f.validate().unwrap();
        }
    }
    assert_eq!(t.rejected(), 0);
}
