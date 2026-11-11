//! Fuzz harnesses for every Wiretap component and the dependency entry points it uses.
//!
//! Each public function is one libFuzzer target (`fuzz_targets/<name>.rs`). Harnesses assert
//! semantic invariants, not just absence of crashes. `tests/replay.rs` runs every seed and
//! regression input through them on stable Rust as part of the normal test suite.

use std::collections::BTreeMap;
use std::fmt::Debug;

use arbitrary::{Result as ArbResult, Unstructured};
use serde::Serialize;
use serde::de::DeserializeOwned;
use wiretap_core::{
    CaptureSource, Direction, EventId, EventMetadata, Flow, Inspection, ModelError, NetworkEvent,
    PayloadEncryption, PayloadId, Protocol, Session, SessionId, Timestamp, Uuid,
};
use wiretap_platform::{OsInfo, Support, classify};
use wiretap_storage::{Store, StoreError};

/// A parsed value validates deterministically and survives a JSON round trip unchanged.
fn json_round_trip<T>(data: &[u8], validate: fn(&T) -> Result<(), ModelError>)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let Ok(value) = serde_json::from_slice::<T>(data) else {
        return;
    };
    let verdict = validate(&value);
    let json = serde_json::to_vec(&value).expect("serializing a parsed value");
    let back: T = serde_json::from_slice(&json).expect("re-parsing serializer output");
    assert_eq!(back, value);
    assert_eq!(validate(&back), verdict);
}

/// `NetworkEvent` deserialization (serde, serde_json) and validation.
pub fn event_json(data: &[u8]) {
    json_round_trip(data, NetworkEvent::validate);
}

/// `Flow` deserialization (serde, serde_json) and validation.
pub fn flow_json(data: &[u8]) {
    json_round_trip(data, Flow::validate);
}

/// UUID text parsing: every accepted string re-formats to its lowercase form.
pub fn uuid_parse(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(id) = text.parse::<Uuid>() {
        assert_eq!(id.to_string(), text.to_ascii_lowercase());
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(serde_json::from_str::<Uuid>(&json).expect("parse"), id);
    }
}

/// Windows support policy: never reports a build outside the matrix as supported.
pub fn os_classify(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let Ok(os) = (|| -> ArbResult<OsInfo> {
        Ok(OsInfo {
            major: u.arbitrary()?,
            minor: u.arbitrary()?,
            build: u.arbitrary()?,
            workstation: u.arbitrary()?,
            native_x64: u.arbitrary()?,
        })
    })() else {
        return;
    };
    if let Support::Supported(_) = classify(&os) {
        assert!(
            os.native_x64 && os.workstation && (os.major, os.minor) == (10, 0),
            "{os:?}"
        );
        assert!(matches!(os.build, 19044..=19045 | 26100..=26200), "{os:?}");
    }
}

/// Shadow model of what the store must contain.
#[derive(Default)]
struct Model {
    /// Session -> (creation time, number of events).
    sessions: BTreeMap<SessionId, (Timestamp, usize)>,
    /// Payload -> (owning session, bytes).
    payloads: BTreeMap<PayloadId, (SessionId, Vec<u8>)>,
}

const SOURCES: [CaptureSource; 3] = [
    CaptureSource::PacketCapture,
    CaptureSource::ExplicitProxy,
    CaptureSource::Import,
];
const INSPECTIONS: [Inspection; 3] = [
    Inspection::Packet,
    Inspection::Plaintext,
    Inspection::Intercepted,
];

/// Random operation sequences against an in-memory store, checked against a shadow model.
/// Exercises our SQL, rusqlite and SQLite through the public storage API.
pub fn storage_ops(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let mut store = Store::open(":memory:", 2 << 20).expect("in-memory store");
    let mut model = Model::default();
    for _ in 0..64 {
        if u.is_empty() || step(&mut u, &mut store, &mut model).is_err() {
            break;
        }
    }
    store.check_integrity().expect("integrity after operations");
}

fn pick_session(u: &mut Unstructured<'_>, model: &Model) -> ArbResult<SessionId> {
    let known: Vec<SessionId> = model.sessions.keys().copied().collect();
    if known.is_empty() || u.ratio(1, 8)? {
        Ok(SessionId::generate())
    } else {
        Ok(*u.choose(&known)?)
    }
}

fn event(u: &mut Unstructured<'_>, session: SessionId) -> ArbResult<NetworkEvent> {
    Ok(NetworkEvent {
        id: EventId::generate(),
        session_id: session,
        timestamp: Timestamp(u.arbitrary()?),
        source: *u.choose(&SOURCES)?,
        protocol: Protocol::Tcp,
        direction: Direction::Unknown,
        process: None,
        local_endpoint: None,
        remote_endpoint: None,
        payload: None,
        metadata: EventMetadata {
            inspection: *u.choose(&INSPECTIONS)?,
            flow_id: None,
            attributes: u.arbitrary()?,
        },
    })
}

fn step(u: &mut Unstructured<'_>, store: &mut Store, model: &mut Model) -> ArbResult<()> {
    match u.int_in_range(0u8..=5)? {
        0 => {
            let session = Session {
                id: SessionId::generate(),
                name: u.arbitrary()?,
                created: Timestamp(u.arbitrary()?),
            };
            let valid = session.validate().is_ok();
            match store.insert_session(&session) {
                Ok(()) => {
                    assert!(valid);
                    model.sessions.insert(session.id, (session.created, 0));
                }
                Err(StoreError::Invalid(_)) => assert!(!valid),
                Err(StoreError::Full) => {}
                Err(e) => panic!("insert_session: {e}"),
            }
        }
        1 => {
            let session = pick_session(u, model)?;
            let count = u.int_in_range(0..=8)?;
            let events = (0..count)
                .map(|_| event(u, session))
                .collect::<ArbResult<Vec<_>>>()?;
            let valid = events.iter().all(|e| e.validate().is_ok());
            let known = model.sessions.contains_key(&session);
            match store.insert_events(&events) {
                Ok(()) => {
                    assert!(valid && (known || events.is_empty()));
                    if let Some(entry) = model.sessions.get_mut(&session) {
                        entry.1 += events.len();
                    }
                }
                Err(StoreError::Invalid(_)) => assert!(!valid),
                Err(StoreError::Sqlite(_)) => assert!(!known, "write to existing session failed"),
                Err(StoreError::Full) => {}
                Err(e) => panic!("insert_events: {e}"),
            }
        }
        2 => {
            let session = pick_session(u, model)?;
            let bytes: Vec<u8> = u.arbitrary()?;
            let size: u64 = u.arbitrary()?;
            let fits = size >= bytes.len() as u64;
            let known = model.sessions.contains_key(&session);
            match store.insert_payload(session, &bytes, size, PayloadEncryption::Cleartext) {
                Ok(reference) => {
                    assert!(known && fits);
                    assert_eq!(reference.stored, bytes.len() as u64);
                    model.payloads.insert(reference.id, (session, bytes));
                }
                Err(StoreError::Invalid(_)) => assert!(!fits),
                Err(StoreError::Sqlite(_)) => assert!(!known, "write to existing session failed"),
                Err(StoreError::Full) => {}
                Err(e) => panic!("insert_payload: {e}"),
            }
        }
        3 => {
            for (id, (_, bytes)) in &model.payloads {
                assert_eq!(
                    store.payload(*id).expect("read payload").as_deref(),
                    Some(bytes.as_slice())
                );
            }
        }
        4 => {
            if u.arbitrary()? {
                let session = pick_session(u, model)?;
                let existed = store.delete_session(session).expect("delete");
                assert_eq!(existed, model.sessions.remove(&session).is_some());
            } else {
                let cutoff = Timestamp(u.arbitrary()?);
                let before = model.sessions.len();
                model.sessions.retain(|_, (created, _)| *created >= cutoff);
                assert_eq!(
                    store.purge_sessions_before(cutoff).expect("purge"),
                    before - model.sessions.len()
                );
            }
            model
                .payloads
                .retain(|_, (session, _)| model.sessions.contains_key(session));
        }
        _ => {
            let session = pick_session(u, model)?;
            let page = u.int_in_range(1..=64)?;
            let (mut cursor, mut seen) = (None, 0);
            loop {
                let events = store.events(session, cursor, page).expect("read events");
                let Some(last) = events.last() else { break };
                for e in &events {
                    let key = (e.timestamp, e.id);
                    assert!(cursor < Some(key), "events out of order");
                    cursor = Some(key);
                }
                assert_eq!(cursor, Some((last.timestamp, last.id)));
                seen += events.len();
            }
            assert_eq!(seen, model.sessions.get(&session).map_or(0, |s| s.1));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Driver protocol (shared with the kernel driver), protocol decoders, tracker and CLI.

use std::collections::VecDeque;

use wiretap_driver_proto::{self as proto, Record};

/// Decoded driver records re-encode to bytes that decode to the same record.
pub fn driver_records(data: &[u8]) {
    for record in proto::records(data) {
        let Ok(record) = record else { break };
        let bytes = match record {
            Record::Flow(f) => [&proto::flow_header(&f)[..], f.path].concat(),
            Record::Data(d) => [
                &proto::data_header(d.timestamp, d.flow, d.inbound, d.wire_len, d.data.len())[..],
                d.data,
            ]
            .concat(),
        };
        let again: Vec<_> = proto::records(&bytes).collect();
        assert_eq!(again, [Ok(record)]);
    }
}

/// The kernel ring buffer behaves exactly like a queue of whole records with a byte budget.
pub fn driver_ring(data: &[u8]) {
    const CAP: usize = 1024;
    let mut u = Unstructured::new(data);
    let mut ring = proto::Ring::<CAP>::new();
    let (mut model, mut used, mut dropped) = (VecDeque::<Vec<u8>>::new(), 0usize, 0u64);
    while !u.is_empty() {
        if u.ratio(1, 16).unwrap_or(false) {
            ring.clear();
            (model, used, dropped) = (VecDeque::new(), 0, 0);
        } else if u.arbitrary::<bool>().unwrap_or(false) {
            let len = u.int_in_range(2u16..=300).unwrap_or(2);
            let mut record = len.to_le_bytes().to_vec();
            record.extend((2..len).map(|_| u.arbitrary::<u8>().unwrap_or(0)));
            let split = u.choose_index(record.len()).unwrap_or(0);
            let fits = record.len() <= CAP - used;
            assert_eq!(ring.push(&[&record[..split], &record[split..]]), fits);
            if fits {
                used += record.len();
                model.push_back(record);
            } else {
                dropped += 1;
            }
        } else {
            let mut out = vec![0u8; u.int_in_range(0usize..=CAP + 64).unwrap_or(0)];
            let n = ring.pop_into(&mut out);
            let mut expected = Vec::new();
            while model
                .front()
                .is_some_and(|r| expected.len() + r.len() <= out.len())
            {
                expected.extend(model.pop_front().unwrap_or_default());
            }
            used -= expected.len();
            assert_eq!(&out[..n], &expected[..]);
            assert_eq!(ring.take_dropped(), std::mem::take(&mut dropped));
            assert_eq!(ring.is_empty(), model.is_empty());
        }
    }
}

/// HTTP/1 heads: complete parses stay within the buffer and limits and satisfy the model's
/// syntax rules; framing never panics.
pub fn http_head(data: &[u8]) {
    use wiretap_protocol::{Parse, StartLine, framing, parse_head};
    let Parse::Complete(head) = parse_head(data) else {
        return;
    };
    assert!(head.len <= data.len() && head.len <= wiretap_protocol::MAX_HEAD);
    assert!(head.headers.len() <= wiretap_core::limits::HEADERS);
    for h in &head.headers {
        assert!(!h.name.is_empty() && h.name.bytes().all(|b| b.is_ascii_graphic() && b != b':'));
        assert!(!h.value.chars().any(|c| c.is_control() && c != '\t'));
    }
    match &head.start {
        StartLine::Request { method, target, .. } => {
            assert!(!method.is_empty() && !target.is_empty())
        }
        StartLine::Response { status, .. } => assert!((100..=999).contains(status)),
    }
    let _ = framing(&head, None);
    let _ = framing(&head, Some("HEAD"));
    assert_eq!(parse_head(data), Parse::Complete(head), "deterministic");
}

/// TLS hellos: extracted metadata is bounded and well-formed.
pub fn tls_hello(data: &[u8]) {
    use wiretap_protocol::{Parse, parse_client_hello, parse_server_hello};
    if let Parse::Complete(hello) = parse_client_hello(data) {
        if let Some(name) = &hello.server_name {
            assert!(
                name.len() <= 253
                    && !name
                        .bytes()
                        .any(|b| b.is_ascii_uppercase() || b.is_ascii_control())
            );
        }
        assert!(hello.alpn.len() <= 16 && !hello.versions.is_empty() && hello.versions.len() <= 16);
        assert!(
            hello
                .versions
                .iter()
                .all(|v| v & 0x0F0F != 0x0A0A || v >> 8 != v & 0xFF || hello.versions.len() == 1)
        );
    }
    let _ = parse_server_hello(data);
    // Server flights: certificate fields are bounded display text, valid as event attributes.
    if let Parse::Complete(flight) = wiretap_protocol::parse_server_flight(data) {
        assert!(flight.certificates.len() <= 8);
        for (key, value) in flight.attributes() {
            assert!(key.starts_with("tls.") && !value.is_empty() && value.len() <= 32 * 1024);
            assert!(!value.chars().any(char::is_control), "{key}: {value:?}");
        }
    }
}

/// Seeds the tracker with protocol-shaped payloads so the fuzzer reaches deep states quickly.
const PAYLOADS: [&[u8]; 4] = [
    b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
    &[22, 3, 1, 0, 4, 1, 0, 0, 0],
];

/// Arbitrary driver record streams: the tracker never produces an output it must reject, and
/// every output renders.
pub fn tracker(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let mut t = wiretap_capture::Tracker::new(
        SessionId::generate(),
        vec![(r"\Device\X".into(), "C:".into())],
    );
    let mut out = Vec::new();
    let flows = [1u64, 2, 3];
    for _ in 0..256 {
        if u.is_empty() {
            break;
        }
        let Ok(flow) = u.choose(&flows).copied() else {
            break;
        };
        let inbound = u.arbitrary().unwrap_or(false);
        if u.ratio(1, 4).unwrap_or(false) {
            let path: Vec<u8> = u.arbitrary().unwrap_or_default();
            let path = &path[..path.len().min(proto::MAX_PATH_BYTES) & !1];
            let record = proto::FlowRecord {
                timestamp: u.arbitrary().unwrap_or(0),
                flow,
                inbound,
                ipv6: u.arbitrary().unwrap_or(false),
                pid: u.arbitrary().unwrap_or(0),
                protocol: *u.choose(&[6u8, 17, 1, 58, 0]).unwrap_or(&6),
                local_port: u.arbitrary().unwrap_or(0),
                remote_port: u.arbitrary().unwrap_or(0),
                local_addr: u.arbitrary().unwrap_or_default(),
                remote_addr: u.arbitrary().unwrap_or_default(),
                path,
            };
            t.record(&Record::Flow(record), &mut out);
        } else {
            let mut payload: Vec<u8> = u.arbitrary().unwrap_or_default();
            if u.arbitrary().unwrap_or(false) {
                payload = [u.choose(&PAYLOADS).copied().unwrap_or_default(), &payload].concat();
            }
            payload.truncate(proto::SEGMENT_CAP);
            let record = proto::DataRecord {
                timestamp: u.arbitrary().unwrap_or(0),
                flow,
                inbound,
                wire_len: u32::try_from(payload.len()).unwrap_or(u32::MAX),
                data: &payload,
            };
            t.record(&Record::Data(record), &mut out);
        }
        for o in out.drain(..) {
            let _ = wiretap_cli::render(&o);
        }
    }
    assert_eq!(t.rejected(), 0, "tracker produced invalid model data");
}

/// Command-line parsing and timestamp formatting never panic.
pub fn cli_args(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = wiretap_cli::parse_args(text.split('\0').map(str::to_owned));
    if let Some(chunk) = data.first_chunk::<8>() {
        let _ = wiretap_cli::utc(Timestamp(i64::from_le_bytes(*chunk)));
    }
}

/// Rule files (`.wtrr` rule lists): parsing round-trips exactly; deciding, rendering and host
/// targeting never panic; a redirect always produces an absolute http(s) URL.
pub fn rules(data: &[u8]) {
    use wiretap_autoreply::{Decision, Request, RuleSet};
    let (url_len, json) = data
        .split_first()
        .map_or((0, data), |(n, rest)| (usize::from(*n), rest));
    let Ok(set) = RuleSet::from_json(json) else {
        return;
    };
    let again = RuleSet::from_json(&serde_json::to_vec(set.rules()).unwrap()).unwrap();
    assert_eq!(again, set);
    let url = String::from_utf8_lossy(json.get(..url_len.min(json.len())).unwrap_or_default());
    let url = format!("https://{url}");
    let headers = [wiretap_core::HttpHeader {
        name: "Host".into(),
        value: "example.test".into(),
    }];
    let request = Request {
        method: "GET",
        url: &url,
        headers: &headers,
        body: json,
        process: Some("app.exe"),
        client: None,
        server: None,
    };
    match set.decide(request) {
        Some(Decision::Redirect { url, .. }) => assert!(
            url.starts_with("http://") || url.starts_with("https://") || url.starts_with("HTTP")
        ),
        Some(Decision::Reply(reply)) => drop(reply.response.to_bytes(false, true)),
        None => {}
    }
    let (host, ..) = wiretap_autoreply::split_url(&url);
    let _ = set.targets_host(host);
}

/// Redirect records shared by the driver and the proxy: decoding never panics and every
/// decoded value round-trips.
pub fn redirect_records(data: &[u8]) {
    use wiretap_driver_proto::{Original, Redirect};
    if let Some(Some(r)) = Redirect::decode(data) {
        assert_eq!(Redirect::decode(&r.encode()), Some(Some(r)));
        assert!(r.pid != 0 && (r.port_v4 != 0 || r.port_v6 != 0));
    }
    if let Some(o) = Original::decode(data) {
        assert_eq!(Original::decode(&o.encode()), Some(o));
        assert_ne!(o.port, 0);
    }
}

/// Certificate host names: whatever passes validation is safe to embed in a certificate
/// (an IP address, or DNS labels of letters, digits, `-` and `_`).
pub fn tls_host(data: &[u8]) {
    let Ok(host) = std::str::from_utf8(data) else {
        return;
    };
    if wiretap_tls::valid_host(host) && host.parse::<std::net::IpAddr>().is_err() {
        assert!(host.len() <= 253);
        assert!(
            host.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        );
        assert!(!host.starts_with('.') && !host.ends_with('.') && !host.contains(".."));
    }
}

/// Chunked bodies: decoding is identical however the input is split, and output never
/// exceeds the limit.
pub fn chunked(data: &[u8]) {
    use wiretap_protocol::{Chunked, Progress};
    let Some((&split, input)) = data.split_first() else {
        return;
    };
    let limit = 4096;
    let whole = {
        let (mut d, mut out) = (Chunked::default(), Vec::new());
        (
            d.feed(input, &mut out, limit).map_err(|_| ()),
            out,
            d.decoded(),
        )
    };
    let at = usize::from(split).min(input.len());
    let (first, second) = input.split_at(at);
    let (mut d, mut out) = (Chunked::default(), Vec::new());
    let parts = match d.feed(first, &mut out, limit) {
        Ok(Progress::NeedMore) => d.feed(second, &mut out, limit).map(|p| match p {
            Progress::Done { consumed } => Progress::Done {
                consumed: consumed + first.len(),
            },
            other => other,
        }),
        other => other,
    };
    assert!(out.len() <= limit);
    match (&whole.0, parts.map_err(|_| ())) {
        (Ok(a), Ok(b)) => {
            assert_eq!(*a, b);
            assert_eq!((&whole.1, whole.2), (&out, d.decoded()));
        }
        (Err(()), Err(())) => {}
        (a, b) => panic!("split changed the outcome: {a:?} vs {b:?}"),
    }
}

/// The UI server's router: nothing is authorized without the exact Host, and every
/// authorized route other than login and the capture feed carried the session cookie.
pub fn ui_router(data: &[u8]) {
    use wiretap_protocol::{Parse, parse_head};
    use wiretap_ui::http::{Auth, Route, route};
    let Parse::Complete(head) = parse_head(data) else {
        return;
    };
    let auth = Auth {
        host: "127.0.0.1:5000",
        token: "t0k3n",
        feed_key: Some("k3y"),
    };
    let Ok(r) = route(&head, &auth) else {
        return;
    };
    assert_eq!(head.header("host"), Some("127.0.0.1:5000"));
    match r {
        Route::Login => assert!(String::from_utf8_lossy(data).contains("t=t0k3n")),
        Route::Feed => assert_eq!(head.header("authorization"), Some("Bearer k3y")),
        _ => {
            assert!(
                head.headers
                    .iter()
                    .any(|h| h.name.eq_ignore_ascii_case("cookie")
                        && h.value.contains("wiretap=t0k3n"))
            )
        }
    }
}

/// Most bytes a content-coding harness lets either decoder produce.
const CONTENT_LIMIT: usize = 1 << 20;

fn gzip_reference(payload: &[u8], level: u8) -> Vec<u8> {
    let mut out = vec![0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 0xFF];
    out.extend(miniz_oxide::deflate::compress_to_vec(payload, level));
    out.extend(wiretap_codec::crc32(payload).to_le_bytes());
    out.extend(u32::try_from(payload.len()).unwrap_or(0).to_le_bytes());
    out
}

fn brotli_reference(payload: &[u8], level: u8) -> Vec<u8> {
    let params = brotli::enc::BrotliEncoderParams {
        quality: i32::from(level % 12),
        lgwin: 10 + i32::from(level / 12 % 15),
        mode: match level / 180 {
            0 => brotli::enc::backward_references::BrotliEncoderMode::BROTLI_MODE_GENERIC,
            _ => brotli::enc::backward_references::BrotliEncoderMode::BROTLI_MODE_TEXT,
        },
        ..Default::default()
    };
    let mut out = Vec::new();
    brotli::BrotliCompress(&mut &payload[..], &mut out, &params).expect("brotli encodes");
    out
}

fn zstd_reference(payload: &[u8], level: u8) -> Vec<u8> {
    use std::io::Write;
    let mut encoder =
        zstd::stream::Encoder::new(Vec::new(), i32::from(level % 26) - 3).expect("zstd encoder");
    encoder
        .include_checksum(level & 0x80 != 0)
        .expect("checksum flag");
    encoder
        .include_contentsize(level & 0x40 != 0)
        .expect("size flag");
    encoder.write_all(payload).expect("zstd encodes");
    encoder.finish().expect("zstd finishes")
}

/// Content codings round trip: whatever a reference encoder produces (miniz_oxide for
/// gzip/zlib/raw DEFLATE, the Brotli encoder at every quality and window, libzstd at every
/// level with and without checksum and content size), Wiretap's decoder restores exactly, even
/// with the output limit set to the exact size.
pub fn content_roundtrip(data: &[u8]) {
    let [kind, level, payload @ ..] = data else {
        return;
    };
    let (coding, compressed) = match kind % 5 {
        0 => ("gzip", gzip_reference(payload, level % 11)),
        1 => (
            "deflate",
            miniz_oxide::deflate::compress_to_vec_zlib(payload, level % 11),
        ),
        2 => (
            "deflate",
            miniz_oxide::deflate::compress_to_vec(payload, level % 11),
        ),
        3 => ("br", brotli_reference(payload, *level)),
        _ => ("zstd", zstd_reference(payload, *level)),
    };
    let decoded = wiretap_codec::decode(coding, &compressed, payload.len());
    assert_eq!(decoded.error, None, "{coding} level {level}");
    assert!(
        decoded.bytes == payload,
        "{coding} level {level}: output differs"
    );
}

/// Writes into a vector, failing once `limit` bytes would be exceeded.
struct Capped(Vec<u8>);

impl std::io::Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len() + bytes.len() > CONTENT_LIMIT {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Arbitrary compressed bodies: no panic, output within the limit, a smaller limit yields a
/// prefix, and the result agrees with the reference decoders. For Brotli and Zstandard
/// (reference implementations), every input they accept Wiretap must decode identically; for
/// DEFLATE (miniz_oxide is more lenient than zlib) only inputs both accept are compared.
pub fn content_decode(data: &[u8]) {
    let Some((&kind, input)) = data.split_first() else {
        return;
    };
    let coding = ["gzip", "deflate", "br", "zstd"][usize::from(kind % 4)];
    let ours = wiretap_codec::decode(coding, input, CONTENT_LIMIT);
    assert!(ours.bytes.len() <= CONTENT_LIMIT);
    let small = wiretap_codec::decode(coding, input, 64);
    assert!(
        ours.bytes.starts_with(&small.bytes),
        "{coding}: limit changed the output"
    );
    assert!(small == ours || small.error == Some(wiretap_codec::Error::TooLarge));
    let (reference, strict) = match kind % 4 {
        1 if input.len() >= 2 && (u16::from(input[0]) << 8 | u16::from(input[1])) % 31 == 0 => (
            miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(input, CONTENT_LIMIT).ok(),
            false,
        ),
        1 => (
            miniz_oxide::inflate::decompress_to_vec_with_limit(input, CONTENT_LIMIT).ok(),
            false,
        ),
        2 => {
            let mut out = Capped(Vec::new());
            // The brotli crate also accepts large-window streams (a non-standard extension the
            // RFC and Google's decoder reject by default), so those are compared, not required.
            let standard = input.first().is_none_or(|b| b & 0x7F != 0x11);
            (
                brotli::BrotliDecompress(&mut &input[..], &mut out)
                    .ok()
                    .map(|()| out.0),
                standard,
            )
        }
        3 => (zstd::bulk::decompress(input, CONTENT_LIMIT).ok(), true),
        _ => (None, false),
    };
    if let Some(expected) = reference {
        if strict {
            assert_eq!(
                ours.error, None,
                "{coding}: the reference decoder accepts this input"
            );
        }
        if ours.error.is_none() {
            assert!(
                ours.bytes == expected,
                "{coding}: output differs from the reference"
            );
        }
    }
}

thread_local! {
    /// The input being run, for the panic hook installed by [`guard`].
    static CURRENT: std::cell::RefCell<Option<(&'static str, Vec<u8>)>> = const { std::cell::RefCell::new(None) };
}

/// Runs a harness; if it panics, the input is saved to `artifacts/<target>/crash-<hash>` first.
/// On Windows libFuzzer cannot save it: libfuzzer-sys aborts from its panic hook, and that abort
/// bypasses libFuzzer's crash handler. This hook runs before theirs.
pub fn guard(target: &'static str, data: &[u8], harness: fn(&[u8])) {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            CURRENT.with(|current| {
                if let Some((target, data)) = current.borrow().as_ref() {
                    let hash = data.iter().fold(0xCBF2_9CE4_8422_2325u64, |h, &b| {
                        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01B3)
                    });
                    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("artifacts")
                        .join(target);
                    let path = dir.join(format!("crash-{hash:016x}"));
                    if std::fs::create_dir_all(&dir)
                        .and_then(|()| std::fs::write(&path, data))
                        .is_ok()
                    {
                        eprintln!("input saved to {}", path.display());
                    }
                }
            });
            previous(info);
        }));
    });
    CURRENT.with(|current| *current.borrow_mut() = Some((target, data.to_vec())));
    harness(data);
}
/// One WebSocket frame; clients mask (`mask`), servers do not.
fn ws_frame(out: &mut Vec<u8>, first: u8, payload: &[u8], mask: Option<[u8; 4]>) {
    out.push(first);
    let bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n @ 0..=125 => out.push(bit | u8::try_from(n).unwrap_or(0)),
        n @ 126..=0xFFFF => {
            out.push(bit | 126);
            out.extend(u16::try_from(n).unwrap_or(0).to_be_bytes());
        }
        n => {
            out.push(bit | 127);
            out.extend((n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend(key);
            out.extend(payload.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k));
        }
        None => out.extend_from_slice(payload),
    }
}

/// WebSocket decoding. Arbitrary bytes: no panic, payloads within the limit, and the same
/// result however the stream is split. Generated valid streams (any opcodes, fragmentation,
/// control frames between fragments, masking, permessage-deflate) decode back to exactly the
/// messages that were sent, without problems.
pub fn websocket(data: &[u8]) {
    use wiretap_protocol::websocket::{Decoder, Deflate, Extensions, Opcode, Sender};
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let sender = if mode & 1 == 0 {
        Sender::Client
    } else {
        Sender::Server
    };
    let deflate = (mode & 2 != 0).then_some(Deflate {
        client_no_context_takeover: mode & 4 != 0,
        server_no_context_takeover: mode & 8 != 0,
    });
    let extensions = Extensions {
        deflate,
        other: mode & 16 != 0,
    };
    let limit = if mode & 32 != 0 { 64 } else { 1 << 16 };
    let decode_split = |bytes: &[u8], at: usize| {
        let (a, b) = bytes.split_at(at.min(bytes.len()));
        let mut d = Decoder::new(sender, extensions, limit);
        let mut out = d.feed(a);
        out.extend(d.feed(b));
        out
    };
    let whole = Decoder::new(sender, extensions, limit).feed(rest);
    assert_eq!(
        whole,
        decode_split(rest, usize::from(mode) * 31 % (rest.len() + 1))
    );
    assert!(whole.iter().flatten().all(|m| m.payload.len() <= limit));

    // Round trip of generated messages.
    let mut u = Unstructured::new(rest);
    let (mut stream, mut sent) = (Vec::new(), Vec::new());
    let mask = || (sender == Sender::Client).then_some([0x5A, 0x01, 0xFE, 0x33]);
    while !u.is_empty() && sent.len() < 32 {
        let Ok(kind) = u.int_in_range(0..=4u8) else {
            break;
        };
        let opcode = [
            Opcode::Text,
            Opcode::Binary,
            Opcode::Close,
            Opcode::Ping,
            Opcode::Pong,
        ][usize::from(kind)];
        let mut payload: Vec<u8> = match opcode {
            Opcode::Text => u
                .arbitrary::<String>()
                .unwrap_or_default()
                .chars()
                .take(1000)
                .collect::<String>()
                .into_bytes(),
            Opcode::Close => u
                .arbitrary::<Option<(u16, String)>>()
                .ok()
                .flatten()
                .map_or_else(Vec::new, |(code, reason)| {
                    let mut p = code.to_be_bytes().to_vec();
                    p.extend(reason.chars().take(30).collect::<String>().into_bytes());
                    p
                }),
            _ => u.arbitrary::<Vec<u8>>().unwrap_or_default(),
        };
        payload.truncate(if matches!(opcode, Opcode::Text | Opcode::Binary) {
            4000
        } else {
            125
        });
        if matches!(opcode, Opcode::Text | Opcode::Binary) {
            let compress = deflate.is_some() && u.arbitrary::<bool>().unwrap_or(false);
            let wire = if compress {
                miniz_oxide::deflate::compress_to_vec(&payload, 6)
            } else {
                payload.clone()
            };
            let pieces = usize::from(u.int_in_range(1..=4u8).unwrap_or(1));
            let size = wire.len().div_ceil(pieces).max(1);
            let chunks: Vec<&[u8]> = if wire.is_empty() {
                vec![&[]]
            } else {
                wire.chunks(size).collect()
            };
            for (i, chunk) in chunks.iter().enumerate() {
                let fin = if i + 1 == chunks.len() { 0x80 } else { 0 };
                let first = if i == 0 {
                    opcode.code() | if compress { 0x40 } else { 0 }
                } else {
                    0
                };
                ws_frame(&mut stream, fin | first, chunk, mask());
                if i == 0 && fin == 0 && u.arbitrary::<bool>().unwrap_or(false) {
                    ws_frame(&mut stream, 0x89, b"between", mask()); // control frame between fragments
                    sent.push((Opcode::Ping, b"between".to_vec()));
                }
            }
        } else {
            ws_frame(&mut stream, 0x80 | opcode.code(), &payload, mask());
        }
        sent.push((opcode, payload));
    }
    let extensions = Extensions {
        deflate,
        other: false,
    };
    let mut d = Decoder::new(sender, extensions, 1 << 16);
    let decoded: Vec<_> = d
        .feed(&stream)
        .into_iter()
        .map(|m| {
            let m = m.expect("a valid stream decodes without protocol errors");
            assert_eq!(m.problem, None, "{:?}", m.opcode);
            (m.opcode, m.payload)
        })
        .collect();
    assert_eq!(decoded, sent);
}

/// HTTP/2 framing, HPACK and Server-Sent Events: decoding is the same however the bytes are split (DATA may come
/// in different parts), header lists stay within the event model's limits, and an error ends
/// decoding. The client direction gets the connection preface unless `mode` bit 1 is set.
pub fn http2(data: &[u8]) {
    use wiretap_protocol::http2::{Decoder, Event, PREFACE};
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let client = mode & 1 == 0;
    let mut input = if client && mode & 2 == 0 {
        PREFACE.to_vec()
    } else {
        Vec::new()
    };
    input.extend_from_slice(rest);
    let merge = |events: Vec<Event>| {
        let mut out: Vec<Event> = Vec::new();
        for e in events {
            if let (
                Some(Event::Data {
                    stream: s,
                    data,
                    flow,
                    end_stream: done,
                }),
                Event::Data {
                    stream,
                    data: more,
                    flow: f,
                    end_stream,
                },
            ) = (out.last_mut(), &e)
                && *s == *stream
                && !*done
            {
                data.extend_from_slice(more);
                *flow += f;
                *done = *end_stream;
                continue;
            }
            out.push(e);
        }
        out
    };
    let whole = merge(Decoder::new(client).feed(&input));
    let at = usize::from(mode) * 37 % (input.len() + 1);
    let mut d = Decoder::new(client);
    let mut split = d.feed(&input[..at]);
    split.extend(d.feed(&input[at..]));
    assert_eq!(whole, merge(split));
    for (i, e) in whole.iter().enumerate() {
        match e {
            Event::Headers { fields, .. } | Event::Promise { fields, .. } => {
                assert!(fields.len() <= 512);
                assert!(fields.iter().map(|(n, v)| n.len() + v.len()).sum::<usize>() <= 256 * 1024);
            }
            Event::Error(_) => assert_eq!(i + 1, whole.len(), "an error ends decoding"),
            _ => {}
        }
    }
    let _ = wiretap_protocol::hpack::Decoder::new(4096).decode(rest, 512, 1 << 16);

    // Server-Sent Events: the same events however the stream is split, data within the limit.
    use wiretap_protocol::sse::Decoder as Sse;
    let whole = Sse::new(64).feed(rest);
    let mut d = Sse::new(64);
    let cut = (usize::from(mode) * 13) % (rest.len() + 1);
    let mut split = d.feed(&rest[..cut]);
    split.extend(d.feed(&rest[cut..]));
    assert_eq!(whole, split);
    assert!(whole.iter().all(|e| e.data.len() <= 64 + 4));
}
/// gRPC framing (all three forms) and the schema-less protobuf view: the same messages however
/// the body is split, kept parts within the limit, an error always last; the view, status and
/// description of anything never panic and stay bounded.
pub fn grpc(data: &[u8]) {
    use wiretap_protocol::grpc::{
        Decoder, Framing, describe, protobuf_text, status, trailer_fields,
    };
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let framing = [Framing::Grpc, Framing::Web, Framing::WebText][usize::from(mode % 3)];
    let whole = Decoder::new(framing, 64).feed(rest);
    let cut = usize::from(mode) * 29 % (rest.len() + 1);
    let mut d = Decoder::new(framing, 64);
    let mut split = d.feed(&rest[..cut]);
    split.extend(d.feed(&rest[cut..]));
    assert_eq!(whole, split);
    for (i, m) in whole.iter().enumerate() {
        match m {
            Ok(m) => {
                assert!(m.data.len() <= 64 && m.data.len() as u64 <= m.size);
                let encoding = if mode & 8 == 0 { "gzip" } else { "deflate" };
                let (_, payload) = describe(m, encoding, mode & 16 != 0, 1 << 16);
                assert!(payload.len() <= 1 << 16);
                let fields = trailer_fields(&m.data);
                let _ = status(fields.iter().map(|(n, v)| (n.as_str(), v.as_str())));
            }
            Err(_) => assert_eq!(i + 1, whole.len(), "an error ends decoding"),
        }
    }
    if let Some(text) = protobuf_text(rest, 512) {
        assert!(text.len() <= 512 + 4, "{}", text.len());
    }
}
