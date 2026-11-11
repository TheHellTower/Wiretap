//! HAR 1.2 (HTTP Archive) import and export of sessions, the format browsers' developer tools
//! and other debuggers exchange. Export keeps Wiretap's extras (process, capture source, tags)
//! in `_wiretap` fields, which HAR reserves for custom data. Import is strict and bounded:
//! every entry becomes a validated flow in a new session, or is skipped and counted. WebSocket
//! messages travel in `_webSocketMessages`, the field browsers use.

use std::collections::HashMap;

use serde_json::{Value, json};
use wiretap_autoreply::base64;
use wiretap_core::{
    CaptureSource, Direction, Endpoint, EventId, EventMetadata, Flow, FlowId, FlowTiming,
    HttpHeader, HttpRequest, HttpResponse, HttpVersion, Inspection, NetworkEvent,
    PayloadEncryption, PayloadReference, ProcessInfo, Protocol, Session, SessionId, Timestamp,
};
use wiretap_protocol::websocket::{Message, Opcode};
use wiretap_storage::{MAX_PAGE, Store};

/// Entries accepted per imported file.
const MAX_ENTRIES: usize = 100_000;
/// Body bytes stored per message (the full size is kept).
const STORE_LIMIT: usize = 4 << 20;

/// HAR date-time (`2026-11-09T10:15:33.492Z`).
fn iso(ts: Timestamp) -> String {
    format!("{}Z", ts.utc().replacen(' ', "T", 1))
}

const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses an ISO 8601 date-time with optional fraction and `Z` / `±hh:mm` offset.
fn parse_time(s: &str) -> Option<Timestamp> {
    let num = |from: usize, to: usize| {
        s.get(from..to)
            .filter(|d| d.bytes().all(|b| b.is_ascii_digit()))?
            .parse::<i64>()
            .ok()
    };
    let sep = |at: usize, ok: &[u8]| s.as_bytes().get(at).is_some_and(|b| ok.contains(b));
    if !(sep(4, b"-") && sep(7, b"-") && sep(10, b"T ") && sep(13, b":") && sep(16, b":")) {
        return None;
    }
    let (y, mo, d, h, mi, se) = (
        num(0, 4)?,
        num(5, 7)?,
        num(8, 10)?,
        num(11, 13)?,
        num(14, 16)?,
        num(17, 19)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = s.get(19..)?;
    let mut micros = 0i64;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        let kept = fraction.get(..digits.min(6))?;
        micros = format!("{kept:0<6}").parse().ok()?;
        rest = fraction.get(digits..)?;
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        o => {
            let sign = match o.as_bytes().first() {
                Some(b'+') => 1,
                Some(b'-') => -1,
                _ => return None,
            };
            let (oh, om) = (
                o.get(1..3)?.parse::<i64>().ok()?,
                o.get(4..6)?.parse::<i64>().ok()?,
            );
            if o.len() != 6 || o.as_bytes().get(3) != Some(&b':') || oh > 23 || om > 59 {
                return None;
            }
            sign * (oh * 3600 + om * 60)
        }
    };
    let seconds = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset;
    Some(Timestamp(
        seconds.checked_mul(1_000_000)?.checked_add(micros)?,
    ))
}

/// Sets `key` on a JSON object (no-op on anything else).
fn set(object: &mut Value, key: &str, value: Value) {
    if let Some(map) = object.as_object_mut() {
        map.insert(key.to_owned(), value);
    }
}

fn header_list(headers: &[HttpHeader]) -> Value {
    headers
        .iter()
        .map(|h| json!({ "name": h.name, "value": h.value }))
        .collect()
}

fn header(headers: &[HttpHeader], name: &str) -> String {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map_or_else(String::new, |h| h.value.clone())
}

/// A body as HAR text: UTF-8 as is, anything else base64 (`encoding` says which).
fn body_text(bytes: &[u8]) -> (String, Option<&'static str>) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_owned(), None),
        Err(_) => (base64::encode(bytes), Some("base64")),
    }
}

fn millis(from: Timestamp, to: Option<Timestamp>) -> f64 {
    to.map_or(0.0, |t| {
        let micros = u32::try_from((t.0 - from.0).max(0)).unwrap_or(u32::MAX);
        f64::from(micros) / 1000.0
    })
}

fn entry(store: &Store, flow: &Flow, messages: Option<&Vec<Value>>) -> Option<Value> {
    let request = flow.request.as_ref()?;
    let load = |r: Option<PayloadReference>| r.and_then(|r| store.payload(r.id).ok().flatten());
    let query: Vec<Value> = request
        .url
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(""))
        .into_iter()
        .flat_map(|q| q.split('&'))
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (name, value) = kv.split_once('=').unwrap_or((kv, ""));
            json!({ "name": name, "value": value })
        })
        .collect();
    let mut req = json!({
        "method": request.method, "url": request.url, "httpVersion": request.version,
        "headers": header_list(&request.headers), "queryString": query, "cookies": [],
        "headersSize": -1, "bodySize": request.body.map_or(0, |b| i64::try_from(b.size).unwrap_or(-1)),
    });
    if let Some(bytes) = load(request.body) {
        let (text, encoding) = body_text(&bytes);
        let mut post =
            json!({ "mimeType": header(&request.headers, "content-type"), "text": text });
        if let Some(e) = encoding {
            set(&mut post, "_encoding", json!(e));
        }
        set(&mut req, "postData", post);
    }
    let t = &flow.timing;
    let res = flow.response.as_ref().map_or_else(
        || json!({ "status": 0, "statusText": "", "httpVersion": "", "headers": [], "cookies": [],
                   "content": { "size": 0, "mimeType": "" }, "redirectURL": "", "headersSize": -1, "bodySize": -1 }),
        |r| {
            let mut content = json!({ "size": r.body.map_or(0, |b| b.size), "mimeType": header(&r.headers, "content-type") });
            if let Some(mut bytes) = load(r.body) {
                // HAR `content.text` is the decoded body; keep the stored bytes if decoding fails.
                let coding = header(&r.headers, "content-encoding");
                if !coding.is_empty() {
                    let decoded = wiretap_codec::decode(&coding, &bytes, crate::server::DECODE_LIMIT);
                    if decoded.error.is_none() {
                        let saved = i64::try_from(decoded.bytes.len()).unwrap_or(0)
                            - i64::try_from(bytes.len()).unwrap_or(0);
                        set(&mut content, "size", json!(decoded.bytes.len()));
                        set(&mut content, "compression", json!(saved));
                        bytes = decoded.bytes;
                    }
                }
                let (text, encoding) = body_text(&bytes);
                set(&mut content, "text", json!(text));
                if let Some(e) = encoding {
                    set(&mut content, "encoding", json!(e));
                }
            }
            json!({ "status": r.status, "statusText": r.reason, "httpVersion": r.version,
                    "headers": header_list(&r.headers), "cookies": [], "content": content,
                    "redirectURL": header(&r.headers, "location"), "headersSize": -1,
                    "bodySize": r.body.map_or(0, |b| i64::try_from(b.size).unwrap_or(-1)) })
        },
    );
    let wait = millis(t.started, t.response_started);
    let total = millis(t.started, t.response_complete.or(t.response_started));
    let mut e = json!({
        "startedDateTime": iso(t.started), "time": total, "request": req, "response": res, "cache": {},
        "timings": { "send": 0, "wait": wait, "receive": (total - wait).max(0.0) },
        "_wiretap": { "source": flow.source, "process": flow.process, "tags": flow.tags },
    });
    if let Some(server) = flow.server {
        set(&mut e, "serverIPAddress", json!(server.ip.to_string()));
    }
    if let Some(messages) = messages {
        set(&mut e, "_webSocketMessages", json!(messages));
    }
    Some(e)
}

const OPCODES: [Opcode; 5] = [
    Opcode::Text,
    Opcode::Binary,
    Opcode::Close,
    Opcode::Ping,
    Opcode::Pong,
];

/// The session's WebSocket messages per flow, as browsers write them in HAR files
/// (`_webSocketMessages`: send/receive, time in seconds, opcode, text or base64 data).
fn websocket_messages(
    store: &Store,
    session: SessionId,
) -> Result<HashMap<FlowId, Vec<Value>>, String> {
    let mut messages: HashMap<FlowId, Vec<Value>> = HashMap::new();
    let mut cursor = None;
    loop {
        let events = store
            .events(session, cursor, MAX_PAGE)
            .map_err(|e| e.to_string())?;
        let Some(last) = events.last() else { break };
        cursor = Some((last.timestamp, last.id));
        for e in events.iter().filter(|e| e.protocol == Protocol::Websocket) {
            let name = e.metadata.attributes.get("opcode").map(String::as_str);
            let (Some(flow), Some(opcode)) = (
                e.metadata.flow_id,
                OPCODES.into_iter().find(|o| Some(o.name()) == name),
            ) else {
                continue; // decoding errors are not messages
            };
            let bytes = e
                .payload
                .and_then(|r| store.payload(r.id).ok().flatten())
                .unwrap_or_default();
            let data = if opcode == Opcode::Binary {
                base64::encode(&bytes)
            } else {
                String::from_utf8_lossy(&bytes).into_owned()
            };
            messages.entry(flow).or_default().push(json!({
                "type": if e.direction == Direction::Outbound { "send" } else { "receive" },
                "time": e.timestamp.0 as f64 / 1e6, "opcode": opcode.code(), "data": data,
            }));
        }
    }
    Ok(messages)
}

/// The WebSocket messages of a HAR entry (see [`websocket_messages`]) as events of `flow`.
fn websocket_events(store: &Store, flow: &Flow, entry: &Value) -> Vec<NetworkEvent> {
    let list = entry.get("_webSocketMessages").and_then(Value::as_array);
    list.into_iter()
        .flatten()
        .filter_map(|m| {
            let opcode = Opcode::from_code(u8::try_from(m.get("opcode")?.as_u64()?).ok()?)?;
            let data = str_of(m, "data");
            let payload = match opcode {
                Opcode::Binary => base64::decode(data).unwrap_or_else(|| data.as_bytes().to_vec()),
                _ => data.as_bytes().to_vec(),
            };
            let seconds = m
                .get("time")?
                .as_f64()
                .filter(|t| t.is_finite() && (0.0..1e11).contains(t))?;
            let message = Message::new(opcode, payload);
            let stored = message
                .payload
                .get(..message.payload.len().min(STORE_LIMIT))
                .unwrap_or_default();
            let event = NetworkEvent {
                id: EventId::generate(),
                session_id: flow.session_id,
                timestamp: Timestamp(format!("{:.0}", seconds * 1e6).parse().ok()?),
                source: CaptureSource::Import,
                protocol: Protocol::Websocket,
                direction: if str_of(m, "type") == "send" {
                    Direction::Outbound
                } else {
                    Direction::Inbound
                },
                process: flow.process.clone(),
                local_endpoint: flow.client,
                remote_endpoint: flow.server,
                payload: (message.size > 0)
                    .then(|| {
                        store
                            .insert_payload(
                                flow.session_id,
                                stored,
                                message.size,
                                PayloadEncryption::Cleartext,
                            )
                            .ok()
                    })
                    .flatten(),
                metadata: EventMetadata {
                    inspection: Inspection::Intercepted,
                    flow_id: Some(flow.id),
                    attributes: message.attributes(),
                },
            };
            event.validate().is_ok().then_some(event)
        })
        .collect()
}

/// The session as a HAR 1.2 document.
///
/// # Errors
/// Storage failures.
pub(crate) fn export(store: &Store, session: &Session) -> Result<Vec<u8>, String> {
    let messages = websocket_messages(store, session.id)?;
    let mut entries = Vec::new();
    let mut cursor = None;
    loop {
        let flows = store
            .flows(session.id, cursor, MAX_PAGE)
            .map_err(|e| e.to_string())?;
        let Some(last) = flows.last() else { break };
        cursor = Some((last.timing.started, last.id));
        entries.extend(
            flows
                .iter()
                .filter_map(|f| entry(store, f, messages.get(&f.id))),
        );
    }
    let har = json!({ "log": {
        "version": "1.2",
        "creator": { "name": "Wiretap", "version": env!("CARGO_PKG_VERSION") },
        "pages": [], "comment": session.name, "entries": entries,
    }});
    serde_json::to_vec_pretty(&har).map_err(|e| e.to_string())
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn headers_of(v: &Value) -> Vec<HttpHeader> {
    v.get("headers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|h| {
            Some(HttpHeader {
                name: h.get("name")?.as_str()?.to_owned(),
                value: h.get("value")?.as_str()?.to_owned(),
            })
        })
        .filter(|h| !h.name.starts_with(':')) // HTTP/2 pseudo-headers are in the URL and status
        .collect()
}

fn version_of(v: &Value) -> HttpVersion {
    serde_json::from_value(v.get("httpVersion").cloned().unwrap_or_default())
        .unwrap_or(HttpVersion::Http11)
}

fn decode_body(text: &str, encoding: &str) -> Option<Vec<u8>> {
    if encoding.eq_ignore_ascii_case("base64") {
        base64::decode(text)
    } else {
        Some(text.as_bytes().to_vec())
    }
}

/// Imports a HAR document into a new session named `name`. Returns the session and how many
/// entries were imported and skipped.
///
/// # Errors
/// Not a HAR document, or storage failures.
pub(crate) fn import(
    store: &mut Store,
    name: &str,
    har: &[u8],
) -> Result<(Session, usize, usize), String> {
    let doc: Value = serde_json::from_slice(har).map_err(|e| format!("not a HAR file: {e}"))?;
    let entries = doc
        .get("log")
        .and_then(|l| l.get("entries"))
        .and_then(Value::as_array)
        .ok_or("not a HAR file: no log.entries")?;
    if entries.len() > MAX_ENTRIES {
        return Err(format!("too many entries (at most {MAX_ENTRIES})"));
    }
    let session = Session::new(name);
    store.insert_session(&session).map_err(|e| e.to_string())?;
    let (mut flows, mut events, mut skipped) = (Vec::new(), Vec::new(), 0);
    let save = |store: &mut Store, flows: &mut Vec<Flow>, events: &mut Vec<NetworkEvent>| {
        store.upsert_flows(flows).map_err(|e| e.to_string())?;
        store.insert_events(events).map_err(|e| e.to_string())?;
        flows.clear();
        events.clear();
        Ok::<_, String>(())
    };
    for e in entries {
        match flow_of(store, session.id, e) {
            Some(flow) if flow.validate().is_ok() => {
                events.extend(websocket_events(store, &flow, e));
                flows.push(flow);
            }
            _ => skipped += 1,
        }
        if flows.len() == MAX_PAGE || events.len() >= MAX_PAGE {
            save(store, &mut flows, &mut events)?;
        }
    }
    save(store, &mut flows, &mut events)?;
    let imported = entries.len() - skipped;
    Ok((session, imported, skipped))
}

fn flow_of(store: &Store, session: SessionId, e: &Value) -> Option<Flow> {
    let (req, res) = (e.get("request")?, e.get("response")?);
    let url = str_of(req, "url");
    let scheme_ok = ["http://", "https://", "ws://", "wss://"].iter().any(|s| {
        url.get(..s.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(s))
    });
    if !scheme_ok {
        return None;
    }
    let started = parse_time(str_of(e, "startedDateTime"))?;
    let at = |ms: Option<f64>| {
        ms.filter(|m| m.is_finite() && *m >= 0.0 && *m < 1e10)
            .map(|m| {
                Timestamp(started.0 + format!("{:.0}", m * 1000.0).parse::<i64>().unwrap_or(0))
            })
    };
    let wait = e
        .get("timings")
        .and_then(|t| t.get("wait"))
        .and_then(Value::as_f64);
    let total = e.get("time").and_then(Value::as_f64);
    let store_body = |bytes: Vec<u8>, size: u64| {
        store
            .insert_payload(
                session,
                bytes
                    .get(..bytes.len().min(STORE_LIMIT))
                    .unwrap_or_default(),
                size,
                PayloadEncryption::Cleartext,
            )
            .ok()
    };
    let request_body = req.get("postData").and_then(|p| {
        let bytes = decode_body(str_of(p, "text"), str_of(p, "_encoding"))?;
        (!bytes.is_empty())
            .then(|| store_body(bytes.clone(), bytes.len() as u64))
            .flatten()
    });
    let status = res
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|s| u16::try_from(s).ok())
        .filter(|s| *s != 0);
    let response = status.map(|status| {
        let content = res.get("content");
        let body = content.and_then(|c| {
            let bytes = decode_body(str_of(c, "text"), str_of(c, "encoding"))?;
            let size = c
                .get("size")
                .and_then(Value::as_u64)
                .filter(|s| *s >= bytes.len() as u64)
                .unwrap_or(bytes.len() as u64);
            (!bytes.is_empty())
                .then(|| store_body(bytes, size))
                .flatten()
        });
        HttpResponse {
            status,
            reason: str_of(res, "statusText").to_owned(),
            version: version_of(res),
            headers: headers_of(res),
            body,
        }
    });
    let extra = e.get("_wiretap");
    let process = extra
        .and_then(|x| x.get("process"))
        .and_then(|p| serde_json::from_value::<ProcessInfo>(p.clone()).ok());
    let server = e
        .get("serverIPAddress")
        .and_then(Value::as_str)
        .and_then(|ip| ip.trim_matches(['[', ']']).parse().ok())
        .map(|ip| Endpoint { ip, port: None });
    Some(Flow {
        id: FlowId::generate(),
        session_id: session,
        source: CaptureSource::Import,
        process,
        client: None,
        server,
        request: Some(HttpRequest {
            method: str_of(req, "method").to_owned(),
            url: url.to_owned(),
            version: version_of(req),
            headers: headers_of(req),
            body: request_body,
        }),
        response,
        timing: FlowTiming {
            started,
            request_complete: None,
            response_started: at(wait).filter(|_| status.is_some()),
            response_complete: at(total).filter(|_| status.is_some()),
        },
        tags: if e.get("_webSocketMessages").is_some() || status == Some(101) {
            vec!["imported".into(), "websocket".into()]
        } else {
            vec!["imported".into()]
        },
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    #[test]
    fn iso_times_round_trip_and_reject_garbage() {
        let ts = Timestamp(1_794_254_133_492_000);
        assert_eq!(parse_time(&iso(ts)), Some(ts));
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(Timestamp(0)));
        assert_eq!(
            parse_time("1970-01-01T01:00:00.5+01:00"),
            Some(Timestamp(500_000))
        );
        for bad in [
            "",
            "2026-13-01T00:00:00Z",
            "2026-11-09 10:15",
            "2026-11-09T10:15:33+1",
            "x026-11-09T10:15:33Z",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }
}
