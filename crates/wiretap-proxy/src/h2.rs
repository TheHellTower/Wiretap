//! HTTP/2 connections (decrypted TLS, or cleartext h2c): relayed untouched, byte for byte as
//! they arrive, while every stream is recorded as its own exchange. Wiretap never re-encodes
//! HTTP/2, so flow control, multiplexing, server push and trailers work exactly as the two
//! endpoints negotiate. WebSockets over HTTP/2 (RFC 8441) are decoded like any other.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use wiretap_autoreply::split_url;

use wiretap_core::{Flow, FlowId, HttpHeader, HttpRequest, HttpResponse, HttpVersion, Timestamp};
use wiretap_protocol::http2::{Decoder, Event};
use wiretap_protocol::sse;
use wiretap_protocol::websocket::{self, Extensions, Sender};

use crate::{
    Exchange, Grpc, Inject, Proxy, STORE_LIMIT, Stream, grpc_status, is_event_stream, pump,
    snapshot, sse_event, values, websocket_event,
};

/// Streams recorded at once per connection (more are relayed, not recorded).
const MAX_STREAMS: usize = 1024;
/// Longest URL recorded.
const MAX_URL: usize = 8 * 1024;
/// How often a relayed connection checks whether a rule now targets its host.
const RULE_CHECK: Duration = Duration::from_secs(1);
/// GOAWAY with the last stream 2^31-1 and NO_ERROR: no new streams on this connection, none of
/// the open ones refused (RFC 9113 6.8, graceful shutdown).
const GOAWAY_ALL: [u8; 17] = [
    0, 0, 8, 7, 0, 0, 0, 0, 0, 0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0,
];

/// The streams of one HTTP/2 connection being recorded.
pub(crate) struct Recorder {
    streams: HashMap<u32, Live>,
    /// The connection's flow: process, endpoints, source, tags.
    template: Flow,
    scheme: &'static str,
    authority: String,
}

impl Recorder {
    /// Recording for `connection` (tagged `h2-connection` here; an `http://` URL means cleartext
    /// h2c, otherwise TLS was decrypted); `authority` names the server for requests without one.
    pub(crate) fn new(connection: &mut Flow, authority: &str) -> Self {
        connection.tags.push("h2-connection".into());
        let decrypted = !connection
            .request
            .as_ref()
            .is_some_and(|r| r.url.starts_with("http://"));
        let tags = if decrypted {
            vec!["decrypted", "h2"]
        } else {
            vec!["h2"]
        };
        Self {
            streams: HashMap::new(),
            template: Flow {
                tags: tags.into_iter().map(Into::into).collect(),
                ..connection.clone()
            },
            scheme: if decrypted { "https" } else { "http" },
            authority: authority.to_owned(),
        }
    }

    /// The request a client header block opens.
    pub(crate) fn request(&self, fields: &[(String, String)]) -> HttpRequest {
        request(fields, self.scheme, &self.authority)
    }

    /// The connection's flow: process and endpoints, for rules.
    pub(crate) const fn connection(&self) -> &Flow {
        &self.template
    }

    /// Adds tags to a stream's record (a rule's outcome).
    pub(crate) fn tag(&mut self, stream: u32, tags: impl IntoIterator<Item = String>) {
        if let Some(live) = self.streams.get_mut(&stream) {
            live.exchange.flow.tags.extend(tags);
        }
    }
}

/// A stream being recorded.
struct Live {
    exchange: Exchange,
    request_done: bool,
    response_done: bool,
    /// WebSocket over HTTP/2: message decoders (client, server) once the server accepted.
    websocket: Option<[websocket::Decoder; 2]>,
    /// Server-Sent Events: the response's event decoder.
    sse: Option<sse::Decoder>,
    /// gRPC: the call's message decoders.
    grpc: Option<Grpc>,
}

/// HTTP header names and methods are tokens (RFC 9110 5.6.2).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// The regular (non-pseudo) fields of a block, as the event model stores them: names that are
/// not tokens are left out, control characters in values are shown as `?`.
fn regular(fields: &[(String, String)]) -> Vec<HttpHeader> {
    fields
        .iter()
        .filter(|(name, _)| is_token(name))
        .map(|(name, value)| HttpHeader {
            name: name.clone(),
            value: value
                .chars()
                .map(|c| if c.is_control() && c != '\t' { '?' } else { c })
                .collect(),
        })
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// The request of a header block: `:method`, and the URL from `:scheme`, `:authority` (or
/// `host`) and `:path`; `scheme` and `authority` stand in for missing ones.
fn request(fields: &[(String, String)], scheme: &str, authority: &str) -> HttpRequest {
    let method = field(fields, ":method").filter(|m| is_token(m));
    let host = field(fields, ":authority")
        .or_else(|| field(fields, "host"))
        .unwrap_or(authority);
    let scheme = field(fields, ":scheme").unwrap_or(scheme);
    let path = field(fields, ":path").unwrap_or_default();
    HttpRequest {
        method: method.unwrap_or("INVALID").into(),
        url: format!("{scheme}://{host}{path}")
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_URL)
            .collect(),
        version: HttpVersion::Http2,
        headers: regular(fields),
        body: None,
    }
}

/// Keeps a prefix of a body and counts its full size.
fn store(body: &mut Vec<u8>, size: &mut u64, data: &[u8]) {
    let room = STORE_LIMIT.saturating_sub(body.len()).min(data.len());
    body.extend_from_slice(data.get(..room).unwrap_or_default());
    *size = size.saturating_add(data.len() as u64);
}

fn now(flow: &Flow) -> Option<Timestamp> {
    Some(Timestamp::now().max(flow.timing.started))
}

impl Proxy<'_> {
    /// Relays an HTTP/2 connection between `client` and `server` untouched, recording each
    /// stream; `early` holds client bytes already read (sent to the server first). `connection`
    /// is the connection's flow (process, endpoints, source; tagged here; an `http://` URL means
    /// cleartext h2c, otherwise TLS was decrypted) and `authority` names the server for requests
    /// without one. `on_request` runs for each request. Returns how many requests there were.
    pub(crate) fn relay_h2(
        &self,
        client: &mut dyn Stream,
        server: &mut dyn Stream,
        early: &[u8],
        connection: &mut Flow,
        authority: &str,
        on_request: &dyn Fn(),
    ) -> usize {
        let mut rec = Recorder::new(connection, authority);
        let mut decoders = [Decoder::new(true), Decoder::new(false)];
        let (mut requests, mut problem) = (0usize, None);
        let host = split_url(&format!("x://{authority}/")).0.to_owned();
        let (mut asked, mut checked) = (false, Instant::now());
        let mut observe = |from_client: bool, bytes: &[u8]| -> Inject {
            let [to_server, to_client] = &mut decoders;
            let decoder = if from_client { to_server } else { to_client };
            for event in decoder.feed(bytes) {
                match event {
                    Event::Error(why) => problem = Some(why),
                    event => {
                        if self.h2_event(&mut rec, from_client, event) {
                            requests += 1;
                            on_request();
                        }
                    }
                }
            }
            // A rule now targets this host (or the capture stopped): between frames, ask the app to
            // open a new connection (terminated, so rules apply; or straight to the server); the
            // streams open here finish untouched.
            if !asked && checked.elapsed() >= RULE_CHECK && decoders[1].at_boundary() {
                checked = Instant::now();
                if self.retired() || self.hooks().rules().targets_host(&host) {
                    asked = true;
                    return Some(GOAWAY_ALL.to_vec());
                }
            }
            None
        };
        if !early.is_empty() {
            if server
                .write_all(early)
                .and_then(|()| server.flush())
                .is_err()
            {
                return 0;
            }
            let _ = observe(true, early);
        }
        pump(client, server, &mut observe);
        self.h2_end(rec);
        if let Some(why) = problem {
            connection.tags.push(format!("h2-undecoded: {why}"));
        }
        requests
    }

    /// Records the streams still open (the connection ended).
    pub(crate) fn h2_end(&self, rec: Recorder) {
        for (_, mut live) in rec.streams {
            live.exchange.flow.tags.push("incomplete".into());
            self.h2_finish(live);
        }
    }

    /// Applies one decoded event (`from_client`: sent by the client); returns whether it opened
    /// a request.
    pub(crate) fn h2_event(&self, rec: &mut Recorder, from_client: bool, event: Event) -> bool {
        let Recorder {
            streams,
            template,
            scheme,
            authority,
        } = rec;
        let (template, scheme, authority) = (&*template, *scheme, authority.as_str());
        let (stream, opened) = match event {
            Event::Headers {
                stream,
                fields,
                end_stream,
            } if from_client => {
                if let Some(live) = streams.get_mut(&stream) {
                    if let Some(r) = live.exchange.flow.request.as_mut() {
                        r.headers.extend(regular(&fields)); // trailers
                    }
                    live.request_done |= end_stream;
                    (stream, false)
                } else if streams.len() < MAX_STREAMS {
                    let mut live = h2_open(template, request(&fields, scheme, authority));
                    live.grpc = Grpc::of(&regular(&fields));
                    let flow = &mut live.exchange.flow;
                    if live.grpc.is_some() {
                        flow.tags.push("grpc".into());
                    }
                    if field(&fields, ":protocol")
                        .is_some_and(|p| p.eq_ignore_ascii_case("websocket"))
                    {
                        flow.tags.push("websocket".into());
                    }
                    live.request_done = end_stream;
                    if end_stream {
                        flow.timing.request_complete = now(flow);
                    }
                    self.hooks().record(snapshot(flow)); // shows while open
                    streams.insert(stream, live);
                    (stream, true)
                } else {
                    return false;
                }
            }
            Event::Headers {
                stream,
                fields,
                end_stream,
            } => {
                let Some(live) = streams.get_mut(&stream) else {
                    return false;
                };
                let flow = &mut live.exchange.flow;
                if let Some(response) = flow.response.as_mut() {
                    response.headers.extend(regular(&fields)); // trailers
                    if live.grpc.is_some() {
                        self.hooks()
                            .event(grpc_status(flow, &regular(&fields)), Vec::new(), 0);
                    }
                } else {
                    let status = field(&fields, ":status").and_then(|s| s.parse().ok());
                    let Some(status @ 200..=999) = status else {
                        return false; // informational (100, 103) or no status
                    };
                    let headers = regular(&fields);
                    let websocket = status == 200 && flow.tags.iter().any(|t| t == "websocket");
                    let event_stream = is_event_stream(&headers);
                    if event_stream {
                        flow.tags.push("sse".into());
                        live.sse = Some(sse::Decoder::new(STORE_LIMIT));
                    }
                    if websocket {
                        let offer = values(&headers, "sec-websocket-extensions");
                        let extensions = Extensions::parse(&offer);
                        live.websocket = Some(
                            [Sender::Client, Sender::Server]
                                .map(|s| websocket::Decoder::new(s, extensions, STORE_LIMIT)),
                        );
                    }
                    flow.response = Some(HttpResponse {
                        status,
                        reason: String::new(),
                        version: HttpVersion::Http2,
                        headers,
                        body: None,
                    });
                    flow.timing.response_started = now(flow);
                    // A Trailers-Only response: an immediate status, no messages.
                    if let Some(g) = &mut live.grpc
                        && (g.respond(&regular(&fields)) || field(&fields, "grpc-status").is_some())
                        && end_stream
                    {
                        self.hooks()
                            .event(grpc_status(flow, &regular(&fields)), Vec::new(), 0);
                    }
                    if websocket || event_stream || live.grpc.is_some() {
                        self.hooks().record(snapshot(flow)); // shows while open
                    }
                }
                live.response_done |= end_stream;
                (stream, false)
            }
            Event::Promise {
                promised, fields, ..
            } => {
                if streams.len() >= MAX_STREAMS || streams.contains_key(&promised) {
                    return false;
                }
                let mut live = h2_open(template, request(&fields, scheme, authority));
                live.exchange.flow.tags.push("push".into());
                live.request_done = true;
                self.hooks().record(snapshot(&live.exchange.flow));
                streams.insert(promised, live);
                (promised, false)
            }
            Event::Data {
                stream,
                data,
                end_stream,
                ..
            } => {
                let Some(live) = streams.get_mut(&stream) else {
                    return false;
                };
                let x = &mut live.exchange;
                if from_client {
                    store(&mut x.request_body, &mut x.request_size, &data);
                    live.request_done |= end_stream;
                    if end_stream {
                        x.flow.timing.request_complete = now(&x.flow);
                    }
                } else {
                    store(&mut x.response_body, &mut x.response_size, &data);
                    live.response_done |= end_stream;
                }
                if let Some([client, server]) = &mut live.websocket {
                    let decoder = if from_client { client } else { server };
                    for decoded in decoder.feed(&data) {
                        let (event, payload, size) =
                            websocket_event(&live.exchange.flow, from_client, decoded);
                        self.hooks().event(event, payload, size);
                    }
                }
                if let Some(g) = &mut live.grpc {
                    for (event, payload, size) in g.feed(&live.exchange.flow, from_client, &data) {
                        self.hooks().event(event, payload, size);
                    }
                }
                if let (false, Some(decoder)) = (from_client, &mut live.sse) {
                    for decoded in decoder.feed(&data) {
                        let (event, payload, size) = sse_event(&live.exchange.flow, decoded);
                        self.hooks().event(event, payload, size);
                    }
                }
                (stream, false)
            }
            Event::Reset { stream, code } => {
                let Some(live) = streams.get_mut(&stream) else {
                    return false;
                };
                live.exchange.flow.tags.push(format!("reset: {code}"));
                (live.request_done, live.response_done) = (true, true);
                (stream, false)
            }
            Event::GoAway { .. }
            | Event::Settings(_)
            | Event::Ping(_)
            | Event::WindowUpdate { .. }
            | Event::Error(_) => return false,
        };
        if streams
            .get(&stream)
            .is_some_and(|l| l.request_done && l.response_done)
            && let Some(live) = streams.remove(&stream)
        {
            self.h2_finish(live);
        }
        opened
    }

    fn h2_finish(&self, mut live: Live) {
        let t = &mut live.exchange.flow.timing;
        let end = Some(Timestamp::now().max(t.started));
        t.response_complete = end;
        t.request_complete = t.request_complete.or(end);
        self.hooks().record(live.exchange);
    }
}

/// A new stream's exchange: the connection's process, endpoints, source and tags.
fn h2_open(template: &Flow, request: HttpRequest) -> Live {
    let mut flow = Flow {
        id: FlowId::generate(),
        request: Some(request),
        response: None,
        ..template.clone()
    };
    flow.timing = wiretap_core::FlowTiming {
        started: Timestamp::now(),
        request_complete: None,
        response_started: None,
        response_complete: None,
    };
    Live {
        exchange: snapshot(&flow),
        request_done: false,
        response_done: false,
        websocket: None,
        sse: None,
        grpc: None,
    }
}
