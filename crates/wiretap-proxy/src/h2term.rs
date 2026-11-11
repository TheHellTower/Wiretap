//! HTTP/2 connections to hosts an auto-reply or redirect rule targets: Wiretap terminates both
//! sides. It is the HTTP/2 server of the app and a client of the real server, each side with its
//! own flow control and header compression, so every request can be answered by a rule, sent to
//! another server, or forwarded; streams map one to one. Connections to other hosts keep the
//! byte-exact relay of `h2.rs`.
//!
//! Flow control: Wiretap grants each side [`WINDOW`] bytes per stream and for the connection, and
//! returns credit as it forwards, so at most that much waits per direction. Header blocks are
//! re-encoded as literals (`hpack::encode`), so neither side's compression state is touched.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::Shutdown;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use wiretap_autoreply::{Decision, Request, split_url};
use wiretap_core::{HttpHeader, HttpResponse};
use wiretap_protocol::hpack::{self, Field};
use wiretap_protocol::http2::{Decoder, Event, PREFACE};

use crate::h2::Recorder;
use crate::{MAX_REQUEST_BODY, Proxy, RELAY_TICK, Stream, UPSTREAM_TIMEOUT, timed_out};

/// Wiretap's receive window on both sides, per stream and for the connection.
const WINDOW: u32 = 1 << 20;
const DEFAULT_WINDOW: i64 = 65_535;
const DEFAULT_FRAME: usize = 16_384;
/// How long Wiretap waits for the server's settings before answering the app.
const SETTINGS_WAIT: Duration = Duration::from_secs(5);

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const ENABLE_PUSH: u16 = 2;
const MAX_CONCURRENT_STREAMS: u16 = 3;
const INITIAL_WINDOW_SIZE: u16 = 4;
const MAX_FRAME_SIZE: u16 = 5;
const ENABLE_CONNECT_PROTOCOL: u16 = 8;
const NO_ERROR: u32 = 0;
const PROTOCOL_ERROR: u32 = 1;
const REFUSED_STREAM: u32 = 7;

/// Response header fields that do not exist in HTTP/2 (RFC 9113 8.2.2).
const HOP_BY_HOP: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
];

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(0).to_be_bytes();
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&[len[1], len[2], len[3], kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
    let payload: Vec<u8> = pairs
        .iter()
        .flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes()))
        .collect();
    frame(SETTINGS, 0, 0, &payload)
}

fn goaway(last: u32, code: u32) -> Vec<u8> {
    frame(
        GOAWAY,
        0,
        0,
        &[last.to_be_bytes(), code.to_be_bytes()].concat(),
    )
}

/// `:status` and the regular fields of an HTTP/1.x-style response, as HTTP/2 wants them.
fn response_fields(response: &HttpResponse) -> Vec<Field> {
    std::iter::once((":status".to_owned(), response.status.to_string()))
        .chain(
            response
                .headers
                .iter()
                .filter(|h| !HOP_BY_HOP.iter().any(|n| h.name.eq_ignore_ascii_case(n)))
                .map(|h| (h.name.to_ascii_lowercase(), h.value.clone())),
        )
        .collect()
}

/// Something to send on a stream, in order.
enum Item {
    /// A header block (head, informational head or trailers), ending the stream or not.
    Headers(Vec<Field>, bool),
    /// Body bytes; whether sending them returns credit to the side they came from.
    Data(Vec<u8>, bool),
    /// The end of the stream (END_STREAM on the last DATA, or an empty DATA).
    End,
    /// RST_STREAM with this code.
    Reset(u32),
}

/// What waits to be sent toward one side for a stream, and the stream's credit there.
#[derive(Default)]
struct Pipe {
    items: VecDeque<Item>,
    window: i64,
    ended: bool,
}

/// How a client stream is handled.
enum Route {
    /// The request body is still coming: a rule looks at bodies, or a redirect needs it.
    Deciding {
        fields: Vec<Field>,
        body: Vec<u8>,
        /// A redirect already decided: the target URL and whether to keep `Host`.
        redirect: Option<(String, bool)>,
    },
    /// Sent to the server, on this server stream.
    Forwarded(u32),
    /// Answered by Wiretap (a rule's reply, or a redirect's response).
    Local,
}

struct Pair {
    route: Route,
    /// Toward the server (the request) and toward the client (the response).
    up: Pipe,
    down: Pipe,
    client_done: bool,
    server_done: bool,
    /// A rule's delay: the response waits until then.
    ready: Option<Instant>,
}

/// One side of the connection.
struct Side {
    decoder: Decoder,
    out: Vec<u8>,
    /// Connection credit for sending to this side.
    window: i64,
    /// The side's SETTINGS_INITIAL_WINDOW_SIZE and SETTINGS_MAX_FRAME_SIZE.
    initial: i64,
    max_frame: usize,
    closed: bool,
}

impl Side {
    fn new(client: bool) -> Self {
        Self {
            decoder: Decoder::new(client),
            out: Vec::new(),
            window: DEFAULT_WINDOW,
            initial: DEFAULT_WINDOW,
            max_frame: DEFAULT_FRAME,
            closed: false,
        }
    }

    /// Applies the side's settings and acknowledges them; returns the change of its initial
    /// stream window (applied to every open stream, RFC 9113 6.9.2).
    fn apply(&mut self, pairs: &[(u16, u32)]) -> i64 {
        let mut delta = 0;
        for &(id, value) in pairs {
            match id {
                INITIAL_WINDOW_SIZE => {
                    delta += i64::from(value) - self.initial;
                    self.initial = i64::from(value);
                }
                MAX_FRAME_SIZE => {
                    let max = usize::try_from(value).unwrap_or(DEFAULT_FRAME);
                    self.max_frame = max.clamp(DEFAULT_FRAME, (1 << 24) - 1);
                }
                _ => {}
            }
        }
        self.out.extend(frame(SETTINGS, ACK, 0, &[]));
        delta
    }

    /// A header block on `stream`, in frames of the side's size.
    fn headers(&mut self, stream: u32, fields: &[Field], end_stream: bool) {
        let block = hpack::encode(fields);
        let parts: Vec<&[u8]> = if block.is_empty() {
            vec![&[]]
        } else {
            block.chunks(self.max_frame).collect()
        };
        for (i, part) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            let mut flags = if last { END_HEADERS } else { 0 };
            if i == 0 && end_stream {
                flags |= END_STREAM;
            }
            let kind = if i == 0 { HEADERS } else { CONTINUATION };
            self.out.extend(frame(kind, flags, stream, part));
        }
    }

    /// Returns `n` bytes of credit for the connection and, while it is still sending, `stream`.
    fn credit(&mut self, stream: Option<u32>, n: usize) {
        if n == 0 {
            return;
        }
        let increment = u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes();
        self.out.extend(frame(WINDOW_UPDATE, 0, 0, &increment));
        if let Some(stream) = stream {
            self.out.extend(frame(WINDOW_UPDATE, 0, stream, &increment));
        }
    }
}

/// Sends what `pipe` holds to `to` on `stream`, as far as credit allows; credit for forwarded
/// bytes goes back to `from` (its `from_stream`, while that side still sends on it).
fn send(to: &mut Side, stream: u32, pipe: &mut Pipe, from: &mut Side, from_stream: Option<u32>) {
    loop {
        let next_is_end = matches!(pipe.items.get(1), Some(Item::End));
        let Some(item) = pipe.items.front_mut() else {
            return;
        };
        match item {
            Item::Headers(fields, end) => {
                to.headers(stream, fields, *end);
                pipe.ended |= *end;
            }
            Item::Data(bytes, credit) => {
                let room = usize::try_from(to.window.min(pipe.window).max(0)).unwrap_or(0);
                let n = bytes.len().min(to.max_frame).min(room);
                if n == 0 && !bytes.is_empty() {
                    return; // wait for credit
                }
                let last = n == bytes.len();
                let end = last && next_is_end;
                let flags = if end { END_STREAM } else { 0 };
                to.out.extend(frame(
                    DATA,
                    flags,
                    stream,
                    bytes.get(..n).unwrap_or_default(),
                ));
                let used = i64::try_from(n).unwrap_or(i64::MAX);
                to.window -= used;
                pipe.window -= used;
                if *credit {
                    from.credit(from_stream, n);
                }
                if !last {
                    bytes.drain(..n);
                    continue;
                }
                if end {
                    pipe.items.pop_front(); // the data; the end goes below
                    pipe.ended = true;
                }
            }
            Item::End => {
                to.out.extend(frame(DATA, END_STREAM, stream, &[]));
                pipe.ended = true;
            }
            Item::Reset(code) => {
                let code = *code;
                to.out
                    .extend(frame(RST_STREAM, 0, stream, &code.to_be_bytes()));
                pipe.ended = true;
            }
        }
        pipe.items.pop_front();
    }
}

/// What the rules decided for a request (owned, so the rule set can be released).
enum Outcome {
    Reply {
        response: HttpResponse,
        body: Vec<u8>,
        delay: Duration,
        rule: String,
    },
    Redirect {
        url: String,
        keep_host: bool,
        rule: String,
    },
    Forward,
}

/// A redirected request's response, from its fetching thread.
type Fetched = (u32, Result<(HttpResponse, Vec<u8>), String>);

struct Engine<'p, 'a> {
    proxy: &'p Proxy<'a>,
    rec: Recorder,
    client: Side,
    server: Side,
    /// By client stream ID.
    pairs: BTreeMap<u32, Pair>,
    by_server: HashMap<u32, u32>,
    next_server: u32,
    last_client: u32,
    /// The server sent GOAWAY or closed: new requests cannot be forwarded.
    server_gone: bool,
    /// The server's first settings (some are mirrored to the client).
    server_settings: Option<Vec<(u16, u32)>>,
    requests: usize,
}

impl<'a> Proxy<'a> {
    /// Serves an HTTP/2 connection whose host a rule targets, terminating both sides (see the
    /// module docs): `client` and `server` speak HTTP/2 (after TLS, or h2c), `early` holds
    /// client bytes already read, `connection` is the connection's flow and `authority` names
    /// the server. `on_request` runs for each request. Returns how many requests there were.
    pub(crate) fn terminate_h2(
        &self,
        client: &mut dyn Stream,
        server: &mut dyn Stream,
        early: &[u8],
        connection: &mut wiretap_core::Flow,
        authority: &str,
        on_request: &dyn Fn(),
    ) -> usize {
        let mut e = Engine {
            proxy: self,
            rec: Recorder::new(connection, authority),
            client: Side::new(true),
            server: Side::new(false),
            pairs: BTreeMap::new(),
            by_server: HashMap::new(),
            next_server: 1,
            last_client: 0,
            server_gone: false,
            server_settings: None,
            requests: 0,
        };
        for s in [client.socket(), server.socket()] {
            let _ = s.set_write_timeout(Some(UPSTREAM_TIMEOUT));
        }
        // The server first: its settings decide what the app is told.
        e.server.out.extend_from_slice(PREFACE);
        e.server
            .out
            .extend(settings(&[(ENABLE_PUSH, 0), (INITIAL_WINDOW_SIZE, WINDOW)]));
        e.server
            .credit(None, usize::try_from(WINDOW).unwrap_or(0) - 65_535);
        let (tx, rx) = mpsc::channel::<Fetched>();
        let _ = server.socket().set_read_timeout(Some(SETTINGS_WAIT));
        let started = Instant::now();
        let mut buf = vec![0u8; 16 * 1024];
        while e.server_settings.is_none() && started.elapsed() < SETTINGS_WAIT {
            if write(server, &mut e.server).is_err() {
                return 0;
            }
            match server.read(&mut buf) {
                Ok(n) if n > 0 => e.feed(false, buf.get(..n).unwrap_or_default(), on_request),
                _ => break,
            }
        }
        let mirrored: Vec<(u16, u32)> = e
            .server_settings
            .iter()
            .flatten()
            .filter(|(id, _)| matches!(*id, MAX_CONCURRENT_STREAMS | ENABLE_CONNECT_PROTOCOL))
            .copied()
            .collect();
        e.client.out.extend(settings(
            &[&[(INITIAL_WINDOW_SIZE, WINDOW)], &mirrored[..]].concat(),
        ));
        e.client
            .credit(None, usize::try_from(WINDOW).unwrap_or(0) - 65_535);
        e.feed(true, early, on_request);
        thread::scope(|scope| e.run(&mut *client, &mut *server, scope, &tx, &rx, on_request));
        for s in [client.socket(), server.socket()] {
            let _ = s.shutdown(Shutdown::Both);
        }
        let requests = e.requests;
        self.h2_end(e.rec);
        requests
    }
}

fn write(io: &mut dyn Stream, side: &mut Side) -> std::io::Result<()> {
    if side.out.is_empty() {
        return Ok(());
    }
    let result = io.write_all(&side.out).and_then(|()| io.flush());
    side.out.clear();
    result
}

impl<'p, 'a> Engine<'p, 'a> {
    fn run<'s>(
        &mut self,
        client: &mut dyn Stream,
        server: &mut dyn Stream,
        scope: &'s thread::Scope<'s, '_>,
        tx: &mpsc::Sender<Fetched>,
        rx: &mpsc::Receiver<Fetched>,
        on_request: &dyn Fn(),
    ) where
        'p: 's,
        'a: 's,
    {
        for s in [client.socket(), server.socket()] {
            let _ = s.set_read_timeout(Some(RELAY_TICK));
        }
        let mut buf = vec![0u8; 16 * 1024];
        let mut retiring = false;
        loop {
            for from_client in [true, false] {
                let io: &mut dyn Stream = if from_client {
                    &mut *client
                } else {
                    &mut *server
                };
                match io.read(&mut buf) {
                    Ok(0) => self.side(from_client).closed = true,
                    Ok(n) => {
                        self.feed(from_client, buf.get(..n).unwrap_or_default(), on_request);
                    }
                    Err(e) if timed_out(&e) => {}
                    Err(_) => self.side(from_client).closed = true,
                }
            }
            while let Ok((stream, result)) = rx.try_recv() {
                self.fetched(stream, result);
            }
            self.spawn_fetches(scope, tx);
            self.flush();
            if !retiring && self.proxy.retired() {
                // The capture stopped: new requests go straight to the server; the open streams
                // (WebSocket, SSE included) go on until they end.
                retiring = true;
                self.client.out.extend(goaway(0x7FFF_FFFF, NO_ERROR));
            }
            if self.server.closed && !self.client.closed {
                // Requests still to come go to a new connection; open streams cannot finish.
                self.client.out.extend(goaway(self.last_client, NO_ERROR));
                self.client.closed = true;
            }
            let wrote =
                write(client, &mut self.client).is_ok() & write(server, &mut self.server).is_ok();
            if !wrote || self.client.closed || self.server.closed {
                break;
            }
        }
    }

    fn side(&mut self, client: bool) -> &mut Side {
        if client {
            &mut self.client
        } else {
            &mut self.server
        }
    }

    fn feed(&mut self, from_client: bool, bytes: &[u8], on_request: &dyn Fn()) {
        for event in self.side(from_client).decoder.feed(bytes) {
            self.event(from_client, event, on_request);
        }
    }

    fn event(&mut self, from_client: bool, event: Event, on_request: &dyn Fn()) {
        match event {
            Event::Error(_) => {
                let side = self.side(from_client);
                side.out.extend(goaway(0, PROTOCOL_ERROR));
                side.closed = true;
            }
            Event::Settings(pairs) => {
                let delta = self.side(from_client).apply(&pairs);
                for pair in self.pairs.values_mut() {
                    let pipe = if from_client {
                        &mut pair.down
                    } else {
                        &mut pair.up
                    };
                    pipe.window += delta;
                }
                if !from_client && self.server_settings.is_none() {
                    self.server_settings = Some(pairs);
                }
            }
            Event::Ping(data) => self
                .side(from_client)
                .out
                .extend(frame(PING, ACK, 0, &data)),
            Event::WindowUpdate {
                stream: 0,
                increment,
            } => {
                self.side(from_client).window += i64::from(increment);
            }
            Event::WindowUpdate { stream, increment } => {
                let client_stream = if from_client {
                    Some(stream)
                } else {
                    self.by_server.get(&stream).copied()
                };
                if let Some(pair) = client_stream.and_then(|c| self.pairs.get_mut(&c)) {
                    let pipe = if from_client {
                        &mut pair.down
                    } else {
                        &mut pair.up
                    };
                    pipe.window += i64::from(increment);
                }
            }
            Event::Headers {
                stream,
                fields,
                end_stream,
            } if from_client => {
                self.client_headers(stream, fields, end_stream, on_request);
            }
            Event::Data {
                stream,
                data,
                flow,
                end_stream,
            } if from_client => {
                self.client_data(stream, data, flow, end_stream);
            }
            Event::Reset { stream, code } if from_client => {
                let _ = self
                    .proxy
                    .h2_event(&mut self.rec, true, Event::Reset { stream, code });
                if let Some(Pair {
                    route: Route::Forwarded(s),
                    ..
                }) = self.pairs.remove(&stream)
                {
                    self.server
                        .out
                        .extend(frame(RST_STREAM, 0, s, &code.to_be_bytes()));
                    self.by_server.remove(&s);
                }
            }
            Event::GoAway { code, .. } if from_client => {
                let last = self.next_server.saturating_sub(2);
                self.server.out.extend(goaway(last, code));
            }
            Event::Headers {
                stream,
                fields,
                end_stream,
            } => {
                let Some(&c) = self.by_server.get(&stream) else {
                    return;
                };
                let _ = self.proxy.h2_event(
                    &mut self.rec,
                    false,
                    Event::Headers {
                        stream: c,
                        fields: fields.clone(),
                        end_stream,
                    },
                );
                if let Some(pair) = self.pairs.get_mut(&c) {
                    pair.down.items.push_back(Item::Headers(fields, end_stream));
                    pair.server_done |= end_stream;
                }
            }
            Event::Data {
                stream,
                data,
                flow,
                end_stream,
            } => {
                let Some(&c) = self.by_server.get(&stream) else {
                    self.server.credit(None, flow);
                    return;
                };
                let event = Event::Data {
                    stream: c,
                    data: data.clone(),
                    flow,
                    end_stream,
                };
                let _ = self.proxy.h2_event(&mut self.rec, false, event);
                let Some(pair) = self.pairs.get_mut(&c) else {
                    return;
                };
                self.server
                    .credit((!end_stream).then_some(stream), flow - data.len()); // padding
                if !data.is_empty() {
                    pair.down.items.push_back(Item::Data(data, true));
                }
                if end_stream {
                    pair.down.items.push_back(Item::End);
                    pair.server_done = true;
                }
            }
            Event::Reset { stream, code } => {
                let Some(c) = self.by_server.remove(&stream) else {
                    return;
                };
                let _ = self
                    .proxy
                    .h2_event(&mut self.rec, false, Event::Reset { stream: c, code });
                if self.pairs.remove(&c).is_some() {
                    self.client
                        .out
                        .extend(frame(RST_STREAM, 0, c, &code.to_be_bytes()));
                }
            }
            Event::GoAway { last, code } => {
                self.server_gone = true;
                let last_client = self
                    .by_server
                    .iter()
                    .filter(|(s, _)| **s <= last)
                    .map(|(_, c)| *c)
                    .max()
                    .unwrap_or(0);
                self.client.out.extend(goaway(last_client, code));
                // Streams the server will not process: the app may retry them elsewhere.
                let refused: Vec<(u32, u32)> = self
                    .by_server
                    .iter()
                    .filter(|(s, _)| **s > last)
                    .map(|(s, c)| (*s, *c))
                    .collect();
                for (s, c) in refused {
                    self.by_server.remove(&s);
                    if self.pairs.remove(&c).is_some() {
                        self.client.out.extend(frame(
                            RST_STREAM,
                            0,
                            c,
                            &REFUSED_STREAM.to_be_bytes(),
                        ));
                    }
                }
            }
            Event::Promise { .. } => {} // push is disabled toward the server; apps cannot push
        }
    }

    fn client_headers(
        &mut self,
        c: u32,
        fields: Vec<Field>,
        end_stream: bool,
        on_request: &dyn Fn(),
    ) {
        let event = Event::Headers {
            stream: c,
            fields: fields.clone(),
            end_stream,
        };
        if self.pairs.contains_key(&c) {
            let _ = self.proxy.h2_event(&mut self.rec, true, event);
            let Some(pair) = self.pairs.get_mut(&c) else {
                return;
            };
            pair.client_done |= end_stream;
            if let Route::Forwarded(_) = pair.route {
                pair.up.items.push_back(Item::Headers(fields, end_stream)); // trailers
            } else if end_stream {
                self.decide(c);
            }
            return;
        }
        if c <= self.last_client {
            return; // a stream already over
        }
        self.last_client = c;
        if self.proxy.h2_event(&mut self.rec, true, event) {
            self.requests += 1;
            on_request();
        }
        let url = self.rec.request(&fields).url;
        let needs_body = self.proxy.hooks().rules().needs_body(split_url(&url).0);
        self.pairs.insert(
            c,
            Pair {
                route: Route::Deciding {
                    fields,
                    body: Vec::new(),
                    redirect: None,
                },
                up: Pipe::default(),
                down: Pipe {
                    window: self.client.initial,
                    ..Pipe::default()
                },
                client_done: end_stream,
                server_done: false,
                ready: None,
            },
        );
        if end_stream || !needs_body {
            self.decide(c);
        }
    }

    fn client_data(&mut self, c: u32, data: Vec<u8>, flow: usize, end_stream: bool) {
        let event = Event::Data {
            stream: c,
            data: data.clone(),
            flow,
            end_stream,
        };
        let _ = self.proxy.h2_event(&mut self.rec, true, event);
        let still_sending = (!end_stream).then_some(c);
        let Some(pair) = self.pairs.get_mut(&c) else {
            self.client.credit(None, flow);
            return;
        };
        pair.client_done |= end_stream;
        let mut decide = false;
        match &mut pair.route {
            Route::Forwarded(_) => {
                self.client.credit(still_sending, flow - data.len()); // padding
                if !data.is_empty() {
                    pair.up.items.push_back(Item::Data(data, true));
                }
                if end_stream {
                    pair.up.items.push_back(Item::End);
                }
            }
            Route::Local => self.client.credit(still_sending, flow),
            Route::Deciding { body, .. } => {
                self.client.credit(still_sending, flow);
                let room = MAX_REQUEST_BODY.saturating_sub(body.len()).min(data.len());
                body.extend_from_slice(data.get(..room).unwrap_or_default());
                decide = end_stream || body.len() >= MAX_REQUEST_BODY;
            }
        }
        if decide {
            self.decide(c);
        }
    }

    /// Decides a stream whose request head (and, when rules need it, body) arrived: answered by
    /// a rule, redirected, or forwarded.
    fn decide(&mut self, c: u32) {
        let Some(Pair {
            route:
                Route::Deciding {
                    fields,
                    body,
                    redirect: None,
                },
            ..
        }) = self.pairs.get(&c)
        else {
            return; // decided already (a redirect is fetched once the body is complete)
        };
        let request = self.rec.request(fields);
        let outcome = {
            let rules = self.proxy.hooks().rules();
            let flow = self.rec.connection();
            let view = Request {
                method: &request.method,
                url: &request.url,
                headers: &request.headers,
                body,
                process: flow.process.as_ref().and_then(|p| p.name.as_deref()),
                client: flow.client.map(|e| e.ip),
                server: flow.server.map(|e| e.ip),
            };
            match rules.decide(view) {
                Some(Decision::Reply(reply)) => Outcome::Reply {
                    response: reply.response.to_model(),
                    body: if request.method.eq_ignore_ascii_case("HEAD") {
                        Vec::new()
                    } else {
                        reply.response.body.clone()
                    },
                    delay: Duration::from_millis(u64::from(reply.delay_ms)),
                    rule: reply.rule.id.to_string(),
                },
                Some(Decision::Redirect { rule, url }) => Outcome::Redirect {
                    keep_host: rule.redirect.as_ref().is_some_and(|r| r.keep_host),
                    url,
                    rule: rule.id.to_string(),
                },
                None => Outcome::Forward,
            }
        };
        match outcome {
            Outcome::Reply {
                response,
                body,
                delay,
                rule,
            } => {
                self.answer(
                    c,
                    &response,
                    body,
                    vec!["auto-reply".into(), format!("rule:{rule}")],
                );
                if let Some(pair) = self.pairs.get_mut(&c) {
                    pair.ready = Some(Instant::now() + delay);
                }
            }
            Outcome::Redirect {
                url,
                keep_host,
                rule,
            } => {
                let mut to = format!("to:{url}");
                to.truncate(to.floor_char_boundary(240));
                self.rec
                    .tag(c, ["redirect".into(), format!("rule:{rule}"), to]);
                if let Some(Pair {
                    route: Route::Deciding { redirect, .. },
                    ..
                }) = self.pairs.get_mut(&c)
                {
                    *redirect = Some((url, keep_host));
                }
            }
            Outcome::Forward => self.forward(c),
        }
    }

    /// Answers stream `c` with `response` and `body`, recorded with `tags`.
    fn answer(&mut self, c: u32, response: &HttpResponse, body: Vec<u8>, tags: Vec<String>) {
        let fields = response_fields(response);
        self.rec.tag(c, tags);
        let end = body.is_empty();
        let _ = self.proxy.h2_event(
            &mut self.rec,
            false,
            Event::Headers {
                stream: c,
                fields: fields.clone(),
                end_stream: end,
            },
        );
        if !end {
            let event = Event::Data {
                stream: c,
                data: body.clone(),
                flow: 0,
                end_stream: true,
            };
            let _ = self.proxy.h2_event(&mut self.rec, false, event);
        }
        let Some(pair) = self.pairs.get_mut(&c) else {
            return;
        };
        pair.route = Route::Local;
        pair.down.items.push_back(Item::Headers(fields, end));
        if !end {
            pair.down.items.push_back(Item::Data(body, false));
            pair.down.items.push_back(Item::End);
        }
        if !pair.client_done {
            // The answer does not need the rest of the request (RFC 9113 8.1).
            pair.down.items.push_back(Item::Reset(NO_ERROR));
        }
        pair.server_done = true;
    }

    /// Sends stream `c` to the server, with the body received so far.
    fn forward(&mut self, c: u32) {
        let Some(pair) = self.pairs.get_mut(&c) else {
            return;
        };
        let Route::Deciding { fields, body, .. } = std::mem::replace(&mut pair.route, Route::Local)
        else {
            return;
        };
        if self.server_gone {
            self.pairs.remove(&c);
            self.client
                .out
                .extend(frame(RST_STREAM, 0, c, &REFUSED_STREAM.to_be_bytes()));
            return;
        }
        let s = self.next_server;
        self.next_server += 2;
        self.by_server.insert(s, c);
        pair.route = Route::Forwarded(s);
        pair.up.window = self.server.initial;
        let done = pair.client_done;
        pair.up
            .items
            .push_back(Item::Headers(fields, done && body.is_empty()));
        if !body.is_empty() {
            pair.up.items.push_back(Item::Data(body, false)); // already credited
            if done {
                pair.up.items.push_back(Item::End);
            }
        }
    }

    /// Starts fetching redirected requests whose body is complete.
    fn spawn_fetches<'s>(&mut self, scope: &'s thread::Scope<'s, '_>, tx: &mpsc::Sender<Fetched>)
    where
        'p: 's,
        'a: 's,
    {
        let ready: Vec<u32> = self
            .pairs
            .iter()
            .filter(|(_, p)| {
                p.client_done
                    && matches!(
                        &p.route,
                        Route::Deciding {
                            redirect: Some(_),
                            ..
                        }
                    )
            })
            .map(|(c, _)| *c)
            .collect();
        for c in ready {
            let Some(pair) = self.pairs.get_mut(&c) else {
                continue;
            };
            let Route::Deciding {
                fields,
                body,
                redirect: Some((url, keep_host)),
            } = std::mem::replace(&mut pair.route, Route::Local)
            else {
                continue;
            };
            let request = self.rec.request(&fields);
            // The original authority travels as `Host` (kept or replaced by the target's).
            let host = split_url(&request.url);
            let authority = request
                .url
                .split_once("://")
                .and_then(|(_, r)| r.split(['/', '?']).next())
                .unwrap_or(host.0)
                .to_owned();
            let mut headers = vec![HttpHeader {
                name: "Host".into(),
                value: authority,
            }];
            headers.extend(
                request
                    .headers
                    .iter()
                    .filter(|h| !h.name.eq_ignore_ascii_case("host"))
                    .cloned(),
            );
            let (proxy, tx) = (self.proxy, tx.clone());
            scope.spawn(move || {
                let result = proxy.fetch(&url, &request.method, &headers, keep_host, &body);
                let _ = tx.send((c, result));
            });
        }
    }

    fn fetched(&mut self, c: u32, result: Result<(HttpResponse, Vec<u8>), String>) {
        match result {
            Ok((response, body)) => self.answer(c, &response, body, Vec::new()),
            Err(message) => {
                let body = format!("Wiretap proxy: {message}").into_bytes();
                let response = HttpResponse {
                    status: 502,
                    reason: String::new(),
                    version: wiretap_core::HttpVersion::Http2,
                    headers: vec![HttpHeader {
                        name: "content-type".into(),
                        value: "text/plain; charset=utf-8".into(),
                    }],
                    body: None,
                };
                self.answer(c, &response, body, vec!["proxy-error".into()]);
            }
        }
    }

    /// Sends what can be sent on every stream, and forgets streams that are over.
    fn flush(&mut self) {
        let now = Instant::now();
        let Self {
            pairs,
            client,
            server,
            by_server,
            ..
        } = self;
        for (&c, pair) in pairs.iter_mut() {
            if let Route::Forwarded(s) = pair.route {
                let from = (!pair.client_done).then_some(c);
                send(server, s, &mut pair.up, client, from);
            }
            if pair.ready.is_none_or(|t| now >= t) {
                let from = match pair.route {
                    Route::Forwarded(s) => (!pair.server_done).then_some(s),
                    _ => None,
                };
                send(client, c, &mut pair.down, server, from);
            }
        }
        pairs.retain(|_, p| {
            let over = p.down.ended
                && p.down.items.is_empty()
                && (p.up.ended || !matches!(p.route, Route::Forwarded(_)));
            if over && let Route::Forwarded(s) = p.route {
                by_server.remove(&s);
            }
            !over
        });
    }
}
