//! Turns `WiretapDriver` records into model events and HTTP flows.
//!
//! The [`Tracker`] is pure (no I/O) and bounded: at most [`MAX_CONNECTIONS`] connections,
//! [`MAX_BUFFER`] unparsed bytes per direction and [`MAX_TOTAL_BUFFER`] overall. Everything it
//! emits has passed model validation. Inspection is honest: TLS connections only yield
//! cleartext handshake metadata, plain HTTP yields parsed message heads.
#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wiretap_core::{
    CaptureSource, Direction, Endpoint, EventId, EventMetadata, Flow, FlowId, FlowTiming,
    HttpRequest, HttpResponse, Inspection, NetworkEvent, ProcessInfo, Protocol, SessionId,
    Timestamp,
};
use wiretap_driver_proto::{DataRecord, FlowRecord, Record};
use wiretap_protocol::{
    Framing, Head, Parse, StartLine, framing, parse_client_hello, parse_head, parse_server_hello,
};

/// Connections tracked at once; the oldest is forgotten first.
pub const MAX_CONNECTIONS: usize = 65_536;
/// Unparsed bytes kept per connection direction.
pub const MAX_BUFFER: usize = 64 * 1024;
/// Unparsed bytes kept across all connections.
pub const MAX_TOTAL_BUFFER: usize = 64 * 1024 * 1024;
/// Requests awaiting a response per connection.
const MAX_PENDING: usize = 32;

/// Something the tracker observed.
#[allow(
    clippy::large_enum_variant,
    reason = "short-lived values moved straight to storage; boxing only adds allocations"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// A connection or TLS handshake event.
    Event(NetworkEvent),
    /// An HTTP flow: emitted when the request head is seen and again when the response head
    /// completes it (same flow ID).
    Flow(Flow),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unknown,
    Http,
    Tls,
    Opaque,
}

#[derive(Default)]
struct Side {
    buf: Vec<u8>,
    skip: u64,
    done: bool,
}

struct Connection {
    generation: u64,
    process: Option<ProcessInfo>,
    local: Endpoint,
    remote: Endpoint,
    inbound: bool,
    mode: Mode,
    client: Side,
    server: Side,
    pending: VecDeque<Flow>,
}

/// Correlates driver records into events and flows for one session.
pub struct Tracker {
    session: SessionId,
    devices: Vec<(String, String)>,
    connections: HashMap<u64, Connection>,
    order: VecDeque<(u64, u64)>,
    generation: u64,
    buffered: usize,
    rejected: u64,
    excluded: Vec<Endpoint>,
    excluded_pids: Vec<u64>,
}

/// Converts a Windows FILETIME (100 ns since 1601) to a Unix-epoch [`Timestamp`].
#[must_use]
pub fn filetime_to_timestamp(filetime: u64) -> Timestamp {
    const UNIX_EPOCH_AS_FILETIME: i64 = 116_444_736_000_000_000;
    Timestamp(
        i64::try_from(filetime)
            .unwrap_or(i64::MAX)
            .saturating_sub(UNIX_EPOCH_AS_FILETIME)
            / 10,
    )
}

impl Tracker {
    /// Creates a tracker. `devices` maps NT device prefixes (e.g. `\Device\HarddiskVolume3`)
    /// to drive letters (`C:`) for readable process paths.
    #[must_use]
    pub fn new(session: SessionId, devices: Vec<(String, String)>) -> Self {
        let devices = devices
            .into_iter()
            .map(|(nt, dos)| (nt.to_ascii_lowercase(), dos))
            .collect();
        Self {
            session,
            devices,
            connections: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
            buffered: 0,
            rejected: 0,
            excluded: Vec::new(),
            excluded_pids: Vec::new(),
        }
    }

    /// Ignores every connection with `endpoint` on either side, such as Wiretap's own UI
    /// server: its traffic carries Wiretap's session secrets and would feed back on itself.
    pub fn exclude(&mut self, endpoint: Endpoint) {
        self.excluded.push(endpoint);
    }

    /// Ignores every connection owned by process `pid` (Wiretap's proxy, whose traffic it
    /// records itself).
    pub fn exclude_process(&mut self, pid: u32) {
        self.excluded_pids.push(u64::from(pid));
    }

    /// Outputs dropped because they failed model validation.
    #[must_use]
    pub const fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Processes one driver record, appending anything observed to `out`.
    pub fn record(&mut self, record: &Record<'_>, out: &mut Vec<Output>) {
        let start = out.len();
        match record {
            Record::Flow(f) => self.flow(f, out),
            Record::Data(d) => self.data(d, out),
        }
        // Defense in depth: never emit data that fails validation.
        let mut index = start;
        while index < out.len() {
            let valid = match out.get(index) {
                Some(Output::Event(e)) => e.validate().is_ok(),
                Some(Output::Flow(f)) => f.validate().is_ok(),
                None => true,
            };
            if valid {
                index += 1;
            } else {
                out.remove(index);
                self.rejected += 1;
            }
        }
    }

    fn process(&self, f: &FlowRecord<'_>) -> Option<ProcessInfo> {
        let units: Vec<u16> = f
            .path
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let raw: String = String::from_utf16_lossy(&units)
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        let lower = raw.to_ascii_lowercase();
        let path = self
            .devices
            .iter()
            .find(|(nt, _)| {
                lower.starts_with(nt.as_str()) && lower.as_bytes().get(nt.len()) == Some(&b'\\')
            })
            .and_then(|(nt, dos)| raw.get(nt.len()..).map(|rest| format!("{dos}{rest}")))
            .unwrap_or(raw);
        if f.pid == 0 && path.is_empty() {
            return None;
        }
        let name = path
            .rsplit('\\')
            .next()
            .filter(|n| !n.is_empty())
            .map(str::to_owned);
        Some(ProcessInfo {
            pid: u32::try_from(f.pid).unwrap_or(u32::MAX),
            name,
            path: (!path.is_empty()).then_some(path),
            started: None,
        })
    }

    fn flow(&mut self, f: &FlowRecord<'_>, out: &mut Vec<Output>) {
        let protocol = match f.protocol {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            58 => Protocol::Icmpv6,
            _ => return,
        };
        let ip = |bytes: [u8; 16]| -> IpAddr {
            if f.ipv6 {
                Ipv6Addr::from(bytes).into()
            } else {
                let [a, b, c, d, ..] = bytes;
                Ipv4Addr::new(a, b, c, d).into()
            }
        };
        let ports = matches!(protocol, Protocol::Tcp | Protocol::Udp);
        let local = Endpoint {
            ip: ip(f.local_addr),
            port: ports.then_some(f.local_port),
        };
        let remote = Endpoint {
            ip: ip(f.remote_addr),
            port: ports.then_some(f.remote_port),
        };
        if self.excluded.iter().any(|e| *e == local || *e == remote)
            || self.excluded_pids.contains(&f.pid)
        {
            return;
        }
        let process = self.process(f);
        out.push(Output::Event(NetworkEvent {
            id: EventId::generate(),
            session_id: self.session,
            timestamp: filetime_to_timestamp(f.timestamp),
            source: CaptureSource::Driver,
            protocol,
            direction: if f.inbound {
                Direction::Inbound
            } else {
                Direction::Outbound
            },
            process: process.clone(),
            local_endpoint: Some(local),
            remote_endpoint: Some(remote),
            payload: None,
            metadata: EventMetadata {
                inspection: Inspection::Metadata,
                flow_id: None,
                attributes: Default::default(),
            },
        }));
        if protocol != Protocol::Tcp {
            return;
        }
        self.forget(f.flow);
        while self.connections.len() >= MAX_CONNECTIONS {
            let Some((handle, generation)) = self.order.pop_front() else {
                break;
            };
            if self
                .connections
                .get(&handle)
                .is_some_and(|c| c.generation == generation)
            {
                self.forget(handle);
            }
        }
        self.generation += 1;
        self.order.push_back((f.flow, self.generation));
        let connection = Connection {
            generation: self.generation,
            process,
            local,
            remote,
            inbound: f.inbound,
            mode: Mode::Unknown,
            client: Side::default(),
            server: Side::default(),
            pending: VecDeque::new(),
        };
        self.connections.insert(f.flow, connection);
    }

    fn forget(&mut self, handle: u64) {
        if let Some(c) = self.connections.remove(&handle) {
            self.buffered -= c.client.buf.len() + c.server.buf.len();
        }
    }

    fn data(&mut self, d: &DataRecord<'_>, out: &mut Vec<Output>) {
        let Some(mut c) = self.connections.remove(&d.flow) else {
            return;
        };
        let from_client = d.inbound == c.inbound;
        let before = c.client.buf.len() + c.server.buf.len();
        let side = if from_client {
            &mut c.client
        } else {
            &mut c.server
        };
        if !side.done {
            let room = MAX_BUFFER
                .saturating_sub(side.buf.len())
                .min(MAX_TOTAL_BUFFER.saturating_sub(self.buffered));
            if d.data.len() > room {
                side.done = true;
                side.buf.clear();
            } else {
                side.buf.extend_from_slice(d.data);
                let session = self.session;
                analyze(
                    &mut c,
                    session,
                    from_client,
                    filetime_to_timestamp(d.timestamp),
                    out,
                );
            }
        }
        let after = c.client.buf.len() + c.server.buf.len();
        self.buffered = self.buffered + after - before;
        self.connections.insert(d.flow, c);
    }
}

/// Shapes a cleartext TLS/HTTP observation into an event attached to the connection.
fn event(
    c: &Connection,
    session: SessionId,
    ts: Timestamp,
    protocol: Protocol,
    attributes: Vec<(&str, String)>,
) -> Output {
    Output::Event(NetworkEvent {
        id: EventId::generate(),
        session_id: session,
        timestamp: ts,
        source: CaptureSource::Driver,
        protocol,
        direction: if c.inbound {
            Direction::Inbound
        } else {
            Direction::Outbound
        },
        process: c.process.clone(),
        local_endpoint: Some(c.local),
        remote_endpoint: Some(c.remote),
        payload: None,
        metadata: EventMetadata {
            inspection: Inspection::Metadata,
            flow_id: None,
            attributes: attributes
                .into_iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        },
    })
}

fn looks_like_http_request(buf: &[u8]) -> bool {
    let token = buf.iter().take_while(|b| b.is_ascii_uppercase()).count();
    (1..=16).contains(&token) && buf.get(token).is_none_or(|&b| b == b' ')
}

fn analyze(
    c: &mut Connection,
    session: SessionId,
    from_client: bool,
    ts: Timestamp,
    out: &mut Vec<Output>,
) {
    if c.mode == Mode::Unknown {
        let first = if from_client {
            &c.client.buf
        } else {
            &c.server.buf
        };
        c.mode = match first.first() {
            Some(22) if from_client => Mode::Tls,
            Some(_) if from_client && looks_like_http_request(first) => Mode::Http,
            _ => Mode::Opaque,
        };
    }
    match c.mode {
        Mode::Tls => tls(c, session, from_client, ts, out),
        Mode::Http if from_client => requests(c, session, ts, out),
        Mode::Http => responses(c, ts, out),
        Mode::Unknown | Mode::Opaque => {
            c.client = Side {
                done: true,
                ..Side::default()
            };
            c.server = Side {
                done: true,
                ..Side::default()
            };
        }
    }
}

fn tls(
    c: &mut Connection,
    session: SessionId,
    from_client: bool,
    ts: Timestamp,
    out: &mut Vec<Output>,
) {
    if from_client {
        match parse_client_hello(&c.client.buf) {
            Parse::Partial => return,
            Parse::Complete(hello) => {
                out.push(event(c, session, ts, Protocol::Tls, hello.attributes()));
            }
            Parse::Invalid => {}
        }
        c.client = Side {
            done: true,
            ..Side::default()
        };
    } else {
        match parse_server_hello(&c.server.buf) {
            Parse::Partial => return,
            Parse::Complete(hello) => {
                out.push(event(c, session, ts, Protocol::Tls, hello.attributes()));
            }
            Parse::Invalid => {}
        }
        c.server = Side {
            done: true,
            ..Side::default()
        };
    }
}

/// Consumes body bytes still owed by the previous message; returns false while some remain.
fn skip_body(side: &mut Side) -> bool {
    let n = usize::try_from(side.skip)
        .unwrap_or(usize::MAX)
        .min(side.buf.len());
    side.buf.drain(..n);
    side.skip -= n as u64;
    side.skip == 0
}

/// Applies body framing after a head; anything but a known length ends parsing of this side.
fn after_head(side: &mut Side, head_len: usize, framing: Option<Framing>) {
    side.buf.drain(..head_len.min(side.buf.len()));
    match framing {
        Some(Framing::Empty) => {}
        Some(Framing::Length(n)) => side.skip = n,
        Some(Framing::Chunked | Framing::UntilClose) | None => side.done = true,
    }
}

fn url(head_target: &str, head: &Head, server: &Endpoint) -> String {
    if head_target.contains("://") {
        return head_target.to_owned();
    }
    let authority = head
        .header("host")
        .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_graphic()))
        .map_or_else(|| server_authority(server), str::to_owned);
    if head_target.starts_with('/') {
        format!("http://{authority}{head_target}")
    } else {
        format!("http://{authority}")
    }
}

fn server_authority(server: &Endpoint) -> String {
    match (server.ip, server.port) {
        (IpAddr::V6(ip), Some(port)) => format!("[{ip}]:{port}"),
        (ip, Some(port)) => format!("{ip}:{port}"),
        (ip, None) => ip.to_string(),
    }
}

fn requests(c: &mut Connection, session: SessionId, ts: Timestamp, out: &mut Vec<Output>) {
    let (client, server) = if c.inbound {
        (c.remote, c.local)
    } else {
        (c.local, c.remote)
    };
    while !c.client.done && skip_body(&mut c.client) && !c.client.buf.is_empty() {
        let head = match parse_head(&c.client.buf) {
            Parse::Complete(head) => head,
            Parse::Partial => return,
            Parse::Invalid => {
                c.client = Side {
                    done: true,
                    ..Side::default()
                };
                return;
            }
        };
        let StartLine::Request {
            method,
            target,
            version,
        } = &head.start
        else {
            c.client = Side {
                done: true,
                ..Side::default()
            };
            return;
        };
        let flow = Flow {
            id: FlowId::generate(),
            session_id: session,
            source: CaptureSource::Driver,
            process: c.process.clone(),
            client: Some(client),
            server: Some(server),
            request: Some(HttpRequest {
                method: method.clone(),
                url: url(target, &head, &server),
                version: *version,
                headers: head.headers.clone(),
                body: None,
            }),
            response: None,
            timing: FlowTiming {
                started: ts,
                request_complete: None,
                response_started: None,
                response_complete: None,
            },
            tags: Vec::new(),
        };
        after_head(&mut c.client, head.len, framing(&head, None));
        if c.pending.len() >= MAX_PENDING {
            c.pending.pop_front();
        }
        c.pending.push_back(flow.clone());
        out.push(Output::Flow(flow));
    }
}

fn responses(c: &mut Connection, ts: Timestamp, out: &mut Vec<Output>) {
    while !c.server.done && skip_body(&mut c.server) && !c.server.buf.is_empty() {
        let head = match parse_head(&c.server.buf) {
            Parse::Complete(head) => head,
            Parse::Partial => return,
            Parse::Invalid => {
                c.server = Side {
                    done: true,
                    ..Side::default()
                };
                return;
            }
        };
        let StartLine::Response {
            status,
            reason,
            version,
        } = &head.start
        else {
            c.server = Side {
                done: true,
                ..Side::default()
            };
            return;
        };
        if (100..200).contains(status) && *status != 101 {
            after_head(&mut c.server, head.len, Some(Framing::Empty)); // interim response
            continue;
        }
        let Some(mut flow) = c.pending.pop_front() else {
            c.server = Side {
                done: true,
                ..Side::default()
            };
            return;
        };
        let method = flow.request.as_ref().map(|r| r.method.clone());
        flow.response = Some(HttpResponse {
            status: *status,
            reason: reason.clone(),
            version: *version,
            headers: head.headers.clone(),
            body: None,
        });
        flow.timing.response_started = Some(ts.max(flow.timing.started));
        if *status == 101 {
            // Protocol switch (e.g. WebSocket): the rest is not HTTP/1.
            c.client = Side {
                done: true,
                ..Side::default()
            };
            c.server = Side {
                done: true,
                ..Side::default()
            };
        } else {
            after_head(&mut c.server, head.len, framing(&head, method.as_deref()));
        }
        out.push(Output::Flow(flow));
    }
}

#[cfg(test)]
mod tests;
