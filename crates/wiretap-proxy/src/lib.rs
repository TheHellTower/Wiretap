//! HTTP/1.1 proxy. Records every exchange (heads and bodies) and answers requests matching an
//! automatic-response rule instead of contacting the server.
//!
//! Clients reach it two ways: *explicitly* (configured as their HTTP proxy, using absolute URLs
//! and `CONNECT`), or *transparently* (the capture driver redirects their outbound connections
//! here; [`Hooks::redirected`] reports where each one was going). Plain HTTP is fully
//! inspected. With a [`Tls`] implementation HTTPS is decrypted too: the proxy terminates the
//! client's TLS with a certificate for the requested host and opens its own verified TLS
//! connection to the server. Clients that refuse the Wiretap certificate (and apps known to pin
//! their certificates) are relayed untouched, like anything that is not HTTP or TLS; relayed
//! connections are still recorded with their cleartext TLS handshake, byte counts and the
//! reason. WebSocket messages are decoded on the side while they are relayed.
//!
//! The proxy speaks strict HTTP/1.1 (heads parsed by `wiretap-protocol`), handles one
//! exchange per connection, and bounds everything: heads (64 KiB), request bodies, stored
//! bodies, ClientHellos, remembered hosts, concurrent connections and idle time.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use wiretap_autoreply::{Decision, Request, RuleSet, split_url};
use wiretap_core::{
    CaptureSource, Direction, Endpoint, EventId, EventMetadata, Flow, FlowId, FlowTiming,
    HttpHeader, HttpRequest, HttpResponse, HttpVersion, Inspection, NetworkEvent, ProcessInfo,
    Protocol, SessionId, Timestamp,
};
use wiretap_protocol::http2::PREFACE;
use wiretap_protocol::websocket::{Decoder, Extensions, Message, Sender};
use wiretap_protocol::{
    Chunked, Framing, Head, Parse, Progress, StartLine, framing, parse_client_hello,
    parse_server_flight, read_head,
};
use wiretap_protocol::{grpc, sse};

/// Largest request body accepted (it is buffered for rule matching).
pub const MAX_REQUEST_BODY: usize = 8 << 20;
/// Bytes of each body kept for recording (bodies are relayed in full regardless).
pub const STORE_LIMIT: usize = 4 << 20;
/// Concurrent client connections.
pub const MAX_CONNECTIONS: usize = 512;
/// Largest response Wiretap reads whole (a redirected HTTP/2 request's answer).
const MAX_FETCH: usize = 64 << 20;
/// Largest ClientHello buffered while looking for the server name.
const MAX_HELLO: usize = 64 * 1024;
/// Remembered `(application, host)` pairs that refused the Wiretap certificate.
const MAX_PASSTHROUGH: usize = 4096;
/// Apps that pin their certificates: they never accept the Wiretap certificate, so they are
/// relayed untouched from their first connection on instead of failing once. Microsoft
/// Defender's components accept only Microsoft's own certificate chains.
const PINNED_APPS: [&str; 8] = [
    "MsMpEng.exe",
    "MpDefenderCoreService.exe",
    "NisSrv.exe",
    "MpCmdRun.exe",
    "MsSense.exe",
    "SenseCncProxy.exe",
    "SenseIR.exe",
    "SenseNdr.exe",
];

const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection may stay silent before it is relayed without inspection (protocols
/// where the server speaks first).
const HELLO_TIMEOUT: Duration = Duration::from_secs(2);
/// A client closing this soon after the handshake, without a request, refused the certificate.
const REFUSAL_WINDOW: Duration = Duration::from_secs(1);
/// Polling interval of relayed (tunnelled or upgraded) connections.
const RELAY_TICK: Duration = Duration::from_millis(15);
/// How often a quiet server is polled while the client waits (long polls, event streams):
/// between polls Wiretap checks the client is still there.
const WAIT_TICK: Duration = Duration::from_millis(250);
/// Client bytes kept while it waits for a response (its next request).
const MAX_AHEAD: usize = 64 * 1024;
/// How long a kept-alive client connection may wait for its next request (Firefox keeps idle
/// connections 115 s; clients retry a request that meets a connection closed meanwhile).
const KEEP_ALIVE_IDLE: Duration = Duration::from_secs(120);
/// TCP keepalive of server connections: a probe after this much silence, then every
/// [`KEEPALIVE_INTERVAL`], so servers that vanished are noticed without any idle limit.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// Request headers not forwarded: hop-by-hop, proxy-only, or re-framed by the proxy.
const DROP_REQUEST: [&str; 10] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "expect",
    "content-length",
];
/// Response headers not relayed (the proxy closes the connection itself).
const DROP_RESPONSE: [&str; 3] = ["connection", "proxy-connection", "keep-alive"];

/// A plaintext byte stream: a socket, or one side of a decrypted TLS connection.
pub trait Stream: Read + Write + Send {
    /// The socket this stream reads from and writes to. Timeouts must be set here: on
    /// Windows a `try_clone` is another descriptor with its own timeouts.
    fn socket(&self) -> &TcpStream;
    /// The protocol negotiated with ALPN (decrypted TLS streams), e.g. `h2`.
    fn alpn(&self) -> Option<&str> {
        None
    }
}

impl Stream for TcpStream {
    fn socket(&self) -> &TcpStream {
        self
    }
}

/// HTTPS interception, supplied by the host application (Wiretap uses SChannel).
pub trait Tls: Send + Sync {
    /// Completes the handshake with an intercepted client as `host`, accepting the first of
    /// the `alpn` protocols it offers (none: no ALPN). `hello` holds the bytes already received
    /// (the ClientHello).
    ///
    /// # Errors
    /// The client refused the handshake (for example, it does not trust the Wiretap root).
    fn accept(
        &self,
        client: TcpStream,
        host: &str,
        hello: Vec<u8>,
        alpn: &[&str],
    ) -> io::Result<Box<dyn Stream>>;
    /// Opens TLS to the real server `host` over `server`, offering the `alpn` protocols, and
    /// verifies its certificate.
    ///
    /// # Errors
    /// Handshake failure or an untrusted certificate.
    fn connect(&self, server: TcpStream, host: &str, alpn: &[&str]) -> io::Result<Box<dyn Stream>>;
}

/// Where a transparently redirected connection was going.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redirected {
    /// The original destination.
    pub addr: SocketAddr,
    /// The process that opened the connection, if known.
    pub process: Option<ProcessInfo>,
}

/// What the proxy observed for one exchange. Bodies are decoded (no chunking) and truncated
/// to [`STORE_LIMIT`]; the flow's `body` references are left empty for storage to fill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// Flow heads, endpoints, process, timing and tags.
    pub flow: Flow,
    /// Stored request body prefix.
    pub request_body: Vec<u8>,
    /// Full request body length.
    pub request_size: u64,
    /// Stored response body prefix.
    pub response_body: Vec<u8>,
    /// Full response body length.
    pub response_size: u64,
}

/// Integration points supplied by the host application.
pub trait Hooks: Send + Sync {
    /// Current automatic-response rules.
    fn rules(&self) -> Arc<RuleSet>;
    /// Process behind the explicit client connection `client` -> `proxy`, if known.
    fn process(&self, client: SocketAddr, proxy: SocketAddr) -> Option<ProcessInfo>;
    /// Called once per completed exchange, and also when an upgraded connection (WebSocket)
    /// starts, so it shows while open; both calls carry the same flow ID.
    fn record(&self, exchange: Exchange);
    /// Called for each decoded WebSocket message (and decoding error) of a recorded flow.
    /// `payload` is its stored prefix (at most [`STORE_LIMIT`]) and `size` its full size; the
    /// event's `payload` reference is left empty for storage to fill.
    fn event(&self, _event: NetworkEvent, _payload: Vec<u8>, _size: u64) {}
    /// HTTPS interception, when enabled.
    fn tls(&self) -> Option<Arc<dyn Tls>> {
        None
    }
    /// The original destination of `client` if the capture driver redirected it here.
    fn redirected(&self, _client: &TcpStream) -> Option<Redirected> {
        None
    }
    /// Whether process `pid` runs outside the user's Windows session (a service in session 0,
    /// or another user's app). The Wiretap root is trusted for the user's account only, so the
    /// HTTPS of such processes is relayed untouched instead of failing.
    fn foreign(&self, _pid: u32) -> bool {
        false
    }
}

/// A running proxy; dropping the handle does not stop it, call [`Handle::stop`].
pub struct Handle {
    addr: SocketAddr,
    addr_v6: Option<SocketAddr>,
    stop: Arc<AtomicBool>,
    shared: Arc<Shared>,
}

/// Loopback listeners for the connections a capture driver redirects (see
/// [`Handle::transparent`]). [`Closing`](Self::close) or dropping them retires the capture: no
/// new connection is accepted, while those already open go on until their endpoints close them
/// (WebSockets and event streams are never cut); HTTP/2 connections are asked to move (a
/// graceful GOAWAY), so the app's next requests go to their servers directly.
pub struct Transparent {
    addrs: Vec<SocketAddr>,
    retired: Arc<AtomicBool>,
}

impl Transparent {
    /// Port on `127.0.0.1`.
    #[must_use]
    pub fn port_v4(&self) -> u16 {
        self.addrs.first().map_or(0, SocketAddr::port)
    }

    /// Port on `[::1]`, or 0 when IPv6 loopback is unavailable.
    #[must_use]
    pub fn port_v6(&self) -> u16 {
        self.addrs.get(1).map_or(0, SocketAddr::port)
    }

    /// Stops accepting; open connections go on (see [`Transparent`]).
    pub fn close(&self) {
        if self.retired.swap(true, Ordering::SeqCst) {
            return;
        }
        for addr in &self.addrs {
            // Wakes the accept loop, which then closes this connection first: its TIME_WAIT
            // stays on the listener's side. On this side it would look like a redirected
            // connection still pending, and keep the driver loaded (see wiretap-driver-client).
            if let Ok(mut wake) = TcpStream::connect_timeout(addr, Duration::from_secs(1)) {
                let _ = wake.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = wake.read(&mut [0u8]);
            }
        }
    }
}

impl Drop for Transparent {
    fn drop(&mut self) {
        self.close();
    }
}

impl Handle {
    /// Listening address (IPv4 loopback).
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The IPv6 loopback listener on the same port, if it could be bound.
    #[must_use]
    pub const fn addr_v6(&self) -> Option<SocketAddr> {
        self.addr_v6
    }

    /// Opens loopback listeners (IPv4 and, when available, IPv6, on ephemeral ports) for the
    /// connections a capture driver redirects here. Keep the result for the capture's lifetime
    /// and drop it when the capture stops.
    ///
    /// # Errors
    /// The IPv4 listener cannot be bound.
    pub fn transparent(&self) -> io::Result<Transparent> {
        let v4 = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).ok();
        let addrs = std::iter::once(&v4)
            .chain(v6.as_ref())
            .map(TcpListener::local_addr)
            .collect::<io::Result<Vec<_>>>()?;
        let retired = Arc::new(AtomicBool::new(false));
        for listener in std::iter::once(v4).chain(v6) {
            let (shared, retired) = (Arc::clone(&self.shared), Arc::clone(&retired));
            thread::spawn(move || accept_loop(&listener, &shared, Some(retired)));
        }
        Ok(Transparent { addrs, retired })
    }

    /// Stops accepting connections (in-flight exchanges finish on their own).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        for addr in std::iter::once(self.addr).chain(self.addr_v6) {
            let _ = TcpStream::connect_timeout(&addr, Duration::from_secs(1));
        }
    }
}

/// State shared by all connections of one proxy.
struct Shared {
    session: SessionId,
    hooks: Arc<dyn Hooks>,
    addrs: Vec<SocketAddr>,
    active: AtomicUsize,
    stop: Arc<AtomicBool>,
    /// What clients showed about the Wiretap certificate, per `application|host`.
    trust: Mutex<Trust>,
}

/// Evidence about clients and the Wiretap certificate, per `application|host`. A TLS alert
/// during the handshake is a refusal (RFC 8446 6.2: a client rejecting a certificate sends
/// one). Hanging up right after a completed handshake is weak evidence: apps that check
/// certificates themselves do it, but so do cancelled preconnects. It counts only twice in a
/// row and never for a pair that already sent a request through the certificate. A client that
/// disappears during the handshake (closed tab, exiting app) refused nothing.
#[derive(Default)]
struct Trust {
    /// Relayed without decryption from now on.
    refused: HashSet<String>,
    /// Sent a request through the Wiretap certificate.
    accepted: HashSet<String>,
    /// Hang-ups right after the handshake, since the last request.
    strikes: HashMap<String, u8>,
}

impl Trust {
    fn bounded(set: &mut HashSet<String>, key: &str) {
        if set.len() >= MAX_PASSTHROUGH {
            set.clear();
        }
        set.insert(key.to_owned());
    }

    fn accept(&mut self, key: &str) {
        self.strikes.remove(key);
        Self::bounded(&mut self.accepted, key);
    }

    /// Records a hang-up right after the handshake; true when it now counts as a refusal.
    fn strike(&mut self, key: &str) -> bool {
        if self.accepted.contains(key) {
            return false;
        }
        if self.strikes.len() >= MAX_PASSTHROUGH {
            self.strikes.clear();
        }
        let strikes = self.strikes.entry(key.to_owned()).or_default();
        *strikes += 1;
        *strikes >= 2
    }
}

/// The client went away (the connection ended), as opposed to a TLS-level failure.
fn gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
    )
}

/// Starts the proxy on `addr` (use a loopback address) for `session`, plus `[::1]` on the
/// same port when `addr` is `127.0.0.1` (for redirected IPv6 connections).
///
/// # Errors
/// The address cannot be bound.
pub fn start(addr: SocketAddr, session: SessionId, hooks: Arc<dyn Hooks>) -> io::Result<Handle> {
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    let v6 = addr
        .ip()
        .is_loopback()
        .then(|| TcpListener::bind((Ipv6Addr::LOCALHOST, addr.port())).ok())
        .flatten();
    let addr_v6 = v6.as_ref().and_then(|l| l.local_addr().ok());
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Shared {
        session,
        hooks,
        addrs: std::iter::once(addr).chain(addr_v6).collect(),
        active: AtomicUsize::new(0),
        stop: Arc::clone(&stop),
        trust: Mutex::default(),
    });
    for listener in std::iter::once(listener).chain(v6) {
        let shared = Arc::clone(&shared);
        thread::spawn(move || accept_loop(&listener, &shared, None));
    }
    Ok(Handle {
        addr,
        addr_v6,
        stop,
        shared,
    })
}

/// Accepts and serves connections; with `retired`, they are redirected ones of a capture (see
/// [`Transparent`]).
fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>, retired: Option<Arc<AtomicBool>>) {
    for stream in listener.incoming() {
        if shared.stop.load(Ordering::SeqCst)
            || retired.as_ref().is_some_and(|r| r.load(Ordering::SeqCst))
        {
            break;
        }
        let Ok(stream) = stream else { continue };
        if shared.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            shared.active.fetch_sub(1, Ordering::SeqCst);
            let _ = (&stream).write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            continue;
        }
        let (shared, retired) = (Arc::clone(shared), retired.clone());
        thread::spawn(move || {
            let proxy = Proxy {
                shared: &shared,
                retired: retired.as_deref(),
            };
            let _ = proxy.serve(stream);
            shared.active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

struct Proxy<'a> {
    shared: &'a Shared,
    /// Set when the capture that redirected this connection stopped.
    retired: Option<&'a AtomicBool>,
}

/// Where to connect upstream: a name to resolve, or a known address (redirected connections).
enum Target {
    Name(String, u16),
    Addr(SocketAddr),
}

/// Opens the upstream connection for an exchange.
type Open<'a> = dyn Fn(&str, u16) -> Result<Box<dyn Stream>, String> + 'a;

fn has(list: &[&str], name: &str) -> bool {
    list.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// `flow` without bodies, to record it while its connection is still open.
fn snapshot(flow: &Flow) -> Exchange {
    Exchange {
        flow: flow.clone(),
        request_body: Vec::new(),
        request_size: 0,
        response_body: Vec::new(),
        response_size: 0,
    }
}

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint {
        ip: addr.ip(),
        port: Some(addr.port()),
    }
}

/// A minimal response generated by the proxy itself.
fn plain(status: u16, reason: &str, message: &str) -> (HttpResponse, Vec<u8>) {
    let headers = vec![
        HttpHeader {
            name: "Content-Type".into(),
            value: "text/plain; charset=utf-8".into(),
        },
        HttpHeader {
            name: "Content-Length".into(),
            value: message.len().to_string(),
        },
    ];
    (
        HttpResponse {
            status,
            reason: reason.into(),
            version: HttpVersion::Http11,
            headers,
            body: None,
        },
        message.as_bytes().to_vec(),
    )
}

fn write_response(out: &mut dyn Write, response: &HttpResponse, body: &[u8]) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, response.reason);
    for h in response
        .headers
        .iter()
        .filter(|h| !has(&DROP_RESPONSE, &h.name))
    {
        head.push_str(&format!("{}: {}\r\n", h.name, h.value));
    }
    head.push_str("Connection: close\r\n\r\n");
    out.write_all(head.as_bytes())?;
    out.write_all(body)
}

/// Records a proxy-generated error response (and sends it when `out` is given).
fn fail(
    out: Option<&mut dyn Write>,
    flow: &mut Flow,
    exchange: &mut Exchange,
    tag: &str,
    message: &str,
) {
    let (response, body) = plain(502, "Bad Gateway", &format!("Wiretap proxy: {message}"));
    if let Some(out) = out {
        let _ = write_response(out, &response, &body);
    }
    flow.response = Some(response);
    flow.tags.push(tag.into());
    exchange.response_size = body.len() as u64;
    exchange.response_body = body;
}

/// `host:port` of a CONNECT request (IPv6 hosts in brackets).
fn connect_target(target: &str) -> Result<(String, u16), String> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or("CONNECT target must be host:port")?;
    let port = port.parse().map_err(|_| "invalid CONNECT port")?;
    Ok((
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        port,
    ))
}

/// `host[:port]` for URLs, omitting the scheme's default port.
fn authority(host: &str, port: u16, default: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == default {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn looks_like_http(buf: &[u8]) -> bool {
    let token = buf.iter().take_while(|b| b.is_ascii_uppercase()).count();
    (1..=16).contains(&token) && buf.get(token) == Some(&b' ')
}

fn timed_out(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// What a relay's observer may send to `a` (the client) after a chunk or on an idle tick.
type Inject = Option<Vec<u8>>;

/// Relays both directions until either side closes or the connection fails: however long it
/// stays quiet, Wiretap never ends it (WebSockets, event streams and idle keep-alive connections
/// live as long as their endpoints keep them; TCP keepalive notices servers that vanished). One
/// thread polls both streams, so decrypted TLS streams need no splitting. `observe` sees each
/// relayed chunk after it was forwarded (`true`: from `a` to `b`), and an empty chunk when
/// nothing moved; bytes it returns are sent to `a`.
fn pump(a: &mut dyn Stream, b: &mut dyn Stream, observe: &mut dyn FnMut(bool, &[u8]) -> Inject) {
    for s in [a.socket(), b.socket()] {
        let _ = s.set_read_timeout(Some(RELAY_TICK));
        let _ = s.set_write_timeout(Some(UPSTREAM_TIMEOUT));
    }
    let mut buf = vec![0u8; 16 * 1024];
    'relay: loop {
        let mut moved = false;
        for forward in [true, false] {
            let (from, to): (&mut dyn Stream, &mut dyn Stream) = if forward {
                (&mut *a, &mut *b)
            } else {
                (&mut *b, &mut *a)
            };
            match from.read(&mut buf) {
                Ok(0) => break 'relay,
                Ok(n) => {
                    let chunk = buf.get(..n).unwrap_or_default();
                    if to.write_all(chunk).and_then(|()| to.flush()).is_err() {
                        break 'relay;
                    }
                    if let Some(extra) = observe(forward, chunk)
                        && a.write_all(&extra).and_then(|()| a.flush()).is_err()
                    {
                        break 'relay;
                    }
                    moved = true;
                }
                Err(e) if timed_out(&e) => {}
                Err(_) => break 'relay,
            }
        }
        if !moved
            && let Some(extra) = observe(false, &[])
            && a.write_all(&extra).and_then(|()| a.flush()).is_err()
        {
            break;
        }
    }
    let _ = a.socket().shutdown(Shutdown::Both);
    let _ = b.socket().shutdown(Shutdown::Both);
}

impl Proxy<'_> {
    fn hooks(&self) -> &dyn Hooks {
        &*self.shared.hooks
    }

    /// Describes a redirected connection for the connections list, as the driver does for the
    /// others (it skips the redirected ones, whose loopback leg would show instead): the app's
    /// endpoint and its real destination, then (TLS) its ClientHello. Not part of any flow.
    fn connection_event(&self, flow: &Flow, protocol: Protocol, attributes: Vec<(&str, String)>) {
        let mut event = meta_event(flow, protocol, attributes);
        event.metadata.flow_id = None;
        self.hooks().event(event, Vec::new(), 0);
    }

    /// Whether the capture that redirected this connection stopped (see [`Transparent`]).
    fn retired(&self) -> bool {
        self.retired.is_some_and(|r| r.load(Ordering::SeqCst))
    }

    fn new_flow(
        &self,
        peer: SocketAddr,
        process: Option<ProcessInfo>,
        source: CaptureSource,
        request: HttpRequest,
    ) -> (Flow, Exchange) {
        let flow = Flow {
            id: FlowId::generate(),
            session_id: self.shared.session,
            source,
            process,
            client: Some(endpoint(peer)),
            server: None,
            request: Some(request),
            response: None,
            timing: FlowTiming {
                started: Timestamp::now(),
                request_complete: None,
                response_started: None,
                response_complete: None,
            },
            tags: Vec::new(),
        };
        let exchange = snapshot(&flow);
        (flow, exchange)
    }

    fn finish(&self, client: &TcpStream, mut flow: Flow, mut exchange: Exchange) {
        // A kept-alive connection's exchanges are recorded as each ends (see `http1`).
        if flow.timing.response_complete.is_none() {
            flow.timing.response_complete = Some(Timestamp::now().max(flow.timing.started));
            exchange.flow = flow;
            self.hooks().record(exchange);
        }
        let _ = client.shutdown(Shutdown::Both);
    }

    fn serve(&self, mut client: TcpStream) -> io::Result<()> {
        client.set_read_timeout(Some(CLIENT_TIMEOUT))?;
        client.set_write_timeout(Some(CLIENT_TIMEOUT))?;
        let peer = client.peer_addr()?;
        if let Some(original) = self.hooks().redirected(&client) {
            return self.transparent(client, peer, original);
        }
        let (head, rest) = match read_head(&mut client) {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                let (r, b) = plain(400, "Bad Request", "Wiretap proxy: malformed request");
                return write_response(&mut client, &r, &b);
            }
            Err(e) => return Err(e),
        };
        let StartLine::Request {
            method,
            target,
            version,
        } = &head.start
        else {
            return Ok(());
        };
        let local = client.local_addr()?;
        let request = HttpRequest {
            method: method.clone(),
            url: if method == "CONNECT" {
                format!("https://{target}")
            } else {
                target.clone()
            },
            version: *version,
            headers: head.headers.clone(),
            body: None,
        };
        let process = self.hooks().process(peer, local);
        let (mut flow, mut exchange) =
            self.new_flow(peer, process, CaptureSource::ExplicitProxy, request);
        if method == "CONNECT" {
            let established = connect_target(target).and_then(|(host, port)| {
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .map_err(|e| e.to_string())?;
                flow.timing.response_started = Some(Timestamp::now().max(flow.timing.started));
                Ok((host, port))
            });
            match established {
                Ok((host, port)) => {
                    let target = Target::Name(host.clone(), port);
                    self.tunnel(
                        &mut client,
                        &host,
                        port,
                        &target,
                        rest,
                        &mut flow,
                        &mut exchange,
                    );
                }
                Err(message) => fail(
                    Some(&mut client),
                    &mut flow,
                    &mut exchange,
                    "proxy-error",
                    &message,
                ),
            }
        } else if !target
            .get(..7)
            .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
        {
            let message = "only absolute http:// URLs and CONNECT are supported";
            fail(
                Some(&mut client),
                &mut flow,
                &mut exchange,
                "proxy-error",
                message,
            );
        } else {
            let open = |host: &str, port: u16| {
                let tcp = self.dial(&Target::Name(host.to_owned(), port))?;
                Ok(Box::new(tcp) as Box<dyn Stream>)
            };
            // Further requests on the connection may go to other servers, as absolute URLs.
            let url_of = |h: &Head| match &h.start {
                StartLine::Request { method, target, .. }
                    if method != "CONNECT"
                        && target
                            .get(..7)
                            .is_some_and(|s| s.eq_ignore_ascii_case("http://")) =>
                {
                    Some(target.clone())
                }
                _ => None,
            };
            let head = head.clone();
            self.http1(
                &mut client,
                head,
                rest,
                &url_of,
                &mut flow,
                &mut exchange,
                &open,
            );
        }
        self.finish(&client, flow, exchange);
        Ok(())
    }

    /// A connection the driver redirected here: TLS is decrypted (when enabled), plain HTTP
    /// is forwarded, anything else is relayed to the original destination.
    fn transparent(
        &self,
        mut client: TcpStream,
        peer: SocketAddr,
        original: Redirected,
    ) -> io::Result<()> {
        let addr = original.addr;
        // Until a request is decoded the connection is a tunnel, as CONNECT is for explicit
        // clients (and a valid method keeps relayed connections storable).
        let request = HttpRequest {
            method: "CONNECT".into(),
            url: format!(
                "https://{}",
                authority(&addr.ip().to_string(), addr.port(), 443)
            ),
            version: HttpVersion::Http11,
            headers: Vec::new(),
            body: None,
        };
        let (mut flow, mut exchange) = self.new_flow(
            peer,
            original.process,
            CaptureSource::TransparentProxy,
            request,
        );
        flow.server = Some(endpoint(addr));
        self.connection_event(&flow, Protocol::Tcp, Vec::new());
        let _ = client.set_read_timeout(Some(HELLO_TIMEOUT));
        let mut first = vec![0u8; 16 * 1024];
        let n = match client.read(&mut first) {
            Ok(0) => return Ok(()), // closed without sending anything
            Ok(n) => n,
            Err(e) if timed_out(&e) => 0, // the server speaks first
            Err(e) => return Err(e),
        };
        first.truncate(n);
        let _ = client.set_read_timeout(Some(CLIENT_TIMEOUT));
        let target = Target::Addr(addr);
        if looks_like_http(&first) {
            let host = authority(&addr.ip().to_string(), addr.port(), 80);
            self.plain(&mut client, first, &host, &target, &mut flow, &mut exchange);
        } else {
            let ip = addr.ip().to_string();
            self.tunnel(
                &mut client,
                &ip,
                addr.port(),
                &target,
                first,
                &mut flow,
                &mut exchange,
            );
        }
        self.finish(&client, flow, exchange);
        Ok(())
    }

    /// TCP to the server, refusing connections back into the proxy itself.
    fn dial(&self, target: &Target) -> Result<TcpStream, String> {
        let addrs: Vec<SocketAddr> = match target {
            Target::Addr(addr) => vec![*addr],
            Target::Name(host, port) => (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(|e| format!("cannot resolve {host}: {e}"))?
                .collect(),
        };
        if addrs.iter().any(|a| {
            self.shared
                .addrs
                .iter()
                .any(|p| a == p || (a.port() == p.port() && a.ip().is_loopback()))
        }) {
            return Err("request loops back to the proxy".into());
        }
        let mut last = String::from("no address");
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(s) => {
                    #[cfg(windows)]
                    let _ = wiretap_platform::keepalive(&s, KEEPALIVE_IDLE, KEEPALIVE_INTERVAL);
                    s.set_read_timeout(Some(UPSTREAM_TIMEOUT))
                        .and_then(|()| s.set_write_timeout(Some(UPSTREAM_TIMEOUT)))
                        .map_err(|e| e.to_string())?;
                    return Ok(s);
                }
                Err(e) => last = format!("cannot connect to {addr}: {e}"),
            }
        }
        Err(last)
    }

    /// A tunnel (after `CONNECT`, or a redirected connection): decrypts TLS when interception
    /// is enabled and the client has not refused it before, otherwise relays the bytes.
    /// A plain HTTP request on a redirected connection or inside a CONNECT tunnel (`first`: the
    /// bytes read so far). `fallback_host` names the server when the request has no `Host`.
    fn plain(
        &self,
        client: &mut TcpStream,
        first: Vec<u8>,
        fallback_host: &str,
        target: &Target,
        flow: &mut Flow,
        exchange: &mut Exchange,
    ) {
        // HTTP/2 with prior knowledge (h2c): relayed and decoded like decrypted HTTP/2.
        let n = first.len().min(PREFACE.len());
        if first.get(..n) == PREFACE.get(..n) {
            let mut upstream = match self.dial(target) {
                Ok(s) => s,
                Err(message) => return fail(None, flow, exchange, "proxy-error", &message),
            };
            flow.server = upstream.peer_addr().ok().map(endpoint);
            if let Some(r) = flow.request.as_mut() {
                r.url = format!("http://{fallback_host}");
            }
            if self
                .hooks()
                .rules()
                .targets_host(split_url(&format!("http://{fallback_host}/")).0)
            {
                self.terminate_h2(client, &mut upstream, &first, flow, fallback_host, &|| {});
            } else {
                self.relay_h2(client, &mut upstream, &first, flow, fallback_host, &|| {});
            }
            return;
        }
        let mut reader = io::Cursor::new(first).chain(&mut *client);
        let Ok((head, rest)) = read_head(&mut reader) else {
            return fail(
                Some(client),
                flow,
                exchange,
                "proxy-error",
                "malformed request",
            );
        };
        let url_of = |h: &Head| {
            let StartLine::Request { target: path, .. } = &h.start else {
                return None;
            };
            let host = h
                .header("host")
                .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_graphic()))
                .unwrap_or(fallback_host);
            Some(if path.starts_with('/') {
                format!("http://{host}{path}")
            } else {
                path.clone()
            })
        };
        let open = |_: &str, _: u16| {
            let tcp = self.dial(target)?;
            Ok(Box::new(tcp) as Box<dyn Stream>)
        };
        self.http1(client, head, rest, &url_of, flow, exchange, &open);
    }
    /// `host`/`port` name the destination; `hello` holds bytes already received.
    #[allow(
        clippy::too_many_arguments,
        reason = "the exchange state lives in the caller"
    )]
    fn tunnel(
        &self,
        client: &mut TcpStream,
        host: &str,
        port: u16,
        target: &Target,
        mut hello: Vec<u8>,
        flow: &mut Flow,
        exchange: &mut Exchange,
    ) {
        // The first bytes decide: plain HTTP (e.g. ws:// through an explicit proxy) is decoded
        // like any HTTP request; anything else goes on below.
        if hello.is_empty() {
            let _ = client.set_read_timeout(Some(HELLO_TIMEOUT));
            let mut buf = [0u8; 16 * 1024];
            match client.read(&mut buf) {
                Ok(0) => return, // client gave up
                Ok(n) => hello.extend_from_slice(buf.get(..n).unwrap_or_default()),
                Err(_) => {} // the server speaks first
            }
            let _ = client.set_read_timeout(Some(CLIENT_TIMEOUT));
        }
        if looks_like_http(&hello) {
            return self.plain(
                client,
                hello,
                &authority(host, port, 80),
                target,
                flow,
                exchange,
            );
        }
        let tls = self.hooks().tls();
        let is_tls = hello.first() == Some(&22);
        // Read the ClientHello for the server name (shown even when nothing is decrypted),
        // unless the client stays silent (the server speaks first) or does not speak TLS.
        let (mut server_name, mut offered) = (None, Vec::new());
        if is_tls {
            let _ = client.set_read_timeout(Some(HELLO_TIMEOUT));
            server_name = loop {
                match parse_client_hello(&hello) {
                    Parse::Complete(h) => {
                        if flow.source == CaptureSource::TransparentProxy {
                            self.connection_event(flow, Protocol::Tls, h.attributes());
                        }
                        offered = h.alpn;
                        break h.server_name;
                    }
                    Parse::Partial
                        if hello.len() < MAX_HELLO && hello.first().is_none_or(|&b| b == 22) => {}
                    _ => break None,
                }
                let mut buf = [0u8; 16 * 1024];
                match client.read(&mut buf) {
                    Ok(0) => return, // client gave up
                    Ok(n) => hello.extend_from_slice(buf.get(..n).unwrap_or_default()),
                    Err(_) => break None,
                }
            };
            let _ = client.set_read_timeout(Some(CLIENT_TIMEOUT));
        }
        // Wiretap decodes HTTP/1.1 and HTTP/2: it offers the server those of the client's ALPN
        // protocols, and gives the client what the server chose. Clients offering neither (only
        // other protocols) are relayed untouched.
        let ours: Vec<&str> = offered
            .iter()
            .map(String::as_str)
            .filter(|p| matches!(*p, "h2" | "http/1.1"))
            .collect();
        let http1 = offered.is_empty() || ours.contains(&"http/1.1");
        let name = server_name.unwrap_or_else(|| host.to_owned());
        let app = flow
            .process
            .as_ref()
            .and_then(|p| p.name.clone())
            .unwrap_or_default();
        let key = format!("{app}|{}", name.to_ascii_lowercase());
        let trust = || {
            self.shared
                .trust
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        };
        let pinned = has(&PINNED_APPS, &app);
        let refused = trust().refused.contains(&key);
        if let Some(r) = flow.request.as_mut() {
            r.url = format!("https://{}", authority(&name, port, 443));
        }
        // Why the connection is not decrypted (see `relay`), if it is not.
        let why = if !is_tls {
            Some("opaque")
        } else if tls.is_none() {
            Some("off")
        } else if pinned {
            Some("pinned")
        } else if refused {
            Some("refused")
        } else if flow
            .process
            .as_ref()
            .is_some_and(|p| self.hooks().foreign(p.pid))
        {
            Some("service")
        } else if !offered.is_empty() && ours.is_empty() {
            Some("protocol")
        } else {
            None
        };
        let (Some(tls), None) = (tls, why) else {
            let why = why.unwrap_or_default();
            if matches!(why, "pinned" | "refused" | "service" | "protocol") {
                flow.tags.push("passthrough".into());
            }
            if matches!(why, "pinned" | "refused") {
                flow.tags.push(why.into());
            }
            if let Err(message) = self.relay(client, target, hello, flow, why, "") {
                fail(None, flow, exchange, "proxy-error", &message);
            }
            return;
        };
        // Reach and verify the real server first: if that fails, the client meets the server
        // exactly as it is (relayed untouched, it decides itself). On hosts a rule targets,
        // HTTP/2 is terminated so rules apply to each stream; without HTTP/2, or when the
        // server cannot be reached, HTTP/1.1 connects only for requests no rule answers, so
        // rules work even when the server is down and never touch it otherwise.
        let connect = |alpn: &[&str]| {
            let tcp = self.dial(target)?;
            tls.connect(tcp, &name, alpn)
                .map_err(|e| format!("TLS to {name} failed: {e}"))
        };
        let targeted = self.hooks().rules().targets_host(&name);
        let early = if targeted && !ours.contains(&"h2") {
            None
        } else {
            match connect(&ours) {
                Ok(stream) => Some(stream),
                Err(_) if targeted && http1 => None,
                Err(error) => {
                    flow.tags.push("passthrough".into());
                    if let Err(message) =
                        self.relay(client, target, hello, flow, "unverified", &error)
                    {
                        fail(None, flow, exchange, "proxy-error", &message);
                    }
                    return;
                }
            }
        };
        let h2 = early.as_ref().and_then(|s| s.alpn()) == Some("h2");
        if !h2 && !http1 {
            // The client speaks only HTTP/2, the server did not choose it: nothing to decode.
            drop(early);
            flow.tags.push("passthrough".into());
            if let Err(message) = self.relay(client, target, hello, flow, "protocol", "") {
                fail(None, flow, exchange, "proxy-error", &message);
            }
            return;
        }
        let client_alpn: &[&str] = match (offered.is_empty(), h2) {
            (true, _) => &[],
            (false, true) => &["h2"],
            (false, false) => &["http/1.1"],
        };
        let early = std::cell::RefCell::new(early);
        // The TLS stream reads through its own descriptor: give it the client timeouts.
        let Ok(tcp) = client.try_clone() else { return };
        if tcp
            .set_read_timeout(Some(CLIENT_TIMEOUT))
            .and_then(|()| tcp.set_write_timeout(Some(CLIENT_TIMEOUT)))
            .is_err()
        {
            return;
        }
        let refuse = |flow: &mut Flow, exchange: &mut Exchange, why: &str| {
            Trust::bounded(&mut trust().refused, &key);
            let message = format!(
                "{} refused the Wiretap certificate for {name}; its next connections there are relayed without decryption ({why})",
                if app.is_empty() { "the client" } else { &app }
            );
            fail(None, flow, exchange, "tls-error", &message);
        };
        let mut inner = match tls.accept(tcp, &name, hello, client_alpn) {
            Ok(s) => s,
            // Gone mid-handshake (closed tab, exiting app, cancelled preconnect): no refusal.
            Err(e) if gone(&e) => return flow.tags.push("client-closed".into()),
            Err(e) => return refuse(flow, exchange, &e.to_string()),
        };
        let accepted = Instant::now();
        if h2 {
            let Some(mut server) = early.borrow_mut().take() else {
                return;
            };
            let authority = authority(&name, port, 443);
            let accept = || trust().accept(&key);
            let requests = if targeted {
                self.terminate_h2(&mut *inner, &mut *server, &[], flow, &authority, &accept)
            } else {
                self.relay_h2(&mut *inner, &mut *server, &[], flow, &authority, &accept)
            };
            // As for HTTP/1.1: hanging up right after the handshake is weak evidence of a refusal.
            if requests == 0 && accepted.elapsed() < REFUSAL_WINDOW && trust().strike(&key) {
                refuse(flow, exchange, "closed twice right after the handshake");
            }
            return;
        }
        let (head, rest) = match read_head(&mut inner) {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                fail(
                    Some(&mut inner),
                    flow,
                    exchange,
                    "proxy-error",
                    "malformed request",
                );
                return;
            }
            // Clients that check certificates themselves finish the handshake, then hang up at
            // once (weak evidence, see `Trust`); idle preconnected sockets close much later.
            Err(e) if accepted.elapsed() < REFUSAL_WINDOW && gone(&e) => {
                if trust().strike(&key) {
                    return refuse(flow, exchange, "closed twice right after the handshake");
                }
                return flow.tags.push("client-closed".into());
            }
            Err(_) => {
                flow.tags.push("no-request".into()); // handshake done, then closed
                return;
            }
        };
        let origin = format!("https://{}", authority(&name, port, 443));
        let url_of = |h: &Head| match &h.start {
            StartLine::Request { target: path, .. } if path.starts_with('/') => {
                Some(format!("{origin}{path}"))
            }
            StartLine::Request { target, .. } => Some(target.clone()),
            StartLine::Response { .. } => None,
        };
        flow.response = None;
        flow.tags.push("decrypted".into());
        trust().accept(&key);
        // The connection opened above, or a new one for rule-targeted hosts.
        let open = |_: &str, _: u16| {
            early
                .borrow_mut()
                .take()
                .map_or_else(|| connect(&["http/1.1"]), Ok)
        };
        self.http1(&mut *inner, head, rest, &url_of, flow, exchange, &open);
    }

    /// Connects to `url`'s server (TLS for `https://`, verified like any upstream).
    fn open_url(&self, url: &str) -> Result<Box<dyn Stream>, String> {
        let (host, port, ..) = split_url(url);
        let tcp = self.dial(&Target::Name(host.to_owned(), port))?;
        if url
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        {
            let tls = self
                .hooks()
                .tls()
                .ok_or("redirecting to https:// needs HTTPS decryption turned on")?;
            tls.connect(tcp, host, &["http/1.1"])
                .map_err(|e| format!("TLS to {host} failed: {e}"))
        } else {
            Ok(Box::new(tcp))
        }
    }

    /// Sends a request to `url` over HTTP/1.1 (TLS for `https://`, verified) and reads the whole
    /// response, its body decoded from chunked framing and at most [`MAX_FETCH`] bytes: how
    /// redirected HTTP/2 requests are answered.
    pub(crate) fn fetch(
        &self,
        url: &str,
        method: &str,
        headers: &[HttpHeader],
        keep_host: bool,
        body: &[u8],
    ) -> Result<(HttpResponse, Vec<u8>), String> {
        let mut upstream = self.open_url(url)?;
        let head = http1_head(method, url, headers, keep_host, body.len(), None);
        upstream
            .write_all(head.as_bytes())
            .and_then(|()| upstream.write_all(body))
            .map_err(|e| e.to_string())?;
        let (mut response, mut pre) =
            read_head(&mut upstream).map_err(|e| format!("bad upstream response: {e}"))?;
        while let StartLine::Response {
            status: 100 | 102..=199,
            ..
        } = response.start
        {
            let mut reader = io::Cursor::new(std::mem::take(&mut pre)).chain(&mut upstream);
            (response, pre) =
                read_head(&mut reader).map_err(|e| format!("bad upstream response: {e}"))?;
        }
        let StartLine::Response {
            status,
            reason,
            version,
        } = &response.start
        else {
            return Err("upstream did not send a response".into());
        };
        let mut full = Vec::new();
        let framing = framing(&response, Some(method));
        let mut keep = |bytes: &[u8]| {
            let room = MAX_FETCH.saturating_sub(full.len()).min(bytes.len());
            full.extend_from_slice(bytes.get(..room).unwrap_or_default());
        };
        let (sink, waiting) = (&mut io::sink(), &mut |_: &mut io::Sink| false);
        let _ = relay_body(&mut upstream, sink, pre, framing, &mut keep, waiting);
        let model = HttpResponse {
            status: *status,
            reason: reason.clone(),
            version: *version,
            headers: response.headers.clone(),
            body: None,
        };
        Ok((model, full))
    }

    /// Relays bytes without decryption (the client already has its answer, if any). The flow is
    /// recorded when the relay starts, so it shows while open, and events describe it: the
    /// cleartext TLS handshake (both hellos and, before TLS 1.3, the server certificate) once
    /// the server sent it, and the bytes each way when it ends. Each carries `relay.reason`,
    /// `why`: `pinned` (a [`PINNED_APPS`] app), `refused` (the client refused the Wiretap
    /// certificate before), `service` (see [`Hooks::foreign`]), `protocol` (it offers only
    /// protocols Wiretap does not decrypt yet),
    /// `unverified` (Wiretap could not verify the server: `detail` says why), `off` (HTTPS
    /// decryption is off) or `opaque` (neither HTTP nor TLS).
    fn relay(
        &self,
        client: &mut TcpStream,
        target: &Target,
        first: Vec<u8>,
        flow: &mut Flow,
        why: &str,
        detail: &str,
    ) -> Result<(), String> {
        let mut upstream = self.dial(target)?;
        flow.server = upstream.peer_addr().ok().map(endpoint);
        flow.tags.push("tunnel".into());
        if flow.response.is_none() && flow.source == CaptureSource::ExplicitProxy {
            flow.response = Some(HttpResponse {
                status: 200,
                reason: "Connection Established".into(),
                version: HttpVersion::Http11,
                headers: Vec::new(),
                body: None,
            });
        }
        upstream.write_all(&first).map_err(|e| e.to_string())?;
        self.hooks().record(snapshot(flow));
        let protocol = if first.first() == Some(&22) {
            Protocol::Tls
        } else {
            Protocol::Tcp
        };
        let mut attributes = vec![("relay.reason", why.to_owned())];
        if !detail.is_empty() {
            attributes.push(("relay.detail", detail.to_owned()));
        }
        if let Parse::Complete(hello) = parse_client_hello(&first) {
            attributes.extend(hello.attributes());
        }
        // The server's bytes until its cleartext handshake is decoded (TLS only).
        let mut server = (protocol == Protocol::Tls).then(Vec::new);
        let (mut sent, mut received, mut replied) = (first.len() as u64, 0u64, None);
        let shown = &*flow;
        pump(client, &mut upstream, &mut |from_client, chunk| {
            if from_client {
                sent += chunk.len() as u64;
                return None;
            }
            if chunk.is_empty() {
                return None; // an idle tick
            }
            received += chunk.len() as u64;
            replied.get_or_insert_with(Timestamp::now);
            let buf = server.as_mut()?;
            buf.extend_from_slice(chunk);
            match parse_server_flight(buf) {
                Parse::Partial => return None,
                Parse::Complete(flight) => attributes.extend(flight.attributes()),
                Parse::Invalid => {}
            }
            server = None;
            let handshake = std::mem::take(&mut attributes);
            self.hooks()
                .event(meta_event(shown, protocol, handshake), Vec::new(), 0);
            None
        });
        if flow.timing.response_started.is_none() {
            flow.timing.response_started = replied.map(|t| t.max(flow.timing.started));
        }
        if attributes.is_empty() {
            attributes.push(("relay.reason", why.to_owned())); // the handshake event had it
        }
        attributes.extend([
            ("relay.sent", sent.to_string()),
            ("relay.received", received.to_string()),
        ]);
        self.hooks()
            .event(meta_event(flow, protocol, attributes), Vec::new(), 0);
        Ok(())
    }

    /// One request/response exchange; `client` is plaintext (a socket or decrypted TLS). `conn`
    /// carries the connection's state from one exchange to the next (keep-alive).
    #[allow(
        clippy::too_many_arguments,
        reason = "the exchange state lives in the caller"
    )]
    fn forward(
        &self,
        client: &mut &mut dyn Stream,
        head: &Head,
        url: &str,
        rest: Vec<u8>,
        flow: &mut Flow,
        exchange: &mut Exchange,
        open: &Open<'_>,
        conn: &mut KeepAlive,
    ) -> Result<(), String> {
        conn.reusable = false;
        let StartLine::Request {
            method, version, ..
        } = &head.start
        else {
            return Err("not a request".into());
        };
        let upgrade = head
            .header("upgrade")
            .filter(|_| has_token(&head.headers, "connection", "upgrade"));
        // After a body-less upgrade request, further bytes already belong to the new protocol
        // (hixie-76 key bytes, frames sent early): forward them, never drop them.
        let (body, early, next) = match (upgrade, framing(head, None)) {
            (Some(_), None | Some(Framing::Empty)) => (Vec::new(), rest, Vec::new()),
            (_, framing) => {
                let (body, next) = read_request_body(client, rest, framing)?;
                (body, Vec::new(), next)
            }
        };
        // The client may send another request on this connection after the response (HTTP/1.1
        // keep-alive), unless it asked to close or the capture that redirected it stopped.
        let keep = upgrade.is_none()
            && *version == HttpVersion::Http11
            && !has_token(&head.headers, "connection", "close")
            && !self.retired();
        flow.timing.request_complete = Some(Timestamp::now().max(flow.timing.started));
        exchange.request_size = body.len() as u64;
        exchange.request_body = body
            .get(..body.len().min(STORE_LIMIT))
            .unwrap_or_default()
            .to_vec();
        // gRPC-Web over HTTP/1.x: the request's messages (its whole body was read).
        let mut grpc = Grpc::of(&head.headers);
        if let Some(g) = &mut grpc {
            flow.tags.push("grpc".into());
            for (event, payload, size) in g.feed(flow, true, &body) {
                self.hooks().event(event, payload, size);
            }
        }

        let rules = self.hooks().rules();
        let view = Request {
            method,
            url,
            headers: &head.headers,
            body: &body,
            process: flow.process.as_ref().and_then(|p| p.name.as_deref()),
            client: flow.client.map(|c| c.ip),
            server: flow.server.map(|s| s.ip),
        };
        // One outcome per request: redirected, answered by Wiretap, or sent to its server.
        let mut destination = None;
        match rules.decide(view) {
            Some(Decision::Reply(reply)) => {
                thread::sleep(Duration::from_millis(u64::from(reply.delay_ms)));
                let head_only = method.eq_ignore_ascii_case("HEAD");
                client
                    .write_all(&reply.response.to_bytes(head_only, !keep))
                    .map_err(|e| e.to_string())?;
                (conn.reusable, conn.ahead) = (keep, next);
                flow.response = Some(reply.response.to_model());
                flow.tags
                    .extend(["auto-reply".to_owned(), format!("rule:{}", reply.rule.id)]);
                flow.timing.response_started = Some(Timestamp::now().max(flow.timing.started));
                exchange.response_size = reply.response.body.len() as u64;
                exchange.response_body =
                    reply.response.body.into_iter().take(STORE_LIMIT).collect();
                return Ok(());
            }
            Some(Decision::Redirect { rule, url: to }) => {
                let mut tag = format!("to:{to}");
                tag.truncate(tag.floor_char_boundary(240));
                flow.tags
                    .extend(["redirect".to_owned(), format!("rule:{}", rule.id), tag]);
                let keep_host = rule.redirect.as_ref().is_some_and(|r| r.keep_host);
                destination = Some((to, keep_host));
            }
            None => {}
        }
        drop(rules);

        // A redirected request never touches the original server. The connection of the
        // previous exchange is reused when it went to the same server.
        let (host, port, ..) = split_url(destination.as_ref().map_or(url, |(to, _)| to));
        let key = format!("{}|{host}:{port}", destination.is_some());
        let connect = || match &destination {
            Some((to, _)) => self.open_url(to),
            None => open(host, port),
        };
        let (target_url, keep_host) = destination
            .as_ref()
            .map_or((url, true), |(to, keep_host)| (to.as_str(), *keep_host));
        let out = http1_head(
            method,
            target_url,
            &head.headers,
            keep_host,
            body.len(),
            upgrade,
        );
        let mut pooled = conn.upstream.take().filter(|(k, _)| *k == key);
        let mut ahead = Vec::new();
        let (mut upstream, response, pre) = loop {
            let reused = pooled.is_some();
            let mut upstream = match pooled.take() {
                Some((_, s)) => s,
                None => connect()?,
            };
            let request = [out.as_bytes(), &body, &early];
            match response_head(&mut *upstream, &mut **client, &mut ahead, &request) {
                Ok((response, pre)) => break (upstream, response, pre),
                Err(e) if is_client_gone(&e) => {
                    flow.tags.push("client-gone".into()); // stopped waiting for the answer
                    return Ok(());
                }
                // The server closed the idle connection meanwhile: once more on a new one.
                Err(_) if reused => {}
                Err(e) => return Err(format!("bad upstream response: {e}")),
            }
        };
        flow.server = upstream
            .socket()
            .peer_addr()
            .ok()
            .map(endpoint)
            .or(flow.server);
        let StartLine::Response {
            status,
            reason,
            version,
        } = &response.start
        else {
            return Err("upstream did not send a response".into());
        };
        flow.response = Some(HttpResponse {
            status: *status,
            reason: reason.clone(),
            version: *version,
            headers: response.headers.clone(),
            body: None,
        });
        flow.timing.response_started = Some(Timestamp::now().max(flow.timing.started));
        let switching = *status == 101 && upgrade.is_some();
        let framing = framing(&response, Some(method));
        // Both connections stay open for the next request only when the body's end is framed.
        let delimited = matches!(
            framing,
            Some(Framing::Empty | Framing::Length(_) | Framing::Chunked)
        );
        let keep = keep && delimited;
        let server_keeps = delimited
            && *version == HttpVersion::Http11
            && !has_token(&response.headers, "connection", "close");
        let mut head_out = format!("HTTP/1.1 {status} {reason}\r\n");
        for h in response
            .headers
            .iter()
            .filter(|h| switching || !has(&DROP_RESPONSE, &h.name))
        {
            head_out.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
        head_out.push_str(if switching || keep {
            "\r\n"
        } else {
            "Connection: close\r\n\r\n"
        });
        // From here on the client has a response; relay errors only end the exchange.
        if client.write_all(head_out.as_bytes()).is_err() {
            return Ok(());
        }
        if switching {
            // WebSocket (or another upgrade): relay both ways until either side closes, decoding
            // WebSocket messages on the side. The flow is recorded now so it shows while open.
            let websocket = upgrade.is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
            if websocket {
                flow.tags.push("websocket".into());
            }
            self.hooks().record(Exchange {
                flow: flow.clone(),
                ..exchange.clone()
            });
            if !pre.is_empty() && client.write_all(&pre).is_err() {
                return Ok(());
            }
            if !websocket {
                pump(*client, &mut *upstream, &mut |_, _| None);
                return Ok(());
            }
            let extensions =
                Extensions::parse(&values(&response.headers, "sec-websocket-extensions"));
            let mut decoders = [Sender::Client, Sender::Server]
                .map(|sender| Decoder::new(sender, extensions, STORE_LIMIT));
            let [client_side, server_side] = &mut decoders;
            let mut observe = |from_client: bool, bytes: &[u8]| {
                let decoder = if from_client {
                    &mut *client_side
                } else {
                    &mut *server_side
                };
                for decoded in decoder.feed(bytes) {
                    let (event, payload, size) = websocket_event(flow, from_client, decoded);
                    self.hooks().event(event, payload, size);
                }
                None
            };
            observe(true, &early);
            observe(false, &pre);
            pump(*client, &mut *upstream, &mut observe);
            return Ok(());
        }
        // Server-Sent Events and gRPC-Web responses: recorded now (they may stream), each event
        // or message a message.
        let mut sse = is_event_stream(&response.headers).then(|| {
            flow.tags.push("sse".into());
            sse::Decoder::new(STORE_LIMIT)
        });
        if let Some(g) = &mut grpc {
            g.respond(&response.headers); // not gRPC (an error page): not decoded
        }
        if sse.is_some() || grpc.as_ref().is_some_and(|g| g.answered) {
            self.hooks().record(snapshot(flow));
        }
        let shown = &*flow;
        let mut on_body = |bytes: &[u8]| {
            for event in sse.as_mut().map(|d| d.feed(bytes)).unwrap_or_default() {
                let (event, payload, size) = sse_event(shown, event);
                self.hooks().event(event, payload, size);
            }
            for (event, payload, size) in grpc
                .as_mut()
                .map(|g| g.feed(shown, false, bytes))
                .unwrap_or_default()
            {
                self.hooks().event(event, payload, size);
            }
        };
        let (stored, size, complete) = relay_body(
            &mut upstream,
            &mut **client,
            pre,
            framing,
            &mut on_body,
            &mut |c| still_there(c, &mut ahead),
        );
        exchange.response_body = stored;
        exchange.response_size = size;
        conn.reusable = keep && complete;
        if server_keeps && complete {
            conn.upstream = Some((key, upstream));
        }
        conn.ahead = [next, ahead].concat(); // in the order the client sent them
        Ok(())
    }

    /// Serves the HTTP/1.x requests of one client connection, `head` first (keep-alive): each
    /// is its own flow, recorded as soon as its response ends; `url_of` gives a request's URL
    /// (`None`: not one this connection serves). The last flow is left in `flow` and `exchange`
    /// for the caller to finish.
    #[allow(
        clippy::too_many_arguments,
        reason = "the exchange state lives in the caller"
    )]
    fn http1(
        &self,
        client: &mut dyn Stream,
        mut head: Head,
        mut rest: Vec<u8>,
        url_of: &dyn Fn(&Head) -> Option<String>,
        flow: &mut Flow,
        exchange: &mut Exchange,
        open: &Open<'_>,
    ) {
        let template = flow.clone();
        let mut conn = KeepAlive::default();
        loop {
            let (
                Some(url),
                StartLine::Request {
                    method, version, ..
                },
            ) = (url_of(&head), &head.start)
            else {
                let message = "malformed or unsupported request";
                return fail(Some(client), flow, exchange, "proxy-error", message);
            };
            flow.request = Some(HttpRequest {
                method: method.clone(),
                url: url.clone(),
                version: *version,
                headers: head.headers.clone(),
                body: None,
            });
            let mut stream: &mut dyn Stream = &mut *client;
            let result = self.forward(
                &mut stream,
                &head,
                &url,
                rest,
                flow,
                exchange,
                open,
                &mut conn,
            );
            if let Err(message) = result {
                return fail(Some(stream), flow, exchange, "proxy-error", &message);
            }
            if !conn.reusable {
                return;
            }
            flow.timing.response_complete = Some(Timestamp::now().max(flow.timing.started));
            let done = std::mem::replace(exchange, snapshot(flow));
            self.hooks().record(Exchange {
                flow: flow.clone(),
                ..done
            });
            let Some(next) = self.next_request(client, &mut conn.ahead) else {
                return;
            };
            (head, rest) = next;
            *flow = Flow {
                id: FlowId::generate(),
                request: None,
                response: None,
                timing: FlowTiming {
                    started: Timestamp::now(),
                    request_complete: None,
                    response_started: None,
                    response_complete: None,
                },
                ..template.clone()
            };
            *exchange = snapshot(flow);
        }
    }

    /// The next request on a kept-alive client connection: waits while the client keeps the
    /// connection, up to [`KEEP_ALIVE_IDLE`] and only until the capture that redirected it stops.
    /// `None` when there is none (closed, idle, retired or malformed).
    fn next_request(
        &self,
        client: &mut dyn Stream,
        ahead: &mut Vec<u8>,
    ) -> Option<(Head, Vec<u8>)> {
        let idle = Instant::now();
        let _ = client.socket().set_read_timeout(Some(WAIT_TICK));
        let mut buf = [0u8; 4096];
        while ahead.is_empty() {
            if self.retired() || idle.elapsed() >= KEEP_ALIVE_IDLE {
                return None;
            }
            match client.read(&mut buf) {
                Ok(n) if n > 0 => ahead.extend_from_slice(buf.get(..n).unwrap_or_default()),
                Err(e) if timed_out(&e) => {}
                _ => return None,
            }
        }
        let _ = client.socket().set_read_timeout(Some(CLIENT_TIMEOUT));
        let mut early = io::Cursor::new(std::mem::take(ahead));
        let (head, mut rest) = read_head(&mut (&mut early).chain(&mut *client)).ok()?;
        // Bytes the head reader did not reach yet come before anything else from the client.
        let position = usize::try_from(early.position()).unwrap_or(usize::MAX);
        rest.extend_from_slice(early.get_ref().get(position..).unwrap_or_default());
        Some((head, rest))
    }
}

/// A client connection's state between its HTTP/1.1 exchanges (keep-alive).
#[derive(Default)]
struct KeepAlive {
    /// The last exchange left the connection usable for another request.
    reusable: bool,
    /// Client bytes already read past the last request: the next one, or its start.
    ahead: Vec<u8>,
    /// The server connection of the last exchange, still usable, with its server's key.
    upstream: Option<(String, Box<dyn Stream>)>,
}

/// Whether a header lists `token` (case-insensitive, comma-separated, e.g. `Connection: close`).
fn has_token(headers: &[HttpHeader], name: &str, token: &str) -> bool {
    values(headers, name)
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// Sends `request` to `upstream` and reads the response head, skipping interim responses
/// (e.g. 100 Continue; the request body was already sent). The server may take any time (long
/// polls, event streams): Wiretap waits as long as `client` does (see [`Patient`]).
fn response_head(
    upstream: &mut dyn Stream,
    client: &mut dyn Stream,
    ahead: &mut Vec<u8>,
    request: &[&[u8]],
) -> io::Result<(Head, Vec<u8>)> {
    for part in request {
        upstream.write_all(part)?;
    }
    upstream.flush()?;
    let _ = upstream.socket().set_read_timeout(Some(WAIT_TICK));
    let mut patient = Patient {
        upstream,
        client,
        ahead,
    };
    let mut head = read_head(&mut patient)?;
    while matches!(
        head.0.start,
        StartLine::Response {
            status: 100 | 102..=199,
            ..
        }
    ) {
        let mut reader = io::Cursor::new(std::mem::take(&mut head.1)).chain(&mut patient);
        head = read_head(&mut reader)?;
    }
    Ok(head)
}

/// All values of header `name`, comma-joined (repeated fields form one list, RFC 9110 5.3).
fn values(headers: &[HttpHeader], name: &str) -> String {
    let all: Vec<&str> = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
        .collect();
    all.join(", ")
}

/// An event of `flow` (its payload reference is left for storage to fill).
fn flow_event(
    flow: &Flow,
    protocol: Protocol,
    direction: Direction,
    inspection: Inspection,
    attributes: BTreeMap<String, String>,
) -> NetworkEvent {
    NetworkEvent {
        id: EventId::generate(),
        session_id: flow.session_id,
        timestamp: Timestamp::now(),
        source: flow.source,
        protocol,
        direction,
        process: flow.process.clone(),
        local_endpoint: flow.client,
        remote_endpoint: flow.server,
        payload: None,
        metadata: EventMetadata {
            inspection,
            flow_id: Some(flow.id),
            attributes,
        },
    }
}

/// Metadata about a relayed (not decrypted) connection of `flow`.
fn meta_event(flow: &Flow, protocol: Protocol, attributes: Vec<(&str, String)>) -> NetworkEvent {
    let attributes = attributes
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    flow_event(
        flow,
        protocol,
        Direction::Outbound,
        Inspection::Metadata,
        attributes,
    )
}

/// The HTTP/1.1 request head Wiretap sends upstream: `method` for `target` (an absolute URL),
/// `headers` without hop-by-hop fields, `Host` kept (`keep_host`) or set to the target's, the
/// body's length, then the upgrade or `Connection: close`.
fn http1_head(
    method: &str,
    target: &str,
    headers: &[HttpHeader],
    keep_host: bool,
    body_len: usize,
    upgrade: Option<&str>,
) -> String {
    let (host, _, path, query) = split_url(target);
    let origin = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut out = format!("{method} {origin} HTTP/1.1\r\n");
    let has_host = headers.iter().any(|h| h.name.eq_ignore_ascii_case("host"));
    if !has_host || !keep_host {
        let authority = target
            .split_once("://")
            .and_then(|(_, rest)| rest.split(['/', '?']).next())
            .unwrap_or(host);
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    for h in headers.iter().filter(|h| {
        !has(&DROP_REQUEST, &h.name) && (keep_host || !h.name.eq_ignore_ascii_case("host"))
    }) {
        out.push_str(&format!("{}: {}\r\n", h.name, h.value));
    }
    if body_len > 0 || matches!(method, "POST" | "PUT" | "PATCH") {
        out.push_str(&format!("Content-Length: {body_len}\r\n"));
    }
    match upgrade {
        Some(protocol) => out.push_str(&format!(
            "Upgrade: {protocol}\r\nConnection: Upgrade\r\n\r\n"
        )),
        None => out.push_str("\r\n"), // persistent: the connection may carry the next request
    }
    out
}

/// Whether a response is a Server-Sent Events stream Wiretap can read (`text/event-stream`, not
/// compressed).
fn is_event_stream(headers: &[HttpHeader]) -> bool {
    let kind = values(headers, "content-type");
    let coding = values(headers, "content-encoding");
    kind.split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))
        && (coding.is_empty() || coding.eq_ignore_ascii_case("identity"))
}

/// A Server-Sent Event as an event of `flow` (from the server), with its data and full size.
fn sse_event(flow: &Flow, event: sse::Event) -> (NetworkEvent, Vec<u8>, u64) {
    let attributes = event.attributes();
    let e = flow_event(
        flow,
        Protocol::Sse,
        Direction::Inbound,
        Inspection::Intercepted,
        attributes,
    );
    (e, event.data.into_bytes(), event.size)
}

/// The gRPC side of one call: how each direction frames its messages and which `grpc-encoding`
/// it uses (client, server), and whether messages are JSON.
pub(crate) struct Grpc {
    pub(crate) decoders: [grpc::Decoder; 2],
    pub(crate) encodings: [String; 2],
    pub(crate) json: bool,
    /// The response is gRPC too (an error page is not decoded).
    pub(crate) answered: bool,
}

impl Grpc {
    /// A call whose request has `headers`, when its content type is gRPC.
    pub(crate) fn of(headers: &[HttpHeader]) -> Option<Self> {
        let (framing, json) = grpc::Framing::of(&values(headers, "content-type"))?;
        Some(Self {
            decoders: [(); 2].map(|()| grpc::Decoder::new(framing, STORE_LIMIT)),
            encodings: [values(headers, "grpc-encoding"), String::new()],
            json,
            answered: false,
        })
    }

    /// The response's headers: its framing and encoding. Returns whether it is gRPC.
    pub(crate) fn respond(&mut self, headers: &[HttpHeader]) -> bool {
        if let Some((framing, _)) = grpc::Framing::of(&values(headers, "content-type")) {
            self.decoders[1] = grpc::Decoder::new(framing, STORE_LIMIT);
            self.answered = true;
        }
        self.encodings[1] = values(headers, "grpc-encoding");
        self.answered
    }

    /// Events for the next body bytes of one direction of `flow`: each message with its view and
    /// payload, the status of a gRPC-Web trailers frame, or the decoding error.
    pub(crate) fn feed(
        &mut self,
        flow: &Flow,
        from_client: bool,
        bytes: &[u8],
    ) -> Vec<(NetworkEvent, Vec<u8>, u64)> {
        let i = usize::from(!from_client);
        if !from_client && !self.answered {
            return Vec::new();
        }
        let (Some(decoder), Some(encoding)) = (self.decoders.get_mut(i), self.encodings.get(i))
        else {
            return Vec::new();
        };
        decoder
            .feed(bytes)
            .into_iter()
            .map(|decoded| {
                let (attributes, payload, size) = match decoded {
                    Ok(m) if m.trailers => {
                        let fields = grpc::trailer_fields(&m.data);
                        let named = fields.iter().map(|(n, v)| (n.as_str(), v.as_str()));
                        (status_or_error(grpc::status(named)), Vec::new(), 0)
                    }
                    Ok(m) => {
                        let (mut a, payload) = grpc::describe(&m, encoding, self.json, STORE_LIMIT);
                        a.insert("size".into(), m.size.to_string()); // on the wire
                        let size = payload.len() as u64; // the stored view is whole
                        (a, payload, size)
                    }
                    Err(e) => (BTreeMap::from([("error".into(), e.into())]), Vec::new(), 0),
                };
                (grpc_event(flow, from_client, attributes), payload, size)
            })
            .collect()
    }
}

/// The call's status event from HTTP trailers (or a Trailers-Only response) of `flow`.
pub(crate) fn grpc_status(flow: &Flow, fields: &[HttpHeader]) -> NetworkEvent {
    let named = fields.iter().map(|h| (h.name.as_str(), h.value.as_str()));
    grpc_event(flow, false, status_or_error(grpc::status(named)))
}

fn status_or_error(status: Option<BTreeMap<String, String>>) -> BTreeMap<String, String> {
    status.unwrap_or_else(|| {
        BTreeMap::from([("error".into(), "trailers without grpc-status".into())])
    })
}

fn grpc_event(
    flow: &Flow,
    from_client: bool,
    attributes: BTreeMap<String, String>,
) -> NetworkEvent {
    let direction = if from_client {
        Direction::Outbound
    } else {
        Direction::Inbound
    };
    flow_event(
        flow,
        Protocol::Grpc,
        direction,
        Inspection::Intercepted,
        attributes,
    )
}

/// A decoded WebSocket message (or the decoding error) as an event of `flow`, with its payload
/// and full size. Attributes come from [`Message::attributes`], or are `error` alone.
fn websocket_event(
    flow: &Flow,
    from_client: bool,
    decoded: Result<Message, &'static str>,
) -> (NetworkEvent, Vec<u8>, u64) {
    let (attributes, payload, size) = match decoded {
        Ok(m) => (m.attributes(), m.payload, m.size),
        Err(error) => (
            BTreeMap::from([("error".into(), error.into())]),
            Vec::new(),
            0,
        ),
    };
    let direction = if from_client {
        Direction::Outbound
    } else {
        Direction::Inbound
    };
    let event = flow_event(
        flow,
        Protocol::Websocket,
        direction,
        Inspection::Intercepted,
        attributes,
    );
    (event, payload, size)
}

/// Reads a request body that starts with `body` (bytes already read). Returns it and the bytes
/// past it (the start of the client's next request).
fn read_request_body(
    client: &mut impl Read,
    mut body: Vec<u8>,
    framing: Option<Framing>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    match framing {
        Some(Framing::Empty | Framing::UntilClose) => Ok((Vec::new(), body)),
        Some(Framing::Length(n)) => {
            let n = usize::try_from(n)
                .ok()
                .filter(|&n| n <= MAX_REQUEST_BODY)
                .ok_or("request body too large")?;
            while body.len() < n {
                let mut chunk = vec![0u8; (n - body.len()).min(64 * 1024)];
                let read = client.read(&mut chunk).map_err(|e| e.to_string())?;
                if read == 0 {
                    return Err("client closed before sending the whole body".into());
                }
                body.extend_from_slice(chunk.get(..read).unwrap_or_default());
            }
            let next = body.split_off(n);
            Ok((body, next))
        }
        Some(Framing::Chunked) => {
            let mut decoder = Chunked::default();
            let mut out = Vec::new();
            let mut input = body;
            let next = loop {
                match decoder
                    .feed(&input, &mut out, MAX_REQUEST_BODY + 1)
                    .map_err(|e| e.to_string())?
                {
                    Progress::Done { consumed } => {
                        break input.get(consumed..).unwrap_or_default().to_vec();
                    }
                    Progress::NeedMore => {}
                }
                if out.len() > MAX_REQUEST_BODY {
                    return Err("request body too large".into());
                }
                input = vec![0u8; 64 * 1024];
                let read = client.read(&mut input).map_err(|e| e.to_string())?;
                if read == 0 {
                    return Err("client closed inside a chunked body".into());
                }
                input.truncate(read);
            };
            if out.len() > MAX_REQUEST_BODY {
                Err("request body too large".into())
            } else {
                Ok((out, next))
            }
        }
        None => Err("conflicting or invalid request framing".into()),
    }
}

/// Relays a response body to the client as received, keeping a decoded prefix for storage and
/// showing all decoded bytes to `on_body` (event streams outlast the stored prefix). When the
/// server is quiet past its read timeout, `waiting` says whether to keep waiting (the client is
/// still there). Returns the stored prefix, the full decoded length, and whether the body ended
/// as framed with nothing after it (the server connection can carry another request).
fn relay_body<C: Write + ?Sized>(
    upstream: &mut impl Read,
    client: &mut C,
    first: Vec<u8>,
    framing: Option<Framing>,
    on_body: &mut dyn FnMut(&[u8]),
    waiting: &mut dyn FnMut(&mut C) -> bool,
) -> (Vec<u8>, u64, bool) {
    let mut stored = Vec::new();
    let mut chunked = matches!(framing, Some(Framing::Chunked)).then(Chunked::default);
    let mut remaining = match framing {
        Some(Framing::Empty) => Some(0u64),
        Some(Framing::Length(n)) => Some(n),
        _ => None,
    };
    let mut total = 0u64;
    let mut piece = first;
    let mut buf = vec![0u8; 64 * 1024];
    // Bytes past the body, or a framing error: the server connection cannot be reused.
    let mut clean = true;
    let complete = loop {
        if let Some(left) = remaining {
            let keep = usize::try_from(left).unwrap_or(usize::MAX).min(piece.len());
            clean &= keep == piece.len();
            piece.truncate(keep);
        }
        let mut done = remaining == Some(piece.len() as u64);
        let mut decoded = Vec::new();
        let body = match &mut chunked {
            Some(decoder) => {
                match decoder.feed(&piece, &mut decoded, usize::MAX) {
                    Ok(Progress::Done { consumed }) => {
                        clean &= consumed == piece.len();
                        piece.truncate(consumed);
                        done = true;
                    }
                    Ok(Progress::NeedMore) => {}
                    Err(_) => (done, clean) = (true, false),
                }
                &decoded
            }
            None => {
                total += piece.len() as u64;
                &piece
            }
        };
        let room = STORE_LIMIT.saturating_sub(stored.len()).min(body.len());
        stored.extend_from_slice(body.get(..room).unwrap_or_default());
        // The client first, then the observer (recording must not delay the stream).
        let sent = client
            .write_all(&piece)
            .and_then(|()| client.flush())
            .is_ok();
        if sent {
            on_body(if chunked.is_some() { &decoded } else { &piece });
        }
        if !sent || done {
            break sent && clean;
        }
        if let Some(left) = remaining.as_mut() {
            *left -= piece.len() as u64;
        }
        let n = loop {
            match upstream.read(&mut buf) {
                Err(e) if timed_out(&e) && waiting(client) => {}
                Ok(n) => break n,
                Err(_) => break 0,
            }
        };
        if n == 0 {
            break false;
        }
        piece = buf.get(..n).unwrap_or_default().to_vec();
    };
    (stored, chunked.map_or(total, |d| d.decoded()), complete)
}

/// Whether `client`, waiting for a response, is still connected (it hung up, or sent a TLS
/// close, when not). Bytes it sent meanwhile, its next request, are kept in `ahead`.
fn still_there(client: &mut dyn Stream, ahead: &mut Vec<u8>) -> bool {
    if ahead.len() >= MAX_AHEAD {
        return true; // nothing more is read until the response is over
    }
    let _ = client.socket().set_read_timeout(Some(RELAY_TICK));
    let mut buf = [0u8; 4096];
    let room = MAX_AHEAD.saturating_sub(ahead.len()).min(buf.len()); // at least 1
    let there = match client.read(buf.get_mut(..room).unwrap_or_default()) {
        Ok(0) => false,
        Ok(n) => {
            ahead.extend_from_slice(buf.get(..n).unwrap_or_default());
            true
        }
        Err(e) => timed_out(&e),
    };
    let _ = client.socket().set_read_timeout(Some(CLIENT_TIMEOUT));
    there
}

/// The client left while Wiretap waited for its response.
#[derive(Debug)]
struct ClientGone;

impl std::fmt::Display for ClientGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the client left")
    }
}

impl std::error::Error for ClientGone {}

fn is_client_gone(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<ClientGone>())
}

/// Reads a server that takes its time for as long as the client waits: each read timeout (the
/// socket's, [`WAIT_TICK`]) checks the client, and fails with [`ClientGone`] once it left.
struct Patient<'a> {
    upstream: &'a mut dyn Stream,
    client: &'a mut dyn Stream,
    ahead: &'a mut Vec<u8>,
}

impl Read for Patient<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.upstream.read(buf) {
                Err(e) if timed_out(&e) => {
                    if !still_there(self.client, self.ahead) {
                        return Err(io::Error::other(ClientGone));
                    }
                }
                result => return result,
            }
        }
    }
}

mod h2;
mod h2term;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wslab;
