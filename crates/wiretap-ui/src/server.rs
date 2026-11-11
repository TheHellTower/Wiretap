//! The UI server: loopback HTTP, token-protected, serving the embedded web app, a JSON API,
//! a server-sent-events live stream and the capture feed. Runs unelevated; captures run in a
//! separate elevated `wiretap --headless capture --feed` process that streams validated
//! messages back and stops (unloading the driver) as soon as this server goes away.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use wiretap_autoreply::{Request, Rule, RuleSet};
use wiretap_core::{
    FlowId, NetworkEvent, PayloadEncryption, ProcessInfo, Session, SessionId, Timestamp,
};
use wiretap_protocol::{Head, read_head};
use wiretap_proxy::{Exchange, Hooks, Redirected, Tls};
use wiretap_storage::{DEFAULT_QUOTA, MAX_PAGE, Store};

use crate::http::{self, Auth, COOKIE, Reject, Route};
use crate::message::Message;

const RULES_KEY: &str = "autoreply.rules";
const TLS_KEY: &str = "tls.enabled";
const DEV_KEY: &str = "ui.dev";
/// Preferred proxy port; an ephemeral port is used when it is taken.
pub const PROXY_PORT: u16 = 8899;
const MAX_CONNECTIONS: usize = 64;
const MAX_FEED_LINE: usize = 4 << 20;
/// Largest decoded body the viewer and HAR export produce.
pub(crate) const DECODE_LIMIT: usize = 64 << 20;
const SUBSCRIBER_QUEUE: usize = 8192;
const SECURITY_HEADERS: &str = "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; \
img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\n\
Cross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the UI server starts.
#[derive(Clone, Debug)]
pub struct Config {
    /// Database file shared with capture processes.
    pub db: PathBuf,
    /// `wiretap.exe`, relaunched elevated for captures.
    pub exe: PathBuf,
    /// Open the app window (otherwise print the URL and run until interrupted).
    pub open_window: bool,
}

enum Capture {
    Idle,
    Starting {
        key: String,
    },
    Running {
        session: Option<SessionId>,
        feed: TcpStream,
        /// The driver is loaded and redirecting (the capture's first statistics arrived).
        ready: bool,
    },
}

/// Shared server state.
pub(crate) struct App {
    pub(crate) host: String,
    pub(crate) token: String,
    config: Config,
    store: Mutex<Store>,
    rules: RwLock<Arc<RuleSet>>,
    subscribers: Mutex<Vec<SyncSender<Arc<str>>>>,
    capture: Mutex<Capture>,
    /// The always-on proxy.
    proxy: Mutex<Option<wiretap_proxy::Handle>>,
    /// Listeners for the running capture's redirected connections; dropped when it stops.
    transparent: Mutex<Option<wiretap_proxy::Transparent>>,
    /// This run's session: proxy exchanges and captures are recorded into it. Stored on first
    /// use, so idle runs leave no empty sessions.
    session: Session,
    session_stored: AtomicBool,
    /// HTTPS decryption, when enabled, and the root certificate for export.
    tls: RwLock<Option<Arc<dyn Tls>>>,
    root: Mutex<Option<Vec<u8>>>,
    /// Developer mode: the UI also shows diagnostics (refused certificates, tunnels, internals).
    dev: AtomicBool,
    error: Mutex<Option<String>>,
    connections: AtomicUsize,
    #[cfg(windows)]
    child: Mutex<Option<Arc<crate::launch::Child>>>,
}

/// A started server.
pub struct Running {
    app: Arc<App>,
    addr: SocketAddr,
}

fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    #[cfg(windows)]
    wiretap_platform::random(&mut buf)?;
    #[cfg(not(windows))]
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Binds the server on an ephemeral loopback port and starts accepting connections.
///
/// # Errors
/// Socket, RNG or database failures.
pub fn start(config: Config) -> io::Result<Running> {
    let store = Store::open(&config.db, DEFAULT_QUOTA).map_err(io::Error::other)?;
    let dev = store.setting(DEV_KEY).map_err(io::Error::other)?.as_deref() == Some("on");
    let (rules, error) = match store.setting(RULES_KEY).map_err(io::Error::other)? {
        None => (RuleSet::default(), None),
        Some(json) => match RuleSet::from_json(json.as_bytes()) {
            Ok(rules) => (rules, None),
            Err(e) => (
                RuleSet::default(),
                Some(format!("stored auto-reply rules ignored: {e}")),
            ),
        },
    };
    // Windows stopping during the last capture is reported first.
    #[cfg(windows)]
    let error = wiretap_driver_client::crash_report(&config.db.with_file_name("")).or(error);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let app = Arc::new(App {
        host: addr.to_string(),
        token: random_hex(32)?,
        config,
        store: Mutex::new(store),
        rules: RwLock::new(Arc::new(rules)),
        subscribers: Mutex::new(Vec::new()),
        capture: Mutex::new(Capture::Idle),
        proxy: Mutex::new(None),
        transparent: Mutex::new(None),
        session: Session::new(format!("Wiretap {}", Timestamp::now().utc())),
        session_stored: AtomicBool::new(false),
        tls: RwLock::new(None),
        root: Mutex::new(None),
        dev: AtomicBool::new(dev),
        error: Mutex::new(error),
        connections: AtomicUsize::new(0),
        #[cfg(windows)]
        child: Mutex::new(None),
    });
    app.restore_tls();
    app.start_proxy()?;
    let server = Arc::clone(&app);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            if server.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                server.connections.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let app = Arc::clone(&server);
            thread::spawn(move || {
                let _ = handle(&app, stream);
                app.connections.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(Running { app, addr })
}

impl Running {
    /// One-time login URL (contains the session token).
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/?t={}", self.addr, self.app.token)
    }

    /// Stops the proxy and any capture (the capture process unloads the driver itself).
    pub fn shutdown(&self) {
        self.app.stop_capture();
        if let Some(proxy) = lock(&self.app.proxy).take() {
            proxy.stop();
        }
        #[cfg(windows)]
        if let Some(child) = lock(&self.app.child).take() {
            let waiter = thread::spawn(move || child.wait());
            let deadline = Instant::now() + Duration::from_secs(15);
            while !waiter.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn app(&self) -> &Arc<App> {
        &self.app
    }
}

/// Runs the app: Wiretap's window until the user closes it, or (without a window) the server
/// until the process is stopped.
///
/// # Errors
/// Startup failures.
pub fn run(config: Config) -> io::Result<()> {
    let open = config.open_window;
    let dir = config.db.with_file_name("");
    // Earlier versions kept Edge profiles here; Wiretap no longer uses any.
    for old in ["ui-profile", "browser-profile"] {
        let _ = std::fs::remove_dir_all(dir.join(old));
    }
    let running = start(config)?;
    let url = running.url();
    #[cfg(windows)]
    if open {
        let webview = dir.join("webview");
        let _ = std::fs::remove_dir_all(&webview);
        let shown = crate::window::run(&url, &webview);
        running.shutdown();
        for path in [webview, dir.join("browser")] {
            wipe(&path);
        }
        return shown;
    }
    let _ = open;
    writeln!(io::stdout(), "Wiretap UI: {url}")?;
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

/// Deletes a throwaway browser folder once its processes have let go of it.
fn wipe(path: &std::path::Path) {
    for _ in 0..50 {
        if std::fs::remove_dir_all(path).is_ok() || !path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}
// ----------------------------------------------------------------------------------------------
// HTTP plumbing

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    media: &str,
    body: &[u8],
    extra: &str,
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {media}\r\nContent-Length: {}\r\n{SECURITY_HEADERS}{extra}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)
}

/// A stored body, decoded when `coding` names its content codings. A decoding failure is
/// reported in `X-Wiretap-Decode-Error` with what decoded (`X-Wiretap-Decoded: partial`) or,
/// when nothing did, the stored bytes.
fn payload_response(stream: &mut TcpStream, bytes: &[u8], coding: Option<&str>) -> io::Result<()> {
    const BINARY: &str = "application/octet-stream";
    let Some(coding) = coding else {
        return respond(stream, 200, "OK", BINARY, bytes, "");
    };
    let decoded = wiretap_codec::decode(coding, bytes, DECODE_LIMIT);
    match decoded.error {
        None => respond(
            stream,
            200,
            "OK",
            BINARY,
            &decoded.bytes,
            "X-Wiretap-Decoded: full\r\n",
        ),
        Some(e) if decoded.bytes.is_empty() || e == wiretap_codec::Error::Unsupported => respond(
            stream,
            200,
            "OK",
            BINARY,
            bytes,
            &format!("X-Wiretap-Decode-Error: {e}\r\n"),
        ),
        Some(e) => respond(
            stream,
            200,
            "OK",
            BINARY,
            &decoded.bytes,
            &format!("X-Wiretap-Decoded: partial\r\nX-Wiretap-Decode-Error: {e}\r\n"),
        ),
    }
}

fn json(stream: &mut TcpStream, value: &impl Serialize) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    respond(stream, 200, "OK", "application/json", &body, "")
}

fn fail(stream: &mut TcpStream, status: u16, message: &str) -> io::Result<()> {
    #[derive(Serialize)]
    struct Error<'a> {
        error: &'a str,
    }
    let body = serde_json::to_vec(&Error { error: message }).map_err(io::Error::other)?;
    let reason = match status {
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    };
    respond(stream, status, reason, "application/json", &body, "")
}

fn read_body(
    stream: &mut TcpStream,
    head: &Head,
    mut body: Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, (u16, &'static str)> {
    let length = match wiretap_protocol::framing(head, None) {
        Some(wiretap_protocol::Framing::Empty) => 0,
        Some(wiretap_protocol::Framing::Length(n)) => usize::try_from(n).unwrap_or(usize::MAX),
        _ => return Err((400, "request bodies need Content-Length")),
    };
    if length > limit {
        return Err((413, "request body too large"));
    }
    while body.len() < length {
        let mut chunk = vec![0u8; (length - body.len()).min(64 * 1024)];
        let n = stream
            .read(&mut chunk)
            .map_err(|_| (400, "incomplete body"))?;
        if n == 0 {
            return Err((400, "incomplete body"));
        }
        body.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    body.truncate(length);
    Ok(body)
}

fn handle(app: &Arc<App>, mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (head, rest) = read_head(&mut stream)?;
    let key = match &*lock(&app.capture) {
        Capture::Starting { key } => Some(key.clone()),
        _ => None,
    };
    let auth = Auth {
        host: &app.host,
        token: &app.token,
        feed_key: key.as_deref(),
    };
    let route = match http::route(&head, &auth) {
        Ok(r) => r,
        Err(reject) => {
            let (status, reason) = reject.status();
            let page = if reject == Reject::Forbidden {
                "Open Wiretap from wiretap.exe."
            } else {
                reason
            };
            return respond(
                &mut stream,
                status,
                reason,
                "text/plain; charset=utf-8",
                page.as_bytes(),
                "",
            );
        }
    };
    if route == Route::Feed {
        return feed(app, stream, rest);
    }
    let body = match read_body(&mut stream, &head, rest, http::body_limit(&route)) {
        Ok(b) => b,
        Err((status, message)) => return fail(&mut stream, status, message),
    };
    match route {
        Route::Login => {
            let cookie = format!(
                "Set-Cookie: {COOKIE}={}; HttpOnly; SameSite=Strict; Path=/\r\nLocation: /\r\n",
                app.token
            );
            respond(&mut stream, 303, "See Other", "text/plain", b"", &cookie)
        }
        Route::Asset(asset) => {
            let (content, media) = asset.content();
            respond(&mut stream, 200, "OK", media, content, "")
        }
        Route::State => json(&mut stream, &app.state()),
        Route::Sessions => match lock(&app.store).sessions() {
            Ok(mut sessions) => {
                sessions.reverse();
                json(&mut stream, &sessions)
            }
            Err(e) => fail(&mut stream, 500, &e.to_string()),
        },
        Route::DeleteSession(id) => match lock(&app.store).delete_session(id) {
            Ok(_) => json(&mut stream, &true),
            Err(e) => fail(&mut stream, 500, &e.to_string()),
        },
        Route::Flows(id, after) => page(
            &mut stream,
            lock(&app.store).flows(id, after.map(|(t, u)| (t, FlowId(u))), MAX_PAGE),
            |f| (f.timing.started, f.id.0),
        ),
        Route::Events(id, after) => page(
            &mut stream,
            lock(&app.store).events(
                id,
                after.map(|(t, u)| (t, wiretap_core::EventId(u))),
                MAX_PAGE,
            ),
            |e| (e.timestamp, e.id.0),
        ),
        Route::Flow(id) => match lock(&app.store).flow(id) {
            Ok(Some(flow)) => json(&mut stream, &flow),
            Ok(None) => fail(&mut stream, 404, "no such flow"),
            Err(e) => fail(&mut stream, 500, &e.to_string()),
        },
        Route::Payload(id, coding) => {
            let payload = lock(&app.store).payload(id); // decode after releasing the store
            match payload {
                Ok(Some(bytes)) => payload_response(&mut stream, &bytes, coding.as_deref()),
                Ok(None) => fail(&mut stream, 404, "no such payload"),
                Err(e) => fail(&mut stream, 500, &e.to_string()),
            }
        }
        Route::Live => live(app, stream),
        Route::CaptureStart => match app.start_capture() {
            Ok(()) => json(&mut stream, &app.state()),
            Err(e) => fail(&mut stream, 409, &e),
        },
        Route::CaptureStop => {
            app.stop_capture();
            json(&mut stream, &app.state())
        }
        // Both block until the user answers Windows' certificate confirmation.
        Route::TlsEnable => match app.enable_tls() {
            Ok(()) => json(&mut stream, &app.state()),
            Err(e) => fail(&mut stream, 409, &e),
        },
        Route::TlsDisable => match app.disable_tls() {
            Ok(()) => json(&mut stream, &app.state()),
            Err(e) => fail(&mut stream, 409, &e),
        },
        Route::TlsRoot => match lock(&app.root).clone() {
            Some(der) => respond(
                &mut stream,
                200,
                "OK",
                "application/pkix-cert",
                &der,
                "Content-Disposition: attachment; filename=\"wiretap-root.cer\"\r\n",
            ),
            None => fail(&mut stream, 404, "HTTPS decryption is off"),
        },
        Route::Browser => match app.open_browser() {
            Ok(()) => json(&mut stream, &true),
            Err(e) => fail(&mut stream, 409, &e),
        },
        Route::Prefs => match app.set_prefs(&body) {
            Ok(()) => json(&mut stream, &app.state()),
            Err(e) => fail(&mut stream, 400, &e),
        },
        Route::HarExport(id) => {
            let store = lock(&app.store);
            match store.session(id) {
                Ok(Some(session)) => match crate::har::export(&store, &session) {
                    Ok(har) => {
                        drop(store);
                        let file: String = session
                            .name
                            .chars()
                            .map(|c| {
                                if c.is_ascii_alphanumeric() || c == '-' {
                                    c
                                } else {
                                    '_'
                                }
                            })
                            .collect();
                        let disposition =
                            format!("Content-Disposition: attachment; filename=\"{file}.har\"\r\n");
                        respond(
                            &mut stream,
                            200,
                            "OK",
                            "application/json",
                            &har,
                            &disposition,
                        )
                    }
                    Err(e) => fail(&mut stream, 500, &e),
                },
                Ok(None) => fail(&mut stream, 404, "no such session"),
                Err(e) => fail(&mut stream, 500, &e.to_string()),
            }
        }
        Route::HarImport => {
            let name = format!("Imported HAR {}", Timestamp::now().utc());
            let imported = crate::har::import(&mut lock(&app.store), &name, &body);
            match imported {
                Ok((session, imported, skipped)) => {
                    app.broadcast(&Message::Session(session.clone()));
                    json(
                        &mut stream,
                        &serde_json::json!({ "session": session, "imported": imported, "skipped": skipped }),
                    )
                }
                Err(e) => fail(&mut stream, 400, &e),
            }
        }
        Route::Rules => json(
            &mut stream,
            &app.rules
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .rules(),
        ),
        Route::SaveRules => match app.save_rules(&body) {
            Ok(()) => json(&mut stream, &true),
            Err(e) => fail(&mut stream, 400, &e),
        },
        Route::RuleFromFlow => match app.rule_from_flow(&body) {
            Ok(rule) => json(&mut stream, &rule),
            Err(e) => fail(&mut stream, 400, &e),
        },
        Route::TestRule => match app.test_rule(&body) {
            Ok(matches) => json(&mut stream, &matches),
            Err(e) => fail(&mut stream, 400, &e),
        },
        Route::Feed => Ok(()),
    }
}

#[derive(Serialize)]
struct Page<T> {
    items: Vec<T>,
    next: Option<String>,
}

fn page<T: Serialize>(
    stream: &mut TcpStream,
    result: Result<Vec<T>, wiretap_storage::StoreError>,
    key: fn(&T) -> (Timestamp, wiretap_core::Uuid),
) -> io::Result<()> {
    match result {
        Ok(items) => {
            let next = (items.len() == MAX_PAGE)
                .then(|| items.last().map(key))
                .flatten()
                .map(|(t, u)| format!("{}_{u}", t.0));
            json(stream, &Page { items, next })
        }
        Err(e) => fail(stream, 500, &e.to_string()),
    }
}

/// Server-sent events: live messages and state changes until the browser disconnects. A browser
/// too slow to keep up is disconnected (see [`App::send`]): it reconnects within a second and
/// reloads what it missed.
fn live(app: &Arc<App>, mut stream: TcpStream) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{SECURITY_HEADERS}Connection: keep-alive\r\n\r\nretry: 1000\n\n"
    );
    stream.write_all(head.as_bytes())?;
    let (tx, rx): (SyncSender<Arc<str>>, Receiver<Arc<str>>) = sync_channel(SUBSCRIBER_QUEUE);
    lock(&app.subscribers).push(tx);
    let mut result = write_event(&mut stream, &app.state_frame());
    while result.is_ok() {
        result = match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(message) => write_event(&mut stream, &message),
            Err(RecvTimeoutError::Timeout) => stream.write_all(b": keep-alive\n\n"),
            Err(RecvTimeoutError::Disconnected) => break,
        };
    }
    Ok(())
}

fn write_event(stream: &mut TcpStream, data: &str) -> io::Result<()> {
    stream.write_all(format!("data: {data}\n\n").as_bytes())
}

/// The elevated capture process streams JSON lines; each is validated before it is relayed.
fn feed(app: &Arc<App>, mut stream: TcpStream, rest: Vec<u8>) -> io::Result<()> {
    {
        let mut capture = lock(&app.capture);
        if !matches!(*capture, Capture::Starting { .. }) {
            return fail(&mut stream, 409, "no capture is starting");
        }
        *capture = Capture::Running {
            session: Some(app.session.id),
            feed: stream.try_clone()?,
            ready: false,
        };
    }
    // The capture process records into this run's session, next to the proxy's exchanges, and
    // redirects outbound HTTP(S) to this process's proxy (which it never redirects itself).
    app.ensure_session(&mut lock(&app.store));
    // Redirected connections get their own listeners, so the capture can tell when they are all
    // closed before it unloads the driver; the explicit proxy ports follow for its filters.
    let proxy = lock(&app.proxy).as_ref().map_or_else(String::new, |p| {
        let explicit = (p.addr().port(), p.addr_v6().map_or(0, |a| a.port()));
        let redirect = match p.transparent() {
            Ok(t) => {
                let ports = (t.port_v4(), t.port_v6());
                *lock(&app.transparent) = Some(t);
                ports
            }
            Err(_) => explicit,
        };
        format!(
            "{}: {} {} {} {} {}\r\n",
            http::PROXY_HEADER,
            std::process::id(),
            redirect.0,
            redirect.1,
            explicit.0,
            explicit.1
        )
    });
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n{}: {}\r\n{proxy}\r\n",
        http::SESSION_HEADER,
        app.session.id
    )?;
    app.broadcast_state();
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(io::Cursor::new(rest).chain(stream.try_clone()?));
    let mut line = Vec::new();
    loop {
        line.clear();
        // A reset connection (capture process killed) ends the feed like a clean close.
        let n = (&mut reader)
            .take(MAX_FEED_LINE as u64 + 1)
            .read_until(b'\n', &mut line)
            .unwrap_or(0);
        if n == 0 || n > MAX_FEED_LINE {
            break;
        }
        let Ok(message) = serde_json::from_slice::<Message>(&line) else {
            continue;
        };
        if message.validate().is_err() {
            continue;
        }
        // The capture's first statistics mean the driver is loaded and redirecting: only then is
        // it shown as running. (State is broadcast after the lock is released.)
        let became_ready = match &mut *lock(&app.capture) {
            Capture::Running { session, ready, .. } => match &message {
                Message::Session(s) => {
                    *session = Some(s.id);
                    false
                }
                Message::Stats(_) => !std::mem::replace(ready, true),
                _ => false,
            },
            _ => false,
        };
        if became_ready {
            app.broadcast_state();
        }
        app.broadcast(&message);
    }
    let _ = stream.shutdown(Shutdown::Both);
    lock(&app.transparent).take(); // retires the listeners: open connections finish first
    let mut capture = lock(&app.capture);
    if matches!(*capture, Capture::Running { .. }) {
        *capture = Capture::Idle;
    }
    drop(capture);
    app.broadcast_state();
    Ok(())
}

// ----------------------------------------------------------------------------------------------
// Application actions

#[derive(Serialize)]
struct ProxyView {
    port: u16,
}

#[derive(Serialize)]
struct State {
    /// This run's session: the proxy and captures record into it.
    session: SessionId,
    capture: &'static str,
    proxy: Option<ProxyView>,
    /// HTTPS decryption is on (the Wiretap root is trusted).
    https: bool,
    /// Developer mode.
    dev: bool,
    error: Option<String>,
    rules: usize,
    platform: Platform,
    db: String,
    version: &'static str,
}

#[derive(Serialize, Default)]
struct Platform {
    windows: String,
    support: String,
    elevated: bool,
    test_signing: bool,
    memory_integrity: bool,
    secure_boot: Option<bool>,
    driver: String,
}

#[derive(Serialize)]
struct StateFrame {
    state: State,
}

fn platform() -> Platform {
    #[cfg(windows)]
    {
        let os = wiretap_platform::detect().ok();
        let p = wiretap_platform::posture();
        Platform {
            windows: os.map_or_else(
                || "unknown".into(),
                |o| format!("{}.{} build {}", o.major, o.minor, o.build),
            ),
            support: os.map_or_else(
                || "unknown".into(),
                |o| format!("{:?}", wiretap_platform::classify(&o)),
            ),
            elevated: p.elevated,
            test_signing: p.test_signing,
            memory_integrity: p.memory_integrity,
            secure_boot: p.secure_boot,
            driver: wiretap_driver_client::driver_state()
                .map_or_else(|e| e.to_string(), |s| format!("{s:?}")),
        }
    }
    #[cfg(not(windows))]
    Platform::default()
}

impl App {
    fn state(&self) -> State {
        let capture = match &*lock(&self.capture) {
            Capture::Idle => "idle",
            Capture::Starting { .. } | Capture::Running { ready: false, .. } => "starting",
            Capture::Running { .. } => "running",
        };
        State {
            session: self.session.id,
            capture,
            proxy: lock(&self.proxy).as_ref().map(|p| ProxyView {
                port: p.addr().port(),
            }),
            https: self
                .tls
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some(),
            dev: self.dev.load(Ordering::SeqCst),
            error: lock(&self.error).clone(),
            rules: self
                .rules
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .rules()
                .len(),
            platform: platform(),
            db: self.config.db.display().to_string(),
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn state_frame(&self) -> String {
        serde_json::to_string(&StateFrame {
            state: self.state(),
        })
        .unwrap_or_default()
    }

    fn send(&self, data: &str) {
        let data: Arc<str> = Arc::from(data);
        lock(&self.subscribers).retain(|tx| match tx.try_send(Arc::clone(&data)) {
            Ok(()) => true,
            // A browser that cannot keep up is dropped; it reconnects and reloads.
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        });
    }

    pub(crate) fn broadcast(&self, message: &Message) {
        if let Ok(data) = serde_json::to_string(message) {
            self.send(&data);
        }
    }

    fn broadcast_state(&self) {
        self.send(&self.state_frame());
    }

    fn set_error(&self, error: Option<String>) {
        *lock(&self.error) = error;
        self.broadcast_state();
    }

    #[cfg(windows)]
    fn start_capture(self: &Arc<Self>) -> Result<(), String> {
        let key = random_hex(32).map_err(|e| e.to_string())?;
        {
            let mut capture = lock(&self.capture);
            if !matches!(*capture, Capture::Idle) {
                return Err("a capture is already running".into());
            }
            *capture = Capture::Starting { key: key.clone() };
        }
        let args = format!(
            "--headless capture --quiet --db \"{}\" --feed {}/{key}",
            self.config.db.display(),
            self.host
        );
        let child = match crate::launch::spawn_elevated(&self.config.exe, &args) {
            Ok(child) => Arc::new(child),
            Err(e) => {
                *lock(&self.capture) = Capture::Idle;
                return Err(if e.raw_os_error() == Some(1223) {
                    "administrator approval was declined".into()
                } else {
                    format!("cannot start the capture process: {e}")
                });
            }
        };
        *lock(&self.child) = Some(Arc::clone(&child));
        self.set_error(None);
        let app = Arc::clone(self);
        thread::spawn(move || {
            let code = child.wait();
            let mut capture = lock(&app.capture);
            let was_starting = matches!(*capture, Capture::Starting { .. });
            if let Capture::Running { feed, .. } = &*capture {
                let _ = feed.shutdown(Shutdown::Both);
            }
            *capture = Capture::Idle;
            drop(capture);
            lock(&app.child).take();
            let failed = code.is_some_and(|c| c != 0);
            app.set_error((was_starting || failed).then(|| {
                format!(
                    "capture process exited ({}); run `wiretap --headless check` for details",
                    code.unwrap_or(u32::MAX)
                )
            }));
        });
        Ok(())
    }

    #[cfg(not(windows))]
    fn start_capture(self: &Arc<Self>) -> Result<(), String> {
        Err("capture requires Windows".into())
    }

    pub(crate) fn stop_capture(&self) {
        let mut capture = lock(&self.capture);
        match &*capture {
            // Closing the feed makes the capture process stop; retiring the listeners sends new
            // connections straight to their servers while open ones finish.
            Capture::Running { feed, .. } => {
                let _ = feed.shutdown(Shutdown::Both);
                lock(&self.transparent).take();
            }
            Capture::Starting { .. } => *capture = Capture::Idle,
            Capture::Idle => {}
        }
    }

    /// Starts the always-on proxy on [`PROXY_PORT`], or an ephemeral port when it is taken.
    fn start_proxy(self: &Arc<Self>) -> io::Result<()> {
        let start = |port: u16| {
            let hooks: Arc<dyn Hooks> = Arc::new(ProxyHooks(Arc::clone(self)));
            wiretap_proxy::start(
                SocketAddr::from(([127, 0, 0, 1], port)),
                self.session.id,
                hooks,
            )
        };
        let handle = start(PROXY_PORT).or_else(|_| start(0))?;
        *lock(&self.proxy) = Some(handle);
        Ok(())
    }

    /// Stores this run's session the first time something is recorded into it.
    fn ensure_session(&self, store: &mut Store) {
        if !self.session_stored.load(Ordering::SeqCst)
            && store.insert_session(&self.session).is_ok()
        {
            self.session_stored.store(true, Ordering::SeqCst);
            self.broadcast(&Message::Session(self.session.clone()));
        }
    }

    #[cfg(windows)]
    fn set_tls(&self, interceptor: Option<crate::tls::Interceptor>) {
        *lock(&self.root) = interceptor.as_ref().map(|i| i.root().to_vec());
        *self.tls.write().unwrap_or_else(PoisonError::into_inner) =
            interceptor.map(|i| Arc::new(i) as Arc<dyn Tls>);
    }

    /// Re-enables HTTPS decryption at startup if it was on and the root is still trusted.
    #[cfg(windows)]
    fn restore_tls(&self) {
        if lock(&self.store).setting(TLS_KEY).ok().flatten().as_deref() == Some("on") {
            match crate::tls::Interceptor::open(false) {
                Ok(interceptor) => self.set_tls(Some(interceptor)),
                Err(e) => *lock(&self.error) = Some(format!("HTTPS decryption is off: {e}")),
            }
        }
    }

    #[cfg(windows)]
    fn enable_tls(&self) -> Result<(), String> {
        let interceptor = crate::tls::Interceptor::open(true)?;
        lock(&self.store)
            .set_setting(TLS_KEY, "on")
            .map_err(|e| e.to_string())?;
        self.set_tls(Some(interceptor));
        self.set_error(None);
        Ok(())
    }

    #[cfg(windows)]
    fn disable_tls(&self) -> Result<(), String> {
        self.set_tls(None);
        lock(&self.store)
            .set_setting(TLS_KEY, "off")
            .map_err(|e| e.to_string())?;
        let removed = crate::tls::Interceptor::remove();
        self.broadcast_state();
        removed
    }

    #[cfg(not(windows))]
    fn restore_tls(&self) {}

    #[cfg(not(windows))]
    fn enable_tls(&self) -> Result<(), String> {
        Err("HTTPS decryption requires Windows".into())
    }

    #[cfg(not(windows))]
    fn disable_tls(&self) -> Result<(), String> {
        Ok(())
    }

    /// `{"dev": bool}`: developer mode on or off (saved).
    fn set_prefs(&self, body: &[u8]) -> Result<(), String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Prefs {
            dev: bool,
        }
        let prefs: Prefs = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        lock(&self.store)
            .set_setting(DEV_KEY, if prefs.dev { "on" } else { "off" })
            .map_err(|e| e.to_string())?;
        self.dev.store(prefs.dev, Ordering::SeqCst);
        self.broadcast_state();
        Ok(())
    }

    /// Opens a browser window (its own profile) that sends everything through the proxy.
    fn open_browser(&self) -> Result<(), String> {
        let port = lock(&self.proxy)
            .as_ref()
            .map(|p| p.addr().port())
            .ok_or("the proxy is not running")?;
        #[cfg(windows)]
        return crate::launch::open_browser(
            port,
            &self.config.db.with_file_name("browser-profile"),
        )
        .map_err(|e| format!("cannot open the browser: {e}"));
        #[cfg(not(windows))]
        Err(format!("set your browser's proxy to 127.0.0.1:{port}"))
    }

    fn save_rules(&self, body: &[u8]) -> Result<(), String> {
        let rules = RuleSet::from_json(body).map_err(|e| e.to_string())?;
        let json = serde_json::to_string(rules.rules()).map_err(|e| e.to_string())?;
        lock(&self.store)
            .set_setting(RULES_KEY, &json)
            .map_err(|e| e.to_string())?;
        *self.rules.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(rules);
        self.broadcast_state();
        Ok(())
    }

    fn rule_from_flow(&self, body: &[u8]) -> Result<Rule, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FromFlow {
            flow: FlowId,
        }
        let request: FromFlow = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        let store = lock(&self.store);
        let flow = store
            .flow(request.flow)
            .map_err(|e| e.to_string())?
            .ok_or("no such flow")?;
        let body = match flow.response.as_ref().and_then(|r| r.body) {
            Some(reference) => store.payload(reference.id).map_err(|e| e.to_string())?,
            None => None,
        };
        Rule::from_flow(&flow, body.as_deref()).ok_or_else(|| "the flow has no request".into())
    }

    fn test_rule(&self, body: &[u8]) -> Result<Vec<FlowId>, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Test {
            rule: Rule,
            session: SessionId,
        }
        let test: Test = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        let set = RuleSet::new(vec![test.rule]).map_err(|e| e.to_string())?;
        let store = lock(&self.store);
        let mut matches = Vec::new();
        let mut cursor = None;
        loop {
            let flows = store
                .flows(test.session, cursor, MAX_PAGE)
                .map_err(|e| e.to_string())?;
            let Some(last) = flows.last() else { break };
            cursor = Some((last.timing.started, last.id));
            for flow in &flows {
                let Some(request) = &flow.request else {
                    continue;
                };
                let request_body = match request.body {
                    Some(r) => store.payload(r.id).ok().flatten().unwrap_or_default(),
                    None => Vec::new(),
                };
                let view = Request {
                    method: &request.method,
                    url: &request.url,
                    headers: &request.headers,
                    body: &request_body,
                    process: flow.process.as_ref().and_then(|p| p.name.as_deref()),
                    client: flow.client.map(|c| c.ip),
                    server: flow.server.map(|s| s.ip),
                };
                if !set.matching(view).is_empty() {
                    matches.push(flow.id);
                }
            }
        }
        Ok(matches)
    }

    /// Stores a proxy exchange (bodies as payloads) and relays it live.
    pub(crate) fn record(&self, exchange: Exchange) {
        let Exchange {
            mut flow,
            request_body,
            request_size,
            response_body,
            response_size,
        } = exchange;
        let mut store = lock(&self.store);
        self.ensure_session(&mut store);
        let put = |bytes: &[u8], size: u64| {
            (size > 0)
                .then(|| {
                    store
                        .insert_payload(flow.session_id, bytes, size, PayloadEncryption::Cleartext)
                        .ok()
                })
                .flatten()
        };
        let request_ref = put(&request_body, request_size);
        let response_ref = put(&response_body, response_size);
        if let Some(r) = flow.request.as_mut() {
            r.body = request_ref;
        }
        if let Some(r) = flow.response.as_mut() {
            r.body = response_ref;
        }
        let stored = store.upsert_flows(std::slice::from_ref(&flow));
        drop(store);
        match stored {
            Ok(()) => self.broadcast(&Message::Flow(flow)),
            Err(e) => self.store_failed("a request", &e.to_string()),
        }
    }

    /// Data that could not be stored is a bug: developer mode shows why.
    fn store_failed(&self, what: &str, why: &str) {
        if self.dev.load(Ordering::SeqCst) {
            self.set_error(Some(format!("Wiretap could not store {what}: {why}")));
        }
    }

    /// Stores a proxy event (a WebSocket message, metadata of a relayed connection) with its
    /// payload and relays it live.
    pub(crate) fn record_event(&self, mut event: NetworkEvent, payload: &[u8], size: u64) {
        let mut store = lock(&self.store);
        self.ensure_session(&mut store);
        if size > 0 {
            event.payload = store
                .insert_payload(
                    event.session_id,
                    payload,
                    size,
                    PayloadEncryption::Cleartext,
                )
                .ok();
        }
        let stored = event.validate().map_err(|e| e.to_string()).and_then(|()| {
            store
                .insert_events(std::slice::from_ref(&event))
                .map_err(|e| e.to_string())
        });
        drop(store);
        match stored {
            Ok(()) => self.broadcast(&Message::Event(event)),
            Err(e) => self.store_failed("an event", &e),
        }
    }
}

struct ProxyHooks(Arc<App>);

/// Name and image path of process `pid`.
#[cfg(windows)]
fn process_info(pid: u32) -> Option<ProcessInfo> {
    let path = wiretap_platform::process_image(pid);
    let name = path
        .as_deref()
        .and_then(|p| p.rsplit('\\').next())
        .map(str::to_owned);
    (pid != 0).then_some(ProcessInfo {
        pid,
        name,
        path,
        started: None,
    })
}

impl Hooks for ProxyHooks {
    fn rules(&self) -> Arc<RuleSet> {
        Arc::clone(&self.0.rules.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn process(&self, client: SocketAddr, proxy: SocketAddr) -> Option<ProcessInfo> {
        #[cfg(windows)]
        return process_info(wiretap_platform::tcp_owner(client, proxy)?);
        #[cfg(not(windows))]
        {
            let _ = (client, proxy);
            None
        }
    }

    fn redirected(&self, client: &TcpStream) -> Option<Redirected> {
        #[cfg(windows)]
        {
            let (addr, pid) = crate::redirect::original(client)?;
            Some(Redirected {
                addr,
                process: process_info(pid),
            })
        }
        #[cfg(not(windows))]
        {
            let _ = client;
            None
        }
    }

    fn record(&self, exchange: Exchange) {
        self.0.record(exchange);
    }

    fn foreign(&self, pid: u32) -> bool {
        #[cfg(windows)]
        {
            static OWN: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
            let own = *OWN.get_or_init(|| wiretap_platform::process_session(std::process::id()));
            // Unknown (the process already exited): decrypt as usual.
            matches!((own, wiretap_platform::process_session(pid)), (Some(a), Some(b)) if a != b)
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            false
        }
    }

    fn event(&self, event: NetworkEvent, payload: Vec<u8>, size: u64) {
        self.0.record_event(event, &payload, size);
    }

    fn tls(&self) -> Option<Arc<dyn Tls>> {
        self.0
            .tls
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
impl App {
    /// Simulates an elevated capture process that was started with `key`.
    pub(crate) fn test_starting(&self, key: &str) {
        *lock(&self.capture) = Capture::Starting { key: key.into() };
    }
}
