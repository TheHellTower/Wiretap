//! `wiretap.exe`: opens the Wiretap app by default; `--headless` selects command-line mode.
#![cfg_attr(not(windows), allow(unused))]

use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use wiretap_cli::{Args, Command, USAGE, parse_args, utc};
use wiretap_core::{SessionId, Timestamp};
use wiretap_storage::{DEFAULT_QUOTA, MAX_PAGE, Store};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "error: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let app = matches!(args.command, Command::Ui { window: true });
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // The app has no console to print to: show the error instead of vanishing.
            #[cfg(windows)]
            if app {
                windows::alert(&format!("Wiretap could not start.\n\n{e}"));
            }
            let _ = writeln!(std::io::stderr(), "error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `--db`, or `%LOCALAPPDATA%\Wiretap\wiretap.db` (created on demand).
fn db_path(path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = path {
        return Ok(p);
    }
    let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set; use --db")?;
    let dir = PathBuf::from(base).join("Wiretap");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("wiretap.db"))
}

fn database(path: Option<PathBuf>) -> Result<Store> {
    Ok(Store::open(db_path(path)?, DEFAULT_QUOTA)?)
}

fn run(args: Args) -> Result {
    let mut out = std::io::stdout().lock();
    match args.command {
        Command::Help => writeln!(out, "{USAGE}")?,
        Command::Version => writeln!(out, "wiretap {}", env!("CARGO_PKG_VERSION"))?,
        Command::Ui { window } => {
            let db = db_path(args.db)?;
            #[cfg(windows)]
            if window {
                windows::detach_console();
            }
            wiretap_ui::run(wiretap_ui::Config {
                db,
                exe: std::env::current_exe()?,
                open_window: window,
            })?;
        }
        Command::Sessions => {
            for s in database(args.db)?.sessions()? {
                writeln!(out, "{}  {}  {}", s.id, utc(s.created), s.name)?;
            }
        }
        Command::Events(session) => {
            dump(&database(args.db)?, session, &mut out, Store::events, |e| {
                (e.timestamp, e.id)
            })?
        }
        Command::Flows(session) => {
            dump(&database(args.db)?, session, &mut out, Store::flows, |f| {
                (f.timing.started, f.id)
            })?
        }
        #[cfg(windows)]
        Command::Check => windows::check(&mut out)?,
        #[cfg(windows)]
        Command::DriverStatus => writeln!(out, "{:?}", wiretap_driver_client::driver_state()?)?,
        #[cfg(windows)]
        Command::DriverStop => wiretap_driver_client::stop_driver()?,
        #[cfg(windows)]
        Command::Capture {
            store,
            quiet,
            duration,
            feed,
        } => {
            let db = db_path(args.db)?;
            let store = if store {
                Some(Store::open(&db, DEFAULT_QUOTA)?)
            } else {
                None
            };
            let dir = db.with_file_name("");
            windows::capture(store, &dir, quiet, duration, feed.as_ref(), &mut out)?;
        }
        #[cfg(not(windows))]
        _ => return Err("this command requires Windows".into()),
    }
    Ok(())
}

/// A keyset-paginated reader such as `Store::events` or `Store::flows`.
type Page<T, K> = fn(
    &Store,
    SessionId,
    Option<(Timestamp, K)>,
    usize,
) -> std::result::Result<Vec<T>, wiretap_storage::StoreError>;

/// Streams every record of a session as JSON lines, page by page.
fn dump<T: serde::Serialize, K: Copy>(
    store: &Store,
    session: SessionId,
    out: &mut impl Write,
    page: Page<T, K>,
    key: fn(&T) -> (Timestamp, K),
) -> Result {
    if store.session(session)?.is_none() {
        return Err(format!("no session {session}").into());
    }
    let mut cursor = None;
    loop {
        let records = page(store, session, cursor, MAX_PAGE)?;
        let Some(last) = records.last() else {
            return Ok(());
        };
        cursor = Some(key(last));
        for record in &records {
            writeln!(out, "{}", serde_json::to_string(record)?)?;
        }
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "console Win32 FFI; every block carries a SAFETY comment"
)]
mod windows {
    use std::io::{BufWriter, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::TRUE;
    use windows_sys::Win32::System::Console::{
        CTRL_CLOSE_EVENT, FreeConsole, GetConsoleProcessList, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    use windows_sys::core::BOOL;
    use wiretap_capture::{Output, Tracker};
    use wiretap_cli::{Feed, render};
    use wiretap_core::{Endpoint, Session, SessionId};
    use wiretap_driver_client::{Capture, DriverState, driver_state};
    use wiretap_driver_proto::{Redirect, records};
    use wiretap_platform::{Support, classify, detect, dos_devices, posture};
    use wiretap_protocol::{StartLine, read_head};
    use wiretap_storage::Store;
    use wiretap_ui::message::{Message, Stats};

    use super::Result;

    static STOP: AtomicBool = AtomicBool::new(false);
    static DONE: AtomicBool = AtomicBool::new(false);

    /// Ctrl+C / Ctrl+Break request a stop. Close, logoff and shutdown end the process when
    /// the handler returns, so wait (within Windows' 5 s budget) for cleanup to finish first.
    unsafe extern "system" fn on_console_event(kind: u32) -> BOOL {
        STOP.store(true, Ordering::SeqCst);
        if kind >= CTRL_CLOSE_EVENT {
            for _ in 0..80 {
                if DONE.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        TRUE
    }

    /// Started from Explorer, Wiretap owns a console of its own: release it so only the app
    /// window remains. Started from a terminal, the console is shared and kept.
    pub(super) fn detach_console() {
        let mut pids = [0u32; 2];
        // SAFETY: `pids` holds 2 entries as declared.
        if unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) } == 1 {
            // SAFETY: detaching from our own console has no preconditions.
            unsafe { FreeConsole() };
        }
    }

    /// Shows `message` in an error dialog.
    pub(super) fn alert(message: &str) {
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (text, caption) = (wide(message), wide("Wiretap"));
        // SAFETY: NUL-terminated strings that outlive the call; no owner window.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                caption.as_ptr(),
                MB_OK | MB_ICONERROR,
            )
        };
    }

    pub(super) fn check(out: &mut impl Write) -> Result {
        let os = detect()?;
        let support = classify(&os);
        let p = posture();
        writeln!(
            out,
            "Windows       {}.{} build {} ({})",
            os.major,
            os.minor,
            os.build,
            if os.workstation { "client" } else { "server" }
        )?;
        writeln!(out, "Support       {support:?}")?;
        writeln!(out, "Administrator {}", yes(p.elevated))?;
        writeln!(out, "Test signing  {}", yes(p.test_signing))?;
        writeln!(out, "Memory integ. {}", yes(p.memory_integrity))?;
        writeln!(
            out,
            "Secure Boot   {}",
            p.secure_boot.map_or("unknown (legacy BIOS)", yes)
        )?;
        let state = driver_state()?;
        writeln!(out, "Driver        {state:?}")?;
        if matches!(support, Support::Unsupported(_)) {
            writeln!(
                out,
                "\nWarning: this system is outside the support matrix (see docs/compatibility/windows.md)."
            )?;
        }
        if state == DriverState::NotInstalled {
            writeln!(out, "\nInstall the driver package first (SETUP.md).")?;
        }
        if !p.elevated {
            writeln!(
                out,
                "\nCapturing requires an elevated (Run as administrator) terminal."
            )?;
        }
        Ok(())
    }

    const fn yes(b: bool) -> &'static str {
        if b { "yes" } else { "no" }
    }

    /// What the app answers when the capture connects its feed.
    struct Joined {
        /// The session to record into (the app's own, shared with its proxy).
        session: Option<SessionId>,
        /// The app's proxy: outbound HTTP(S) is redirected there for full decoding.
        proxy: Option<Redirect>,
        /// The proxy's explicit (non-redirect) ports on 127.0.0.1 and [::1].
        explicit: [u16; 2],
    }

    /// Connects to the app's feed before anything is captured: no feed, no capture.
    fn connect_feed(feed: &Feed) -> Result<(BufWriter<TcpStream>, Joined)> {
        let mut s = TcpStream::connect_timeout(&feed.addr, Duration::from_secs(5))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        write!(
            s,
            "POST /internal/feed HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/x-ndjson\r\n\r\n",
            feed.addr, feed.key
        )?;
        let (head, _) = read_head(&mut s)?;
        if !matches!(head.start, StartLine::Response { status: 200, .. }) {
            return Err("the Wiretap app refused the capture feed".into());
        }
        let session = head
            .header(wiretap_ui::http::SESSION_HEADER)
            .and_then(|id| id.parse().ok())
            .map(SessionId);
        // `<pid> <redirect v4 port> <redirect v6 port> [<explicit v4 port> <explicit v6 port>]`
        let numbers: Option<Vec<u32>> = head
            .header(wiretap_ui::http::PROXY_HEADER)
            .and_then(|v| v.split(' ').map(|n| n.parse().ok()).collect::<Option<_>>());
        let port = |n: &u32| u16::try_from(*n).ok();
        let (proxy, explicit) = match numbers.as_deref() {
            Some([pid, v4, v6, rest @ ..]) if rest.is_empty() || rest.len() == 2 => {
                let redirect = port(v4).zip(port(v6)).and_then(|(port_v4, port_v6)| {
                    let r = Redirect {
                        pid: *pid,
                        port_v4,
                        port_v6,
                    };
                    Redirect::decode(&r.encode()).flatten() // the driver's own validation
                });
                let explicit = match rest {
                    [a, b] => [port(a).unwrap_or(0), port(b).unwrap_or(0)],
                    _ => [0, 0],
                };
                (redirect, explicit)
            }
            _ => (None, [0, 0]),
        };
        Ok((
            BufWriter::new(s),
            Joined {
                session,
                proxy,
                explicit,
            },
        ))
    }

    fn send(feed: &mut BufWriter<TcpStream>, message: &Message) -> std::io::Result<()> {
        serde_json::to_writer(&mut *feed, message).map_err(std::io::Error::other)?;
        feed.write_all(b"\n")
    }

    pub(super) fn capture(
        mut store: Option<Store>,
        dir: &std::path::Path,
        quiet: bool,
        duration: Option<u64>,
        feed: Option<&Feed>,
        out: &mut impl Write,
    ) -> Result {
        if !posture().elevated {
            return Err("capture requires an elevated (Run as administrator) terminal".into());
        }
        let own = feed.map(|f| Endpoint {
            ip: f.addr.ip(),
            port: Some(f.addr.port()),
        });
        let (mut feed, joined) = match feed.map(connect_feed).transpose()? {
            Some((f, joined)) => (Some(f), joined),
            None => (
                None,
                Joined {
                    session: None,
                    proxy: None,
                    explicit: [0, 0],
                },
            ),
        };
        let session = match joined.session {
            Some(id) => id, // stored by the app
            None => {
                let session = Session::new(format!(
                    "Capture {}",
                    super::utc(wiretap_core::Timestamp::now())
                ));
                if let Some(store) = &store {
                    store.insert_session(&session)?;
                }
                if let Some(f) = &mut feed {
                    send(f, &Message::Session(session.clone()))?;
                    f.flush()?;
                }
                session.id
            }
        };
        let mut tracker = Tracker::new(session, dos_devices());
        // The app's own UI and feed connections (the same server) are not user traffic.
        if let Some(own) = own {
            tracker.exclude(own);
        }
        // Redirected connections are recorded in full by the proxy: skip the driver's view of
        // their loopback leg and of the proxy's own upstream connections.
        if let Some(r) = joined.proxy {
            let [explicit_v4, explicit_v6] = joined.explicit;
            for (ip, port) in [
                (IpAddr::from(Ipv4Addr::LOCALHOST), r.port_v4),
                (Ipv6Addr::LOCALHOST.into(), r.port_v6),
                (Ipv4Addr::LOCALHOST.into(), explicit_v4),
                (Ipv6Addr::LOCALHOST.into(), explicit_v6),
            ] {
                if port != 0 {
                    tracker.exclude(Endpoint {
                        ip,
                        port: Some(port),
                    });
                }
            }
            tracker.exclude_process(r.pid);
        }
        // SAFETY: registers a handler with the documented signature; it only touches atomics.
        unsafe { SetConsoleCtrlHandler(Some(on_console_event), TRUE) };
        if let Some(report) = wiretap_driver_client::crash_report(dir) {
            writeln!(out, "{report}")?;
        }
        // Kept from before the driver loads until the capture ends: if Windows stops meanwhile,
        // the next start reports it.
        let _marker = wiretap_driver_client::CaptureMarker::create(dir)?;
        let mut capture = Capture::start(joined.proxy)?;
        // Tells the app the driver is loaded and redirecting: it then shows the capture as running.
        if let Some(f) = &mut feed {
            send(f, &Message::Stats(Stats::default()))?;
            f.flush()?;
        }
        writeln!(
            out,
            "Capturing into session {} (driver loaded). Press Ctrl+C to stop.",
            session
        )?;

        let (mut outputs, mut stats, mut malformed) = (Vec::new(), Stats::default(), 0u64);
        let deadline = duration.map(|s| Instant::now() + Duration::from_secs(s));
        let mut heartbeat = Instant::now();
        let result = (|| -> Result {
            while !STOP.load(Ordering::SeqCst) && deadline.is_none_or(|d| Instant::now() < d) {
                let (lost, bytes) = capture.read()?;
                stats.dropped += lost;
                for record in records(bytes) {
                    match record {
                        Ok(record) => tracker.record(&record, &mut outputs),
                        Err(_) => {
                            malformed += 1;
                            break;
                        }
                    }
                }
                stats.observations += outputs.len() as u64;
                stats.rejected = tracker.rejected();
                if let Some(store) = &mut store {
                    let events: Vec<_> = outputs
                        .iter()
                        .filter_map(|o| {
                            if let Output::Event(e) = o {
                                Some(e.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    let flows: Vec<_> = outputs
                        .iter()
                        .filter_map(|o| {
                            if let Output::Flow(f) = o {
                                Some(f.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    store.insert_events(&events)?;
                    store.upsert_flows(&flows)?;
                }
                if let Some(f) = &mut feed {
                    // The app closing the feed (stop button, window closed, app gone) ends the
                    // capture and unloads the driver.
                    let sent = outputs.iter().try_for_each(|o| {
                        send(
                            f,
                            &match o {
                                Output::Event(e) => Message::Event(e.clone()),
                                Output::Flow(fl) => Message::Flow(fl.clone()),
                            },
                        )
                    });
                    let beat = if heartbeat.elapsed() >= Duration::from_secs(1) {
                        heartbeat = Instant::now();
                        send(f, &Message::Stats(stats))
                    } else {
                        Ok(())
                    };
                    if sent.and(beat).and_then(|()| f.flush()).is_err() {
                        break;
                    }
                }
                if !quiet {
                    for o in &outputs {
                        writeln!(out, "{}", render(o))?;
                    }
                }
                outputs.clear();
            }
            Ok(())
        })();
        let stopped = capture.stop();
        DONE.store(true, Ordering::SeqCst);
        writeln!(
            out,
            "\nStopped. {} observations, {} records dropped by the driver (ring full), {malformed} malformed batches, {} rejected outputs.",
            stats.observations,
            stats.dropped,
            tracker.rejected()
        )?;
        result?;
        let stopped = stopped.map_err(|e| format!("driver could not be unloaded: {e}"))?;
        if !stopped.unloaded {
            writeln!(
                out,
                "The driver stays loaded until Windows restarts (no filters, no redirection: it sees and changes no traffic): connections it redirected keep memory Windows frees only when they are gone, and unloading under them could crash Windows. The next capture uses it."
            )?;
        }
        Ok(())
    }
}
