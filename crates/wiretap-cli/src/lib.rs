//! Pure parts of `wiretap.exe`: argument parsing and output formatting (unit-tested and
//! fuzzed; the binary in `main.rs` only adds I/O).
#![forbid(unsafe_code)]

use std::path::PathBuf;

use wiretap_capture::Output;
use wiretap_core::{
    Direction, Endpoint, Flow, NetworkEvent, ProcessInfo, Protocol, SessionId, Timestamp,
};

/// Usage text.
pub const USAGE: &str = "\
Wiretap - see everything, understand everything, debug anything.

Usage:
  wiretap [--db <path>] [--no-window]        Open the Wiretap app (default)
  wiretap --headless <command> [options]     Command-line mode

Commands (with --headless):
  check                 Show Windows support, privileges and driver status
  capture               Load the driver, capture until Ctrl+C, then unload it
  sessions              List stored capture sessions
  events <session-id>   Print a session's events as JSON lines
  flows <session-id>    Print a session's HTTP flows as JSON lines
  driver status         Show the driver service state
  driver stop           Unload the driver if that is safe (never after it redirected)

Options:
  --db <path>     Database file (default: %LOCALAPPDATA%\\Wiretap\\wiretap.db)
  --no-window     App mode: print the UI address instead of opening a window
  --no-store      capture: print only, do not save
  --quiet         capture: print only the summary
  --duration <s>  capture: stop automatically after <s> seconds
  -h, --help      Show this help
  -V, --version   Show the version";

/// Where an app-started capture streams its messages (`127.0.0.1:port/key`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feed {
    /// UI server address (loopback only).
    pub addr: std::net::SocketAddr,
    /// One-time key (64 hex digits).
    pub key: String,
}

impl std::str::FromStr for Feed {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, key) = s.split_once('/').ok_or("--feed needs 127.0.0.1:port/key")?;
        let addr: std::net::SocketAddr = addr.parse().map_err(|_| "invalid --feed address")?;
        if !addr.ip().is_loopback() {
            return Err("--feed must point to a loopback address".into());
        }
        if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid --feed key".into());
        }
        Ok(Self {
            addr,
            key: key.to_owned(),
        })
    }
}

/// What to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Open the app (default without `--headless`).
    Ui {
        /// Open the app window (otherwise print the address).
        window: bool,
    },
    /// Diagnostics.
    Check,
    /// Live capture.
    Capture {
        /// Persist to the database.
        store: bool,
        /// Suppress per-event output.
        quiet: bool,
        /// Stop automatically after this many seconds.
        duration: Option<u64>,
        /// Stream to the app instead of (only) the console.
        feed: Option<Feed>,
    },
    /// List sessions.
    Sessions,
    /// Dump a session's events.
    Events(SessionId),
    /// Dump a session's flows.
    Flows(SessionId),
    /// Driver service state.
    DriverStatus,
    /// Unload the driver.
    DriverStop,
    /// Print usage.
    Help,
    /// Print the version.
    Version,
}

/// Parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    /// Command to run.
    pub command: Command,
    /// Database override.
    pub db: Option<PathBuf>,
}

/// Parses arguments (without the program name). Without `--headless` only the app options are
/// accepted; command-line commands require `--headless`.
///
/// # Errors
/// A message describing the first problem.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Args, String> {
    let (mut words, mut db, mut headless, mut window) = (Vec::new(), None, false, true);
    let (mut no_store, mut quiet, mut duration, mut feed) = (false, false, None, None);
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                return Ok(Args {
                    command: Command::Help,
                    db,
                });
            }
            "-V" | "--version" => {
                return Ok(Args {
                    command: Command::Version,
                    db,
                });
            }
            "--headless" => headless = true,
            "--no-window" => window = false,
            "--db" => db = Some(PathBuf::from(args.next().ok_or("--db needs a path")?)),
            "--no-store" => no_store = true,
            "--quiet" | "-q" => quiet = true,
            "--duration" => {
                let secs = args.next().ok_or("--duration needs a number of seconds")?;
                duration = Some(
                    secs.parse::<u64>()
                        .map_err(|_| format!("invalid duration {secs}"))?,
                );
            }
            "--feed" => feed = Some(args.next().ok_or("--feed needs a value")?.parse::<Feed>()?),
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
            _ => words.push(arg),
        }
    }
    let capture_only = no_store || quiet || duration.is_some() || feed.is_some();
    if !headless {
        if !words.is_empty() || capture_only {
            return Err(format!(
                "command-line use needs --headless, e.g. wiretap --headless {}",
                words.join(" ")
            ));
        }
        return Ok(Args {
            command: Command::Ui { window },
            db,
        });
    }
    let session = |id: Option<&String>| -> Result<SessionId, String> {
        let id = id.ok_or("missing <session-id>")?;
        id.parse()
            .map(SessionId)
            .map_err(|_| format!("invalid session id {id}"))
    };
    let command = match words.as_slice() {
        [] => Command::Help,
        [c] if c == "check" => Command::Check,
        [c] if c == "capture" => Command::Capture {
            store: !no_store,
            quiet,
            duration,
            feed,
        },
        [c] if c == "sessions" => Command::Sessions,
        [c, rest @ ..] if c == "events" && rest.len() <= 1 => {
            Command::Events(session(rest.first())?)
        }
        [c, rest @ ..] if c == "flows" && rest.len() <= 1 => Command::Flows(session(rest.first())?),
        [c, s] if c == "driver" && s == "status" => Command::DriverStatus,
        [c, s] if c == "driver" && s == "stop" => Command::DriverStop,
        _ => return Err(format!("unknown command: {}", words.join(" "))),
    };
    if capture_only && !matches!(command, Command::Capture { .. }) {
        return Err("--no-store, --quiet, --duration and --feed only apply to capture".into());
    }
    if !window {
        return Err("--no-window only applies to the app".into());
    }
    Ok(Args { command, db })
}

/// Formats a timestamp as `YYYY-MM-DD HH:MM:SS.mmm` (UTC).
#[must_use]
pub fn utc(ts: Timestamp) -> String {
    ts.utc()
}

fn who(process: Option<&ProcessInfo>) -> String {
    match process {
        Some(p) => format!("{}[{}]", p.name.as_deref().unwrap_or("?"), p.pid),
        None => "?".into(),
    }
}

fn endpoint(e: Option<&Endpoint>) -> String {
    match e {
        Some(Endpoint {
            ip: std::net::IpAddr::V6(ip),
            port: Some(port),
        }) => format!("[{ip}]:{port}"),
        Some(Endpoint {
            ip,
            port: Some(port),
        }) => format!("{ip}:{port}"),
        Some(Endpoint { ip, port: None }) => ip.to_string(),
        None => "?".into(),
    }
}

fn render_event(e: &NetworkEvent) -> String {
    let time = utc(e.timestamp);
    let clock = time.get(11..).unwrap_or(&time);
    let arrow = if e.direction == Direction::Inbound {
        "<-"
    } else {
        "->"
    };
    let peers = format!(
        "{} {arrow} {}",
        endpoint(e.local_endpoint.as_ref()),
        endpoint(e.remote_endpoint.as_ref())
    );
    let attrs: Vec<String> = e
        .metadata
        .attributes
        .iter()
        .map(|(k, v)| format!("{}={v}", k.trim_start_matches("tls.")))
        .collect();
    let protocol = match e.protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
        Protocol::Icmp => "ICMP",
        Protocol::Icmpv6 => "ICMPv6",
        Protocol::Tls => "TLS",
        _ => "?",
    };
    format!(
        "{clock}  {:<24} {protocol:<6} {peers} {}",
        who(e.process.as_ref()),
        attrs.join(" ")
    )
    .trim_end()
    .to_owned()
}

fn render_flow(f: &Flow) -> String {
    let time = utc(f.timing.response_started.unwrap_or(f.timing.started));
    let clock = time.get(11..).unwrap_or(&time);
    let (method, url) = f
        .request
        .as_ref()
        .map_or(("?", "?"), |r| (r.method.as_str(), r.url.as_str()));
    let status = f.response.as_ref().map_or_else(
        || "...".to_owned(),
        |r| format!("{} {}", r.status, r.reason),
    );
    format!(
        "{clock}  {:<24} HTTP   {method} {url} -> {status}",
        who(f.process.as_ref())
    )
}

/// One human-readable line per observation. Model validation guarantees the values contain
/// no control characters, so lines cannot inject terminal escape sequences.
#[must_use]
pub fn render(output: &Output) -> String {
    match output {
        Output::Event(e) => render_event(e),
        Output::Flow(f) => render_flow(f),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Result<Args, String> {
        parse_args(line.split_whitespace().map(str::to_owned))
    }

    #[test]
    fn app_mode_is_the_default() {
        assert_eq!(parse("").unwrap().command, Command::Ui { window: true });
        assert_eq!(
            parse("--no-window --db x.db").unwrap(),
            Args {
                command: Command::Ui { window: false },
                db: Some("x.db".into())
            }
        );
        assert!(
            parse("capture").unwrap_err().contains("--headless"),
            "commands need --headless"
        );
        assert!(parse("--quiet").is_err());
        assert_eq!(parse("--help").unwrap().command, Command::Help);
    }

    #[test]
    fn parses_headless_commands_and_options() {
        assert_eq!(parse("--headless").unwrap().command, Command::Help);
        assert_eq!(
            parse("--headless capture --no-store").unwrap().command,
            Command::Capture {
                store: false,
                quiet: false,
                duration: None,
                feed: None
            }
        );
        assert_eq!(
            parse("--quiet --headless capture --duration 30")
                .unwrap()
                .command,
            Command::Capture {
                store: true,
                quiet: true,
                duration: Some(30),
                feed: None
            }
        );
        let key = "ab".repeat(32);
        let Command::Capture {
            feed: Some(feed), ..
        } = parse(&format!("--headless capture --feed 127.0.0.1:5000/{key}"))
            .unwrap()
            .command
        else {
            panic!("feed not parsed");
        };
        assert_eq!((feed.addr.port(), feed.key), (5000, key));
        let id = SessionId::generate();
        assert_eq!(
            parse(&format!("--headless flows {id} --db x.db")).unwrap(),
            Args {
                command: Command::Flows(id),
                db: Some("x.db".into())
            }
        );
        assert_eq!(
            parse("driver stop --headless").unwrap().command,
            Command::DriverStop
        );
    }

    #[test]
    fn rejects_bad_command_lines() {
        for line in [
            "--headless bogus",
            "--headless events",
            "--headless events not-a-uuid",
            "--headless capture --db",
            "--headless sessions --quiet",
            "--headless check --frobnicate",
            "--headless driver",
            "--headless flows a b",
            "--headless capture --duration -1",
            "--headless check --duration 5",
            "--headless check --no-window",
            "--headless capture --feed 10.0.0.1:5000/00",
            "--headless capture --feed 127.0.0.1:5000/short",
            "--headless capture --feed nonsense",
        ] {
            assert!(parse(line).is_err(), "{line}");
        }
    }

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(utc(Timestamp(0)), "1970-01-01 00:00:00.000");
        assert_eq!(
            utc(Timestamp(951_782_400_000_000)),
            "2000-02-29 00:00:00.000"
        );
        assert_eq!(
            utc(Timestamp(1_762_300_800_123_456)),
            "2025-11-05 00:00:00.123"
        );
        assert_eq!(utc(Timestamp(-1_000)), "1969-12-31 23:59:59.999");
        let _ = utc(Timestamp(i64::MIN));
        let _ = utc(Timestamp(i64::MAX));
    }
}
