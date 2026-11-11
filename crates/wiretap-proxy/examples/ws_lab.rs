//! WebSocket lab: an echo server and a self-checking client to test Wiretap by hand (DEV.md).
//!
//! ```text
//! ws_lab server [--port 9001] [--tls <host>]      ws:// echo server, or wss:// for <host>
//! ws_lab client <url> [--proxy host:port] [--deflate] [--version 13|8|7] [--trust root.cer]
//! ws_lab cleanup                                  delete the wss:// server's lab keys
//! ```
//!
//! `cargo run -p wiretap-proxy --example ws_lab -- server --tls localhost` writes the server's
//! root to `ws-lab-root.cer`; give it to the client with `--trust`. Without `--trust`, the client
//! trusts what Windows trusts (public servers, or anything Wiretap decrypts).
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool"
)]

#[path = "../src/wslab.rs"]
mod wslab;

use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

const LAB_CA: &str = "Wiretap WS Lab";

fn value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("server") => server(&args),
        Some("client") => client(&args),
        Some("cleanup") => cleanup(),
        _ => Err("usage: ws_lab server [--port 9001] [--tls <host>] | client <url> [--proxy host:port] [--deflate] [--version 13|8|7] [--trust root.cer] | cleanup".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ws_lab: {e}");
            ExitCode::FAILURE
        }
    }
}

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn server(args: &[String]) -> Result {
    let port = value(args, "--port").unwrap_or_else(|| "9001".into());
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;
    let tls = match value(args, "--tls") {
        Some(host) => Some((wss_server()?, host)),
        None => None,
    };
    let scheme = if tls.is_some() { "wss" } else { "ws" };
    println!(
        "echo server on {scheme}://{}/ (Ctrl+C to stop)",
        listener.local_addr()?
    );
    wslab::serve(listener, tls);
    Ok(())
}

fn client(args: &[String]) -> Result {
    let url = args
        .get(1)
        .ok_or("client needs a ws:// or wss:// URL")?
        .clone();
    let tls = if url.starts_with("wss://") {
        Some(wss_client(value(args, "--trust"))?)
    } else {
        None
    };
    let lab = wslab::Client {
        url,
        proxy: value(args, "--proxy"),
        deflate: args.iter().any(|a| a == "--deflate"),
        version: value(args, "--version").map_or(Ok(13), |v| v.parse())?,
        tls,
    };
    for line in wslab::run(&lab)? {
        println!("{line}");
    }
    println!("all echoes matched");
    Ok(())
}

#[cfg(windows)]
fn wss_server() -> std::result::Result<wslab::Wrap, Box<dyn std::error::Error>> {
    let authority = Arc::new(wiretap_tls::Authority::open(LAB_CA)?);
    std::fs::write("ws-lab-root.cer", authority.certificate())?;
    println!("server root written to ws-lab-root.cer (client: --trust ws-lab-root.cer)");
    Ok(Arc::new(move |tcp, host| {
        Ok(Box::new(authority.accept(tcp, host, Vec::new(), &[])?) as Box<dyn wslab::Io>)
    }))
}

#[cfg(windows)]
fn wss_client(
    trust: Option<String>,
) -> std::result::Result<wslab::Wrap, Box<dyn std::error::Error>> {
    let upstream = Arc::new(match trust {
        Some(path) => wiretap_tls::Upstream::trusting(&std::fs::read(path)?)?,
        None => wiretap_tls::Upstream::system()?,
    });
    Ok(Arc::new(move |tcp, host| {
        Ok(Box::new(upstream.connect(tcp, host, &[])?) as Box<dyn wslab::Io>)
    }))
}

#[cfg(windows)]
fn cleanup() -> Result {
    wiretap_tls::Authority::open(LAB_CA)?.delete()?;
    println!("deleted the {LAB_CA} keys");
    Ok(())
}

#[cfg(not(windows))]
fn wss_server() -> std::result::Result<wslab::Wrap, Box<dyn std::error::Error>> {
    Err("wss:// needs Windows (SChannel)".into())
}

#[cfg(not(windows))]
fn wss_client(_: Option<String>) -> std::result::Result<wslab::Wrap, Box<dyn std::error::Error>> {
    Err("wss:// needs Windows (SChannel)".into())
}

#[cfg(not(windows))]
fn cleanup() -> Result {
    Ok(())
}
