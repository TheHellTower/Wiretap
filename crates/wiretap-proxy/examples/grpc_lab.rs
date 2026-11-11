//! gRPC lab: unary calls over cleartext HTTP/2 (prior knowledge), optionally through an HTTP
//! proxy's CONNECT, to test Wiretap's gRPC view against a real server (DEV.md).
//!
//! ```text
//! grpc_lab <host:port> <path> <hex message> [--proxy host:port]
//! grpc_lab grpcb.in:9000 /hello.HelloService/SayHello 0a0757697265746170 --proxy 127.0.0.1:8899
//! ```
//!
//! Prints each response message (as protobuf text) and the call's status.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool"
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

use wiretap_protocol::grpc::{self, Framing};
use wiretap_protocol::http2::{Decoder, Event, PREFACE};
use wiretap_protocol::{hpack, read_head};

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(0).to_be_bytes();
    let mut out = vec![len[1], len[2], len[3], kind, flags];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn hex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn call(target: &str, path: &str, message: &[u8], proxy: Option<&str>) -> Result<(), String> {
    let err = |e: std::io::Error| e.to_string();
    let mut tcp = TcpStream::connect(proxy.unwrap_or(target)).map_err(err)?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(err)?;
    if proxy.is_some() {
        write!(tcp, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").map_err(err)?;
        let (head, _) = read_head(&mut tcp).map_err(err)?;
        println!("proxy: {:?}", head.start);
    }
    let authority = target.to_owned();
    let fields: Vec<hpack::Field> = [
        (":method", "POST"),
        (":scheme", "http"),
        (":path", path),
        (":authority", authority.as_str()),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("user-agent", "wiretap-grpc-lab/1"),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_owned(), v.to_owned()))
    .collect();
    let mut body = vec![0];
    body.extend_from_slice(&u32::try_from(message.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(message);
    let mut out = PREFACE.to_vec();
    out.extend(frame(4, 0, 0, &[]));
    out.extend(frame(1, 0x04, 1, &hpack::encode(&fields)));
    out.extend(frame(0, 0x01, 1, &body));
    tcp.write_all(&out).map_err(err)?;
    let (mut decoder, mut messages) = (
        Decoder::new(false),
        grpc::Decoder::new(Framing::Grpc, 1 << 20),
    );
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = tcp.read(&mut buf).map_err(err)?;
        if n == 0 {
            return Err("the server closed the connection".into());
        }
        for event in decoder.feed(buf.get(..n).unwrap_or_default()) {
            match event {
                Event::Settings(_) => tcp.write_all(&frame(4, 0x01, 0, &[])).map_err(err)?,
                Event::Headers {
                    fields, end_stream, ..
                } => {
                    for (name, value) in &fields {
                        println!("{name}: {value}");
                    }
                    if end_stream {
                        let named = fields.iter().map(|(n, v)| (n.as_str(), v.as_str()));
                        println!("status: {:?}", grpc::status(named));
                        return Ok(());
                    }
                }
                Event::Data { data, .. } => {
                    for m in messages.feed(&data) {
                        let m = m.map_err(str::to_owned)?;
                        let (_, view) = grpc::describe(&m, "gzip", false, 1 << 20);
                        println!(
                            "message ({} bytes):\n{}",
                            m.size,
                            String::from_utf8_lossy(&view)
                        );
                    }
                }
                Event::Reset { code, .. } => return Err(format!("stream reset ({code})")),
                Event::GoAway { code, .. } => return Err(format!("GOAWAY ({code})")),
                Event::Error(e) => return Err(e.into()),
                _ => {}
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let proxy = args
        .iter()
        .position(|a| a == "--proxy")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);
    let (Some(target), Some(path), Some(message)) =
        (args.first(), args.get(1), args.get(2).and_then(|m| hex(m)))
    else {
        eprintln!("usage: grpc_lab <host:port> <path> <hex message> [--proxy host:port]");
        return ExitCode::FAILURE;
    };
    match call(target, path, &message, proxy) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
