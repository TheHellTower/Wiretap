//! WebSocket lab: a small echo server and a self-checking client, for testing Wiretap by hand
//! (`cargo run -p wiretap-proxy --example ws_lab`, see DEV.md) and in the proxy tests. Test
//! tooling only, never shipped.
//!
//! Covers RFC 6455 (version 13) and the hybi-07/08 drafts (versions 7 and 8: same framing,
//! `Sec-WebSocket-Origin` instead of `Origin`), `ws://` and `wss://`, direct or through a proxy
//! (CONNECT, as browsers do), and `permessage-deflate` (RFC 7692). The server answers compressed
//! with uncompressed DEFLATE blocks, which needs no compressor.
#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    unreachable_pub,
    missing_docs,
    dead_code,
    reason = "test tooling, shared by the tests and examples/ws_lab.rs"
)]

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wiretap_autoreply::base64;
use wiretap_protocol::read_head;
use wiretap_protocol::websocket::{Decoder, Extensions, Message, Opcode, Sender};

/// A byte stream: TCP, or TLS on top of it.
pub trait Io: Read + Write + Send {}
impl<T: Read + Write + Send> Io for T {}

/// Wraps an accepted (server) or opened (client, for `host`) connection in TLS.
pub type Wrap = Arc<dyn Fn(TcpStream, &str) -> io::Result<Box<dyn Io>> + Send + Sync>;

const MASK: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];
const LIMIT: usize = 16 << 20;

/// SHA-1 (FIPS 180-4), only for `Sec-WebSocket-Accept`.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend((data.len() as u64 * 8).to_be_bytes());
    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (slot, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5A82_7999),
                20..40 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            (e, d, c, b, a) = (d, c, b.rotate_left(30), a, t);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = word.to_be_bytes();
    }
    out
}

/// `Sec-WebSocket-Accept` for a client key (RFC 6455 section 4.2.2).
pub fn accept_key(key: &str) -> String {
    base64::encode(&sha1(
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    ))
}

/// Writes one frame; `first` is the FIN/RSV/opcode byte, `mask` masks it (client frames).
pub fn write_frame(out: &mut dyn Io, first: u8, payload: &[u8], mask: bool) -> io::Result<()> {
    let bit = if mask { 0x80 } else { 0 };
    let mut f = vec![first];
    match payload.len() {
        n @ 0..=125 => f.push(bit | n as u8),
        n @ 126..=0xFFFF => {
            f.push(bit | 126);
            f.extend((n as u16).to_be_bytes());
        }
        n => {
            f.push(bit | 127);
            f.extend((n as u64).to_be_bytes());
        }
    }
    if mask {
        f.extend(MASK);
        f.extend(payload.iter().zip(MASK.iter().cycle()).map(|(b, k)| b ^ k));
    } else {
        f.extend_from_slice(payload);
    }
    out.write_all(&f)
}

/// `permessage-deflate` payload without a compressor: uncompressed DEFLATE blocks, then the
/// sync flush with its `00 00 ff ff` tail removed (RFC 7692 section 7.2.3.3).
pub fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(0xFFFF) {
        let n = chunk.len() as u16;
        out.push(0);
        out.extend(n.to_le_bytes());
        out.extend((!n).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.push(0);
    out
}

/// Reads until the decoder completes at least one message.
fn next(io: &mut dyn Io, decoder: &mut Decoder, queue: &mut Vec<Message>) -> io::Result<Message> {
    let mut buf = [0u8; 16 * 1024];
    while queue.is_empty() {
        let n = io.read(&mut buf)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        for m in decoder.feed(&buf[..n]) {
            queue.push(m.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
        }
    }
    Ok(queue.remove(0))
}

/// Echo server on `listener`: echoes text and binary messages (compressed when the client
/// offered `permessage-deflate`), answers pings, returns the client's close. With `tls`, serves
/// `wss://` for host `tls_host`.
pub fn serve(listener: TcpListener, tls: Option<(Wrap, String)>) {
    for tcp in listener.incoming().flatten() {
        let tls = tls.clone();
        thread::spawn(move || {
            let io: Box<dyn Io> = match &tls {
                Some((wrap, host)) => match wrap(tcp, host) {
                    Ok(io) => io,
                    Err(_) => return,
                },
                None => Box::new(tcp),
            };
            let _ = serve_one(io);
        });
    }
}

fn serve_one(mut io: Box<dyn Io>) -> io::Result<()> {
    let (head, rest) = read_head(&mut io)?;
    let version = head.header("sec-websocket-version").unwrap_or("");
    let Some(key) = head.header("sec-websocket-key") else {
        return io.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
    };
    if !matches!(version, "13" | "8" | "7") {
        return io.write_all(b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13, 8, 7\r\nContent-Length: 0\r\n\r\n");
    }
    let offered = head.header("sec-websocket-extensions").unwrap_or("");
    let agreed = if offered.contains("permessage-deflate") {
        "permessage-deflate; server_no_context_takeover"
    } else {
        ""
    };
    let ext_line = if agreed.is_empty() {
        String::new()
    } else {
        format!("Sec-WebSocket-Extensions: {agreed}\r\n")
    };
    write!(
        io,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n{ext_line}\r\n",
        accept_key(key)
    )?;
    let compress = !agreed.is_empty();
    let mut decoder = Decoder::new(Sender::Client, Extensions::parse(agreed), LIMIT);
    let mut queue: Vec<Message> = decoder
        .feed(&rest)
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    loop {
        let m = next(&mut *io, &mut decoder, &mut queue)?;
        match m.opcode {
            Opcode::Text | Opcode::Binary if compress => write_frame(
                &mut *io,
                0xC0 | m.opcode.code(),
                &deflate_stored(&m.payload),
                false,
            )?,
            Opcode::Text | Opcode::Binary => {
                write_frame(&mut *io, 0x80 | m.opcode.code(), &m.payload, false)?
            }
            Opcode::Ping => write_frame(&mut *io, 0x8A, &m.payload, false)?,
            Opcode::Pong => {}
            Opcode::Close => return write_frame(&mut *io, 0x88, &m.payload, false),
        }
    }
}

/// What the client sends and checks.
#[derive(Clone)]
pub struct Client {
    /// `ws://host[:port]/path` or `wss://...`.
    pub url: String,
    /// Explicit proxy (`host:port`): reached with CONNECT, like browsers do.
    pub proxy: Option<String>,
    /// Offer `permessage-deflate`.
    pub deflate: bool,
    /// `Sec-WebSocket-Version`: 13 (RFC 6455), or 8 / 7 (drafts).
    pub version: u8,
    /// TLS for `wss://`.
    pub tls: Option<Wrap>,
}

/// Connects, runs the scripted exchange against an echo server and returns a line per step.
///
/// # Errors
/// Connection or protocol failures, and any echo that differs from what was sent.
pub fn run(c: &Client) -> io::Result<Vec<String>> {
    let bad = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
    let (secure, rest) = match c.url.split_once("://") {
        Some(("ws", rest)) => (false, rest),
        Some(("wss", rest)) => (true, rest),
        _ => return Err(bad(format!("not a ws:// or wss:// URL: {}", c.url))),
    };
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_owned()), |(a, p)| (a, format!("/{p}")));
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(h, _)| h)
        .trim_matches(['[', ']']);
    let address = if authority
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
    {
        authority.to_owned()
    } else {
        format!("{authority}:{}", if secure { 443 } else { 80 })
    };
    let mut tcp = TcpStream::connect(c.proxy.as_deref().unwrap_or(&address))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut log = Vec::new();
    if c.proxy.is_some() {
        write!(tcp, "CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n")?;
        let (head, _) = read_head(&mut tcp)?;
        log.push(format!("proxy: {:?}", head.start));
    }
    let mut io: Box<dyn Io> = match (&c.tls, secure) {
        (Some(wrap), true) => wrap(tcp, host)?,
        (None, true) => return Err(bad("wss:// needs TLS".into())),
        _ => Box::new(tcp),
    };
    let origin = if c.version == 13 {
        "Origin"
    } else {
        "Sec-WebSocket-Origin"
    };
    let offer = if c.deflate {
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
    } else {
        ""
    };
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    write!(
        io,
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: {}\r\n{origin}: http://{authority}\r\n{offer}\r\n",
        c.version
    )?;
    let (head, rest) = read_head(&mut io)?;
    if head.header("sec-websocket-accept") != Some(accept_key(key).as_str()) {
        return Err(bad(format!("handshake refused: {:?}", head.start)));
    }
    let ext = Extensions::parse(head.header("sec-websocket-extensions").unwrap_or(""));
    log.push(format!(
        "handshake: version {}, permessage-deflate {}",
        c.version,
        ext.deflate.is_some()
    ));
    let mut decoder = Decoder::new(Sender::Server, ext, LIMIT);
    let mut queue: Vec<Message> = decoder
        .feed(&rest)
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    let mut expect =
        |io: &mut dyn Io, opcode: Opcode, payload: &[u8], step: &str| -> io::Result<()> {
            let m = next(io, &mut decoder, &mut queue)?;
            if m.opcode != opcode || m.payload != payload || m.problem.is_some() {
                return Err(bad(format!(
                    "{step}: got {:?} {} bytes {:?}",
                    m.opcode,
                    m.payload.len(),
                    m.problem
                )));
            }
            log.push(format!(
                "{step}: ok ({} bytes{})",
                m.payload.len(),
                if m.compressed { ", compressed" } else { "" }
            ));
            Ok(())
        };
    write_frame(&mut *io, 0x81, b"hello wiretap", true)?;
    expect(&mut *io, Opcode::Text, b"hello wiretap", "text")?;
    let binary: Vec<u8> = (0..=255).collect();
    write_frame(&mut *io, 0x82, &binary, true)?;
    expect(&mut *io, Opcode::Binary, &binary, "binary")?;
    // Fragmented text with a ping between the fragments (RFC 6455 section 5.4).
    write_frame(&mut *io, 0x01, b"frag", true)?;
    write_frame(&mut *io, 0x89, b"between", true)?;
    write_frame(&mut *io, 0x00, b"men", true)?;
    write_frame(&mut *io, 0x80, b"ted", true)?;
    expect(&mut *io, Opcode::Pong, b"between", "ping")?;
    expect(&mut *io, Opcode::Text, b"fragmented", "fragments")?;
    let large: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    write_frame(&mut *io, 0x82, &large, true)?; // 64-bit length
    expect(&mut *io, Opcode::Binary, &large, "large")?;
    write_frame(&mut *io, 0x81, "héllo 👋".as_bytes(), true)?;
    expect(&mut *io, Opcode::Text, "héllo 👋".as_bytes(), "unicode")?;
    if ext.deflate.is_some() {
        write_frame(&mut *io, 0xC1, &deflate_stored(b"compressed hello"), true)?;
        expect(&mut *io, Opcode::Text, b"compressed hello", "compressed")?;
    }
    write_frame(&mut *io, 0x88, b"\x03\xE8done", true)?;
    expect(&mut *io, Opcode::Close, b"\x03\xE8done", "close")?;
    Ok(log)
}

#[cfg(test)]
#[test]
fn rfc6455_accept_key() {
    assert_eq!(
        accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
    assert_eq!(
        sha1(b"abc"),
        [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
        ]
    );
}
