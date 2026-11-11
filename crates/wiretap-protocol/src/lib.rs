//! Bounded, panic-free decoders for untrusted network bytes: HTTP/1.x message heads, chunked
//! bodies, HTTP/2 frames and HPACK header blocks, WebSocket messages, Server-Sent Events, and TLS
//! handshake metadata (SSL 3.0 to TLS 1.3 versions, cipher suite, SNI, ALPN, and the server certificate before
//! TLS 1.3). Every decoder is total: arbitrary input yields a result or an error, never a panic
//! or unbounded work.
#![forbid(unsafe_code)]

mod chunked;
pub mod grpc;
pub mod hpack;
mod http;
pub mod http2;
pub mod sse;
mod tls;
pub mod websocket;

pub use chunked::{ChunkError, Chunked, Progress};
pub use http::{Framing, Head, MAX_HEAD, StartLine, framing, parse_head};
pub use tls::{
    Certificate, ClientHello, MAX_FLIGHT, ServerFlight, ServerHello, cipher_suite_name,
    parse_client_hello, parse_server_flight, parse_server_hello, version_name,
};

/// Outcome of decoding a buffer prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parse<T> {
    /// A complete message was decoded.
    Complete(T),
    /// The buffer is a valid prefix; more bytes are needed.
    Partial,
    /// The bytes are not (or no longer) this protocol, or exceed a limit.
    Invalid,
}

/// Reads from `reader` until one complete message head is parsed (at most [`MAX_HEAD`]
/// bytes). Returns the head and any bytes read past it (the start of the body).
///
/// # Errors
/// I/O errors, end of stream before a complete head, or an invalid or oversized head.
pub fn read_head(reader: &mut impl std::io::Read) -> std::io::Result<(Head, Vec<u8>)> {
    use std::io::{Error, ErrorKind};
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed before a complete HTTP head",
            ));
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        match parse_head(&buf) {
            Parse::Complete(head) => {
                let rest = buf.split_off(head.len.min(buf.len()));
                return Ok((head, rest));
            }
            Parse::Partial => {}
            Parse::Invalid => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid or oversized HTTP head",
                ));
            }
        }
    }
}

/// Panic-free big-endian reader.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        let (b, rest) = self.0.split_first_chunk::<2>()?;
        self.0 = rest;
        Some(u16::from_be_bytes(*b))
    }
    fn u24(&mut self) -> Option<usize> {
        let (&[a, b, c], rest) = self.0.split_first_chunk::<3>()?;
        self.0 = rest;
        Some((usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c))
    }
    /// A sub-reader over a vector with a 24-bit length (TLS handshake messages, certificates).
    fn vec24(&mut self) -> Option<Reader<'a>> {
        let n = self.u24()?;
        self.bytes(n).map(Reader)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    /// A sub-reader over a length-prefixed vector.
    fn vec16(&mut self) -> Option<Reader<'a>> {
        let n = usize::from(self.u16()?);
        self.bytes(n).map(Reader)
    }
    fn vec8(&mut self) -> Option<Reader<'a>> {
        let n = usize::from(self.u8()?);
        self.bytes(n).map(Reader)
    }
}

#[cfg(test)]
mod grpc_tests;
#[cfg(test)]
mod http2_tests;
#[cfg(test)]
mod sse_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod websocket_tests;
