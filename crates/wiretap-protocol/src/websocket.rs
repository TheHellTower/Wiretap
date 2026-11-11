//! WebSocket (RFC 6455) message decoding for a relayed connection, with `permessage-deflate`
//! (RFC 7692). The relay forwards bytes untouched; a [`Decoder`] only observes one direction.
//! A protocol violation ends decoding of that direction (the endpoints close the connection).

use std::collections::BTreeMap;

use wiretap_codec::{Error as CodecError, Inflater};

/// Largest compressed message buffered for decompression.
const MAX_COMPRESSED: usize = 16 << 20;

/// Who sends the frames a [`Decoder`] reads: clients mask every frame, servers never do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    /// The connecting side.
    Client,
    /// The accepting side.
    Server,
}

/// Message type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    /// UTF-8 text.
    Text,
    /// Binary data.
    Binary,
    /// Closing handshake.
    Close,
    /// Keep-alive request.
    Ping,
    /// Keep-alive answer.
    Pong,
}

impl Opcode {
    /// Lowercase name, as stored in event attributes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Close => "close",
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }

    /// The opcode's number on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::Binary => 2,
            Self::Close => 8,
            Self::Ping => 9,
            Self::Pong => 10,
        }
    }

    /// The opcode for a wire number (not continuation, 0).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Text),
            2 => Some(Self::Binary),
            8 => Some(Self::Close),
            9 => Some(Self::Ping),
            10 => Some(Self::Pong),
            _ => None,
        }
    }

    const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// One complete message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Message type.
    pub opcode: Opcode,
    /// Unmasked, reassembled and decompressed payload; at most the decoder's limit.
    pub payload: Vec<u8>,
    /// Full payload size (after decompression; the stored prefix when that failed).
    pub size: u64,
    /// Payload bytes on the wire (the compressed size for compressed messages).
    pub wire_size: u64,
    /// Number of frames the message was split into.
    pub frames: u32,
    /// The message was compressed with `permessage-deflate`.
    pub compressed: bool,
    /// Why the payload is incomplete or invalid, if it is (it was relayed regardless).
    pub problem: Option<&'static str>,
}

impl Message {
    /// A message of one frame (imported records).
    #[must_use]
    pub fn new(opcode: Opcode, payload: Vec<u8>) -> Self {
        let size = payload.len() as u64;
        Self {
            opcode,
            payload,
            size,
            wire_size: size,
            frames: 1,
            compressed: false,
            problem: None,
        }
    }

    /// Status code and reason of a close message that carries them (RFC 6455 section 5.5.1).
    #[must_use]
    pub fn close_status(&self) -> Option<(u16, &str)> {
        let (code, reason) = self.payload.split_first_chunk::<2>()?;
        (self.opcode == Opcode::Close)
            .then(|| Some((u16::from_be_bytes(*code), std::str::from_utf8(reason).ok()?)))
            .flatten()
    }

    /// Event attributes describing the message: `opcode`, `preview` (start of the text, or hex
    /// for binary data), and when relevant `close_code`, `close_reason`, `frames`, `wire_size`
    /// (compressed size) and `problem`. Values contain no control characters.
    #[must_use]
    pub fn attributes(&self) -> BTreeMap<String, String> {
        let printable = |text: &str, max| -> String {
            let shown = text.chars().take(max);
            shown
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect()
        };
        let mut a = BTreeMap::from([("opcode".to_owned(), self.opcode.name().to_owned())]);
        if self.compressed {
            a.insert("wire_size".into(), self.wire_size.to_string());
        }
        if self.frames > 1 {
            a.insert("frames".into(), self.frames.to_string());
        }
        if let Some(problem) = self.problem {
            a.insert("problem".into(), problem.into());
        }
        if let Some((code, reason)) = self.close_status() {
            a.insert("close_code".into(), code.to_string());
            if !reason.is_empty() {
                a.insert("close_reason".into(), printable(reason, 123));
            }
        }
        let preview = match std::str::from_utf8(&self.payload) {
            Ok(text) if self.opcode != Opcode::Binary => printable(text, 120),
            _ => {
                let hex: Vec<String> = self
                    .payload
                    .iter()
                    .take(16)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                hex.join(" ")
            }
        };
        if !preview.is_empty() && self.opcode != Opcode::Close {
            a.insert("preview".into(), preview);
        }
        a
    }
}
/// Negotiated `permessage-deflate` parameters (RFC 7692 section 7.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deflate {
    /// Each client message is compressed on its own.
    pub client_no_context_takeover: bool,
    /// Each server message is compressed on its own.
    pub server_no_context_takeover: bool,
}

/// Extensions agreed in the handshake (the server's `Sec-WebSocket-Extensions`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extensions {
    /// `permessage-deflate`, when agreed.
    pub deflate: Option<Deflate>,
    /// Another extension was agreed: its frames may use reserved bits Wiretap cannot decode.
    pub other: bool,
}

impl Extensions {
    /// Parses the server's `Sec-WebSocket-Extensions` value(s), comma-separated.
    #[must_use]
    pub fn parse(header: &str) -> Self {
        let mut agreed = Self::default();
        for extension in header.split(',') {
            let mut params = extension.split(';').map(str::trim);
            match params.next() {
                Some("") | None => {}
                Some(name) if name.eq_ignore_ascii_case("permessage-deflate") => {
                    let mut deflate = Deflate::default();
                    for param in params {
                        let key = param.split('=').next().unwrap_or("").trim();
                        if key.eq_ignore_ascii_case("client_no_context_takeover") {
                            deflate.client_no_context_takeover = true;
                        } else if key.eq_ignore_ascii_case("server_no_context_takeover") {
                            deflate.server_no_context_takeover = true;
                        }
                    }
                    agreed.deflate.get_or_insert(deflate);
                }
                Some(_) => agreed.other = true,
            }
        }
        agreed
    }
}

/// A message being assembled from frames.
struct Partial {
    opcode: Opcode,
    compressed: bool,
    /// A frame used reserved bits of an extension Wiretap does not decode.
    foreign: bool,
    payload: Vec<u8>,
    size: u64,
    frames: u32,
    cap: usize,
}

/// The frame whose payload is arriving.
struct Frame {
    fin: bool,
    control: bool,
    mask: Option<[u8; 4]>,
    remaining: u64,
    offset: u64,
}

/// Decodes the messages of one direction of a WebSocket connection.
pub struct Decoder {
    sender: Sender,
    extensions: Extensions,
    limit: usize,
    inflater: Inflater,
    /// A compressed message could not be decompressed: with context takeover, the following
    /// ones cannot be either.
    inflate_lost: bool,
    header: Vec<u8>,
    frame: Option<Frame>,
    data: Option<Partial>,
    control: Option<Partial>,
    failed: bool,
}

/// Header bytes needed for the frame whose header starts `h`.
fn header_len(h: &[u8]) -> usize {
    match h {
        [_, b, ..] => {
            let length = match b & 0x7F {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            2 + length + if b & 0x80 == 0 { 0 } else { 4 }
        }
        _ => 2,
    }
}

impl Decoder {
    /// A decoder for frames sent by `sender`, keeping at most `limit` bytes of each payload.
    #[must_use]
    pub fn new(sender: Sender, extensions: Extensions, limit: usize) -> Self {
        Self {
            sender,
            extensions,
            limit,
            inflater: Inflater::default(),
            inflate_lost: false,
            header: Vec::with_capacity(14),
            frame: None,
            data: None,
            control: None,
            failed: false,
        }
    }

    /// Decodes the next relayed bytes of this direction. Returns each message they complete
    /// and, last, the protocol violation that ends decoding, if one occurs.
    pub fn feed(&mut self, mut bytes: &[u8]) -> Vec<Result<Message, &'static str>> {
        let mut out = Vec::new();
        while !bytes.is_empty() && !self.failed {
            let result = if self.frame.is_some() {
                self.payload(&mut bytes, &mut out);
                Ok(())
            } else {
                let need = header_len(&self.header);
                let take = need.saturating_sub(self.header.len()).min(bytes.len());
                let (head, rest) = bytes.split_at(take);
                self.header.extend_from_slice(head);
                bytes = rest;
                if self.header.len() < header_len(&self.header) {
                    continue;
                }
                let header = std::mem::take(&mut self.header);
                self.start(&header, &mut out)
            };
            if let Err(e) = result {
                self.failed = true;
                out.push(Err(e));
            }
        }
        out
    }

    /// Validates a complete frame header (RFC 6455 section 5) and starts its payload.
    fn start(
        &mut self,
        h: &[u8],
        out: &mut Vec<Result<Message, &'static str>>,
    ) -> Result<(), &'static str> {
        let [b0, b1, rest @ ..] = h else {
            return Err("truncated frame header");
        };
        let (fin, rsv, code, masked) = (b0 & 0x80 != 0, b0 & 0x70, b0 & 0x0F, b1 & 0x80 != 0);
        let (len, rest) = match (b1 & 0x7F, rest) {
            (126, [a, b, rest @ ..]) => (u64::from(u16::from_be_bytes([*a, *b])), rest),
            (127, [a, b, c, d, e, f, g, i, rest @ ..]) => {
                (u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *i]), rest)
            }
            (n, rest) => (u64::from(n), rest),
        };
        if len >> 63 != 0 {
            return Err("frame length out of range");
        }
        if masked != (self.sender == Sender::Client) {
            return Err(if masked {
                "server frame is masked"
            } else {
                "client frame is not masked"
            });
        }
        let opcode = match code {
            0 => None,
            c => Some(Opcode::from_code(c).ok_or("reserved opcode")?),
        };
        let deflate = self.extensions.deflate.is_some();
        let data_start = matches!(opcode, Some(Opcode::Text | Opcode::Binary));
        let compressed = rsv & 0x40 != 0 && deflate && data_start;
        // Reserved bits nothing here decodes: an error, unless another extension was agreed.
        let foreign = rsv & 0x30 != 0 || (rsv & 0x40 != 0 && !compressed);
        if foreign && !self.extensions.other {
            return Err("reserved bits set");
        }
        let control = opcode.is_some_and(Opcode::is_control);
        let partial = |opcode, compressed, cap| Partial {
            opcode,
            compressed,
            foreign: false,
            payload: Vec::new(),
            size: 0,
            frames: 0,
            cap,
        };
        match opcode {
            Some(op) if control => {
                if !fin {
                    return Err("fragmented control frame");
                }
                if len > 125 {
                    return Err("control frame longer than 125 bytes");
                }
                self.control = Some(Partial {
                    frames: 1,
                    foreign,
                    ..partial(op, false, self.limit)
                });
            }
            Some(op) => {
                if self.data.is_some() {
                    return Err("new message before the previous one ended");
                }
                let cap = if compressed {
                    MAX_COMPRESSED
                } else {
                    self.limit
                };
                self.data = Some(partial(op, compressed, cap));
            }
            None => {}
        }
        if !control {
            let data = self.data.as_mut().ok_or("continuation without a message")?;
            data.frames += 1;
            data.foreign |= foreign;
        }
        self.frame = Some(Frame {
            fin,
            control,
            mask: masked.then(|| rest.first_chunk::<4>().copied()).flatten(),
            remaining: len,
            offset: 0,
        });
        if len == 0 {
            self.end_frame(out);
        }
        Ok(())
    }

    /// Consumes payload bytes of the current frame.
    fn payload(&mut self, bytes: &mut &[u8], out: &mut Vec<Result<Message, &'static str>>) {
        let Some(frame) = self.frame.as_mut() else {
            return;
        };
        let n = usize::try_from(frame.remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let (chunk, rest) = bytes.split_at(n);
        *bytes = rest;
        let target = if frame.control {
            self.control.as_mut()
        } else {
            self.data.as_mut()
        };
        if let Some(p) = target {
            let keep = chunk
                .get(..p.cap.saturating_sub(p.payload.len()).min(n))
                .unwrap_or_default();
            match frame.mask {
                Some(mask) => {
                    let start = usize::try_from(frame.offset % 4).unwrap_or(0);
                    let key = mask.iter().cycle().skip(start);
                    p.payload.extend(keep.iter().zip(key).map(|(b, k)| b ^ k));
                }
                None => p.payload.extend_from_slice(keep),
            }
            p.size += n as u64;
        }
        frame.remaining -= n as u64;
        frame.offset += n as u64;
        if frame.remaining == 0 {
            self.end_frame(out);
        }
    }

    /// Ends the current frame; a final frame completes its message.
    fn end_frame(&mut self, out: &mut Vec<Result<Message, &'static str>>) {
        let Some(frame) = self.frame.take() else {
            return;
        };
        let done = if frame.control {
            self.control.take()
        } else if frame.fin {
            self.data.take()
        } else {
            None
        };
        if let Some(partial) = done {
            out.push(Ok(self.complete(partial)));
        }
    }

    fn complete(&mut self, p: Partial) -> Message {
        let truncated = (p.payload.len() as u64) < p.size;
        let mut m = Message {
            opcode: p.opcode,
            payload: p.payload,
            size: p.size,
            wire_size: p.size,
            frames: p.frames,
            compressed: p.compressed,
            problem: if p.foreign {
                Some("uses an extension Wiretap does not decode")
            } else {
                truncated.then_some("payload larger than the capture limit")
            },
        };
        if p.compressed {
            let takeover = match self.sender {
                Sender::Client => !self
                    .extensions
                    .deflate
                    .is_some_and(|d| d.client_no_context_takeover),
                Sender::Server => !self
                    .extensions
                    .deflate
                    .is_some_and(|d| d.server_no_context_takeover),
            };
            if truncated || (self.inflate_lost && takeover) {
                self.inflate_lost = true;
                m.problem =
                    Some("compressed message not decoded (too large or after one that was)");
            } else {
                let decoded = self.inflater.message(&m.payload, takeover, self.limit);
                m.payload = decoded.bytes;
                m.size = m.payload.len() as u64;
                if let Some(e) = decoded.error {
                    self.inflate_lost = true;
                    m.problem = Some(if e == CodecError::TooLarge {
                        "decompressed payload larger than the capture limit"
                    } else {
                        "invalid compressed data"
                    });
                }
            }
        }
        // A compressed payload that was not decoded is kept, cut to the limit like any other.
        m.payload.truncate(self.limit);
        if m.problem.is_none() {
            let text = match m.opcode {
                Opcode::Text => Some(m.payload.as_slice()),
                Opcode::Close => m.payload.get(2..),
                _ => None,
            };
            if m.opcode == Opcode::Close && m.payload.len() == 1 {
                m.problem = Some("close payload of one byte");
            } else if text.is_some_and(|t| std::str::from_utf8(t).is_err()) {
                m.problem = Some("invalid UTF-8 text");
            }
        }
        m
    }
}
