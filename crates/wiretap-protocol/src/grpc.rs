//! gRPC messages, as the official specifications define them (grpc/grpc `doc/PROTOCOL-HTTP2.md`
//! and `doc/PROTOCOL-WEB.md`): the Length-Prefixed-Messages of a body as it arrives, gRPC-Web's
//! in-body trailers and base64 text form, the call status, and a schema-less view of Protocol
//! Buffers messages (protobuf.dev, "Encoding"). Bounded and panic-free.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// How a body carries gRPC messages, from its `content-type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// `application/grpc[+format]` (HTTP/2; the status comes in HTTP trailers).
    Grpc,
    /// `application/grpc-web[+format]`: the status comes in a final trailers frame.
    Web,
    /// `application/grpc-web-text[+format]`: gRPC-Web in base64.
    WebText,
}

impl Framing {
    /// The framing a `content-type` names, and whether its messages are JSON (`+json`; other
    /// formats, `+proto` by default, are binary).
    #[must_use]
    pub fn of(content_type: &str) -> Option<(Self, bool)> {
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let (base, format) = essence.split_once('+').unwrap_or((&essence, "proto"));
        let framing = match base {
            "application/grpc" => Self::Grpc,
            "application/grpc-web" => Self::Web,
            "application/grpc-web-text" => Self::WebText,
            _ => return None,
        };
        Some((framing, format == "json"))
    }
}

/// One Length-Prefixed-Message (or gRPC-Web trailers frame).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// The Compressed-Flag: the bytes are in the call's `grpc-encoding`.
    pub compressed: bool,
    /// A gRPC-Web trailers frame (an HTTP/1 header block) rather than a message.
    pub trailers: bool,
    /// The bytes as sent, up to the decoder's limit.
    pub data: Vec<u8>,
    /// The Message-Length.
    pub size: u64,
}

/// Splits one direction of a call into its messages.
#[derive(Debug)]
pub struct Decoder {
    web: bool,
    base64: Option<Base64>,
    prefix: [u8; 5],
    have: usize,
    current: Option<Message>,
    remaining: u64,
    limit: usize,
    failed: bool,
}

impl Decoder {
    /// A decoder for `framing`, keeping at most `limit` bytes of each message.
    #[must_use]
    pub fn new(framing: Framing, limit: usize) -> Self {
        Self {
            web: framing != Framing::Grpc,
            base64: (framing == Framing::WebText).then(Base64::default),
            prefix: [0; 5],
            have: 0,
            current: None,
            remaining: 0,
            limit,
            failed: false,
        }
    }

    /// Decodes the next body bytes; returns the messages they complete. After an error (always
    /// last) nothing more is decoded.
    pub fn feed(&mut self, input: &[u8]) -> Vec<Result<Message, &'static str>> {
        let mut out = Vec::new();
        if self.failed {
            return out;
        }
        // Base64 is decoded up to a bad character: what came before still forms messages, so the
        // result does not depend on how the body was split.
        let (decoded, bad) = match &mut self.base64 {
            Some(b64) => {
                let (bytes, bad) = b64.feed(input);
                (Some(bytes), bad)
            }
            None => (None, None),
        };
        let mut rest = decoded.as_deref().unwrap_or(input);
        while !rest.is_empty() {
            if let Some(m) = &mut self.current {
                let take = usize::try_from(self.remaining)
                    .unwrap_or(usize::MAX)
                    .min(rest.len());
                let (part, tail) = rest.split_at(take);
                let room = self.limit.saturating_sub(m.data.len()).min(part.len());
                m.data
                    .extend_from_slice(part.get(..room).unwrap_or_default());
                self.remaining -= take as u64;
                rest = tail;
                if self.remaining == 0
                    && let Some(m) = self.current.take()
                {
                    out.push(Ok(m));
                }
                continue;
            }
            let take = (5 - self.have).min(rest.len());
            let (part, tail) = rest.split_at(take);
            if let Some(slot) = self.prefix.get_mut(self.have..self.have + take) {
                slot.copy_from_slice(part);
            }
            self.have += take;
            rest = tail;
            if self.have < 5 {
                break;
            }
            self.have = 0;
            let [flag, a, b, c, d] = self.prefix;
            let trailers = self.web && flag & 0x80 != 0;
            if flag & 0x7E != 0 || (!self.web && flag & 0x80 != 0) {
                return self.fail(out, "invalid gRPC message flag");
            }
            let message = Message {
                compressed: flag & 1 != 0,
                trailers,
                data: Vec::new(),
                size: u64::from(u32::from_be_bytes([a, b, c, d])),
            };
            if message.size == 0 {
                out.push(Ok(message));
            } else {
                self.remaining = message.size;
                self.current = Some(message);
            }
        }
        match bad {
            Some(why) => self.fail(out, why),
            None => out,
        }
    }

    /// Whether the body may end here (no message or prefix is cut).
    #[must_use]
    pub const fn at_boundary(&self) -> bool {
        self.have == 0 && self.current.is_none()
    }

    fn fail(
        &mut self,
        mut out: Vec<Result<Message, &'static str>>,
        why: &'static str,
    ) -> Vec<Result<Message, &'static str>> {
        self.failed = true;
        out.push(Err(why));
        out
    }
}

/// Base64 in chunks: gRPC-Web-text servers flush base64 per message, so `=` padding may end any
/// group (the body as a whole need not be valid base64). Both alphabets and line breaks are
/// accepted.
#[derive(Debug, Default)]
struct Base64 {
    group: [u8; 4],
    n: usize,
    pad: usize,
}

impl Base64 {
    /// The bytes decoded, and the error that stopped decoding early, if any.
    fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Option<&'static str>) {
        const BAD: &str = "invalid base64 in a gRPC-Web text body";
        let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
        for &c in input {
            let value = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                b'=' if self.n >= 2 => {
                    self.pad += 1;
                    0
                }
                b'\r' | b'\n' | b' ' | b'\t' => continue,
                _ => return (out, Some(BAD)),
            };
            if self.pad > 0 && c != b'=' {
                return (out, Some(BAD));
            }
            if let Some(slot) = self.group.get_mut(self.n) {
                *slot = value;
            }
            self.n += 1;
            if self.n == 4 {
                let [a, b, c, d] = self.group;
                let bytes = [a << 2 | b >> 4, b << 4 | c >> 2, c << 6 | d];
                out.extend_from_slice(bytes.get(..3 - self.pad).unwrap_or_default());
                (self.n, self.pad) = (0, 0);
            }
        }
        (out, None)
    }
}

/// The name of a gRPC status code (`grpc/grpc` `doc/statuscodes.md`).
#[must_use]
pub const fn status_name(code: u32) -> &'static str {
    match code {
        0 => "OK",
        1 => "CANCELLED",
        2 => "UNKNOWN",
        3 => "INVALID_ARGUMENT",
        4 => "DEADLINE_EXCEEDED",
        5 => "NOT_FOUND",
        6 => "ALREADY_EXISTS",
        7 => "PERMISSION_DENIED",
        8 => "RESOURCE_EXHAUSTED",
        9 => "FAILED_PRECONDITION",
        10 => "ABORTED",
        11 => "OUT_OF_RANGE",
        12 => "UNIMPLEMENTED",
        13 => "INTERNAL",
        14 => "UNAVAILABLE",
        15 => "DATA_LOSS",
        16 => "UNAUTHENTICATED",
        _ => "",
    }
}

/// Decodes a `grpc-message` value (UTF-8, percent-encoded); bad encodings are kept as sent, as
/// the specification asks.
#[must_use]
pub fn percent_decode(value: &str) -> String {
    let (bytes, mut out, mut i) = (value.as_bytes(), Vec::new(), 0);
    while let Some(&b) = bytes.get(i) {
        let hex = |j: usize| bytes.get(j).and_then(|&h| (h as char).to_digit(16));
        match (b, hex(i + 1), hex(i + 2)) {
            (b'%', Some(h), Some(l)) => {
                out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
                i += 3;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Attributes of a call's status, from its trailers (HTTP/2 trailers, a Trailers-Only response
/// or a gRPC-Web trailers frame): `status` (code and name), `grpc-message`, `status.details`
/// (present). `None` without `grpc-status`.
#[must_use]
pub fn status<'a>(
    fields: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (name, value) in fields {
        match name.trim().to_ascii_lowercase().as_str() {
            "grpc-status" => {
                let code = value.trim();
                let name = code.parse().map_or("", status_name);
                let shown = if name.is_empty() {
                    code.to_owned()
                } else {
                    format!("{code} {name}")
                };
                out.insert("status".into(), clean(&shown, 64));
            }
            "grpc-message" => {
                out.insert("grpc-message".into(), clean(&percent_decode(value), 1024));
            }
            "grpc-status-details-bin" => {
                out.insert("status.details".into(), "present".into());
            }
            _ => {}
        }
    }
    out.contains_key("status").then_some(out)
}

/// The fields of a gRPC-Web trailers frame (`name: value` lines).
#[must_use]
pub fn trailer_fields(block: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(block)
        .split("\r\n")
        .flat_map(|l| l.split('\n'))
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

fn clean(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Longest decoded view kept per message.
pub const MAX_VIEW: usize = 16 * 1024;

/// A message's attributes and payload, given the call's `grpc-encoding` and whether messages
/// are JSON. The payload is the readable view (protobuf text or JSON, up to [`MAX_VIEW`]) when
/// there is one, else the message bytes (decompressed). Attributes: `compressed` (the
/// encoding), `shown` (`protobuf`, `json` or `bytes`), `preview` (the start of the view),
/// `error` (why there is no view).
#[must_use]
pub fn describe(
    message: &Message,
    encoding: &str,
    json: bool,
    limit: usize,
) -> (BTreeMap<String, String>, Vec<u8>) {
    let mut a = BTreeMap::new();
    let complete = message.data.len() as u64 == message.size;
    let data = if message.compressed {
        a.insert("compressed".into(), clean(encoding, 32));
        let decoded = wiretap_codec::decode(encoding, &message.data, limit);
        if let Some(e) = decoded.error.filter(|_| complete) {
            a.insert("error".into(), e.to_string());
        }
        decoded.bytes
    } else {
        message.data.clone()
    };
    let view = if a.contains_key("error") {
        None
    } else if json {
        Some(String::from_utf8_lossy(&data).into_owned())
    } else {
        protobuf_text(&data, MAX_VIEW)
    };
    let Some(mut text) = view else {
        if !a.contains_key("error") {
            let why = if complete {
                "not a Protocol Buffers message (or one Wiretap cannot show without its schema)"
            } else {
                "message larger than the stored part"
            };
            a.insert("error".into(), why.into());
        }
        a.insert("shown".into(), "bytes".into());
        return (a, data);
    };
    let preview = if text.is_empty() {
        "(empty message)".to_owned()
    } else {
        clean(&text.split_whitespace().collect::<Vec<_>>().join(" "), 200)
    };
    a.insert("preview".into(), preview);
    a.insert(
        "shown".into(),
        if json { "json" } else { "protobuf" }.into(),
    );
    text.truncate(text.floor_char_boundary(MAX_VIEW));
    (a, text.into_bytes())
}
/// A field of a message, as the wire format has it.
enum Value<'a> {
    Varint(u64),
    I64(u64),
    Len(&'a [u8]),
    Group(Vec<(u32, Value<'a>)>),
    I32(u32),
}

/// Deepest nesting shown (the reference implementations stop at 100).
const MAX_DEPTH: usize = 32;
/// Largest field number (protobuf.dev, "Assigning Field Numbers": 2^29 - 1).
const MAX_FIELD: u64 = (1 << 29) - 1;

fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let b = *bytes.get(*at)?;
        *at += 1;
        let part = u64::from(b & 0x7F);
        if i == 9 && part > 1 {
            return None; // more than 64 bits
        }
        value |= part << (7 * i);
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Parses fields until the end of `bytes`, or until the EGROUP of `group`.
fn fields<'a>(
    bytes: &'a [u8],
    at: &mut usize,
    group: Option<u32>,
    depth: usize,
) -> Option<Vec<(u32, Value<'a>)>> {
    let mut out = Vec::new();
    while *at < bytes.len() {
        let tag = varint(bytes, at)?;
        let number = u32::try_from(tag >> 3)
            .ok()
            .filter(|&n| n >= 1 && u64::from(n) <= MAX_FIELD)?;
        let value = match tag & 7 {
            0 => Value::Varint(varint(bytes, at)?),
            1 => {
                let b = bytes.get(*at..*at + 8)?;
                *at += 8;
                Value::I64(u64::from_le_bytes(b.try_into().ok()?))
            }
            2 => {
                let len = usize::try_from(varint(bytes, at)?).ok()?;
                let b = bytes.get(*at..at.checked_add(len)?)?;
                *at += len;
                Value::Len(b)
            }
            3 if depth < MAX_DEPTH => Value::Group(fields(bytes, at, Some(number), depth + 1)?),
            4 => return (group == Some(number)).then_some(out),
            5 => {
                let b = bytes.get(*at..*at + 4)?;
                *at += 4;
                Value::I32(u32::from_le_bytes(b.try_into().ok()?))
            }
            _ => return None,
        };
        out.push((number, value));
    }
    group.is_none().then_some(out)
}

/// Renders `bytes` as a Protocol Buffers message without its schema, like protoscope: one
/// `number: value` line per field, nested messages in braces. The wire format does not say
/// whether a length-delimited field is text, bytes or a message; it is shown as text when it is
/// printable UTF-8, else as a message when it parses as one, else as hex. `None` when `bytes`
/// is not a message. At most `max` bytes of text.
#[must_use]
pub fn protobuf_text(bytes: &[u8], max: usize) -> Option<String> {
    let parsed = fields(bytes, &mut 0, None, 0)?;
    let mut out = String::new();
    render(&parsed, 0, &mut out, max);
    if out.len() > max {
        out.truncate(out.floor_char_boundary(max));
        out.push_str("\n…");
    }
    Some(out)
}

fn render(fields: &[(u32, Value<'_>)], depth: usize, out: &mut String, max: usize) {
    let indent = "  ".repeat(depth);
    for (number, value) in fields {
        if out.len() > max {
            return;
        }
        let _ = write!(out, "{indent}{number}: ");
        match value {
            Value::Varint(v) => {
                let _ = write!(out, "{v}");
                if *v >> 63 == 1 {
                    let _ = write!(out, " ({})", v.cast_signed());
                }
            }
            Value::I64(v) => {
                let _ = write!(out, "0x{v:016x}");
                let f = f64::from_bits(*v);
                if f == 0.0 || (f.is_finite() && (1e-9..1e15).contains(&f.abs())) {
                    let _ = write!(out, " ({f})");
                }
            }
            Value::I32(v) => {
                let _ = write!(out, "0x{v:08x}");
                let f = f32::from_bits(*v);
                if f == 0.0 || (f.is_finite() && (1e-6..1e9).contains(&f.abs())) {
                    let _ = write!(out, " ({f})");
                }
            }
            Value::Group(inner) => {
                out.push_str("group {\n");
                render(inner, depth + 1, out, max);
                let _ = write!(out, "{indent}}}");
            }
            Value::Len(b) => len(b, depth, &indent, out, max),
        }
        out.push('\n');
    }
}

fn len(b: &[u8], depth: usize, indent: &str, out: &mut String, max: usize) {
    if let Ok(text) = std::str::from_utf8(b)
        && text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    {
        let _ = write!(out, "{text:?}");
        return;
    }
    if depth < MAX_DEPTH
        && let Some(inner) = fields(b, &mut 0, None, depth + 1)
    {
        out.push_str("{\n");
        render(&inner, depth + 1, out, max);
        let _ = write!(out, "{indent}}}");
        return;
    }
    out.push_str("0x");
    for byte in b.iter().take(max / 2) {
        let _ = write!(out, "{byte:02x}");
    }
}
