//! HTTP/1.0 and HTTP/1.1 message heads (RFC 9112), parsed strictly: CRLF line endings, no
//! obsolete line folding, token methods and field names, no control characters in values.

use wiretap_core::{HttpHeader, HttpVersion, limits};

use crate::Parse;

/// Largest accepted message head (start line plus fields), in bytes.
pub const MAX_HEAD: usize = 64 * 1024;

/// First line of a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartLine {
    /// `method SP request-target SP version`.
    Request {
        /// Request method.
        method: String,
        /// Request target as sent (origin-form or absolute-form).
        target: String,
        /// Protocol version.
        version: HttpVersion,
    },
    /// `version SP status SP reason`.
    Response {
        /// Status code.
        status: u16,
        /// Reason phrase.
        reason: String,
        /// Protocol version.
        version: HttpVersion,
    },
}

/// A parsed message head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// Start line.
    pub start: StartLine,
    /// Header fields in wire order.
    pub headers: Vec<HttpHeader>,
    /// Bytes consumed, including the terminating empty line.
    pub len: usize,
}

impl Head {
    /// First value of header `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn version(s: &str) -> Option<HttpVersion> {
    match s {
        "HTTP/1.1" => Some(HttpVersion::Http11),
        "HTTP/1.0" => Some(HttpVersion::Http10),
        _ => None,
    }
}

/// Field values may contain any visible character, space, tab or obs-text, but no controls.
fn clean_value(raw: &[u8]) -> Option<String> {
    let value = String::from_utf8_lossy(raw);
    let value = value.trim_matches([' ', '\t']);
    (!value.chars().any(|c| c.is_control() && c != '\t')).then(|| value.to_owned())
}

fn start_line(line: &[u8]) -> Option<StartLine> {
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.splitn(3, ' ');
    let (first, second, third) = (parts.next()?, parts.next()?, parts.next().unwrap_or(""));
    if let Some(version) = version(first) {
        let status: u16 = second
            .parse()
            .ok()
            .filter(|_| second.len() == 3 && second.bytes().all(|b| b.is_ascii_digit()))?;
        let reason = clean_value(third.as_bytes())?;
        return (status >= 100 && reason.len() <= limits::LABEL).then_some(StartLine::Response {
            status,
            reason,
            version,
        });
    }
    let version = version(third)?;
    let method_ok =
        !first.is_empty() && first.len() <= limits::LABEL && first.bytes().all(is_tchar);
    let target_ok = !second.is_empty()
        && second.len() <= limits::URL
        && second.bytes().all(|b| b.is_ascii_graphic());
    (method_ok && target_ok).then(|| StartLine::Request {
        method: first.to_owned(),
        target: second.to_owned(),
        version,
    })
}

fn field(line: &[u8]) -> Option<HttpHeader> {
    let colon = line.iter().position(|&b| b == b':')?;
    let (name, rest) = line.split_at(colon);
    let value = rest.get(1..)?;
    if name.is_empty() || name.len() > limits::LABEL || !name.iter().all(|&b| is_tchar(b)) {
        return None;
    }
    Some(HttpHeader {
        name: String::from_utf8_lossy(name).into_owned(),
        value: clean_value(value)?,
    })
}

/// Parses a request or response head at the start of `buf`.
#[must_use]
pub fn parse_head(buf: &[u8]) -> Parse<Head> {
    let window = buf.get(..MAX_HEAD.min(buf.len())).unwrap_or(buf);
    let Some(end) = window.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() >= MAX_HEAD {
            Parse::Invalid
        } else {
            Parse::Partial
        };
    };
    // Include the final CRLF so that every line, the last one too, must end with CRLF.
    let Some(head) = window.get(..end + 2) else {
        return Parse::Invalid;
    };
    let mut lines = head
        .split_inclusive(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r\n"));
    let Some(Some(start)) = lines.next().map(|l| l.and_then(start_line)) else {
        return Parse::Invalid;
    };
    let mut headers = Vec::new();
    let mut total = 0usize;
    for line in lines {
        // Bare LF line endings and obsolete line folding are rejected.
        let Some(line) = line else {
            return Parse::Invalid;
        };
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t')
            || headers.len() >= limits::HEADERS
        {
            return Parse::Invalid;
        }
        let Some(h) = field(line) else {
            return Parse::Invalid;
        };
        total = total.saturating_add(h.name.len() + h.value.len());
        headers.push(h);
    }
    if total > limits::HEADER_BYTES {
        return Parse::Invalid;
    }
    Parse::Complete(Head {
        start,
        headers,
        len: end + 4,
    })
}

/// How the message body following a head is delimited (RFC 9112 section 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    Empty,
    /// Exactly this many bytes.
    Length(u64),
    /// Chunked transfer coding.
    Chunked,
    /// Until the connection closes.
    UntilClose,
}

/// Determines body framing. `request_method` is the method of the request a response
/// answers (`None` when `head` is a request). Conflicting `Content-Length` values are
/// treated as invalid (`None`), as are lengths combined with `Transfer-Encoding`.
#[must_use]
pub fn framing(head: &Head, request_method: Option<&str>) -> Option<Framing> {
    let status = match &head.start {
        StartLine::Response { status, .. } => Some(*status),
        StartLine::Request { .. } => None,
    };
    if request_method == Some("HEAD") || status.is_some_and(|s| s < 200 || s == 204 || s == 304) {
        return Some(Framing::Empty);
    }
    let transfer = head.header("transfer-encoding");
    let mut lengths = head
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| {
            h.value
                .parse::<u64>()
                .ok()
                .filter(|_| h.value.bytes().all(|b| b.is_ascii_digit()))
        });
    let length = match lengths.next() {
        None => None,
        Some(first) => {
            let first = first?;
            if lengths.any(|other| other != Some(first)) {
                return None;
            }
            Some(first)
        }
    };
    match (transfer, length) {
        (Some(_), Some(_)) => None,
        (Some(te), None)
            if te
                .rsplit(',')
                .next()
                .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked")) =>
        {
            Some(Framing::Chunked)
        }
        (Some(_), None) => Some(if status.is_some() {
            Framing::UntilClose
        } else {
            return None;
        }),
        (None, Some(n)) => Some(Framing::Length(n)),
        (None, None) => Some(if status.is_some() {
            Framing::UntilClose
        } else {
            Framing::Empty
        }),
    }
}
