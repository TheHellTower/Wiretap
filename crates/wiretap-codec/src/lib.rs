//! Bounded, panic-free decoders for HTTP content codings: `gzip` (RFC 1952), `deflate` (zlib,
//! RFC 1950, or raw RFC 1951), `br` (Brotli, RFC 7932) and `zstd` (Zstandard, RFC 8878), plus the
//! stateful raw-DEFLATE decoder WebSocket `permessage-deflate` needs (RFC 7692).
//!
//! Pure Rust, no dependencies, no `unsafe`. Every decoder stops at a caller-given output limit, so
//! a small "decompression bomb" cannot exhaust memory, and keeps what it decoded before an error,
//! so a truncated capture still shows its beginning.
#![forbid(unsafe_code)]

mod bits;
mod brotli;
mod huffman;
mod inflate;
mod zstd;

#[cfg(test)]
mod tests;

pub use inflate::Inflater;

/// Most `Content-Encoding` layers undone for one body; more is not real-world traffic.
const MAX_LAYERS: usize = 4;

/// Why decoding stopped early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ended before the end of the stream.
    Truncated,
    /// The input is not valid for the coding.
    Corrupt,
    /// The output would exceed the caller's limit.
    TooLarge,
    /// A coding or feature Wiretap does not decode (an unknown coding, a zstd dictionary).
    Unsupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "the body ends before the end of the compressed stream",
            Self::Corrupt => "the body is not valid for its content encoding",
            Self::TooLarge => "the decoded body exceeds the display limit",
            Self::Unsupported => "the content encoding is not supported",
        })
    }
}

impl std::error::Error for Error {}

/// A decoded body: everything decoded, and why decoding stopped early, if it did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    /// The decoded bytes (a prefix of the full body when `error` is set).
    pub bytes: Vec<u8>,
    /// Why decoding stopped before the end, if it did.
    pub error: Option<Error>,
}

/// One HTTP content coding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    /// `identity`: no transformation.
    Identity,
    /// `gzip` or `x-gzip`.
    Gzip,
    /// `deflate`: zlib framing, or raw DEFLATE as some servers send.
    Deflate,
    /// `br`.
    Brotli,
    /// `zstd`.
    Zstd,
}

impl Coding {
    /// Parses one `Content-Encoding` token (case-insensitive); `None` for unknown codings.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let token = token.trim();
        [
            ("identity", Self::Identity),
            ("gzip", Self::Gzip),
            ("x-gzip", Self::Gzip),
            ("deflate", Self::Deflate),
            ("br", Self::Brotli),
            ("zstd", Self::Zstd),
        ]
        .into_iter()
        .find(|(name, _)| token.eq_ignore_ascii_case(name))
        .map(|(_, coding)| coding)
    }

    /// Decodes `input`, producing at most `limit` bytes.
    #[must_use]
    pub fn decode(self, input: &[u8], limit: usize) -> Decoded {
        let mut bytes = Vec::new();
        let result = match self {
            Self::Identity => extend(&mut bytes, input, limit),
            Self::Gzip => inflate::gzip(input, &mut bytes, limit),
            Self::Deflate => inflate::deflate(input, &mut bytes, limit),
            Self::Brotli => brotli::decode(input, &mut bytes, limit),
            Self::Zstd => zstd::decode(input, &mut bytes, limit),
        };
        Decoded {
            bytes,
            error: result.err(),
        }
    }
}

/// Undoes a `Content-Encoding` header value such as `"gzip"` or `"deflate, br"`: codings are
/// listed in the order they were applied, so they are undone from last to first.
///
/// An unknown coding (or more than four layers) yields the body unchanged with
/// [`Error::Unsupported`]; a failure inside a layer yields what that layer decoded.
#[must_use]
pub fn decode(content_encoding: &str, body: &[u8], limit: usize) -> Decoded {
    let codings: Option<Vec<Coding>> = content_encoding
        .split(',')
        .filter(|token| !token.trim().is_empty())
        .map(Coding::parse)
        .collect();
    let Some(codings) = codings.filter(|c| c.len() <= MAX_LAYERS) else {
        return Decoded {
            bytes: body.to_vec(),
            error: Some(Error::Unsupported),
        };
    };
    let mut current = std::borrow::Cow::Borrowed(body);
    for coding in codings.iter().rev() {
        let decoded = coding.decode(&current, limit);
        if decoded.error.is_some() {
            return decoded;
        }
        current = std::borrow::Cow::Owned(decoded.bytes);
    }
    Decoded {
        bytes: current.into_owned(),
        error: None,
    }
}

/// CRC-32 (ISO 3309, as used by gzip and the RFC check values).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    #[allow(
        clippy::indexing_slicing,
        reason = "evaluated at compile time; an out-of-bounds index fails the build"
    )]
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut c0 = 0u32;
        while c0 < 256 {
            let i = c0 as usize;
            let mut c = c0;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 == 0 {
                    c >> 1
                } else {
                    0xEDB8_8320 ^ (c >> 1)
                };
                k += 1;
            }
            table[i] = c;
            c0 += 1;
        }
        table
    };
    !data.iter().fold(!0u32, |c, &b| {
        let index = usize::from(c.to_le_bytes()[0] ^ b);
        TABLE.get(index).copied().unwrap_or_default() ^ (c >> 8)
    })
}

/// Lossless on every supported (64-bit) target.
pub(crate) fn us(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Appends one byte unless the output is full.
pub(crate) fn push(out: &mut Vec<u8>, byte: u8, limit: usize) -> Result<(), Error> {
    if out.len() >= limit {
        return Err(Error::TooLarge);
    }
    out.push(byte);
    Ok(())
}

/// Appends `data`, or as much of it as fits before failing with [`Error::TooLarge`].
pub(crate) fn extend(out: &mut Vec<u8>, data: &[u8], limit: usize) -> Result<(), Error> {
    let room = limit.saturating_sub(out.len());
    if data.len() > room {
        out.extend_from_slice(data.get(..room).unwrap_or_default());
        return Err(Error::TooLarge);
    }
    out.extend_from_slice(data);
    Ok(())
}

/// Appends `len` bytes copied from `distance` bytes back; the regions may overlap (LZ77).
pub(crate) fn copy_back(
    out: &mut Vec<u8>,
    distance: usize,
    len: usize,
    limit: usize,
) -> Result<(), Error> {
    if distance == 0 {
        return Err(Error::Corrupt);
    }
    let mut from = out.len().checked_sub(distance).ok_or(Error::Corrupt)?;
    let room = limit.saturating_sub(out.len());
    let mut left = len.min(room);
    out.reserve(left);
    while left > 0 {
        // Each pass copies bytes that already exist: at most `distance` at a time.
        let n = left.min(distance);
        out.extend_from_within(from..from + n);
        from += n;
        left -= n;
    }
    if len > room {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}
