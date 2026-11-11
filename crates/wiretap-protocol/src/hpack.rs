//! HPACK header decompression (RFC 7541). Decoder only: Wiretap observes HTTP/2 connections and
//! never re-encodes them. Bounded: field counts and bytes, string lengths, the dynamic table.

use std::collections::VecDeque;

/// One header field (name, value). Bytes that are not UTF-8 are shown lossily.
pub type Field = (String, String);

/// The static table (RFC 7541 Appendix A), generated from the RFC text.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Huffman code length of each symbol 0..=256 (256 is EOS), from RFC 7541 Appendix B. The code
/// is canonical (checked when the table was generated from the RFC text), so the lengths define
/// it: shorter codes first, and within a length, codes count up in symbol order.
const LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, //
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, //
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, //
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, //
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, //
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, //
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, //
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, //
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, //
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, //
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, //
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, //
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, //
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, //
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, //
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, //
    30,
];

const LONGEST: usize = 30;
const EOS: u16 = 256;

/// The canonical code, by length: the first code of each length, where its symbols start in
/// `symbols`, and how many there are.
struct Canonical {
    first: [u32; LONGEST + 1],
    start: [u16; LONGEST + 1],
    count: [u16; LONGEST + 1],
    symbols: [u16; 257],
}

#[allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "compile-time only: an out-of-range index fails the build; symbols are below 257"
)]
const fn canonical() -> Canonical {
    let mut c = Canonical {
        first: [0; LONGEST + 1],
        start: [0; LONGEST + 1],
        count: [0; LONGEST + 1],
        symbols: [0; 257],
    };
    let mut s = 0;
    while s < 257 {
        c.count[LENGTHS[s] as usize] += 1;
        s += 1;
    }
    let (mut code, mut next, mut len) = (0u32, 0u16, 1);
    while len <= LONGEST {
        c.first[len] = code;
        c.start[len] = next;
        code = (code + c.count[len] as u32) << 1;
        next += c.count[len];
        len += 1;
    }
    let mut filled = [0u16; LONGEST + 1];
    s = 0;
    while s < 257 {
        let len = LENGTHS[s] as usize;
        c.symbols[(c.start[len] + filled[len]) as usize] = s as u16;
        filled[len] += 1;
        s += 1;
    }
    c
}

static CODE: Canonical = canonical();

/// Decodes a Huffman-coded string (RFC 7541 5.2): padding must be under 8 bits of the EOS
/// prefix (all ones), and EOS itself must not appear.
fn huffman(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(raw.len().saturating_mul(8) / 5);
    let (mut code, mut len) = (0u32, 0usize);
    for byte in raw {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            let (Some(&first), Some(&count), Some(&start)) = (
                CODE.first.get(len),
                CODE.count.get(len),
                CODE.start.get(len),
            ) else {
                return Err("invalid Huffman code");
            };
            let offset = code.wrapping_sub(first);
            if code >= first && offset < u32::from(count) {
                let index = usize::from(start) + usize::try_from(offset).unwrap_or(usize::MAX);
                match CODE.symbols.get(index) {
                    Some(&EOS) | None => return Err("EOS in a Huffman string"),
                    Some(&symbol) => out.push(u8::try_from(symbol).unwrap_or(0)),
                }
                (code, len) = (0, 0);
            }
        }
    }
    let ones = (1u32 << len) - 1;
    if len >= 8 || code != ones {
        return Err("invalid Huffman padding");
    }
    Ok(out)
}

/// An integer with an `n`-bit prefix (RFC 7541 5.1), at most 2^28 + prefix.
fn integer(input: &mut &[u8], n: u32) -> Result<usize, &'static str> {
    let (&first, rest) = input.split_first().ok_or("truncated integer")?;
    *input = rest;
    let max = (1usize << n) - 1;
    let mut value = usize::from(first) & max;
    if value < max {
        return Ok(value);
    }
    for shift in (0..=28).step_by(7) {
        let (&byte, rest) = input.split_first().ok_or("truncated integer")?;
        *input = rest;
        value = value.saturating_add(usize::from(byte & 0x7F) << shift);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("integer too large")
}

/// A string literal (RFC 7541 5.2).
fn string(input: &mut &[u8]) -> Result<String, &'static str> {
    let huffman_coded = input.first().is_some_and(|b| b & 0x80 != 0);
    let len = integer(input, 7)?;
    if len > input.len() {
        return Err("truncated string");
    }
    let (raw, rest) = input.split_at(len);
    *input = rest;
    let bytes = if huffman_coded {
        huffman(raw)?
    } else {
        raw.to_vec()
    };
    Ok(String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// Encodes fields as literals without indexing (RFC 7541 6.2.2), without Huffman coding: valid
/// for any decoder state and changing none, so Wiretap can add blocks to a connection freely.
#[must_use]
pub fn encode(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in fields {
        out.push(0);
        for s in [name, value] {
            put_integer(&mut out, 7, s.len());
            out.extend_from_slice(s.as_bytes());
        }
    }
    out
}

/// An integer with an `n`-bit prefix (RFC 7541 5.1), the prefix's other bits zero.
fn put_integer(out: &mut Vec<u8>, n: u32, mut value: usize) {
    let max = (1usize << n) - 1;
    if value < max {
        out.push(u8::try_from(value).unwrap_or(0));
        return;
    }
    out.push(u8::try_from(max).unwrap_or(0));
    value -= max;
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7F).unwrap_or(0) | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap_or(0));
}

/// The decompression context of one direction of an HTTP/2 connection.
#[derive(Debug)]
pub struct Decoder {
    /// Newest entry first.
    table: VecDeque<Field>,
    size: usize,
    max: usize,
    limit: usize,
}

/// Size of a table entry (RFC 7541 4.1).
fn entry_size((name, value): &Field) -> usize {
    name.len().saturating_add(value.len()).saturating_add(32)
}

impl Decoder {
    /// A decoder whose dynamic table starts at the default 4096 bytes and may be resized up to
    /// `limit` by the encoder.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            table: VecDeque::new(),
            size: 0,
            max: 4096.min(limit),
            limit,
        }
    }

    /// Bytes in the dynamic table (RFC 7541 4.1).
    #[cfg(test)]
    pub(crate) const fn table_size(&self) -> usize {
        self.size
    }

    fn evict(&mut self) {
        while self.size > self.max {
            let Some(old) = self.table.pop_back() else {
                break;
            };
            self.size = self.size.saturating_sub(entry_size(&old));
        }
    }

    fn insert(&mut self, field: Field) {
        let size = entry_size(&field);
        if size > self.max {
            self.table.clear(); // RFC 7541 4.4: an entry larger than the table empties it
            self.size = 0;
            return;
        }
        self.size = self.size.saturating_add(size);
        self.table.push_front(field);
        self.evict();
    }

    fn get(&self, index: usize) -> Result<Field, &'static str> {
        let field = match index {
            0 => None,
            1..=61 => STATIC
                .get(index - 1)
                .map(|&(n, v)| (n.to_owned(), v.to_owned())),
            _ => self.table.get(index - 62).cloned(),
        };
        field.ok_or("invalid table index")
    }

    /// Decodes one header block into its fields, keeping at most `max_fields` of them and
    /// `max_bytes` of names and values (the rest is still decoded, so the table stays right).
    ///
    /// # Errors
    /// Malformed block. The compression context is then lost: stop decoding this direction.
    pub fn decode(
        &mut self,
        mut block: &[u8],
        max_fields: usize,
        max_bytes: usize,
    ) -> Result<Vec<Field>, &'static str> {
        let (mut fields, mut bytes) = (Vec::new(), 0usize);
        while let Some(&first) = block.first() {
            let field = if first & 0x80 != 0 {
                self.get(integer(&mut block, 7)?)?
            } else if first & 0x20 != 0 && first & 0x40 == 0 {
                let max = integer(&mut block, 5)?;
                if max > self.limit {
                    return Err("dynamic table size above the limit");
                }
                self.max = max;
                self.evict();
                continue;
            } else {
                let indexed = first & 0x40 != 0;
                let index = integer(&mut block, if indexed { 6 } else { 4 })?;
                let name = if index == 0 {
                    string(&mut block)?
                } else {
                    self.get(index)?.0
                };
                let field = (name, string(&mut block)?);
                if indexed {
                    self.insert(field.clone());
                }
                field
            };
            let size = field.0.len().saturating_add(field.1.len());
            if fields.len() < max_fields && bytes.saturating_add(size) <= max_bytes {
                bytes = bytes.saturating_add(size);
                fields.push(field);
            }
        }
        Ok(fields)
    }
}
