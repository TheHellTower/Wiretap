//! DEFLATE (RFC 1951) with zlib (RFC 1950) and gzip (RFC 1952) framing.

use crate::{Decoded, Error, bits::Bits, copy_back, crc32, extend, huffman::Huffman, push, us};

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Order of the code length code lengths in a dynamic block header.
const ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
/// LZ77 window: the furthest a back-reference reaches.
const WINDOW: usize = 32 << 10;

/// How a raw DEFLATE stream ended.
#[derive(Debug, PartialEq, Eq)]
enum End {
    /// A block marked final.
    Final,
    /// The input ran out exactly at a block boundary (a sync-flushed fragment).
    Input,
}

/// Inflates blocks into `out`; back-references may reach back to `out[base]`.
fn raw(bits: &mut Bits<'_>, out: &mut Vec<u8>, base: usize, limit: usize) -> Result<End, Error> {
    loop {
        if bits.is_empty() {
            return Ok(End::Input);
        }
        let last = bits.bit()?;
        match bits.take(2)? {
            0 => stored(bits, out, limit)?,
            1 => {
                let (literals, distances) = fixed()?;
                codes(bits, out, base, limit, &literals, &distances)?;
            }
            2 => {
                let (literals, distances) = dynamic(bits)?;
                codes(bits, out, base, limit, &literals, &distances)?;
            }
            _ => return Err(Error::Corrupt),
        }
        if last {
            return Ok(End::Final);
        }
    }
}

fn stored(bits: &mut Bits<'_>, out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    bits.align();
    let len = bits.take(16)?;
    if bits.take(16)? != !len & 0xFFFF {
        return Err(Error::Corrupt);
    }
    extend(out, bits.bytes(us(len))?, limit)
}

fn fixed() -> Result<(Huffman, Huffman), Error> {
    let mut lengths = [0u8; 288];
    for (symbol, len) in lengths.iter_mut().enumerate() {
        *len = match symbol {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    Ok((Huffman::new(&lengths)?.0, Huffman::new(&[5; 30])?.0))
}

fn dynamic(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), Error> {
    let literal_count = us(bits.take(5)?) + 257;
    let distance_count = us(bits.take(5)?) + 1;
    let code_count = us(bits.take(4)?) + 4;
    if literal_count > 286 || distance_count > 30 {
        return Err(Error::Corrupt);
    }
    let mut code_lengths = [0u8; 19];
    for &symbol in ORDER.iter().take(code_count) {
        *code_lengths.get_mut(symbol).ok_or(Error::Corrupt)? =
            u8::try_from(bits.take(3)?).map_err(|_| Error::Corrupt)?;
    }
    let (lengths_code, unused) = Huffman::new(&code_lengths)?;
    if unused != 0 {
        return Err(Error::Corrupt);
    }
    let total = literal_count + distance_count;
    let mut lengths = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let symbol = lengths_code.decode(bits)?;
        let (value, repeat) = match symbol {
            0..=15 => {
                *lengths.get_mut(i).ok_or(Error::Corrupt)? =
                    u8::try_from(symbol).map_err(|_| Error::Corrupt)?;
                i += 1;
                continue;
            }
            16 => {
                let previous = i
                    .checked_sub(1)
                    .and_then(|p| lengths.get(p))
                    .ok_or(Error::Corrupt)?;
                (*previous, 3 + us(bits.take(2)?))
            }
            17 => (0, 3 + us(bits.take(3)?)),
            _ => (0, 11 + us(bits.take(7)?)),
        };
        lengths
            .get_mut(i..i + repeat)
            .ok_or(Error::Corrupt)?
            .fill(value);
        i += repeat;
    }
    let (literal_lengths, distance_lengths) = lengths.split_at(literal_count);
    if literal_lengths.get(256) == Some(&0) {
        return Err(Error::Corrupt);
    }
    // An incomplete code is only valid when it has a single code of length 1 (RFC 1951 3.2.7).
    let build = |lengths: &[u8]| -> Result<Huffman, Error> {
        let (code, unused) = Huffman::new(lengths)?;
        if unused != 0 && lengths.iter().any(|&l| l > 1) {
            return Err(Error::Corrupt);
        }
        Ok(code)
    };
    Ok((build(literal_lengths)?, build(distance_lengths)?))
}

fn codes(
    bits: &mut Bits<'_>,
    out: &mut Vec<u8>,
    base: usize,
    limit: usize,
    literals: &Huffman,
    distances: &Huffman,
) -> Result<(), Error> {
    loop {
        let symbol = literals.decode(bits)?;
        if let Ok(byte) = u8::try_from(symbol) {
            push(out, byte, limit)?;
            continue;
        }
        if symbol == 256 {
            return Ok(());
        }
        let i = usize::from(symbol - 257);
        let len_base = *LENGTH_BASE.get(i).ok_or(Error::Corrupt)?;
        let len_extra = *LENGTH_EXTRA.get(i).ok_or(Error::Corrupt)?;
        let len = usize::from(len_base) + us(bits.take(u32::from(len_extra))?);
        let d = usize::from(distances.decode(bits)?);
        let dist_base = *DIST_BASE.get(d).ok_or(Error::Corrupt)?;
        let dist_extra = *DIST_EXTRA.get(d).ok_or(Error::Corrupt)?;
        let distance = usize::from(dist_base) + us(bits.take(u32::from(dist_extra))?);
        if distance > out.len() - base {
            return Err(Error::Corrupt);
        }
        copy_back(out, distance, len, limit)?;
    }
}

fn is_zlib(input: &[u8]) -> bool {
    match input {
        [cmf, flg, ..] => {
            cmf & 0x0F == 8 && cmf >> 4 <= 7 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0
        }
        _ => false,
    }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    // 5552 bytes is the most that can be summed before the modulo without overflowing u32.
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    b << 16 | a
}

fn trailer<const N: usize>(bits: &mut Bits<'_>) -> Result<[u8; N], Error> {
    bits.align();
    bits.bytes(N)?.try_into().map_err(|_| Error::Truncated)
}

/// `deflate` content: zlib framing, or raw DEFLATE (both occur in the wild).
pub(crate) fn deflate(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    let start = out.len();
    if !is_zlib(input) {
        return match raw(&mut Bits::new(input), out, start, limit)? {
            End::Final => Ok(()),
            End::Input => Err(Error::Truncated),
        };
    }
    if input.get(1).is_some_and(|flg| flg & 0x20 != 0) {
        return Err(Error::Unsupported); // preset dictionary
    }
    let mut bits = Bits::new(input.get(2..).unwrap_or_default());
    if raw(&mut bits, out, start, limit)? != End::Final {
        return Err(Error::Truncated);
    }
    let expected = u32::from_be_bytes(trailer(&mut bits)?);
    if adler32(out.get(start..).unwrap_or_default()) == expected {
        Ok(())
    } else {
        Err(Error::Corrupt)
    }
}

/// The deflate data after a gzip member header.
fn gzip_header(input: &[u8]) -> Result<&[u8], Error> {
    let [id1, id2, method, flags, ..] = *input else {
        return Err(Error::Truncated);
    };
    if id1 != 0x1F || id2 != 0x8B || method != 8 || flags & 0xE0 != 0 {
        return Err(Error::Corrupt);
    }
    let mut pos = 10;
    if flags & 0x04 != 0 {
        let len: [u8; 2] = input
            .get(pos..pos + 2)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Truncated)?;
        pos += 2 + usize::from(u16::from_le_bytes(len));
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            let rest = input.get(pos..).ok_or(Error::Truncated)?;
            pos += rest.iter().position(|&b| b == 0).ok_or(Error::Truncated)? + 1;
        }
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }
    input.get(pos..).ok_or(Error::Truncated)
}

/// `gzip` content: one or more members; bytes after the last member are ignored.
pub(crate) fn gzip(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    let mut rest = input;
    loop {
        let body = gzip_header(rest)?;
        let start = out.len();
        let mut bits = Bits::new(body);
        if raw(&mut bits, out, start, limit)? != End::Final {
            return Err(Error::Truncated);
        }
        let check: [u8; 8] = trailer(&mut bits)?;
        let member = out.get(start..).unwrap_or_default();
        let [c0, c1, c2, c3, s0, s1, s2, s3] = check;
        let size = u32::try_from(member.len() & 0xFFFF_FFFF).unwrap_or(0);
        if crc32(member) != u32::from_le_bytes([c0, c1, c2, c3])
            || size != u32::from_le_bytes([s0, s1, s2, s3])
        {
            return Err(Error::Corrupt);
        }
        rest = body.get(bits.consumed()..).unwrap_or_default();
        if !rest.starts_with(&[0x1F, 0x8B]) {
            return Ok(());
        }
    }
}

/// Raw-DEFLATE decoder for WebSocket `permessage-deflate` (RFC 7692). Each message is a
/// sync-flushed fragment whose back-references may reach into earlier messages ("context
/// takeover") unless the extension negotiated `no_context_takeover`.
#[derive(Clone, Debug, Default)]
pub struct Inflater {
    window: Vec<u8>,
}

impl Inflater {
    /// Decodes one message payload, producing at most `limit` bytes. `takeover` is false when the
    /// sender negotiated `*_no_context_takeover` (each message stands alone).
    #[must_use]
    pub fn message(&mut self, payload: &[u8], takeover: bool, limit: usize) -> Decoded {
        let mut data = Vec::with_capacity(payload.len() + 4);
        data.extend_from_slice(payload);
        data.extend_from_slice(&[0, 0, 0xFF, 0xFF]);
        let mut out = if takeover {
            std::mem::take(&mut self.window)
        } else {
            Vec::new()
        };
        let start = out.len();
        let result = raw(
            &mut Bits::new(&data),
            &mut out,
            0,
            start.saturating_add(limit),
        );
        let bytes = out.get(start..).unwrap_or_default().to_vec();
        out.drain(..out.len().saturating_sub(WINDOW));
        self.window = out;
        Decoded {
            bytes,
            error: result.err(),
        }
    }
}
