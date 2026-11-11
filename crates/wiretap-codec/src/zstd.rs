//! Zstandard (RFC 8878) decoder for frames without dictionaries (as HTTP uses it, RFC 9659).
//! Section numbers below refer to RFC 8878.

use crate::{
    Error,
    bits::{Backward, Bits},
    copy_back, extend, us,
};

const MAGIC: u32 = 0xFD2F_B528;
/// Largest block, compressed or not (section 3.1.1.2.4).
const BLOCK_MAX: usize = 128 << 10;

/// Literals length codes: baseline and extra bits (section 3.1.1.3.2.1.1).
const LITERALS_LENGTH: [(u32, u32); 36] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 1),
    (18, 1),
    (20, 1),
    (22, 1),
    (24, 2),
    (28, 2),
    (32, 3),
    (40, 3),
    (48, 4),
    (64, 6),
    (128, 7),
    (256, 8),
    (512, 9),
    (1024, 10),
    (2048, 11),
    (4096, 12),
    (8192, 13),
    (16384, 14),
    (32768, 15),
    (65536, 16),
];
/// Match length codes 32 and up (codes 0 to 31 mean lengths 3 to 34 without extra bits).
const MATCH_LENGTH: [(u32, u32); 21] = [
    (35, 1),
    (37, 1),
    (39, 1),
    (41, 1),
    (43, 2),
    (47, 2),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 5),
    (131, 7),
    (259, 8),
    (515, 9),
    (1027, 10),
    (2051, 11),
    (4099, 12),
    (8195, 13),
    (16387, 14),
    (32771, 15),
    (65539, 16),
];
/// Default distributions (section 3.1.1.3.2.2).
const LITERALS_LENGTH_DEFAULT: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const MATCH_LENGTH_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OFFSET_DEFAULT: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

pub(crate) fn decode(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    // Zero frames (an empty body) decode to nothing, as in libzstd.
    let mut rest = Cursor(input);
    while !rest.0.is_empty() {
        let magic = u32::try_from(rest.uint(4)?).map_err(|_| Error::Corrupt)?;
        if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            let size = rest.uint(4)?;
            rest.bytes(usize::try_from(size).map_err(|_| Error::Truncated)?)?;
        } else if magic == MAGIC {
            frame(&mut rest, out, limit)?;
        } else {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}

/// A byte cursor over the input.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(*self.bytes(1)?.first().ok_or(Error::Truncated)?)
    }

    /// A little-endian unsigned integer of `n` (at most 8) bytes.
    fn uint(&mut self, n: usize) -> Result<u64, Error> {
        Ok(self
            .bytes(n)?
            .iter()
            .rev()
            .fold(0, |v, &b| v << 8 | u64::from(b)))
    }
}

/// Per-frame state carried from block to block.
#[derive(Default)]
struct Frame {
    repeat: [usize; 3],
    huffman: Option<Huffman>,
    /// Literals length, offset and match length tables, for `Repeat_Mode`.
    tables: [Option<Fse>; 3],
}

/// One frame (section 3.1.1), appended to `out`.
fn frame(input: &mut Cursor<'_>, out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    let descriptor = input.u8()?;
    let single_segment = descriptor & 0x20 != 0;
    if descriptor & 0x08 != 0 {
        return Err(Error::Corrupt); // reserved bit
    }
    if !single_segment {
        input.u8()?; // Window_Descriptor: the whole frame stays in memory anyway
    }
    let dictionary = input.uint(match descriptor & 3 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    })?;
    if dictionary != 0 {
        return Err(Error::Unsupported);
    }
    let content_size = match descriptor >> 6 {
        0 if single_segment => Some(input.uint(1)?),
        0 => None,
        1 => Some(input.uint(2)? + 256),
        2 => Some(input.uint(4)?),
        _ => Some(input.uint(8)?),
    };
    let start = out.len();
    let mut state = Frame {
        repeat: [1, 4, 8],
        ..Frame::default()
    };
    loop {
        let header = input.uint(3)?;
        let size = usize::try_from(header >> 3).map_err(|_| Error::Corrupt)?;
        // libzstd enforces the block maximum on compressed blocks only; raw and RLE blocks of
        // any size are accepted (the output limit still bounds them).
        match (header >> 1) & 3 {
            0 => extend(out, input.bytes(size)?, limit)?,
            1 => {
                let byte = input.u8()?;
                let room = limit.saturating_sub(out.len());
                out.resize(out.len() + size.min(room), byte);
                if size > room {
                    return Err(Error::TooLarge);
                }
            }
            2 if size > BLOCK_MAX => return Err(Error::Corrupt),
            2 => block(input.bytes(size)?, out, start, limit, &mut state)?,
            _ => return Err(Error::Corrupt),
        }
        if header & 1 != 0 {
            break;
        }
    }
    let produced = out.get(start..).unwrap_or_default();
    if content_size.is_some_and(|size| u64::try_from(produced.len()).ok() != Some(size)) {
        return Err(Error::Corrupt);
    }
    if descriptor & 0x04 != 0 {
        let checksum = input.uint(4)?;
        if xxh64(produced) & 0xFFFF_FFFF != checksum {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}

/// A compressed block (section 3.1.1.3).
fn block(
    data: &[u8],
    out: &mut Vec<u8>,
    start: usize,
    limit: usize,
    state: &mut Frame,
) -> Result<(), Error> {
    let mut input = Cursor(data);
    let literals = literals(&mut input, &mut state.huffman)?;
    sequences(input.0, &literals, out, start, limit, state)
}

/// The literals section (section 3.1.1.3.1).
fn literals(input: &mut Cursor<'_>, huffman: &mut Option<Huffman>) -> Result<Vec<u8>, Error> {
    let first = *input.0.first().ok_or(Error::Corrupt)?;
    let kind = first & 3;
    let format = (first >> 2) & 3;
    if kind < 2 {
        let header = match format {
            0 | 2 => 1,
            1 => 2,
            _ => 3,
        };
        let value = input.uint(header)?;
        let size = usize::try_from(value >> if header == 1 { 3 } else { 4 })
            .map_err(|_| Error::Corrupt)?;
        if size > BLOCK_MAX {
            return Err(Error::Corrupt);
        }
        return if kind == 0 {
            Ok(input.bytes(size)?.to_vec())
        } else {
            Ok(vec![input.u8()?; size])
        };
    }
    let (header, size_bits, four_streams) = match format {
        0 => (3, 10, false),
        1 => (3, 10, true),
        2 => (4, 14, true),
        _ => (5, 18, true),
    };
    let value = input.uint(header)?;
    let mask = (1u64 << size_bits) - 1;
    let regenerated = usize::try_from((value >> 4) & mask).map_err(|_| Error::Corrupt)?;
    let compressed =
        usize::try_from((value >> (4 + size_bits)) & mask).map_err(|_| Error::Corrupt)?;
    if regenerated > BLOCK_MAX {
        return Err(Error::Corrupt);
    }
    let mut body = input.bytes(compressed)?;
    if kind == 2 {
        let (table, used) = Huffman::read(body)?;
        *huffman = Some(table);
        body = body.get(used..).ok_or(Error::Corrupt)?;
    }
    let table = huffman.as_ref().ok_or(Error::Corrupt)?;
    let mut decoded = Vec::with_capacity(regenerated);
    if !four_streams {
        table.stream(body, regenerated, &mut decoded)?;
        return Ok(decoded);
    }
    let (jump, streams) = body.split_at_checked(6).ok_or(Error::Corrupt)?;
    if body.len() < 10 {
        return Err(Error::Corrupt);
    }
    let size = |i: usize| {
        usize::from(u16::from_le_bytes([
            jump.get(i).copied().unwrap_or(0),
            jump.get(i + 1).copied().unwrap_or(0),
        ]))
    };
    let segment = regenerated.div_ceil(4);
    let last = regenerated.checked_sub(3 * segment).ok_or(Error::Corrupt)?;
    let mut rest = streams;
    for (len, count) in [
        (Some(size(0)), segment),
        (Some(size(2)), segment),
        (Some(size(4)), segment),
        (None, last),
    ] {
        let (stream, tail) = rest
            .split_at_checked(len.unwrap_or(rest.len()))
            .ok_or(Error::Corrupt)?;
        table.stream(stream, count, &mut decoded)?;
        rest = tail;
    }
    Ok(decoded)
}

/// A literals Huffman table (section 4.2.1): `(symbol, bits)` per `max_bits`-bit index.
struct Huffman {
    max_bits: u32,
    table: Vec<(u8, u32)>,
}

impl Huffman {
    /// Reads a tree description; returns the table and the bytes it used.
    fn read(data: &[u8]) -> Result<(Self, usize), Error> {
        let header = usize::from(*data.first().ok_or(Error::Corrupt)?);
        if header < 128 {
            let region = data.get(1..=header).ok_or(Error::Corrupt)?;
            return Ok((Self::from_weights(fse_weights(region)?)?, 1 + header));
        }
        let count = header - 127;
        let region = data.get(1..1 + count.div_ceil(2)).ok_or(Error::Corrupt)?;
        let weights = (0..count)
            .map(|i| {
                let byte = region.get(i / 2).copied().unwrap_or(0);
                if i % 2 == 0 { byte >> 4 } else { byte & 15 }
            })
            .collect();
        Ok((Self::from_weights(weights)?, 1 + region.len()))
    }

    fn from_weights(mut weights: Vec<u8>) -> Result<Self, Error> {
        if weights.len() > 255 {
            return Err(Error::Corrupt);
        }
        let mut total = 0u32;
        for &weight in &weights {
            if weight > 12 {
                return Err(Error::Corrupt);
            }
            if weight > 0 {
                total += 1 << (weight - 1);
            }
        }
        if total == 0 {
            return Err(Error::Corrupt);
        }
        let max_bits = u32::BITS - total.leading_zeros();
        if max_bits > 12 {
            return Err(Error::Corrupt);
        }
        let rest = (1 << max_bits) - total;
        if !rest.is_power_of_two() {
            return Err(Error::Corrupt);
        }
        weights.push(u8::try_from(rest.trailing_zeros() + 1).map_err(|_| Error::Corrupt)?);
        let ones = weights.iter().filter(|&&w| w == 1).count();
        if ones < 2 || ones % 2 == 1 {
            return Err(Error::Corrupt);
        }
        // Lowest weight first, symbols in order within a weight (section 4.2.1.3).
        let mut table = vec![(0u8, 0u32); 1 << max_bits];
        let mut next = [0usize; 13];
        let mut position = 0;
        for weight in 1..=max_bits {
            let count = weights.iter().filter(|&&w| u32::from(w) == weight).count();
            *next.get_mut(us(weight)).ok_or(Error::Corrupt)? = position;
            position += count << (weight - 1);
        }
        for (symbol, &weight) in weights.iter().enumerate() {
            if weight == 0 {
                continue;
            }
            let slot = next.get_mut(usize::from(weight)).ok_or(Error::Corrupt)?;
            let len = 1usize << (weight - 1);
            let entry = (
                u8::try_from(symbol).map_err(|_| Error::Corrupt)?,
                max_bits + 1 - u32::from(weight),
            );
            table
                .get_mut(*slot..*slot + len)
                .ok_or(Error::Corrupt)?
                .fill(entry);
            *slot += len;
        }
        Ok(Self { max_bits, table })
    }

    /// Decodes `count` literals from one backward stream, which must be consumed exactly.
    fn stream(&self, data: &[u8], count: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut bits = Backward::new(data)?;
        for _ in 0..count {
            let (symbol, len) = *self
                .table
                .get(us(bits.peek(self.max_bits)))
                .ok_or(Error::Corrupt)?;
            bits.consume(len);
            out.push(symbol);
        }
        if bits.finished() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
}

/// Huffman weights compressed with FSE (section 4.2.1.2).
fn fse_weights(region: &[u8]) -> Result<Vec<u8>, Error> {
    let mut header = Bits::new(region);
    // Symbols up to 255 may be described (as libzstd accepts); weights above 12 are rejected
    // when the table is built.
    let table = Fse::read(&mut header, 255, 6)?;
    let mut bits = Backward::new(region.get(header.consumed()..).unwrap_or_default())?;
    let mut states = [bits.read(table.log), bits.read(table.log)];
    let mut weights = Vec::new();
    for i in (0..2).cycle() {
        let state = states.get_mut(i).ok_or(Error::Corrupt)?;
        let (symbol, len, base) = table.entry(*state)?;
        weights.push(symbol);
        *state = base + bits.read(len);
        if bits.overflowed() {
            let other = *states.get(1 - i).ok_or(Error::Corrupt)?;
            weights.push(table.entry(other)?.0);
            break;
        }
        if weights.len() > 255 {
            return Err(Error::Corrupt);
        }
    }
    Ok(weights)
}

/// An FSE decoding table (section 4.1): `(symbol, bits, baseline)` per state.
#[derive(Clone)]
struct Fse {
    log: u32,
    table: Vec<(u8, u32, u32)>,
}

impl Fse {
    /// Reads a distribution (section 4.1.1) with symbols up to `max_symbol`.
    fn read(bits: &mut Bits<'_>, max_symbol: usize, max_log: u32) -> Result<Self, Error> {
        let log = bits.take(4)? + 5;
        if log > max_log {
            return Err(Error::Corrupt);
        }
        let mut remaining = (1i32 << log) + 1;
        let mut threshold = 1i32 << log;
        let mut width = log + 1;
        let mut counts: Vec<i16> = Vec::new();
        let mut zero = false;
        while remaining > 1 {
            if zero {
                loop {
                    let run = bits.take(2)?;
                    counts.extend(std::iter::repeat_n(0, us(run)));
                    if run != 3 {
                        break;
                    }
                }
            }
            if counts.len() > max_symbol {
                return Err(Error::Corrupt);
            }
            let max = 2 * threshold - 1 - remaining;
            let small = i32::try_from(bits.peek(width - 1)).map_err(|_| Error::Corrupt)?;
            let value = if small < max {
                bits.skip(width - 1)?;
                small
            } else {
                let full = i32::try_from(bits.peek(width)).map_err(|_| Error::Corrupt)?;
                bits.skip(width)?;
                if full >= threshold { full - max } else { full }
            };
            let probability = value - 1;
            remaining -= probability.abs();
            counts.push(i16::try_from(probability).map_err(|_| Error::Corrupt)?);
            zero = probability == 0;
            while remaining < threshold {
                width -= 1;
                threshold >>= 1;
            }
        }
        if remaining != 1 || counts.len() > max_symbol + 1 {
            return Err(Error::Corrupt);
        }
        Self::new(&counts, log)
    }

    /// Builds the decoding table for normalized `counts` (section 4.1.1).
    fn new(counts: &[i16], log: u32) -> Result<Self, Error> {
        let size = 1usize << log;
        let mut symbols = vec![0u8; size];
        let mut next = vec![0u32; counts.len()];
        let mut high = size;
        for (symbol, &count) in counts.iter().enumerate() {
            let symbol_byte = u8::try_from(symbol).map_err(|_| Error::Corrupt)?;
            let slot = next.get_mut(symbol).ok_or(Error::Corrupt)?;
            if count == -1 {
                high = high.checked_sub(1).ok_or(Error::Corrupt)?;
                *symbols.get_mut(high).ok_or(Error::Corrupt)? = symbol_byte;
                *slot = 1;
            } else {
                *slot = u32::try_from(count).map_err(|_| Error::Corrupt)?;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut position = 0;
        for (symbol, &count) in counts.iter().enumerate() {
            for _ in 0..count.max(0) {
                *symbols.get_mut(position).ok_or(Error::Corrupt)? =
                    u8::try_from(symbol).map_err(|_| Error::Corrupt)?;
                loop {
                    position = (position + step) & mask;
                    if position < high {
                        break;
                    }
                }
            }
        }
        if position != 0 {
            return Err(Error::Corrupt);
        }
        let mut table = Vec::with_capacity(size);
        for &symbol in &symbols {
            let state = next.get_mut(usize::from(symbol)).ok_or(Error::Corrupt)?;
            let current = *state;
            *state += 1;
            if current == 0 {
                return Err(Error::Corrupt);
            }
            let len = log
                .checked_sub(u32::BITS - 1 - current.leading_zeros())
                .ok_or(Error::Corrupt)?;
            let base = (current << len)
                .checked_sub(u32::try_from(size).map_err(|_| Error::Corrupt)?)
                .ok_or(Error::Corrupt)?;
            table.push((symbol, len, base));
        }
        Ok(Self { log, table })
    }

    /// A table that always decodes `symbol` (`RLE_Mode`).
    fn rle(symbol: u8) -> Self {
        Self {
            log: 0,
            table: vec![(symbol, 0, 0)],
        }
    }

    fn entry(&self, state: u32) -> Result<(u8, u32, u32), Error> {
        self.table.get(us(state)).copied().ok_or(Error::Corrupt)
    }
}

/// The three sequence symbol types.
#[derive(Clone, Copy)]
enum Kind {
    LiteralsLength,
    Offset,
    MatchLength,
}

impl Kind {
    const fn max_symbol(self) -> usize {
        match self {
            Self::LiteralsLength => 35,
            Self::Offset => 31,
            Self::MatchLength => 52,
        }
    }

    const fn max_log(self) -> u32 {
        match self {
            Self::Offset => 8,
            _ => 9,
        }
    }

    fn predefined(self) -> Result<Fse, Error> {
        match self {
            Self::LiteralsLength => Fse::new(&LITERALS_LENGTH_DEFAULT, 6),
            Self::Offset => Fse::new(&OFFSET_DEFAULT, 5),
            Self::MatchLength => Fse::new(&MATCH_LENGTH_DEFAULT, 6),
        }
    }
}

/// Reads the table for `kind` in `mode` and stores it in `slot` for later `Repeat_Mode`.
fn table<'s>(
    input: &mut Cursor<'_>,
    mode: u8,
    kind: Kind,
    slot: &'s mut Option<Fse>,
) -> Result<&'s Fse, Error> {
    match mode {
        0 => *slot = Some(kind.predefined()?),
        1 => {
            let symbol = input.u8()?;
            if usize::from(symbol) > kind.max_symbol() {
                return Err(Error::Corrupt);
            }
            *slot = Some(Fse::rle(symbol));
        }
        2 => {
            let mut bits = Bits::new(input.0);
            *slot = Some(Fse::read(&mut bits, kind.max_symbol(), kind.max_log())?);
            input.bytes(bits.consumed())?;
        }
        _ => {}
    }
    slot.as_ref().ok_or(Error::Corrupt)
}

/// The sequences section (section 3.1.1.3.2) and its execution (section 3.1.1.4).
fn sequences(
    data: &[u8],
    literals: &[u8],
    out: &mut Vec<u8>,
    start: usize,
    limit: usize,
    state: &mut Frame,
) -> Result<(), Error> {
    let mut input = Cursor(data);
    let first = usize::from(input.u8().map_err(|_| Error::Corrupt)?);
    let count = match first {
        0..128 => first,
        128..255 => ((first - 128) << 8) + usize::from(input.u8()?),
        _ => usize::try_from(input.uint(2)?).map_err(|_| Error::Corrupt)? + 0x7F00,
    };
    if count == 0 {
        // No sequences (in any of the three size forms): the block is its literals.
        if !input.0.is_empty() {
            return Err(Error::Corrupt);
        }
        return extend(out, literals, limit);
    }
    let modes = input.u8()?;
    if modes & 3 != 0 {
        return Err(Error::Corrupt);
    }
    let [ll_slot, of_slot, ml_slot] = &mut state.tables;
    let ll = table(&mut input, modes >> 6, Kind::LiteralsLength, ll_slot)?;
    let of = table(&mut input, (modes >> 4) & 3, Kind::Offset, of_slot)?;
    let ml = table(&mut input, (modes >> 2) & 3, Kind::MatchLength, ml_slot)?;
    let mut bits = Backward::new(input.0)?;
    let mut ll_state = bits.read(ll.log);
    let mut of_state = bits.read(of.log);
    let mut ml_state = bits.read(ml.log);
    let mut used = 0usize;
    for i in 0..count {
        let (ll_code, ll_len, ll_base) = ll.entry(ll_state)?;
        let (of_code, of_len, of_base) = of.entry(of_state)?;
        let (ml_code, ml_len, ml_base) = ml.entry(ml_state)?;
        if of_code > 31 {
            return Err(Error::Corrupt);
        }
        let offset_value = (1u64 << of_code) + u64::from(bits.read(u32::from(of_code)));
        let match_length = match ml_code {
            0..32 => u32::from(ml_code) + 3,
            _ => {
                let (base, extra) = *MATCH_LENGTH
                    .get(usize::from(ml_code) - 32)
                    .ok_or(Error::Corrupt)?;
                base + bits.read(extra)
            }
        };
        let (base, extra) = *LITERALS_LENGTH
            .get(usize::from(ll_code))
            .ok_or(Error::Corrupt)?;
        let literals_length = us(base + bits.read(extra));
        let offset = resolve(offset_value, literals_length, &mut state.repeat)?;
        let run = literals
            .get(used..used + literals_length)
            .ok_or(Error::Corrupt)?;
        extend(out, run, limit)?;
        used += literals_length;
        if offset > out.len() - start {
            return Err(Error::Corrupt);
        }
        copy_back(out, offset, us(match_length), limit)?;
        if i + 1 < count {
            ll_state = ll_base + bits.read(ll_len);
            ml_state = ml_base + bits.read(ml_len);
            of_state = of_base + bits.read(of_len);
        }
    }
    if !bits.finished() {
        return Err(Error::Corrupt);
    }
    extend(out, literals.get(used..).unwrap_or_default(), limit)
}

/// The offset for an `Offset_Value`, updating the repeat offsets (section 3.1.1.5).
fn resolve(value: u64, literals_length: usize, repeat: &mut [usize; 3]) -> Result<usize, Error> {
    let [r1, r2, r3] = *repeat;
    if value > 3 {
        let offset = usize::try_from(value - 3).map_err(|_| Error::Corrupt)?;
        *repeat = [offset, r1, r2];
        return Ok(offset);
    }
    let index =
        usize::try_from(value).map_err(|_| Error::Corrupt)? - 1 + usize::from(literals_length == 0);
    let offset = match index {
        0 => return Ok(r1),
        1 => r2,
        2 => r3,
        _ => r1.saturating_sub(1),
    };
    if offset == 0 {
        return Err(Error::Corrupt);
    }
    *repeat = if index == 1 {
        [offset, r1, r3]
    } else {
        [offset, r1, r2]
    };
    Ok(offset)
}

/// XXH64 with seed 0; the frame checksum is its low 32 bits.
pub(crate) fn xxh64(data: &[u8]) -> u64 {
    const P1: u64 = 0x9E37_79B1_85EB_CA87;
    const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const P3: u64 = 0x1656_67B1_9E37_79F9;
    const P4: u64 = 0x85EB_CA77_C2B2_AE63;
    const P5: u64 = 0x27D4_EB2F_1656_67C5;
    let round = |acc: u64, lane: u64| {
        acc.wrapping_add(lane.wrapping_mul(P2))
            .rotate_left(31)
            .wrapping_mul(P1)
    };
    let (stripes, tail) = data.as_chunks::<32>();
    let mut hash = if stripes.is_empty() {
        P5
    } else {
        let mut v = [P1.wrapping_add(P2), P2, 0, 0u64.wrapping_sub(P1)];
        for stripe in stripes {
            for (acc, lane) in v.iter_mut().zip(stripe.as_chunks::<8>().0) {
                *acc = round(*acc, u64::from_le_bytes(*lane));
            }
        }
        let [v1, v2, v3, v4] = v;
        let mut h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        for acc in v {
            h = (h ^ round(0, acc)).wrapping_mul(P1).wrapping_add(P4);
        }
        h
    };
    hash = hash.wrapping_add(u64::try_from(data.len()).unwrap_or(0));
    let (words, mut rest) = tail.as_chunks::<8>();
    for word in words {
        hash = (hash ^ round(0, u64::from_le_bytes(*word)))
            .rotate_left(27)
            .wrapping_mul(P1)
            .wrapping_add(P4);
    }
    if let Some((half, tail)) = rest.split_first_chunk::<4>() {
        hash = (hash ^ u64::from(u32::from_le_bytes(*half)).wrapping_mul(P1))
            .rotate_left(23)
            .wrapping_mul(P2)
            .wrapping_add(P3);
        rest = tail;
    }
    for &byte in rest {
        hash = (hash ^ u64::from(byte).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(P2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(P3);
    hash ^ (hash >> 32)
}
