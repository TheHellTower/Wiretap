//! Brotli (RFC 7932) decoder. Section numbers below refer to the RFC.

pub(crate) mod tables;

use crate::{Error, bits::Bits, copy_back, extend, huffman::Huffman, push, us};
use tables::{LUT0, LUT1, LUT2, TRANSFORMS};

/// The static dictionary (appendix A); `tests.rs` checks its CRC-32 against the RFC.
pub(crate) static DICTIONARY: &[u8] = include_bytes!("brotli/dictionary.bin");

/// Bits of the word index per word length (section 8).
const NDBITS: [u32; 25] = [
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5,
];
/// Offset of the words of each length in the dictionary (section 8).
pub(crate) const DOFFSET: [usize; 25] = [
    0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864,
    104704, 106752, 108928, 113536, 115968, 118528, 119872, 121280, 122016,
];
/// Insert length codes: base and extra bits (section 5).
const INSERT: [(usize, u32); 24] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 1),
    (8, 1),
    (10, 2),
    (14, 2),
    (18, 3),
    (26, 3),
    (34, 4),
    (50, 4),
    (66, 5),
    (98, 5),
    (130, 6),
    (194, 7),
    (322, 8),
    (578, 9),
    (1090, 10),
    (2114, 12),
    (6210, 14),
    (22594, 24),
];
/// Copy length codes: base and extra bits (section 5).
const COPY: [(usize, u32); 24] = [
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 1),
    (12, 1),
    (14, 2),
    (18, 2),
    (22, 3),
    (30, 3),
    (38, 4),
    (54, 4),
    (70, 5),
    (102, 5),
    (134, 6),
    (198, 7),
    (326, 8),
    (582, 9),
    (1094, 10),
    (2118, 24),
];
/// Insert-and-copy symbol cells of 64: insert code base, copy code base, implicit distance 0.
const CELLS: [(usize, usize, bool); 11] = [
    (0, 0, true),
    (0, 8, true),
    (0, 0, false),
    (0, 8, false),
    (8, 0, false),
    (8, 8, false),
    (0, 16, false),
    (16, 0, false),
    (8, 16, false),
    (16, 8, false),
    (16, 16, false),
];
/// Block count codes: base and extra bits (section 6).
const BLOCK_COUNT: [(usize, u32); 26] = [
    (1, 2),
    (5, 2),
    (9, 2),
    (13, 2),
    (17, 3),
    (25, 3),
    (33, 3),
    (41, 3),
    (49, 4),
    (65, 4),
    (81, 4),
    (97, 4),
    (113, 5),
    (145, 5),
    (177, 5),
    (209, 5),
    (241, 6),
    (305, 6),
    (369, 7),
    (497, 8),
    (753, 9),
    (1265, 10),
    (2289, 11),
    (4337, 12),
    (8433, 13),
    (16625, 24),
];
/// Order in which code length code lengths are stored (section 3.5).
const CODE_LENGTH_ORDER: [usize; 18] =
    [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// The fixed code for code length code lengths, indexed by the next 4 bits: (length, value).
const CODE_LENGTH_CODE: [(u32, u8); 16] = [
    (2, 0),
    (2, 4),
    (2, 3),
    (3, 2),
    (2, 0),
    (2, 4),
    (2, 3),
    (4, 1),
    (2, 0),
    (2, 4),
    (2, 3),
    (3, 2),
    (2, 0),
    (2, 4),
    (2, 3),
    (4, 5),
];
/// Block count when a category has a single block type.
const ONE_BLOCK: usize = 1 << 24;

pub(crate) fn decode(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    let start = out.len();
    let mut bits = Bits::new(input);
    let window = (1usize << window_bits(&mut bits)?) - 16;
    let mut distances = [4, 11, 15, 16];
    loop {
        let last = bits.bit()?;
        if last && bits.bit()? {
            break; // ISLASTEMPTY
        }
        let nibbles = match bits.take(2)? {
            3 => 0,
            n => n + 4,
        };
        if nibbles == 0 {
            // Metadata: skipped.
            if bits.bit()? {
                return Err(Error::Corrupt);
            }
            let skip_bytes = bits.take(2)?;
            let mut skip = 0;
            for i in 0..skip_bytes {
                let byte = bits.take(8)?;
                if i + 1 == skip_bytes && skip_bytes > 1 && byte == 0 {
                    return Err(Error::Corrupt);
                }
                skip |= us(byte) << (8 * i);
            }
            if skip_bytes > 0 {
                skip += 1;
            }
            if bits.align() != 0 {
                return Err(Error::Corrupt);
            }
            bits.bytes(skip)?;
            if last {
                break;
            }
            continue;
        }
        let mut len = 0;
        for i in 0..nibbles {
            let nibble = bits.take(4)?;
            if i + 1 == nibbles && nibbles > 4 && nibble == 0 {
                return Err(Error::Corrupt);
            }
            len |= us(nibble) << (4 * i);
        }
        len += 1;
        if !last && bits.bit()? {
            // Uncompressed meta-block.
            if bits.align() != 0 {
                return Err(Error::Corrupt);
            }
            extend(out, bits.bytes(len)?, limit)?;
            continue;
        }
        let meta = MetaBlock {
            start,
            end: out.len() + len,
            window,
            limit,
        };
        meta.decode(&mut bits, out, &mut distances)?;
        if last {
            break;
        }
    }
    if bits.align() == 0 {
        Ok(())
    } else {
        Err(Error::Corrupt)
    }
}

/// WBITS (section 9.1): 10 to 24.
fn window_bits(bits: &mut Bits<'_>) -> Result<u32, Error> {
    if !bits.bit()? {
        return Ok(16);
    }
    let n = bits.take(3)?;
    if n != 0 {
        return Ok(17 + n);
    }
    match bits.take(3)? {
        0 => Ok(17),
        1 => Err(Error::Unsupported), // large-window Brotli, not used by HTTP
        n => Ok(8 + n),
    }
}

/// A value from 0 to 255 in the variable-length code of section 9.2.
fn var_u8(bits: &mut Bits<'_>) -> Result<usize, Error> {
    if !bits.bit()? {
        return Ok(0);
    }
    match bits.take(3)? {
        0 => Ok(1),
        n => Ok(us(bits.take(n)?) + (1 << n)),
    }
}

/// A prefix code over `alphabet` symbols (sections 3.4 and 3.5).
fn prefix_code(bits: &mut Bits<'_>, alphabet: usize) -> Result<Huffman, Error> {
    let skip = bits.take(2)?;
    if skip == 1 {
        return simple_code(bits, alphabet);
    }
    let mut code_lengths = [0u8; 18];
    let (mut space, mut codes) = (32i32, 0);
    for &symbol in CODE_LENGTH_ORDER.iter().skip(us(skip)) {
        let (len, value) = *CODE_LENGTH_CODE
            .get(us(bits.peek(4)))
            .ok_or(Error::Corrupt)?;
        bits.skip(len)?;
        *code_lengths.get_mut(symbol).ok_or(Error::Corrupt)? = value;
        if value != 0 {
            space -= 32 >> value;
            codes += 1;
            if space <= 0 {
                break;
            }
        }
    }
    if codes != 1 && space != 0 {
        return Err(Error::Corrupt);
    }
    let lengths_code = if codes == 1 {
        let symbol = code_lengths
            .iter()
            .position(|&l| l != 0)
            .ok_or(Error::Corrupt)?;
        Huffman::single(u16::try_from(symbol).map_err(|_| Error::Corrupt)?)
    } else {
        Huffman::new(&code_lengths)?.0
    };
    let mut lengths = vec![0u8; alphabet];
    let (mut symbol, mut previous, mut repeat, mut repeat_len) = (0usize, 8u8, 0usize, 0u8);
    let mut space = 32768i64;
    while symbol < alphabet && space > 0 {
        let code = lengths_code.decode(bits)?;
        if code < 16 {
            let len = u8::try_from(code).map_err(|_| Error::Corrupt)?;
            repeat = 0;
            *lengths.get_mut(symbol).ok_or(Error::Corrupt)? = len;
            if len != 0 {
                previous = len;
                space -= 32768 >> len;
            }
            symbol += 1;
            continue;
        }
        let (extra, new_len) = if code == 16 { (2, previous) } else { (3, 0) };
        if repeat_len != new_len {
            repeat = 0;
            repeat_len = new_len;
        }
        let old = repeat;
        if repeat > 0 {
            repeat = (repeat - 2) << extra;
        }
        repeat += us(bits.take(extra)?) + 3;
        let delta = repeat - old;
        lengths
            .get_mut(symbol..symbol + delta)
            .ok_or(Error::Corrupt)?
            .fill(repeat_len);
        symbol += delta;
        if repeat_len != 0 {
            let delta = i64::try_from(delta).map_err(|_| Error::Corrupt)?;
            space -= delta << (15 - repeat_len);
        }
    }
    if space != 0 {
        return Err(Error::Corrupt);
    }
    Ok(Huffman::new(&lengths)?.0)
}

/// A simple prefix code: one to four listed symbols with fixed code lengths (section 3.4).
fn simple_code(bits: &mut Bits<'_>, alphabet: usize) -> Result<Huffman, Error> {
    let count = us(bits.take(2)?) + 1;
    let width = usize::BITS - (alphabet - 1).leading_zeros();
    let mut symbols = [0usize; 4];
    for i in 0..count {
        let symbol = us(bits.take(width)?);
        if symbol >= alphabet || symbols.iter().take(i).any(|&s| s == symbol) {
            return Err(Error::Corrupt);
        }
        *symbols.get_mut(i).ok_or(Error::Corrupt)? = symbol;
    }
    let code_lengths: &[u8] = match count {
        1 => {
            return Ok(Huffman::single(
                u16::try_from(symbols[0]).map_err(|_| Error::Corrupt)?,
            ));
        }
        2 => &[1, 1],
        3 => &[1, 2, 2],
        _ if bits.bit()? => &[1, 2, 3, 3],
        _ => &[2, 2, 2, 2],
    };
    let mut lengths = vec![0u8; alphabet];
    for (&symbol, &len) in symbols.iter().zip(code_lengths) {
        *lengths.get_mut(symbol).ok_or(Error::Corrupt)? = len;
    }
    Ok(Huffman::new(&lengths)?.0)
}

/// Block types and counts of one category: literals, insert-and-copy commands or distances.
struct Category {
    types: usize,
    codes: Option<(Huffman, Huffman)>,
    current: usize,
    previous: usize,
    left: usize,
}

impl Category {
    fn read(bits: &mut Bits<'_>) -> Result<Self, Error> {
        let types = var_u8(bits)? + 1;
        let (codes, left) = if types < 2 {
            (None, ONE_BLOCK)
        } else {
            let type_code = prefix_code(bits, types + 2)?;
            let count_code = prefix_code(bits, 26)?;
            let left = block_count(bits, &count_code)?;
            (Some((type_code, count_code)), left)
        };
        Ok(Self {
            types,
            codes,
            current: 0,
            previous: 1,
            left,
        })
    }

    /// The block type for the next symbol, switching blocks when the current one is used up.
    fn next(&mut self, bits: &mut Bits<'_>) -> Result<usize, Error> {
        if self.left == 0 {
            match &self.codes {
                Some((type_code, count_code)) => {
                    let mut block_type = match usize::from(type_code.decode(bits)?) {
                        0 => self.previous,
                        1 => self.current + 1,
                        n => n - 2,
                    };
                    if block_type >= self.types {
                        block_type -= self.types;
                    }
                    self.previous = self.current;
                    self.current = block_type;
                    self.left = block_count(bits, count_code)?;
                }
                None => self.left = ONE_BLOCK,
            }
        }
        self.left -= 1;
        Ok(self.current)
    }
}

fn block_count(bits: &mut Bits<'_>, code: &Huffman) -> Result<usize, Error> {
    let (base, extra) = *BLOCK_COUNT
        .get(usize::from(code.decode(bits)?))
        .ok_or(Error::Corrupt)?;
    Ok(base + us(bits.take(extra)?))
}

/// A context map with inverse move-to-front (section 7.3).
fn context_map(bits: &mut Bits<'_>, size: usize, trees: usize) -> Result<Vec<u8>, Error> {
    let mut map = vec![0u8; size];
    if trees < 2 {
        return Ok(map);
    }
    let rle_max = if bits.bit()? {
        us(bits.take(4)?) + 1
    } else {
        0
    };
    let code = prefix_code(bits, trees + rle_max)?;
    let mut i = 0;
    while i < size {
        let symbol = usize::from(code.decode(bits)?);
        if symbol == 0 {
            i += 1;
        } else if symbol <= rle_max {
            let run = (1 << symbol) + us(bits.take(u32::try_from(symbol).unwrap_or(0))?);
            if i + run > size {
                return Err(Error::Corrupt);
            }
            i += run; // the map is already zero
        } else {
            *map.get_mut(i).ok_or(Error::Corrupt)? =
                u8::try_from(symbol - rle_max).map_err(|_| Error::Corrupt)?;
            i += 1;
        }
    }
    if bits.bit()? {
        let mut mtf: Vec<u8> = (0..=255).collect();
        for value in &mut map {
            let index = usize::from(*value);
            let front = mtf.remove(index);
            mtf.insert(0, front);
            *value = front;
        }
    }
    Ok(map)
}

/// A distance from a distance code (section 4); the caller updates the ring of last distances.
fn distance(
    bits: &mut Bits<'_>,
    code: usize,
    postfix: u32,
    direct: usize,
    last: &[usize; 4],
) -> Result<usize, Error> {
    let [d0, d1, d2, d3] = *last;
    let short = |base: usize, delta: i64| {
        let d = i64::try_from(base).map_err(|_| Error::Corrupt)? + delta;
        usize::try_from(d)
            .ok()
            .filter(|&d| d > 0)
            .ok_or(Error::Corrupt)
    };
    match code {
        0 => Ok(d0),
        1 => Ok(d1),
        2 => Ok(d2),
        3 => Ok(d3),
        4..=15 => {
            let base = if code < 10 { d0 } else { d1 };
            let delta = [-1, 1, -2, 2, -3, 3]
                .get((code - 4) % 6)
                .copied()
                .unwrap_or(0);
            short(base, delta)
        }
        _ if code < 16 + direct => Ok(code - 15),
        _ => {
            let c = code - direct - 16;
            let extra_bits = 1 + (c >> (postfix + 1));
            let extra = us(bits.take(u32::try_from(extra_bits).map_err(|_| Error::Corrupt)?)?);
            let high = c >> postfix;
            let low = c & ((1 << postfix) - 1);
            let offset = ((2 + (high & 1)) << extra_bits) - 4;
            Ok(((offset + extra) << postfix) + low + direct + 1)
        }
    }
}

/// A static dictionary word after its transform (section 8).
fn dictionary_word(len: usize, word_id: usize) -> Result<Vec<u8>, Error> {
    if !(4..=24).contains(&len) {
        return Err(Error::Corrupt);
    }
    let index_bits = *NDBITS.get(len).ok_or(Error::Corrupt)?;
    let index = word_id & ((1 << index_bits) - 1);
    let &(prefix, kind, suffix) = TRANSFORMS
        .get(word_id >> index_bits)
        .ok_or(Error::Corrupt)?;
    let offset = DOFFSET.get(len).ok_or(Error::Corrupt)? + index * len;
    let word = DICTIONARY.get(offset..offset + len).ok_or(Error::Corrupt)?;
    let mut word = match kind {
        3..=11 => word.get(usize::from(kind - 2)..).unwrap_or_default(),
        12..=20 => word
            .get(..len.saturating_sub(usize::from(kind - 11)))
            .unwrap_or_default(),
        _ => word,
    }
    .to_vec();
    if kind == 1 {
        uppercase(&mut word, 0);
    } else if kind == 2 {
        let mut i = 0;
        while i < word.len() {
            i += uppercase(&mut word, i);
        }
    }
    Ok([prefix, &word, suffix].concat())
}

/// Uppercases the UTF-8 character at `i` the way the RFC does; returns its length.
fn uppercase(word: &mut [u8], i: usize) -> usize {
    let Some(&first) = word.get(i) else {
        return 1;
    };
    let (step, at, mask) = match first {
        0..0xC0 => (1, i, if first.is_ascii_lowercase() { 32 } else { 0 }),
        0xC0..0xE0 => (2, i + 1, 32),
        _ => (3, i + 2, 5),
    };
    if let Some(byte) = word.get_mut(at) {
        *byte ^= mask;
    }
    step
}

/// The byte `back` positions before the end of the output, or 0 before the stream start.
fn byte_back(out: &[u8], start: usize, back: usize) -> u8 {
    out.len()
        .checked_sub(back)
        .filter(|&i| i >= start)
        .and_then(|i| out.get(i).copied())
        .unwrap_or(0)
}

/// A compressed meta-block (section 9.2) ending at output position `end`.
struct MetaBlock {
    start: usize,
    end: usize,
    window: usize,
    limit: usize,
}

impl MetaBlock {
    fn decode(
        &self,
        bits: &mut Bits<'_>,
        out: &mut Vec<u8>,
        last: &mut [usize; 4],
    ) -> Result<(), Error> {
        let mut literal = Category::read(bits)?;
        let mut command = Category::read(bits)?;
        let mut dist = Category::read(bits)?;
        let postfix = bits.take(2)?;
        let direct = us(bits.take(4)?) << postfix;
        let modes = (0..literal.types)
            .map(|_| bits.take(2))
            .collect::<Result<Vec<u32>, _>>()?;
        let literal_trees = var_u8(bits)? + 1;
        let literal_map = context_map(bits, 64 * literal.types, literal_trees)?;
        let distance_trees = var_u8(bits)? + 1;
        let distance_map = context_map(bits, 4 * dist.types, distance_trees)?;
        let literal_codes = (0..literal_trees)
            .map(|_| prefix_code(bits, 256))
            .collect::<Result<Vec<_>, _>>()?;
        let command_codes = (0..command.types)
            .map(|_| prefix_code(bits, 704))
            .collect::<Result<Vec<_>, _>>()?;
        let distance_alphabet = 16 + direct + (48 << postfix);
        let distance_codes = (0..distance_trees)
            .map(|_| prefix_code(bits, distance_alphabet))
            .collect::<Result<Vec<_>, _>>()?;

        while out.len() < self.end {
            let code = command_codes
                .get(command.next(bits)?)
                .ok_or(Error::Corrupt)?;
            let symbol = usize::from(code.decode(bits)?);
            let &(insert_base, copy_base, implicit) =
                CELLS.get(symbol >> 6).ok_or(Error::Corrupt)?;
            let (ib, ie) = *INSERT
                .get(insert_base + ((symbol >> 3) & 7))
                .ok_or(Error::Corrupt)?;
            let (cb, ce) = *COPY.get(copy_base + (symbol & 7)).ok_or(Error::Corrupt)?;
            let insert = ib + us(bits.take(ie)?);
            let copy = cb + us(bits.take(ce)?);
            if insert > self.end - out.len() {
                return Err(Error::Corrupt);
            }
            for _ in 0..insert {
                let block_type = literal.next(bits)?;
                let p1 = byte_back(out, self.start, 1);
                let p2 = byte_back(out, self.start, 2);
                let mode = *modes.get(block_type).ok_or(Error::Corrupt)?;
                let tree = *literal_map
                    .get(64 * block_type + context(mode, p1, p2))
                    .ok_or(Error::Corrupt)?;
                let byte = literal_codes
                    .get(usize::from(tree))
                    .ok_or(Error::Corrupt)?
                    .decode(bits)?;
                push(
                    out,
                    u8::try_from(byte).map_err(|_| Error::Corrupt)?,
                    self.limit,
                )?;
            }
            if out.len() == self.end {
                break;
            }
            let (distance, code) = if implicit {
                (last[0], 0)
            } else {
                let block_type = dist.next(bits)?;
                let tree = *distance_map
                    .get(4 * block_type + copy.min(5) - 2)
                    .ok_or(Error::Corrupt)?;
                let code = usize::from(
                    distance_codes
                        .get(usize::from(tree))
                        .ok_or(Error::Corrupt)?
                        .decode(bits)?,
                );
                (distance(bits, code, postfix, direct, last)?, code)
            };
            let max = self.window.min(out.len() - self.start);
            let room = self.end - out.len();
            if distance <= max {
                if code != 0 {
                    *last = [distance, last[0], last[1], last[2]];
                }
                if copy > room {
                    return Err(Error::Corrupt);
                }
                copy_back(out, distance, copy, self.limit)?;
            } else {
                let word = dictionary_word(copy, distance - max - 1)?;
                if word.len() > room {
                    return Err(Error::Corrupt);
                }
                extend(out, &word, self.limit)?;
            }
        }
        Ok(())
    }
}

/// Literal context ID from the last two bytes (section 7.1).
fn context(mode: u32, p1: u8, p2: u8) -> usize {
    let lut =
        |table: &[u8; 256], i: u8| usize::from(table.get(usize::from(i)).copied().unwrap_or(0));
    match mode {
        0 => usize::from(p1 & 0x3F),
        1 => usize::from(p1 >> 2),
        2 => lut(&LUT0, p1) | lut(&LUT1, p2),
        _ => (lut(&LUT2, p1) << 3) | lut(&LUT2, p2),
    }
}
