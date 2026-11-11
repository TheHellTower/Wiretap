//! Canonical prefix codes as DEFLATE and Brotli use them: built from code lengths, codes of equal
//! length assigned in symbol order, bits read most-significant first within a code.

use crate::{Error, bits::Bits, us};

/// Longest code DEFLATE and Brotli allow.
const MAX_BITS: usize = 15;

pub(crate) struct Huffman {
    counts: [u32; MAX_BITS + 1],
    symbols: Vec<u16>,
    /// A code with one symbol that takes no bits (Brotli).
    single: Option<u16>,
}

impl Huffman {
    pub(crate) fn single(symbol: u16) -> Self {
        Self {
            counts: [0; MAX_BITS + 1],
            symbols: Vec::new(),
            single: Some(symbol),
        }
    }

    /// Builds the code for `lengths` (0 = unused symbol). Returns the code and the unused code
    /// space (0 when the code is complete); over-subscribed lengths are corrupt.
    pub(crate) fn new(lengths: &[u8]) -> Result<(Self, u32), Error> {
        let mut counts = [0u32; MAX_BITS + 1];
        for &len in lengths {
            *counts.get_mut(usize::from(len)).ok_or(Error::Corrupt)? += 1;
        }
        let mut left = 1u32;
        for &count in counts.iter().skip(1) {
            left = (left << 1).checked_sub(count).ok_or(Error::Corrupt)?;
        }
        let mut next = [0usize; MAX_BITS + 1];
        let mut total = 0;
        for (slot, &count) in next.iter_mut().zip(counts.iter()).skip(1) {
            *slot = total;
            total += us(count);
        }
        let mut symbols = vec![0u16; total];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let slot = next.get_mut(usize::from(len)).ok_or(Error::Corrupt)?;
            *symbols.get_mut(*slot).ok_or(Error::Corrupt)? =
                u16::try_from(symbol).map_err(|_| Error::Corrupt)?;
            *slot += 1;
        }
        Ok((
            Self {
                counts,
                symbols,
                single: None,
            },
            left,
        ))
    }

    /// Decodes one symbol.
    pub(crate) fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, Error> {
        if let Some(symbol) = self.single {
            return Ok(symbol);
        }
        let (mut code, mut first, mut index) = (0u32, 0u32, 0u32);
        for &count in self.counts.iter().skip(1) {
            code |= bits.take(1)?;
            if code < first + count {
                return self
                    .symbols
                    .get(us(index + code - first))
                    .copied()
                    .ok_or(Error::Corrupt);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::Corrupt)
    }
}
