//! Bit readers: forward LSB-first (DEFLATE, Brotli, Zstandard table headers) and backward
//! (Zstandard entropy streams).

use crate::{Error, us};

/// Reads bits least-significant first, refilling a 64-bit buffer byte by byte.
pub(crate) struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    count: u32,
}

impl<'a> Bits<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buf: 0,
            count: 0,
        }
    }

    fn refill(&mut self) {
        while self.count <= 56 {
            let Some(&byte) = self.data.get(self.pos) else {
                break;
            };
            self.buf |= u64::from(byte) << self.count;
            self.pos += 1;
            self.count += 8;
        }
    }

    /// The next `n` (at most 32) bits without consuming them; bits past the end read as zero.
    pub(crate) fn peek(&mut self, n: u32) -> u32 {
        if self.count < n {
            self.refill();
        }
        low(self.buf, n)
    }

    /// Consumes `n` (at most 32) bits.
    pub(crate) fn skip(&mut self, n: u32) -> Result<(), Error> {
        if self.count < n {
            self.refill();
            if self.count < n {
                return Err(Error::Truncated);
            }
        }
        self.buf = self.buf.checked_shr(n).unwrap_or(0);
        self.count -= n;
        Ok(())
    }

    /// Reads `n` (at most 32) bits.
    pub(crate) fn take(&mut self, n: u32) -> Result<u32, Error> {
        let value = self.peek(n);
        self.skip(n)?;
        Ok(value)
    }

    pub(crate) fn bit(&mut self) -> Result<bool, Error> {
        Ok(self.take(1)? == 1)
    }

    /// Skips to the next byte boundary and returns the skipped bits.
    pub(crate) fn align(&mut self) -> u32 {
        let n = self.count % 8;
        let skipped = low(self.buf, n);
        self.buf >>= n;
        self.count -= n;
        skipped
    }

    /// The next `n` bytes; the reader must be byte-aligned.
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let start = self.consumed();
        let end = start.checked_add(n).ok_or(Error::Truncated)?;
        let slice = self.data.get(start..end).ok_or(Error::Truncated)?;
        self.pos = end;
        self.buf = 0;
        self.count = 0;
        Ok(slice)
    }

    /// Bytes consumed so far, a partly read byte included.
    pub(crate) fn consumed(&self) -> usize {
        self.pos.saturating_sub(us(self.count / 8))
    }

    /// Every input bit has been consumed.
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0 && self.pos >= self.data.len()
    }
}

/// Reads a Zstandard backward bitstream: from the end of the slice towards its start, skipping
/// the final padding marker. Reading past the start yields zero bits and is reported by
/// [`Backward::overflowed`].
pub(crate) struct Backward<'a> {
    data: &'a [u8],
    /// Unread bits before the current position; negative after reading past the start.
    left: i64,
}

impl<'a> Backward<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Result<Self, Error> {
        let last = *data.last().ok_or(Error::Corrupt)?;
        if last == 0 {
            return Err(Error::Corrupt);
        }
        let total = i64::try_from(data.len()).map_err(|_| Error::Corrupt)? * 8;
        Ok(Self {
            data,
            left: total - i64::from(last.leading_zeros()) - 1,
        })
    }

    /// The next `n` (at most 32) bits, without consuming them.
    pub(crate) fn peek(&self, n: u32) -> u32 {
        let lo = self.left - i64::from(n);
        if lo >= 0 {
            return field(self.data, lo, n);
        }
        let available = i64::from(n) + lo;
        if available <= 0 {
            return 0;
        }
        let available = u32::try_from(available).unwrap_or(0);
        field(self.data, 0, available) << (n - available)
    }

    pub(crate) fn consume(&mut self, n: u32) {
        self.left -= i64::from(n);
    }

    pub(crate) fn read(&mut self, n: u32) -> u32 {
        let value = self.peek(n);
        self.consume(n);
        value
    }

    pub(crate) const fn overflowed(&self) -> bool {
        self.left < 0
    }

    pub(crate) const fn finished(&self) -> bool {
        self.left == 0
    }
}

/// `n` (at most 32) bits starting at bit `lo` of a little-endian bit string.
fn field(data: &[u8], lo: i64, n: u32) -> u32 {
    let lo = usize::try_from(lo).unwrap_or(0);
    let (byte, shift) = (lo / 8, lo % 8);
    let mut word = 0u64;
    for (i, b) in data.iter().skip(byte).take(5).enumerate() {
        word |= u64::from(*b) << (8 * i);
    }
    low(word >> shift, n)
}

/// The low `n` (at most 32) bits of `v`.
fn low(v: u64, n: u32) -> u32 {
    let mask = 1u64.checked_shl(n).map_or(u64::MAX, |m| m - 1);
    u32::try_from(v & mask & 0xFFFF_FFFF).unwrap_or(0)
}
