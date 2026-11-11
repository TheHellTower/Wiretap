//! Incremental, strict decoder for the chunked transfer coding (RFC 9112 section 7.1).

/// Longest chunk-size line (hex digits plus extensions) accepted.
const MAX_SIZE_LINE: usize = 1024;
/// Largest trailer section accepted.
const MAX_TRAILER: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Size { digits: usize },
    Extension { len: usize },
    SizeLf,
    Data(u64),
    DataCr,
    DataLf,
    Trailer { len: usize, total: usize },
    TrailerLf { len: usize, total: usize },
    Done,
}

/// Result of feeding bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// The body continues; all input was consumed.
    NeedMore,
    /// The body ended after `consumed` bytes of this input.
    Done {
        /// Bytes of the last input that belonged to the body.
        consumed: usize,
    },
}

/// Malformed chunked encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkError;

impl std::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed chunked transfer coding")
    }
}

impl std::error::Error for ChunkError {}

/// Decodes a chunked body fed in arbitrary pieces. Strict: CRLF line endings, bounded size
/// lines, extensions and trailers, no size overflow.
#[derive(Clone, Debug)]
pub struct Chunked {
    state: State,
    size: u64,
    decoded: u64,
}

impl Default for Chunked {
    fn default() -> Self {
        Self {
            state: State::Size { digits: 0 },
            size: 0,
            decoded: 0,
        }
    }
}

impl Chunked {
    /// Total decoded body bytes so far (including bytes beyond `limit`).
    #[must_use]
    pub const fn decoded(&self) -> u64 {
        self.decoded
    }

    /// Feeds raw bytes; decoded data is appended to `out` until it holds `limit` bytes.
    ///
    /// # Errors
    /// The encoding is malformed; the decoder must not be fed again.
    pub fn feed(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<Progress, ChunkError> {
        let mut i = 0;
        while i < input.len() {
            let Some(&b) = input.get(i) else { break };
            self.state = match self.state {
                State::Done => return Ok(Progress::Done { consumed: i }),
                State::Size { digits } => match char::from(b).to_digit(16) {
                    Some(d) if digits < 16 => {
                        self.size = (self.size << 4) | u64::from(d);
                        State::Size { digits: digits + 1 }
                    }
                    _ if digits == 0 => return Err(ChunkError),
                    None if b == b';' || b == b' ' || b == b'\t' => {
                        State::Extension { len: digits }
                    }
                    None if b == b'\r' => State::SizeLf,
                    _ => return Err(ChunkError),
                },
                State::Extension { len } => match b {
                    b'\r' => State::SizeLf,
                    b'\n' => return Err(ChunkError),
                    _ if len < MAX_SIZE_LINE => State::Extension { len: len + 1 },
                    _ => return Err(ChunkError),
                },
                State::SizeLf if b == b'\n' => {
                    let size = std::mem::take(&mut self.size);
                    if size == 0 {
                        State::Trailer { len: 0, total: 0 }
                    } else {
                        State::Data(size)
                    }
                }
                State::Data(remaining) => {
                    let take = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(input.len() - i);
                    let data = input.get(i..i + take).unwrap_or_default();
                    let room = limit.saturating_sub(out.len()).min(data.len());
                    out.extend_from_slice(data.get(..room).unwrap_or_default());
                    self.decoded = self.decoded.saturating_add(take as u64);
                    i += take;
                    let left = remaining - take as u64;
                    self.state = if left == 0 {
                        State::DataCr
                    } else {
                        State::Data(left)
                    };
                    continue;
                }
                State::DataCr if b == b'\r' => State::DataLf,
                State::DataLf if b == b'\n' => State::Size { digits: 0 },
                State::Trailer { len, total } => match b {
                    b'\r' => State::TrailerLf { len, total },
                    b'\n' => return Err(ChunkError),
                    _ if total < MAX_TRAILER => State::Trailer {
                        len: len + 1,
                        total: total + 1,
                    },
                    _ => return Err(ChunkError),
                },
                State::TrailerLf { len, total } if b == b'\n' => {
                    if len == 0 {
                        State::Done
                    } else {
                        State::Trailer {
                            len: 0,
                            total: total + 2,
                        }
                    }
                }
                State::SizeLf | State::DataCr | State::DataLf | State::TrailerLf { .. } => {
                    return Err(ChunkError);
                }
            };
            i += 1;
        }
        Ok(if self.state == State::Done {
            Progress::Done { consumed: i }
        } else {
            Progress::NeedMore
        })
    }
}
