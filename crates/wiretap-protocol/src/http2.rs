//! HTTP/2 framing (RFC 9113) for observing a connection: one [`Decoder`] per direction turns
//! the bytes into header lists, body data and stream ends. It decodes only what inspection
//! needs and validates nothing else: Wiretap relays the bytes untouched and the endpoints
//! enforce the protocol. DATA is passed through as it arrives (no whole-frame buffering); other
//! frames are buffered up to [`MAX_CONTROL`] bytes.

use crate::hpack::{self, Field};

/// The client connection preface (RFC 9113 3.4).
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Largest non-DATA frame or header block decoded.
pub const MAX_CONTROL: usize = 1 << 20;
/// Largest dynamic table an encoder may switch to.
const MAX_TABLE: usize = 1 << 16;
/// Header fields kept per block (the event model's limits).
const MAX_FIELDS: usize = 512;
const MAX_FIELD_BYTES: usize = 256 * 1024;

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const PUSH_PROMISE: u8 = 5;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// What one direction of a connection carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A complete header block (HEADERS with its CONTINUATIONs): request or response head,
    /// informational response, or trailers.
    Headers {
        /// Stream ID.
        stream: u32,
        /// Decoded fields, pseudo-header fields (`:method`, `:status`, ...) included.
        fields: Vec<Field>,
        /// The sender's last frame on this stream.
        end_stream: bool,
    },
    /// A server push (PUSH_PROMISE): the request the server will answer on `promised`.
    Promise {
        /// Stream the promise was sent on.
        stream: u32,
        /// The pushed stream.
        promised: u32,
        /// The promised request's fields.
        fields: Vec<Field>,
    },
    /// Body bytes (DATA payload without padding), possibly part of a frame.
    Data {
        /// Stream ID.
        stream: u32,
        /// The bytes.
        data: Vec<u8>,
        /// Flow-controlled bytes this part accounts for (padding included): what the receiver
        /// returns with WINDOW_UPDATE.
        flow: usize,
        /// The sender's last frame on this stream (set on the frame's last part).
        end_stream: bool,
    },
    /// The stream was cancelled (RST_STREAM) with an error code.
    Reset {
        /// Stream ID.
        stream: u32,
        /// Error code (RFC 9113 7).
        code: u32,
    },
    /// The connection is closing (GOAWAY) with an error code.
    GoAway {
        /// The last stream the sender processed or may process.
        last: u32,
        /// Error code.
        code: u32,
    },
    /// SETTINGS (acknowledgements are not reported): identifier and value pairs.
    Settings(Vec<(u16, u32)>),
    /// PING (acknowledgements are not reported): its opaque payload.
    Ping([u8; 8]),
    /// WINDOW_UPDATE: more flow-control credit for a stream, or the connection (stream 0).
    WindowUpdate {
        /// Stream ID (0: the connection).
        stream: u32,
        /// Bytes of credit.
        increment: u32,
    },
    /// Decoding stopped (the connection itself goes on): why.
    Error(&'static str),
}

/// A DATA frame being passed through.
#[derive(Debug)]
struct Body {
    stream: u32,
    /// Payload bytes still to come, padding included.
    left: usize,
    /// Padding at the end of `left`.
    padding: usize,
    end_stream: bool,
    /// Whether the pad length byte was read already.
    started: bool,
    padded: bool,
}

/// A header block waiting for CONTINUATION frames.
#[derive(Debug)]
struct Block {
    stream: u32,
    end_stream: bool,
    promised: Option<u32>,
    fragment: Vec<u8>,
}

/// One direction of an HTTP/2 connection.
#[derive(Debug)]
pub struct Decoder {
    /// Client direction: the preface is still expected (bytes of it seen so far).
    preface: Option<usize>,
    buf: Vec<u8>,
    body: Option<Body>,
    block: Option<Block>,
    hpack: hpack::Decoder,
    failed: bool,
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    if let Some(src) = bytes.get(at..at.saturating_add(4)) {
        word.copy_from_slice(src);
    }
    u32::from_be_bytes(word)
}

impl Decoder {
    /// A decoder for the bytes the client sends (`client`, starting with the preface) or the
    /// server sends.
    #[must_use]
    pub fn new(client: bool) -> Self {
        Self {
            preface: client.then_some(0),
            buf: Vec::new(),
            body: None,
            block: None,
            hpack: hpack::Decoder::new(MAX_TABLE),
            failed: false,
        }
    }

    /// Whether the bytes so far end exactly between frames, outside a header block: where a
    /// frame can be added to this direction (e.g. a GOAWAY).
    #[must_use]
    pub fn at_boundary(&self) -> bool {
        !self.failed
            && self.preface.is_none()
            && self.buf.is_empty()
            && self.body.is_none()
            && self.block.is_none()
    }

    /// Decodes the next bytes of this direction.
    pub fn feed(&mut self, mut input: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        if self.failed {
            return events;
        }
        if let Some(seen) = self.preface {
            let want = PREFACE.get(seen..).unwrap_or_default();
            let n = want.len().min(input.len());
            if want.get(..n) != input.get(..n) {
                return self.fail(events, "no HTTP/2 connection preface");
            }
            input = input.get(n..).unwrap_or_default();
            self.preface = (seen + n < PREFACE.len()).then_some(seen + n);
            if self.preface.is_some() {
                return events;
            }
        }
        while !input.is_empty() {
            if let Some(body) = &mut self.body {
                input = Self::pass_body(body, input, &mut events);
                if body.left == 0 {
                    self.body = None;
                }
                continue;
            }
            // A frame header, then (for non-DATA frames) the whole payload.
            let need = if self.buf.len() < 9 {
                9
            } else {
                9 + self.frame_len()
            };
            let take = need.saturating_sub(self.buf.len()).min(input.len());
            self.buf
                .extend_from_slice(input.get(..take).unwrap_or_default());
            input = input.get(take..).unwrap_or_default();
            if self.buf.len() < need {
                continue;
            }
            if need == 9 {
                let (kind, len) = (self.buf.get(3).copied().unwrap_or(0), self.frame_len());
                if kind == DATA {
                    let header = std::mem::take(&mut self.buf);
                    let flags = header.get(4).copied().unwrap_or(0);
                    let body = Body {
                        stream: u32_at(&header, 5) & 0x7FFF_FFFF,
                        left: len,
                        padding: 0,
                        end_stream: flags & END_STREAM != 0,
                        started: false,
                        padded: flags & PADDED != 0,
                    };
                    if len > 0 {
                        self.body = Some(body);
                    } else if body.end_stream {
                        events.push(Event::Data {
                            stream: body.stream,
                            data: Vec::new(),
                            flow: 0,
                            end_stream: true,
                        });
                    }
                    continue;
                }
                if len > MAX_CONTROL {
                    return self.fail(events, "HTTP/2 frame too large to decode");
                }
                if len > 0 {
                    continue; // read the payload
                }
            }
            let frame = std::mem::take(&mut self.buf);
            if let Err(e) = self.frame(&frame, &mut events) {
                return self.fail(events, e);
            }
        }
        events
    }

    fn frame_len(&self) -> usize {
        let b = |i| usize::from(self.buf.get(i).copied().unwrap_or(0));
        (b(0) << 16) | (b(1) << 8) | b(2)
    }

    fn fail(&mut self, mut events: Vec<Event>, why: &'static str) -> Vec<Event> {
        self.failed = true;
        self.buf = Vec::new();
        events.push(Event::Error(why));
        events
    }

    /// Passes DATA payload bytes through; returns the input after them.
    fn pass_body<'a>(body: &mut Body, mut input: &'a [u8], events: &mut Vec<Event>) -> &'a [u8] {
        let mut flow = 0;
        if body.padded && !body.started {
            let Some((&pad, rest)) = input.split_first() else {
                return input;
            };
            flow = 1;
            body.started = true;
            body.left = body.left.saturating_sub(1);
            body.padding = usize::from(pad).min(body.left);
            input = rest;
        }
        body.started = true;
        let take = body.left.min(input.len());
        let data_left = body.left.saturating_sub(body.padding);
        let data = input.get(..take.min(data_left)).unwrap_or_default();
        body.left -= take;
        flow += take;
        let last = body.left == 0;
        if flow > 0 || (last && body.end_stream) {
            events.push(Event::Data {
                stream: body.stream,
                data: data.to_vec(),
                flow,
                end_stream: last && body.end_stream,
            });
        }
        input.get(take..).unwrap_or_default()
    }

    /// Handles one complete non-DATA frame (header and payload).
    fn frame(&mut self, frame: &[u8], events: &mut Vec<Event>) -> Result<(), &'static str> {
        let (kind, flags) = (
            frame.get(3).copied().unwrap_or(0),
            frame.get(4).copied().unwrap_or(0),
        );
        let stream = u32_at(frame, 5) & 0x7FFF_FFFF;
        let payload = frame.get(9..).unwrap_or_default();
        if self.block.is_some() && kind != CONTINUATION {
            return Err("header block interrupted");
        }
        match kind {
            HEADERS | PUSH_PROMISE => {
                let mut body = payload;
                let mut padding = 0;
                if flags & PADDED != 0 {
                    let (&pad, rest) = body.split_first().ok_or("truncated padding")?;
                    (padding, body) = (usize::from(pad), rest);
                }
                let mut promised = None;
                if kind == PUSH_PROMISE {
                    promised = Some(u32_at(body, 0) & 0x7FFF_FFFF);
                    body = body.get(4..).ok_or("truncated PUSH_PROMISE")?;
                } else if flags & PRIORITY != 0 {
                    body = body.get(5..).ok_or("truncated priority")?;
                }
                let end = body.len().checked_sub(padding).ok_or("padding too long")?;
                self.block = Some(Block {
                    stream,
                    end_stream: kind == HEADERS && flags & END_STREAM != 0,
                    promised,
                    fragment: body.get(..end).unwrap_or_default().to_vec(),
                });
            }
            CONTINUATION => {
                let block = self.block.as_mut().ok_or("CONTINUATION without headers")?;
                if block.stream != stream || block.fragment.len() + payload.len() > MAX_CONTROL {
                    return Err("invalid CONTINUATION");
                }
                block.fragment.extend_from_slice(payload);
            }
            RST_STREAM => events.push(Event::Reset {
                stream,
                code: u32_at(payload, 0),
            }),
            GOAWAY => events.push(Event::GoAway {
                last: u32_at(payload, 0) & 0x7FFF_FFFF,
                code: u32_at(payload, 4),
            }),
            SETTINGS if flags & ACK == 0 => {
                let pairs = payload.as_chunks::<6>().0.iter();
                events.push(Event::Settings(
                    pairs
                        .map(|&[a, b, c, d, e, f]| {
                            (u16::from_be_bytes([a, b]), u32::from_be_bytes([c, d, e, f]))
                        })
                        .collect(),
                ));
            }
            PING if flags & ACK == 0 => {
                let mut data = [0u8; 8];
                if let Some(src) = payload.get(..8) {
                    data.copy_from_slice(src);
                }
                events.push(Event::Ping(data));
            }
            WINDOW_UPDATE => events.push(Event::WindowUpdate {
                stream,
                increment: u32_at(payload, 0) & 0x7FFF_FFFF,
            }),
            _ => {} // PRIORITY, acknowledgements, extensions
        }
        if matches!(kind, HEADERS | PUSH_PROMISE | CONTINUATION) && flags & END_HEADERS != 0 {
            let block = self.block.take().ok_or("header block missing")?;
            let fields = self
                .hpack
                .decode(&block.fragment, MAX_FIELDS, MAX_FIELD_BYTES)?;
            events.push(match block.promised {
                Some(promised) => Event::Promise {
                    stream: block.stream,
                    promised,
                    fields,
                },
                None => Event::Headers {
                    stream: block.stream,
                    fields,
                    end_stream: block.end_stream,
                },
            });
        }
        Ok(())
    }
}
