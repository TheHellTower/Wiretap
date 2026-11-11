//! Server-Sent Events (`text/event-stream`, WHATWG HTML 9.2.6): turns a response body, as it
//! arrives, into the events a browser's `EventSource` would dispatch. Bounded: each event's data
//! is kept up to a limit (its full size is still counted) and so is a line without its end.

/// One dispatched event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    /// The `event:` field (empty: the default `message`).
    pub kind: String,
    /// The `data:` lines joined with `\n`, up to the decoder's limit.
    pub data: String,
    /// Full size of the data, in bytes.
    pub size: u64,
    /// The `id:` field in effect, if any (it persists across events, as in `EventSource`).
    pub id: Option<String>,
    /// The `retry:` field of this event, in milliseconds.
    pub retry: Option<u64>,
}

impl Event {
    /// Event attributes: `event`, `id`, `retry`, `preview` (start of the data).
    #[must_use]
    pub fn attributes(&self) -> std::collections::BTreeMap<String, String> {
        let preview: String = self
            .data
            .chars()
            .take(200)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        [
            (
                "event",
                if self.kind.is_empty() {
                    "message".into()
                } else {
                    self.kind.clone()
                },
            ),
            ("id", self.id.clone().unwrap_or_default()),
            (
                "retry",
                self.retry.map(|r| r.to_string()).unwrap_or_default(),
            ),
            ("preview", preview),
        ]
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }
}

/// Decodes one event stream.
#[derive(Debug)]
pub struct Decoder {
    line: Vec<u8>,
    /// Bytes of the current line beyond `limit` (not kept, still counted).
    dropped: usize,
    /// The previous chunk ended with CR: a following LF belongs to that line end.
    after_cr: bool,
    /// Bytes of the UTF-8 BOM seen at the very start (skipped), until something else comes.
    bom: Option<usize>,
    event: Event,
    has_data: bool,
    last_id: Option<String>,
    limit: usize,
}

impl Decoder {
    /// A decoder keeping at most `limit` bytes of each event's data and of a line.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            line: Vec::new(),
            dropped: 0,
            after_cr: false,
            bom: Some(0),
            event: Event::default(),
            has_data: false,
            last_id: None,
            limit,
        }
    }

    /// Decodes the next body bytes; returns the events they complete.
    pub fn feed(&mut self, input: &[u8]) -> Vec<Event> {
        const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
        let mut out = Vec::new();
        for &b in input {
            if let Some(seen) = self.bom {
                self.bom = (BOM.get(seen) == Some(&b) && seen < 2).then_some(seen + 1);
                if BOM.get(seen) == Some(&b) {
                    continue;
                }
            }
            match b {
                b'\n' if self.after_cr => self.after_cr = false,
                b'\r' | b'\n' => {
                    self.after_cr = b == b'\r';
                    let line = std::mem::take(&mut self.line);
                    let dropped = std::mem::take(&mut self.dropped);
                    self.line(&line, dropped, &mut out);
                }
                _ => {
                    self.after_cr = false;
                    if self.line.len() < self.limit {
                        self.line.push(b);
                    } else {
                        self.dropped = self.dropped.saturating_add(1);
                    }
                }
            }
        }
        out
    }

    fn line(&mut self, line: &[u8], dropped: usize, out: &mut Vec<Event>) {
        if line.is_empty() && dropped == 0 {
            // Dispatch (no data: nothing to dispatch, the event type resets).
            let mut event = std::mem::take(&mut self.event);
            if std::mem::take(&mut self.has_data) {
                if event.data.ends_with('\n') {
                    event.data.pop();
                    event.size = event.size.saturating_sub(1);
                }
                event.id.clone_from(&self.last_id);
                out.push(event);
            }
            return;
        }
        let (name, value) = match line.iter().position(|&b| b == b':') {
            Some(0) => return, // a comment
            Some(i) => {
                let value = line.get(i + 1..).unwrap_or_default();
                (
                    line.get(..i).unwrap_or_default(),
                    value.strip_prefix(b" ").unwrap_or(value),
                )
            }
            None => (line, &[][..]),
        };
        let value = String::from_utf8_lossy(value);
        match name {
            b"event" => self.event.kind = value.into_owned(),
            b"data" => {
                self.has_data = true;
                let room = self.limit.saturating_sub(self.event.data.len());
                let kept: String = value
                    .chars()
                    .scan(0, |used, c| {
                        *used += c.len_utf8();
                        (*used <= room).then_some(c)
                    })
                    .collect();
                self.event.data.push_str(&kept);
                if self.event.data.len() < self.limit {
                    self.event.data.push('\n');
                }
                let full = value.len().saturating_add(dropped).saturating_add(1);
                self.event.size = self.event.size.saturating_add(full as u64);
            }
            b"id" if !value.contains('\0') => self.last_id = Some(value.into_owned()),
            b"retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                self.event.retry = value.parse().ok();
            }
            _ => {}
        }
    }
}
