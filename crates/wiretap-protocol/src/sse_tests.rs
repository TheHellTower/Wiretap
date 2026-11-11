use crate::sse::{Decoder, Event};

fn event(kind: &str, data: &str, id: Option<&str>) -> Event {
    Event {
        kind: kind.into(),
        data: data.into(),
        size: data.len() as u64,
        id: id.map(Into::into),
        retry: None,
    }
}

/// The examples of WHATWG HTML 9.2.6 (Interpreting an event stream).
#[test]
fn whatwg_examples() {
    let stocks = Decoder::new(1 << 20).feed(b"data: YHOO\ndata: +2\ndata: 10\n\n");
    assert_eq!(stocks, [event("", "YHOO\n+2\n10", None)]);
    let ids = Decoder::new(1 << 20).feed(
        b": test stream\n\ndata: first event\nid: 1\n\ndata:second event\nid\n\ndata:  third event\n",
    );
    assert_eq!(
        ids,
        [
            event("", "first event", Some("1")),
            event("", "second event", Some(""))
        ],
        "the last event has no blank line: not dispatched"
    );
    let empty = Decoder::new(1 << 20).feed(b"data\n\ndata\ndata\n\ndata:");
    assert_eq!(empty, [event("", "", None), event("", "\n", None)]);
    let spaces = Decoder::new(1 << 20).feed(b"data:test\n\ndata: test\n\n");
    assert_eq!(spaces, [event("", "test", None), event("", "test", None)]);
}

#[test]
fn line_ends_fields_and_splits() {
    let stream =
        b"\xEF\xBB\xBFevent: update\r\ndata: a\rdata: b\r\nretry: 3000\nid: 7\n\r\ndata: x\n\n";
    let expected = vec![
        Event {
            retry: Some(3000),
            ..event("update", "a\nb", Some("7"))
        },
        event("", "x", Some("7")), // the id persists, the type and retry do not
    ];
    for size in [stream.len(), 1, 2, 3] {
        let mut d = Decoder::new(1 << 20);
        let got: Vec<Event> = stream.chunks(size).flat_map(|c| d.feed(c)).collect();
        assert_eq!(got, expected, "chunks of {size}");
    }
    let attributes = expected[0].attributes();
    assert_eq!(attributes.get("event").map(String::as_str), Some("update"));
    assert_eq!(attributes.get("retry").map(String::as_str), Some("3000"));
    assert_eq!(
        expected[1].attributes().get("event").map(String::as_str),
        Some("message")
    );
}

#[test]
fn data_is_bounded_but_counted() {
    let mut d = Decoder::new(8);
    let big = d.feed(b"data: 0123456789abcdef\ndata: more\n\n");
    assert_eq!(big.len(), 1);
    assert!(big[0].data.len() <= 8, "{:?}", big[0].data);
    assert_eq!(big[0].size, 16 + 1 + 4);
    // A line that never ends stays bounded.
    let mut d = Decoder::new(16);
    for _ in 0..1000 {
        assert!(d.feed(&[b'a'; 1024]).is_empty());
    }
    assert_eq!(
        d.feed(b"\n\n"),
        Vec::<Event>::new(),
        "an unknown field, nothing dispatched"
    );
}
