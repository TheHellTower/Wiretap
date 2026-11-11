use crate::hpack::{self, Field};
use crate::http2::{Decoder, Event, MAX_CONTROL, PREFACE};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fields(list: &[(&str, &str)]) -> Vec<Field> {
    list.iter().map(|&(n, v)| (n.into(), v.into())).collect()
}

/// RFC 7541 Appendix C, extracted from the RFC text: each group shares one decoder (one
/// connection); C.3/C.4 are requests (plain and Huffman), C.5/C.6 responses with a 256-byte
/// table, so entries are evicted. After C.3.3/C.4.3 the table holds 164 bytes, after
/// C.5.3/C.6.3 215 bytes (as the RFC states).
#[test]
fn rfc7541_appendix_c_examples_decode() {
    type Vector = (&'static str, &'static [(&'static str, &'static str)]);
    let requests: [Vector; 3] = [
        (
            "828684410f7777772e6578616d706c652e636f6d",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
        ),
        (
            "828684be58086e6f2d6361636865",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ],
        ),
        (
            "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ],
        ),
    ];
    let huffman_requests: [&str; 3] = [
        "828684418cf1e3c2e5f23a6ba0ab90f4ff",
        "828684be5886a8eb10649cbf",
        "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
    ];
    let responses: [Vector; 3] = [
        (
            "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        ),
        (
            "4803333037c1c0bf",
            &[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        ),
        (
            "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
            &[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
                (
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
                ),
            ],
        ),
    ];
    let huffman_responses: [&str; 3] = [
        "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        "4883640effc1c0bf",
        "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
    ];
    for (blocks, expected, limit, size) in [
        (requests.map(|r| r.0), requests.map(|r| r.1), 4096, 164),
        (huffman_requests, requests.map(|r| r.1), 4096, 164),
        (responses.map(|r| r.0), responses.map(|r| r.1), 256, 215),
        (huffman_responses, responses.map(|r| r.1), 256, 215),
    ] {
        let mut decoder = hpack::Decoder::new(limit);
        for (block, want) in blocks.iter().zip(expected) {
            assert_eq!(
                decoder.decode(&hex(block), 512, 1 << 20).unwrap(),
                fields(want),
                "{block}"
            );
        }
        assert_eq!(decoder.table_size(), size);
    }
}

#[test]
fn hpack_rejects_malformed_blocks_and_bounds_output() {
    let mut d = hpack::Decoder::new(4096);
    assert!(d.decode(&[0x80], 512, 1024).is_err(), "index 0");
    assert!(d.decode(&[0xBE], 512, 1024).is_err(), "empty dynamic table");
    assert!(
        d.decode(&[0x41, 0x05, b'a'], 512, 1024).is_err(),
        "truncated string"
    );
    assert!(
        d.decode(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01], 512, 1024)
            .is_err(),
        "huge integer"
    );
    assert!(
        d.decode(&[0x3F, 0xE1, 0xFF, 0x03], 512, 1024).is_err(),
        "table above the limit"
    );
    // Huffman: EOS inside, padding of zeros, padding of 8 bits or more.
    assert!(
        d.decode(&[0x40, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x81, b'a'], 512, 1024)
            .is_err()
    );
    assert!(
        d.decode(&[0x40, 0x81, 0x00, 0x81, b'a'], 512, 1024)
            .is_err()
    );
    assert!(
        d.decode(&[0x40, 0x82, 0x1F, 0xFF, 0x81, b'a'], 512, 1024)
            .is_err()
    );
    // Output bounds keep the table in step: fields past the limit are decoded, not returned.
    let mut d = hpack::Decoder::new(4096);
    let block = hex("828684410f7777772e6578616d706c652e636f6d");
    assert_eq!(d.decode(&block, 2, 1 << 20).unwrap().len(), 2);
    assert_eq!(
        d.decode(&[0xBE], 512, 1024).unwrap(),
        fields(&[(":authority", "www.example.com")])
    );
    // Non-UTF-8 bytes are shown, not rejected.
    let mut d = hpack::Decoder::new(4096);
    let lossy = d
        .decode(&[0x00, 0x01, b'x', 0x01, 0xFF], 512, 1024)
        .unwrap();
    assert_eq!(lossy, fields(&[("x", "\u{FFFD}")]));
}

/// Encoded blocks decode to the same fields in any decoder state, and leave the state unchanged.
#[test]
fn hpack_literals_round_trip_without_touching_the_table() {
    let long = "x".repeat(300);
    let list = fields(&[
        (":status", "200"),
        ("content-type", "text/plain"),
        ("x-long", &long),
        ("", ""),
    ]);
    let mut d = hpack::Decoder::new(4096);
    let block = hex("828684410f7777772e6578616d706c652e636f6d"); // fills the table (RFC 7541 C.3.1)
    d.decode(&block, 512, 1 << 20).unwrap();
    let size = d.table_size();
    assert_eq!(d.decode(&hpack::encode(&list), 512, 1 << 20).unwrap(), list);
    assert_eq!(d.table_size(), size, "literals without indexing");
}

/// Test-only frame encoder.
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut out = vec![len[1], len[2], len[3], kind, flags];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A literal header field without indexing, new name (no Huffman).
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![0x00, u8::try_from(name.len()).unwrap()];
    out.extend_from_slice(name.as_bytes());
    out.push(u8::try_from(value.len()).unwrap());
    out.extend_from_slice(value.as_bytes());
    out
}

fn feed_all(decoder: &mut Decoder, bytes: &[u8], chunk: usize) -> Vec<Event> {
    bytes.chunks(chunk).flat_map(|c| decoder.feed(c)).collect()
}

/// Joins consecutive DATA parts of a stream (how a split changes the events, not their meaning).
fn merged(events: Vec<Event>) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::new();
    for e in events {
        if let (
            Some(Event::Data {
                stream: s,
                data,
                flow,
                end_stream,
            }),
            Event::Data {
                stream,
                data: more,
                flow: f,
                end_stream: end,
            },
        ) = (out.last_mut(), &e)
            && *s == *stream
            && !*end_stream
        {
            data.extend_from_slice(more);
            *flow += f;
            *end_stream = *end;
            continue;
        }
        out.push(e);
    }
    out
}

#[test]
fn http2_client_streams_decode_however_the_bytes_are_split() {
    let mut wire = PREFACE.to_vec();
    wire.extend(frame(4, 0, 0, &[0, 3, 0, 0, 0, 100])); // SETTINGS
    wire.extend(frame(8, 0, 0, &[0, 0, 0xFF, 0])); // WINDOW_UPDATE
    // Stream 1: HEADERS (padded, with priority) + CONTINUATION, then padded DATA with END_STREAM.
    let mut block = vec![0x82, 0x87]; // :method GET, :scheme https
    block.extend(literal(":path", "/api"));
    let (first, second) = block.split_at(3);
    let mut headers = vec![2]; // pad length
    headers.extend_from_slice(&[0x80, 0, 0, 0, 16]); // exclusive dependency, weight
    headers.extend_from_slice(first);
    headers.extend_from_slice(&[0, 0]);
    wire.extend(frame(1, 0x08 | 0x20, 1, &headers));
    wire.extend(frame(9, 0x04, 1, second));
    let mut data = vec![3];
    data.extend_from_slice(b"hello");
    data.extend_from_slice(&[0, 0, 0]);
    wire.extend(frame(0, 0x08 | 0x01, 1, &data));
    // Stream 3: HEADERS with END_STREAM (a GET), then a reset of stream 5 and an empty DATA end.
    wire.extend(frame(1, 0x05, 3, &[0x82, 0x86, 0x84]));
    wire.extend(frame(3, 0, 5, &8u32.to_be_bytes()));
    wire.extend(frame(0, 0x01, 7, &[]));
    wire.extend(frame(7, 0, 0, &[0, 0, 0, 3, 0, 0, 0, 0]));
    let expected = vec![
        Event::Settings(vec![(3, 100)]),
        Event::WindowUpdate {
            stream: 0,
            increment: 0xFF00,
        },
        Event::Headers {
            stream: 1,
            fields: fields(&[(":method", "GET"), (":scheme", "https"), (":path", "/api")]),
            end_stream: false,
        },
        Event::Data {
            stream: 1,
            data: b"hello".to_vec(),
            flow: 9, // pad length, data and padding
            end_stream: true,
        },
        Event::Headers {
            stream: 3,
            fields: fields(&[(":method", "GET"), (":scheme", "http"), (":path", "/")]),
            end_stream: true,
        },
        Event::Reset { stream: 5, code: 8 },
        Event::Data {
            stream: 7,
            data: Vec::new(),
            flow: 0,
            end_stream: true,
        },
        Event::GoAway { last: 3, code: 0 },
    ];
    for chunk in [wire.len(), 1, 2, 7, 10, 64] {
        let events = feed_all(&mut Decoder::new(true), &wire, chunk);
        assert_eq!(merged(events), expected, "chunk {chunk}");
    }
}

#[test]
fn http2_server_pushes_and_large_data_pass_through() {
    let mut wire = frame(4, 0, 0, &[]);
    // PUSH_PROMISE on stream 1 for stream 2.
    let mut promise = 2u32.to_be_bytes().to_vec();
    promise.extend_from_slice(&[0x82, 0x87, 0x85]); // GET https /index.html
    wire.extend(frame(5, 0x04, 1, &promise));
    // Response head with :status 200 (static index 8), then 40 KiB of DATA in three frames.
    wire.extend(frame(1, 0x04, 1, &[0x88]));
    let body: Vec<u8> = (0..40_960u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    for (i, part) in body.chunks(16_384).enumerate() {
        let flags = if (i + 1) * 16_384 >= body.len() {
            0x01
        } else {
            0
        };
        wire.extend(frame(0, flags, 1, part));
    }
    let events = merged(feed_all(&mut Decoder::new(false), &wire, 1000));
    assert_eq!(
        events,
        [
            Event::Settings(Vec::new()),
            Event::Promise {
                stream: 1,
                promised: 2,
                fields: fields(&[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":path", "/index.html")
                ]),
            },
            Event::Headers {
                stream: 1,
                fields: fields(&[(":status", "200")]),
                end_stream: false
            },
            Event::Data {
                stream: 1,
                data: body,
                flow: 40_960,
                end_stream: true
            },
        ]
    );
}

#[test]
fn http2_decoding_stops_on_malformed_input() {
    let error = |d: &mut Decoder, bytes: &[u8]| {
        let events = d.feed(bytes);
        assert!(matches!(events.last(), Some(Event::Error(_))), "{events:?}");
        assert!(
            d.feed(&frame(1, 0x05, 1, &[0x82])).is_empty(),
            "stopped for good"
        );
    };
    error(&mut Decoder::new(true), b"GET / HTTP/1.1\r\n\r\n");
    // A header block interrupted by another frame, a CONTINUATION out of place, bad HPACK.
    let mut wire = frame(1, 0, 1, &[0x82]);
    wire.extend(frame(4, 0, 0, &[]));
    error(&mut Decoder::new(false), &wire);
    error(&mut Decoder::new(false), &frame(9, 0x04, 1, &[0x82]));
    error(&mut Decoder::new(false), &frame(1, 0x04, 1, &[0x80]));
    error(&mut Decoder::new(false), &frame(1, 0x0C, 1, &[200, 0x82]));
    // Non-DATA frames above the decoding limit are not buffered.
    let len = u32::try_from(MAX_CONTROL + 1).unwrap().to_be_bytes();
    error(
        &mut Decoder::new(false),
        &[len[1], len[2], len[3], 1, 0, 0, 0, 0, 1],
    );
    // A partial preface is fine; the rest is checked when it arrives.
    let mut d = Decoder::new(true);
    assert!(d.feed(&PREFACE[..10]).is_empty());
    assert!(d.feed(&PREFACE[10..]).is_empty());
}
