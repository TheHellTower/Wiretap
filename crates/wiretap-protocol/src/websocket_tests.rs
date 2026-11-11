#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::websocket::{Decoder, Deflate, Extensions, Message, Opcode, Sender};

const LIMIT: usize = 1 << 20;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b.trim_start_matches("0x"), 16).unwrap())
        .collect()
}

/// One frame: `first` is the FIN/RSV/opcode byte; `mask` masks the payload as a client would.
fn frame(first: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut f = vec![first];
    let m = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n @ 0..=125 => f.push(m | u8::try_from(n).unwrap()),
        n @ 126..=65535 => {
            f.push(m | 126);
            f.extend(u16::try_from(n).unwrap().to_be_bytes());
        }
        n => {
            f.push(m | 127);
            f.extend((n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            f.extend(key);
            f.extend(payload.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k));
        }
        None => f.extend_from_slice(payload),
    }
    f
}

fn decode(sender: Sender, ext: Extensions, bytes: &[u8]) -> Vec<Result<Message, &'static str>> {
    Decoder::new(sender, ext, LIMIT).feed(bytes)
}

fn messages(sender: Sender, ext: Extensions, bytes: &[u8]) -> Vec<Message> {
    decode(sender, ext, bytes)
        .into_iter()
        .map(Result::unwrap)
        .collect()
}

fn summary(m: &Message) -> (Opcode, &[u8], Option<&str>) {
    (m.opcode, m.payload.as_slice(), m.problem)
}

/// RFC 6455 section 5.7.
#[test]
fn rfc6455_examples() {
    let none = Extensions::default();
    let hello = messages(Sender::Server, none, &hex("81 05 48 65 6c 6c 6f"));
    assert_eq!(summary(&hello[0]), (Opcode::Text, &b"Hello"[..], None));
    let masked = messages(
        Sender::Client,
        none,
        &hex("81 85 37 fa 21 3d 7f 9f 4d 51 58"),
    );
    assert_eq!(summary(&masked[0]), (Opcode::Text, &b"Hello"[..], None));
    let fragmented = messages(Sender::Server, none, &hex("01 03 48 65 6c 80 02 6c 6f"));
    assert_eq!((fragmented.len(), fragmented[0].frames), (1, 2));
    assert_eq!(summary(&fragmented[0]), (Opcode::Text, &b"Hello"[..], None));
    let ping = messages(Sender::Server, none, &hex("89 05 48 65 6c 6c 6f"));
    assert_eq!(summary(&ping[0]), (Opcode::Ping, &b"Hello"[..], None));
    let pong = messages(
        Sender::Client,
        none,
        &hex("8a 85 37 fa 21 3d 7f 9f 4d 51 58"),
    );
    assert_eq!(summary(&pong[0]), (Opcode::Pong, &b"Hello"[..], None));
    // 16-bit and 64-bit lengths.
    for len in [126, 256, 65535, 65536, 70000] {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let m = messages(Sender::Server, none, &frame(0x82, &data, None));
        assert_eq!(
            (m[0].opcode, m[0].size, m[0].payload == data),
            (Opcode::Binary, len as u64, true)
        );
    }
}

/// Relayed bytes arrive in arbitrary pieces: decoding one byte at a time gives the same result.
#[test]
fn any_split_decodes_the_same() {
    let key = [1, 2, 3, 4];
    let mut stream = frame(0x01, b"Hel", Some(key));
    stream.extend(frame(0x89, b"ping", Some(key))); // control frame inside a fragmented message
    stream.extend(frame(0x00, b"lo \xE2\x82", Some(key))); // a UTF-8 character split across frames
    stream.extend(frame(0x80, b"\xAC", Some(key)));
    stream.extend(frame(0x82, &[0; 300], Some(key)));
    stream.extend(frame(0x88, b"\x03\xE8bye", Some(key)));
    let whole = decode(Sender::Client, Extensions::default(), &stream);
    let mut decoder = Decoder::new(Sender::Client, Extensions::default(), LIMIT);
    let pieces: Vec<_> = stream
        .iter()
        .flat_map(|b| decoder.feed(std::slice::from_ref(b)))
        .collect();
    assert_eq!(whole, pieces);
    let kinds: Vec<_> = whole.iter().map(|m| m.as_ref().unwrap().opcode).collect();
    assert_eq!(
        kinds,
        [Opcode::Ping, Opcode::Text, Opcode::Binary, Opcode::Close]
    );
    let text = whole[1].as_ref().unwrap();
    assert_eq!(
        (text.payload.as_slice(), text.frames, text.problem),
        ("Hello €".as_bytes(), 3, None)
    );
    assert_eq!(
        whole[3].as_ref().unwrap().close_status(),
        Some((1000, "bye"))
    );
}

#[test]
fn close_and_text_payloads_are_checked() {
    let none = Extensions::default();
    let empty = messages(Sender::Server, none, &hex("88 00"));
    assert_eq!((empty[0].close_status(), empty[0].problem), (None, None));
    let one = messages(Sender::Server, none, &hex("88 01 03"));
    assert_eq!(one[0].problem, Some("close payload of one byte"));
    let bad_reason = messages(Sender::Server, none, &frame(0x88, b"\x03\xE8\xFF", None));
    assert_eq!(bad_reason[0].problem, Some("invalid UTF-8 text"));
    let bad_text = messages(Sender::Server, none, &frame(0x81, b"\xC3\x28", None));
    assert_eq!(bad_text[0].problem, Some("invalid UTF-8 text"));
    // Binary data is never checked.
    assert_eq!(
        messages(Sender::Server, none, &frame(0x82, b"\xFF", None))[0].problem,
        None
    );
}

#[test]
fn protocol_violations_end_decoding() {
    let none = Extensions::default();
    let key = Some([9, 9, 9, 9]);
    let cases: [(Sender, Vec<u8>, &str); 9] = [
        (Sender::Server, frame(0x83, b"x", None), "reserved opcode"),
        (Sender::Server, frame(0xA1, b"x", None), "reserved bits set"),
        (Sender::Server, frame(0xC1, b"x", None), "reserved bits set"), // no permessage-deflate agreed
        (
            Sender::Client,
            frame(0x81, b"x", None),
            "client frame is not masked",
        ),
        (
            Sender::Server,
            frame(0x81, b"x", key),
            "server frame is masked",
        ),
        (
            Sender::Server,
            frame(0x89, &[0; 126], None),
            "control frame longer than 125 bytes",
        ),
        (
            Sender::Server,
            frame(0x09, b"x", None),
            "fragmented control frame",
        ),
        (
            Sender::Server,
            frame(0x80, b"x", None),
            "continuation without a message",
        ),
        (
            Sender::Server,
            [frame(0x01, b"a", None), frame(0x81, b"b", None)].concat(),
            "new message before the previous one ended",
        ),
    ];
    for (sender, bytes, error) in cases {
        let mut d = Decoder::new(sender, none, LIMIT);
        assert_eq!(d.feed(&bytes), [Err(error)], "{error}");
        assert!(
            d.feed(&frame(0x81, b"later", None)).is_empty(),
            "{error}: decoding stopped"
        );
    }
    let huge = hex("82 7f 80 00 00 00 00 00 00 00");
    assert_eq!(
        decode(Sender::Server, none, &huge),
        [Err("frame length out of range")]
    );
}

#[test]
fn large_payloads_keep_a_prefix_and_their_size() {
    let mut d = Decoder::new(Sender::Server, Extensions::default(), 10);
    let m = d.feed(&frame(0x82, &[7; 1000], None)).remove(0).unwrap();
    assert_eq!(
        (m.payload.len(), m.size, m.problem),
        (10, 1000, Some("payload larger than the capture limit"))
    );
    // The stream stays in sync after the oversized message.
    assert_eq!(
        d.feed(&frame(0x81, b"ok", None)).remove(0).unwrap().payload,
        b"ok"
    );
}

/// RFC 7692 section 7.2.3.
#[test]
fn rfc7692_examples() {
    let deflate = Extensions {
        deflate: Some(Deflate::default()),
        other: false,
    };
    for (example, bytes) in [
        ("one block", "c1 07 f2 48 cd c9 c9 07 00"),
        ("two fragments", "41 03 f2 48 cd 80 04 c9 c9 07 00"),
        ("stored block", "c1 0b 00 05 00 fa ff 48 65 6c 6c 6f 00"),
        ("BFINAL set", "c1 08 f3 48 cd c9 c9 07 00 00"),
        ("two blocks", "c1 0d f2 48 05 00 00 00 ff ff ca c9 c9 07 00"),
        (
            "empty last fragment",
            "41 0b f2 48 cd c9 c9 07 00 00 00 ff ff 80 01 00",
        ),
    ] {
        let m = messages(Sender::Server, deflate, &hex(bytes));
        assert_eq!(
            summary(&m[0]),
            (Opcode::Text, &b"Hello"[..], None),
            "{example}"
        );
        assert!(m[0].compressed, "{example}");
    }
    // Sharing the LZ77 window: the second "Hello" refers to the first one.
    let shared = hex("c1 07 f2 48 cd c9 c9 07 00 c1 05 f2 00 11 00 00");
    let both = messages(Sender::Server, deflate, &shared);
    assert_eq!(
        (summary(&both[1]), both[1].wire_size, both[1].size),
        ((Opcode::Text, &b"Hello"[..], None), 5, 5)
    );
    // With server_no_context_takeover each message stands alone, so that reference is invalid.
    let alone = Extensions {
        deflate: Some(Deflate {
            server_no_context_takeover: true,
            ..Deflate::default()
        }),
        other: false,
    };
    assert_eq!(
        messages(Sender::Server, alone, &shared)[1].problem,
        Some("invalid compressed data")
    );
    // Control frames and continuations never carry the compression bit.
    assert_eq!(
        decode(Sender::Server, deflate, &frame(0xC9, b"", None)),
        [Err("reserved bits set")]
    );
}

#[test]
fn extension_negotiation() {
    assert_eq!(Extensions::parse(""), Extensions::default());
    let agreed = Extensions::parse(
        "permessage-deflate; client_no_context_takeover; server_max_window_bits=10",
    );
    let expected = Deflate {
        client_no_context_takeover: true,
        server_no_context_takeover: false,
    };
    assert_eq!(
        agreed,
        Extensions {
            deflate: Some(expected),
            other: false
        }
    );
    let both = Extensions::parse("PerMessage-Deflate;Server_No_Context_Takeover, x-custom");
    assert!(both.other && both.deflate.is_some_and(|d| d.server_no_context_takeover));
    // With an unknown extension agreed, its reserved bits are tolerated and flagged.
    let foreign = Extensions {
        deflate: None,
        other: true,
    };
    let m = messages(Sender::Server, foreign, &frame(0xE1, b"?", None));
    assert_eq!(
        m[0].problem,
        Some("uses an extension Wiretap does not decode")
    );
}
