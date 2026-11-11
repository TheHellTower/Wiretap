//! gRPC and protobuf decoding against the official documents: grpc/grpc `doc/PROTOCOL-HTTP2.md`,
//! `doc/PROTOCOL-WEB.md` and the examples of protobuf.dev "Encoding".

use crate::grpc::{Decoder, Framing, Message, describe, percent_decode, protobuf_text, status};

fn frame(flag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![flag];
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn all(decoder: &mut Decoder, input: &[u8]) -> Vec<Result<Message, &'static str>> {
    decoder.feed(input)
}

#[test]
fn content_types_name_the_framing_and_format() {
    assert_eq!(
        Framing::of("application/grpc"),
        Some((Framing::Grpc, false))
    );
    assert_eq!(
        Framing::of("Application/GRPC+proto"),
        Some((Framing::Grpc, false))
    );
    assert_eq!(
        Framing::of("application/grpc+json; charset=utf-8"),
        Some((Framing::Grpc, true))
    );
    assert_eq!(
        Framing::of("application/grpc-web"),
        Some((Framing::Web, false))
    );
    assert_eq!(
        Framing::of("application/grpc-web-text+proto"),
        Some((Framing::WebText, false))
    );
    assert_eq!(Framing::of("application/grpcx"), None);
    assert_eq!(Framing::of("application/json"), None);
}

#[test]
fn length_prefixed_messages_survive_any_split() {
    let mut wire = frame(0, b"\x08\x96\x01");
    wire.extend(frame(1, b"zz"));
    wire.extend(frame(0, b""));
    let whole = all(&mut Decoder::new(Framing::Grpc, 1024), &wire);
    assert_eq!(whole.len(), 3);
    let first = whole[0].as_ref().unwrap();
    assert_eq!(
        (first.compressed, first.size, &first.data[..]),
        (false, 3, &b"\x08\x96\x01"[..])
    );
    assert!(whole[1].as_ref().unwrap().compressed);
    assert_eq!(whole[2].as_ref().unwrap().size, 0);
    let mut d = Decoder::new(Framing::Grpc, 1024);
    let bytewise: Vec<_> = wire.iter().flat_map(|b| d.feed(&[*b])).collect();
    assert_eq!(bytewise, whole);
    assert!(d.at_boundary());
}

#[test]
fn messages_beyond_the_limit_are_counted_not_kept() {
    let out = all(
        &mut Decoder::new(Framing::Grpc, 4),
        &frame(0, b"0123456789"),
    );
    let m = out[0].as_ref().unwrap();
    assert_eq!((m.size, &m.data[..]), (10, &b"0123"[..]));
}

#[test]
fn bad_flags_end_decoding() {
    // gRPC flags are 0 or 1; the trailers bit exists only in gRPC-Web.
    let out = all(&mut Decoder::new(Framing::Grpc, 64), &frame(0x80, b""));
    assert!(matches!(out[..], [Err(_)]));
    let mut d = Decoder::new(Framing::Web, 64);
    assert!(matches!(d.feed(&frame(0x02, b""))[..], [Err(_)]));
    assert!(d.feed(&frame(0, b"x")).is_empty(), "nothing after an error");
}

#[test]
fn grpc_web_trailers_frame_carries_the_status() {
    let mut wire = frame(0, b"\x08\x01");
    wire.extend(frame(
        0x80,
        b"grpc-status: 5\r\ngrpc-message: Not%20found%3A x",
    ));
    let out = all(&mut Decoder::new(Framing::Web, 1024), &wire);
    let trailers = out[1].as_ref().unwrap();
    assert!(trailers.trailers && !out[0].as_ref().unwrap().trailers);
    let fields = crate::grpc::trailer_fields(&trailers.data);
    let s = status(fields.iter().map(|(n, v)| (n.as_str(), v.as_str()))).unwrap();
    assert_eq!(s["status"], "5 NOT_FOUND");
    assert_eq!(s["grpc-message"], "Not found: x");
}

#[test]
fn grpc_web_text_is_base64_in_chunks_with_padding_anywhere() {
    use std::fmt::Write as _;
    // Each message is encoded on its own, padding included, as servers flush them.
    let b64 = |bytes: &[u8]| {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in bytes.chunks(3) {
            let n = u32::from(chunk[0]) << 16
                | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= chunk.len() {
                    s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    };
    let mut text = String::new();
    let _ = write!(text, "{}", b64(&frame(0, b"\x12\x01h")));
    let _ = write!(text, "{}", b64(&frame(0x80, b"grpc-status: 0")));
    assert!(
        text[..text.len() / 2].contains('='),
        "padding mid-stream: {text}"
    );
    let mut d = Decoder::new(Framing::WebText, 1024);
    let out: Vec<_> = text.as_bytes().chunks(5).flat_map(|c| d.feed(c)).collect();
    assert_eq!(out.len(), 2, "{out:?}");
    assert_eq!(out[0].as_ref().unwrap().data, b"\x12\x01h");
    assert!(out[1].as_ref().unwrap().trailers);
    assert!(matches!(
        Decoder::new(Framing::WebText, 9).feed(b"A=BC")[..],
        [Err(_)]
    ));
}

#[test]
fn statuses_and_messages_follow_the_spec() {
    assert_eq!(
        percent_decode("caf%C3%A9 %zz%2"),
        "café %zz%2",
        "bad escapes kept"
    );
    let ok = status([("grpc-status", "0")]).unwrap();
    assert_eq!(ok["status"], "0 OK");
    assert_eq!(status([("grpc-status", "99")]).unwrap()["status"], "99");
    assert!(
        status([("grpc-message", "x")]).is_none(),
        "no status, no call result"
    );
}

#[test]
fn protobuf_examples_from_the_encoding_guide() {
    // protobuf.dev "Encoding": Test1.a = 150, Test2.b = "testing", Test3.c = Test1, packed
    // repeated int32 [3, 270, 86942].
    assert_eq!(protobuf_text(b"\x08\x96\x01", 1024).unwrap(), "1: 150\n");
    assert_eq!(
        protobuf_text(b"\x12\x07\x74\x65\x73\x74\x69\x6e\x67", 1024).unwrap(),
        "2: \"testing\"\n"
    );
    assert_eq!(
        protobuf_text(b"\x1a\x03\x08\x96\x01", 1024).unwrap(),
        "3: {\n  1: 150\n}\n"
    );
    assert_eq!(
        protobuf_text(b"\x32\x06\x03\x8e\x02\x9e\xa7\x05", 1024).unwrap(),
        "6: 0x038e029ea705\n",
        "packed values cannot be told apart from bytes without the schema"
    );
    // int32 -2: ten bytes of two's complement.
    let minus_two = b"\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01";
    assert_eq!(
        protobuf_text(minus_two, 1024).unwrap(),
        "1: 18446744073709551614 (-2)\n"
    );
    // Fixed-width fields, a group, the empty message.
    assert_eq!(
        protobuf_text(b"\x0d\x00\x00\x80\x3f\x0b\x08\x01\x0c", 1024).unwrap(),
        "1: 0x3f800000 (1)\n1: group {\n  1: 1\n}\n"
    );
    assert_eq!(protobuf_text(b"", 1024).unwrap(), "");
}

#[test]
fn malformed_protobuf_is_not_shown_as_a_message() {
    for bad in [
        &b"\x0b\x08\x01\x14"[..], // group ended by another field number
        b"\x0c",                  // EGROUP without SGROUP
        b"\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f", // varint beyond 64 bits
        b"\x12\x05ab",            // LEN past the end
        b"\x00\x01",              // field number 0
        b"\x0e",                  // wire type 6
    ] {
        assert!(protobuf_text(bad, 1024).is_none(), "{bad:02x?}");
    }
    let deep = [b"\x0a\x00".to_vec(), vec![0x0b; 40]].concat();
    assert!(
        protobuf_text(&deep, 1024).is_none(),
        "groups deeper than the limit"
    );
    let long = protobuf_text(&b"\x08\x01".repeat(1000), 100).unwrap();
    assert!(long.len() < 120 && long.ends_with('…'));
}

#[test]
fn messages_are_decompressed_and_described() {
    // A gzip member with one stored DEFLATE block, as RFC 1952 and RFC 1951 define them.
    let body = b"\x08\x96\x01";
    let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1, 3, 0, 0xfc, 0xff];
    gz.extend_from_slice(body);
    gz.extend_from_slice(&wiretap_codec::crc32(body).to_le_bytes());
    gz.extend_from_slice(&3u32.to_le_bytes());
    let message = Message {
        compressed: true,
        trailers: false,
        size: gz.len() as u64,
        data: gz,
    };
    let (a, payload) = describe(&message, "gzip", false, 1024);
    assert_eq!(payload, b"1: 150\n", "the view is the payload");
    assert_eq!(
        (a["compressed"].as_str(), a["preview"].as_str()),
        ("gzip", "1: 150")
    );
    let (a, _) = describe(&message, "snappy", false, 1024);
    assert!(a.contains_key("error") && a["shown"] == "bytes", "{a:?}");
    let json = Message {
        size: 9,
        data: br#"{"a":150}"#.to_vec(),
        ..Message::default()
    };
    assert_eq!(describe(&json, "", true, 1024).1, br#"{"a":150}"#);
}

/// Regression (fuzz `grpc`, CI 2026-11-10): base64 decoding stops at a bad character, and the
/// messages before it are delivered, in one chunk as when split.
#[test]
fn bad_base64_still_delivers_the_messages_before_it() {
    let body = b"AAAAAAMIARA=g*AAAA";
    let whole = Decoder::new(Framing::WebText, 64).feed(body);
    let mut d = Decoder::new(Framing::WebText, 64);
    let mut split = d.feed(&body[..12]);
    split.extend(d.feed(&body[12..]));
    assert_eq!(whole, split);
    assert_eq!(whole[0].as_ref().unwrap().data, b"\x08\x01\x10");
    assert!(whole[1].is_err());
}
