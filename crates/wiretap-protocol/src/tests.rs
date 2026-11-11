use wiretap_core::HttpVersion;

use super::*;

fn complete<T: std::fmt::Debug>(p: Parse<T>) -> T {
    match p {
        Parse::Complete(v) => v,
        other => panic!("expected complete, got {other:?}"),
    }
}

#[test]
fn parses_request_head() {
    let raw =
        b"GET /search?q=rust HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nX-Empty:\r\n\r\nBODY";
    let head = complete(parse_head(raw));
    assert_eq!(head.len, raw.len() - 4);
    assert_eq!(
        head.start,
        StartLine::Request {
            method: "GET".into(),
            target: "/search?q=rust".into(),
            version: HttpVersion::Http11
        }
    );
    assert_eq!(head.header("host"), Some("example.com"));
    assert_eq!(head.header("x-empty"), Some(""));
    assert_eq!(head.headers.len(), 3);
}

#[test]
fn parses_response_head() {
    let head = complete(parse_head(
        b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    ));
    assert_eq!(
        head.start,
        StartLine::Response {
            status: 404,
            reason: "Not Found".into(),
            version: HttpVersion::Http10
        }
    );
    let head = complete(parse_head(b"HTTP/1.1 204 \r\n\r\n"));
    assert!(matches!(
        head.start,
        StartLine::Response { status: 204, .. }
    ));
}

#[test]
fn partial_and_invalid_heads() {
    assert_eq!(parse_head(b"GET / HTTP/1.1\r\nHost: a"), Parse::Partial);
    assert_eq!(parse_head(b""), Parse::Partial);
    for raw in [
        &b"GET / HTTP/2\r\n\r\n"[..],                 // unsupported version
        b"GET  / HTTP/1.1\r\n\r\n",                   // empty target
        b"G(T / HTTP/1.1\r\n\r\n",                    // non-token method
        b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n",     // space in field name
        b"GET / HTTP/1.1\r\nX: a\x01b\r\n\r\n",       // control character
        b"GET / HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", // obsolete line folding
        b"GET / HTTP/1.1\nX: a\r\n\r\n",              // bare LF
        b"HTTP/1.1 20 OK\r\n\r\n",                    // two-digit status
        b"HTTP/1.1 099 Low\r\n\r\n",                  // status below 100
        b"\x16\x03\x01\x00\x05hello\r\n\r\n",         // TLS, not HTTP
    ] {
        assert_eq!(
            parse_head(raw),
            Parse::Invalid,
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }
    let huge = vec![b'a'; MAX_HEAD + 1];
    assert_eq!(parse_head(&huge), Parse::Invalid);
}

#[test]
fn header_count_is_bounded() {
    let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
    for _ in 0..=wiretap_core::limits::HEADERS {
        raw.extend_from_slice(b"X: y\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    assert_eq!(parse_head(&raw), Parse::Invalid);
}

#[test]
fn body_framing_rules() {
    let req = |extra: &str| {
        complete(parse_head(
            format!("POST / HTTP/1.1\r\nHost: a\r\n{extra}\r\n").as_bytes(),
        ))
    };
    let resp = |status: &str, extra: &str| {
        complete(parse_head(
            format!("HTTP/1.1 {status}\r\n{extra}\r\n").as_bytes(),
        ))
    };
    assert_eq!(framing(&req(""), None), Some(Framing::Empty));
    assert_eq!(
        framing(&req("Content-Length: 12\r\n"), None),
        Some(Framing::Length(12))
    );
    assert_eq!(
        framing(&req("Content-Length: 5\r\nContent-Length: 5\r\n"), None),
        Some(Framing::Length(5))
    );
    assert_eq!(
        framing(&req("Content-Length: 5\r\nContent-Length: 6\r\n"), None),
        None,
        "conflicting lengths"
    );
    assert_eq!(framing(&req("Content-Length: +5\r\n"), None), None);
    assert_eq!(
        framing(&req("Transfer-Encoding: gzip, chunked\r\n"), None),
        Some(Framing::Chunked)
    );
    assert_eq!(
        framing(
            &req("Transfer-Encoding: chunked\r\nContent-Length: 3\r\n"),
            None
        ),
        None,
        "smuggling"
    );
    assert_eq!(framing(&req("Transfer-Encoding: gzip\r\n"), None), None);
    assert_eq!(
        framing(&resp("200 OK", ""), Some("GET")),
        Some(Framing::UntilClose)
    );
    assert_eq!(
        framing(&resp("200 OK", "Content-Length: 3\r\n"), Some("HEAD")),
        Some(Framing::Empty)
    );
    assert_eq!(
        framing(
            &resp("304 Not Modified", "Content-Length: 3\r\n"),
            Some("GET")
        ),
        Some(Framing::Empty)
    );
    assert_eq!(
        framing(&resp("100 Continue", ""), Some("POST")),
        Some(Framing::Empty)
    );
}

/// Builds a TLS record carrying a ClientHello with the given extensions.
fn client_hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut ext = Vec::new();
    for (kind, data) in extensions {
        ext.extend_from_slice(&kind.to_be_bytes());
        ext.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        ext.extend_from_slice(data);
    }
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[7; 32]);
    hello.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    hello.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
    hello.extend_from_slice(&ext);
    let len = u32::try_from(hello.len()).unwrap().to_be_bytes();
    let mut handshake = vec![1, len[1], len[2], len[3]];
    handshake.extend_from_slice(&hello);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn sni(name: &[u8]) -> (u16, Vec<u8>) {
    let mut entry = vec![0];
    entry.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
    entry.extend_from_slice(name);
    let mut list = u16::try_from(entry.len()).unwrap().to_be_bytes().to_vec();
    list.extend_from_slice(&entry);
    (0, list)
}

fn alpn(protocols: &[&str]) -> (u16, Vec<u8>) {
    let mut entries = Vec::new();
    for p in protocols {
        entries.push(u8::try_from(p.len()).unwrap());
        entries.extend_from_slice(p.as_bytes());
    }
    let mut list = u16::try_from(entries.len()).unwrap().to_be_bytes().to_vec();
    list.extend_from_slice(&entries);
    (16, list)
}

#[test]
fn extracts_server_name_and_alpn() {
    let record = client_hello(&[
        (0x2b, vec![2, 3, 4]),
        sni(b"WWW.Example.com"),
        alpn(&["h2", "http/1.1"]),
    ]);
    let hello = complete(parse_client_hello(&record));
    assert_eq!(hello.server_name.as_deref(), Some("www.example.com"));
    assert_eq!(hello.alpn, ["h2", "http/1.1"]);
    // Every strict prefix is a valid partial record.
    for cut in 0..record.len() {
        assert_eq!(
            parse_client_hello(&record[..cut]),
            Parse::Partial,
            "cut at {cut}"
        );
    }
}

#[test]
fn rejects_malformed_hellos() {
    let bad_name = complete(parse_client_hello(&client_hello(&[sni(
        b"evil\x1b[2J.com",
    )])));
    assert_eq!(bad_name.server_name, None, "non-LDH names are dropped");
    assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\n"), Parse::Invalid);
    let mut wrong_type = client_hello(&[]);
    wrong_type[5] = 2; // ServerHello
    assert_eq!(parse_client_hello(&wrong_type), Parse::Invalid);
    let mut overlong = client_hello(&[sni(b"a.com")]);
    let last = overlong.len() - 1;
    overlong[last - 6] = 0xFF; // corrupt an inner length
    assert!(matches!(
        parse_client_hello(&overlong),
        Parse::Invalid | Parse::Complete(_)
    ));
    assert_eq!(
        parse_client_hello(&[22, 3, 1, 0xFF, 0xFF]),
        Parse::Invalid,
        "record above limit"
    );
}

fn server_hello(legacy: u16, cipher: u16, extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut ext = Vec::new();
    for (kind, data) in extensions {
        ext.extend_from_slice(&kind.to_be_bytes());
        ext.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        ext.extend_from_slice(data);
    }
    let mut hello = legacy.to_be_bytes().to_vec();
    hello.extend_from_slice(&[9; 32]);
    hello.push(0);
    hello.extend_from_slice(&cipher.to_be_bytes());
    hello.push(0);
    hello.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
    hello.extend_from_slice(&ext);
    let len = u32::try_from(hello.len()).unwrap().to_be_bytes();
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&u16::try_from(hello.len() + 4).unwrap().to_be_bytes());
    record.extend_from_slice(&[2, len[1], len[2], len[3]]);
    record.extend_from_slice(&hello);
    record
}

#[test]
fn reports_offered_versions_from_tls10_to_tls13() {
    // TLS 1.3 client: supported_versions with a GREASE value first.
    let versions = (43u16, vec![6, 0x5A, 0x5A, 0x03, 0x04, 0x03, 0x03]);
    let hello = complete(parse_client_hello(&client_hello(&[versions])));
    assert_eq!(hello.versions, [0x0304, 0x0303]);
    // Legacy client without supported_versions: legacy_version (0x0303 in the builder).
    let hello = complete(parse_client_hello(&client_hello(&[])));
    assert_eq!(hello.versions, [0x0303]);
    for (v, name) in [
        (0x0300, "SSL 3.0"),
        (0x0301, "TLS 1.0"),
        (0x0302, "TLS 1.1"),
        (0x0303, "TLS 1.2"),
        (0x0304, "TLS 1.3"),
    ] {
        assert_eq!(version_name(v), Some(name));
    }
    assert_eq!(version_name(0x7F1C), None);
}

#[test]
fn reports_negotiated_version_cipher_and_alpn() {
    let tls13 = server_hello(0x0303, 0x1301, &[(43, vec![0x03, 0x04])]);
    assert_eq!(
        complete(parse_server_hello(&tls13)),
        ServerHello {
            version: 0x0304,
            cipher_suite: 0x1301,
            alpn: None
        }
    );
    let tls12 = server_hello(0x0303, 0xC02F, &[alpn(&["h2"])]);
    assert_eq!(
        complete(parse_server_hello(&tls12)).alpn.as_deref(),
        Some("h2")
    );
    let tls10 = server_hello(0x0301, 0x002F, &[]);
    assert_eq!(complete(parse_server_hello(&tls10)).version, 0x0301);
    assert_eq!(
        parse_server_hello(&client_hello(&[])),
        Parse::Invalid,
        "a ClientHello is not a ServerHello"
    );
}

/// A DER element (long-form lengths when needed).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n @ 0..0x80 => out.push(u8::try_from(n).unwrap()),
        n @ 0x80..0x100 => out.extend_from_slice(&[0x81, u8::try_from(n).unwrap()]),
        n => out.extend(
            [0x82]
                .into_iter()
                .chain(u16::try_from(n).unwrap().to_be_bytes()),
        ),
    }
    out.extend_from_slice(content);
    out
}

/// A distinguished name: `(oid, string tag, value)` attributes, one per RDN.
fn dn(parts: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
    let rdns: Vec<u8> = parts
        .iter()
        .flat_map(|(oid, kind, value)| {
            let pair = [tlv(0x06, oid), tlv(*kind, value)].concat();
            tlv(0x31, &tlv(0x30, &pair))
        })
        .collect();
    tlv(0x30, &rdns)
}

const CN: &[u8] = &[0x55, 4, 3];
const O: &[u8] = &[0x55, 4, 10];

/// The leading fields of an X.509 certificate (all the parser reads), with a fake signature.
fn cert(issuer: &[u8], subject: &[u8], validity: [(u8, &str); 2]) -> Vec<u8> {
    let tbs = [
        tlv(0xA0, &tlv(0x02, &[2])),                                     // v3
        tlv(0x02, &[0x01, 0x23]),                                        // serial
        tlv(0x30, &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 4, 3, 2])), // ecdsa-with-SHA256
        issuer.to_vec(),
        tlv(
            0x30,
            &[
                tlv(validity[0].0, validity[0].1.as_bytes()),
                tlv(validity[1].0, validity[1].1.as_bytes()),
            ]
            .concat(),
        ),
        subject.to_vec(),
        tlv(0x30, &[0; 40]), // subject public key info (not read)
    ]
    .concat();
    tlv(
        0x30,
        &[tlv(0x30, &tbs), tlv(0x30, &[]), tlv(0x03, &[0])].concat(),
    )
}

/// A handshake message.
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    [&[kind, len[1], len[2], len[3]][..], body].concat()
}

/// Handshake `bytes` split into records of at most `size` bytes.
fn records(bytes: &[u8], size: usize) -> Vec<u8> {
    bytes
        .chunks(size)
        .flat_map(|c| {
            [
                &[22, 3, 3][..],
                &u16::try_from(c.len()).unwrap().to_be_bytes(),
                c,
            ]
            .concat()
        })
        .collect()
}

/// A TLS 1.2 server flight: ServerHello, Certificate (`certs`), ServerHelloDone.
fn tls12_flight(certs: &[Vec<u8>]) -> Vec<u8> {
    let hello = server_hello(0x0303, 0xC02F, &[alpn(&["http/1.1"])]);
    let list: Vec<u8> = certs
        .iter()
        .flat_map(|c| [&u32::try_from(c.len()).unwrap().to_be_bytes()[1..], c].concat())
        .collect();
    let certificate = [
        &u32::try_from(list.len()).unwrap().to_be_bytes()[1..],
        &list,
    ]
    .concat();
    [
        &hello[5..], // the hello message without its record header
        &message(11, &certificate),
        &message(14, &[]),
    ]
    .concat()
}

#[test]
fn server_flights_show_the_tls12_certificate_chain() {
    let root = dn(&[(CN, 0x13, b"Test Root"), (O, 0x0C, b"Wiretap \xC3\xA9")]);
    let leaf = cert(
        &root,
        &dn(&[(CN, 0x0C, b"api.example.test")]),
        [(0x17, "260101000000Z"), (0x18, "20270630235959Z")],
    );
    // A BMPString name and a 20th-century UTCTime.
    let ca = cert(
        &root,
        &dn(&[(
            CN,
            0x1E,
            &[
                0, b'T', 0, b'e', 0, b's', 0, b't', 0, b' ', 0, b'C', 0, b'A',
            ],
        )]),
        [(0x17, "991231235959Z"), (0x17, "491231235959Z")],
    );
    let flight = tls12_flight(&[leaf, ca]);
    // Records split inside the Certificate message; every prefix asks for more.
    for size in [flight.len(), 100, 7] {
        let wire = records(&flight, size);
        let decoded = complete(parse_server_flight(&wire));
        assert_eq!(decoded.hello.cipher_suite, 0xC02F);
        assert_eq!(
            decoded.certificates,
            [
                Certificate {
                    subject: "CN=api.example.test".into(),
                    issuer: "CN=Test Root, O=Wiretap é".into(),
                    not_before: "2026-01-01 00:00:00 UTC".into(),
                    not_after: "2027-06-30 23:59:59 UTC".into(),
                },
                Certificate {
                    subject: "CN=Test CA".into(),
                    issuer: "CN=Test Root, O=Wiretap é".into(),
                    not_before: "1999-12-31 23:59:59 UTC".into(),
                    not_after: "2049-12-31 23:59:59 UTC".into(),
                },
            ]
        );
        // Prefixes ask for more until the whole chain arrived: never a chain cut short.
        let mut complete_from = None;
        for end in 0..wire.len() {
            match parse_server_flight(&wire[..end]) {
                Parse::Partial => assert!(complete_from.is_none(), "size {size}, cut at {end}"),
                Parse::Complete(f) => {
                    assert_eq!(f.certificates.len(), 2, "size {size}, cut at {end}");
                    complete_from.get_or_insert(end);
                }
                Parse::Invalid => panic!("size {size}, cut at {end}"),
            }
        }
    }
    let attributes = complete(parse_server_flight(&records(&flight, 512))).attributes();
    assert_eq!(
        attributes,
        [
            ("tls.version", "TLS 1.2".to_owned()),
            (
                "tls.cipher_suite",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into()
            ),
            ("tls.alpn", "http/1.1".into()),
            ("tls.certificate", "CN=api.example.test".into()),
            ("tls.issuer", "CN=Test Root, O=Wiretap é".into()),
            (
                "tls.valid",
                "2026-01-01 00:00:00 UTC to 2027-06-30 23:59:59 UTC".into()
            ),
            ("tls.chain", "CN=api.example.test → CN=Test CA".into()),
        ]
    );
}

/// A real certificate (Microsoft's 2011 root from the Windows store, SHA-1 thumbprint
/// 8F43288AD272F3103B6FB1428485EA3014C0BCFE) reads as Windows shows it.
#[test]
fn real_certificates_read_as_windows_shows_them() {
    let der = include_bytes!("testdata/microsoft-root-2011.der").to_vec();
    let flight = complete(parse_server_flight(&records(
        &tls12_flight(&[der]),
        16 * 1024,
    )));
    let name = "CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation";
    assert_eq!(
        flight.certificates,
        [Certificate {
            subject: name.into(),
            issuer: name.into(),
            not_before: "2011-03-22 22:05:28 UTC".into(),
            not_after: "2036-03-22 22:13:04 UTC".into(),
        }]
    );
}

#[test]
fn server_flights_end_where_the_cleartext_ends() {
    let no_certs = |wire: &[u8]| complete(parse_server_flight(wire)).certificates.is_empty();
    // TLS 1.3 encrypts the certificate: the hello alone is complete.
    let tls13 = server_hello(0x0303, 0x1302, &[(43, vec![3, 4])]);
    assert!(no_certs(&tls13));
    assert_eq!(
        complete(parse_server_flight(&tls13)).attributes(),
        [
            ("tls.version", "TLS 1.3".to_owned()),
            ("tls.cipher_suite", "TLS_AES_256_GCM_SHA384".into()),
        ]
    );
    // A resumed TLS 1.2 session: ServerHello, then ChangeCipherSpec.
    let tls12 = server_hello(0x0303, 0xC030, &[]);
    assert_eq!(parse_server_flight(&tls12), Parse::Partial);
    assert!(no_certs(&[&tls12[..], &[20, 3, 3, 0, 1, 1]].concat()));
    // ServerHelloDone without a certificate (anonymous or PSK suites).
    assert!(no_certs(
        &[&tls12[..], &records(&message(14, &[]), 64)].concat()
    ));
    // An unknown suite is shown by number; an unparsable certificate is left out.
    let odd = [
        &server_hello(0x0303, 0xFFFE, &[])[..],
        &records(&message(11, &[0, 0, 4, 0, 0, 1, 0xFF]), 64),
    ]
    .concat();
    let flight = complete(parse_server_flight(&odd));
    assert!(flight.certificates.is_empty());
    assert_eq!(
        flight.attributes()[1],
        ("tls.cipher_suite", "0xfffe".into())
    );
    // Bounded: a flight that never finishes is reported from MAX_FLIGHT bytes on.
    let mut endless = tls12.clone();
    endless.extend(records(&message(12, &vec![0; MAX_FLIGHT]), 16 * 1024));
    endless.truncate(MAX_FLIGHT);
    assert!(no_certs(&endless));
    // Not a server flight.
    assert_eq!(parse_server_flight(&client_hello(&[])), Parse::Invalid);
    assert_eq!(parse_server_flight(&[20, 3, 3, 0, 1, 1]), Parse::Invalid);
    assert_eq!(
        parse_server_flight(b"SSH-2.0-OpenSSH_9.9\r\n"),
        Parse::Invalid
    );
    assert_eq!(parse_server_flight(&[22, 3]), Parse::Partial);
    assert_eq!(cipher_suite_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
}

fn decode_all(input: &[u8], limit: usize) -> Result<(Vec<u8>, Progress, u64), ChunkError> {
    let mut d = Chunked::default();
    let mut out = Vec::new();
    let progress = d.feed(input, &mut out, limit)?;
    Ok((out, progress, d.decoded()))
}

#[test]
fn chunked_decoding() {
    let body = b"4\r\nWiki\r\n5;ext=1\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT";
    let (out, progress, decoded) = decode_all(body, usize::MAX).unwrap();
    assert_eq!(out, b"Wikipedia in\r\n\r\nchunks.");
    assert_eq!(
        progress,
        Progress::Done {
            consumed: body.len() - 4
        },
        "stops before the next message"
    );
    assert_eq!(decoded, 23);
    // Any split into two pieces gives the same result.
    for split in 0..body.len() {
        let (a, b) = body.split_at(split);
        let mut d = Chunked::default();
        let mut out = Vec::new();
        let first = d.feed(a, &mut out, usize::MAX).unwrap();
        let second = if first == Progress::NeedMore {
            d.feed(b, &mut out, usize::MAX).unwrap()
        } else {
            first
        };
        assert_eq!(out, b"Wikipedia in\r\n\r\nchunks.", "split {split}");
        assert!(matches!(second, Progress::Done { .. }), "split {split}");
    }
    let (limited, _, decoded) = decode_all(body, 6).unwrap();
    assert_eq!(
        (limited.as_slice(), decoded),
        (&b"Wikipe"[..], 23),
        "limit bounds storage, not counting"
    );
    assert_eq!(
        decode_all(b"5\r\nab", usize::MAX).unwrap().1,
        Progress::NeedMore
    );
}

#[test]
fn chunked_rejects_malformed_input() {
    for bad in [
        &b"\r\n"[..],             // missing size
        b"g\r\n",                 // not hex
        b"4\nWiki\r\n",           // bare LF after size
        b"2\r\nabX\r\n",          // missing CRLF after data
        b"11111111111111111\r\n", // 17 hex digits (overflow)
        b"0\r\nX: 1\n\r\n",       // bare LF in trailer
    ] {
        assert!(
            decode_all(bad, usize::MAX).is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    let long_ext = [b"1;".to_vec(), vec![b'x'; 2000], b"\r\n".to_vec()].concat();
    assert!(decode_all(&long_ext, usize::MAX).is_err());
}

#[test]
fn read_head_returns_body_prefix() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";
    let (head, rest) = read_head(&mut &raw[..]).unwrap();
    assert!(matches!(
        head.start,
        StartLine::Response { status: 200, .. }
    ));
    assert_eq!(rest, b"hel");
    assert!(
        read_head(&mut &b"HTTP/1.1 200 OK\r\n"[..]).is_err(),
        "eof before end of head"
    );
    assert!(read_head(&mut &b"\x16\x03\x01garbage\r\n\r\n"[..]).is_err());
}
