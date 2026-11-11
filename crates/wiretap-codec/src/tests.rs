#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const TEXT: &str = "Wiretap decodes HTTP bodies. ";

fn text() -> Vec<u8> {
    let mut t = TEXT.repeat(40);
    t.push_str("The end.");
    t.into_bytes()
}

/// .NET `DeflateStream` output for [`text`] (an independent encoder).
fn raw_deflate() -> Vec<u8> {
    hex(
        "0bcf2c4a2d492c5048494dce4f492d56f00809095048ca4fc94c2dd653081f951c951c951c95a4bd644846aa426a5e8a1e00",
    )
}

/// .NET `GZipStream` output for [`text`].
fn gzip_member() -> Vec<u8> {
    hex("1f8b0800000000000400\
         0bcf2c4a2d492c5048494dce4f492d56f00809095048ca4fc94c2dd653081f951c951c951c95a4bd644846aa426a5e8a1e00\
         36d110ab90040000")
}

fn zlib() -> Vec<u8> {
    let mut z = vec![0x78, 0x9C];
    z.extend(raw_deflate());
    let (mut a, mut b) = (1u32, 0u32);
    for &x in &text() {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    z.extend((b << 16 | a).to_be_bytes());
    z
}

const LIMIT: usize = 64 << 20;

#[test]
fn rfc_check_values() {
    // RFC 7932 appendix A, section 7.1 and appendix B publish these CRC-32 values.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(brotli::DICTIONARY.len(), 122_784);
    assert_eq!(crc32(brotli::DICTIONARY), 0x5136_CB04);
    assert_eq!(crc32(&brotli::tables::LUT0), 0x8E91_EFB7);
    assert_eq!(crc32(&brotli::tables::LUT1), 0xD01A_32F4);
    assert_eq!(crc32(&brotli::tables::LUT2), 0x0DD7_A0D6);
    let mut transforms = Vec::new();
    for (prefix, kind, suffix) in brotli::tables::TRANSFORMS {
        transforms.extend_from_slice(prefix);
        transforms.extend([0, kind]);
        transforms.extend_from_slice(suffix);
        transforms.push(0);
    }
    assert_eq!(transforms.len(), 648);
    assert_eq!(crc32(&transforms), 0x3D96_5F81);
    // Word offsets follow from the word counts per length (section 8).
    let bits = [
        10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5,
    ];
    let mut offset = 0;
    for (len, b) in (4..=24).zip(bits) {
        assert_eq!(brotli::DOFFSET[len], offset, "length {len}");
        offset += len << b;
    }
    assert_eq!(offset, brotli::DICTIONARY.len());
}

#[test]
fn xxh64_reference_values() {
    assert_eq!(zstd::xxh64(b""), 0xEF46_DB37_51D8_E999);
    assert_eq!(zstd::xxh64(b"abc"), 0x44BC_2CF5_AD77_0999);
}

#[test]
fn gzip_deflate_and_zlib() {
    let expected = text();
    assert_eq!(
        decode("gzip", &gzip_member(), LIMIT),
        Decoded {
            bytes: expected.clone(),
            error: None
        }
    );
    assert_eq!(decode("x-gzip", &gzip_member(), LIMIT).bytes, expected);
    assert_eq!(decode("deflate", &raw_deflate(), LIMIT).bytes, expected);
    assert_eq!(
        decode("Deflate", &zlib(), LIMIT),
        Decoded {
            bytes: expected.clone(),
            error: None
        }
    );
    // Two gzip members concatenate; trailing garbage after a member is ignored.
    let mut two = gzip_member();
    two.extend(gzip_member());
    two.extend(b"junk");
    assert_eq!(
        decode("gzip", &two, LIMIT).bytes,
        [expected.clone(), expected].concat()
    );
}

#[test]
fn damaged_bodies_keep_what_decoded() {
    let full = gzip_member();
    let cut = decode("gzip", &full[..full.len() - 12], LIMIT);
    assert_eq!(cut.error, Some(Error::Truncated));
    assert!(text().starts_with(&cut.bytes));
    let mut bad_crc = full.clone();
    let n = bad_crc.len();
    bad_crc[n - 8] ^= 1;
    assert_eq!(decode("gzip", &bad_crc, LIMIT).error, Some(Error::Corrupt));
    let mut bad_adler = zlib();
    let n = bad_adler.len();
    bad_adler[n - 1] ^= 1;
    assert_eq!(
        decode("deflate", &bad_adler, LIMIT).error,
        Some(Error::Corrupt)
    );
    assert_eq!(
        decode("gzip", b"not gzip", LIMIT).error,
        Some(Error::Corrupt)
    );
    assert_eq!(decode("br", &[], LIMIT).error, Some(Error::Truncated));
    assert_eq!(decode("zstd", &[], LIMIT), Decoded::default()); // zero frames, as libzstd
}

#[test]
fn limit_caps_output() {
    for (coding, body) in [
        ("gzip", gzip_member()),
        ("deflate", zlib()),
        ("br", hex("5bffff036002201e0b28f77e00")),
    ] {
        let d = decode(coding, &body, 100);
        assert_eq!(d.error, Some(Error::TooLarge), "{coding}");
        assert_eq!(d.bytes.len(), 100, "{coding}");
    }
}

#[test]
fn unknown_and_layered_codings() {
    let d = decode("compress", b"raw", LIMIT);
    assert_eq!(
        (d.bytes.as_slice(), d.error),
        (&b"raw"[..], Some(Error::Unsupported))
    );
    assert_eq!(
        decode("", b"raw", LIMIT),
        Decoded {
            bytes: b"raw".to_vec(),
            error: None
        }
    );
    assert_eq!(decode("identity", b"raw", LIMIT).bytes, b"raw");
    // Codings are undone last to first: "gzip, identity" is gzip.
    assert_eq!(
        decode("gzip, identity", &gzip_member(), LIMIT).bytes,
        text()
    );
    assert_eq!(
        decode(
            "identity, identity, identity, identity, identity",
            b"x",
            LIMIT
        )
        .error,
        Some(Error::Unsupported)
    );
}

/// Vectors from google/brotli `tests/testdata` (MIT).
#[test]
fn brotli_reference_vectors() {
    let cases: [(&str, Vec<u8>); 6] = [
        ("06", Vec::new()),
        ("0b00805803", b"X".to_vec()),
        ("1b130000a4b0b2ea8147028a", b"XXXXXXXXXXYYYYYYYYYY".to_vec()),
        (
            "0b158054686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f6703",
            b"The quick brown fox jumps over the lazy dog".to_vec(),
        ),
        (
            "1b760000144aac9b7abde1979d7f8ec282360e9ce09003f78b9e38e6b600abc3caa0c2da6636dccd808d2e21d76ee3ea4cb8f0d2b8c7c2704d3af0697ea1b84573abc4571e",
            b"ukko nooa, ukko nooa oli kunnon mies, kun han meni saunaan, pisti laukun naulaan, ukko nooa, ukko nooa oli kunnon mies.".to_vec(),
        ),
        ("5bffff036002201e0b28f77e00", vec![0; 262_144]),
    ];
    for (input, expected) in cases {
        let d = decode("br", &hex(input), LIMIT);
        assert_eq!(d.error, None, "{input}");
        assert!(d.bytes == expected, "{input}: {} bytes", d.bytes.len());
    }
    let fox = hex(
        "1b760000144aac9b7abde1979d7f8ec282360e9ce09003f78b9e38e6b600abc3caa0c2da6636dccd808d2e21d76ee3ea4cb8f0d2b8c7c2704d3af0697ea1b84573abc4571e",
    );
    assert_eq!(
        decode("br", &fox[..40], LIMIT).error,
        Some(Error::Truncated)
    );
}

/// Vectors from facebook/zstd `tests/golden-decompression` (BSD) plus hand-built frames.
#[test]
fn zstd_reference_vectors() {
    let hello = decode(
        "zstd",
        &hex("28b52ffd00008500006848656c6c6f20576f726c64210a8000"),
        LIMIT,
    );
    assert_eq!(
        hello,
        Decoded {
            bytes: b"Hello World!\n".to_vec(),
            error: None
        }
    );
    assert_eq!(
        decode("zstd", &hex("28b52ffd00001500000000"), LIMIT),
        Decoded::default()
    );
    // RLE blocks with a content size and a checksum over 1 MiB of zeros.
    let rle = hex(
        "28b52ffda4000010000200100002001000020010000200100002001000020010000200100003001000f13e16e1",
    );
    assert_eq!(
        decode("zstd", &rle, LIMIT),
        Decoded {
            bytes: vec![0; 1 << 20],
            error: None
        }
    );
    let mut bad = rle.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert_eq!(decode("zstd", &bad, LIMIT).error, Some(Error::Corrupt));
    // Single-segment frame with a 128 KiB raw block (the largest allowed), then a skippable frame.
    let data: Vec<u8> = (0..BLOCK).map(|i| (i * 7 % 251) as u8).collect();
    const BLOCK: usize = 128 << 10;
    let mut frame = hex("28b52ffd");
    frame.push(0x80 | 0x20); // 4-byte content size, single segment
    frame.extend(u32::try_from(BLOCK).unwrap().to_le_bytes());
    frame.extend(&(((BLOCK as u32) << 3) | 1).to_le_bytes()[..3]); // last, raw
    frame.extend(&data);
    frame.extend(hex("5a2a4d1802000000abcd"));
    assert_eq!(
        decode("zstd", &frame, LIMIT),
        Decoded {
            bytes: data,
            error: None
        }
    );
    // A dictionary frame is reported, not misdecoded.
    assert_eq!(
        decode("zstd", &hex("28b52ffd0100010000"), LIMIT).error,
        Some(Error::Unsupported)
    );
}

/// RFC 7692 section 7.2.3.2: "Hello" twice, the second message reusing the first's window.
#[test]
fn permessage_deflate_context_takeover() {
    let mut inflater = Inflater::default();
    let first = inflater.message(&hex("f248cdc9c90700"), true, LIMIT);
    assert_eq!(
        first,
        Decoded {
            bytes: b"Hello".to_vec(),
            error: None
        }
    );
    let second = inflater.message(&hex("f200110000"), true, LIMIT);
    assert_eq!(
        second,
        Decoded {
            bytes: b"Hello".to_vec(),
            error: None
        }
    );
    // Without the shared window the back-reference has nothing to point at.
    let mut alone = Inflater::default();
    assert_eq!(
        alone.message(&hex("f200110000"), false, LIMIT).error,
        Some(Error::Corrupt)
    );
}

#[test]
fn arbitrary_input_never_panics() {
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let seeds = [
        gzip_member(),
        zlib(),
        hex(
            "1b760000144aac9b7abde1979d7f8ec282360e9ce09003f78b9e38e6b600abc3caa0c2da6636dccd808d2e21d76ee3ea4cb8f0d2b8c7c2704d3af0697ea1b84573abc4571e",
        ),
        hex("28b52ffd00008500006848656c6c6f20576f726c64210a8000"),
    ];
    for _ in 0..4000 {
        let mut input = seeds[(next() % 4) as usize].clone();
        for _ in 0..(next() % 4 + 1) {
            let i = (next() as usize) % input.len();
            input[i] ^= 1 << (next() % 8);
        }
        input.truncate((next() as usize) % (input.len() + 1));
        for coding in ["gzip", "deflate", "br", "zstd"] {
            let d = decode(coding, &input, 1 << 20);
            assert!(d.bytes.len() <= 1 << 20);
        }
        let _ = Inflater::default().message(&input, true, 1 << 20);
    }
}
