//! The certificates Wiretap issues, encoded as DER by hand: a tiny writer instead of an ASN.1
//! dependency. Pure (no I/O, no parsing) so it is unit-tested and fuzzed; Windows parses and
//! validates the result.

use std::net::IpAddr;

use wiretap_core::Timestamp;

const SHA256_RSA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
];
const RSA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
const NULL: &[u8] = &[0x05, 0x00];
const COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const ORGANIZATION: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x0A];
const BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x13];
const KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0F];
const EXTENDED_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];
const SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const SUBJECT_ALT_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x11];
const SUBJECT_KEY_ID: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0E];
const AUTHORITY_KEY_ID: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x23];
const TRUE: &[u8] = &[0x01, 0x01, 0xFF];

/// Tag, definite length, content.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 10);
    out.push(tag);
    match u8::try_from(content.len()) {
        Ok(n) if n < 0x80 => out.push(n),
        _ => {
            let len = content.len().to_be_bytes();
            let skip = len.iter().take_while(|&&b| b == 0).count();
            let len = len.get(skip..).unwrap_or_default();
            out.push(0x80 | u8::try_from(len.len()).unwrap_or(8));
            out.extend_from_slice(len);
        }
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// Non-negative INTEGER from big-endian bytes (minimal encoding).
pub(crate) fn uint(be: &[u8]) -> Vec<u8> {
    let digits = be
        .iter()
        .position(|&b| b != 0)
        .and_then(|i| be.get(i..))
        .unwrap_or(&[0]);
    let mut content = Vec::with_capacity(digits.len() + 1);
    if digits.first().is_some_and(|&b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(digits);
    tlv(0x02, &content)
}

fn bits(content: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0u8][..], content].concat())
}

/// `sha256WithRSAEncryption`, the only signature algorithm Wiretap uses.
fn algorithm() -> Vec<u8> {
    seq(&[SHA256_RSA, NULL])
}

/// `(SubjectPublicKeyInfo, RSAPublicKey)` for an RSA key; the latter is hashed into key IDs.
pub(crate) fn rsa_public_key(modulus: &[u8], exponent: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = seq(&[&uint(modulus), &uint(exponent)]);
    (seq(&[&seq(&[RSA, NULL]), &bits(&key)]), key)
}

/// `O=Wiretap, CN=<common>`.
pub(crate) fn name(common: &str) -> Vec<u8> {
    let rdn = |oid: &[u8], value: &str| tlv(0x31, &seq(&[oid, &tlv(0x0C, value.as_bytes())]));
    seq(&[&rdn(ORGANIZATION, "Wiretap"), &rdn(COMMON_NAME, common)])
}

/// UTCTime before 2050, GeneralizedTime after (RFC 5280 4.1.2.5).
fn time(ts: Timestamp) -> Vec<u8> {
    let digits: String = ts.utc().chars().filter(char::is_ascii_digit).collect();
    let year: u32 = digits.get(..4).and_then(|y| y.parse().ok()).unwrap_or(1970);
    match year {
        ..2050 => tlv(
            0x17,
            format!("{}Z", digits.get(2..14).unwrap_or_default()).as_bytes(),
        ),
        _ => tlv(
            0x18,
            format!("{}Z", digits.get(..14).unwrap_or_default()).as_bytes(),
        ),
    }
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    seq(&[oid, if critical { TRUE } else { &[] }, &tlv(0x04, value)])
}

/// A host name or IP address Wiretap may issue a certificate for.
#[must_use]
pub fn valid_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || ((1..=253).contains(&host.len())
            && host.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }))
}

/// What a certificate is for.
pub(crate) enum Kind<'a> {
    /// The root: may only sign certificates.
    Authority { key_id: &'a [u8] },
    /// A server certificate for one host (validated with [`valid_host`]).
    Leaf {
        host: &'a str,
        authority_key_id: &'a [u8],
    },
}

/// The to-be-signed part of a certificate.
pub(crate) struct Tbs<'a> {
    pub(crate) serial: [u8; 16],
    pub(crate) issuer: &'a [u8],
    pub(crate) subject: &'a [u8],
    pub(crate) not_before: Timestamp,
    pub(crate) not_after: Timestamp,
    pub(crate) spki: &'a [u8],
    pub(crate) kind: Kind<'a>,
}

impl Tbs<'_> {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let extensions = match self.kind {
            Kind::Authority { key_id } => vec![
                extension(BASIC_CONSTRAINTS, true, &seq(&[TRUE, &uint(&[0])])),
                extension(KEY_USAGE, true, &[0x03, 0x02, 0x01, 0x06]), // keyCertSign, cRLSign
                extension(SUBJECT_KEY_ID, false, &tlv(0x04, key_id)),
            ],
            Kind::Leaf {
                host,
                authority_key_id,
            } => {
                let alt = match host.parse::<IpAddr>() {
                    Ok(IpAddr::V4(ip)) => tlv(0x87, &ip.octets()),
                    Ok(IpAddr::V6(ip)) => tlv(0x87, &ip.octets()),
                    Err(_) => tlv(0x82, host.as_bytes()),
                };
                vec![
                    extension(BASIC_CONSTRAINTS, true, &seq(&[])),
                    extension(KEY_USAGE, true, &[0x03, 0x02, 0x05, 0xA0]), // digitalSignature, keyEncipherment
                    extension(EXTENDED_KEY_USAGE, false, &seq(&[SERVER_AUTH])),
                    extension(SUBJECT_ALT_NAME, false, &seq(&[&alt])),
                    extension(
                        AUTHORITY_KEY_ID,
                        false,
                        &seq(&[&tlv(0x80, authority_key_id)]),
                    ),
                ]
            }
        };
        let extensions: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
        seq(&[
            &[0xA0, 0x03, 0x02, 0x01, 0x02], // version: v3
            &uint(&self.serial),
            &algorithm(),
            self.issuer,
            &seq(&[&time(self.not_before), &time(self.not_after)]),
            self.subject,
            self.spki,
            &tlv(0xA3, &seq(&extensions)),
        ])
    }
}

/// The signed certificate.
pub(crate) fn certificate(tbs: &[u8], signature: &[u8]) -> Vec<u8> {
    seq(&[tbs, &algorithm(), &bits(signature)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_integers_are_minimal_der() {
        assert_eq!(tlv(0x04, &[7; 3]), [0x04, 3, 7, 7, 7]);
        assert_eq!(tlv(0x04, &[0; 200]).get(..3), Some(&[0x04, 0x81, 200][..]));
        assert_eq!(
            tlv(0x04, &[0; 300]).get(..4),
            Some(&[0x04, 0x82, 0x01, 0x2C][..])
        );
        assert_eq!(uint(&[0, 0, 5]), [0x02, 1, 5]);
        assert_eq!(uint(&[0x80]), [0x02, 2, 0, 0x80]);
        assert_eq!(uint(&[0, 0]), [0x02, 1, 0]);
        assert_eq!(time(Timestamp(0)), b"\x17\x0d700101000000Z");
        assert_eq!(time(Timestamp(2_556_143_999_000_000)).first(), Some(&0x18)); // 2050-12-31
    }

    #[test]
    fn hosts_are_validated() {
        for ok in [
            "example.com",
            "a-b.c_d.test",
            "localhost",
            "127.0.0.1",
            "::1",
        ] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in [
            "",
            "a..b",
            "-.",
            "ex ample.com",
            "a\0b",
            "a/b",
            &"a".repeat(64),
            "é.com",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
    }
}
