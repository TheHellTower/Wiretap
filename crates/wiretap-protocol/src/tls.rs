//! Cleartext TLS handshake metadata for SSL 3.0 and TLS 1.0 through 1.3 (RFC 8446 4.1.2/4.1.3,
//! RFC 5246 7.4): offered and negotiated versions, cipher suite, SNI, ALPN and, before TLS 1.3,
//! the server's certificate chain. Nothing is decrypted. (TLS 1.3 encrypts everything after the
//! ServerHello, so the server's ALPN choice and certificates are only reported for TLS 1.2 and
//! older.)

use crate::{Parse, Reader};

/// Cleartext metadata from a ClientHello.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// Server Name Indication host name, if offered and well-formed.
    pub server_name: Option<String>,
    /// Application protocols offered (ALPN), in client preference order.
    pub alpn: Vec<String>,
    /// Protocol versions offered (`supported_versions`, else `legacy_version`), GREASE removed.
    pub versions: Vec<u16>,
}

/// Cleartext metadata from a ServerHello (or TLS 1.3 HelloRetryRequest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHello {
    /// Negotiated version (`supported_versions` for TLS 1.3, else `legacy_version`).
    pub version: u16,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected application protocol (TLS 1.2 and older only).
    pub alpn: Option<String>,
}

/// What an X.509 certificate says about itself (RFC 5280 4.1), for display.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Certificate {
    /// Subject common name and organization, e.g. `CN=example.com, O=Example`.
    pub subject: String,
    /// Issuer, in the same form.
    pub issuer: String,
    /// Start of validity, `YYYY-MM-DD HH:MM:SS UTC`.
    pub not_before: String,
    /// End of validity, in the same form.
    pub not_after: String,
}

/// The cleartext part of a server's first flight: its hello and, before TLS 1.3, its
/// certificates (leaf first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerFlight {
    /// The ServerHello.
    pub hello: ServerHello,
    /// Certificates sent (RFC 5246 7.4.2); empty for TLS 1.3 and resumed sessions.
    pub certificates: Vec<Certificate>,
}

/// Bytes of a server flight read while looking for its certificates; past this the hello alone
/// is reported.
pub const MAX_FLIGHT: usize = 64 * 1024;

const CONTENT_HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const CERTIFICATE: u8 = 11;
const SERVER_HELLO_DONE: u8 = 14;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const MAX_RECORD: usize = 16 * 1024 + 2048;
const MAX_LIST: usize = 16;
/// Certificates kept of a chain (real chains have 2 to 4), so that `tls.chain` stays short.
const MAX_CHAIN: usize = 8;
/// Characters kept of each certificate name.
const MAX_NAME: usize = 256;

/// Human-readable name of a protocol version.
#[must_use]
pub const fn version_name(version: u16) -> Option<&'static str> {
    match version {
        0x0300 => Some("SSL 3.0"),
        0x0301 => Some("TLS 1.0"),
        0x0302 => Some("TLS 1.1"),
        0x0303 => Some("TLS 1.2"),
        0x0304 => Some("TLS 1.3"),
        _ => None,
    }
}

/// IANA name of a cipher suite Windows (SChannel) or common servers negotiate.
#[must_use]
pub const fn cipher_suite_name(suite: u16) -> Option<&'static str> {
    Some(match suite {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xC023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xC024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xC027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xC028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        _ => return None,
    })
}

fn versions(list: &[u16]) -> String {
    list.iter()
        .map(|&v| version_name(v).map_or_else(|| format!("0x{v:04x}"), str::to_owned))
        .collect::<Vec<_>>()
        .join(",")
}

/// `(key, value)` pairs, without empty values.
fn pairs(list: [(&'static str, String); 3]) -> Vec<(&'static str, String)> {
    list.into_iter().filter(|(_, v)| !v.is_empty()).collect()
}

impl ClientHello {
    /// Event attributes: `tls.sni`, `tls.alpn_offered`, `tls.versions_offered`.
    #[must_use]
    pub fn attributes(&self) -> Vec<(&'static str, String)> {
        pairs([
            ("tls.sni", self.server_name.clone().unwrap_or_default()),
            ("tls.alpn_offered", self.alpn.join(",")),
            ("tls.versions_offered", versions(&self.versions)),
        ])
    }
}

impl ServerHello {
    /// Event attributes: `tls.version`, `tls.cipher_suite`, `tls.alpn`.
    #[must_use]
    pub fn attributes(&self) -> Vec<(&'static str, String)> {
        let suite = cipher_suite_name(self.cipher_suite)
            .map_or_else(|| format!("0x{:04x}", self.cipher_suite), str::to_owned);
        pairs([
            ("tls.version", versions(&[self.version])),
            ("tls.cipher_suite", suite),
            ("tls.alpn", self.alpn.clone().unwrap_or_default()),
        ])
    }
}

impl ServerFlight {
    /// The hello's attributes plus, when certificates were sent, `tls.certificate`,
    /// `tls.issuer` and `tls.valid` (of the leaf) and `tls.chain` (every subject, leaf first).
    #[must_use]
    pub fn attributes(&self) -> Vec<(&'static str, String)> {
        let mut out = self.hello.attributes();
        if let Some(leaf) = self.certificates.first() {
            out.push(("tls.certificate", leaf.subject.clone()));
            out.push(("tls.issuer", leaf.issuer.clone()));
            out.push((
                "tls.valid",
                format!("{} to {}", leaf.not_before, leaf.not_after),
            ));
        }
        if self.certificates.len() > 1 {
            let chain: Vec<&str> = self
                .certificates
                .iter()
                .map(|c| c.subject.as_str())
                .collect();
            out.push(("tls.chain", chain.join(" → ")));
        }
        out.retain(|(_, v)| !v.is_empty());
        out
    }
}

/// RFC 8701 GREASE values (`0x?A?A`) carry no meaning and are skipped.
const fn is_grease(v: u16) -> bool {
    v & 0x0F0F == 0x0A0A && (v >> 8) == (v & 0xFF)
}

/// A DNS host name: letters, digits, `-`, `_` and `.`, at most 253 bytes.
fn host_name(raw: &[u8]) -> Option<String> {
    let ok = !raw.is_empty()
        && raw.len() <= 253
        && raw
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    ok.then(|| String::from_utf8_lossy(raw).to_ascii_lowercase())
}

fn alpn_list(mut list: Reader<'_>, out: &mut Vec<String>) -> Option<()> {
    while !list.0.is_empty() {
        let proto = list.vec8()?.0;
        if out.len() < MAX_LIST && !proto.is_empty() && proto.iter().all(u8::is_ascii_graphic) {
            out.push(String::from_utf8_lossy(proto).into_owned());
        }
    }
    Some(())
}

/// A record header that may still turn out to be TLS (`Partial`) or cannot (`Invalid`).
fn short_record<T>(buf: &[u8]) -> Parse<T> {
    let plausible = match buf {
        [] => true,
        [c, rest @ ..] => *c == CONTENT_HANDSHAKE && rest.first().is_none_or(|&m| m == 3),
    };
    if plausible {
        Parse::Partial
    } else {
        Parse::Invalid
    }
}

/// Extracts the handshake message of type `kind` from the first TLS record in `buf`.
fn handshake(buf: &[u8], kind: u8) -> Parse<&[u8]> {
    let mut record = Reader(buf);
    let (Some(content), Some(major), Some(_minor), Some(len)) =
        (record.u8(), record.u8(), record.u8(), record.u16())
    else {
        return short_record(buf);
    };
    let len = usize::from(len);
    if content != CONTENT_HANDSHAKE || major != 3 || len > MAX_RECORD {
        return Parse::Invalid;
    }
    let Some(body) = record.bytes(len) else {
        return Parse::Partial;
    };
    let mut r = Reader(body);
    // The whole message must sit in this record (fragmented hellos are not decoded).
    match (r.u8(), r.vec24()) {
        (Some(t), Some(message)) if t == kind => Parse::Complete(message.0),
        _ => Parse::Invalid,
    }
}

/// Parses the first TLS record a client sends.
#[must_use]
pub fn parse_client_hello(buf: &[u8]) -> Parse<ClientHello> {
    match handshake(buf, CLIENT_HELLO) {
        Parse::Complete(message) => decode_client(message).map_or(Parse::Invalid, Parse::Complete),
        Parse::Partial => Parse::Partial,
        Parse::Invalid => Parse::Invalid,
    }
}

/// Parses the first TLS record a server sends.
#[must_use]
pub fn parse_server_hello(buf: &[u8]) -> Parse<ServerHello> {
    match handshake(buf, SERVER_HELLO) {
        Parse::Complete(message) => decode_server(message).map_or(Parse::Invalid, Parse::Complete),
        Parse::Partial => Parse::Partial,
        Parse::Invalid => Parse::Invalid,
    }
}

/// Parses the start of what a server sends: the ServerHello and, before TLS 1.3, the
/// Certificate message, across as many handshake records as they take. `Partial` until the
/// certificates (or the end of the server's cleartext handshake) arrived; from
/// [`MAX_FLIGHT`] bytes on, the hello alone is complete.
#[must_use]
pub fn parse_server_flight(buf: &[u8]) -> Parse<ServerFlight> {
    // Handshake messages may span records: join the leading handshake records.
    let mut joined = Vec::new();
    let mut records = Reader(buf);
    let mut ended = buf.len() >= MAX_FLIGHT;
    loop {
        let start = records.0;
        let (Some(content), Some(major), Some(_minor), Some(len)) =
            (records.u8(), records.u8(), records.u8(), records.u16())
        else {
            if joined.is_empty() && start.len() == buf.len() {
                return short_record(buf);
            }
            break;
        };
        if major != 3 || usize::from(len) > MAX_RECORD {
            return Parse::Invalid;
        }
        if content != CONTENT_HANDSHAKE {
            if joined.is_empty() {
                return Parse::Invalid;
            }
            ended = true; // ChangeCipherSpec, an alert or encrypted data: the cleartext is over
            break;
        }
        let Some(body) = records.bytes(usize::from(len)) else {
            break;
        };
        joined.extend_from_slice(body);
    }
    let mut messages = Reader(&joined);
    let mut hello: Option<ServerHello> = None;
    let mut done = false; // no certificate can follow
    while let (false, Some(kind), Some(body)) = (done, messages.u8(), messages.vec24()) {
        match (&hello, kind) {
            (None, SERVER_HELLO) => {
                let Some(h) = decode_server(body.0) else {
                    return Parse::Invalid;
                };
                done = h.version >= 0x0304; // TLS 1.3: the rest is encrypted
                hello = Some(h);
            }
            (None, _) => return Parse::Invalid,
            (Some(h), CERTIFICATE) => {
                return Parse::Complete(ServerFlight {
                    hello: h.clone(),
                    certificates: certificates(body),
                });
            }
            // No certificate (resumed session, anonymous or PSK suites).
            (Some(_), SERVER_HELLO_DONE) => done = true,
            _ => {} // CertificateStatus, ServerKeyExchange, ...
        }
    }
    match hello {
        Some(hello) if done || ended => Parse::Complete(ServerFlight {
            hello,
            certificates: Vec::new(),
        }),
        None if ended => Parse::Invalid,
        _ => Parse::Partial,
    }
}

/// The certificate list of a TLS 1.2 Certificate message, leaf first, until one does not parse.
fn certificates(mut body: Reader<'_>) -> Vec<Certificate> {
    let Some(mut list) = body.vec24() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    while out.len() < MAX_CHAIN {
        let Some(cert) = list.vec24().and_then(|der| certificate(der.0)) else {
            break;
        };
        out.push(cert);
    }
    out
}

/// One DER element (definite length up to 16 MiB): its tag and contents.
fn der<'a>(r: &mut Reader<'a>) -> Option<(u8, Reader<'a>)> {
    let tag = r.u8()?;
    let first = r.u8()?;
    let len = match first {
        0..=0x7F => usize::from(first),
        0x81 => usize::from(r.u8()?),
        0x82 => usize::from(r.u16()?),
        0x83 => r.u24()?,
        _ => return None,
    };
    Some((tag, Reader(r.bytes(len)?)))
}

fn sequence<'a>(r: &mut Reader<'a>) -> Option<Reader<'a>> {
    der(r).and_then(|(tag, inner)| (tag == 0x30).then_some(inner))
}

/// Subject, issuer and validity of a DER certificate (RFC 5280 4.1).
fn certificate(bytes: &[u8]) -> Option<Certificate> {
    let mut tbs = sequence(&mut sequence(&mut Reader(bytes))?)?;
    let (mut tag, _) = der(&mut tbs)?;
    if tag == 0xA0 {
        (tag, _) = der(&mut tbs)?; // [0] version, then the serial number
    }
    if tag != 0x02 {
        return None;
    }
    sequence(&mut tbs)?; // signature algorithm
    let issuer = name(sequence(&mut tbs)?);
    let mut validity = sequence(&mut tbs)?;
    let not_before = time(der(&mut validity)?)?;
    let not_after = time(der(&mut validity)?)?;
    let subject = name(sequence(&mut tbs)?);
    Some(Certificate {
        subject,
        issuer,
        not_before,
        not_after,
    })
}

/// `CN=…, O=…` from a distinguished name: its first common name and organization, whatever
/// their order (other attributes are left out).
fn name(mut rdns: Reader<'_>) -> String {
    let mut parts: [Option<String>; 2] = [None, None];
    while let Some((0x31, mut set)) = der(&mut rdns) {
        while let Some(mut pair) = sequence(&mut set) {
            let (Some((0x06, oid)), Some((kind, value))) = (der(&mut pair), der(&mut pair)) else {
                continue;
            };
            let (slot, label) = match oid.0 {
                [0x55, 0x04, 0x03] => (0, "CN"),
                [0x55, 0x04, 0x0A] => (1, "O"),
                _ => continue,
            };
            if let Some(part @ None) = parts.get_mut(slot) {
                *part = Some(format!("{label}={}", string(kind, value.0)));
            }
        }
    }
    parts.into_iter().flatten().collect::<Vec<_>>().join(", ")
}

/// A directory string for display: BMPString is UTF-16, the others are read as UTF-8; control
/// characters become `?` and long values are cut.
fn string(kind: u8, raw: &[u8]) -> String {
    let text = if kind == 0x1E {
        let units: Vec<u16> = raw
            .as_chunks()
            .0
            .iter()
            .map(|&p| u16::from_be_bytes(p))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    text.chars()
        .take(MAX_NAME)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) as
/// `YYYY-MM-DD HH:MM:SS UTC`.
fn time((tag, value): (u8, Reader<'_>)) -> Option<String> {
    let (&b'Z', digits) = value.0.split_last()? else {
        return None;
    };
    let digits = std::str::from_utf8(digits)
        .ok()
        .filter(|d| d.bytes().all(|b| b.is_ascii_digit()))?;
    let (year, rest) = match (tag, digits.len()) {
        (0x17, 12) => {
            let yy: u16 = digits.get(..2)?.parse().ok()?;
            (
                if yy >= 50 { 1900 + yy } else { 2000 + yy },
                digits.get(2..)?,
            )
        }
        (0x18, 14) => (digits.get(..4)?.parse().ok()?, digits.get(4..)?),
        _ => return None,
    };
    let part = |i: usize| rest.get(i..i + 2);
    Some(format!(
        "{year:04}-{}-{} {}:{}:{} UTC",
        part(0)?,
        part(2)?,
        part(4)?,
        part(6)?,
        part(8)?
    ))
}

fn decode_client(message: &[u8]) -> Option<ClientHello> {
    let mut hello = Reader(message);
    let legacy_version = hello.u16()?;
    hello.bytes(32)?; // random
    hello.vec8()?; // legacy_session_id
    hello.vec16()?; // cipher_suites
    hello.vec8()?; // legacy_compression_methods
    let mut out = ClientHello::default();
    // Extensions are absent in some SSL 3.0 / TLS 1.0 hellos.
    if let Some(mut extensions) = hello.vec16() {
        while !extensions.0.is_empty() {
            let kind = extensions.u16()?;
            let mut data = extensions.vec16()?;
            match kind {
                EXT_SERVER_NAME => {
                    let mut list = data.vec16()?;
                    while !list.0.is_empty() {
                        let name_type = list.u8()?;
                        let name = list.vec16()?;
                        if name_type == 0 && out.server_name.is_none() {
                            out.server_name = host_name(name.0);
                        }
                    }
                }
                EXT_ALPN => alpn_list(data.vec16()?, &mut out.alpn)?,
                EXT_SUPPORTED_VERSIONS => {
                    let mut list = data.vec8()?;
                    while !list.0.is_empty() {
                        let v = list.u16()?;
                        if !is_grease(v) && out.versions.len() < MAX_LIST {
                            out.versions.push(v);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if out.versions.is_empty() {
        out.versions.push(legacy_version);
    }
    Some(out)
}

fn decode_server(message: &[u8]) -> Option<ServerHello> {
    let mut hello = Reader(message);
    let mut version = hello.u16()?;
    hello.bytes(32)?; // random
    hello.vec8()?; // legacy_session_id_echo
    let cipher_suite = hello.u16()?;
    hello.u8()?; // legacy_compression_method
    let mut alpn = Vec::new();
    if let Some(mut extensions) = hello.vec16() {
        while !extensions.0.is_empty() {
            let kind = extensions.u16()?;
            let mut data = extensions.vec16()?;
            match kind {
                EXT_SUPPORTED_VERSIONS => version = data.u16()?,
                EXT_ALPN => alpn_list(data.vec16()?, &mut alpn)?,
                _ => {}
            }
        }
    }
    Some(ServerHello {
        version,
        cipher_suite,
        alpn: alpn.into_iter().next(),
    })
}
