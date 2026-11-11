//! HTTPS interception built only on Windows: SChannel speaks TLS (whatever versions the
//! system enables, TLS 1.0 to 1.3), CNG keeps the keys, CryptoAPI verifies certificates.
//! No TLS or ASN.1 dependency.
//!
//! - [`Authority`]: the per-user Wiretap root CA and the server certificates it issues for
//!   each intercepted host. Both private keys are persisted, non-exportable CNG keys; the
//!   root certificate is rebuilt from its key on every start, so nothing else is stored. It is
//!   trusted only when the user asks for it ([`Authority::trust`]), and Windows itself asks
//!   the user to confirm.
//! - [`Upstream`]: TLS client connections to real servers, verified like a browser would
//!   (chain to a trusted root, validity, server-auth usage, host name).

mod crypto;
mod stream;
pub mod x509;

use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};

use wiretap_core::Timestamp;

use crypto::{Cert, Engine, Key, Store, random, sha1};
use stream::Credentials;
pub use stream::TlsStream;
pub use x509::valid_host;

/// Key container prefix used by the app (tests use their own).
pub const DEFAULT_NAME: &str = "Wiretap";
/// Issued host certificates kept in memory.
const MAX_LEAVES: usize = 1024;
const DAY: i64 = 86_400_000_000;

/// The Wiretap root certificate authority.
pub struct Authority {
    key: Key,
    leaf_key: Key,
    leaf_key_name: String,
    leaf_spki: Vec<u8>,
    subject: Vec<u8>,
    key_id: [u8; 20],
    cert: Cert,
    leaves: Mutex<HashMap<String, (Cert, Arc<Credentials>)>>,
}

fn serial() -> io::Result<[u8; 16]> {
    let mut serial = [0u8; 16];
    random(&mut serial)?;
    if let Some(first) = serial.first_mut() {
        *first = (*first & 0x7F) | 0x40; // positive, fixed length
    }
    Ok(serial)
}

impl Authority {
    /// Opens the authority `name` (see [`DEFAULT_NAME`]), creating its keys on first use.
    ///
    /// # Errors
    /// Key storage or certificate creation failed.
    pub fn open(name: &str) -> io::Result<Self> {
        let key = Key::open_or_create(&format!("{name} Root CA"), 3072)?;
        let leaf_key_name = format!("{name} Leaf Key");
        let leaf_key = Key::open_or_create(&leaf_key_name, 2048)?;
        let (modulus, exponent) = key.rsa_public()?;
        let (spki, rsa) = x509::rsa_public_key(&modulus, &exponent);
        let key_id = sha1(&rsa)?;
        let (modulus, exponent) = leaf_key.rsa_public()?;
        let (leaf_spki, _) = x509::rsa_public_key(&modulus, &exponent);
        // The subject depends only on the key, so every rebuilt root matches the one the user
        // trusted and issued certificates chain to it.
        let id: String = key_id.iter().take(4).map(|b| format!("{b:02X}")).collect();
        let subject = x509::name(&format!("{name} Root CA {id}"));
        let now = Timestamp::now().0;
        let tbs = x509::Tbs {
            serial: serial()?,
            issuer: &subject,
            subject: &subject,
            not_before: Timestamp(now - DAY),
            not_after: Timestamp(now + 3650 * DAY),
            spki: &spki,
            kind: x509::Kind::Authority { key_id: &key_id },
        }
        .encode();
        let cert = Cert::from_der(&x509::certificate(&tbs, &key.sign(&tbs)?))?;
        Ok(Self {
            key,
            leaf_key,
            leaf_key_name,
            leaf_spki,
            subject,
            key_id,
            cert,
            leaves: Mutex::default(),
        })
    }

    /// The root certificate (DER), for export to other browsers and devices.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        self.cert.der()
    }

    /// Whether the current user trusts this root.
    ///
    /// # Errors
    /// The root store cannot be opened.
    pub fn trusted(&self) -> io::Result<bool> {
        Ok(Store::user_root()?.contains_key(&self.cert))
    }

    /// Adds the root to the current user's trusted roots. Windows shows its own confirmation
    /// dialog; this blocks until the user answers.
    ///
    /// # Errors
    /// The user declined, or the store cannot be changed.
    pub fn trust(&self) -> io::Result<()> {
        Store::user_root()?.add(&self.cert)
    }

    /// Removes the root from the current user's trusted roots (Windows confirms).
    ///
    /// # Errors
    /// The user declined, or the store cannot be changed.
    pub fn untrust(&self) -> io::Result<()> {
        Store::user_root()?.remove_key(&self.cert)
    }

    /// Deletes both private keys. Call [`Authority::untrust`] first.
    ///
    /// # Errors
    /// Key storage refused.
    pub fn delete(self) -> io::Result<()> {
        let Self { key, leaf_key, .. } = self;
        key.delete()?;
        leaf_key.delete()
    }

    fn leaf(&self, host: &str) -> io::Result<Arc<Credentials>> {
        let host = host.to_ascii_lowercase();
        if !valid_host(&host) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid host name",
            ));
        }
        let mut leaves = self.leaves.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((_, creds)) = leaves.get(&host) {
            return Ok(Arc::clone(creds));
        }
        let now = Timestamp::now().0;
        let subject = x509::name(&host);
        let tbs = x509::Tbs {
            serial: serial()?,
            issuer: &self.subject,
            subject: &subject,
            not_before: Timestamp(now - DAY),
            not_after: Timestamp(now + 30 * DAY),
            spki: &self.leaf_spki,
            kind: x509::Kind::Leaf {
                host: &host,
                authority_key_id: &self.key_id,
            },
        }
        .encode();
        let cert = Cert::from_der(&x509::certificate(&tbs, &self.key.sign(&tbs)?))?;
        cert.link_key(&self.leaf_key_name)?;
        let creds = Arc::new(Credentials::new(Some(&cert))?);
        if leaves.len() >= MAX_LEAVES {
            leaves.clear();
        }
        leaves.insert(host, (cert, Arc::clone(&creds)));
        Ok(creds)
    }

    /// Server side of an intercepted connection: completes the handshake with the client,
    /// presenting a certificate for `host` and accepting the first protocol of `alpn` the client
    /// offers (none: no ALPN). `received` holds bytes already read (the ClientHello).
    ///
    /// # Errors
    /// Invalid host, or the client rejected the handshake (e.g. it does not trust the root).
    pub fn accept(
        &self,
        tcp: TcpStream,
        host: &str,
        received: Vec<u8>,
        alpn: &[&str],
    ) -> io::Result<TlsStream> {
        let mut stream = TlsStream::new(tcp, self.leaf(host)?, None);
        stream.offer(alpn);
        stream.handshake(received)?;
        Ok(stream)
    }
}

/// Verified TLS client connections to servers.
pub struct Upstream {
    creds: Arc<Credentials>,
    engine: Engine,
}

impl Upstream {
    /// Trusts what the current user trusts (the Windows root store).
    ///
    /// # Errors
    /// SChannel refused the credential.
    pub fn system() -> io::Result<Self> {
        Ok(Self {
            creds: Arc::new(Credentials::new(None)?),
            engine: Engine::user(),
        })
    }

    /// Trusts only the root certificate `root` (DER): private CAs and tests.
    ///
    /// # Errors
    /// Invalid certificate, or SChannel refused the credential.
    pub fn trusting(root: &[u8]) -> io::Result<Self> {
        Ok(Self {
            creds: Arc::new(Credentials::new(None)?),
            engine: Engine::exclusive(&Cert::from_der(root)?)?,
        })
    }

    /// Connects TLS over `tcp` to `host` (sent as SNI), offering the `alpn` protocols (none:
    /// no ALPN), and verifies its certificate.
    ///
    /// # Errors
    /// Handshake failure or an untrusted, expired or mismatched certificate.
    pub fn connect(&self, tcp: TcpStream, host: &str, alpn: &[&str]) -> io::Result<TlsStream> {
        let mut stream = TlsStream::new(tcp, Arc::clone(&self.creds), Some(host));
        stream.offer(alpn);
        stream.handshake(Vec::new())?;
        let cert = stream.peer_certificate()?;
        self.engine.verify(cert.0, host)?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests;
