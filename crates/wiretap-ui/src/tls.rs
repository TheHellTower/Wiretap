//! HTTPS decryption for the proxy, backed by the Wiretap root CA (`wiretap-tls`).

use std::io::{self, Read, Write};
use std::net::TcpStream;

use wiretap_proxy::{Stream, Tls};
use wiretap_tls::{Authority, DEFAULT_NAME, Upstream};

/// A decrypted TLS side as a proxy [`Stream`] (timeouts go to its own socket).
struct Side(wiretap_tls::TlsStream);

impl Read for Side {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Side {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Stream for Side {
    fn socket(&self) -> &TcpStream {
        self.0.socket()
    }
    fn alpn(&self) -> Option<&str> {
        self.0.alpn()
    }
}
/// The proxy's TLS: certificates from the Wiretap root, servers verified against Windows.
pub(crate) struct Interceptor {
    authority: Authority,
    upstream: Upstream,
}

impl Interceptor {
    /// Opens the Wiretap root (creating its keys on first use). With `trust`, asks Windows
    /// to trust it when it is not yet; otherwise an untrusted root is an error.
    pub(crate) fn open(trust: bool) -> Result<Self, String> {
        let authority = Authority::open(DEFAULT_NAME)
            .map_err(|e| format!("cannot open the Wiretap root: {e}"))?;
        if !authority.trusted().map_err(|e| e.to_string())? {
            if !trust {
                return Err("the Wiretap root certificate is no longer trusted".into());
            }
            authority
                .trust()
                .map_err(|e| format!("Windows did not add the Wiretap root certificate: {e}"))?;
        }
        let upstream = Upstream::system().map_err(|e| e.to_string())?;
        Ok(Self {
            authority,
            upstream,
        })
    }

    /// The root certificate (DER).
    pub(crate) fn root(&self) -> &[u8] {
        self.authority.certificate()
    }

    /// Removes the root from the user's trusted roots (Windows confirms) and deletes its keys.
    pub(crate) fn remove() -> Result<(), String> {
        let authority = Authority::open(DEFAULT_NAME).map_err(|e| e.to_string())?;
        authority
            .untrust()
            .map_err(|e| format!("Windows did not remove the Wiretap root certificate: {e}"))?;
        authority.delete().map_err(|e| e.to_string())
    }
}

impl Tls for Interceptor {
    fn accept(
        &self,
        client: TcpStream,
        host: &str,
        hello: Vec<u8>,
        alpn: &[&str],
    ) -> io::Result<Box<dyn Stream>> {
        Ok(Box::new(Side(
            self.authority.accept(client, host, hello, alpn)?,
        )))
    }

    fn connect(&self, server: TcpStream, host: &str, alpn: &[&str]) -> io::Result<Box<dyn Stream>> {
        Ok(Box::new(Side(self.upstream.connect(server, host, alpn)?)))
    }
}
