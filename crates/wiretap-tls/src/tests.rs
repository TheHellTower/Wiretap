#![allow(clippy::unwrap_used, reason = "test code")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use super::*;

/// A throwaway authority with its own CNG keys, deleted when dropped. Never trusted.
struct TestCa(Option<Authority>);

impl TestCa {
    fn new() -> Self {
        let mut id = [0u8; 8];
        random(&mut id).unwrap();
        let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
        Self(Some(
            Authority::open(&format!("Wiretap Test {name}")).unwrap(),
        ))
    }
    fn get(&self) -> &Authority {
        self.0.as_ref().unwrap()
    }
}

impl Drop for TestCa {
    fn drop(&mut self) {
        if let Some(ca) = self.0.take() {
            ca.delete().unwrap();
        }
    }
}

/// Serves one TLS connection as `host`: echoes everything back until the client closes.
fn echo_server(
    ca: &Arc<TestCa>,
    host: &'static str,
    alpn: &'static [&'static str],
) -> (
    std::net::SocketAddr,
    thread::JoinHandle<io::Result<Option<String>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let ca = Arc::clone(ca);
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept()?;
        let mut tls = ca.get().accept(tcp, host, Vec::new(), alpn)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = tls.read(&mut buf)?;
            if n == 0 {
                return Ok(tls.alpn().map(str::to_owned));
            }
            tls.write_all(buf.get(..n).unwrap())?;
        }
    });
    (addr, server)
}

#[test]
fn issued_certificates_verify_and_carry_data_both_ways() {
    let ca = Arc::new(TestCa::new());
    assert!(
        !ca.get().trusted().unwrap(),
        "tests never touch the user's trust store"
    );
    let (addr, server) = echo_server(&ca, "localhost", &[]);
    let upstream = Upstream::trusting(ca.get().certificate()).unwrap();
    let mut tls = upstream
        .connect(TcpStream::connect(addr).unwrap(), "localhost", &[])
        .unwrap();
    assert!(tls.protocol().starts_with("TLS 1."), "{}", tls.protocol());
    // Larger than one TLS record (16 KiB) in both directions.
    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    tls.write_all(&payload).unwrap();
    let mut echoed = vec![0u8; payload.len()];
    if let Err(e) = tls.read_exact(&mut echoed) {
        panic!("client: {e}; server: {:?}", server.join());
    }
    assert_eq!(echoed, payload);
    tls.socket().shutdown(std::net::Shutdown::Write).unwrap();
    drop(tls);
    server.join().unwrap().unwrap();
}

#[test]
fn untrusted_roots_and_wrong_names_are_rejected() {
    let ca = Arc::new(TestCa::new());
    // The system trust store does not know this test root.
    let (addr, _server) = echo_server(&ca, "localhost", &[]);
    let error = Upstream::system()
        .unwrap()
        .connect(TcpStream::connect(addr).unwrap(), "localhost", &[])
        .err()
        .unwrap();
    assert!(error.to_string().contains("not trusted"), "{error}");
    // Trusted root, but the certificate is for another name.
    let (addr, _server) = echo_server(&ca, "localhost", &[]);
    let upstream = Upstream::trusting(ca.get().certificate()).unwrap();
    let error = upstream
        .connect(TcpStream::connect(addr).unwrap(), "example.com", &[])
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("not valid for example.com"),
        "{error}"
    );
}

#[test]
fn invalid_host_names_get_no_certificate() {
    let ca = TestCa::new();
    let (a, _b) = (TcpListener::bind("127.0.0.1:0").unwrap(), ());
    let tcp = TcpStream::connect(a.local_addr().unwrap()).unwrap();
    let error = ca
        .get()
        .accept(tcp, "bad host\r\n", Vec::new(), &[])
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

/// ALPN: the server accepts the first of its protocols the client offers; both ends report it.
#[test]
fn alpn_is_negotiated_both_ways() {
    let ca = Arc::new(TestCa::new());
    let upstream = Upstream::trusting(ca.get().certificate()).unwrap();
    for (offered, accepted, expected) in [
        (&["h2", "http/1.1"][..], &["h2"][..], Some("h2")),
        (&["h2", "http/1.1"], &["http/1.1"], Some("http/1.1")),
        (&[], &["h2"], None),
        (&["h2", "http/1.1"], &[], None),
    ] {
        let (addr, server) = echo_server(&ca, "localhost", accepted);
        let mut tls = upstream
            .connect(TcpStream::connect(addr).unwrap(), "localhost", offered)
            .unwrap();
        assert_eq!(tls.alpn(), expected, "{offered:?} / {accepted:?}");
        tls.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        tls.read_exact(&mut back).unwrap();
        tls.socket().shutdown(std::net::Shutdown::Write).unwrap();
        drop(tls);
        assert_eq!(server.join().unwrap().unwrap().as_deref(), expected);
    }
}
