//! A TLS connection over a `TcpStream`, driven by SChannel (both roles).
#![allow(
    unsafe_code,
    reason = "SSPI/SChannel FFI; every block carries a SAFETY comment"
)]

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::ptr::{null, null_mut};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    SEC_E_INCOMPLETE_MESSAGE, SEC_E_OK, SEC_I_CONTEXT_EXPIRED, SEC_I_CONTINUE_NEEDED,
    SEC_I_INCOMPLETE_CREDENTIALS, SEC_I_RENEGOTIATE,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    ASC_REQ_ALLOCATE_MEMORY, ASC_REQ_CONFIDENTIALITY, ASC_REQ_EXTENDED_ERROR,
    ASC_REQ_REPLAY_DETECT, ASC_REQ_SEQUENCE_DETECT, ASC_REQ_STREAM, AcceptSecurityContext,
    AcquireCredentialsHandleW, DecryptMessage, DeleteSecurityContext, EncryptMessage,
    FreeContextBuffer, FreeCredentialsHandle, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY,
    ISC_REQ_EXTENDED_ERROR, ISC_REQ_MANUAL_CRED_VALIDATION, ISC_REQ_REPLAY_DETECT,
    ISC_REQ_SEQUENCE_DETECT, ISC_REQ_STREAM, InitializeSecurityContextW, QueryContextAttributesW,
    SCH_CRED_MANUAL_CRED_VALIDATION, SCH_CRED_NO_DEFAULT_CREDS, SCH_CREDENTIALS,
    SCH_CREDENTIALS_VERSION, SECBUFFER_ALERT, SECBUFFER_APPLICATION_PROTOCOLS, SECBUFFER_DATA,
    SECBUFFER_EMPTY, SECBUFFER_EXTRA, SECBUFFER_STREAM_HEADER, SECBUFFER_STREAM_TRAILER,
    SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_APPLICATION_PROTOCOL,
    SECPKG_ATTR_CONNECTION_INFO, SECPKG_ATTR_REMOTE_CERT_CONTEXT, SECPKG_ATTR_STREAM_SIZES,
    SECPKG_CRED_INBOUND, SECPKG_CRED_OUTBOUND, SecApplicationProtocolNegotiationExt_ALPN,
    SecApplicationProtocolNegotiationStatus_Success, SecBuffer, SecBufferDesc,
    SecPkgContext_ApplicationProtocol, SecPkgContext_ConnectionInfo, SecPkgContext_StreamSizes,
    UNISP_NAME_W,
};
use windows_sys::Win32::Security::Credentials::SecHandle;
use windows_sys::Win32::Security::Cryptography::CERT_CONTEXT;

use crate::crypto::{Cert, check, len32};

/// Handshake bytes buffered at most (certificate chains included).
const MAX_HANDSHAKE: usize = 256 * 1024;
/// Handshake round trips at most.
const MAX_ROUNDS: usize = 32;
/// Longest a handshake waits for the peer when the socket polls with short timeouts.
const HANDSHAKE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
/// Bytes read from the socket at once.
const READ_CHUNK: usize = 16 * 1024;

/// An SChannel credential: a server certificate, or the client role with manual validation.
pub(crate) struct Credentials(SecHandle);

impl Drop for Credentials {
    fn drop(&mut self) {
        // SAFETY: owned handle, freed once.
        unsafe { FreeCredentialsHandle(&self.0) };
    }
}

impl Credentials {
    /// `Some(cert)`: server credential for that certificate. `None`: client credential that
    /// leaves server certificate validation to us (see `Engine::verify`).
    pub(crate) fn new(server: Option<&Cert>) -> io::Result<Self> {
        let mut certs = [server.map_or(null_mut(), |c| c.0.cast_mut())];
        // SAFETY: plain data; all-zero is valid (system default protocols and ciphers).
        let mut sch: SCH_CREDENTIALS = unsafe { std::mem::zeroed() };
        sch.dwVersion = SCH_CREDENTIALS_VERSION;
        if server.is_some() {
            sch.cCreds = 1;
            sch.paCred = certs.as_mut_ptr();
        } else {
            sch.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
        }
        let role = if server.is_some() {
            SECPKG_CRED_INBOUND
        } else {
            SECPKG_CRED_OUTBOUND
        };
        let mut handle = SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        // SAFETY: `sch` and `certs` outlive the call; SChannel references the certificate.
        let status = unsafe {
            AcquireCredentialsHandleW(
                null(),
                UNISP_NAME_W,
                role,
                null(),
                (&raw const sch).cast(),
                None,
                null(),
                &mut handle,
                null_mut(),
            )
        };
        check(status, "AcquireCredentialsHandle").map(|()| Self(handle))
    }
}

/// A TLS connection. Reads and writes plaintext; the peer sees TLS.
pub struct TlsStream {
    tcp: TcpStream,
    creds: Arc<Credentials>,
    ctx: SecHandle,
    has_ctx: bool,
    /// Client role: the server name (SNI and certificate check), NUL-terminated.
    target: Option<Vec<u16>>,
    sizes: SecPkgContext_StreamSizes,
    protocol: u32,
    /// ALPN: the protocols to offer (`SEC_APPLICATION_PROTOCOLS`), then the one negotiated.
    offer: Vec<u8>,
    alpn: Option<String>,
    incoming: Vec<u8>,
    plain: Vec<u8>,
    plain_pos: usize,
    eof: bool,
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        if self.has_ctx {
            // SAFETY: owned context, deleted once.
            unsafe { DeleteSecurityContext(&self.ctx) };
        }
    }
}

fn read_more(tcp: &mut TcpStream, buf: &mut Vec<u8>, limit: usize) -> io::Result<()> {
    let mut chunk = [0u8; READ_CHUNK];
    let n = tcp.read(&mut chunk)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed during TLS",
        ));
    }
    if buf.len() + n > limit {
        return Err(io::Error::other("TLS record too large"));
    }
    buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    Ok(())
}

/// The trailing bytes SChannel did not consume (`SECBUFFER_EXTRA`).
fn extra(buffer: &SecBuffer, input: &[u8]) -> Vec<u8> {
    if buffer.BufferType == SECBUFFER_EXTRA {
        input
            .get(input.len().saturating_sub(buffer.cbBuffer as usize)..)
            .unwrap_or_default()
            .to_vec()
    } else {
        Vec::new()
    }
}

impl TlsStream {
    pub(crate) fn new(tcp: TcpStream, creds: Arc<Credentials>, target: Option<&str>) -> Self {
        Self {
            tcp,
            creds,
            ctx: SecHandle {
                dwLower: 0,
                dwUpper: 0,
            },
            has_ctx: false,
            target: target.map(crate::crypto::wide),
            sizes: SecPkgContext_StreamSizes {
                cbHeader: 0,
                cbTrailer: 0,
                cbMaximumMessage: 0,
                cBuffers: 0,
                cbBlockSize: 0,
            },
            protocol: 0,
            offer: Vec::new(),
            alpn: None,
            incoming: Vec::new(),
            plain: Vec::new(),
            plain_pos: 0,
            eof: false,
        }
    }

    /// Runs (or continues, for TLS 1.3 post-handshake messages) the handshake. `input` holds
    /// bytes already received from the peer.
    pub(crate) fn handshake(&mut self, mut input: Vec<u8>) -> io::Result<()> {
        for _ in 0..MAX_ROUNDS {
            let client_hello = self.target.is_some() && !self.has_ctx;
            if !client_hello && input.is_empty() {
                self.read_handshake(&mut input)?;
            }
            // ALPN goes with the first call of either role (the client's offer, the server's
            // choice).
            let alpn = !self.has_ctx && !self.offer.is_empty();
            let alpn_buffer = SecBuffer {
                cbBuffer: len32(self.offer.len())?,
                BufferType: SECBUFFER_APPLICATION_PROTOCOLS,
                pvBuffer: self.offer.as_mut_ptr().cast(),
            };
            let mut inbufs = [
                SecBuffer {
                    cbBuffer: len32(input.len())?,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: input.as_mut_ptr().cast(),
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_EMPTY,
                    pvBuffer: null_mut(),
                },
                alpn_buffer,
            ];
            let indesc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: if alpn { 3 } else { 2 },
                pBuffers: inbufs.as_mut_ptr(),
            };
            let mut hello_bufs = [alpn_buffer];
            let hello_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: hello_bufs.as_mut_ptr(),
            };
            let mut outbufs = [
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: null_mut(),
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_ALERT,
                    pvBuffer: null_mut(),
                },
            ];
            let mut outdesc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: outbufs.as_mut_ptr(),
            };
            let current: *const SecHandle = if self.has_ctx {
                &raw const self.ctx
            } else {
                null()
            };
            let mut attributes = 0u32;
            let status = match &self.target {
                // SAFETY: valid credential, buffers and out pointers; SChannel allocates the
                // output tokens (freed below).
                Some(target) => unsafe {
                    InitializeSecurityContextW(
                        &self.creds.0,
                        current,
                        target.as_ptr(),
                        ISC_REQ_SEQUENCE_DETECT
                            | ISC_REQ_REPLAY_DETECT
                            | ISC_REQ_CONFIDENTIALITY
                            | ISC_REQ_EXTENDED_ERROR
                            | ISC_REQ_ALLOCATE_MEMORY
                            | ISC_REQ_STREAM
                            | ISC_REQ_MANUAL_CRED_VALIDATION,
                        0,
                        0,
                        match (client_hello, alpn) {
                            (true, true) => &hello_desc,
                            (true, false) => null(),
                            (false, _) => &indesc,
                        },
                        0,
                        &mut self.ctx,
                        &mut outdesc,
                        &mut attributes,
                        null_mut(),
                    )
                },
                // SAFETY: as above.
                None => unsafe {
                    AcceptSecurityContext(
                        &self.creds.0,
                        current,
                        &indesc,
                        ASC_REQ_SEQUENCE_DETECT
                            | ASC_REQ_REPLAY_DETECT
                            | ASC_REQ_CONFIDENTIALITY
                            | ASC_REQ_EXTENDED_ERROR
                            | ASC_REQ_ALLOCATE_MEMORY
                            | ASC_REQ_STREAM,
                        0,
                        &mut self.ctx,
                        &mut outdesc,
                        &mut attributes,
                        null_mut(),
                    )
                },
            };
            if matches!(
                status,
                SEC_E_OK | SEC_I_CONTINUE_NEEDED | SEC_I_INCOMPLETE_CREDENTIALS
            ) {
                self.has_ctx = true;
            }
            let mut token = Vec::new();
            for out in &outbufs {
                if !out.pvBuffer.is_null() {
                    if out.BufferType == SECBUFFER_TOKEN {
                        // SAFETY: SChannel wrote `cbBuffer` bytes at `pvBuffer`.
                        token.extend_from_slice(unsafe {
                            std::slice::from_raw_parts(
                                out.pvBuffer.cast::<u8>(),
                                out.cbBuffer as usize,
                            )
                        });
                    }
                    // SAFETY: allocated by SChannel (ISC/ASC_REQ_ALLOCATE_MEMORY).
                    unsafe { FreeContextBuffer(out.pvBuffer) };
                }
            }
            if !token.is_empty() {
                self.tcp.write_all(&token)?; // on failure this carries the TLS alert
            }
            match status {
                SEC_E_OK => {
                    self.incoming = extra(&inbufs[1], &input);
                    return self.query_sizes();
                }
                SEC_I_CONTINUE_NEEDED | SEC_I_INCOMPLETE_CREDENTIALS => {
                    input = extra(&inbufs[1], &input)
                }
                SEC_E_INCOMPLETE_MESSAGE => self.read_handshake(&mut input)?,
                error => return check(error, "TLS handshake"),
            }
        }
        Err(io::Error::other("TLS handshake did not finish"))
    }

    /// Reads handshake bytes. A short read timeout (a relay polling the socket) only delays
    /// the handshake; it gives up after [`HANDSHAKE_WAIT`].
    fn read_handshake(&mut self, input: &mut Vec<u8>) -> io::Result<()> {
        let started = std::time::Instant::now();
        loop {
            match read_more(&mut self.tcp, input, MAX_HANDSHAKE) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) && started.elapsed() < HANDSHAKE_WAIT => {}
                other => return other,
            }
        }
    }
    fn query_sizes(&mut self) -> io::Result<()> {
        // SAFETY: the attribute fills exactly this structure.
        let status = unsafe {
            QueryContextAttributesW(
                &self.ctx,
                SECPKG_ATTR_STREAM_SIZES,
                (&raw mut self.sizes).cast(),
            )
        };
        check(status, "QueryContextAttributes")?;
        // SAFETY: plain data; filled by the call.
        let mut info: SecPkgContext_ConnectionInfo = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe {
            QueryContextAttributesW(
                &self.ctx,
                SECPKG_ATTR_CONNECTION_INFO,
                (&raw mut info).cast(),
            )
        } == SEC_E_OK
        {
            self.protocol = info.dwProtocol;
        }
        // SAFETY: plain data; filled by the call.
        let mut app: SecPkgContext_ApplicationProtocol = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let negotiated = unsafe {
            QueryContextAttributesW(
                &self.ctx,
                SECPKG_ATTR_APPLICATION_PROTOCOL,
                (&raw mut app).cast(),
            )
        } == SEC_E_OK
            && app.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success
            && app.ProtoNegoExt == SecApplicationProtocolNegotiationExt_ALPN;
        if negotiated {
            let id = app.ProtocolId.get(..usize::from(app.ProtocolIdSize));
            self.alpn = id.map(|id| String::from_utf8_lossy(id).into_owned());
        }
        Ok(())
    }

    /// Offers `protocols` with ALPN (client), or accepts the first of them the client offers
    /// (server). Call before the handshake.
    pub(crate) fn offer(&mut self, protocols: &[&str]) {
        if protocols.is_empty() {
            return;
        }
        // SEC_APPLICATION_PROTOCOLS with one SEC_APPLICATION_PROTOCOL_LIST: the lists' size,
        // the extension (ALPN), the list's size, then the length-prefixed names.
        let list: Vec<u8> = protocols
            .iter()
            .filter(|p| !p.is_empty() && p.len() <= 255)
            .flat_map(|p| std::iter::once(u8::try_from(p.len()).unwrap_or(0)).chain(p.bytes()))
            .collect();
        let size = u16::try_from(list.len()).unwrap_or(u16::MAX);
        let ext = SecApplicationProtocolNegotiationExt_ALPN.cast_unsigned();
        self.offer = [
            &(u32::from(size) + 6).to_le_bytes()[..],
            &ext.to_le_bytes(),
            &size.to_le_bytes(),
            &list,
        ]
        .concat();
    }

    /// The protocol negotiated with ALPN, if any (e.g. `h2`).
    #[must_use]
    pub fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    /// Client role: the server's certificate, for verification.
    pub(crate) fn peer_certificate(&self) -> io::Result<Cert> {
        let mut cert: *const CERT_CONTEXT = null();
        // SAFETY: returns a new certificate reference, owned by the returned `Cert`.
        let status = unsafe {
            QueryContextAttributesW(
                &self.ctx,
                SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                (&raw mut cert).cast(),
            )
        };
        check(status, "QueryContextAttributes")?;
        if cert.is_null() {
            Err(io::Error::other("the server sent no certificate"))
        } else {
            Ok(Cert(cert))
        }
    }

    /// Negotiated protocol, e.g. `TLS 1.3`.
    #[must_use]
    pub const fn protocol(&self) -> &'static str {
        match self.protocol {
            0x3000 | 0x1000 | 0x2000 => "TLS 1.3",
            0x0C00 | 0x0400 | 0x0800 => "TLS 1.2",
            0x0300 | 0x0100 | 0x0200 => "TLS 1.1",
            0x00C0 | 0x0040 | 0x0080 => "TLS 1.0",
            _ => "TLS",
        }
    }

    /// The underlying socket (timeouts, shutdown).
    #[must_use]
    pub const fn socket(&self) -> &TcpStream {
        &self.tcp
    }

    /// Decrypts buffered records into `plain`. Returns false when more input is needed.
    fn decrypt(&mut self) -> io::Result<bool> {
        let mut buffers = [
            SecBuffer {
                cbBuffer: len32(self.incoming.len())?,
                BufferType: SECBUFFER_DATA,
                pvBuffer: self.incoming.as_mut_ptr().cast(),
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_EMPTY,
                pvBuffer: null_mut(),
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_EMPTY,
                pvBuffer: null_mut(),
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_EMPTY,
                pvBuffer: null_mut(),
            },
        ];
        let desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 4,
            pBuffers: buffers.as_mut_ptr(),
        };
        // SAFETY: decrypts in place inside `incoming`; buffers point into it.
        let status = unsafe { DecryptMessage(&self.ctx, &desc, 0, null_mut()) };
        let base = self.incoming.as_ptr().addr();
        let mut plain = None;
        let mut rest = Vec::new();
        for b in &buffers {
            if b.BufferType == SECBUFFER_DATA && !b.pvBuffer.is_null() {
                let start = b.pvBuffer.addr().saturating_sub(base);
                plain = self
                    .incoming
                    .get(start..start + b.cbBuffer as usize)
                    .map(<[u8]>::to_vec);
            } else if b.BufferType == SECBUFFER_EXTRA {
                rest = extra(b, &self.incoming);
            }
        }
        match status {
            SEC_E_OK => {
                self.plain = plain.unwrap_or_default();
                self.plain_pos = 0;
                self.incoming = rest;
                Ok(true)
            }
            SEC_E_INCOMPLETE_MESSAGE => Ok(false),
            SEC_I_CONTEXT_EXPIRED => {
                self.eof = true; // close_notify
                Ok(true)
            }
            SEC_I_RENEGOTIATE => {
                // TLS 1.3 post-handshake message (session ticket, key update).
                self.incoming.clear();
                self.handshake(rest)?;
                Ok(true)
            }
            error => check(error, "DecryptMessage").map(|()| true),
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(available) = self.plain.get(self.plain_pos..).filter(|p| !p.is_empty()) {
                let n = available.len().min(out.len());
                out.get_mut(..n)
                    .unwrap_or_default()
                    .copy_from_slice(available.get(..n).unwrap_or_default());
                self.plain_pos += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            if self.incoming.is_empty() || !self.decrypt()? {
                // Complete records are always decrypted first, so at most one partial record
                // plus one socket read is ever buffered.
                let record = (self.sizes.cbHeader
                    + self.sizes.cbMaximumMessage
                    + self.sizes.cbTrailer) as usize;
                let limit = record + READ_CHUNK;
                match read_more(&mut self.tcp, &mut self.incoming, limit) {
                    Err(e)
                        if e.kind() == io::ErrorKind::UnexpectedEof && self.incoming.is_empty() =>
                    {
                        self.eof = true; // closed without close_notify at a record boundary
                    }
                    other => other?,
                }
            }
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(self.sizes.cbMaximumMessage as usize);
        let (header, trailer) = (self.sizes.cbHeader as usize, self.sizes.cbTrailer as usize);
        let mut record = vec![0u8; header + n + trailer];
        record
            .get_mut(header..header + n)
            .unwrap_or_default()
            .copy_from_slice(data.get(..n).unwrap_or_default());
        let base = record.as_mut_ptr();
        // SAFETY: the offsets stay within `record`.
        let (data_ptr, trailer_ptr) = unsafe { (base.add(header), base.add(header + n)) };
        let mut buffers = [
            SecBuffer {
                cbBuffer: len32(header)?,
                BufferType: SECBUFFER_STREAM_HEADER,
                pvBuffer: base.cast(),
            },
            SecBuffer {
                cbBuffer: len32(n)?,
                BufferType: SECBUFFER_DATA,
                pvBuffer: data_ptr.cast(),
            },
            SecBuffer {
                cbBuffer: len32(trailer)?,
                BufferType: SECBUFFER_STREAM_TRAILER,
                pvBuffer: trailer_ptr.cast(),
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_EMPTY,
                pvBuffer: null_mut(),
            },
        ];
        let desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 4,
            pBuffers: buffers.as_mut_ptr(),
        };
        // SAFETY: encrypts in place inside `record`.
        let status = unsafe { EncryptMessage(&self.ctx, 0, &desc, 0) };
        check(status, "EncryptMessage")?;
        let total = buffers
            .iter()
            .take(3)
            .map(|b| b.cbBuffer as usize)
            .sum::<usize>();
        self.tcp
            .write_all(record.get(..total).unwrap_or_default())?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}
