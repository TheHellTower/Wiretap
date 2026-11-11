//! CNG keys, certificate contexts, certificate stores and chain verification.
#![allow(
    unsafe_code,
    reason = "CNG and CryptoAPI FFI; every block carries a SAFETY comment"
)]

use std::io;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
use windows_sys::Win32::Security::Cryptography::{
    AUTHTYPE_SERVER, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_RSAPUBLIC_BLOB,
    BCRYPT_SHA1_ALG_HANDLE, BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA256_ALGORITHM,
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom, BCryptHash, CERT_CHAIN_ENGINE_CONFIG,
    CERT_CHAIN_PARA, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_SSL, CERT_CHAIN_POLICY_STATUS,
    CERT_CONTEXT, CERT_FIND_PUBLIC_KEY, CERT_KEY_PROV_INFO_PROP_ID, CERT_STORE_ADD_USE_EXISTING,
    CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
    CRYPT_KEY_PROV_INFO, CertAddCertificateContextToStore, CertCloseStore,
    CertCreateCertificateChainEngine, CertCreateCertificateContext, CertDeleteCertificateFromStore,
    CertFindCertificateInStore, CertFreeCertificateChain, CertFreeCertificateChainEngine,
    CertFreeCertificateContext, CertGetCertificateChain, CertOpenStore,
    CertSetCertificateContextProperty, CertVerifyCertificateChainPolicy, HCERTCHAINENGINE,
    HCERTSTORE, HTTPSPolicyCallbackData, MS_KEY_STORAGE_PROVIDER, NCRYPT_KEY_HANDLE,
    NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
    USAGE_MATCH_TYPE_AND, X509_ASN_ENCODING, szOID_PKIX_KP_SERVER_AUTH,
};

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub(crate) fn len32(n: usize) -> io::Result<u32> {
    u32::try_from(n).map_err(|_| io::Error::other("buffer too large"))
}

/// Maps a failed HRESULT/NTSTATUS to an error naming the call.
pub(crate) fn check(status: i32, what: &str) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{what} failed (0x{:08X})",
            status.cast_unsigned()
        )))
    }
}

pub(crate) fn random(buf: &mut [u8]) -> io::Result<()> {
    // SAFETY: writes exactly `buf.len()` bytes into `buf`.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            buf.as_mut_ptr(),
            len32(buf.len())?,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    check(status, "BCryptGenRandom")
}

pub(crate) fn sha1(data: &[u8]) -> io::Result<[u8; 20]> {
    let mut out = [0u8; 20];
    // SAFETY: the SHA-1 pseudo-handle needs no setup; `out` has the digest size.
    let status = unsafe {
        BCryptHash(
            BCRYPT_SHA1_ALG_HANDLE,
            null(),
            0,
            data.as_ptr(),
            len32(data.len())?,
            out.as_mut_ptr(),
            20,
        )
    };
    check(status, "BCryptHash").map(|()| out)
}

fn sha256(data: &[u8]) -> io::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    // SAFETY: as in `sha1`.
    let status = unsafe {
        BCryptHash(
            BCRYPT_SHA256_ALG_HANDLE,
            null(),
            0,
            data.as_ptr(),
            len32(data.len())?,
            out.as_mut_ptr(),
            32,
        )
    };
    check(status, "BCryptHash").map(|()| out)
}

/// A persisted, non-exportable RSA key in the user's Microsoft Software Key Storage Provider.
pub(crate) struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once.
        unsafe { NCryptFreeObject(self.0) };
    }
}

struct Provider(NCRYPT_PROV_HANDLE);

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once.
        unsafe { NCryptFreeObject(self.0) };
    }
}

impl Key {
    /// Opens the key `name`, creating it (`bits` long) on first use.
    pub(crate) fn open_or_create(name: &str, bits: u32) -> io::Result<Self> {
        let mut provider = 0;
        // SAFETY: valid out pointer and NUL-terminated provider name.
        let status =
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) };
        check(status, "NCryptOpenStorageProvider")?;
        let provider = Provider(provider);
        let name = wide(name);
        let mut key = 0;
        // SAFETY: valid provider handle, out pointer and NUL-terminated name.
        let status =
            unsafe { NCryptOpenKey(provider.0, &mut key, name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        if status == 0 {
            return Ok(Self(key));
        }
        if status != NTE_BAD_KEYSET {
            check(status, "NCryptOpenKey")?;
        }
        // SAFETY: as above; the default export policy keeps the private key non-exportable.
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                BCRYPT_RSA_ALGORITHM,
                name.as_ptr(),
                0,
                0,
            )
        };
        check(status, "NCryptCreatePersistedKey")?;
        let key = Self(key);
        // SAFETY: the Length property takes a 4-byte DWORD.
        let status = unsafe {
            NCryptSetProperty(
                key.0,
                NCRYPT_LENGTH_PROPERTY,
                (&raw const bits).cast(),
                4,
                0,
            )
        };
        check(status, "NCryptSetProperty")?;
        // SAFETY: finalizes the key created above.
        let status = unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) };
        check(status, "NCryptFinalizeKey")?;
        Ok(key)
    }

    /// `(modulus, public exponent)`, big-endian.
    pub(crate) fn rsa_public(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut len = 0u32;
        // SAFETY: size query (null output buffer).
        let status = unsafe {
            NCryptExportKey(
                self.0,
                0,
                BCRYPT_RSAPUBLIC_BLOB,
                null(),
                null_mut(),
                0,
                &mut len,
                0,
            )
        };
        check(status, "NCryptExportKey")?;
        let mut blob = vec![0u8; len as usize];
        // SAFETY: `blob` holds `len` bytes.
        let status = unsafe {
            NCryptExportKey(
                self.0,
                0,
                BCRYPT_RSAPUBLIC_BLOB,
                null(),
                blob.as_mut_ptr(),
                len,
                &mut len,
                0,
            )
        };
        check(status, "NCryptExportKey")?;
        // BCRYPT_RSAKEY_BLOB: six little-endian u32 fields, then exponent and modulus.
        let field = |i: usize| -> usize {
            blob.get(i * 4..i * 4 + 4)
                .and_then(|b| b.try_into().ok())
                .map_or(0, |b| u32::from_le_bytes(b) as usize)
        };
        let (exponent_len, modulus_len) = (field(2), field(3));
        let exponent = blob.get(24..24 + exponent_len);
        let modulus = blob.get(24 + exponent_len..24 + exponent_len + modulus_len);
        match (modulus, exponent) {
            (Some(m), Some(e)) => Ok((m.to_vec(), e.to_vec())),
            _ => Err(io::Error::other("malformed RSA public key blob")),
        }
    }

    /// RSASSA-PKCS1-v1_5 signature over SHA-256(`data`).
    pub(crate) fn sign(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let hash = sha256(data)?;
        let padding = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
        };
        let info = (&raw const padding).cast();
        let mut len = 0u32;
        // SAFETY: size query; `padding` and `hash` outlive the call.
        let status = unsafe {
            NCryptSignHash(
                self.0,
                info,
                hash.as_ptr(),
                32,
                null_mut(),
                0,
                &mut len,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        };
        check(status, "NCryptSignHash")?;
        let mut signature = vec![0u8; len as usize];
        // SAFETY: `signature` holds `len` bytes.
        let status = unsafe {
            NCryptSignHash(
                self.0,
                info,
                hash.as_ptr(),
                32,
                signature.as_mut_ptr(),
                len,
                &mut len,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        };
        check(status, "NCryptSignHash")?;
        signature.truncate(len as usize);
        Ok(signature)
    }

    /// Deletes the key from storage.
    pub(crate) fn delete(self) -> io::Result<()> {
        let handle = self.0;
        std::mem::forget(self);
        // SAFETY: NCryptDeleteKey frees the handle on success; on failure it is still ours.
        let status = unsafe { NCryptDeleteKey(handle, 0) };
        if status != 0 {
            // SAFETY: still a valid handle after a failed delete.
            unsafe { NCryptFreeObject(handle) };
        }
        check(status, "NCryptDeleteKey")
    }
}

/// An owned certificate context.
pub(crate) struct Cert(pub(crate) *const CERT_CONTEXT);

// SAFETY: certificate contexts are immutable, reference-counted and thread-safe.
unsafe impl Send for Cert {}
// SAFETY: as above.
unsafe impl Sync for Cert {}

impl Drop for Cert {
    fn drop(&mut self) {
        // SAFETY: owned reference, released once.
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

impl Cert {
    pub(crate) fn from_der(der: &[u8]) -> io::Result<Self> {
        // SAFETY: CryptoAPI copies and parses the encoded certificate.
        let ctx = unsafe {
            CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), len32(der.len())?)
        };
        if ctx.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(ctx))
        }
    }

    pub(crate) fn der(&self) -> &[u8] {
        // SAFETY: the context owns `cbCertEncoded` bytes at `pbCertEncoded` while it lives.
        unsafe {
            std::slice::from_raw_parts((*self.0).pbCertEncoded, (*self.0).cbCertEncoded as usize)
        }
    }

    /// Links the persisted CNG key `container` as this certificate's private key, which is how
    /// SChannel (in LSASS) finds it.
    pub(crate) fn link_key(&self, container: &str) -> io::Result<()> {
        let mut container = wide(container);
        let mut provider = wide("Microsoft Software Key Storage Provider");
        // SAFETY: plain data; all-zero is valid (no parameters, CNG provider type 0).
        let mut info: CRYPT_KEY_PROV_INFO = unsafe { std::mem::zeroed() };
        info.pwszContainerName = container.as_mut_ptr();
        info.pwszProvName = provider.as_mut_ptr();
        // SAFETY: CryptoAPI copies the property; the strings outlive the call.
        let ok = unsafe {
            CertSetCertificateContextProperty(
                self.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                0,
                (&raw const info).cast(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// An open certificate store.
pub(crate) struct Store(HCERTSTORE);

// SAFETY: store handles are thread-safe.
unsafe impl Send for Store {}
// SAFETY: as above.
unsafe impl Sync for Store {}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: owned handle, closed once.
        unsafe { CertCloseStore(self.0, 0) };
    }
}

impl Store {
    /// The current user's trusted root store. Windows itself asks the user to confirm every
    /// addition and removal.
    pub(crate) fn user_root() -> io::Result<Self> {
        let name = wide("Root");
        // SAFETY: system store provider with a NUL-terminated store name.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                CERT_SYSTEM_STORE_CURRENT_USER,
                name.as_ptr().cast(),
            )
        };
        if store.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(store))
        }
    }

    pub(crate) fn memory() -> io::Result<Self> {
        // SAFETY: an empty in-memory store.
        let store = unsafe { CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, null()) };
        if store.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(store))
        }
    }

    pub(crate) fn add(&self, cert: &Cert) -> io::Result<()> {
        // SAFETY: valid store and certificate context.
        let ok = unsafe {
            CertAddCertificateContextToStore(
                self.0,
                cert.0,
                CERT_STORE_ADD_USE_EXISTING,
                null_mut(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// A certificate in the store with the same public key as `cert`, if any.
    fn find_key(&self, cert: &Cert) -> Option<Cert> {
        // SAFETY: `cert` is valid, so is its CERT_INFO; the result is a new reference.
        let found = unsafe {
            CertFindCertificateInStore(
                self.0,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_PUBLIC_KEY,
                (&raw const (*(*cert.0).pCertInfo).SubjectPublicKeyInfo).cast(),
                null(),
            )
        };
        (!found.is_null()).then_some(Cert(found))
    }

    pub(crate) fn contains_key(&self, cert: &Cert) -> bool {
        self.find_key(cert).is_some()
    }

    /// Removes every certificate sharing `cert`'s public key.
    pub(crate) fn remove_key(&self, cert: &Cert) -> io::Result<()> {
        while let Some(found) = self.find_key(cert) {
            let ctx = found.0;
            std::mem::forget(found);
            // SAFETY: CertDeleteCertificateFromStore always releases the context it is given.
            if unsafe { CertDeleteCertificateFromStore(ctx) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// A certificate chain engine: the user's trust (null handle) or a single exclusive root.
pub(crate) struct Engine {
    handle: HCERTCHAINENGINE,
    _roots: Option<Store>,
}

// SAFETY: chain engines are thread-safe.
unsafe impl Send for Engine {}
// SAFETY: as above.
unsafe impl Sync for Engine {}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: owned engine, freed once.
            unsafe { CertFreeCertificateChainEngine(self.handle) };
        }
    }
}

impl Engine {
    pub(crate) const fn user() -> Self {
        Self {
            handle: null_mut(),
            _roots: None,
        }
    }

    pub(crate) fn exclusive(root: &Cert) -> io::Result<Self> {
        let roots = Store::memory()?;
        roots.add(root)?;
        // SAFETY: plain data; all-zero means defaults.
        let mut config: CERT_CHAIN_ENGINE_CONFIG = unsafe { std::mem::zeroed() };
        config.cbSize = len32(size_of::<CERT_CHAIN_ENGINE_CONFIG>())?;
        config.hExclusiveRoot = roots.0;
        let mut handle = null_mut();
        // SAFETY: valid config and out pointer; `roots` is kept alive with the engine.
        if unsafe { CertCreateCertificateChainEngine(&config, &mut handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            _roots: Some(roots),
        })
    }

    /// Verifies `cert` (with the intermediates in its store) as a TLS server certificate for
    /// `host`: trusted chain, validity, server-auth usage and name.
    pub(crate) fn verify(&self, cert: *const CERT_CONTEXT, host: &str) -> io::Result<()> {
        let mut usage = [szOID_PKIX_KP_SERVER_AUTH.cast_mut()];
        // SAFETY: plain data; all-zero is valid.
        let mut para: CERT_CHAIN_PARA = unsafe { std::mem::zeroed() };
        para.cbSize = len32(size_of::<CERT_CHAIN_PARA>())?;
        para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        para.RequestedUsage.Usage.cUsageIdentifier = 1;
        para.RequestedUsage.Usage.rgpszUsageIdentifier = usage.as_mut_ptr();
        let mut chain = null_mut();
        // SAFETY: `cert` is a live context; `para` and `usage` outlive the call.
        let ok = unsafe {
            CertGetCertificateChain(
                self.handle,
                cert,
                null(),
                (*cert).hCertStore,
                &para,
                0,
                null(),
                &mut chain,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut name = wide(host);
        // SAFETY: plain data; all-zero is valid.
        let mut extra: HTTPSPolicyCallbackData = unsafe { std::mem::zeroed() };
        extra.Anonymous.cbStruct = len32(size_of::<HTTPSPolicyCallbackData>())?;
        extra.dwAuthType = AUTHTYPE_SERVER;
        extra.pwszServerName = name.as_mut_ptr();
        let policy = CERT_CHAIN_POLICY_PARA {
            cbSize: len32(size_of::<CERT_CHAIN_POLICY_PARA>())?,
            dwFlags: 0,
            pvExtraPolicyPara: (&raw mut extra).cast(),
        };
        // SAFETY: plain data; all-zero is valid.
        let mut status: CERT_CHAIN_POLICY_STATUS = unsafe { std::mem::zeroed() };
        status.cbSize = len32(size_of::<CERT_CHAIN_POLICY_STATUS>())?;
        // SAFETY: `chain` was just built; the policy structures outlive the call.
        let ok = unsafe {
            CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policy, &mut status)
        };
        // SAFETY: releases the chain built above.
        unsafe { CertFreeCertificateChain(chain) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        match status.dwError {
            0 => Ok(()),
            0x800B_0109 => Err(io::Error::other(
                "server certificate is not trusted (unknown root)",
            )),
            0x800B_010F => Err(io::Error::other(format!(
                "server certificate is not valid for {host}"
            ))),
            0x800B_0101 => Err(io::Error::other(
                "server certificate has expired or is not yet valid",
            )),
            code => Err(io::Error::other(format!(
                "server certificate rejected (0x{code:08X})"
            ))),
        }
    }
}
