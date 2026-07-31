#![forbid(unsafe_code)]

//! PKCS#12 (.p12/.pfx) parser for the Bergshamra XML Security library.
//!
//! Supports both legacy PBE (SHA-1 + 3DES-CBC) and modern PBES2
//! (PBKDF2 + AES-256-CBC) encryption as used by OpenSSL 3.x.

mod kdf;
mod parse;

/// Zeroizing, provider-neutral PKCS#8 private-key encoding.
pub struct PrivateKeyDer(zeroize::Zeroizing<Vec<u8>>);

impl PrivateKeyDer {
    #[must_use]
    pub fn new(der: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(der))
    }
}

impl AsRef<[u8]> for PrivateKeyDer {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::ops::Deref for PrivateKeyDer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl std::fmt::Debug for PrivateKeyDer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateKeyDer")
            .field("length", &self.0.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Contents extracted from a PKCS#12 file.
#[derive(Debug)]
pub struct Pkcs12Contents {
    /// PKCS#8 DER-encoded private keys.
    pub private_keys: Vec<PrivateKeyDer>,
    /// DER-encoded X.509 certificates.
    pub certificates: Vec<Vec<u8>>,
}

/// Parse a PKCS#12 file, decrypting with the given password.
pub fn parse_pkcs12(data: &[u8], password: &str) -> Result<Pkcs12Contents, bergshamra_core::Error> {
    parse::parse_pfx(data, password)
}
