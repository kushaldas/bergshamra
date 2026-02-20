#![forbid(unsafe_code)]

//! PKCS#12 (.p12/.pfx) parser for the Bergshamra XML Security library.
//!
//! Supports both legacy PBE (SHA-1 + 3DES-CBC) and modern PBES2
//! (PBKDF2 + AES-256-CBC) encryption as used by OpenSSL 3.x.

mod kdf;
mod parse;

/// Contents extracted from a PKCS#12 file.
#[derive(Debug)]
pub struct Pkcs12Contents {
    /// PKCS#8 DER-encoded private keys.
    pub private_keys: Vec<Vec<u8>>,
    /// DER-encoded X.509 certificates.
    pub certificates: Vec<Vec<u8>>,
}

/// Parse a PKCS#12 file, decrypting with the given password.
pub fn parse_pkcs12(data: &[u8], password: &str) -> Result<Pkcs12Contents, bergshamra_core::Error> {
    parse::parse_pfx(data, password)
}
