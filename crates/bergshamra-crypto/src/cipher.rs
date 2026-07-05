#![forbid(unsafe_code)]

//! Block cipher algorithm implementations (AES-CBC, AES-GCM, 3DES-CBC).

use bergshamra_core::{algorithm, Error};
use kryptering::algorithm::{AesKeySize, CipherAlgorithm as KCipherAlgorithm};

/// Trait for cipher algorithms.
pub trait CipherAlgorithm: Send {
    /// Return the XML Encryption algorithm URI implemented by this cipher.
    fn uri(&self) -> &'static str;

    /// Encrypt `plaintext` with `key`.
    ///
    /// The `key` length must match [`CipherAlgorithm::key_size`]. The returned
    /// bytes are the XML Encryption cipher payload for the selected algorithm,
    /// including any algorithm-specific IV or nonce material.
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypt `ciphertext` with `key`.
    ///
    /// The input must be in the format produced by [`CipherAlgorithm::encrypt`]
    /// for the same algorithm URI.
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Return the required symmetric key size in bytes.
    fn key_size(&self) -> usize;
}

/// Map an XML algorithm URI to a `kryptering::CipherAlgorithm`.
fn uri_to_cipher(uri: &str) -> Result<(KCipherAlgorithm, &'static str), Error> {
    match uri {
        algorithm::AES128_CBC => Ok((
            KCipherAlgorithm::AesCbc(AesKeySize::Aes128),
            algorithm::AES128_CBC,
        )),
        algorithm::AES192_CBC => Ok((
            KCipherAlgorithm::AesCbc(AesKeySize::Aes192),
            algorithm::AES192_CBC,
        )),
        algorithm::AES256_CBC => Ok((
            KCipherAlgorithm::AesCbc(AesKeySize::Aes256),
            algorithm::AES256_CBC,
        )),
        algorithm::AES128_GCM => Ok((
            KCipherAlgorithm::AesGcm(AesKeySize::Aes128),
            algorithm::AES128_GCM,
        )),
        algorithm::AES192_GCM => Ok((
            KCipherAlgorithm::AesGcm(AesKeySize::Aes192),
            algorithm::AES192_GCM,
        )),
        algorithm::AES256_GCM => Ok((
            KCipherAlgorithm::AesGcm(AesKeySize::Aes256),
            algorithm::AES256_GCM,
        )),
        algorithm::TRIPLEDES_CBC => Ok((KCipherAlgorithm::TripleDesCbc, algorithm::TRIPLEDES_CBC)),
        _ => Err(Error::UnsupportedAlgorithm(format!("cipher: {uri}"))),
    }
}

/// Create a cipher algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn CipherAlgorithm>, Error> {
    let (algo, static_uri) = uri_to_cipher(uri)?;
    Ok(Box::new(KrypteringCipher {
        algo,
        uri: static_uri,
    }))
}

// ── Wrapper that delegates to kryptering ────────────────────────────

struct KrypteringCipher {
    algo: KCipherAlgorithm,
    uri: &'static str,
}

impl CipherAlgorithm for KrypteringCipher {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn key_size(&self) -> usize {
        self.algo.key_size()
    }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        match self.algo {
            // AES-CBC lives under kryptering::hazmat::aes_cbc because it is
            // unauthenticated and a padding-oracle hazard when exposed to
            // remote attackers. XML-Enc 1.0 requires it for interop, which
            // is the legitimate use case here; the hazard still applies and
            // callers must authenticate ciphertexts out of band.
            KCipherAlgorithm::AesCbc(size) => {
                kryptering::hazmat::aes_cbc::encrypt(size, key, plaintext)
                    .map_err(crate::map_kryptering_err)
            }
            _ => kryptering::cipher::encrypt(self.algo, key, plaintext)
                .map_err(crate::map_kryptering_err),
        }
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        match self.algo {
            KCipherAlgorithm::AesCbc(size) => {
                kryptering::hazmat::aes_cbc::decrypt(size, key, ciphertext)
                    .map_err(crate::map_kryptering_err)
            }
            _ => kryptering::cipher::decrypt(self.algo, key, ciphertext)
                .map_err(crate::map_kryptering_err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = [0x42u8; 16];
        let cipher = from_uri(algorithm::AES128_CBC).unwrap();
        let pt = b"hello world test";
        let ct = cipher.encrypt(&key, pt).unwrap();
        let decrypted = cipher.decrypt(&key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = from_uri(algorithm::AES256_GCM).unwrap();
        let pt = b"hello world";
        let ct = cipher.encrypt(&key, pt).unwrap();
        let decrypted = cipher.decrypt(&key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_3des_roundtrip() {
        let key = [0x42u8; 24];
        let cipher = from_uri(algorithm::TRIPLEDES_CBC).unwrap();
        let pt = b"test data";
        let ct = cipher.encrypt(&key, pt).unwrap();
        let decrypted = cipher.decrypt(&key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    // ── AES-GCM authentication failure test (ported from signedxml) ──

    #[test]
    fn test_aes_gcm_authentication_failure() {
        // Encrypt with AES-128-GCM, then corrupt the ciphertext and verify
        // that decryption fails (GCM authentication tag check).
        let key = [0x42u8; 16];
        let cipher = from_uri(algorithm::AES128_GCM).unwrap();
        let pt = b"test message for GCM auth failure";
        let mut ct = cipher.encrypt(&key, pt).unwrap();

        // Corrupt the last byte (part of the GCM authentication tag)
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let result = cipher.decrypt(&key, &ct);
        assert!(
            result.is_err(),
            "decryption should fail for corrupted GCM ciphertext"
        );
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        // Encrypt with one key, try to decrypt with another
        let key1 = [0x42u8; 16];
        let key2 = [0x99u8; 16];
        let cipher = from_uri(algorithm::AES128_GCM).unwrap();
        let pt = b"sensitive data";
        let ct = cipher.encrypt(&key1, pt).unwrap();

        let result = cipher.decrypt(&key2, &ct);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    // ── AES-GCM round-trip for all key sizes (ported from signedxml) ──

    #[test]
    fn test_aes_gcm_roundtrip_all_sizes() {
        let cases: &[(&str, usize)] = &[
            (algorithm::AES128_GCM, 16),
            (algorithm::AES192_GCM, 24),
            (algorithm::AES256_GCM, 32),
        ];
        let pt = b"Hello, World! This is a test message for AES-GCM encryption.";

        for &(uri, key_size) in cases {
            let key: Vec<u8> = (0..key_size).map(|i| i as u8).collect();
            let cipher = from_uri(uri).unwrap();
            let ct = cipher.encrypt(&key, pt).unwrap();
            let decrypted = cipher.decrypt(&key, &ct).unwrap();
            assert_eq!(decrypted, pt, "roundtrip failed for {uri}");
        }
    }

    // ── AES-CBC round-trip for all key sizes and plaintext sizes ─────

    #[test]
    fn test_aes_cbc_roundtrip_all_sizes() {
        let cases: &[(&str, usize)] = &[
            (algorithm::AES128_CBC, 16),
            (algorithm::AES192_CBC, 24),
            (algorithm::AES256_CBC, 32),
        ];
        let plaintexts: &[&[u8]] = &[
            b"A",
            b"Hello",
            b"Hello, World!",
            b"Exactly16bytes!!", // Exactly one AES block
            b"This is a much longer test message that spans multiple AES blocks.",
        ];

        for &(uri, key_size) in cases {
            let key: Vec<u8> = (0..key_size).map(|i| i as u8).collect();
            let cipher = from_uri(uri).unwrap();
            for &pt in plaintexts {
                let ct = cipher.encrypt(&key, pt).unwrap();
                let decrypted = cipher.decrypt(&key, &ct).unwrap();
                assert_eq!(
                    decrypted,
                    pt,
                    "roundtrip failed for {uri}, pt_len={}",
                    pt.len()
                );
            }
        }
    }

    // ── W3C algorithm URI validation (ported from signedxml) ─────────

    #[test]
    fn test_w3c_algorithm_uri_correctness() {
        // Block encryption
        assert_eq!(
            algorithm::AES128_GCM,
            "http://www.w3.org/2009/xmlenc11#aes128-gcm"
        );
        assert_eq!(
            algorithm::AES192_GCM,
            "http://www.w3.org/2009/xmlenc11#aes192-gcm"
        );
        assert_eq!(
            algorithm::AES256_GCM,
            "http://www.w3.org/2009/xmlenc11#aes256-gcm"
        );
        assert_eq!(
            algorithm::AES128_CBC,
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
        );
        assert_eq!(
            algorithm::AES192_CBC,
            "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
        );
        assert_eq!(
            algorithm::AES256_CBC,
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        );
        // Key wrapping
        assert_eq!(
            algorithm::KW_AES128,
            "http://www.w3.org/2001/04/xmlenc#kw-aes128"
        );
        assert_eq!(
            algorithm::KW_AES192,
            "http://www.w3.org/2001/04/xmlenc#kw-aes192"
        );
        assert_eq!(
            algorithm::KW_AES256,
            "http://www.w3.org/2001/04/xmlenc#kw-aes256"
        );
    }

    #[test]
    fn test_all_w3c_cipher_algorithms_round_trip() {
        // Test all 6 W3C-specified block cipher algorithms via from_uri()
        let algorithms: &[(&str, usize)] = &[
            (algorithm::AES128_GCM, 16),
            (algorithm::AES192_GCM, 24),
            (algorithm::AES256_GCM, 32),
            (algorithm::AES128_CBC, 16),
            (algorithm::AES192_CBC, 24),
            (algorithm::AES256_CBC, 32),
        ];
        let pt = b"Test plaintext for W3C algorithm testing";

        for &(uri, key_size) in algorithms {
            let key: Vec<u8> = (0..key_size).map(|i| i as u8).collect();
            let cipher = from_uri(uri).unwrap();
            assert_eq!(cipher.key_size(), key_size, "key_size() mismatch for {uri}");
            let ct = cipher.encrypt(&key, pt).unwrap();
            let decrypted = cipher.decrypt(&key, &ct).unwrap();
            assert_eq!(decrypted, pt, "roundtrip failed for {uri}");
        }
    }

    #[test]
    fn test_unsupported_cipher_algorithm() {
        let result = from_uri("http://example.com/fake-cipher");
        assert!(result.is_err());
    }
}
