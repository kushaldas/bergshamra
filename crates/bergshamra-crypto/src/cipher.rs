#![forbid(unsafe_code)]

//! Block cipher algorithm implementations (AES-CBC, AES-GCM, 3DES-CBC).

use bergshamra_core::{algorithm, Error};

/// Trait for cipher algorithms.
pub trait CipherAlgorithm: Send {
    fn uri(&self) -> &'static str;
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
    fn key_size(&self) -> usize;
}

/// Create a cipher algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn CipherAlgorithm>, Error> {
    match uri {
        algorithm::AES128_CBC => Ok(Box::new(AesCbc {
            key_size: 16,
            uri: algorithm::AES128_CBC,
        })),
        algorithm::AES192_CBC => Ok(Box::new(AesCbc {
            key_size: 24,
            uri: algorithm::AES192_CBC,
        })),
        algorithm::AES256_CBC => Ok(Box::new(AesCbc {
            key_size: 32,
            uri: algorithm::AES256_CBC,
        })),
        algorithm::AES128_GCM => Ok(Box::new(AesGcm {
            key_size: 16,
            uri: algorithm::AES128_GCM,
        })),
        algorithm::AES192_GCM => Ok(Box::new(AesGcm {
            key_size: 24,
            uri: algorithm::AES192_GCM,
        })),
        algorithm::AES256_GCM => Ok(Box::new(AesGcm {
            key_size: 32,
            uri: algorithm::AES256_GCM,
        })),
        algorithm::TRIPLEDES_CBC => Ok(Box::new(TripleDesCbc)),
        _ => Err(Error::UnsupportedAlgorithm(format!("cipher: {uri}"))),
    }
}

// ── AES-CBC with PKCS#7 padding ─────────────────────────────────────

struct AesCbc {
    key_size: usize,
    uri: &'static str,
}

impl CipherAlgorithm for AesCbc {
    fn uri(&self) -> &'static str {
        self.uri
    }
    fn key_size(&self) -> usize {
        self.key_size
    }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use rand::RngCore;

        if key.len() != self.key_size {
            return Err(Error::Crypto(format!(
                "expected {} byte key, got {}",
                self.key_size,
                key.len()
            )));
        }

        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        // Already PKCS7-padded, use NoPadding in cipher
        let mut buf = pkcs7_pad(plaintext, 16);
        let buf_len = buf.len();

        macro_rules! do_encrypt {
            ($aes:ty) => {{
                let enc = cbc::Encryptor::<$aes>::new_from_slices(key, &iv)
                    .map_err(|e| Error::Crypto(format!("AES-CBC init: {e}")))?;
                enc.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, buf_len)
                    .map_err(|e| Error::Crypto(format!("AES-CBC encrypt: {e}")))?;
            }};
        }

        match self.key_size {
            16 => do_encrypt!(aes::Aes128),
            24 => do_encrypt!(aes::Aes192),
            32 => do_encrypt!(aes::Aes256),
            _ => return Err(Error::Crypto("unsupported AES key size".into())),
        }

        let mut result = Vec::with_capacity(16 + buf.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&buf);
        Ok(result)
    }

    fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};

        if key.len() != self.key_size {
            return Err(Error::Crypto(format!(
                "expected {} byte key, got {}",
                self.key_size,
                key.len()
            )));
        }
        if data.len() < 16 || data.len() % 16 != 0 {
            return Err(Error::Crypto("AES-CBC data invalid length".into()));
        }

        let iv = &data[..16];
        let ciphertext = &data[16..];
        let mut buf = ciphertext.to_vec();

        macro_rules! do_decrypt {
            ($aes:ty) => {{
                let dec = cbc::Decryptor::<$aes>::new_from_slices(key, iv)
                    .map_err(|e| Error::Crypto(format!("AES-CBC init: {e}")))?;
                dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                    .map_err(|e| Error::Crypto(format!("AES-CBC decrypt: {e}")))?;
            }};
        }

        match self.key_size {
            16 => do_decrypt!(aes::Aes128),
            24 => do_decrypt!(aes::Aes192),
            32 => do_decrypt!(aes::Aes256),
            _ => return Err(Error::Crypto("unsupported AES key size".into())),
        }

        xmlenc_unpad(&buf, 16)
    }
}

// ── AES-GCM ──────────────────────────────────────────────────────────

struct AesGcm {
    key_size: usize,
    uri: &'static str,
}

impl CipherAlgorithm for AesGcm {
    fn uri(&self) -> &'static str {
        self.uri
    }
    fn key_size(&self) -> usize {
        self.key_size
    }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        use aes_gcm::{aead::Aead, KeyInit, Nonce};
        use rand::RngCore;

        if key.len() != self.key_size {
            return Err(Error::Crypto(format!(
                "expected {} byte key, got {}",
                self.key_size,
                key.len()
            )));
        }

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = match self.key_size {
            16 => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
            }
            24 => {
                use aes_gcm::aead::consts::U12;
                let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
            }
            32 => {
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
            }
            _ => {
                return Err(Error::Crypto(
                    "AES-GCM only supports 128, 192, and 256 bit keys".into(),
                ))
            }
        };

        let mut result = Vec::with_capacity(12 + ct.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ct);
        Ok(result)
    }

    fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        use aes_gcm::{aead::Aead, KeyInit, Nonce};

        if key.len() != self.key_size {
            return Err(Error::Crypto(format!(
                "expected {} byte key, got {}",
                self.key_size,
                key.len()
            )));
        }
        if data.len() < 12 + 16 {
            return Err(Error::Crypto("AES-GCM data too short".into()));
        }

        let nonce = Nonce::from_slice(&data[..12]);
        let ct_and_tag = &data[12..];

        match self.key_size {
            16 => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher
                    .decrypt(nonce, ct_and_tag)
                    .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
            }
            24 => {
                use aes_gcm::aead::consts::U12;
                let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher
                    .decrypt(nonce, ct_and_tag)
                    .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
            }
            32 => {
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher
                    .decrypt(nonce, ct_and_tag)
                    .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
            }
            _ => Err(Error::Crypto(
                "AES-GCM only supports 128, 192, and 256 bit keys".into(),
            )),
        }
    }
}

// ── 3DES-CBC ─────────────────────────────────────────────────────────

struct TripleDesCbc;

impl CipherAlgorithm for TripleDesCbc {
    fn uri(&self) -> &'static str {
        algorithm::TRIPLEDES_CBC
    }
    fn key_size(&self) -> usize {
        24
    }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use rand::RngCore;

        if key.len() != 24 {
            return Err(Error::Crypto(format!(
                "3DES key must be 24 bytes, got {}",
                key.len()
            )));
        }

        let mut iv = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut iv);

        let mut buf = pkcs7_pad(plaintext, 8);
        let buf_len = buf.len();

        let enc = cbc::Encryptor::<des::TdesEde3>::new_from_slices(key, &iv)
            .map_err(|e| Error::Crypto(format!("3DES init: {e}")))?;
        enc.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, buf_len)
            .map_err(|e| Error::Crypto(format!("3DES encrypt: {e}")))?;

        let mut result = Vec::with_capacity(8 + buf.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&buf);
        Ok(result)
    }

    fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};

        if key.len() != 24 {
            return Err(Error::Crypto(format!(
                "3DES key must be 24 bytes, got {}",
                key.len()
            )));
        }
        if data.len() < 8 || data.len() % 8 != 0 {
            return Err(Error::Crypto("3DES data invalid length".into()));
        }

        let iv = &data[..8];
        let mut buf = data[8..].to_vec();

        let dec = cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, iv)
            .map_err(|e| Error::Crypto(format!("3DES init: {e}")))?;
        dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
            .map_err(|e| Error::Crypto(format!("3DES decrypt: {e}")))?;

        xmlenc_unpad(&buf, 8)
    }
}

// ── PKCS#7 padding ───────────────────────────────────────────────────

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

/// Remove W3C XML Encryption padding.
///
/// The XML Encryption spec (both 1.0 PKCS#7 style and 1.1 ISO 10126 style)
/// stores the padding length in the last byte.  PKCS#7 fills all padding bytes
/// with the length value; ISO 10126 uses random filler bytes with only the
/// last byte indicating the length.  We accept both by only checking the last
/// byte, which is compatible with either scheme.
fn xmlenc_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let pad_byte = *data.last().unwrap();
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Err(Error::Crypto("invalid padding".into()));
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_roundtrip() {
        let padded = pkcs7_pad(b"hello", 16);
        assert_eq!(padded.len(), 16);
        let unpadded = xmlenc_unpad(&padded, 16).unwrap();
        assert_eq!(unpadded, b"hello");
    }

    #[test]
    fn test_iso10126_unpad() {
        // ISO 10126 padding: random bytes + last byte = pad length
        let mut data = b"hello world!".to_vec(); // 12 bytes
        data.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x04]); // 4 bytes padding, last = 4
        let unpadded = xmlenc_unpad(&data, 16).unwrap();
        assert_eq!(unpadded, b"hello world!");
    }

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
