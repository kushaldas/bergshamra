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
        algorithm::AES128_CBC => Ok(Box::new(AesCbc { key_size: 16, uri: algorithm::AES128_CBC })),
        algorithm::AES192_CBC => Ok(Box::new(AesCbc { key_size: 24, uri: algorithm::AES192_CBC })),
        algorithm::AES256_CBC => Ok(Box::new(AesCbc { key_size: 32, uri: algorithm::AES256_CBC })),
        algorithm::AES128_GCM => Ok(Box::new(AesGcm { key_size: 16, uri: algorithm::AES128_GCM })),
        algorithm::AES192_GCM => Ok(Box::new(AesGcm { key_size: 24, uri: algorithm::AES192_GCM })),
        algorithm::AES256_GCM => Ok(Box::new(AesGcm { key_size: 32, uri: algorithm::AES256_GCM })),
        algorithm::TRIPLEDES_CBC => Ok(Box::new(TripleDesCbc)),
        _ => Err(Error::UnsupportedAlgorithm(format!("cipher: {uri}"))),
    }
}

// ── AES-CBC with PKCS#7 padding ─────────────────────────────────────

struct AesCbc { key_size: usize, uri: &'static str }

impl CipherAlgorithm for AesCbc {
    fn uri(&self) -> &'static str { self.uri }
    fn key_size(&self) -> usize { self.key_size }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use rand::RngCore;

        if key.len() != self.key_size {
            return Err(Error::Crypto(format!("expected {} byte key, got {}", self.key_size, key.len())));
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
            return Err(Error::Crypto(format!("expected {} byte key, got {}", self.key_size, key.len())));
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

struct AesGcm { key_size: usize, uri: &'static str }

impl CipherAlgorithm for AesGcm {
    fn uri(&self) -> &'static str { self.uri }
    fn key_size(&self) -> usize { self.key_size }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        use aes_gcm::{aead::Aead, KeyInit, Nonce};
        use rand::RngCore;

        if key.len() != self.key_size {
            return Err(Error::Crypto(format!("expected {} byte key, got {}", self.key_size, key.len())));
        }

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = match self.key_size {
            16 => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher.encrypt(nonce, plaintext)
                    .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
            }
            24 => {
                use aes_gcm::aead::consts::U12;
                let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher.encrypt(nonce, plaintext)
                    .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
            }
            32 => {
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher.encrypt(nonce, plaintext)
                    .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
            }
            _ => return Err(Error::Crypto("AES-GCM only supports 128, 192, and 256 bit keys".into())),
        };

        let mut result = Vec::with_capacity(12 + ct.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ct);
        Ok(result)
    }

    fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        use aes_gcm::{aead::Aead, KeyInit, Nonce};

        if key.len() != self.key_size {
            return Err(Error::Crypto(format!("expected {} byte key, got {}", self.key_size, key.len())));
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
                cipher.decrypt(nonce, ct_and_tag)
                    .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
            }
            24 => {
                use aes_gcm::aead::consts::U12;
                let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher.decrypt(nonce, ct_and_tag)
                    .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
            }
            32 => {
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
                cipher.decrypt(nonce, ct_and_tag)
                    .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
            }
            _ => Err(Error::Crypto("AES-GCM only supports 128, 192, and 256 bit keys".into())),
        }
    }
}

// ── 3DES-CBC ─────────────────────────────────────────────────────────

struct TripleDesCbc;

impl CipherAlgorithm for TripleDesCbc {
    fn uri(&self) -> &'static str { algorithm::TRIPLEDES_CBC }
    fn key_size(&self) -> usize { 24 }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use rand::RngCore;

        if key.len() != 24 {
            return Err(Error::Crypto(format!("3DES key must be 24 bytes, got {}", key.len())));
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
            return Err(Error::Crypto(format!("3DES key must be 24 bytes, got {}", key.len())));
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
}
