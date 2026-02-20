#![forbid(unsafe_code)]

//! Key wrap algorithms (AES-KW per RFC 3394, 3DES-KW per RFC 3217).

use bergshamra_core::{algorithm, Error};
use aes_kw::Kek;

/// Trait for key wrap algorithms.
pub trait KeyWrapAlgorithm: Send {
    fn uri(&self) -> &'static str;
    fn wrap(&self, kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>, Error>;
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error>;
    fn kek_size(&self) -> usize;
}

/// Create a key wrap algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn KeyWrapAlgorithm>, Error> {
    match uri {
        algorithm::KW_AES128 => Ok(Box::new(AesKeyWrap { kek_size: 16, uri: algorithm::KW_AES128 })),
        algorithm::KW_AES192 => Ok(Box::new(AesKeyWrap { kek_size: 24, uri: algorithm::KW_AES192 })),
        algorithm::KW_AES256 => Ok(Box::new(AesKeyWrap { kek_size: 32, uri: algorithm::KW_AES256 })),
        algorithm::KW_TRIPLEDES => Ok(Box::new(TripleDesKeyWrap)),
        _ => Err(Error::UnsupportedAlgorithm(format!("key wrap: {uri}"))),
    }
}

struct AesKeyWrap { kek_size: usize, uri: &'static str }

impl KeyWrapAlgorithm for AesKeyWrap {
    fn uri(&self) -> &'static str { self.uri }
    fn kek_size(&self) -> usize { self.kek_size }

    fn wrap(&self, kek_bytes: &[u8], key_data: &[u8]) -> Result<Vec<u8>, Error> {
        if kek_bytes.len() != self.kek_size {
            return Err(Error::Crypto(format!("expected {} byte KEK, got {}", self.kek_size, kek_bytes.len())));
        }
        let mut out = vec![0u8; key_data.len() + 8];
        macro_rules! do_wrap {
            ($aes:ty) => {{
                let kek = Kek::<$aes>::new(kek_bytes.into());
                kek.wrap(key_data, &mut out)
                    .map_err(|e| Error::Crypto(format!("AES-KW wrap: {e}")))?;
            }};
        }
        match self.kek_size {
            16 => do_wrap!(aes::Aes128),
            24 => do_wrap!(aes::Aes192),
            32 => do_wrap!(aes::Aes256),
            _ => return Err(Error::Crypto("unsupported KEK size".into())),
        }
        Ok(out)
    }

    fn unwrap(&self, kek_bytes: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
        if kek_bytes.len() != self.kek_size {
            return Err(Error::Crypto(format!("expected {} byte KEK, got {}", self.kek_size, kek_bytes.len())));
        }
        if wrapped.len() < 16 {
            return Err(Error::Crypto("wrapped key too short".into()));
        }
        let mut out = vec![0u8; wrapped.len() - 8];
        macro_rules! do_unwrap {
            ($aes:ty) => {{
                let kek = Kek::<$aes>::new(kek_bytes.into());
                kek.unwrap(wrapped, &mut out)
                    .map_err(|e| Error::Crypto(format!("AES-KW unwrap: {e}")))?;
            }};
        }
        match self.kek_size {
            16 => do_unwrap!(aes::Aes128),
            24 => do_unwrap!(aes::Aes192),
            32 => do_unwrap!(aes::Aes256),
            _ => return Err(Error::Crypto("unsupported KEK size".into())),
        }
        Ok(out)
    }
}

/// CMS Triple-DES Key Wrap per RFC 3217.
struct TripleDesKeyWrap;

/// Fixed IV for the second 3DES-CBC encryption pass (RFC 3217 section 3.2).
const TDES_KW_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

impl KeyWrapAlgorithm for TripleDesKeyWrap {
    fn uri(&self) -> &'static str { algorithm::KW_TRIPLEDES }
    fn kek_size(&self) -> usize { 24 }

    fn wrap(&self, kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>, Error> {
        if kek.len() != 24 {
            return Err(Error::Crypto(format!("expected 24 byte 3DES KEK, got {}", kek.len())));
        }

        // 1. Compute CMS Key Checksum (SHA-1 hash, first 8 bytes)
        use sha1::Digest;
        let mut hasher = sha1::Sha1::new();
        hasher.update(key_data);
        let hash = hasher.finalize();
        let checksum = &hash[..8];

        // 2. WKCKS = key_data || checksum
        let mut wkcks = Vec::with_capacity(key_data.len() + 8);
        wkcks.extend_from_slice(key_data);
        wkcks.extend_from_slice(checksum);

        // 3. Generate random 8-byte IV
        use rand::RngCore;
        let mut iv = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut iv);

        // 4. First encryption: 3DES-CBC encrypt WKCKS with random IV
        let temp1 = tdes_cbc_encrypt(kek, &iv, &wkcks)?;

        // 5. TEMP2 = IV || TEMP1
        let mut temp2 = Vec::with_capacity(8 + temp1.len());
        temp2.extend_from_slice(&iv);
        temp2.extend_from_slice(&temp1);

        // 6. Reverse byte order
        temp2.reverse();

        // 7. Second encryption: 3DES-CBC encrypt reversed data with fixed IV
        tdes_cbc_encrypt(kek, &TDES_KW_IV, &temp2)
    }

    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
        if kek.len() != 24 {
            return Err(Error::Crypto(format!("expected 24 byte 3DES KEK, got {}", kek.len())));
        }
        if wrapped.len() < 16 {
            return Err(Error::Crypto("3DES-KW wrapped data too short".into()));
        }

        // 1. First decryption: 3DES-CBC decrypt with fixed IV
        let mut temp2 = tdes_cbc_decrypt(kek, &TDES_KW_IV, wrapped)?;

        // 2. Reverse byte order
        temp2.reverse();

        // 3. Extract IV (first 8 bytes) and encrypted data
        if temp2.len() < 8 {
            return Err(Error::Crypto("3DES-KW unwrapped data too short".into()));
        }
        let iv: [u8; 8] = temp2[..8].try_into()
            .map_err(|_| Error::Crypto("invalid IV length".into()))?;
        let enc_data = &temp2[8..];

        // 4. Second decryption: 3DES-CBC decrypt with extracted IV
        let wkcks = tdes_cbc_decrypt(kek, &iv, enc_data)?;

        // 5. Split into key data and checksum
        if wkcks.len() < 8 {
            return Err(Error::Crypto("3DES-KW: decrypted data too short for checksum".into()));
        }
        let key_data = &wkcks[..wkcks.len() - 8];
        let checksum = &wkcks[wkcks.len() - 8..];

        // 6. Verify CMS Key Checksum
        use sha1::Digest;
        let mut hasher = sha1::Sha1::new();
        hasher.update(key_data);
        let hash = hasher.finalize();
        if checksum != &hash[..8] {
            return Err(Error::Crypto("3DES-KW: key checksum verification failed".into()));
        }

        Ok(key_data.to_vec())
    }
}

/// 3DES-CBC encrypt (no padding — input must be multiple of 8 bytes).
fn tdes_cbc_encrypt(key: &[u8], iv: &[u8; 8], data: &[u8]) -> Result<Vec<u8>, Error> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    type TdesCbcEnc = cbc::Encryptor<des::TdesEde3>;

    let encryptor = TdesCbcEnc::new(key.into(), iv.into());
    // Data must be block-aligned (8 bytes for 3DES)
    if data.len() % 8 != 0 {
        return Err(Error::Crypto("3DES-KW: data not block-aligned".into()));
    }
    let mut buf = data.to_vec();
    encryptor.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, data.len())
        .map_err(|e| Error::Crypto(format!("3DES-CBC encrypt: {e}")))?;
    Ok(buf)
}

/// 3DES-CBC decrypt (no padding — input must be multiple of 8 bytes).
fn tdes_cbc_decrypt(key: &[u8], iv: &[u8; 8], data: &[u8]) -> Result<Vec<u8>, Error> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;

    let decryptor = TdesCbcDec::new(key.into(), iv.into());
    let mut buf = data.to_vec();
    let result = decryptor.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| Error::Crypto(format!("3DES-CBC decrypt: {e}")))?;
    Ok(result.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdes_key_wrap_roundtrip() {
        // 24-byte KEK
        let kek = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18";
        // 24-byte key to wrap (3DES key)
        let key_data = b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8";

        let kw = TripleDesKeyWrap;
        let wrapped = kw.wrap(kek, key_data).expect("wrap");
        let unwrapped = kw.unwrap(kek, &wrapped).expect("unwrap");
        assert_eq!(unwrapped, key_data);
    }
}
