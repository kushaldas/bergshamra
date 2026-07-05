#![forbid(unsafe_code)]

//! Key wrap algorithms (AES-KW per RFC 3394, 3DES-KW per RFC 3217).

use bergshamra_core::{algorithm, Error};
use kryptering::algorithm::{AesKeySize, KeyWrapAlgorithm as KKeyWrapAlgorithm};

/// Trait for key wrap algorithms.
pub trait KeyWrapAlgorithm: Send {
    /// Return the XML Encryption key-wrap algorithm URI.
    fn uri(&self) -> &'static str;

    /// Wrap `key_data` with the key-encryption key `kek`.
    fn wrap(&self, kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Unwrap `wrapped` key data with the key-encryption key `kek`.
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error>;

    /// Return the required key-encryption-key size in bytes.
    fn kek_size(&self) -> usize;
}

/// Map an XML algorithm URI to a `kryptering::KeyWrapAlgorithm`.
fn uri_to_keywrap(uri: &str) -> Result<(KKeyWrapAlgorithm, &'static str), Error> {
    match uri {
        algorithm::KW_AES128 => Ok((
            KKeyWrapAlgorithm::AesKw(AesKeySize::Aes128),
            algorithm::KW_AES128,
        )),
        algorithm::KW_AES192 => Ok((
            KKeyWrapAlgorithm::AesKw(AesKeySize::Aes192),
            algorithm::KW_AES192,
        )),
        algorithm::KW_AES256 => Ok((
            KKeyWrapAlgorithm::AesKw(AesKeySize::Aes256),
            algorithm::KW_AES256,
        )),
        algorithm::KW_TRIPLEDES => Ok((KKeyWrapAlgorithm::TripleDesKw, algorithm::KW_TRIPLEDES)),
        _ => Err(Error::UnsupportedAlgorithm(format!("key wrap: {uri}"))),
    }
}

/// Create a key wrap algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn KeyWrapAlgorithm>, Error> {
    let (algo, static_uri) = uri_to_keywrap(uri)?;
    Ok(Box::new(KrypteringKeyWrap {
        algo,
        uri: static_uri,
    }))
}

// ── Wrapper that delegates to kryptering ────────────────────────────

struct KrypteringKeyWrap {
    algo: KKeyWrapAlgorithm,
    uri: &'static str,
}

impl KeyWrapAlgorithm for KrypteringKeyWrap {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn kek_size(&self) -> usize {
        self.algo.kek_size()
    }

    fn wrap(&self, kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>, Error> {
        kryptering::keywrap::wrap(self.algo, kek, key_data).map_err(crate::map_kryptering_err)
    }

    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
        kryptering::keywrap::unwrap(self.algo, kek, wrapped).map_err(crate::map_kryptering_err)
    }
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

        let kw = from_uri(algorithm::KW_TRIPLEDES).unwrap();
        let wrapped = kw.wrap(kek, key_data).expect("wrap");
        let unwrapped = kw.unwrap(kek, &wrapped).expect("unwrap");
        assert_eq!(unwrapped, key_data);
    }

    // ── RFC 3394 / NIST SP 800-38F AES Key Wrap test vectors ─────────

    /// Helper: run a single NIST AES-KW test vector (wrap + unwrap).
    fn nist_aes_kw_vector(kek: &[u8], plaintext: &[u8], expected_ct: &[u8]) {
        let kw = from_uri(match kek.len() {
            16 => algorithm::KW_AES128,
            24 => algorithm::KW_AES192,
            32 => algorithm::KW_AES256,
            _ => panic!("unexpected KEK size"),
        })
        .unwrap();

        let wrapped = kw.wrap(kek, plaintext).expect("wrap failed");
        assert_eq!(wrapped, expected_ct, "wrap ciphertext mismatch");

        let unwrapped = kw.unwrap(kek, expected_ct).expect("unwrap failed");
        assert_eq!(unwrapped, plaintext, "unwrap plaintext mismatch");
    }

    #[test]
    fn test_nist_aes128_kw_128bit_data() {
        // RFC 3394 Section 4.1: 128-bit KEK, 128-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let ct = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();
        nist_aes_kw_vector(&kek, &pt, &ct);
    }

    #[test]
    fn test_nist_aes192_kw_128bit_data() {
        // RFC 3394 Section 4.2: 192-bit KEK, 128-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let ct = hex::decode("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D").unwrap();
        nist_aes_kw_vector(&kek, &pt, &ct);
    }

    #[test]
    fn test_nist_aes256_kw_128bit_data() {
        // RFC 3394 Section 4.3: 256-bit KEK, 128-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let ct = hex::decode("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7").unwrap();
        nist_aes_kw_vector(&kek, &pt, &ct);
    }

    #[test]
    fn test_nist_aes192_kw_192bit_data() {
        // RFC 3394 Section 4.4: 192-bit KEK, 192-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF0001020304050607").unwrap();
        let ct = hex::decode("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")
            .unwrap();
        nist_aes_kw_vector(&kek, &pt, &ct);
    }

    #[test]
    fn test_nist_aes256_kw_256bit_data() {
        // RFC 3394 Section 4.6: 256-bit KEK, 256-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
            .unwrap();
        let ct = hex::decode(
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        )
        .unwrap();
        nist_aes_kw_vector(&kek, &pt, &ct);
    }

    // ── AES-KW error and edge-case tests ─────────────────────────────

    #[test]
    fn test_aes_kw_wrong_kek_size() {
        let kw = from_uri(algorithm::KW_AES128).unwrap();
        // KEK is 15 bytes instead of 16
        let result = kw.wrap(&[0u8; 15], &[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_kw_integrity_check_failure() {
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let kw = from_uri(algorithm::KW_AES128).unwrap();

        let mut wrapped = kw.wrap(&kek, &pt).unwrap();
        // Corrupt the first byte
        wrapped[0] ^= 0xFF;
        let result = kw.unwrap(&kek, &wrapped);
        assert!(
            result.is_err(),
            "unwrap should fail for corrupted ciphertext"
        );
    }

    #[test]
    fn test_aes_kw_roundtrip_all_sizes() {
        // Round-trip test for all KEK sizes with multiple data sizes
        let kek_sizes: &[(usize, &str)] = &[
            (16, algorithm::KW_AES128),
            (24, algorithm::KW_AES192),
            (32, algorithm::KW_AES256),
        ];
        let data_sizes = [16, 24, 32, 40, 48, 64, 128];

        for &(kek_size, uri) in kek_sizes {
            let kw = from_uri(uri).unwrap();
            for &data_size in &data_sizes {
                let kek: Vec<u8> = (0..kek_size).map(|i| (i * 7 + 3) as u8).collect();
                let data: Vec<u8> = (0..data_size).map(|i| (i * 13 + 5) as u8).collect();
                let wrapped = kw.wrap(&kek, &data).unwrap();
                assert_eq!(
                    wrapped.len(),
                    data.len() + 8,
                    "ciphertext should be 8 bytes longer"
                );
                let unwrapped = kw.unwrap(&kek, &wrapped).unwrap();
                assert_eq!(
                    unwrapped, data,
                    "roundtrip failed for kek={kek_size}, data={data_size}"
                );
            }
        }
    }
}
