#![forbid(unsafe_code)]

//! Key Derivation Functions: ConcatKDF (NIST SP 800-56A), PBKDF2, and HKDF (RFC 5869).

use bergshamra_core::{algorithm, Error};
use digest::Digest;

/// ConcatKDF parameters from XML.
#[derive(Debug, Clone, Default)]
pub struct ConcatKdfParams {
    /// Digest algorithm URI (e.g., SHA-256)
    pub digest_uri: Option<String>,
    /// AlgorithmID — hex-encoded in the XML
    pub algorithm_id: Option<Vec<u8>>,
    /// PartyUInfo — hex-encoded in the XML
    pub party_u_info: Option<Vec<u8>>,
    /// PartyVInfo — hex-encoded in the XML
    pub party_v_info: Option<Vec<u8>>,
}

/// PBKDF2 parameters from XML.
#[derive(Debug, Clone)]
pub struct Pbkdf2Params {
    /// PRF algorithm URI (e.g., HMAC-SHA256)
    pub prf_uri: String,
    /// Salt bytes
    pub salt: Vec<u8>,
    /// Iteration count
    pub iteration_count: u32,
    /// Desired key length in bytes
    pub key_length: usize,
}

/// Derive a key using ConcatKDF (NIST SP 800-56A, Section 5.8.1).
///
/// The single-step KDF:
///   K(i) = H(counter || Z || OtherInfo)
///   DerivedKeyingMaterial = K(1) || K(2) || ... (truncated to key_len)
///
/// OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo
/// (SuppPubInfo/SuppPrivInfo not used per W3C XML Enc 1.1 spec)
pub fn concat_kdf(
    shared_secret: &[u8],
    key_len: usize,
    params: &ConcatKdfParams,
) -> Result<Vec<u8>, Error> {
    let digest_uri = params.digest_uri.as_deref().unwrap_or(algorithm::SHA256);

    // Build OtherInfo per W3C XML Enc 1.1 spec:
    // OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo
    // Note: SuppPubInfo and SuppPrivInfo are NOT used per the W3C spec.
    let mut other_info = Vec::new();
    if let Some(ref alg_id) = params.algorithm_id {
        other_info.extend_from_slice(alg_id);
    }
    if let Some(ref party_u) = params.party_u_info {
        other_info.extend_from_slice(party_u);
    }
    if let Some(ref party_v) = params.party_v_info {
        other_info.extend_from_slice(party_v);
    }

    // Dispatch by digest
    match digest_uri {
        algorithm::SHA1 => concat_kdf_inner::<sha1::Sha1>(shared_secret, &other_info, key_len),
        algorithm::SHA224 => concat_kdf_inner::<sha2::Sha224>(shared_secret, &other_info, key_len),
        algorithm::SHA256 => concat_kdf_inner::<sha2::Sha256>(shared_secret, &other_info, key_len),
        algorithm::SHA384 => concat_kdf_inner::<sha2::Sha384>(shared_secret, &other_info, key_len),
        algorithm::SHA512 => concat_kdf_inner::<sha2::Sha512>(shared_secret, &other_info, key_len),
        algorithm::SHA3_224 => {
            concat_kdf_inner::<sha3::Sha3_224>(shared_secret, &other_info, key_len)
        }
        algorithm::SHA3_256 => {
            concat_kdf_inner::<sha3::Sha3_256>(shared_secret, &other_info, key_len)
        }
        algorithm::SHA3_384 => {
            concat_kdf_inner::<sha3::Sha3_384>(shared_secret, &other_info, key_len)
        }
        algorithm::SHA3_512 => {
            concat_kdf_inner::<sha3::Sha3_512>(shared_secret, &other_info, key_len)
        }
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "ConcatKDF digest: {digest_uri}"
        ))),
    }
}

fn concat_kdf_inner<H: Digest + Clone>(
    shared_secret: &[u8],
    other_info: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, Error> {
    let hash_len = <H as Digest>::output_size();
    let reps = (key_len + hash_len - 1) / hash_len;
    let mut derived = Vec::with_capacity(reps * hash_len);

    for counter in 1..=(reps as u32) {
        let mut hasher = H::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(shared_secret);
        hasher.update(other_info);
        derived.extend_from_slice(&hasher.finalize());
    }

    derived.truncate(key_len);
    Ok(derived)
}

/// Derive a key using PBKDF2 (RFC 8018).
pub fn pbkdf2_derive(password: &[u8], params: &Pbkdf2Params) -> Result<Vec<u8>, Error> {
    let mut derived = vec![0u8; params.key_length];

    match params.prf_uri.as_str() {
        algorithm::HMAC_SHA1 => {
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        algorithm::HMAC_SHA224 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha224>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        algorithm::HMAC_SHA256 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        algorithm::HMAC_SHA384 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha384>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        algorithm::HMAC_SHA512 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        _ => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "PBKDF2 PRF: {}",
                params.prf_uri
            )))
        }
    }

    Ok(derived)
}

/// HKDF parameters from XML (RFC 5869).
#[derive(Debug, Clone, Default)]
pub struct HkdfParams {
    /// PRF algorithm URI (e.g., HMAC-SHA256). Defaults to HMAC-SHA256 if not set.
    pub prf_uri: Option<String>,
    /// Optional salt bytes. When `None`, HKDF uses a zero-filled salt of hash length.
    pub salt: Option<Vec<u8>>,
    /// Optional info/context bytes for the HKDF-Expand step.
    pub info: Option<Vec<u8>>,
    /// Desired output key length in bits. Converted to bytes internally.
    /// If 0 or unset, the caller must supply `key_len` to `hkdf_derive()`.
    pub key_length_bits: u32,
}

/// Derive a key using HKDF (RFC 5869: Extract-then-Expand).
///
/// `shared_secret` is the input keying material (IKM).
/// `key_len` is the desired output length in bytes (overridden by
/// `params.key_length_bits / 8` if that is nonzero).
pub fn hkdf_derive(
    shared_secret: &[u8],
    key_len: usize,
    params: &HkdfParams,
) -> Result<Vec<u8>, Error> {
    let prf_uri = params.prf_uri.as_deref().unwrap_or(algorithm::HMAC_SHA256);

    // Determine output length: params override the caller's key_len
    let out_len = if params.key_length_bits > 0 {
        (params.key_length_bits as usize) / 8
    } else if key_len > 0 {
        key_len
    } else {
        16 // Default 128 bits (AES-128)
    };

    let salt = params.salt.as_deref();
    let info = params.info.as_deref().unwrap_or(&[]);

    match prf_uri {
        algorithm::HMAC_SHA1 => {
            let hk = hkdf::Hkdf::<sha1::Sha1>::new(salt, shared_secret);
            let mut okm = vec![0u8; out_len];
            hk.expand(info, &mut okm)
                .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;
            Ok(okm)
        }
        algorithm::HMAC_SHA224 => {
            let hk = hkdf::Hkdf::<sha2::Sha224>::new(salt, shared_secret);
            let mut okm = vec![0u8; out_len];
            hk.expand(info, &mut okm)
                .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;
            Ok(okm)
        }
        algorithm::HMAC_SHA256 => {
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(salt, shared_secret);
            let mut okm = vec![0u8; out_len];
            hk.expand(info, &mut okm)
                .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;
            Ok(okm)
        }
        algorithm::HMAC_SHA384 => {
            let hk = hkdf::Hkdf::<sha2::Sha384>::new(salt, shared_secret);
            let mut okm = vec![0u8; out_len];
            hk.expand(info, &mut okm)
                .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;
            Ok(okm)
        }
        algorithm::HMAC_SHA512 => {
            let hk = hkdf::Hkdf::<sha2::Sha512>::new(salt, shared_secret);
            let mut okm = vec![0u8; out_len];
            hk.expand(info, &mut okm)
                .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;
            Ok(okm)
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("HKDF PRF: {prf_uri}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha256_basic() {
        // RFC 5869 Test Case 1
        let ikm = [0x0b; 22];
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");

        let params = HkdfParams {
            prf_uri: Some(algorithm::HMAC_SHA256.to_string()),
            salt: Some(salt),
            info: Some(info),
            key_length_bits: 336, // 42 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_sha256_empty_salt_and_info() {
        // RFC 5869 Test Case 3: zero-length salt and info
        let ikm = [0x0b; 22];
        let params = HkdfParams {
            prf_uri: Some(algorithm::HMAC_SHA256.to_string()),
            salt: None,
            info: None,
            key_length_bits: 336, // 42 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(
            hex_encode(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_default_prf_is_sha256() {
        // When prf_uri is None, should default to HMAC-SHA256
        let ikm = [0x0b; 22];
        let params_explicit = HkdfParams {
            prf_uri: Some(algorithm::HMAC_SHA256.to_string()),
            salt: None,
            info: None,
            key_length_bits: 128,
        };
        let params_default = HkdfParams {
            prf_uri: None,
            salt: None,
            info: None,
            key_length_bits: 128,
        };

        let okm1 = hkdf_derive(&ikm, 0, &params_explicit).unwrap();
        let okm2 = hkdf_derive(&ikm, 0, &params_default).unwrap();
        assert_eq!(okm1, okm2);
    }

    #[test]
    fn hkdf_key_len_fallback() {
        // key_length_bits=0 should use the key_len parameter
        let ikm = [0x0b; 22];
        let params = HkdfParams {
            prf_uri: Some(algorithm::HMAC_SHA256.to_string()),
            salt: None,
            info: None,
            key_length_bits: 0,
        };

        let okm = hkdf_derive(&ikm, 32, &params).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn hkdf_unsupported_prf() {
        let params = HkdfParams {
            prf_uri: Some("http://example.com/unsupported".to_string()),
            ..Default::default()
        };
        let err = hkdf_derive(&[0u8; 16], 16, &params).unwrap_err();
        assert!(
            err.to_string().contains("HKDF PRF"),
            "unexpected error: {err}"
        );
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
