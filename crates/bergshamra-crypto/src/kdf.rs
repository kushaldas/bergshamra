#![forbid(unsafe_code)]

//! Key Derivation Functions: ConcatKDF (NIST SP 800-56A) and PBKDF2.

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
    let digest_uri = params.digest_uri.as_deref()
        .unwrap_or(algorithm::SHA256);

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
        algorithm::SHA256 =>
            concat_kdf_inner::<sha2::Sha256>(shared_secret, &other_info, key_len),
        algorithm::SHA384 => concat_kdf_inner::<sha2::Sha384>(shared_secret, &other_info, key_len),
        algorithm::SHA512 => concat_kdf_inner::<sha2::Sha512>(shared_secret, &other_info, key_len),
        algorithm::SHA3_224 => concat_kdf_inner::<sha3::Sha3_224>(shared_secret, &other_info, key_len),
        algorithm::SHA3_256 => concat_kdf_inner::<sha3::Sha3_256>(shared_secret, &other_info, key_len),
        algorithm::SHA3_384 => concat_kdf_inner::<sha3::Sha3_384>(shared_secret, &other_info, key_len),
        algorithm::SHA3_512 => concat_kdf_inner::<sha3::Sha3_512>(shared_secret, &other_info, key_len),
        _ => Err(Error::UnsupportedAlgorithm(format!("ConcatKDF digest: {digest_uri}"))),
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
pub fn pbkdf2_derive(
    password: &[u8],
    params: &Pbkdf2Params,
) -> Result<Vec<u8>, Error> {
    let mut derived = vec![0u8; params.key_length];

    match params.prf_uri.as_str() {
        algorithm::HMAC_SHA1 => {
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
                password, &params.salt, params.iteration_count, &mut derived,
            );
        }
        algorithm::HMAC_SHA224 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha224>(
                password, &params.salt, params.iteration_count, &mut derived,
            );
        }
        algorithm::HMAC_SHA256 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                password, &params.salt, params.iteration_count, &mut derived,
            );
        }
        algorithm::HMAC_SHA384 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha384>(
                password, &params.salt, params.iteration_count, &mut derived,
            );
        }
        algorithm::HMAC_SHA512 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
                password, &params.salt, params.iteration_count, &mut derived,
            );
        }
        _ => return Err(Error::UnsupportedAlgorithm(format!("PBKDF2 PRF: {}", params.prf_uri))),
    }

    Ok(derived)
}
