#![forbid(unsafe_code)]

//! Provider-neutral XML Signature operations.
//!
//! All key material is held by [`kryptering::SoftwareKey`]. This module only
//! translates XML algorithm identifiers and signature encodings; primitive
//! implementations live behind kryptering's selected provider.

use bergshamra_core::{algorithm, Error};
use kryptering::{Signer as _, Verifier as _};

use crate::map_kryptering_err;

/// Opaque, shared software key used for signing and verification.
pub type SigningKey = kryptering::SoftwareKey;

/// Post-quantum algorithm variants retained as XML-facing metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2_128f,
    SlhDsaSha2_128s,
    SlhDsaSha2_192f,
    SlhDsaSha2_192s,
    SlhDsaSha2_256f,
    SlhDsaSha2_256s,
}

impl PqAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            Self::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            Self::SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
            Self::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            Self::SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
            Self::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        }
    }

    #[cfg(feature = "post-quantum")]
    pub fn to_kryptering(self) -> kryptering::PqAlgorithm {
        use kryptering::{MlDsaVariant as M, PqAlgorithm as P, SlhDsaVariant as S};
        match self {
            Self::MlDsa44 => P::MlDsa(M::MlDsa44),
            Self::MlDsa65 => P::MlDsa(M::MlDsa65),
            Self::MlDsa87 => P::MlDsa(M::MlDsa87),
            Self::SlhDsaSha2_128f => P::SlhDsa(S::Sha2_128f),
            Self::SlhDsaSha2_128s => P::SlhDsa(S::Sha2_128s),
            Self::SlhDsaSha2_192f => P::SlhDsa(S::Sha2_192f),
            Self::SlhDsaSha2_192s => P::SlhDsa(S::Sha2_192s),
            Self::SlhDsaSha2_256f => P::SlhDsa(S::Sha2_256f),
            Self::SlhDsaSha2_256s => P::SlhDsa(S::Sha2_256s),
        }
    }
}

/// Provider-independent signature interface used by XML-DSig.
pub trait SignatureAlgorithm: Send {
    fn uri(&self) -> &'static str;
    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify(&self, key: &SigningKey, data: &[u8], signature: &[u8]) -> Result<bool, Error>;

    fn verify_truncated(
        &self,
        key: &SigningKey,
        data: &[u8],
        signature: &[u8],
        expected_len_bytes: usize,
    ) -> Result<bool, Error> {
        if signature.len() != expected_len_bytes {
            return Ok(false);
        }
        self.verify(key, data, signature)
    }
}

#[derive(Clone)]
struct ProviderSignature {
    uri: &'static str,
    algorithm: kryptering::SignatureAlgorithm,
    context: Vec<u8>,
}

impl SignatureAlgorithm for ProviderSignature {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        let algorithm = algorithm_for_key(self.algorithm, key);
        let signer =
            kryptering::SoftwareSigner::new_with_pq_context(algorithm, key.clone(), &self.context)
                .map_err(map_kryptering_err)?;
        signer.sign(data).map_err(map_kryptering_err)
    }

    fn verify(&self, key: &SigningKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let algorithm = algorithm_for_key(self.algorithm, key);
        let verifier = kryptering::SoftwareVerifier::new_with_pq_context(
            algorithm,
            key.clone(),
            &self.context,
        )
        .map_err(map_kryptering_err)?;
        verifier.verify(data, signature).map_err(map_kryptering_err)
    }

    fn verify_truncated(
        &self,
        key: &SigningKey,
        data: &[u8],
        signature: &[u8],
        expected_len_bytes: usize,
    ) -> Result<bool, Error> {
        if signature.len() != expected_len_bytes {
            return Ok(false);
        }
        if !matches!(self.algorithm, kryptering::SignatureAlgorithm::Hmac(_)) {
            return self.verify(key, data, signature);
        }
        let expected = self.sign(key, data)?;
        if expected_len_bytes > expected.len() {
            return Ok(false);
        }
        Ok(constant_time_eq(&expected[..expected_len_bytes], signature))
    }
}

fn algorithm_for_key(
    algorithm: kryptering::SignatureAlgorithm,
    key: &SigningKey,
) -> kryptering::SignatureAlgorithm {
    match (algorithm, key.algorithm()) {
        (kryptering::SignatureAlgorithm::Ecdsa(_, hash), kryptering::KeyAlgorithm::Ec(curve)) => {
            kryptering::SignatureAlgorithm::Ecdsa(curve, hash)
        }
        _ => algorithm,
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

pub fn from_uri(uri: &str) -> Result<Box<dyn SignatureAlgorithm>, Error> {
    from_uri_with_context(uri, None)
}

/// Whether an XML signature URI identifies an algorithm with a context string.
pub fn is_pq_algorithm(uri: &str) -> bool {
    matches!(
        uri,
        algorithm::ML_DSA_44
            | algorithm::ML_DSA_65
            | algorithm::ML_DSA_87
            | algorithm::SLH_DSA_SHA2_128F
            | algorithm::SLH_DSA_SHA2_128S
            | algorithm::SLH_DSA_SHA2_192F
            | algorithm::SLH_DSA_SHA2_192S
            | algorithm::SLH_DSA_SHA2_256F
            | algorithm::SLH_DSA_SHA2_256S
    )
}

/// Whether an XML signature URI identifies an HMAC algorithm.
pub fn is_hmac_algorithm(uri: &str) -> bool {
    matches!(
        uri,
        algorithm::HMAC_SHA1
            | algorithm::HMAC_SHA224
            | algorithm::HMAC_SHA256
            | algorithm::HMAC_SHA384
            | algorithm::HMAC_SHA512
            | algorithm::HMAC_MD5
            | algorithm::HMAC_RIPEMD160
    )
}

pub fn from_uri_with_context(
    uri: &str,
    context: Option<Vec<u8>>,
) -> Result<Box<dyn SignatureAlgorithm>, Error> {
    use kryptering::{EcCurve as C, HashAlgorithm as H, SignatureAlgorithm as S};

    let algorithm = match uri {
        algorithm::RSA_SHA1 => S::RsaPkcs1v15(H::Sha1),
        algorithm::RSA_SHA224 => S::RsaPkcs1v15(H::Sha224),
        algorithm::RSA_SHA256 => S::RsaPkcs1v15(H::Sha256),
        algorithm::RSA_SHA384 => S::RsaPkcs1v15(H::Sha384),
        algorithm::RSA_SHA512 => S::RsaPkcs1v15(H::Sha512),
        algorithm::RSA_PSS_SHA1 => S::RsaPss(H::Sha1),
        algorithm::RSA_PSS_SHA224 => S::RsaPss(H::Sha224),
        algorithm::RSA_PSS_SHA256 => S::RsaPss(H::Sha256),
        algorithm::RSA_PSS_SHA384 => S::RsaPss(H::Sha384),
        algorithm::RSA_PSS_SHA512 => S::RsaPss(H::Sha512),
        algorithm::RSA_PSS_SHA3_224 => S::RsaPss(H::Sha3_224),
        algorithm::RSA_PSS_SHA3_256 => S::RsaPss(H::Sha3_256),
        algorithm::RSA_PSS_SHA3_384 => S::RsaPss(H::Sha3_384),
        algorithm::RSA_PSS_SHA3_512 => S::RsaPss(H::Sha3_512),
        algorithm::ECDSA_SHA1 => S::Ecdsa(C::P256, H::Sha1),
        algorithm::ECDSA_SHA224 => S::Ecdsa(C::P256, H::Sha224),
        algorithm::ECDSA_SHA256 => S::Ecdsa(C::P256, H::Sha256),
        algorithm::ECDSA_SHA384 => S::Ecdsa(C::P384, H::Sha384),
        algorithm::ECDSA_SHA512 => S::Ecdsa(C::P521, H::Sha512),
        algorithm::ECDSA_SHA3_224 => S::Ecdsa(C::P256, H::Sha3_224),
        algorithm::ECDSA_SHA3_256 => S::Ecdsa(C::P256, H::Sha3_256),
        algorithm::ECDSA_SHA3_384 => S::Ecdsa(C::P384, H::Sha3_384),
        algorithm::ECDSA_SHA3_512 => S::Ecdsa(C::P521, H::Sha3_512),
        algorithm::EDDSA_ED25519 => S::Ed25519,
        algorithm::HMAC_SHA1 => S::Hmac(H::Sha1),
        algorithm::HMAC_SHA224 => S::Hmac(H::Sha224),
        algorithm::HMAC_SHA256 => S::Hmac(H::Sha256),
        algorithm::HMAC_SHA384 => S::Hmac(H::Sha384),
        algorithm::HMAC_SHA512 => S::Hmac(H::Sha512),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::RSA_MD5 => S::RsaPkcs1v15(H::Md5),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::RSA_RIPEMD160 => S::RsaPkcs1v15(H::Ripemd160),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::ECDSA_RIPEMD160 => S::Ecdsa(C::P256, H::Ripemd160),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::HMAC_MD5 => S::Hmac(H::Md5),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::HMAC_RIPEMD160 => S::Hmac(H::Ripemd160),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::DSA_SHA1 => S::Dsa(H::Sha1),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::DSA_SHA256 => S::Dsa(H::Sha256),
        #[cfg(feature = "post-quantum")]
        algorithm::ML_DSA_44 => S::MlDsa(kryptering::MlDsaVariant::MlDsa44),
        #[cfg(feature = "post-quantum")]
        algorithm::ML_DSA_65 => S::MlDsa(kryptering::MlDsaVariant::MlDsa65),
        #[cfg(feature = "post-quantum")]
        algorithm::ML_DSA_87 => S::MlDsa(kryptering::MlDsaVariant::MlDsa87),
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_128F => S::SlhDsa(kryptering::SlhDsaVariant::Sha2_128f),
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_128S => S::SlhDsa(kryptering::SlhDsaVariant::Sha2_128s),
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_192F => S::SlhDsa(kryptering::SlhDsaVariant::Sha2_192f),
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_192S => S::SlhDsa(kryptering::SlhDsaVariant::Sha2_192s),
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_256F => S::SlhDsa(kryptering::SlhDsaVariant::Sha2_256f),
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_256S => S::SlhDsa(kryptering::SlhDsaVariant::Sha2_256s),
        _ => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "signature algorithm: {uri}"
            )))
        }
    };

    let context = context.unwrap_or_default();
    #[cfg(feature = "post-quantum")]
    let accepts_context = matches!(algorithm, S::MlDsa(_) | S::SlhDsa(_));
    #[cfg(not(feature = "post-quantum"))]
    let accepts_context = false;
    if !context.is_empty() && !accepts_context {
        return Err(Error::Key(
            "only ML-DSA and SLH-DSA accept a context string".into(),
        ));
    }
    Ok(Box::new(ProviderSignature {
        uri: canonical_uri(algorithm).expect("URI mapping must be bidirectional"),
        algorithm,
        context,
    }))
}

/// Return the canonical XML-DSig URI for a kryptering signature algorithm.
pub fn kryptering_algorithm_uri(alg: kryptering::SignatureAlgorithm) -> Option<&'static str> {
    canonical_uri(alg)
}

fn canonical_uri(alg: kryptering::SignatureAlgorithm) -> Option<&'static str> {
    use kryptering::{HashAlgorithm as H, SignatureAlgorithm as S};
    Some(match alg {
        S::RsaPkcs1v15(H::Sha1) => algorithm::RSA_SHA1,
        S::RsaPkcs1v15(H::Sha224) => algorithm::RSA_SHA224,
        S::RsaPkcs1v15(H::Sha256) => algorithm::RSA_SHA256,
        S::RsaPkcs1v15(H::Sha384) => algorithm::RSA_SHA384,
        S::RsaPkcs1v15(H::Sha512) => algorithm::RSA_SHA512,
        S::RsaPss(H::Sha1) => algorithm::RSA_PSS_SHA1,
        S::RsaPss(H::Sha224) => algorithm::RSA_PSS_SHA224,
        S::RsaPss(H::Sha256) => algorithm::RSA_PSS_SHA256,
        S::RsaPss(H::Sha384) => algorithm::RSA_PSS_SHA384,
        S::RsaPss(H::Sha512) => algorithm::RSA_PSS_SHA512,
        S::RsaPss(H::Sha3_224) => algorithm::RSA_PSS_SHA3_224,
        S::RsaPss(H::Sha3_256) => algorithm::RSA_PSS_SHA3_256,
        S::RsaPss(H::Sha3_384) => algorithm::RSA_PSS_SHA3_384,
        S::RsaPss(H::Sha3_512) => algorithm::RSA_PSS_SHA3_512,
        S::Ecdsa(_, H::Sha1) => algorithm::ECDSA_SHA1,
        S::Ecdsa(_, H::Sha224) => algorithm::ECDSA_SHA224,
        S::Ecdsa(_, H::Sha256) => algorithm::ECDSA_SHA256,
        S::Ecdsa(_, H::Sha384) => algorithm::ECDSA_SHA384,
        S::Ecdsa(_, H::Sha512) => algorithm::ECDSA_SHA512,
        S::Ecdsa(_, H::Sha3_224) => algorithm::ECDSA_SHA3_224,
        S::Ecdsa(_, H::Sha3_256) => algorithm::ECDSA_SHA3_256,
        S::Ecdsa(_, H::Sha3_384) => algorithm::ECDSA_SHA3_384,
        S::Ecdsa(_, H::Sha3_512) => algorithm::ECDSA_SHA3_512,
        S::Ed25519 => algorithm::EDDSA_ED25519,
        S::Hmac(H::Sha1) => algorithm::HMAC_SHA1,
        S::Hmac(H::Sha224) => algorithm::HMAC_SHA224,
        S::Hmac(H::Sha256) => algorithm::HMAC_SHA256,
        S::Hmac(H::Sha384) => algorithm::HMAC_SHA384,
        S::Hmac(H::Sha512) => algorithm::HMAC_SHA512,
        #[cfg(feature = "legacy-algorithms")]
        S::RsaPkcs1v15(H::Md5) => algorithm::RSA_MD5,
        #[cfg(feature = "legacy-algorithms")]
        S::RsaPkcs1v15(H::Ripemd160) => algorithm::RSA_RIPEMD160,
        #[cfg(feature = "legacy-algorithms")]
        S::Ecdsa(_, H::Ripemd160) => algorithm::ECDSA_RIPEMD160,
        #[cfg(feature = "legacy-algorithms")]
        S::Hmac(H::Md5) => algorithm::HMAC_MD5,
        #[cfg(feature = "legacy-algorithms")]
        S::Hmac(H::Ripemd160) => algorithm::HMAC_RIPEMD160,
        #[cfg(feature = "legacy-algorithms")]
        S::Dsa(H::Sha1) => algorithm::DSA_SHA1,
        #[cfg(feature = "legacy-algorithms")]
        S::Dsa(H::Sha256) => algorithm::DSA_SHA256,
        #[cfg(feature = "post-quantum")]
        S::MlDsa(kryptering::MlDsaVariant::MlDsa44) => algorithm::ML_DSA_44,
        #[cfg(feature = "post-quantum")]
        S::MlDsa(kryptering::MlDsaVariant::MlDsa65) => algorithm::ML_DSA_65,
        #[cfg(feature = "post-quantum")]
        S::MlDsa(kryptering::MlDsaVariant::MlDsa87) => algorithm::ML_DSA_87,
        #[cfg(feature = "post-quantum")]
        S::SlhDsa(kryptering::SlhDsaVariant::Sha2_128f) => algorithm::SLH_DSA_SHA2_128F,
        #[cfg(feature = "post-quantum")]
        S::SlhDsa(kryptering::SlhDsaVariant::Sha2_128s) => algorithm::SLH_DSA_SHA2_128S,
        #[cfg(feature = "post-quantum")]
        S::SlhDsa(kryptering::SlhDsaVariant::Sha2_192f) => algorithm::SLH_DSA_SHA2_192F,
        #[cfg(feature = "post-quantum")]
        S::SlhDsa(kryptering::SlhDsaVariant::Sha2_192s) => algorithm::SLH_DSA_SHA2_192S,
        #[cfg(feature = "post-quantum")]
        S::SlhDsa(kryptering::SlhDsaVariant::Sha2_256f) => algorithm::SLH_DSA_SHA2_256F,
        #[cfg(feature = "post-quantum")]
        S::SlhDsa(kryptering::SlhDsaVariant::Sha2_256s) => algorithm::SLH_DSA_SHA2_256S,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip_and_declared_truncation() {
        let key =
            SigningKey::from_symmetric_bytes(kryptering::KeyAlgorithm::Hmac, b"secret").unwrap();
        let algorithm = from_uri(algorithm::HMAC_SHA256).unwrap();
        let signature = algorithm.sign(&key, b"payload").unwrap();
        assert!(algorithm.verify(&key, b"payload", &signature).unwrap());
        assert!(algorithm
            .verify_truncated(&key, b"payload", &signature[..10], 10)
            .unwrap());
        assert!(!algorithm
            .verify_truncated(&key, b"payload", &signature[..9], 10)
            .unwrap());
    }
}
