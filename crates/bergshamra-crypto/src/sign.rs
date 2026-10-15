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
            | algorithm::ML_DSA_44_W3C
            | algorithm::ML_DSA_65_W3C
            | algorithm::ML_DSA_87_W3C
            | algorithm::SLH_DSA_SHA2_128F
            | algorithm::SLH_DSA_SHA2_128S
            | algorithm::SLH_DSA_SHA2_192F
            | algorithm::SLH_DSA_SHA2_192S
            | algorithm::SLH_DSA_SHA2_256F
            | algorithm::SLH_DSA_SHA2_256S
            | algorithm::SLH_DSA_SHA2_128F_W3C
            | algorithm::SLH_DSA_SHA2_128S_W3C
            | algorithm::SLH_DSA_SHA2_192F_W3C
            | algorithm::SLH_DSA_SHA2_192S_W3C
            | algorithm::SLH_DSA_SHA2_256F_W3C
            | algorithm::SLH_DSA_SHA2_256S_W3C
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

/// Resolve an XML-DSig `SignatureMethod` URI to the provider algorithm it
/// names. Alias spellings (the W3C and xmlsec ML-DSA identifiers) resolve
/// to the same algorithm; unknown URIs are rejected.
fn algorithm_for_uri(uri: &str) -> Result<kryptering::SignatureAlgorithm, Error> {
    use kryptering::{EcCurve as C, HashAlgorithm as H, SignatureAlgorithm as S};

    Ok(match uri {
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
        algorithm::ML_DSA_44 | algorithm::ML_DSA_44_W3C => {
            S::MlDsa(kryptering::MlDsaVariant::MlDsa44)
        }
        #[cfg(feature = "post-quantum")]
        algorithm::ML_DSA_65 | algorithm::ML_DSA_65_W3C => {
            S::MlDsa(kryptering::MlDsaVariant::MlDsa65)
        }
        #[cfg(feature = "post-quantum")]
        algorithm::ML_DSA_87 | algorithm::ML_DSA_87_W3C => {
            S::MlDsa(kryptering::MlDsaVariant::MlDsa87)
        }
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_128F | algorithm::SLH_DSA_SHA2_128F_W3C => {
            S::SlhDsa(kryptering::SlhDsaVariant::Sha2_128f)
        }
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_128S | algorithm::SLH_DSA_SHA2_128S_W3C => {
            S::SlhDsa(kryptering::SlhDsaVariant::Sha2_128s)
        }
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_192F | algorithm::SLH_DSA_SHA2_192F_W3C => {
            S::SlhDsa(kryptering::SlhDsaVariant::Sha2_192f)
        }
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_192S | algorithm::SLH_DSA_SHA2_192S_W3C => {
            S::SlhDsa(kryptering::SlhDsaVariant::Sha2_192s)
        }
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_256F | algorithm::SLH_DSA_SHA2_256F_W3C => {
            S::SlhDsa(kryptering::SlhDsaVariant::Sha2_256f)
        }
        #[cfg(feature = "post-quantum")]
        algorithm::SLH_DSA_SHA2_256S | algorithm::SLH_DSA_SHA2_256S_W3C => {
            S::SlhDsa(kryptering::SlhDsaVariant::Sha2_256s)
        }
        _ => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "signature algorithm: {uri}"
            )))
        }
    })
}

/// Return the canonical URI spelling for any accepted `SignatureMethod` URI,
/// or `None` when the URI names no supported algorithm. Alias spellings map
/// to the canonical one, so two URIs name the same algorithm exactly when
/// their canonical spellings are equal.
pub fn canonical_signature_uri(uri: &str) -> Option<&'static str> {
    algorithm_for_uri(uri).ok().and_then(canonical_uri)
}

/// Whether a declared `SignatureMethod` URI names the algorithm an injected
/// signer or verifier reports, accepting alias spellings of the same
/// algorithm and rejecting everything else (including unmapped algorithms).
pub fn uri_matches_algorithm(uri: &str, algorithm: kryptering::SignatureAlgorithm) -> bool {
    match canonical_uri(algorithm) {
        Some(expected) => canonical_signature_uri(uri) == Some(expected),
        None => false,
    }
}

pub fn from_uri_with_context(
    uri: &str,
    context: Option<Vec<u8>>,
) -> Result<Box<dyn SignatureAlgorithm>, Error> {
    let algorithm = algorithm_for_uri(uri)?;

    let context = context.unwrap_or_default();
    #[cfg(feature = "post-quantum")]
    let accepts_context = matches!(
        algorithm,
        kryptering::SignatureAlgorithm::MlDsa(_) | kryptering::SignatureAlgorithm::SlhDsa(_)
    );
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

    /// Regression: feeds signed with the W3C `2026/08/xmldsig-more` ML-DSA
    /// identifiers were rejected as unsupported although the parameter sets
    /// are the ones behind the xmlsec identifiers. Both spellings must
    /// resolve to the same algorithm and be recognised as context-string
    /// algorithms.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn w3c_ml_dsa_uris_resolve_to_the_xmlsec_algorithms() {
        for (w3c, xmlsec) in [
            (algorithm::ML_DSA_44_W3C, algorithm::ML_DSA_44),
            (algorithm::ML_DSA_65_W3C, algorithm::ML_DSA_65),
            (algorithm::ML_DSA_87_W3C, algorithm::ML_DSA_87),
        ] {
            assert!(is_pq_algorithm(w3c), "{w3c} must take a context string");
            let via_w3c = from_uri(w3c).unwrap_or_else(|e| panic!("{w3c}: {e}"));
            let via_xmlsec = from_uri(xmlsec).unwrap_or_else(|e| panic!("{xmlsec}: {e}"));
            assert_eq!(via_w3c.uri(), via_xmlsec.uri(), "{w3c} must alias {xmlsec}");
            assert!(
                from_uri_with_context(w3c, Some(b"ctx".to_vec())).is_ok(),
                "{w3c} must accept a context string"
            );
        }
        assert!(
            from_uri("http://www.w3.org/2026/08/xmldsig-more#ml-dsa-99").is_err(),
            "unknown W3C parameter sets must still be rejected"
        );
    }

    /// Regression: SAML metadata feeds signed with the W3C
    /// `2026/08/xmldsig-more#slh-dsa-sha2-*` identifiers were rejected as
    /// unsupported although every SHA2 parameter set is implemented under
    /// the xmlsec identifier. The SHAKE parameter sets stay unsupported.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn w3c_slh_dsa_uris_resolve_to_the_xmlsec_algorithms() {
        use kryptering::{SignatureAlgorithm as S, SlhDsaVariant as V};

        for (w3c, xmlsec, variant) in [
            (
                algorithm::SLH_DSA_SHA2_128F_W3C,
                algorithm::SLH_DSA_SHA2_128F,
                V::Sha2_128f,
            ),
            (
                algorithm::SLH_DSA_SHA2_128S_W3C,
                algorithm::SLH_DSA_SHA2_128S,
                V::Sha2_128s,
            ),
            (
                algorithm::SLH_DSA_SHA2_192F_W3C,
                algorithm::SLH_DSA_SHA2_192F,
                V::Sha2_192f,
            ),
            (
                algorithm::SLH_DSA_SHA2_192S_W3C,
                algorithm::SLH_DSA_SHA2_192S,
                V::Sha2_192s,
            ),
            (
                algorithm::SLH_DSA_SHA2_256F_W3C,
                algorithm::SLH_DSA_SHA2_256F,
                V::Sha2_256f,
            ),
            (
                algorithm::SLH_DSA_SHA2_256S_W3C,
                algorithm::SLH_DSA_SHA2_256S,
                V::Sha2_256s,
            ),
        ] {
            assert!(is_pq_algorithm(w3c), "{w3c} must take a context string");
            let via_w3c = from_uri(w3c).unwrap_or_else(|e| panic!("{w3c}: {e}"));
            let via_xmlsec = from_uri(xmlsec).unwrap_or_else(|e| panic!("{xmlsec}: {e}"));
            assert_eq!(via_w3c.uri(), via_xmlsec.uri(), "{w3c} must alias {xmlsec}");
            assert_eq!(canonical_signature_uri(w3c), Some(xmlsec));
            assert!(uri_matches_algorithm(w3c, S::SlhDsa(variant)), "{w3c}");
            assert!(
                uri_matches_algorithm(xmlsec, S::SlhDsa(variant)),
                "{xmlsec}"
            );
            assert!(
                from_uri_with_context(w3c, Some(b"ctx".to_vec())).is_ok(),
                "{w3c} must accept a context string"
            );
        }
        assert!(!uri_matches_algorithm(
            algorithm::SLH_DSA_SHA2_128F_W3C,
            S::SlhDsa(V::Sha2_128s)
        ));
        for shake in ["128s", "128f", "192s", "192f", "256s", "256f"] {
            let uri = format!("http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-{shake}");
            assert!(from_uri(&uri).is_err(), "{uri} is not implemented");
            assert!(!is_pq_algorithm(&uri));
        }
    }

    /// Regression: injected signers and verifiers compared the declared URI
    /// with the canonical spelling only, so a W3C alias was reported as an
    /// algorithm mismatch. The comparison must be alias-aware while still
    /// rejecting different algorithms and unknown URIs.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn alias_aware_uri_matching_for_injected_providers() {
        use kryptering::{HashAlgorithm as H, MlDsaVariant as M, SignatureAlgorithm as S};

        assert_eq!(
            canonical_signature_uri(algorithm::ML_DSA_87_W3C),
            Some(algorithm::ML_DSA_87)
        );
        assert_eq!(
            canonical_signature_uri(algorithm::ML_DSA_87),
            Some(algorithm::ML_DSA_87)
        );
        assert_eq!(
            canonical_signature_uri(algorithm::RSA_SHA256),
            Some(algorithm::RSA_SHA256)
        );
        assert_eq!(canonical_signature_uri("urn:nope"), None);

        for (w3c, xmlsec, variant) in [
            (algorithm::ML_DSA_44_W3C, algorithm::ML_DSA_44, M::MlDsa44),
            (algorithm::ML_DSA_65_W3C, algorithm::ML_DSA_65, M::MlDsa65),
            (algorithm::ML_DSA_87_W3C, algorithm::ML_DSA_87, M::MlDsa87),
        ] {
            assert!(uri_matches_algorithm(w3c, S::MlDsa(variant)), "{w3c}");
            assert!(uri_matches_algorithm(xmlsec, S::MlDsa(variant)), "{xmlsec}");
        }
        // A different parameter set, a different family, and an unknown URI
        // are still mismatches.
        assert!(!uri_matches_algorithm(
            algorithm::ML_DSA_65_W3C,
            S::MlDsa(M::MlDsa44)
        ));
        assert!(!uri_matches_algorithm(
            algorithm::RSA_SHA256,
            S::MlDsa(M::MlDsa44)
        ));
        assert!(!uri_matches_algorithm(
            algorithm::ML_DSA_44_W3C,
            S::RsaPkcs1v15(H::Sha256)
        ));
        assert!(!uri_matches_algorithm("urn:nope", S::MlDsa(M::MlDsa44)));
        // Existing non-alias behaviour is unchanged.
        assert!(uri_matches_algorithm(
            algorithm::RSA_SHA256,
            S::RsaPkcs1v15(H::Sha256)
        ));
        assert!(!uri_matches_algorithm(
            algorithm::RSA_SHA256,
            S::RsaPkcs1v15(H::Sha512)
        ));
    }
}
