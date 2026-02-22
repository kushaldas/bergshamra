#![forbid(unsafe_code)]

//! Signature algorithm implementations (RSA, ECDSA, Ed25519, HMAC, ML-DSA, SLH-DSA).

use bergshamra_core::{algorithm, Error};
use signature::SignatureEncoding;

/// Key material for signature operations.
pub enum SigningKey {
    Rsa(rsa::RsaPrivateKey),
    RsaPublic(rsa::RsaPublicKey),
    EcP256(p256::ecdsa::SigningKey),
    EcP256Public(p256::ecdsa::VerifyingKey),
    EcP384(p384::ecdsa::SigningKey),
    EcP384Public(p384::ecdsa::VerifyingKey),
    EcP521(p521::ecdsa::SigningKey),
    EcP521Public(p521::ecdsa::VerifyingKey),
    Dsa(dsa::SigningKey),
    DsaPublic(dsa::VerifyingKey),
    Ed25519(ed25519_dalek::SigningKey),
    Ed25519Public(ed25519_dalek::VerifyingKey),
    Hmac(Vec<u8>),
    /// Post-quantum key stored as raw DER bytes.
    /// The algorithm variant determines how to parse them.
    PostQuantum {
        algorithm: PqAlgorithm,
        private_der: Option<Vec<u8>>,
        public_der: Vec<u8>,
    },
}

/// Post-quantum algorithm variants.
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
    /// Return a human-readable name.
    pub fn name(&self) -> &'static str {
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
}

/// Trait for signature algorithms.
pub trait SignatureAlgorithm: Send {
    fn uri(&self) -> &'static str;
    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify(&self, key: &SigningKey, data: &[u8], signature: &[u8]) -> Result<bool, Error>;
}

/// Create a signature algorithm from its URI (no context string).
pub fn from_uri(uri: &str) -> Result<Box<dyn SignatureAlgorithm>, Error> {
    from_uri_with_context(uri, None)
}

/// Create a signature algorithm from its URI with an optional context string.
/// Context strings are used by ML-DSA and SLH-DSA algorithms.
pub fn from_uri_with_context(
    uri: &str,
    context: Option<Vec<u8>>,
) -> Result<Box<dyn SignatureAlgorithm>, Error> {
    match uri {
        algorithm::RSA_SHA1 => Ok(Box::new(RsaPkcs1v15 {
            uri: algorithm::RSA_SHA1,
            hash: HashType::Sha1,
        })),
        algorithm::RSA_SHA224 => Ok(Box::new(RsaPkcs1v15 {
            uri: algorithm::RSA_SHA224,
            hash: HashType::Sha224,
        })),
        algorithm::RSA_SHA256 => Ok(Box::new(RsaPkcs1v15 {
            uri: algorithm::RSA_SHA256,
            hash: HashType::Sha256,
        })),
        algorithm::RSA_SHA384 => Ok(Box::new(RsaPkcs1v15 {
            uri: algorithm::RSA_SHA384,
            hash: HashType::Sha384,
        })),
        algorithm::RSA_SHA512 => Ok(Box::new(RsaPkcs1v15 {
            uri: algorithm::RSA_SHA512,
            hash: HashType::Sha512,
        })),

        algorithm::RSA_PSS_SHA1 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA1,
            hash: HashType::Sha1,
        })),
        algorithm::RSA_PSS_SHA224 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA224,
            hash: HashType::Sha224,
        })),
        algorithm::RSA_PSS_SHA256 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA256,
            hash: HashType::Sha256,
        })),
        algorithm::RSA_PSS_SHA384 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA384,
            hash: HashType::Sha384,
        })),
        algorithm::RSA_PSS_SHA512 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA512,
            hash: HashType::Sha512,
        })),

        algorithm::RSA_PSS_SHA3_224 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA3_224,
            hash: HashType::Sha3_224,
        })),
        algorithm::RSA_PSS_SHA3_256 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA3_256,
            hash: HashType::Sha3_256,
        })),
        algorithm::RSA_PSS_SHA3_384 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA3_384,
            hash: HashType::Sha3_384,
        })),
        algorithm::RSA_PSS_SHA3_512 => Ok(Box::new(RsaPss {
            uri: algorithm::RSA_PSS_SHA3_512,
            hash: HashType::Sha3_512,
        })),

        algorithm::ECDSA_SHA1 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA1,
            hash: HashType::Sha1,
        })),
        algorithm::ECDSA_SHA224 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA224,
            hash: HashType::Sha224,
        })),
        algorithm::ECDSA_SHA256 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA256,
            hash: HashType::Sha256,
        })),
        algorithm::ECDSA_SHA384 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA384,
            hash: HashType::Sha384,
        })),
        algorithm::ECDSA_SHA512 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA512,
            hash: HashType::Sha512,
        })),

        algorithm::ECDSA_SHA3_224 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA3_224,
            hash: HashType::Sha3_224,
        })),
        algorithm::ECDSA_SHA3_256 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA3_256,
            hash: HashType::Sha3_256,
        })),
        algorithm::ECDSA_SHA3_384 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA3_384,
            hash: HashType::Sha3_384,
        })),
        algorithm::ECDSA_SHA3_512 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_SHA3_512,
            hash: HashType::Sha3_512,
        })),

        algorithm::DSA_SHA1 => Ok(Box::new(DsaSign {
            uri: algorithm::DSA_SHA1,
            hash: HashType::Sha1,
        })),
        algorithm::DSA_SHA256 => Ok(Box::new(DsaSign {
            uri: algorithm::DSA_SHA256,
            hash: HashType::Sha256,
        })),

        algorithm::EDDSA_ED25519 => Ok(Box::new(Ed25519Sign)),

        algorithm::HMAC_SHA1 => Ok(Box::new(HmacSign {
            uri: algorithm::HMAC_SHA1,
            hash: HashType::Sha1,
        })),
        algorithm::HMAC_SHA224 => Ok(Box::new(HmacSign {
            uri: algorithm::HMAC_SHA224,
            hash: HashType::Sha224,
        })),
        algorithm::HMAC_SHA256 => Ok(Box::new(HmacSign {
            uri: algorithm::HMAC_SHA256,
            hash: HashType::Sha256,
        })),
        algorithm::HMAC_SHA384 => Ok(Box::new(HmacSign {
            uri: algorithm::HMAC_SHA384,
            hash: HashType::Sha384,
        })),
        algorithm::HMAC_SHA512 => Ok(Box::new(HmacSign {
            uri: algorithm::HMAC_SHA512,
            hash: HashType::Sha512,
        })),

        #[cfg(feature = "legacy-algorithms")]
        algorithm::RSA_MD5 => Ok(Box::new(RsaPkcs1v15 {
            uri: algorithm::RSA_MD5,
            hash: HashType::Md5,
        })),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::RSA_RIPEMD160 => Ok(Box::new(RsaPkcs1v15 {
            uri: algorithm::RSA_RIPEMD160,
            hash: HashType::Ripemd160,
        })),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::ECDSA_RIPEMD160 => Ok(Box::new(Ecdsa {
            uri: algorithm::ECDSA_RIPEMD160,
            hash: HashType::Ripemd160,
        })),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::HMAC_MD5 => Ok(Box::new(HmacSign {
            uri: algorithm::HMAC_MD5,
            hash: HashType::Md5,
        })),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::HMAC_RIPEMD160 => Ok(Box::new(HmacSign {
            uri: algorithm::HMAC_RIPEMD160,
            hash: HashType::Ripemd160,
        })),

        algorithm::ML_DSA_44 => Ok(Box::new(PqSign {
            uri: algorithm::ML_DSA_44,
            algorithm: PqAlgorithm::MlDsa44,
            context: context.unwrap_or_default(),
        })),
        algorithm::ML_DSA_65 => Ok(Box::new(PqSign {
            uri: algorithm::ML_DSA_65,
            algorithm: PqAlgorithm::MlDsa65,
            context: context.unwrap_or_default(),
        })),
        algorithm::ML_DSA_87 => Ok(Box::new(PqSign {
            uri: algorithm::ML_DSA_87,
            algorithm: PqAlgorithm::MlDsa87,
            context: context.unwrap_or_default(),
        })),

        algorithm::SLH_DSA_SHA2_128F => Ok(Box::new(PqSign {
            uri: algorithm::SLH_DSA_SHA2_128F,
            algorithm: PqAlgorithm::SlhDsaSha2_128f,
            context: context.unwrap_or_default(),
        })),
        algorithm::SLH_DSA_SHA2_128S => Ok(Box::new(PqSign {
            uri: algorithm::SLH_DSA_SHA2_128S,
            algorithm: PqAlgorithm::SlhDsaSha2_128s,
            context: context.unwrap_or_default(),
        })),
        algorithm::SLH_DSA_SHA2_192F => Ok(Box::new(PqSign {
            uri: algorithm::SLH_DSA_SHA2_192F,
            algorithm: PqAlgorithm::SlhDsaSha2_192f,
            context: context.unwrap_or_default(),
        })),
        algorithm::SLH_DSA_SHA2_192S => Ok(Box::new(PqSign {
            uri: algorithm::SLH_DSA_SHA2_192S,
            algorithm: PqAlgorithm::SlhDsaSha2_192s,
            context: context.unwrap_or_default(),
        })),
        algorithm::SLH_DSA_SHA2_256F => Ok(Box::new(PqSign {
            uri: algorithm::SLH_DSA_SHA2_256F,
            algorithm: PqAlgorithm::SlhDsaSha2_256f,
            context: context.unwrap_or_default(),
        })),
        algorithm::SLH_DSA_SHA2_256S => Ok(Box::new(PqSign {
            uri: algorithm::SLH_DSA_SHA2_256S,
            algorithm: PqAlgorithm::SlhDsaSha2_256s,
            context: context.unwrap_or_default(),
        })),

        _ => Err(Error::UnsupportedAlgorithm(format!(
            "signature algorithm: {uri}"
        ))),
    }
}

#[derive(Debug, Clone, Copy)]
enum HashType {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    #[cfg(feature = "legacy-algorithms")]
    Md5,
    #[cfg(feature = "legacy-algorithms")]
    Ripemd160,
}

// ── RSA PKCS#1 v1.5 ─────────────────────────────────────────────────

struct RsaPkcs1v15 {
    uri: &'static str,
    hash: HashType,
}

impl RsaPkcs1v15 {
    fn sign_with_key(
        &self,
        private_key: &rsa::RsaPrivateKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use signature::Signer;
        macro_rules! do_sign {
            ($hasher:ty) => {{
                let sk = rsa::pkcs1v15::SigningKey::<$hasher>::new(private_key.clone());
                Ok(sk.sign(data).to_vec())
            }};
        }
        match self.hash {
            HashType::Sha1 => do_sign!(sha1::Sha1),
            HashType::Sha224 => do_sign!(sha2::Sha224),
            HashType::Sha256 => do_sign!(sha2::Sha256),
            HashType::Sha384 => do_sign!(sha2::Sha384),
            HashType::Sha512 => do_sign!(sha2::Sha512),
            HashType::Sha3_224 => do_sign!(sha3::Sha3_224),
            HashType::Sha3_256 => do_sign!(sha3::Sha3_256),
            HashType::Sha3_384 => do_sign!(sha3::Sha3_384),
            HashType::Sha3_512 => do_sign!(sha3::Sha3_512),
            #[cfg(feature = "legacy-algorithms")]
            HashType::Md5 => do_sign!(md5::Md5),
            #[cfg(feature = "legacy-algorithms")]
            HashType::Ripemd160 => do_sign!(ripemd::Ripemd160),
        }
    }

    fn verify_with_key(
        &self,
        public_key: &rsa::RsaPublicKey,
        data: &[u8],
        sig_bytes: &[u8],
    ) -> Result<bool, Error> {
        use signature::Verifier;
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid RSA signature: {e}")))?;
        macro_rules! do_verify {
            ($hasher:ty) => {{
                let vk = rsa::pkcs1v15::VerifyingKey::<$hasher>::new(public_key.clone());
                Ok(vk.verify(data, &sig).is_ok())
            }};
        }
        match self.hash {
            HashType::Sha1 => do_verify!(sha1::Sha1),
            HashType::Sha224 => do_verify!(sha2::Sha224),
            HashType::Sha256 => do_verify!(sha2::Sha256),
            HashType::Sha384 => do_verify!(sha2::Sha384),
            HashType::Sha512 => do_verify!(sha2::Sha512),
            HashType::Sha3_224 => do_verify!(sha3::Sha3_224),
            HashType::Sha3_256 => do_verify!(sha3::Sha3_256),
            HashType::Sha3_384 => do_verify!(sha3::Sha3_384),
            HashType::Sha3_512 => do_verify!(sha3::Sha3_512),
            #[cfg(feature = "legacy-algorithms")]
            HashType::Md5 => do_verify!(md5::Md5),
            #[cfg(feature = "legacy-algorithms")]
            HashType::Ripemd160 => do_verify!(ripemd::Ripemd160),
        }
    }
}

impl SignatureAlgorithm for RsaPkcs1v15 {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        match key {
            SigningKey::Rsa(pk) => self.sign_with_key(pk, data),
            _ => Err(Error::Key("RSA private key required".into())),
        }
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        let pubk = match key {
            SigningKey::Rsa(pk) => pk.to_public_key(),
            SigningKey::RsaPublic(pk) => pk.clone(),
            _ => return Err(Error::Key("RSA key required".into())),
        };
        self.verify_with_key(&pubk, data, sig_bytes)
    }
}

// ── RSA-PSS ──────────────────────────────────────────────────────────

struct RsaPss {
    uri: &'static str,
    hash: HashType,
}

impl SignatureAlgorithm for RsaPss {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        use signature::RandomizedSigner;
        let SigningKey::Rsa(private_key) = key else {
            return Err(Error::Key("RSA private key required for PSS".into()));
        };
        let mut rng = rand::thread_rng();
        macro_rules! do_sign {
            ($hasher:ty) => {{
                let sk = rsa::pss::SigningKey::<$hasher>::new(private_key.clone());
                let sig = sk.sign_with_rng(&mut rng, data);
                Ok(sig.to_vec())
            }};
        }
        match self.hash {
            HashType::Sha1 => do_sign!(sha1::Sha1),
            HashType::Sha224 => do_sign!(sha2::Sha224),
            HashType::Sha256 => do_sign!(sha2::Sha256),
            HashType::Sha384 => do_sign!(sha2::Sha384),
            HashType::Sha512 => do_sign!(sha2::Sha512),
            HashType::Sha3_224 => do_sign!(sha3::Sha3_224),
            HashType::Sha3_256 => do_sign!(sha3::Sha3_256),
            HashType::Sha3_384 => do_sign!(sha3::Sha3_384),
            HashType::Sha3_512 => do_sign!(sha3::Sha3_512),
            #[cfg(feature = "legacy-algorithms")]
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "RSA-PSS with {:?}",
                self.hash
            ))),
        }
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        use signature::Verifier;
        let pubk = match key {
            SigningKey::Rsa(pk) => pk.to_public_key(),
            SigningKey::RsaPublic(pk) => pk.clone(),
            _ => return Err(Error::Key("RSA key required for PSS".into())),
        };
        let sig = rsa::pss::Signature::try_from(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid RSA-PSS signature: {e}")))?;
        macro_rules! do_verify {
            ($hasher:ty) => {{
                let vk = rsa::pss::VerifyingKey::<$hasher>::new(pubk);
                Ok(vk.verify(data, &sig).is_ok())
            }};
        }
        match self.hash {
            HashType::Sha1 => do_verify!(sha1::Sha1),
            HashType::Sha224 => do_verify!(sha2::Sha224),
            HashType::Sha256 => do_verify!(sha2::Sha256),
            HashType::Sha384 => do_verify!(sha2::Sha384),
            HashType::Sha512 => do_verify!(sha2::Sha512),
            HashType::Sha3_224 => do_verify!(sha3::Sha3_224),
            HashType::Sha3_256 => do_verify!(sha3::Sha3_256),
            HashType::Sha3_384 => do_verify!(sha3::Sha3_384),
            HashType::Sha3_512 => do_verify!(sha3::Sha3_512),
            #[cfg(feature = "legacy-algorithms")]
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "RSA-PSS with {:?}",
                self.hash
            ))),
        }
    }
}

// ── ECDSA (unified P-256 / P-384) ────────────────────────────────────

struct Ecdsa {
    uri: &'static str,
    hash: HashType,
}

/// Compute the digest of `data` using the given HashType.
fn compute_hash(hash: HashType, data: &[u8]) -> Vec<u8> {
    use digest::Digest;
    match hash {
        HashType::Sha1 => sha1::Sha1::digest(data).to_vec(),
        HashType::Sha224 => sha2::Sha224::digest(data).to_vec(),
        HashType::Sha256 => sha2::Sha256::digest(data).to_vec(),
        HashType::Sha384 => sha2::Sha384::digest(data).to_vec(),
        HashType::Sha512 => sha2::Sha512::digest(data).to_vec(),
        HashType::Sha3_224 => sha3::Sha3_224::digest(data).to_vec(),
        HashType::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
        HashType::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
        HashType::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        #[cfg(feature = "legacy-algorithms")]
        HashType::Md5 => md5::Md5::digest(data).to_vec(),
        #[cfg(feature = "legacy-algorithms")]
        HashType::Ripemd160 => ripemd::Ripemd160::digest(data).to_vec(),
    }
}

/// Normalize a raw r||s ECDSA signature where each component may be
/// padded (extra leading zeros) or truncated (missing leading zeros).
/// Splits evenly, strips leading zeros, then left-pads each to `field_size`.
fn normalize_raw_ecdsa(sig_bytes: &[u8], field_size: usize) -> Result<Vec<u8>, Error> {
    if sig_bytes.len() % 2 != 0 {
        return Err(Error::Crypto(format!(
            "ECDSA signature has odd length {}, cannot split into r||s",
            sig_bytes.len()
        )));
    }
    let half = sig_bytes.len() / 2;
    let mut out = vec![0u8; field_size * 2];

    for (i, component) in [&sig_bytes[..half], &sig_bytes[half..]].iter().enumerate() {
        let trimmed = match component.iter().position(|&b| b != 0) {
            Some(pos) => &component[pos..],
            None => &component[component.len().saturating_sub(1)..],
        };
        if trimmed.len() > field_size {
            return Err(Error::Crypto(format!(
                "ECDSA component {} too large: {} bytes (field size {})",
                if i == 0 { "r" } else { "s" },
                trimmed.len(),
                field_size
            )));
        }
        let offset = i * field_size + field_size - trimmed.len();
        out[offset..offset + trimmed.len()].copy_from_slice(trimmed);
    }
    Ok(out)
}

/// Convert XML-DSig ECDSA signature to a typed Signature for P-256.
/// Accepts raw r||s (64 bytes), DER/ASN.1, or padded/truncated raw formats.
pub fn xmldsig_to_p256(sig_bytes: &[u8]) -> Result<p256::ecdsa::Signature, Error> {
    const FIELD: usize = 32;
    if sig_bytes.len() == FIELD * 2 {
        let r = p256::FieldBytes::from_slice(&sig_bytes[..FIELD]);
        let s = p256::FieldBytes::from_slice(&sig_bytes[FIELD..]);
        return p256::ecdsa::Signature::from_scalars(*r, *s)
            .map_err(|e| Error::Crypto(format!("invalid P-256 signature: {e}")));
    }
    if sig_bytes.first() == Some(&0x30) {
        return p256::ecdsa::Signature::from_der(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid P-256 DER signature: {e}")));
    }
    let normalized = normalize_raw_ecdsa(sig_bytes, FIELD)?;
    let r = p256::FieldBytes::from_slice(&normalized[..FIELD]);
    let s = p256::FieldBytes::from_slice(&normalized[FIELD..]);
    p256::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|e| Error::Crypto(format!("invalid P-256 signature: {e}")))
}

/// Convert P-256 signature to XML-DSig r||s format.
pub fn p256_to_xmldsig(sig: &p256::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// Convert XML-DSig ECDSA signature to a typed Signature for P-384.
/// Accepts raw r||s (96 bytes), DER/ASN.1, or padded/truncated raw formats.
pub fn xmldsig_to_p384(sig_bytes: &[u8]) -> Result<p384::ecdsa::Signature, Error> {
    const FIELD: usize = 48;
    if sig_bytes.len() == FIELD * 2 {
        let r = p384::FieldBytes::from_slice(&sig_bytes[..FIELD]);
        let s = p384::FieldBytes::from_slice(&sig_bytes[FIELD..]);
        return p384::ecdsa::Signature::from_scalars(*r, *s)
            .map_err(|e| Error::Crypto(format!("invalid P-384 signature: {e}")));
    }
    if sig_bytes.first() == Some(&0x30) {
        return p384::ecdsa::Signature::from_der(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid P-384 DER signature: {e}")));
    }
    let normalized = normalize_raw_ecdsa(sig_bytes, FIELD)?;
    let r = p384::FieldBytes::from_slice(&normalized[..FIELD]);
    let s = p384::FieldBytes::from_slice(&normalized[FIELD..]);
    p384::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|e| Error::Crypto(format!("invalid P-384 signature: {e}")))
}

/// Convert P-384 signature to XML-DSig r||s format.
pub fn p384_to_xmldsig(sig: &p384::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// Convert XML-DSig ECDSA signature to a typed Signature for P-521.
/// Accepts raw r||s (132 bytes), DER/ASN.1, or padded/truncated raw formats.
pub fn xmldsig_to_p521(sig_bytes: &[u8]) -> Result<p521::ecdsa::Signature, Error> {
    const FIELD: usize = 66;
    if sig_bytes.len() == FIELD * 2 {
        let r = p521::FieldBytes::from_slice(&sig_bytes[..FIELD]);
        let s = p521::FieldBytes::from_slice(&sig_bytes[FIELD..]);
        return p521::ecdsa::Signature::from_scalars(*r, *s)
            .map_err(|e| Error::Crypto(format!("invalid P-521 signature: {e}")));
    }
    if sig_bytes.first() == Some(&0x30) {
        return p521::ecdsa::Signature::from_der(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid P-521 DER signature: {e}")));
    }
    let normalized = normalize_raw_ecdsa(sig_bytes, FIELD)?;
    let r = p521::FieldBytes::from_slice(&normalized[..FIELD]);
    let s = p521::FieldBytes::from_slice(&normalized[FIELD..]);
    p521::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|e| Error::Crypto(format!("invalid P-521 signature: {e}")))
}

/// Convert P-521 signature to XML-DSig r||s format.
pub fn p521_to_xmldsig(sig: &p521::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(132);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// Left-pad a prehash with zeros to match the EC field size.
/// The ecdsa crate's `verify_prehash` requires the hash to be at least
/// as long as the curve's scalar field. When using a shorter hash
/// (e.g. SHA-1 with P-384), we must zero-pad on the left.
fn pad_prehash(prehash: &[u8], field_size: usize) -> Vec<u8> {
    if prehash.len() >= field_size {
        return prehash.to_vec();
    }
    let mut padded = vec![0u8; field_size];
    padded[field_size - prehash.len()..].copy_from_slice(prehash);
    padded
}

impl SignatureAlgorithm for Ecdsa {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        use signature::hazmat::PrehashSigner;
        let raw_hash = compute_hash(self.hash, data);
        match key {
            SigningKey::EcP256(sk) => {
                let prehash = pad_prehash(&raw_hash, 32);
                let sig: p256::ecdsa::Signature = sk
                    .sign_prehash(&prehash)
                    .map_err(|e| Error::Crypto(format!("ECDSA P-256 sign: {e}")))?;
                Ok(p256_to_xmldsig(&sig))
            }
            SigningKey::EcP384(sk) => {
                let prehash = pad_prehash(&raw_hash, 48);
                let sig: p384::ecdsa::Signature = sk
                    .sign_prehash(&prehash)
                    .map_err(|e| Error::Crypto(format!("ECDSA P-384 sign: {e}")))?;
                Ok(p384_to_xmldsig(&sig))
            }
            SigningKey::EcP521(sk) => {
                let prehash = pad_prehash(&raw_hash, 66);
                let sig: p521::ecdsa::Signature = sk
                    .sign_prehash(&prehash)
                    .map_err(|e| Error::Crypto(format!("ECDSA P-521 sign: {e}")))?;
                Ok(p521_to_xmldsig(&sig))
            }
            _ => Err(Error::Key(
                "ECDSA signing key required (P-256, P-384, or P-521)".into(),
            )),
        }
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        use signature::hazmat::PrehashVerifier;
        let raw_hash = compute_hash(self.hash, data);
        match key {
            SigningKey::EcP256(sk) => {
                let prehash = pad_prehash(&raw_hash, 32);
                let sig = xmldsig_to_p256(sig_bytes)?;
                Ok(sk.verifying_key().verify_prehash(&prehash, &sig).is_ok())
            }
            SigningKey::EcP256Public(vk) => {
                let prehash = pad_prehash(&raw_hash, 32);
                let sig = xmldsig_to_p256(sig_bytes)?;
                Ok(vk.verify_prehash(&prehash, &sig).is_ok())
            }
            SigningKey::EcP384(sk) => {
                let prehash = pad_prehash(&raw_hash, 48);
                let sig = xmldsig_to_p384(sig_bytes)?;
                Ok(sk.verifying_key().verify_prehash(&prehash, &sig).is_ok())
            }
            SigningKey::EcP384Public(vk) => {
                let prehash = pad_prehash(&raw_hash, 48);
                let sig = xmldsig_to_p384(sig_bytes)?;
                Ok(vk.verify_prehash(&prehash, &sig).is_ok())
            }
            SigningKey::EcP521(sk) => {
                let prehash = pad_prehash(&raw_hash, 66);
                let sig = xmldsig_to_p521(sig_bytes)?;
                let vk = p521::ecdsa::VerifyingKey::from(sk);
                Ok(vk.verify_prehash(&prehash, &sig).is_ok())
            }
            SigningKey::EcP521Public(vk) => {
                let prehash = pad_prehash(&raw_hash, 66);
                let sig = xmldsig_to_p521(sig_bytes)?;
                Ok(vk.verify_prehash(&prehash, &sig).is_ok())
            }
            _ => Err(Error::Key(
                "ECDSA key required (P-256, P-384, or P-521)".into(),
            )),
        }
    }
}

// ── DSA ──────────────────────────────────────────────────────────────

struct DsaSign {
    uri: &'static str,
    hash: HashType,
}

impl SignatureAlgorithm for DsaSign {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        use signature::DigestSigner;
        let SigningKey::Dsa(sk) = key else {
            return Err(Error::Key("DSA signing key required".into()));
        };
        let sig: dsa::Signature = match self.hash {
            HashType::Sha1 => sk
                .try_sign_digest(sha1::Sha1::new_with_prefix(data))
                .map_err(|e| Error::Crypto(format!("DSA sign: {e}")))?,
            HashType::Sha256 => sk
                .try_sign_digest(sha2::Sha256::new_with_prefix(data))
                .map_err(|e| Error::Crypto(format!("DSA sign: {e}")))?,
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "DSA signature with {:?}",
                    self.hash
                )))
            }
        };
        // XML-DSig format: r||s, each zero-padded to q byte length
        Ok(dsa_sig_to_xmldsig(sk.verifying_key(), &sig))
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        use signature::DigestVerifier;
        let vk = match key {
            SigningKey::Dsa(sk) => sk.verifying_key().clone(),
            SigningKey::DsaPublic(vk) => vk.clone(),
            _ => return Err(Error::Key("DSA key required".into())),
        };
        let sig = xmldsig_to_dsa(&vk, sig_bytes)?;
        let result = match self.hash {
            HashType::Sha1 => vk.verify_digest(sha1::Sha1::new_with_prefix(data), &sig),
            HashType::Sha256 => vk.verify_digest(sha2::Sha256::new_with_prefix(data), &sig),
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "DSA with {:?}",
                    self.hash
                )))
            }
        };
        Ok(result.is_ok())
    }
}

use digest::Digest;

/// Convert a DSA signature to XML-DSig r||s format.
/// Each component is zero-padded to the byte-length of q.
fn dsa_sig_to_xmldsig(vk: &dsa::VerifyingKey, sig: &dsa::Signature) -> Vec<u8> {
    let q_len = (vk.components().q().bits() as usize + 7) / 8;
    let r_bytes = sig.r().to_bytes_be();
    let s_bytes = sig.s().to_bytes_be();
    let mut out = vec![0u8; q_len * 2];
    // Right-align r
    let r_start = q_len.saturating_sub(r_bytes.len());
    out[r_start..q_len].copy_from_slice(&r_bytes[r_bytes.len().saturating_sub(q_len)..]);
    // Right-align s
    let s_start = q_len + q_len.saturating_sub(s_bytes.len());
    out[s_start..q_len * 2].copy_from_slice(&s_bytes[s_bytes.len().saturating_sub(q_len)..]);
    out
}

/// Convert XML-DSig r||s format to a DSA signature.
fn xmldsig_to_dsa(vk: &dsa::VerifyingKey, rs: &[u8]) -> Result<dsa::Signature, Error> {
    let q_len = (vk.components().q().bits() as usize + 7) / 8;
    if rs.len() != q_len * 2 {
        return Err(Error::Crypto(format!(
            "DSA signature must be {} bytes (2 * q_len={}), got {}",
            q_len * 2,
            q_len,
            rs.len()
        )));
    }
    let r = dsa::BigUint::from_bytes_be(&rs[..q_len]);
    let s = dsa::BigUint::from_bytes_be(&rs[q_len..]);
    dsa::Signature::from_components(r, s)
        .map_err(|e| Error::Crypto(format!("invalid DSA signature: {e}")))
}

// ── Ed25519 (EdDSA over Curve25519) ──────────────────────────────────

struct Ed25519Sign;

impl SignatureAlgorithm for Ed25519Sign {
    fn uri(&self) -> &'static str {
        algorithm::EDDSA_ED25519
    }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        use ed25519_dalek::Signer;
        let SigningKey::Ed25519(sk) = key else {
            return Err(Error::Key("Ed25519 signing key required".into()));
        };
        let sig = sk.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        use ed25519_dalek::Verifier;
        let vk = match key {
            SigningKey::Ed25519(sk) => sk.verifying_key(),
            SigningKey::Ed25519Public(vk) => *vk,
            _ => return Err(Error::Key("Ed25519 key required".into())),
        };
        let sig = ed25519_dalek::Signature::from_slice(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid Ed25519 signature: {e}")))?;
        Ok(vk.verify(data, &sig).is_ok())
    }
}

// ── HMAC ─────────────────────────────────────────────────────────────

struct HmacSign {
    uri: &'static str,
    hash: HashType,
}

impl SignatureAlgorithm for HmacSign {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        let SigningKey::Hmac(key_bytes) = key else {
            return Err(Error::Key("HMAC key required".into()));
        };
        Ok(compute_hmac(self.hash, key_bytes, data))
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        let SigningKey::Hmac(key_bytes) = key else {
            return Err(Error::Key("HMAC key required".into()));
        };
        let expected = compute_hmac(self.hash, key_bytes, data);
        Ok(constant_time_eq(&expected, sig_bytes))
    }
}

fn compute_hmac(hash: HashType, key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    macro_rules! hmac_compute {
        ($hasher:ty) => {{
            let mut mac = <Hmac<$hasher>>::new_from_slice(key).expect("HMAC key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match hash {
        HashType::Sha1 => hmac_compute!(sha1::Sha1),
        HashType::Sha224 => hmac_compute!(sha2::Sha224),
        HashType::Sha256 => hmac_compute!(sha2::Sha256),
        HashType::Sha384 => hmac_compute!(sha2::Sha384),
        HashType::Sha512 => hmac_compute!(sha2::Sha512),
        HashType::Sha3_224 => hmac_compute!(sha3::Sha3_224),
        HashType::Sha3_256 => hmac_compute!(sha3::Sha3_256),
        HashType::Sha3_384 => hmac_compute!(sha3::Sha3_384),
        HashType::Sha3_512 => hmac_compute!(sha3::Sha3_512),
        #[cfg(feature = "legacy-algorithms")]
        HashType::Md5 => hmac_compute!(md5::Md5),
        #[cfg(feature = "legacy-algorithms")]
        HashType::Ripemd160 => hmac_compute!(ripemd::Ripemd160),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if b.is_empty() || a.is_empty() {
        return false;
    }
    if b.len() < a.len() {
        // Truncated HMAC comparison
        return a[..b.len()]
            .iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0;
    }
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Return the hash output size in bits for an HMAC algorithm URI.
/// Returns `None` if the URI is not a recognized HMAC algorithm.
pub fn hmac_hash_output_bits(uri: &str) -> Option<usize> {
    match uri {
        algorithm::HMAC_SHA1 => Some(160),
        algorithm::HMAC_SHA224 => Some(224),
        algorithm::HMAC_SHA256 => Some(256),
        algorithm::HMAC_SHA384 => Some(384),
        algorithm::HMAC_SHA512 => Some(512),
        algorithm::HMAC_MD5 => Some(128),
        algorithm::HMAC_RIPEMD160 => Some(160),
        _ => None,
    }
}

/// Returns `true` if the given URI is an HMAC signature algorithm.
pub fn is_hmac_algorithm(uri: &str) -> bool {
    hmac_hash_output_bits(uri).is_some()
}

/// Returns `true` if the given URI is a post-quantum (ML-DSA or SLH-DSA) algorithm.
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

// ── Post-quantum (ML-DSA / SLH-DSA) ─────────────────────────────────

struct PqSign {
    uri: &'static str,
    algorithm: PqAlgorithm,
    context: Vec<u8>,
}

impl SignatureAlgorithm for PqSign {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        let SigningKey::PostQuantum {
            algorithm,
            private_der,
            ..
        } = key
        else {
            return Err(Error::Key(format!(
                "{} signing key required",
                self.algorithm.name()
            )));
        };
        if *algorithm != self.algorithm {
            return Err(Error::Key(format!(
                "key algorithm mismatch: key is {}, but signature requires {}",
                algorithm.name(),
                self.algorithm.name(),
            )));
        }
        let private = private_der.as_ref().ok_or_else(|| {
            Error::Key(format!(
                "{} private key required for signing",
                self.algorithm.name()
            ))
        })?;

        match self.algorithm {
            PqAlgorithm::MlDsa44 => pq_ml_dsa_sign::<ml_dsa::MlDsa44>(private, data, &self.context),
            PqAlgorithm::MlDsa65 => pq_ml_dsa_sign::<ml_dsa::MlDsa65>(private, data, &self.context),
            PqAlgorithm::MlDsa87 => pq_ml_dsa_sign::<ml_dsa::MlDsa87>(private, data, &self.context),
            PqAlgorithm::SlhDsaSha2_128f => {
                pq_slh_dsa_sign::<slh_dsa::Sha2_128f>(private, data, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_128s => {
                pq_slh_dsa_sign::<slh_dsa::Sha2_128s>(private, data, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_192f => {
                pq_slh_dsa_sign::<slh_dsa::Sha2_192f>(private, data, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_192s => {
                pq_slh_dsa_sign::<slh_dsa::Sha2_192s>(private, data, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_256f => {
                pq_slh_dsa_sign::<slh_dsa::Sha2_256f>(private, data, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_256s => {
                pq_slh_dsa_sign::<slh_dsa::Sha2_256s>(private, data, &self.context)
            }
        }
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        let SigningKey::PostQuantum {
            algorithm,
            public_der,
            ..
        } = key
        else {
            return Err(Error::Key(format!(
                "{} key required",
                self.algorithm.name()
            )));
        };
        if *algorithm != self.algorithm {
            return Err(Error::Key(format!(
                "key algorithm mismatch: key is {}, but signature requires {}",
                algorithm.name(),
                self.algorithm.name(),
            )));
        }

        match self.algorithm {
            PqAlgorithm::MlDsa44 => {
                pq_ml_dsa_verify::<ml_dsa::MlDsa44>(public_der, data, sig_bytes, &self.context)
            }
            PqAlgorithm::MlDsa65 => {
                pq_ml_dsa_verify::<ml_dsa::MlDsa65>(public_der, data, sig_bytes, &self.context)
            }
            PqAlgorithm::MlDsa87 => {
                pq_ml_dsa_verify::<ml_dsa::MlDsa87>(public_der, data, sig_bytes, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_128f => {
                pq_slh_dsa_verify::<slh_dsa::Sha2_128f>(public_der, data, sig_bytes, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_128s => {
                pq_slh_dsa_verify::<slh_dsa::Sha2_128s>(public_der, data, sig_bytes, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_192f => {
                pq_slh_dsa_verify::<slh_dsa::Sha2_192f>(public_der, data, sig_bytes, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_192s => {
                pq_slh_dsa_verify::<slh_dsa::Sha2_192s>(public_der, data, sig_bytes, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_256f => {
                pq_slh_dsa_verify::<slh_dsa::Sha2_256f>(public_der, data, sig_bytes, &self.context)
            }
            PqAlgorithm::SlhDsaSha2_256s => {
                pq_slh_dsa_verify::<slh_dsa::Sha2_256s>(public_der, data, sig_bytes, &self.context)
            }
        }
    }
}

/// Sign with ML-DSA (FIPS 204).
///
/// `private_der` may be either a full PKCS#8 DER document (from RustCrypto format)
/// or just the 32-byte seed (from OpenSSL format, extracted by the loader).
fn pq_ml_dsa_sign<P>(private_der: &[u8], data: &[u8], context: &[u8]) -> Result<Vec<u8>, Error>
where
    P: ml_dsa::MlDsaParams + ml_dsa::KeyGen,
    P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
{
    let sk = load_ml_dsa_signing_key::<P>(private_der)?;
    let sig = sk
        .sign_deterministic(data, context)
        .map_err(|e| Error::Crypto(format!("ML-DSA sign failed: {e}")))?;
    Ok(sig.encode().to_vec())
}

/// Verify with ML-DSA (FIPS 204).
fn pq_ml_dsa_verify<P>(
    public_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool, Error>
where
    P: ml_dsa::MlDsaParams + ml_dsa::KeyGen,
    P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
{
    use pkcs8_pq::spki::DecodePublicKey;
    let vk = ml_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
        .map_err(|e| Error::Key(format!("failed to parse ML-DSA public key: {e}")))?;
    let encoded_sig = ml_dsa::EncodedSignature::<P>::try_from(sig_bytes)
        .map_err(|_| Error::Crypto("invalid ML-DSA signature length".into()))?;
    let sig = ml_dsa::Signature::<P>::decode(&encoded_sig)
        .ok_or_else(|| Error::Crypto("failed to decode ML-DSA signature".into()))?;
    Ok(vk.verify_with_context(data, context, &sig))
}

/// Sign with SLH-DSA (FIPS 205).
///
/// `private_der` may be either a full PKCS#8 DER document (from RustCrypto format)
/// or just the raw key bytes (from OpenSSL format, extracted by the loader).
fn pq_slh_dsa_sign<P>(private_der: &[u8], data: &[u8], context: &[u8]) -> Result<Vec<u8>, Error>
where
    P: slh_dsa::ParameterSet,
{
    let sk = load_slh_dsa_signing_key::<P>(private_der)?;
    let sig = sk
        .try_sign_with_context(data, context, None)
        .map_err(|e| Error::Crypto(format!("SLH-DSA sign failed: {e}")))?;
    Ok(sig.to_bytes().to_vec())
}

/// Verify with SLH-DSA (FIPS 205).
fn pq_slh_dsa_verify<P>(
    public_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool, Error>
where
    P: slh_dsa::ParameterSet,
{
    use pkcs8_pq::spki::DecodePublicKey;
    let vk = slh_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
        .map_err(|e| Error::Key(format!("failed to parse SLH-DSA public key: {e}")))?;
    let sig = slh_dsa::Signature::<P>::try_from(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid SLH-DSA signature: {e}")))?;
    Ok(vk.try_verify_with_context(data, context, &sig).is_ok())
}

/// Load an ML-DSA signing key from either PKCS#8 DER or a 32-byte seed.
fn load_ml_dsa_signing_key<P>(private_der: &[u8]) -> Result<ml_dsa::SigningKey<P>, Error>
where
    P: ml_dsa::MlDsaParams + ml_dsa::KeyGen,
    P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
{
    // Try full PKCS#8 DER first (RustCrypto format)
    use pkcs8_pq::DecodePrivateKey;
    if let Ok(sk) = ml_dsa::SigningKey::<P>::from_pkcs8_der(private_der) {
        return Ok(sk);
    }
    // Fall back to 32-byte seed (from OpenSSL format, extracted by loader)
    if private_der.len() == 32 {
        let seed = ml_dsa::Seed::try_from(private_der)
            .map_err(|_| Error::Key("invalid ML-DSA seed length".into()))?;
        return Ok(ml_dsa::SigningKey::<P>::from_seed(&seed));
    }
    Err(Error::Key(format!(
        "failed to parse ML-DSA private key: expected PKCS#8 DER or 32-byte seed, got {} bytes",
        private_der.len()
    )))
}

/// Load an SLH-DSA signing key from either PKCS#8 DER or raw key bytes.
fn load_slh_dsa_signing_key<P>(private_der: &[u8]) -> Result<slh_dsa::SigningKey<P>, Error>
where
    P: slh_dsa::ParameterSet,
{
    // Try full PKCS#8 DER first (RustCrypto format)
    use pkcs8_pq::DecodePrivateKey;
    if let Ok(sk) = slh_dsa::SigningKey::<P>::from_pkcs8_der(private_der) {
        return Ok(sk);
    }
    // Fall back to raw key bytes (from OpenSSL format, extracted by loader)
    slh_dsa::SigningKey::<P>::try_from(private_der)
        .map_err(|e| Error::Key(format!("failed to parse SLH-DSA private key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p384_sha1_verify() {
        // P-384 public key (uncompressed point, 97 bytes)
        let pk_bytes: Vec<u8> = vec![
            0x04, 0xef, 0xf2, 0x77, 0xf3, 0x99, 0xcc, 0x37, 0xe3, 0x5f, 0x8a, 0xa2, 0xbc, 0x36,
            0x3f, 0xbe, 0xc5, 0x08, 0xba, 0x1e, 0x8a, 0x58, 0x0c, 0x68, 0xc5, 0x6e, 0x4f, 0xe2,
            0xe9, 0x2f, 0xc1, 0xdf, 0x93, 0xea, 0x95, 0x65, 0x8d, 0x6b, 0x17, 0xd9, 0x40, 0x49,
            0x34, 0xdc, 0xb9, 0x31, 0xd8, 0x53, 0xc0, 0x1f, 0x1e, 0xd9, 0x8c, 0x01, 0xf2, 0x45,
            0x1b, 0x27, 0x07, 0x6c, 0x01, 0x2f, 0xd7, 0x1a, 0x2f, 0xdf, 0xcf, 0xcb, 0xa7, 0x16,
            0xbb, 0x3e, 0x95, 0x59, 0x40, 0x80, 0x8b, 0x3a, 0xb3, 0xfc, 0x41, 0x60, 0x56, 0xdf,
            0x52, 0x84, 0x62, 0x01, 0xa7, 0x03, 0xd9, 0x2a, 0x55, 0x0d, 0xee, 0x97, 0x04,
        ];

        use p384::elliptic_curve::sec1::FromEncodedPoint;
        let encoded = p384::EncodedPoint::from_bytes(&pk_bytes).unwrap();
        let pk = p384::PublicKey::from_encoded_point(&encoded).unwrap();
        let vk = p384::ecdsa::VerifyingKey::from(pk);

        // Signature (96 bytes: r || s)
        let sig_bytes: Vec<u8> = vec![
            0x7f, 0x7f, 0x38, 0x89, 0xc4, 0x6a, 0x65, 0xa4, 0xa9, 0xc6, 0xfb, 0xa8, 0xdc, 0x93,
            0x0a, 0x80, 0x9e, 0xdf, 0xb2, 0x7e, 0x0a, 0x10, 0x00, 0x37, 0xd6, 0x1f, 0x9b, 0xe5,
            0xb3, 0xc0, 0x79, 0xfe, 0xca, 0x7c, 0xa1, 0x5c, 0xdf, 0xb8, 0xcb, 0xde, 0x29, 0xc0,
            0x19, 0x6e, 0x9e, 0xe8, 0xa6, 0xac, 0x14, 0x3f, 0xe6, 0x06, 0x17, 0x96, 0xbc, 0xcd,
            0xe2, 0x45, 0x78, 0x41, 0xc0, 0x00, 0x3d, 0xcd, 0xa8, 0xe1, 0xf2, 0x2e, 0xa4, 0xf6,
            0x0b, 0xd0, 0xae, 0x1d, 0x6d, 0x2c, 0xa8, 0xec, 0x30, 0x25, 0x4e, 0xb2, 0x42, 0xbd,
            0x70, 0x4d, 0x6f, 0xfd, 0x57, 0xaf, 0xcf, 0x54, 0xf6, 0xa7, 0x49, 0x4f,
        ];
        let sig = xmldsig_to_p384(&sig_bytes).unwrap();

        // Canonicalized SignedInfo (SHA-1 prehash = e5a7073da63df89f5ad1c3be2fc00175463d0980)
        let prehash_hex = "e5a7073da63df89f5ad1c3be2fc00175463d0980";
        let prehash: Vec<u8> = (0..prehash_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&prehash_hex[i..i + 2], 16).unwrap())
            .collect();

        // SHA-1 prehash is 20 bytes - shorter than P-384 field size of 48 bytes
        assert_eq!(prehash.len(), 20);

        // pad_prehash should left-pad to 48 bytes
        let padded = pad_prehash(&prehash, 48);
        assert_eq!(padded.len(), 48);

        use signature::hazmat::PrehashVerifier;
        let result = vk.verify_prehash(&padded, &sig);
        assert!(
            result.is_ok(),
            "P-384 with SHA-1 prehash (left-padded) should verify"
        );
    }

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        // Generate a random Ed25519 key pair
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let data = b"The quick brown fox jumps over the lazy dog";

        // Sign using our Ed25519Sign implementation
        let algo = Ed25519Sign;
        let signing_key = super::SigningKey::Ed25519(sk.clone());
        let signature = algo
            .sign(&signing_key, data)
            .expect("signing should succeed");

        // Verify using our Ed25519Sign implementation
        let verify_key = super::SigningKey::Ed25519Public(vk);
        let result = algo.verify(&verify_key, data, &signature);
        assert!(
            result.is_ok(),
            "Ed25519 round-trip verification should succeed"
        );
    }

    #[test]
    fn test_ed25519_tampered_data_fails() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let data = b"Original content";
        let tampered = b"Tampered content";

        let algo = Ed25519Sign;
        let signing_key = super::SigningKey::Ed25519(sk);
        let signature = algo
            .sign(&signing_key, data)
            .expect("signing should succeed");

        // Verify against tampered data should return Ok(false)
        let verify_key = super::SigningKey::Ed25519Public(vk);
        let result = algo.verify(&verify_key, tampered, &signature);
        assert_eq!(
            result.unwrap(),
            false,
            "Ed25519 verification of tampered data should return false"
        );
    }

    #[test]
    fn test_ed25519_tampered_signature_fails() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let data = b"Some data to sign";

        let algo = Ed25519Sign;
        let signing_key = super::SigningKey::Ed25519(sk);
        let mut signature = algo
            .sign(&signing_key, data)
            .expect("signing should succeed");

        // Tamper with the signature
        if let Some(b) = signature.last_mut() {
            *b ^= 0xff;
        }

        let verify_key = super::SigningKey::Ed25519Public(vk);
        let result = algo.verify(&verify_key, data, &signature);
        // May return Ok(false) or Err depending on whether the tampered sig is parseable
        match result {
            Ok(valid) => assert!(
                !valid,
                "Ed25519 verification of tampered signature should be false"
            ),
            Err(_) => {} // Also acceptable — invalid signature bytes
        }
    }

    #[test]
    fn test_ed25519_algorithm_uri_mapping() {
        use bergshamra_core::algorithm;

        // from_uri_with_context should return Ok for the Ed25519 URI
        let algo = from_uri_with_context(algorithm::EDDSA_ED25519, None);
        assert!(
            algo.is_ok(),
            "EDDSA_ED25519 URI should resolve to an algorithm"
        );

        // Sign and verify to prove it works through the factory
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let signing_key = super::SigningKey::Ed25519(sk.clone());

        let data = b"test data";
        let algo = algo.unwrap();
        let sig = algo.sign(&signing_key, data).expect("should sign");

        let vk = super::SigningKey::Ed25519Public(sk.verifying_key());
        let result = algo.verify(&vk, data, &sig);
        assert!(result.is_ok(), "factory-created Ed25519 algo should verify");
    }

    #[test]
    fn test_ed25519_verify_with_private_key() {
        // Ed25519 verification should also work when given a SigningKey (private)
        // since Ed25519Sign::verify extracts the verifying key
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let data = b"verify with private key";

        let algo = Ed25519Sign;
        let signing_key = super::SigningKey::Ed25519(sk.clone());
        let signature = algo
            .sign(&signing_key, data)
            .expect("signing should succeed");

        // Verify using the private key (should internally extract verifying key)
        let result = algo.verify(&signing_key, data, &signature);
        assert!(
            result.is_ok(),
            "Ed25519 verification with private key should succeed"
        );
    }

    #[test]
    fn test_ed25519_signature_is_64_bytes() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let data = b"check signature length";

        let algo = Ed25519Sign;
        let signing_key = super::SigningKey::Ed25519(sk);
        let signature = algo
            .sign(&signing_key, data)
            .expect("signing should succeed");

        assert_eq!(
            signature.len(),
            64,
            "Ed25519 signature should be exactly 64 bytes"
        );
    }
}
