#![forbid(unsafe_code)]

//! Signature algorithm implementations (RSA, ECDSA, HMAC).

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
    Hmac(Vec<u8>),
}

/// Trait for signature algorithms.
pub trait SignatureAlgorithm: Send {
    fn uri(&self) -> &'static str;
    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify(&self, key: &SigningKey, data: &[u8], signature: &[u8]) -> Result<bool, Error>;
}

/// Create a signature algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn SignatureAlgorithm>, Error> {
    match uri {
        algorithm::RSA_SHA1 => Ok(Box::new(RsaPkcs1v15 { uri: algorithm::RSA_SHA1, hash: HashType::Sha1 })),
        algorithm::RSA_SHA224 => Ok(Box::new(RsaPkcs1v15 { uri: algorithm::RSA_SHA224, hash: HashType::Sha224 })),
        algorithm::RSA_SHA256 => Ok(Box::new(RsaPkcs1v15 { uri: algorithm::RSA_SHA256, hash: HashType::Sha256 })),
        algorithm::RSA_SHA384 => Ok(Box::new(RsaPkcs1v15 { uri: algorithm::RSA_SHA384, hash: HashType::Sha384 })),
        algorithm::RSA_SHA512 => Ok(Box::new(RsaPkcs1v15 { uri: algorithm::RSA_SHA512, hash: HashType::Sha512 })),

        algorithm::RSA_PSS_SHA1 => Ok(Box::new(RsaPss { uri: algorithm::RSA_PSS_SHA1, hash: HashType::Sha1 })),
        algorithm::RSA_PSS_SHA224 => Ok(Box::new(RsaPss { uri: algorithm::RSA_PSS_SHA224, hash: HashType::Sha224 })),
        algorithm::RSA_PSS_SHA256 => Ok(Box::new(RsaPss { uri: algorithm::RSA_PSS_SHA256, hash: HashType::Sha256 })),
        algorithm::RSA_PSS_SHA384 => Ok(Box::new(RsaPss { uri: algorithm::RSA_PSS_SHA384, hash: HashType::Sha384 })),
        algorithm::RSA_PSS_SHA512 => Ok(Box::new(RsaPss { uri: algorithm::RSA_PSS_SHA512, hash: HashType::Sha512 })),

        algorithm::ECDSA_SHA1 => Ok(Box::new(EcdsaP256 { uri: algorithm::ECDSA_SHA1 })),
        algorithm::ECDSA_SHA256 => Ok(Box::new(EcdsaP256 { uri: algorithm::ECDSA_SHA256 })),
        algorithm::ECDSA_SHA384 => Ok(Box::new(EcdsaP384 { uri: algorithm::ECDSA_SHA384 })),
        algorithm::ECDSA_SHA512 => Ok(Box::new(EcdsaP384 { uri: algorithm::ECDSA_SHA512 })),

        algorithm::HMAC_SHA1 => Ok(Box::new(HmacSign { uri: algorithm::HMAC_SHA1, hash: HashType::Sha1 })),
        algorithm::HMAC_SHA224 => Ok(Box::new(HmacSign { uri: algorithm::HMAC_SHA224, hash: HashType::Sha224 })),
        algorithm::HMAC_SHA256 => Ok(Box::new(HmacSign { uri: algorithm::HMAC_SHA256, hash: HashType::Sha256 })),
        algorithm::HMAC_SHA384 => Ok(Box::new(HmacSign { uri: algorithm::HMAC_SHA384, hash: HashType::Sha384 })),
        algorithm::HMAC_SHA512 => Ok(Box::new(HmacSign { uri: algorithm::HMAC_SHA512, hash: HashType::Sha512 })),

        _ => Err(Error::UnsupportedAlgorithm(format!("signature algorithm: {uri}"))),
    }
}

#[derive(Debug, Clone, Copy)]
enum HashType { Sha1, Sha224, Sha256, Sha384, Sha512 }

// ── RSA PKCS#1 v1.5 ─────────────────────────────────────────────────

struct RsaPkcs1v15 { uri: &'static str, hash: HashType }

impl RsaPkcs1v15 {
    fn sign_with_key(&self, private_key: &rsa::RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
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
        }
    }

    fn verify_with_key(&self, public_key: &rsa::RsaPublicKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
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
        }
    }
}

impl SignatureAlgorithm for RsaPkcs1v15 {
    fn uri(&self) -> &'static str { self.uri }

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

struct RsaPss { uri: &'static str, hash: HashType }

impl SignatureAlgorithm for RsaPss {
    fn uri(&self) -> &'static str { self.uri }

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
        }
    }
}

// ── ECDSA P-256 ──────────────────────────────────────────────────────

struct EcdsaP256 { uri: &'static str }

/// Convert XML-DSig ECDSA r||s to a typed Signature for P-256.
pub fn xmldsig_to_p256(rs: &[u8]) -> Result<p256::ecdsa::Signature, Error> {
    if rs.len() != 64 {
        return Err(Error::Crypto(format!("P-256 signature must be 64 bytes, got {}", rs.len())));
    }
    let r = p256::FieldBytes::from_slice(&rs[..32]);
    let s = p256::FieldBytes::from_slice(&rs[32..]);
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

impl SignatureAlgorithm for EcdsaP256 {
    fn uri(&self) -> &'static str { self.uri }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        use signature::Signer;
        let SigningKey::EcP256(sk) = key else {
            return Err(Error::Key("P-256 signing key required".into()));
        };
        let sig: p256::ecdsa::Signature = sk.sign(data);
        Ok(p256_to_xmldsig(&sig))
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        use signature::Verifier;
        let vk = match key {
            SigningKey::EcP256(sk) => *sk.verifying_key(),
            SigningKey::EcP256Public(vk) => *vk,
            _ => return Err(Error::Key("P-256 key required".into())),
        };
        let sig = xmldsig_to_p256(sig_bytes)?;
        Ok(vk.verify(data, &sig).is_ok())
    }
}

// ── ECDSA P-384 ──────────────────────────────────────────────────────

struct EcdsaP384 { uri: &'static str }

/// Convert XML-DSig ECDSA r||s to a typed Signature for P-384.
pub fn xmldsig_to_p384(rs: &[u8]) -> Result<p384::ecdsa::Signature, Error> {
    if rs.len() != 96 {
        return Err(Error::Crypto(format!("P-384 signature must be 96 bytes, got {}", rs.len())));
    }
    let r = p384::FieldBytes::from_slice(&rs[..48]);
    let s = p384::FieldBytes::from_slice(&rs[48..]);
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

impl SignatureAlgorithm for EcdsaP384 {
    fn uri(&self) -> &'static str { self.uri }

    fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        use signature::Signer;
        let SigningKey::EcP384(sk) = key else {
            return Err(Error::Key("P-384 signing key required".into()));
        };
        let sig: p384::ecdsa::Signature = sk.sign(data);
        Ok(p384_to_xmldsig(&sig))
    }

    fn verify(&self, key: &SigningKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool, Error> {
        use signature::Verifier;
        let vk = match key {
            SigningKey::EcP384(sk) => *sk.verifying_key(),
            SigningKey::EcP384Public(vk) => *vk,
            _ => return Err(Error::Key("P-384 key required".into())),
        };
        let sig = xmldsig_to_p384(sig_bytes)?;
        Ok(vk.verify(data, &sig).is_ok())
    }
}

// ── HMAC ─────────────────────────────────────────────────────────────

struct HmacSign { uri: &'static str, hash: HashType }

impl SignatureAlgorithm for HmacSign {
    fn uri(&self) -> &'static str { self.uri }

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
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if b.len() < a.len() {
        // Truncated HMAC comparison
        return a[..b.len()].iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0;
    }
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
