#![forbid(unsafe_code)]

//! Key loading from various formats (PEM, DER, PKCS#8, PKCS#12, raw binary).

use crate::key::{Key, KeyData, KeyUsage};
use bergshamra_core::Error;

/// Load an RSA private key from PEM data.
pub fn load_rsa_private_pem(pem_data: &[u8]) -> Result<Key, Error> {
    use pkcs8::DecodePrivateKey;
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| Error::Key(format!("invalid PEM encoding: {e}")))?;

    // Try PKCS#8 first
    if let Ok(pk) = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str) {
        let public = pk.to_public_key();
        return Ok(Key::new(
            KeyData::Rsa { private: Some(pk), public },
            KeyUsage::Any,
        ));
    }

    // Try PKCS#1
    use pkcs1::DecodeRsaPrivateKey;
    let pk = rsa::RsaPrivateKey::from_pkcs1_pem(pem_str)
        .map_err(|e| Error::Key(format!("failed to parse RSA private key PEM: {e}")))?;
    let public = pk.to_public_key();
    Ok(Key::new(
        KeyData::Rsa { private: Some(pk), public },
        KeyUsage::Any,
    ))
}

/// Load an RSA public key from PEM data.
pub fn load_rsa_public_pem(pem_data: &[u8]) -> Result<Key, Error> {
    use pkcs8::DecodePublicKey;
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| Error::Key(format!("invalid PEM encoding: {e}")))?;

    // Try SPKI first
    if let Ok(pk) = rsa::RsaPublicKey::from_public_key_pem(pem_str) {
        return Ok(Key::new(
            KeyData::Rsa { private: None, public: pk },
            KeyUsage::Verify,
        ));
    }

    // Try PKCS#1
    use pkcs1::DecodeRsaPublicKey;
    let pk = rsa::RsaPublicKey::from_pkcs1_pem(pem_str)
        .map_err(|e| Error::Key(format!("failed to parse RSA public key PEM: {e}")))?;
    Ok(Key::new(
        KeyData::Rsa { private: None, public: pk },
        KeyUsage::Verify,
    ))
}

/// Load an EC P-256 private key from PEM data.
pub fn load_ec_p256_private_pem(pem_data: &[u8]) -> Result<Key, Error> {
    use pkcs8::DecodePrivateKey;
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| Error::Key(format!("invalid PEM encoding: {e}")))?;

    let sk = p256::ecdsa::SigningKey::from_pkcs8_pem(pem_str)
        .map_err(|e| Error::Key(format!("failed to parse EC P-256 private key: {e}")))?;
    let vk = *sk.verifying_key();
    Ok(Key::new(
        KeyData::EcP256 { private: Some(sk), public: vk },
        KeyUsage::Any,
    ))
}

/// Load an EC P-384 private key from PEM data.
pub fn load_ec_p384_private_pem(pem_data: &[u8]) -> Result<Key, Error> {
    use pkcs8::DecodePrivateKey;
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| Error::Key(format!("invalid PEM encoding: {e}")))?;

    let sk = p384::ecdsa::SigningKey::from_pkcs8_pem(pem_str)
        .map_err(|e| Error::Key(format!("failed to parse EC P-384 private key: {e}")))?;
    let vk = *sk.verifying_key();
    Ok(Key::new(
        KeyData::EcP384 { private: Some(sk), public: vk },
        KeyUsage::Any,
    ))
}

/// Load an EC P-521 private key from PEM data.
pub fn load_ec_p521_private_pem(pem_data: &[u8]) -> Result<Key, Error> {
    use pkcs8::DecodePrivateKey;
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| Error::Key(format!("invalid PEM encoding: {e}")))?;

    let secret = p521::SecretKey::from_pkcs8_pem(pem_str)
        .map_err(|e| Error::Key(format!("failed to parse EC P-521 private key: {e}")))?;
    let sk = p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(secret));
    let vk = p521::ecdsa::VerifyingKey::from(&sk);
    Ok(Key::new(
        KeyData::EcP521 { private: Some(sk), public: vk },
        KeyUsage::Any,
    ))
}

/// Load an HMAC key from raw binary data.
pub fn load_hmac_key(data: &[u8]) -> Key {
    Key::new(KeyData::Hmac(data.to_vec()), KeyUsage::Any)
}

/// Load an AES key from raw binary data.
pub fn load_aes_key(data: &[u8]) -> Result<Key, Error> {
    match data.len() {
        16 | 24 | 32 => Ok(Key::new(KeyData::Aes(data.to_vec()), KeyUsage::Any)),
        n => Err(Error::Key(format!("invalid AES key size: {n} (expected 16, 24, or 32)"))),
    }
}

/// Load a 3DES key from raw binary data.
pub fn load_des3_key(data: &[u8]) -> Result<Key, Error> {
    if data.len() != 24 {
        return Err(Error::Key(format!("invalid 3DES key size: {} (expected 24)", data.len())));
    }
    Ok(Key::new(KeyData::Des3(data.to_vec()), KeyUsage::Any))
}

/// Load a private key from PKCS#8 DER bytes (as extracted from PKCS#12 or other containers).
///
/// Tries RSA, then EC P-256, P-384, P-521 in order.
fn load_private_key_pkcs8_der(der: &[u8]) -> Result<Key, Error> {
    use pkcs8::DecodePrivateKey;

    // Try RSA
    if let Ok(pk) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
        let public = pk.to_public_key();
        return Ok(Key::new(
            KeyData::Rsa { private: Some(pk), public },
            KeyUsage::Any,
        ));
    }

    // Try EC P-256
    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
        let vk = *sk.verifying_key();
        return Ok(Key::new(
            KeyData::EcP256 { private: Some(sk), public: vk },
            KeyUsage::Any,
        ));
    }

    // Try EC P-384
    if let Ok(sk) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
        let vk = *sk.verifying_key();
        return Ok(Key::new(
            KeyData::EcP384 { private: Some(sk), public: vk },
            KeyUsage::Any,
        ));
    }

    // Try EC P-521
    if let Ok(secret) = p521::SecretKey::from_pkcs8_der(der) {
        let sk = p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(secret));
        let vk = p521::ecdsa::VerifyingKey::from(&sk);
        return Ok(Key::new(
            KeyData::EcP521 { private: Some(sk), public: vk },
            KeyUsage::Any,
        ));
    }

    // Try DSA
    {
        use pkcs8::der::Decode;
        if let Ok(pki) = pkcs8::PrivateKeyInfo::from_der(der) {
            if let Ok(sk) = dsa::SigningKey::try_from(pki) {
                let vk = sk.verifying_key().clone();
                return Ok(Key::new(
                    KeyData::Dsa { private: Some(sk), public: vk },
                    KeyUsage::Any,
                ));
            }
        }
    }

    // Try post-quantum (ML-DSA, SLH-DSA)
    if let Some(key) = try_load_pq_private_key(der) {
        return Ok(key);
    }

    Err(Error::Key("unable to parse PKCS#8 DER private key (tried RSA, P-256, P-384, P-521, DSA, ML-DSA, SLH-DSA)".into()))
}

/// Load keys from a PKCS#12 (.p12/.pfx) file.
///
/// Returns the first private key found, with any X.509 certificates attached
/// to the key's x509_chain.
pub fn load_pkcs12(data: &[u8], password: &str) -> Result<Key, Error> {
    let contents = bergshamra_pkcs12::parse_pkcs12(data, password)?;

    if contents.private_keys.is_empty() {
        return Err(Error::Key("PKCS#12 contains no private keys".into()));
    }

    let mut key = load_private_key_pkcs8_der(&contents.private_keys[0])?;
    key.x509_chain = contents.certificates;
    Ok(key)
}

/// Load a private key from encrypted PEM (PKCS#8 ENCRYPTED PRIVATE KEY).
///
/// Tries RSA, then EC P-256, P-384 in order.
fn load_encrypted_pem(pem_data: &[u8], password: &str) -> Result<Key, Error> {
    use pkcs8::DecodePrivateKey;
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| Error::Key(format!("invalid PEM encoding: {e}")))?;

    // Try RSA
    if let Ok(pk) = rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(pem_str, password) {
        let public = pk.to_public_key();
        return Ok(Key::new(
            KeyData::Rsa { private: Some(pk), public },
            KeyUsage::Any,
        ));
    }

    // Try EC P-256
    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_encrypted_pem(pem_str, password) {
        let vk = *sk.verifying_key();
        return Ok(Key::new(
            KeyData::EcP256 { private: Some(sk), public: vk },
            KeyUsage::Any,
        ));
    }

    // Try EC P-384
    if let Ok(sk) = p384::ecdsa::SigningKey::from_pkcs8_encrypted_pem(pem_str, password) {
        let vk = *sk.verifying_key();
        return Ok(Key::new(
            KeyData::EcP384 { private: Some(sk), public: vk },
            KeyUsage::Any,
        ));
    }

    // Try EC P-521
    if let Ok(secret) = p521::SecretKey::from_pkcs8_encrypted_pem(pem_str, password) {
        let sk = p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(secret));
        let vk = p521::ecdsa::VerifyingKey::from(&sk);
        return Ok(Key::new(
            KeyData::EcP521 { private: Some(sk), public: vk },
            KeyUsage::Any,
        ));
    }

    // Try generic decrypt via pem-rfc7468 + DER parse (catches DSA and others)
    {
        if let Ok((_label, der_bytes)) = pem_rfc7468::decode_vec(pem_data) {
            use pkcs8::der::Decode;
            if let Ok(enc_pki) = pkcs8::EncryptedPrivateKeyInfo::from_der(&der_bytes) {
                if let Ok(der_doc) = enc_pki.decrypt(password) {
                    if let Ok(key) = load_private_key_pkcs8_der(der_doc.as_bytes()) {
                        return Ok(key);
                    }
                }
            }
        }
    }

    Err(Error::Key("failed to decrypt encrypted PKCS#8 PEM (tried RSA, P-256, P-384, P-521, DSA, ML-DSA, SLH-DSA)".into()))
}

/// Auto-detect key format and load from PEM data.
///
/// Tries encrypted PKCS#8 (if password provided), then RSA private, RSA public,
/// EC P-256, EC P-384 in order.
pub fn load_pem_auto(pem_data: &[u8], password: Option<&str>) -> Result<Key, Error> {
    // Try encrypted PEM if password is provided and data looks encrypted
    if let Some(pwd) = password {
        const MARKER: &[u8] = b"ENCRYPTED PRIVATE KEY";
        if pem_data.windows(MARKER.len()).any(|w| w == MARKER) {
            return load_encrypted_pem(pem_data, pwd);
        }
    }

    // Try each unencrypted format
    if let Ok(key) = load_rsa_private_pem(pem_data) {
        return Ok(key);
    }
    if let Ok(key) = load_rsa_public_pem(pem_data) {
        return Ok(key);
    }
    // Try SPKI PEM (handles EC P-256/P-384/P-521 and DSA public keys)
    if let Ok(key) = load_spki_pem(pem_data) {
        return Ok(key);
    }
    if let Ok(key) = load_ec_p256_private_pem(pem_data) {
        return Ok(key);
    }
    if let Ok(key) = load_ec_p384_private_pem(pem_data) {
        return Ok(key);
    }
    if let Ok(key) = load_ec_p521_private_pem(pem_data) {
        return Ok(key);
    }
    // Try X.509 certificate PEM
    if let Ok(key) = load_x509_cert_pem(pem_data) {
        return Ok(key);
    }
    Err(Error::Key("unable to auto-detect key format from PEM data".into()))
}

/// Load a public key from a PEM-encoded SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`).
pub fn load_spki_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let (_label, der_bytes) = pem_rfc7468::decode_vec(pem_data)
        .map_err(|e| Error::Key(format!("failed to decode SPKI PEM: {e}")))?;
    load_spki_der(&der_bytes)
}

/// Load a public key from a PEM-encoded X.509 certificate.
pub fn load_x509_cert_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| Error::Key(format!("invalid PEM encoding: {e}")))?;

    // Trim trailing whitespace — some PEM files have extra newlines
    let trimmed = pem_str.trim();

    // Extract DER from PEM
    let (label, der_bytes) = pem_rfc7468::decode_vec(trimmed.as_bytes())
        .map_err(|e| Error::Key(format!("failed to decode certificate PEM: {e}")))?;

    if label != "CERTIFICATE" {
        return Err(Error::Key(format!("expected CERTIFICATE PEM label, got: {label}")));
    }

    load_x509_cert_der(&der_bytes)
}

/// Load a key from a file, auto-detecting format.
///
/// Optionally provide a password for PKCS#12 or encrypted PEM files.
pub fn load_key_file(path: &std::path::Path) -> Result<Key, Error> {
    load_key_file_with_password(path, None)
}

/// Load a key from a file with an optional password for encrypted containers.
pub fn load_key_file_with_password(
    path: &std::path::Path,
    password: Option<&str>,
) -> Result<Key, Error> {
    let data = std::fs::read(path)?;

    // Check extension for PKCS#12
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext.eq_ignore_ascii_case("p12") || ext.eq_ignore_ascii_case("pfx") {
        return load_pkcs12(&data, password.unwrap_or(""));
    }

    // Check extension for X.509 certificate files
    if ext.eq_ignore_ascii_case("crt") || ext.eq_ignore_ascii_case("cer") {
        // Try PEM first, then DER
        if data.starts_with(b"-----BEGIN") {
            return load_x509_cert_pem(&data);
        }
        return load_x509_cert_der(&data);
    }

    // Check if it's PEM
    if data.starts_with(b"-----BEGIN") {
        return load_pem_auto(&data, password);
    }

    // Try DER formats
    if let Ok(key) = load_private_key_pkcs8_der(&data) {
        return Ok(key);
    }

    // Try RSA PKCS#1 DER
    use pkcs1::DecodeRsaPrivateKey;
    if let Ok(pk) = rsa::RsaPrivateKey::from_pkcs1_der(&data) {
        let public = pk.to_public_key();
        return Ok(Key::new(
            KeyData::Rsa { private: Some(pk), public },
            KeyUsage::Any,
        ));
    }

    // Try SPKI DER (public key)
    if let Ok(key) = load_spki_der(&data) {
        return Ok(key);
    }

    // Try X.509 certificate DER (extract public key)
    if let Ok(key) = load_x509_cert_der(&data) {
        return Ok(key);
    }

    // Raw binary (could be HMAC or AES key)
    Err(Error::Key(format!(
        "unable to auto-detect key format from file: {}",
        path.display()
    )))
}

/// Load a public key from a DER-encoded X.509 certificate.
pub fn load_x509_cert_der(data: &[u8]) -> Result<Key, Error> {
    use x509_cert::Certificate;
    use der::{Decode, Encode};

    let cert = Certificate::from_der(data)
        .map_err(|e| Error::Key(format!("failed to parse X.509 certificate: {e}")))?;

    // Extract SubjectPublicKeyInfo and try to parse it
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki.to_der()
        .map_err(|e| Error::Key(format!("failed to encode SPKI: {e}")))?;

    // Try RSA
    use spki::DecodePublicKey;
    if let Ok(pk) = rsa::RsaPublicKey::from_public_key_der(&spki_der) {
        let mut key = Key::new(
            KeyData::Rsa { private: None, public: pk },
            KeyUsage::Verify,
        );
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    // Try EC P-256
    if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der) {
        let mut key = Key::new(
            KeyData::EcP256 { private: None, public: vk },
            KeyUsage::Verify,
        );
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    // Try EC P-384
    if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(&spki_der) {
        let mut key = Key::new(
            KeyData::EcP384 { private: None, public: vk },
            KeyUsage::Verify,
        );
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    // Try EC P-521
    if let Ok(pk) = p521::PublicKey::from_public_key_der(&spki_der) {
        let vk = p521::ecdsa::VerifyingKey::from(
            ecdsa::VerifyingKey::from(pk),
        );
        let mut key = Key::new(
            KeyData::EcP521 { private: None, public: vk },
            KeyUsage::Verify,
        );
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    // Try DSA
    {
        use pkcs8::der::Decode;
        if let Ok(spki_ref) = spki::SubjectPublicKeyInfoRef::from_der(&spki_der) {
            if let Ok(vk) = dsa::VerifyingKey::try_from(spki_ref) {
                let mut key = Key::new(
                    KeyData::Dsa { private: None, public: vk },
                    KeyUsage::Verify,
                );
                key.x509_chain = vec![data.to_vec()];
                return Ok(key);
            }
        }
    }

    // Try post-quantum (ML-DSA, SLH-DSA)
    if let Some(mut key) = try_load_pq_public_key(&spki_der) {
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    Err(Error::Key("unsupported public key algorithm in X.509 certificate".into()))
}

/// Load a key from raw SubjectPublicKeyInfo DER bytes.
pub fn load_spki_der(spki_der: &[u8]) -> Result<Key, Error> {
    use spki::DecodePublicKey;

    // Try RSA
    if let Ok(pk) = rsa::RsaPublicKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::Rsa { private: None, public: pk },
            KeyUsage::Verify,
        ));
    }

    // Try EC P-256
    if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::EcP256 { private: None, public: vk },
            KeyUsage::Verify,
        ));
    }

    // Try EC P-384
    if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::EcP384 { private: None, public: vk },
            KeyUsage::Verify,
        ));
    }

    // Try EC P-521
    if let Ok(pk) = p521::PublicKey::from_public_key_der(spki_der) {
        let vk = p521::ecdsa::VerifyingKey::from(ecdsa::VerifyingKey::from(pk));
        return Ok(Key::new(
            KeyData::EcP521 { private: None, public: vk },
            KeyUsage::Verify,
        ));
    }

    // Try DSA
    {
        use pkcs8::der::Decode;
        if let Ok(spki_ref) = spki::SubjectPublicKeyInfoRef::from_der(spki_der) {
            if let Ok(vk) = dsa::VerifyingKey::try_from(spki_ref) {
                return Ok(Key::new(
                    KeyData::Dsa { private: None, public: vk },
                    KeyUsage::Verify,
                ));
            }
        }
    }

    // Try post-quantum (ML-DSA, SLH-DSA)
    if let Some(key) = try_load_pq_public_key(spki_der) {
        return Ok(key);
    }

    Err(Error::Key("unsupported public key algorithm in SPKI DER".into()))
}

// ── Post-quantum key loading helpers ─────────────────────────────────

/// Try to load a post-quantum private key from PKCS#8 DER bytes.
///
/// Handles both the RustCrypto format (seed in context-specific tag) and the
/// OpenSSL format (seed in `SEQUENCE { OCTET STRING(seed), ... }`).
fn try_load_pq_private_key(der: &[u8]) -> Option<Key> {
    use bergshamra_crypto::sign::PqAlgorithm;
    use ml_dsa::signature::Keypair;
    use pkcs8_pq::DecodePrivateKey;
    use pkcs8_pq::spki::EncodePublicKey;

    // First try the standard from_pkcs8_der (works if key is in RustCrypto format)
    macro_rules! try_standard {
        (ml $paramset:ty, $algo:expr) => {
            if let Ok(sk) = ml_dsa::SigningKey::<$paramset>::from_pkcs8_der(der) {
                let vk = sk.verifying_key();
                if let Ok(pub_doc) = vk.to_public_key_der() {
                    return Some(Key::new(
                        KeyData::PostQuantum {
                            algorithm: $algo,
                            private_der: Some(der.to_vec()),
                            public_der: pub_doc.to_vec(),
                        },
                        KeyUsage::Any,
                    ));
                }
            }
        };
        (slh $paramset:ty, $algo:expr) => {
            if let Ok(sk) = slh_dsa::SigningKey::<$paramset>::from_pkcs8_der(der) {
                let vk = sk.verifying_key();
                if let Ok(pub_doc) = vk.to_public_key_der() {
                    return Some(Key::new(
                        KeyData::PostQuantum {
                            algorithm: $algo,
                            private_der: Some(der.to_vec()),
                            public_der: pub_doc.to_vec(),
                        },
                        KeyUsage::Any,
                    ));
                }
            }
        };
    }

    try_standard!(ml ml_dsa::MlDsa44, PqAlgorithm::MlDsa44);
    try_standard!(ml ml_dsa::MlDsa65, PqAlgorithm::MlDsa65);
    try_standard!(ml ml_dsa::MlDsa87, PqAlgorithm::MlDsa87);
    try_standard!(slh slh_dsa::Sha2_128f, PqAlgorithm::SlhDsaSha2_128f);
    try_standard!(slh slh_dsa::Sha2_128s, PqAlgorithm::SlhDsaSha2_128s);
    try_standard!(slh slh_dsa::Sha2_192f, PqAlgorithm::SlhDsaSha2_192f);
    try_standard!(slh slh_dsa::Sha2_192s, PqAlgorithm::SlhDsaSha2_192s);
    try_standard!(slh slh_dsa::Sha2_256f, PqAlgorithm::SlhDsaSha2_256f);
    try_standard!(slh slh_dsa::Sha2_256s, PqAlgorithm::SlhDsaSha2_256s);

    // Standard parsing failed. Try OpenSSL format where the private key content
    // is wrapped in SEQUENCE { OCTET STRING(seed/key), [OCTET STRING(expanded)] }.
    use pkcs8_pq::der::Decode;
    let pki = pkcs8_pq::PrivateKeyInfoRef::from_der(der).ok()?;
    let oid = pki.algorithm.oid;
    let pk_bytes = pki.private_key.as_bytes();

    // Extract the first OCTET STRING from SEQUENCE { OCTET STRING, ... }
    let inner_bytes = extract_first_octet_string(pk_bytes)?;

    // ML-DSA: seed is always 32 bytes
    use const_oid_pq::db::fips204;
    use const_oid_pq::db::fips205;

    macro_rules! try_ml_dsa_from_seed {
        ($oid_const:expr, $paramset:ty, $algo:expr) => {
            if oid == $oid_const {
                if inner_bytes.len() == 32 {
                    let seed = ml_dsa::Seed::from_slice(&inner_bytes);
                    let sk = ml_dsa::SigningKey::<$paramset>::from_seed(seed);
                    let vk = sk.verifying_key();
                    if let Ok(pub_doc) = vk.to_public_key_der() {
                        // Store just the 32-byte seed — sign.rs will use from_seed()
                        return Some(Key::new(
                            KeyData::PostQuantum {
                                algorithm: $algo,
                                private_der: Some(inner_bytes.to_vec()),
                                public_der: pub_doc.to_vec(),
                            },
                            KeyUsage::Any,
                        ));
                    }
                }
                return None;
            }
        };
    }

    macro_rules! try_slh_dsa_from_raw {
        ($oid_const:expr, $paramset:ty, $algo:expr) => {
            if oid == $oid_const {
                if let Ok(sk) = slh_dsa::SigningKey::<$paramset>::try_from(inner_bytes) {
                    let vk = sk.verifying_key();
                    if let Ok(pub_doc) = vk.to_public_key_der() {
                        // Store just the raw key bytes — sign.rs will use try_from()
                        return Some(Key::new(
                            KeyData::PostQuantum {
                                algorithm: $algo,
                                private_der: Some(inner_bytes.to_vec()),
                                public_der: pub_doc.to_vec(),
                            },
                            KeyUsage::Any,
                        ));
                    }
                }
                return None;
            }
        };
    }

    try_ml_dsa_from_seed!(fips204::ID_ML_DSA_44, ml_dsa::MlDsa44, PqAlgorithm::MlDsa44);
    try_ml_dsa_from_seed!(fips204::ID_ML_DSA_65, ml_dsa::MlDsa65, PqAlgorithm::MlDsa65);
    try_ml_dsa_from_seed!(fips204::ID_ML_DSA_87, ml_dsa::MlDsa87, PqAlgorithm::MlDsa87);

    try_slh_dsa_from_raw!(fips205::ID_SLH_DSA_SHA_2_128_F, slh_dsa::Sha2_128f, PqAlgorithm::SlhDsaSha2_128f);
    try_slh_dsa_from_raw!(fips205::ID_SLH_DSA_SHA_2_128_S, slh_dsa::Sha2_128s, PqAlgorithm::SlhDsaSha2_128s);
    try_slh_dsa_from_raw!(fips205::ID_SLH_DSA_SHA_2_192_F, slh_dsa::Sha2_192f, PqAlgorithm::SlhDsaSha2_192f);
    try_slh_dsa_from_raw!(fips205::ID_SLH_DSA_SHA_2_192_S, slh_dsa::Sha2_192s, PqAlgorithm::SlhDsaSha2_192s);
    try_slh_dsa_from_raw!(fips205::ID_SLH_DSA_SHA_2_256_F, slh_dsa::Sha2_256f, PqAlgorithm::SlhDsaSha2_256f);
    try_slh_dsa_from_raw!(fips205::ID_SLH_DSA_SHA_2_256_S, slh_dsa::Sha2_256s, PqAlgorithm::SlhDsaSha2_256s);

    None
}

/// Extract the first OCTET STRING from an ASN.1 SEQUENCE.
///
/// Handles OpenSSL-style PQ private key encoding:
/// `SEQUENCE { OCTET STRING(key_data), ... }`
fn extract_first_octet_string(data: &[u8]) -> Option<&[u8]> {
    // Must start with SEQUENCE tag (0x30)
    if data.first() != Some(&0x30) {
        return None;
    }
    let (_, seq_content) = parse_asn1_length(&data[1..])?;
    // First element should be OCTET STRING (0x04)
    if seq_content.first() != Some(&0x04) {
        return None;
    }
    let (octet_len, octet_content) = parse_asn1_length(&seq_content[1..])?;
    Some(&octet_content[..octet_len])
}

/// Parse an ASN.1 length and return (length, rest_of_data).
fn parse_asn1_length(data: &[u8]) -> Option<(usize, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, &data[1..]))
    } else if first == 0x81 {
        if data.len() < 2 { return None; }
        Some((data[1] as usize, &data[2..]))
    } else if first == 0x82 {
        if data.len() < 3 { return None; }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Some((len, &data[3..]))
    } else if first == 0x83 {
        if data.len() < 4 { return None; }
        let len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
        Some((len, &data[4..]))
    } else {
        None
    }
}

/// Try to load a post-quantum public key from SPKI DER bytes.
fn try_load_pq_public_key(spki_der: &[u8]) -> Option<Key> {
    use bergshamra_crypto::sign::PqAlgorithm;
    use pkcs8_pq::spki::DecodePublicKey;

    macro_rules! try_ml_dsa {
        ($paramset:ty, $algo:expr) => {
            if ml_dsa::VerifyingKey::<$paramset>::from_public_key_der(spki_der).is_ok() {
                return Some(Key::new(
                    KeyData::PostQuantum {
                        algorithm: $algo,
                        private_der: None,
                        public_der: spki_der.to_vec(),
                    },
                    KeyUsage::Verify,
                ));
            }
        };
    }

    macro_rules! try_slh_dsa {
        ($paramset:ty, $algo:expr) => {
            if slh_dsa::VerifyingKey::<$paramset>::from_public_key_der(spki_der).is_ok() {
                return Some(Key::new(
                    KeyData::PostQuantum {
                        algorithm: $algo,
                        private_der: None,
                        public_der: spki_der.to_vec(),
                    },
                    KeyUsage::Verify,
                ));
            }
        };
    }

    try_ml_dsa!(ml_dsa::MlDsa44, PqAlgorithm::MlDsa44);
    try_ml_dsa!(ml_dsa::MlDsa65, PqAlgorithm::MlDsa65);
    try_ml_dsa!(ml_dsa::MlDsa87, PqAlgorithm::MlDsa87);

    try_slh_dsa!(slh_dsa::Sha2_128f, PqAlgorithm::SlhDsaSha2_128f);
    try_slh_dsa!(slh_dsa::Sha2_128s, PqAlgorithm::SlhDsaSha2_128s);
    try_slh_dsa!(slh_dsa::Sha2_192f, PqAlgorithm::SlhDsaSha2_192f);
    try_slh_dsa!(slh_dsa::Sha2_192s, PqAlgorithm::SlhDsaSha2_192s);
    try_slh_dsa!(slh_dsa::Sha2_256f, PqAlgorithm::SlhDsaSha2_256f);
    try_slh_dsa!(slh_dsa::Sha2_256s, PqAlgorithm::SlhDsaSha2_256s);

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_encrypted_pem_rsa() {
        let pem_path = std::path::Path::new("../../test-data/keys/cakey.pem");
        if !pem_path.exists() {
            eprintln!("skipping test: {pem_path:?} not found");
            return;
        }
        let key = load_key_file_with_password(pem_path, Some("secret123"))
            .expect("load encrypted PEM");
        assert!(matches!(key.data, KeyData::Rsa { private: Some(_), .. }));
    }

    #[test]
    fn test_load_encrypted_pem_wrong_password() {
        let pem_path = std::path::Path::new("../../test-data/keys/cakey.pem");
        if !pem_path.exists() {
            eprintln!("skipping test: {pem_path:?} not found");
            return;
        }
        let result = load_key_file_with_password(pem_path, Some("wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_encrypted_pem_no_password() {
        let pem_path = std::path::Path::new("../../test-data/keys/cakey.pem");
        if !pem_path.exists() {
            eprintln!("skipping test: {pem_path:?} not found");
            return;
        }
        let result = load_key_file_with_password(pem_path, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_pkcs12_rsa() {
        let p12_path = std::path::Path::new("../../test-data/keys/rsa/rsa-2048-key.p12");
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let key = load_pkcs12(&data, "secret123").expect("load_pkcs12");
        assert!(matches!(key.data, KeyData::Rsa { .. }));
        assert!(!key.x509_chain.is_empty());
    }

    #[test]
    fn test_load_pkcs12_mldsa44() {
        let p12_path = std::path::Path::new("../../test-data/keys/ml-dsa/ml-dsa-44-key.p12");
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let key = load_pkcs12(&data, "secret123").expect("load_pkcs12 should succeed");
        assert!(matches!(key.data, KeyData::PostQuantum { .. }));
    }
}
