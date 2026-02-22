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
            KeyData::Rsa {
                private: Some(pk),
                public,
            },
            KeyUsage::Any,
        ));
    }

    // Try PKCS#1
    use pkcs1::DecodeRsaPrivateKey;
    let pk = rsa::RsaPrivateKey::from_pkcs1_pem(pem_str)
        .map_err(|e| Error::Key(format!("failed to parse RSA private key PEM: {e}")))?;
    let public = pk.to_public_key();
    Ok(Key::new(
        KeyData::Rsa {
            private: Some(pk),
            public,
        },
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
            KeyData::Rsa {
                private: None,
                public: pk,
            },
            KeyUsage::Verify,
        ));
    }

    // Try PKCS#1
    use pkcs1::DecodeRsaPublicKey;
    let pk = rsa::RsaPublicKey::from_pkcs1_pem(pem_str)
        .map_err(|e| Error::Key(format!("failed to parse RSA public key PEM: {e}")))?;
    Ok(Key::new(
        KeyData::Rsa {
            private: None,
            public: pk,
        },
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
        KeyData::EcP256 {
            private: Some(sk),
            public: vk,
        },
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
        KeyData::EcP384 {
            private: Some(sk),
            public: vk,
        },
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
        KeyData::EcP521 {
            private: Some(sk),
            public: vk,
        },
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
        n => Err(Error::Key(format!(
            "invalid AES key size: {n} (expected 16, 24, or 32)"
        ))),
    }
}

/// Load a 3DES key from raw binary data.
pub fn load_des3_key(data: &[u8]) -> Result<Key, Error> {
    if data.len() != 24 {
        return Err(Error::Key(format!(
            "invalid 3DES key size: {} (expected 24)",
            data.len()
        )));
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
            KeyData::Rsa {
                private: Some(pk),
                public,
            },
            KeyUsage::Any,
        ));
    }

    // Try EC P-256
    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
        let vk = *sk.verifying_key();
        return Ok(Key::new(
            KeyData::EcP256 {
                private: Some(sk),
                public: vk,
            },
            KeyUsage::Any,
        ));
    }

    // Try EC P-384
    if let Ok(sk) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
        let vk = *sk.verifying_key();
        return Ok(Key::new(
            KeyData::EcP384 {
                private: Some(sk),
                public: vk,
            },
            KeyUsage::Any,
        ));
    }

    // Try EC P-521
    if let Ok(secret) = p521::SecretKey::from_pkcs8_der(der) {
        let sk = p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(secret));
        let vk = p521::ecdsa::VerifyingKey::from(&sk);
        return Ok(Key::new(
            KeyData::EcP521 {
                private: Some(sk),
                public: vk,
            },
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
                    KeyData::Dsa {
                        private: Some(sk),
                        public: vk,
                    },
                    KeyUsage::Any,
                ));
            }
        }
    }

    // Try DH (X9.42 DH, OID 1.2.840.10046.2.1)
    if let Ok(key) = load_dh_private_pkcs8_der(der) {
        return Ok(key);
    }

    // Try Ed25519
    if let Ok(key) = load_ed25519_private_pkcs8_der(der) {
        return Ok(key);
    }

    // Try post-quantum (ML-DSA, SLH-DSA)
    if let Some(key) = try_load_pq_private_key(der) {
        return Ok(key);
    }

    Err(Error::Key("unable to parse PKCS#8 DER private key (tried RSA, P-256, P-384, P-521, DSA, DH, Ed25519, ML-DSA, SLH-DSA)".into()))
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
            KeyData::Rsa {
                private: Some(pk),
                public,
            },
            KeyUsage::Any,
        ));
    }

    // Try EC P-256
    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_encrypted_pem(pem_str, password) {
        let vk = *sk.verifying_key();
        return Ok(Key::new(
            KeyData::EcP256 {
                private: Some(sk),
                public: vk,
            },
            KeyUsage::Any,
        ));
    }

    // Try EC P-384
    if let Ok(sk) = p384::ecdsa::SigningKey::from_pkcs8_encrypted_pem(pem_str, password) {
        let vk = *sk.verifying_key();
        return Ok(Key::new(
            KeyData::EcP384 {
                private: Some(sk),
                public: vk,
            },
            KeyUsage::Any,
        ));
    }

    // Try EC P-521
    if let Ok(secret) = p521::SecretKey::from_pkcs8_encrypted_pem(pem_str, password) {
        let sk = p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(secret));
        let vk = p521::ecdsa::VerifyingKey::from(&sk);
        return Ok(Key::new(
            KeyData::EcP521 {
                private: Some(sk),
                public: vk,
            },
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
    // Try generic PKCS#8 PEM (DH, DSA, etc. that aren't caught above)
    if let Ok(key) = load_generic_pkcs8_pem(pem_data) {
        return Ok(key);
    }
    Err(Error::Key(
        "unable to auto-detect key format from PEM data".into(),
    ))
}

/// Load a public key from a PEM-encoded SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`).
pub fn load_spki_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let (_label, der_bytes) = pem_rfc7468::decode_vec(pem_data)
        .map_err(|e| Error::Key(format!("failed to decode SPKI PEM: {e}")))?;
    load_spki_der(&der_bytes)
}

/// Load a private key from a generic PKCS#8 PEM (fallback for DH, DSA, etc.).
fn load_generic_pkcs8_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let (label, der_bytes) = pem_rfc7468::decode_vec(pem_data)
        .map_err(|e| Error::Key(format!("failed to decode PEM: {e}")))?;
    match label {
        "PRIVATE KEY" => load_private_key_pkcs8_der(&der_bytes),
        "PUBLIC KEY" => load_spki_der(&der_bytes),
        _ => Err(Error::Key(format!("unsupported PEM label: {label}"))),
    }
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
        return Err(Error::Key(format!(
            "expected CERTIFICATE PEM label, got: {label}"
        )));
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
            KeyData::Rsa {
                private: Some(pk),
                public,
            },
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
    use der::{Decode, Encode};
    use x509_cert::Certificate;

    let cert = Certificate::from_der(data)
        .map_err(|e| Error::Key(format!("failed to parse X.509 certificate: {e}")))?;

    // Extract SubjectPublicKeyInfo and try to parse it
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki
        .to_der()
        .map_err(|e| Error::Key(format!("failed to encode SPKI: {e}")))?;

    // Try RSA
    use spki::DecodePublicKey;
    if let Ok(pk) = rsa::RsaPublicKey::from_public_key_der(&spki_der) {
        let mut key = Key::new(
            KeyData::Rsa {
                private: None,
                public: pk,
            },
            KeyUsage::Verify,
        );
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    // Try EC P-256
    if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der) {
        let mut key = Key::new(
            KeyData::EcP256 {
                private: None,
                public: vk,
            },
            KeyUsage::Verify,
        );
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    // Try EC P-384
    if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(&spki_der) {
        let mut key = Key::new(
            KeyData::EcP384 {
                private: None,
                public: vk,
            },
            KeyUsage::Verify,
        );
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    // Try EC P-521
    if let Ok(pk) = p521::PublicKey::from_public_key_der(&spki_der) {
        let vk = p521::ecdsa::VerifyingKey::from(ecdsa::VerifyingKey::from(pk));
        let mut key = Key::new(
            KeyData::EcP521 {
                private: None,
                public: vk,
            },
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
                    KeyData::Dsa {
                        private: None,
                        public: vk,
                    },
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

    // Try DH (X9.42 DH)
    if let Ok(mut key) = load_dh_public_spki_der(&spki_der) {
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    // Try Ed25519
    if let Ok(mut key) = load_ed25519_public_spki_der(&spki_der) {
        key.x509_chain = vec![data.to_vec()];
        return Ok(key);
    }

    Err(Error::Key(
        "unsupported public key algorithm in X.509 certificate".into(),
    ))
}

/// Load a key from raw SubjectPublicKeyInfo DER bytes.
pub fn load_spki_der(spki_der: &[u8]) -> Result<Key, Error> {
    use spki::DecodePublicKey;

    // Try RSA
    if let Ok(pk) = rsa::RsaPublicKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::Rsa {
                private: None,
                public: pk,
            },
            KeyUsage::Verify,
        ));
    }

    // Try EC P-256
    if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::EcP256 {
                private: None,
                public: vk,
            },
            KeyUsage::Verify,
        ));
    }

    // Try EC P-384
    if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::EcP384 {
                private: None,
                public: vk,
            },
            KeyUsage::Verify,
        ));
    }

    // Try EC P-521
    if let Ok(pk) = p521::PublicKey::from_public_key_der(spki_der) {
        let vk = p521::ecdsa::VerifyingKey::from(ecdsa::VerifyingKey::from(pk));
        return Ok(Key::new(
            KeyData::EcP521 {
                private: None,
                public: vk,
            },
            KeyUsage::Verify,
        ));
    }

    // Try DSA
    {
        use pkcs8::der::Decode;
        if let Ok(spki_ref) = spki::SubjectPublicKeyInfoRef::from_der(spki_der) {
            if let Ok(vk) = dsa::VerifyingKey::try_from(spki_ref) {
                return Ok(Key::new(
                    KeyData::Dsa {
                        private: None,
                        public: vk,
                    },
                    KeyUsage::Verify,
                ));
            }
        }
    }

    // Try DH (X9.42 DH, OID 1.2.840.10046.2.1)
    if let Ok(key) = load_dh_public_spki_der(spki_der) {
        return Ok(key);
    }

    // Try Ed25519
    if let Ok(key) = load_ed25519_public_spki_der(spki_der) {
        return Ok(key);
    }

    // Try post-quantum (ML-DSA, SLH-DSA)
    if let Some(key) = try_load_pq_public_key(spki_der) {
        return Ok(key);
    }

    Err(Error::Key(
        "unsupported public key algorithm in SPKI DER".into(),
    ))
}

// ── DH key loading helpers ───────────────────────────────────────────

/// Load an Ed25519 private key from PKCS#8 DER bytes.
fn load_ed25519_private_pkcs8_der(der: &[u8]) -> Result<Key, Error> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let sk = ed25519_dalek::SigningKey::from_pkcs8_der(der)
        .map_err(|e| Error::Key(format!("failed to parse Ed25519 private key: {e}")))?;
    let vk = sk.verifying_key();
    Ok(Key::new(
        KeyData::Ed25519 {
            private: Some(sk),
            public: vk,
        },
        KeyUsage::Any,
    ))
}

/// Load an Ed25519 public key from SPKI DER bytes.
fn load_ed25519_public_spki_der(spki_der: &[u8]) -> Result<Key, Error> {
    use ed25519_dalek::pkcs8::spki::DecodePublicKey;
    let vk = ed25519_dalek::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| Error::Key(format!("failed to parse Ed25519 public key: {e}")))?;
    Ok(Key::new(
        KeyData::Ed25519 {
            private: None,
            public: vk,
        },
        KeyUsage::Verify,
    ))
}

/// Load an X25519 key pair from raw 32-byte private key bytes.
///
/// Derives the public key from the private key.
pub fn load_x25519_private_raw(private_bytes: &[u8]) -> Result<Key, Error> {
    if private_bytes.len() != 32 {
        return Err(Error::Key(format!(
            "X25519 private key must be 32 bytes, got {}",
            private_bytes.len()
        )));
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(private_bytes);
    let static_secret = x25519_dalek::StaticSecret::from(secret);
    let public = x25519_dalek::PublicKey::from(&static_secret);
    Ok(Key::new(
        KeyData::X25519 {
            private: Some(secret),
            public: *public.as_bytes(),
        },
        KeyUsage::Any,
    ))
}

/// Load an X25519 public key from raw 32-byte public key bytes.
pub fn load_x25519_public_raw(public_bytes: &[u8]) -> Result<Key, Error> {
    if public_bytes.len() != 32 {
        return Err(Error::Key(format!(
            "X25519 public key must be 32 bytes, got {}",
            public_bytes.len()
        )));
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(public_bytes);
    Ok(Key::new(
        KeyData::X25519 {
            private: None,
            public,
        },
        KeyUsage::Encrypt,
    ))
}

/// OID for X9.42 DH (dhpublicnumber): 1.2.840.10046.2.1
const OID_DH_PUBLIC_NUMBER: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01];

/// Load a DH private key from PKCS#8 DER bytes.
///
/// Structure: SEQUENCE {
///   version INTEGER,
///   algorithm SEQUENCE { oid OID, params SEQUENCE { p INTEGER, g INTEGER, q INTEGER } },
///   privateKey OCTET STRING containing INTEGER
/// }
fn load_dh_private_pkcs8_der(der: &[u8]) -> Result<Key, Error> {
    use num_bigint_dig::BigUint;

    // Check that this is a DH key by looking for the OID
    if !der
        .windows(OID_DH_PUBLIC_NUMBER.len())
        .any(|w| w == OID_DH_PUBLIC_NUMBER)
    {
        return Err(Error::Key("not a DH key (OID mismatch)".into()));
    }

    // Parse the PKCS#8 structure manually using our ASN.1 helpers
    // Parse outer SEQUENCE — content is the first return value
    let (outer_content, _) = parse_asn1_tl(der, 0x30)?;

    // Skip version INTEGER
    let (_, rest) = skip_asn1_element(outer_content)?;

    // Parse algorithm SEQUENCE
    let (algo_content, rest) = parse_asn1_tl(rest, 0x30)?;

    // Skip OID in algorithm
    let (_, algo_rest) = skip_asn1_element(algo_content)?;

    // Parse DH parameters SEQUENCE { p, g, q }
    let (params_content, _) = parse_asn1_tl(algo_rest, 0x30)?;
    let (p_bytes, params_rest) = parse_asn1_integer(params_content)?;
    let (g_bytes, params_rest) = parse_asn1_integer(params_rest)?;
    let q_bytes = if !params_rest.is_empty() {
        let (q, _) = parse_asn1_integer(params_rest)?;
        Some(q)
    } else {
        None
    };

    // Parse privateKey OCTET STRING containing INTEGER
    let (pk_octet, _) = parse_asn1_tl(rest, 0x04)?;
    let (x_bytes, _) = parse_asn1_integer(pk_octet)?;

    validate_dh_params(&p_bytes, &g_bytes, q_bytes.as_deref())?;

    // Compute public key: y = g^x mod p
    let p_uint = BigUint::from_bytes_be(&p_bytes);
    let g_uint = BigUint::from_bytes_be(&g_bytes);
    let x_uint = BigUint::from_bytes_be(&x_bytes);
    let y_uint = g_uint.modpow(&x_uint, &p_uint);
    let public_key = y_uint.to_bytes_be();

    Ok(Key::new(
        KeyData::Dh {
            p: p_bytes,
            g: g_bytes,
            q: q_bytes,
            private_key: Some(x_bytes),
            public_key,
        },
        KeyUsage::Any,
    ))
}

/// Load a DH public key from SPKI DER bytes.
///
/// Structure: SEQUENCE {
///   algorithm SEQUENCE { oid OID, params SEQUENCE { p INTEGER, g INTEGER, q INTEGER } },
///   subjectPublicKey BIT STRING containing INTEGER
/// }
fn load_dh_public_spki_der(spki_der: &[u8]) -> Result<Key, Error> {
    // Check for DH OID
    if !spki_der
        .windows(OID_DH_PUBLIC_NUMBER.len())
        .any(|w| w == OID_DH_PUBLIC_NUMBER)
    {
        return Err(Error::Key("not a DH key (OID mismatch)".into()));
    }

    // Parse outer SEQUENCE — content is the first return value
    let (outer_content, _) = parse_asn1_tl(spki_der, 0x30)?;

    // Parse algorithm SEQUENCE
    let (algo_content, rest) = parse_asn1_tl(outer_content, 0x30)?;

    // Skip OID
    let (_, algo_rest) = skip_asn1_element(algo_content)?;

    // Parse DH parameters
    let (params_content, _) = parse_asn1_tl(algo_rest, 0x30)?;
    let (p_bytes, params_rest) = parse_asn1_integer(params_content)?;
    let (g_bytes, params_rest) = parse_asn1_integer(params_rest)?;
    let q_bytes = if !params_rest.is_empty() {
        let (q, _) = parse_asn1_integer(params_rest)?;
        Some(q)
    } else {
        None
    };

    // Parse subjectPublicKey BIT STRING containing INTEGER
    let (bitstring_content, _) = parse_asn1_tl(rest, 0x03)?;
    // Skip the unused-bits byte (always 0 for DH)
    if bitstring_content.is_empty() {
        return Err(Error::Key("empty BIT STRING in DH public key".into()));
    }
    let inner = &bitstring_content[1..]; // skip unused bits byte
    let (y_bytes, _) = parse_asn1_integer(inner)?;

    validate_dh_params(&p_bytes, &g_bytes, q_bytes.as_deref())?;

    Ok(Key::new(
        KeyData::Dh {
            p: p_bytes,
            g: g_bytes,
            q: q_bytes,
            private_key: None,
            public_key: y_bytes,
        },
        KeyUsage::Any,
    ))
}

fn validate_dh_params(p: &[u8], g: &[u8], q: Option<&[u8]>) -> Result<(), Error> {
    use num_bigint_dig::prime::probably_prime;
    use num_bigint_dig::BigUint;
    use num_traits::{One, Zero};

    let p_uint = BigUint::from_bytes_be(p);
    // W3C XML Encryption 1.1 §5.6.1: "The size of p MUST be at least 512 bits"
    if p_uint.bits() < 512 {
        return Err(Error::Key(
            "DH prime p too small (W3C requires >= 512 bits)".into(),
        ));
    }
    if !probably_prime(&p_uint, 20) {
        return Err(Error::Key("DH prime p is not prime".into()));
    }
    let g_uint = BigUint::from_bytes_be(g);
    // W3C XML Encryption 1.1 §5.6.1: "g at least 160 bits"
    if g_uint.bits() < 160 {
        return Err(Error::Key(
            "DH generator g too small (W3C requires >= 160 bits)".into(),
        ));
    }
    if g_uint >= p_uint {
        return Err(Error::Key("DH generator g out of range".into()));
    }
    if let Some(q_bytes) = q {
        let q_uint = BigUint::from_bytes_be(q_bytes);
        if q_uint.is_zero() || q_uint.is_one() {
            return Err(Error::Key("DH subgroup order q is trivial".into()));
        }
        let pm1 = &p_uint - BigUint::one();
        if (&pm1 % &q_uint) != BigUint::zero() {
            return Err(Error::Key("DH subgroup order q does not divide p-1".into()));
        }
    }

    Ok(())
}

/// Parse an ASN.1 tag + length, returning (content, remaining_data).
fn parse_asn1_tl(data: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), Error> {
    if data.is_empty() || data[0] != expected_tag {
        return Err(Error::Key(format!(
            "expected ASN.1 tag 0x{expected_tag:02X}, got 0x{:02X}",
            data.first().unwrap_or(&0)
        )));
    }
    let (len, content_start) =
        parse_asn1_length(&data[1..]).ok_or_else(|| Error::Key("invalid ASN.1 length".into()))?;
    if content_start.len() < len {
        return Err(Error::Key("ASN.1 length exceeds data".into()));
    }
    Ok((&content_start[..len], &content_start[len..]))
}

/// Skip one ASN.1 element, returning (skipped_element_content, remaining_data).
fn skip_asn1_element(data: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if data.is_empty() {
        return Err(Error::Key("empty ASN.1 data".into()));
    }
    let tag = data[0];
    let (len, content_start) =
        parse_asn1_length(&data[1..]).ok_or_else(|| Error::Key("invalid ASN.1 length".into()))?;
    if content_start.len() < len {
        return Err(Error::Key("ASN.1 element exceeds data".into()));
    }
    // Return the content of this element plus what remains after it
    let _ = tag;
    Ok((&content_start[..len], &content_start[len..]))
}

/// Parse an ASN.1 INTEGER, stripping leading zero byte, returning (value_bytes, remaining_data).
fn parse_asn1_integer(data: &[u8]) -> Result<(Vec<u8>, &[u8]), Error> {
    let (content, rest) = parse_asn1_tl(data, 0x02)?;
    // Strip leading zero byte added for sign
    let value = if content.len() > 1 && content[0] == 0 {
        &content[1..]
    } else {
        content
    };
    Ok((value.to_vec(), rest))
}

// ── Post-quantum key loading helpers ─────────────────────────────────

/// Try to load a post-quantum private key from PKCS#8 DER bytes.
///
/// Handles both the RustCrypto format (seed in context-specific tag) and the
/// OpenSSL format (seed in `SEQUENCE { OCTET STRING(seed), ... }`).
fn try_load_pq_private_key(der: &[u8]) -> Option<Key> {
    use bergshamra_crypto::sign::PqAlgorithm;
    use ml_dsa::signature::Keypair;
    use pkcs8_pq::spki::EncodePublicKey;
    use pkcs8_pq::DecodePrivateKey;

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
                    let seed =
                        ml_dsa::Seed::try_from(inner_bytes).expect("seed length already checked");
                    let sk = ml_dsa::SigningKey::<$paramset>::from_seed(&seed);
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

    try_slh_dsa_from_raw!(
        fips205::ID_SLH_DSA_SHA_2_128_F,
        slh_dsa::Sha2_128f,
        PqAlgorithm::SlhDsaSha2_128f
    );
    try_slh_dsa_from_raw!(
        fips205::ID_SLH_DSA_SHA_2_128_S,
        slh_dsa::Sha2_128s,
        PqAlgorithm::SlhDsaSha2_128s
    );
    try_slh_dsa_from_raw!(
        fips205::ID_SLH_DSA_SHA_2_192_F,
        slh_dsa::Sha2_192f,
        PqAlgorithm::SlhDsaSha2_192f
    );
    try_slh_dsa_from_raw!(
        fips205::ID_SLH_DSA_SHA_2_192_S,
        slh_dsa::Sha2_192s,
        PqAlgorithm::SlhDsaSha2_192s
    );
    try_slh_dsa_from_raw!(
        fips205::ID_SLH_DSA_SHA_2_256_F,
        slh_dsa::Sha2_256f,
        PqAlgorithm::SlhDsaSha2_256f
    );
    try_slh_dsa_from_raw!(
        fips205::ID_SLH_DSA_SHA_2_256_S,
        slh_dsa::Sha2_256s,
        PqAlgorithm::SlhDsaSha2_256s
    );

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
        if data.len() < 2 {
            return None;
        }
        Some((data[1] as usize, &data[2..]))
    } else if first == 0x82 {
        if data.len() < 3 {
            return None;
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Some((len, &data[3..]))
    } else if first == 0x83 {
        if data.len() < 4 {
            return None;
        }
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
        let key =
            load_key_file_with_password(pem_path, Some("secret123")).expect("load encrypted PEM");
        assert!(matches!(
            key.data,
            KeyData::Rsa {
                private: Some(_),
                ..
            }
        ));
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

    #[test]
    fn test_load_pkcs12_dh() {
        let p12_path =
            std::path::Path::new("../../test-data/xmlenc11-interop-2012/DH-1024_SHA256WithDSA.p12");
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let key = load_pkcs12(&data, "passwd").expect("load_pkcs12 DH should succeed");
        eprintln!("loaded key algo: {}", key.data.algorithm_name());
        assert!(
            matches!(key.data, KeyData::Dh { .. }),
            "expected DH key, got {}",
            key.data.algorithm_name()
        );
    }

    #[test]
    fn test_load_dh_pem_private() {
        let pem_path = std::path::Path::new("../../test-data/keys/dhx/dhx-rfc5114-3-first-key.pem");
        if !pem_path.exists() {
            eprintln!("skipping test: {pem_path:?} not found");
            return;
        }
        let key = load_key_file_with_password(pem_path, None).expect("load DH PEM private");
        eprintln!("loaded key algo: {}", key.data.algorithm_name());
        assert!(
            matches!(key.data, KeyData::Dh { .. }),
            "expected DH key, got {}",
            key.data.algorithm_name()
        );
        if let KeyData::Dh { private_key, .. } = &key.data {
            assert!(private_key.is_some(), "should have private key");
        }
    }

    #[test]
    fn test_load_dh_pem_public() {
        let pem_path =
            std::path::Path::new("../../test-data/keys/dhx/dhx-rfc5114-3-second-pubkey.pem");
        if !pem_path.exists() {
            eprintln!("skipping test: {pem_path:?} not found");
            return;
        }
        let key = load_key_file_with_password(pem_path, None).expect("load DH PEM public");
        eprintln!("loaded key algo: {}", key.data.algorithm_name());
        assert!(
            matches!(key.data, KeyData::Dh { .. }),
            "expected DH key, got {}",
            key.data.algorithm_name()
        );
    }

    #[test]
    fn test_load_ed25519_private_pkcs8() {
        // Create an Ed25519 key from fixed bytes and encode as PKCS#8 DER
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::SigningKey;

        let secret: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let sk = SigningKey::from_bytes(&secret);
        let pkcs8_der = sk.to_pkcs8_der().expect("encode PKCS#8 DER");

        let key = load_ed25519_private_pkcs8_der(pkcs8_der.as_bytes())
            .expect("load Ed25519 private key from PKCS#8 DER");
        assert!(
            matches!(
                key.data,
                KeyData::Ed25519 {
                    private: Some(_),
                    ..
                }
            ),
            "expected Ed25519 key with private component, got {}",
            key.data.algorithm_name()
        );
        assert_eq!(key.data.algorithm_name(), "Ed25519");
    }

    #[test]
    fn test_load_ed25519_public_spki() {
        // Create an Ed25519 key and encode the public key as SPKI DER
        use ed25519_dalek::pkcs8::spki::EncodePublicKey;
        use ed25519_dalek::SigningKey;

        let secret: [u8; 32] = [
            0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc,
            0xb7, 0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e,
            0x0b, 0x44, 0x58, 0xf7,
        ];
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();
        let spki_der = vk.to_public_key_der().expect("encode SPKI DER");

        let key = load_ed25519_public_spki_der(spki_der.as_ref())
            .expect("load Ed25519 public key from SPKI DER");
        assert!(
            matches!(key.data, KeyData::Ed25519 { private: None, .. }),
            "expected Ed25519 key without private component, got {}",
            key.data.algorithm_name()
        );
        assert_eq!(key.usage, KeyUsage::Verify);
    }

    #[test]
    fn test_load_ed25519_via_autodetect_pkcs8() {
        // Test that the auto-detect chain in load_private_key_pkcs8_der picks up Ed25519
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::SigningKey;

        let secret: [u8; 32] = [
            0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20,
            0x91, 0x1e, 0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9,
            0x6d, 0xca, 0x3d, 0x42,
        ];
        let sk = SigningKey::from_bytes(&secret);
        let pkcs8_der = sk.to_pkcs8_der().expect("encode PKCS#8 DER");

        let key = load_private_key_pkcs8_der(pkcs8_der.as_bytes())
            .expect("auto-detect Ed25519 from PKCS#8");
        assert!(
            matches!(
                key.data,
                KeyData::Ed25519 {
                    private: Some(_),
                    ..
                }
            ),
            "auto-detect should find Ed25519 key"
        );
    }

    #[test]
    fn test_load_ed25519_via_autodetect_spki() {
        // Test that the auto-detect chain in load_spki_der picks up Ed25519
        use ed25519_dalek::pkcs8::spki::EncodePublicKey;
        use ed25519_dalek::SigningKey;

        let secret: [u8; 32] = [
            0xab, 0x72, 0x00, 0x1b, 0xa2, 0x49, 0xca, 0xad, 0xb4, 0x95, 0xb1, 0xf6, 0x4c, 0x5a,
            0x0f, 0x85, 0xd2, 0x40, 0x23, 0x50, 0x0c, 0x00, 0xa9, 0xf4, 0xbb, 0x29, 0x8e, 0x1b,
            0x5e, 0x65, 0x59, 0xbb,
        ];
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();
        let spki_der = vk.to_public_key_der().expect("encode SPKI DER");

        let key = load_spki_der(spki_der.as_ref()).expect("auto-detect Ed25519 from SPKI");
        assert!(
            matches!(key.data, KeyData::Ed25519 { private: None, .. }),
            "auto-detect should find Ed25519 public key"
        );
    }

    #[test]
    fn test_ed25519_roundtrip_pkcs8_sign_verify() {
        // Full roundtrip: generate → encode PKCS#8 → load → sign → verify
        use ed25519_dalek::pkcs8::spki::EncodePublicKey;
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::SigningKey;

        let secret: [u8; 32] = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ];
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();

        // Encode and reload
        let pkcs8_der = sk.to_pkcs8_der().expect("encode private");
        let spki_der = vk.to_public_key_der().expect("encode public");

        let priv_key = load_private_key_pkcs8_der(pkcs8_der.as_bytes()).expect("load private");
        let pub_key = load_spki_der(spki_der.as_ref()).expect("load public");

        // Sign with loaded private key
        let signing_key = priv_key.to_signing_key().expect("convert to signing key");
        let algo = bergshamra_crypto::sign::from_uri_with_context(
            bergshamra_core::algorithm::EDDSA_ED25519,
            None,
        )
        .expect("resolve Ed25519 algorithm");

        let data = b"roundtrip test data";
        let signature = algo.sign(&signing_key, data).expect("sign");

        // Verify with loaded public key
        let verify_key = pub_key.to_signing_key().expect("convert to verify key");
        let result = algo.verify(&verify_key, data, &signature);
        assert!(
            result.is_ok(),
            "Ed25519 roundtrip through PKCS#8/SPKI should verify"
        );
    }

    #[test]
    fn test_load_x25519_private_raw() {
        // Generate a random X25519 key and load it
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let expected_public = x25519_dalek::PublicKey::from(&secret);

        let key = load_x25519_private_raw(secret.as_bytes()).expect("load X25519 private");
        match &key.data {
            KeyData::X25519 {
                private: Some(priv_bytes),
                public,
            } => {
                assert_eq!(priv_bytes, secret.as_bytes());
                assert_eq!(public, expected_public.as_bytes());
            }
            _ => panic!("expected X25519 key data with private key"),
        }
    }

    #[test]
    fn test_load_x25519_public_raw() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let public = x25519_dalek::PublicKey::from(&secret);

        let key = load_x25519_public_raw(public.as_bytes()).expect("load X25519 public");
        match &key.data {
            KeyData::X25519 {
                private: None,
                public: pub_bytes,
            } => {
                assert_eq!(pub_bytes, public.as_bytes());
            }
            _ => panic!("expected X25519 public key data"),
        }
    }

    #[test]
    fn test_load_x25519_private_wrong_length() {
        let short = [0u8; 16];
        assert!(load_x25519_private_raw(&short).is_err());
        let long = [0u8; 64];
        assert!(load_x25519_private_raw(&long).is_err());
    }

    #[test]
    fn test_load_x25519_public_wrong_length() {
        let short = [0u8; 31];
        assert!(load_x25519_public_raw(&short).is_err());
        let long = [0u8; 33];
        assert!(load_x25519_public_raw(&long).is_err());
    }

    #[test]
    fn test_x25519_key_value_xml() {
        // Verify to_key_value_xml produces correct ECKeyValue with X25519 NamedCurve
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let key = load_x25519_private_raw(secret.as_bytes()).expect("load X25519 private");
        let xml = key
            .data
            .to_key_value_xml("")
            .expect("X25519 should produce XML");
        assert!(
            xml.contains("urn:ietf:params:xml:ns:keyprov:curve:x25519"),
            "should contain X25519 NamedCurve URI"
        );
        assert!(
            xml.contains("ECKeyValue"),
            "should be an ECKeyValue element"
        );
        assert!(
            xml.contains("PublicKey"),
            "should contain PublicKey element"
        );
    }

    #[test]
    fn test_x25519_manager_find() {
        use crate::manager::KeysManager;

        let mut mgr = KeysManager::new();
        assert!(mgr.find_x25519().is_none());

        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let key = load_x25519_private_raw(secret.as_bytes()).expect("load X25519 private");
        mgr.add_key(key);

        let found = mgr.find_x25519().expect("should find X25519 key");
        assert_eq!(found.data.algorithm_name(), "X25519");
    }
}
