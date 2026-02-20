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

/// Auto-detect key format and load from PEM data.
///
/// Tries RSA private, RSA public, EC P-256, EC P-384 in order.
pub fn load_pem_auto(pem_data: &[u8]) -> Result<Key, Error> {
    // Try each format
    if let Ok(key) = load_rsa_private_pem(pem_data) {
        return Ok(key);
    }
    if let Ok(key) = load_rsa_public_pem(pem_data) {
        return Ok(key);
    }
    if let Ok(key) = load_ec_p256_private_pem(pem_data) {
        return Ok(key);
    }
    if let Ok(key) = load_ec_p384_private_pem(pem_data) {
        return Ok(key);
    }
    Err(Error::Key("unable to auto-detect key format from PEM data".into()))
}

/// Load a key from a file, auto-detecting format.
pub fn load_key_file(path: &std::path::Path) -> Result<Key, Error> {
    let data = std::fs::read(path)?;

    // Check if it's PEM
    if data.starts_with(b"-----BEGIN") {
        return load_pem_auto(&data);
    }

    // Try DER formats
    // Try RSA PKCS#8 DER
    use pkcs8::DecodePrivateKey;
    if let Ok(pk) = rsa::RsaPrivateKey::from_pkcs8_der(&data) {
        let public = pk.to_public_key();
        return Ok(Key::new(
            KeyData::Rsa { private: Some(pk), public },
            KeyUsage::Any,
        ));
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

    // Raw binary (could be HMAC or AES key)
    Err(Error::Key(format!(
        "unable to auto-detect key format from file: {}",
        path.display()
    )))
}
