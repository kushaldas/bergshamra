#![forbid(unsafe_code)]

//! Provider-neutral key loading for AWS-LC builds.

use crate::key::{Key, KeyData, KeyUsage};
use bergshamra_core::Error;
use der::{Decode, Encode};

pub fn load_rsa_private_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let der = pem_der(pem_data, "PRIVATE KEY")?;
    load_private_key_pkcs8_der_for(&der, kryptering::KeyAlgorithm::Rsa)
}

pub fn load_rsa_public_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let der = pem_der(pem_data, "PUBLIC KEY")?;
    load_spki_der_for(&der, kryptering::KeyAlgorithm::Rsa)
}

pub fn load_ec_p256_private_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let der = pem_der(pem_data, "PRIVATE KEY")?;
    load_private_key_pkcs8_der_for(
        &der,
        kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
    )
}

pub fn load_ec_p384_private_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let der = pem_der(pem_data, "PRIVATE KEY")?;
    load_private_key_pkcs8_der_for(
        &der,
        kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
    )
}

pub fn load_ec_p521_private_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let der = pem_der(pem_data, "PRIVATE KEY")?;
    load_private_key_pkcs8_der_for(
        &der,
        kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521),
    )
}

pub fn load_hmac_key(data: &[u8]) -> Result<Key, Error> {
    Ok(Key::new(
        KeyData::from_symmetric_bytes(kryptering::KeyAlgorithm::Hmac, data)?,
        KeyUsage::Any,
    ))
}

pub fn load_aes_key(data: &[u8]) -> Result<Key, Error> {
    if !matches!(data.len(), 16 | 24 | 32) {
        return Err(Error::Key(format!(
            "invalid AES key size: {} (expected 16, 24, or 32)",
            data.len()
        )));
    }
    Ok(Key::new(
        KeyData::from_symmetric_bytes(kryptering::KeyAlgorithm::Aes, data)?,
        KeyUsage::Any,
    ))
}

pub fn load_des3_key(data: &[u8]) -> Result<Key, Error> {
    if data.len() != 24 {
        return Err(Error::Key(format!(
            "invalid 3DES key size: {} (expected 24)",
            data.len()
        )));
    }
    Ok(Key::new(
        KeyData::from_symmetric_bytes(kryptering::KeyAlgorithm::TripleDes, data)?,
        KeyUsage::Any,
    ))
}

fn load_private_key_pkcs8_der(der: &[u8]) -> Result<Key, Error> {
    let info = pkcs8::PrivateKeyInfo::from_der(der)
        .map_err(|err| Error::Key(format!("invalid PKCS#8 private key: {err}")))?;
    let algorithm = key_algorithm(&info.algorithm)?;
    load_private_key_pkcs8_der_for(der, algorithm)
}

fn load_private_key_pkcs8_der_for(
    der: &[u8],
    expected: kryptering::KeyAlgorithm,
) -> Result<Key, Error> {
    let info = pkcs8::PrivateKeyInfo::from_der(der)
        .map_err(|err| Error::Key(format!("invalid PKCS#8 private key: {err}")))?;
    let actual = key_algorithm(&info.algorithm)?;
    if actual != expected {
        return Err(Error::Key(format!(
            "expected {expected:?} PKCS#8 key, found {actual:?}"
        )));
    }
    Ok(Key::new(
        KeyData::from_pkcs8_der(actual, der)?,
        KeyUsage::Any,
    ))
}

pub fn load_pkcs12(data: &[u8], password: &str) -> Result<Key, Error> {
    let contents = bergshamra_pkcs12::parse_pkcs12(data, password)?;
    let private = contents
        .private_keys
        .first()
        .ok_or_else(|| Error::Key("PKCS#12 contains no private keys".into()))?;
    let mut key = load_private_key_pkcs8_der(private)?;
    key.x509_chain = contents.certificates;
    Ok(key)
}

pub fn load_pem_auto(pem_data: &[u8], password: Option<&str>) -> Result<Key, Error> {
    let first = first_pem_block(pem_data).unwrap_or(pem_data);
    let (label, der) = pem_rfc7468::decode_vec(first)
        .map_err(|err| Error::Key(format!("failed to decode PEM: {err}")))?;
    match label {
        "PRIVATE KEY" => load_private_key_pkcs8_der(&der),
        "PUBLIC KEY" => load_spki_der(&der),
        "CERTIFICATE" => load_x509_cert_der(&der),
        "ENCRYPTED PRIVATE KEY" if password.is_some() => Err(Error::UnsupportedAlgorithm(
            "encrypted PKCS#8 PEM is not available through the selected provider".into(),
        )),
        label => Err(Error::Key(format!(
            "unsupported PEM label for selected provider: {label}"
        ))),
    }
}

fn first_pem_block(input: &[u8]) -> Option<&[u8]> {
    let end_marker = b"-----END ";
    let end_start = input
        .windows(end_marker.len())
        .position(|part| part == end_marker)?;
    let line_end = input[end_start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(input.len(), |offset| end_start + offset + 1);
    Some(&input[..line_end])
}

pub fn load_spki_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let der = pem_der(pem_data, "PUBLIC KEY")?;
    load_spki_der(&der)
}

pub fn load_x509_cert_pem(pem_data: &[u8]) -> Result<Key, Error> {
    let der = pem_der(pem_data, "CERTIFICATE")?;
    load_x509_cert_der(&der)
}

pub fn load_key_file(path: &std::path::Path) -> Result<Key, Error> {
    load_key_file_with_password(path, None)
}

pub fn load_key_file_with_password(
    path: &std::path::Path,
    password: Option<&str>,
) -> Result<Key, Error> {
    let data = zeroize::Zeroizing::new(std::fs::read(path)?);
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(extension.as_str(), "p12" | "pfx") {
        return load_pkcs12(&data, password.unwrap_or(""));
    }
    if data.starts_with(b"-----BEGIN") {
        return load_pem_auto(&data, password);
    }
    load_private_key_pkcs8_der(&data)
        .or_else(|_| load_spki_der(&data))
        .or_else(|_| load_x509_cert_der(&data))
}

pub fn load_x509_cert_der(data: &[u8]) -> Result<Key, Error> {
    let cert = x509_cert::Certificate::from_der(data)
        .map_err(|err| Error::Certificate(format!("invalid X.509 certificate: {err}")))?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|err| Error::Key(format!("SPKI encoding failed: {err}")))?;
    let mut key = load_spki_der(&spki)?;
    key.x509_chain.push(data.to_vec());
    Ok(key)
}

pub fn load_spki_der(spki_der: &[u8]) -> Result<Key, Error> {
    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|err| Error::Key(format!("invalid SPKI public key: {err}")))?;
    let algorithm = key_algorithm(&spki.algorithm)?;
    load_spki_der_for(spki_der, algorithm)
}

fn load_spki_der_for(der: &[u8], expected: kryptering::KeyAlgorithm) -> Result<Key, Error> {
    let spki = spki::SubjectPublicKeyInfoRef::from_der(der)
        .map_err(|err| Error::Key(format!("invalid SPKI public key: {err}")))?;
    let actual = key_algorithm(&spki.algorithm)?;
    if actual != expected {
        return Err(Error::Key(format!(
            "expected {expected:?} SPKI key, found {actual:?}"
        )));
    }
    Ok(Key::new(
        KeyData::from_spki_der(actual, der)?,
        KeyUsage::Verify,
    ))
}

pub fn load_ed25519_private_pkcs8_der(der: &[u8]) -> Result<Key, Error> {
    load_private_key_pkcs8_der_for(der, kryptering::KeyAlgorithm::Ed25519)
}

pub fn load_ed25519_public_spki_der(spki_der: &[u8]) -> Result<Key, Error> {
    load_spki_der_for(spki_der, kryptering::KeyAlgorithm::Ed25519)
}

pub fn load_x25519_private_raw(_private_bytes: &[u8]) -> Result<Key, Error> {
    Err(Error::UnsupportedAlgorithm(
        "raw X25519 private import also requires its public component; use KeyData::from_x25519"
            .into(),
    ))
}

pub fn load_x25519_public_raw(public_bytes: &[u8]) -> Result<Key, Error> {
    Ok(Key::new(
        KeyData::from_x25519(None, public_bytes)?,
        KeyUsage::Verify,
    ))
}

pub fn try_load_pq_private_key(_der: &[u8]) -> Option<Key> {
    None
}

pub fn try_load_pq_public_key(_spki_der: &[u8]) -> Option<Key> {
    None
}

fn pem_der(pem_data: &[u8], expected_label: &str) -> Result<Vec<u8>, Error> {
    let (label, der) = pem_rfc7468::decode_vec(pem_data)
        .map_err(|err| Error::Key(format!("failed to decode PEM: {err}")))?;
    if label != expected_label {
        return Err(Error::Key(format!(
            "expected {expected_label} PEM label, got {label}"
        )));
    }
    Ok(der)
}

fn key_algorithm(
    algorithm: &spki::AlgorithmIdentifierRef<'_>,
) -> Result<kryptering::KeyAlgorithm, Error> {
    let oid = algorithm.oid;
    if oid == der::oid::db::rfc5912::RSA_ENCRYPTION || oid == der::oid::db::rfc5912::ID_RSASSA_PSS {
        return Ok(kryptering::KeyAlgorithm::Rsa);
    }
    if oid == der::oid::db::rfc5912::ID_DSA {
        return Ok(kryptering::KeyAlgorithm::Dsa);
    }
    if oid == der::oid::db::rfc8410::ID_ED_25519 {
        return Ok(kryptering::KeyAlgorithm::Ed25519);
    }
    if oid == der::oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        let parameters = algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| Error::Key("EC key has no named-curve parameters".into()))?;
        let curve: der::asn1::ObjectIdentifier = parameters
            .decode_as()
            .map_err(|err| Error::Key(format!("invalid EC curve parameters: {err}")))?;
        return if curve == der::oid::db::rfc5912::SECP_256_R_1 {
            Ok(kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256))
        } else if curve == der::oid::db::rfc5912::SECP_384_R_1 {
            Ok(kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384))
        } else if curve == der::oid::db::rfc5912::SECP_521_R_1 {
            Ok(kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521))
        } else {
            Err(Error::UnsupportedAlgorithm(format!("EC curve OID {curve}")))
        };
    }
    Err(Error::UnsupportedAlgorithm(format!(
        "key algorithm OID {oid}"
    )))
}
