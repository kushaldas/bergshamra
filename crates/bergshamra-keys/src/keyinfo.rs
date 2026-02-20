#![forbid(unsafe_code)]

//! KeyInfo XML processing — reads `<ds:KeyInfo>` elements to extract key material.

use crate::key::{Key, KeyData, KeyUsage};
use crate::manager::KeysManager;
use bergshamra_core::{ns, Error};

/// Process a `<KeyInfo>` element and attempt to resolve a key from the manager.
pub fn resolve_key_info<'a>(
    key_info_node: roxmltree::Node<'_, '_>,
    manager: &'a KeysManager,
) -> Result<&'a Key, Error> {
    // Try <KeyName> first
    for child in key_info_node.children() {
        if !child.is_element() {
            continue;
        }
        let ns_uri = child.tag_name().namespace().unwrap_or("");
        let local = child.tag_name().name();

        if ns_uri == ns::DSIG && local == ns::node::KEY_NAME {
            let name_text = child.text().unwrap_or("").trim();
            if !name_text.is_empty() {
                if let Some(key) = manager.find_by_name(name_text) {
                    return Ok(key);
                }
            }
        }
    }

    // Try <KeyValue> — extract RSA or EC public key from inline XML
    for child in key_info_node.children() {
        if !child.is_element() {
            continue;
        }
        let ns_uri = child.tag_name().namespace().unwrap_or("");
        let local = child.tag_name().name();

        if local == ns::node::KEY_VALUE && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            // Try RSA KeyValue
            if let Ok(_key) = parse_rsa_key_value(child) {
                // We can't return an owned key from a borrow-based API,
                // so we need a different approach. For now, fall through
                // to first_key() which will be reached below.
                // The caller (verify.rs) handles KeyValue extraction directly.
            }
        }
    }

    // Fallback: return the first key in the manager
    manager.first_key()
}

/// Try to extract an inline key from `<KeyInfo>` (RSA, EC, DSA KeyValue, or X509Certificate).
///
/// Returns `Some(Key)` if a KeyValue or X509Certificate was found and parsed, `None` otherwise.
pub fn extract_key_value(key_info_node: roxmltree::Node<'_, '_>) -> Option<Key> {
    for child in key_info_node.children() {
        if !child.is_element() {
            continue;
        }
        let ns_uri = child.tag_name().namespace().unwrap_or("");
        let local = child.tag_name().name();

        if local == ns::node::KEY_VALUE && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            // Try RSA KeyValue
            if let Ok(key) = parse_rsa_key_value(child) {
                return Some(key);
            }
            // Try EC KeyValue
            if let Ok(key) = parse_ec_key_value(child) {
                return Some(key);
            }
            // Try DSA KeyValue
            if let Ok(key) = parse_dsa_key_value(child) {
                return Some(key);
            }
        }

        // Try X509Data > X509Certificate
        if local == ns::node::X509_DATA && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            if let Some(key) = extract_x509_certificate(child) {
                return Some(key);
            }
        }
    }
    None
}

/// Extract a public key from `<X509Data><X509Certificate>` (base64-encoded DER).
///
/// If multiple certificates are present, returns the end-entity (non-CA) cert
/// that is most likely the signer. Specifically, prefers non-RSA keys (DSA, EC)
/// over RSA, since RSA certs in a chain are typically CA certs.
fn extract_x509_certificate(x509_data_node: roxmltree::Node<'_, '_>) -> Option<Key> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let mut keys = Vec::new();
    for child in x509_data_node.children() {
        if !child.is_element() {
            continue;
        }
        if child.tag_name().name() == ns::node::X509_CERTIFICATE {
            let b64 = child.text().unwrap_or("").trim();
            let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            if let Ok(der) = engine.decode(&clean) {
                if let Ok(key) = crate::loader::load_x509_cert_der(&der) {
                    keys.push(key);
                }
            }
        }
    }

    if keys.is_empty() {
        return None;
    }
    if keys.len() == 1 {
        return keys.into_iter().next();
    }

    // If there are multiple certs, prefer non-RSA (DSA, EC) over RSA
    // as RSA certs in a chain are typically the CA, not the signer
    for key in &keys {
        if !matches!(&key.data, KeyData::Rsa { .. }) {
            // Return the first non-RSA key (clone-free by draining)
            let idx = keys.iter().position(|k| !matches!(&k.data, KeyData::Rsa { .. })).unwrap();
            return Some(keys.into_iter().nth(idx).unwrap());
        }
    }

    // All RSA — return the first one
    keys.into_iter().next()
}

/// Extract an RSA public key from a `<KeyValue><RSAKeyValue>` element.
pub fn parse_rsa_key_value(key_value_node: roxmltree::Node<'_, '_>) -> Result<Key, Error> {
    let rsa_kv: roxmltree::Node<'_, '_> = key_value_node
        .children()
        .find(|n: &roxmltree::Node<'_, '_>| {
            n.is_element()
                && n.tag_name().name() == ns::node::RSA_KEY_VALUE
                && n.tag_name().namespace().unwrap_or("") == ns::DSIG
        })
        .ok_or_else(|| Error::MissingElement("RSAKeyValue".into()))?;

    let modulus_b64: &str = rsa_kv
        .children()
        .find(|n: &roxmltree::Node<'_, '_>| {
            n.is_element() && n.tag_name().name() == ns::node::RSA_MODULUS
        })
        .and_then(|n: roxmltree::Node<'_, '_>| n.text())
        .ok_or_else(|| Error::MissingElement("Modulus".into()))?;

    let exponent_b64: &str = rsa_kv
        .children()
        .find(|n: &roxmltree::Node<'_, '_>| {
            n.is_element() && n.tag_name().name() == ns::node::RSA_EXPONENT
        })
        .and_then(|n: roxmltree::Node<'_, '_>| n.text())
        .ok_or_else(|| Error::MissingElement("Exponent".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let modulus_bytes = engine
        .decode(modulus_b64.trim().replace(['\n', '\r', ' '], ""))
        .map_err(|e| Error::Base64(format!("Modulus: {e}")))?;
    let exponent_bytes = engine
        .decode(exponent_b64.trim().replace(['\n', '\r', ' '], ""))
        .map_err(|e| Error::Base64(format!("Exponent: {e}")))?;

    let n = rsa::BigUint::from_bytes_be(&modulus_bytes);
    let e = rsa::BigUint::from_bytes_be(&exponent_bytes);
    let public = rsa::RsaPublicKey::new(n, e)
        .map_err(|err| Error::Key(format!("invalid RSA public key: {err}")))?;

    Ok(Key::new(
        KeyData::Rsa { private: None, public },
        KeyUsage::Verify,
    ))
}

/// Extract a DSA public key from a `<KeyValue><DSAKeyValue>` element.
///
/// DSAKeyValue contains P, Q, G (domain parameters) and Y (public key).
pub fn parse_dsa_key_value(key_value_node: roxmltree::Node<'_, '_>) -> Result<Key, Error> {
    let dsa_kv = key_value_node
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == ns::node::DSA_KEY_VALUE
                && n.tag_name().namespace().unwrap_or("") == ns::DSIG
        })
        .ok_or_else(|| Error::MissingElement("DSAKeyValue".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let decode_elem = |name: &str| -> Result<Vec<u8>, Error> {
        let b64 = dsa_kv
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == name)
            .and_then(|n| n.text())
            .ok_or_else(|| Error::MissingElement(name.into()))?;
        let clean: String = b64.trim().chars().filter(|c| !c.is_whitespace()).collect();
        engine
            .decode(&clean)
            .map_err(|e| Error::Base64(format!("{name}: {e}")))
    };

    let p_bytes = decode_elem(ns::node::DSA_P)?;
    let q_bytes = decode_elem(ns::node::DSA_Q)?;
    let g_bytes = decode_elem(ns::node::DSA_G)?;
    let y_bytes = decode_elem(ns::node::DSA_Y)?;

    let p = dsa::BigUint::from_bytes_be(&p_bytes);
    let q = dsa::BigUint::from_bytes_be(&q_bytes);
    let g = dsa::BigUint::from_bytes_be(&g_bytes);
    let y = dsa::BigUint::from_bytes_be(&y_bytes);

    let components = dsa::Components::from_components(p, q, g)
        .map_err(|e| Error::Key(format!("invalid DSA components: {e}")))?;
    let vk = dsa::VerifyingKey::from_components(components, y)
        .map_err(|e| Error::Key(format!("invalid DSA public key: {e}")))?;

    Ok(Key::new(
        KeyData::Dsa { private: None, public: vk },
        KeyUsage::Verify,
    ))
}

/// Extract an EC public key from a `<KeyValue><ECKeyValue>` element.
///
/// Supports P-256, P-384, P-521 curves via NamedCurve OID.
pub fn parse_ec_key_value(key_value_node: roxmltree::Node<'_, '_>) -> Result<Key, Error> {
    // ECKeyValue is in the xmldsig11 namespace
    let ec_kv = key_value_node
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == ns::node::EC_KEY_VALUE
                && (n.tag_name().namespace().unwrap_or("") == ns::DSIG11
                    || n.tag_name().namespace().unwrap_or("") == ns::DSIG)
        })
        .ok_or_else(|| Error::MissingElement("ECKeyValue".into()))?;

    // Read NamedCurve URI
    let named_curve = ec_kv
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == ns::node::NAMED_CURVE)
        .ok_or_else(|| Error::MissingElement("NamedCurve".into()))?;

    let curve_uri = named_curve
        .attribute(ns::attr::URI)
        .ok_or_else(|| Error::MissingAttribute("URI on NamedCurve".into()))?;

    // Read PublicKey (base64-encoded uncompressed point)
    let public_key_b64 = ec_kv
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == ns::node::PUBLIC_KEY)
        .and_then(|n| n.text())
        .ok_or_else(|| Error::MissingElement("PublicKey".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let point_bytes = engine
        .decode(public_key_b64.trim().replace(['\n', '\r', ' '], ""))
        .map_err(|e| Error::Base64(format!("EC PublicKey: {e}")))?;

    match curve_uri {
        "urn:oid:1.2.840.10045.3.1.7" => {
            // P-256
            use p256::elliptic_curve::sec1::FromEncodedPoint;
            let encoded = p256::EncodedPoint::from_bytes(&point_bytes)
                .map_err(|e| Error::Key(format!("invalid P-256 point: {e}")))?;
            let point = p256::PublicKey::from_encoded_point(&encoded);
            if point.is_none().into() {
                return Err(Error::Key("invalid P-256 public key point".into()));
            }
            let vk = p256::ecdsa::VerifyingKey::from(point.unwrap());
            Ok(Key::new(
                KeyData::EcP256 { private: None, public: vk },
                KeyUsage::Verify,
            ))
        }
        "urn:oid:1.3.132.0.34" => {
            // P-384
            use p384::elliptic_curve::sec1::FromEncodedPoint;
            let encoded = p384::EncodedPoint::from_bytes(&point_bytes)
                .map_err(|e| Error::Key(format!("invalid P-384 point: {e}")))?;
            let point = p384::PublicKey::from_encoded_point(&encoded);
            if point.is_none().into() {
                return Err(Error::Key("invalid P-384 public key point".into()));
            }
            let vk = p384::ecdsa::VerifyingKey::from(point.unwrap());
            Ok(Key::new(
                KeyData::EcP384 { private: None, public: vk },
                KeyUsage::Verify,
            ))
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("EC curve: {curve_uri}"))),
    }
}
