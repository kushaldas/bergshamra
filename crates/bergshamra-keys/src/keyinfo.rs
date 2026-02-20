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

    // Fallback: return the first key in the manager
    manager.first_key()
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
