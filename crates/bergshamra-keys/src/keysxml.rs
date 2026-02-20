#![forbid(unsafe_code)]

//! Parser for xmlsec's `keys.xml` format.
//!
//! The format uses a `<Keys xmlns="http://www.aleksey.com/xmlsec/2002">` root
//! element containing multiple `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">`
//! children. Each KeyInfo has a `<KeyName>` and a `<KeyValue>` whose child
//! element determines the key type:
//!
//! - `<HMACKeyValue xmlns="...aleksey...">` — base64 HMAC key
//! - `<AESKeyValue xmlns="...aleksey...">` — base64 AES key
//! - `<DESKeyValue xmlns="...aleksey...">` — base64 3DES key
//! - `<RSAKeyValue>` — standard ds:RSAKeyValue (Modulus + Exponent)

use crate::key::Key;
use crate::loader;
use bergshamra_core::Error;

const ALEKSEY_NS: &str = "http://www.aleksey.com/xmlsec/2002";
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Parse an xmlsec `keys.xml` file and return all named keys.
pub fn parse_keys_xml(xml: &str) -> Result<Vec<Key>, Error> {
    let doc = roxmltree::Document::parse_with_options(xml, roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() })
        .map_err(|e| Error::XmlParse(format!("keys.xml: {e}")))?;

    let mut keys = Vec::new();

    for node in doc.descendants() {
        if !node.is_element() {
            continue;
        }
        let ns = node.tag_name().namespace().unwrap_or("");
        let local = node.tag_name().name();

        // Each <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"> is one key entry
        if ns == DSIG_NS && local == "KeyInfo" {
            if let Some(key) = parse_key_info_entry(node)? {
                keys.push(key);
            }
        }
    }

    Ok(keys)
}

/// Parse a single `<KeyInfo>` entry from keys.xml.
fn parse_key_info_entry(key_info_node: roxmltree::Node<'_, '_>) -> Result<Option<Key>, Error> {
    // Extract <KeyName>
    let key_name = key_info_node
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == "KeyName"
                && n.tag_name().namespace().unwrap_or("") == DSIG_NS
        })
        .and_then(|n| n.text())
        .map(|s| s.trim().to_owned());

    // Extract <KeyValue>
    let key_value_node = key_info_node.children().find(|n| {
        n.is_element()
            && n.tag_name().name() == "KeyValue"
            && n.tag_name().namespace().unwrap_or("") == DSIG_NS
    });

    let key_value_node = match key_value_node {
        Some(n) => n,
        None => return Ok(None),
    };

    // Determine key type from the child of <KeyValue>
    for child in key_value_node.children() {
        if !child.is_element() {
            continue;
        }
        let child_ns = child.tag_name().namespace().unwrap_or("");
        let child_local = child.tag_name().name();

        let mut key = match (child_ns, child_local) {
            (ALEKSEY_NS, "HMACKeyValue") => {
                let b64 = child.text().unwrap_or("").trim();
                let bytes = decode_b64(b64, "HMACKeyValue")?;
                loader::load_hmac_key(&bytes)
            }
            (ALEKSEY_NS, "AESKeyValue") => {
                let b64 = child.text().unwrap_or("").trim();
                let bytes = decode_b64(b64, "AESKeyValue")?;
                loader::load_aes_key(&bytes)?
            }
            (ALEKSEY_NS, "DESKeyValue") => {
                let b64 = child.text().unwrap_or("").trim();
                let bytes = decode_b64(b64, "DESKeyValue")?;
                loader::load_des3_key(&bytes)?
            }
            (DSIG_NS, "RSAKeyValue") => {
                // Re-use the existing RSAKeyValue parser
                crate::keyinfo::parse_rsa_key_value(key_value_node)?
            }
            _ => continue, // Skip DSAKeyValue and other unsupported types
        };

        if let Some(name) = &key_name {
            key.name = Some(name.clone());
        }
        return Ok(Some(key));
    }

    Ok(None)
}

fn decode_b64(b64: &str, context: &str) -> Result<Vec<u8>, Error> {
    use base64::Engine;
    let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&clean)
        .map_err(|e| Error::Base64(format!("{context}: {e}")))
}

/// Load keys from an xmlsec keys.xml file path into a list of named keys.
pub fn load_keys_file(path: &std::path::Path) -> Result<Vec<Key>, Error> {
    let xml = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
    parse_keys_xml(&xml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keys_xml() {
        let keys_path = std::path::Path::new("../../test-data/keys/keys.xml");
        if !keys_path.exists() {
            eprintln!("skipping test: {keys_path:?} not found");
            return;
        }
        let keys = load_keys_file(keys_path).expect("parse keys.xml");

        // Should have: test-hmac-sha1, test-dsa (skipped), test-rsa, test-des, test-aes128/192/256
        // DSA is unsupported so 6 keys
        assert!(keys.len() >= 6, "expected at least 6 keys, got {}", keys.len());

        // Check HMAC key
        let hmac = keys.iter().find(|k| k.name.as_deref() == Some("test-hmac-sha1")).unwrap();
        assert!(matches!(&hmac.data, KeyData::Hmac(v) if v == b"secret"));

        // Check AES-128 key
        let aes128 = keys.iter().find(|k| k.name.as_deref() == Some("test-aes128")).unwrap();
        assert!(matches!(&aes128.data, KeyData::Aes(v) if v.len() == 16));

        // Check AES-192 key
        let aes192 = keys.iter().find(|k| k.name.as_deref() == Some("test-aes192")).unwrap();
        assert!(matches!(&aes192.data, KeyData::Aes(v) if v.len() == 24));

        // Check AES-256 key
        let aes256 = keys.iter().find(|k| k.name.as_deref() == Some("test-aes256")).unwrap();
        assert!(matches!(&aes256.data, KeyData::Aes(v) if v.len() == 32));

        // Check 3DES key
        let des = keys.iter().find(|k| k.name.as_deref() == Some("test-des")).unwrap();
        assert!(matches!(&des.data, KeyData::Des3(v) if v.len() == 24));

        // Check RSA key
        let rsa_key = keys.iter().find(|k| k.name.as_deref() == Some("test-rsa")).unwrap();
        assert!(matches!(&rsa_key.data, KeyData::Rsa { .. }));
    }
}
