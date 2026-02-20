#![forbid(unsafe_code)]

//! XML-Enc decryption.
//!
//! Processing order per spec:
//! 1. Parse `<EncryptedData>`, register ID attributes
//! 2. Read `<EncryptionMethod>` URI
//! 3. Read `<KeyInfo>` to resolve decryption key (may involve `<EncryptedKey>`)
//! 4. Read `<CipherData>`: `<CipherValue>` (Base64 inline) or `<CipherReference>`
//! 5. Decrypt using resolved key and algorithm
//! 6. Replace `<EncryptedData>` with plaintext depending on Type attribute

use crate::context::EncContext;
use bergshamra_core::{algorithm, ns, Error};
use std::collections::HashMap;

/// Decrypt an XML document containing `<EncryptedData>`.
///
/// Returns the decrypted XML document as a string.
pub fn decrypt(ctx: &EncContext, xml: &str) -> Result<String, Error> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    // Build ID map
    let mut id_attrs: Vec<&str> = vec!["Id", "ID", "id"];
    let extra: Vec<&str> = ctx.id_attrs.iter().map(|s| s.as_str()).collect();
    id_attrs.extend(extra);
    let id_map = build_id_map(&doc, &id_attrs);

    // Find first <EncryptedData> element
    let enc_data_node = find_element(&doc, ns::ENC, ns::node::ENCRYPTED_DATA)
        .ok_or_else(|| Error::MissingElement("EncryptedData".into()))?;

    // Read Type attribute (Element or Content)
    let enc_type = enc_data_node.attribute(ns::attr::TYPE).unwrap_or("");

    // Read EncryptionMethod
    let enc_method_node = find_child_element(enc_data_node, ns::ENC, ns::node::ENCRYPTION_METHOD)
        .ok_or_else(|| Error::MissingElement("EncryptionMethod".into()))?;
    let enc_uri = enc_method_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on EncryptionMethod".into()))?;

    // Resolve decryption key
    let key_bytes = resolve_decryption_key(ctx, enc_data_node, &doc, &id_map)?;

    // Read CipherData/CipherValue
    let cipher_data_node = find_child_element(enc_data_node, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData".into()))?;

    let cipher_bytes = read_cipher_data(cipher_data_node)?;

    // Decrypt
    let cipher_alg = bergshamra_crypto::cipher::from_uri(enc_uri)?;
    let plaintext = cipher_alg.decrypt(&key_bytes, &cipher_bytes)?;

    // Replace EncryptedData with plaintext
    let result = replace_encrypted_data(xml, enc_data_node, enc_type, &plaintext)?;

    Ok(result)
}

/// Resolve the decryption key from KeyInfo or EncryptedKey.
fn resolve_decryption_key(
    ctx: &EncContext,
    enc_data_node: roxmltree::Node<'_, '_>,
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
) -> Result<Vec<u8>, Error> {
    let key_info_node = find_child_element(enc_data_node, ns::DSIG, ns::node::KEY_INFO);

    if let Some(ki) = key_info_node {
        // Check for EncryptedKey inside KeyInfo
        if let Some(enc_key_node) = find_child_element(ki, ns::ENC, ns::node::ENCRYPTED_KEY) {
            return decrypt_encrypted_key(ctx, enc_key_node, doc, id_map);
        }

        // Check for KeyName
        for child in ki.children() {
            if !child.is_element() {
                continue;
            }
            let child_ns = child.tag_name().namespace().unwrap_or("");
            let child_local = child.tag_name().name();

            if child_ns == ns::DSIG && child_local == ns::node::KEY_NAME {
                let name = child.text().unwrap_or("").trim();
                if !name.is_empty() {
                    if let Some(key) = ctx.keys_manager.find_by_name(name) {
                        if let Some(bytes) = key.symmetric_key_bytes() {
                            return Ok(bytes.to_vec());
                        }
                    }
                }
            }

            // Check for RetrievalMethod pointing to an EncryptedKey
            if child_ns == ns::DSIG && child_local == ns::node::RETRIEVAL_METHOD {
                if let Some(retrieval_uri) = child.attribute(ns::attr::URI) {
                    if let Some(retrieval_type) = child.attribute(ns::attr::TYPE) {
                        if retrieval_type.contains("EncryptedKey") {
                            if let Some(id) = retrieval_uri.strip_prefix('#') {
                                if let Some(&node_id) = id_map.get(id) {
                                    let target = doc.get_node(node_id)
                                        .ok_or_else(|| Error::InvalidUri(format!("cannot resolve #{id}")))?;
                                    return decrypt_encrypted_key(ctx, target, doc, id_map);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: try first symmetric key in the manager
    let key = ctx.keys_manager.first_key()?;
    if let Some(bytes) = key.symmetric_key_bytes() {
        Ok(bytes.to_vec())
    } else {
        Err(Error::Key("no suitable decryption key found".into()))
    }
}

/// Decrypt an <EncryptedKey> element to get the session key.
fn decrypt_encrypted_key(
    ctx: &EncContext,
    enc_key_node: roxmltree::Node<'_, '_>,
    _doc: &roxmltree::Document<'_>,
    _id_map: &HashMap<String, roxmltree::NodeId>,
) -> Result<Vec<u8>, Error> {
    // Read EncryptionMethod on EncryptedKey
    let enc_method = find_child_element(enc_key_node, ns::ENC, ns::node::ENCRYPTION_METHOD)
        .ok_or_else(|| Error::MissingElement("EncryptionMethod on EncryptedKey".into()))?;
    let enc_uri = enc_method
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on EncryptedKey EncryptionMethod".into()))?;

    // Read CipherData/CipherValue
    let cipher_data = find_child_element(enc_key_node, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData on EncryptedKey".into()))?;
    let cipher_bytes = read_cipher_data(cipher_data)?;

    // Determine key unwrap method
    match enc_uri {
        // RSA key transport
        algorithm::RSA_PKCS1 | algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
            let transport = bergshamra_crypto::keytransport::from_uri(enc_uri)?;
            // Find RSA private key in manager
            let rsa_key = ctx.keys_manager.find_rsa()
                .ok_or_else(|| Error::Key("no RSA key for EncryptedKey decryption".into()))?;
            let private_key = rsa_key.rsa_private_key()
                .ok_or_else(|| Error::Key("RSA private key required for key transport".into()))?;
            transport.decrypt(private_key, &cipher_bytes)
        }

        // AES Key Wrap
        algorithm::KW_AES128 | algorithm::KW_AES192 | algorithm::KW_AES256 => {
            let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
            // Find AES key in manager to use as KEK
            let aes_key = ctx.keys_manager.find_aes()
                .ok_or_else(|| Error::Key("no AES key for key unwrap".into()))?;
            let kek_bytes = aes_key.symmetric_key_bytes()
                .ok_or_else(|| Error::Key("AES key has no bytes".into()))?;
            kw.unwrap(kek_bytes, &cipher_bytes)
        }

        // 3DES Key Wrap
        algorithm::KW_TRIPLEDES => {
            let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
            let des_key = ctx.keys_manager.first_key()?;
            let kek_bytes = des_key.symmetric_key_bytes()
                .ok_or_else(|| Error::Key("no symmetric key for 3DES key unwrap".into()))?;
            kw.unwrap(kek_bytes, &cipher_bytes)
        }

        _ => Err(Error::UnsupportedAlgorithm(format!("EncryptedKey method: {enc_uri}"))),
    }
}

/// Read CipherData — extract CipherValue (Base64) or CipherReference.
fn read_cipher_data(cipher_data_node: roxmltree::Node<'_, '_>) -> Result<Vec<u8>, Error> {
    // Try CipherValue first
    if let Some(cipher_value) = find_child_element(cipher_data_node, ns::ENC, ns::node::CIPHER_VALUE) {
        let b64_text = cipher_value.text().unwrap_or("").trim();
        let clean: String = b64_text.chars().filter(|c| !c.is_whitespace()).collect();

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        return engine
            .decode(&clean)
            .map_err(|e| Error::Base64(format!("CipherValue: {e}")));
    }

    // CipherReference not yet supported
    if find_child_element(cipher_data_node, ns::ENC, ns::node::CIPHER_REFERENCE).is_some() {
        return Err(Error::UnsupportedAlgorithm("CipherReference not yet supported".into()));
    }

    Err(Error::MissingElement("CipherValue or CipherReference".into()))
}

/// Replace the <EncryptedData> element in the XML string with the decrypted plaintext.
fn replace_encrypted_data(
    xml: &str,
    enc_data_node: roxmltree::Node<'_, '_>,
    enc_type: &str,
    plaintext: &[u8],
) -> Result<String, Error> {
    let plaintext_str = std::str::from_utf8(plaintext)
        .map_err(|e| Error::Decryption(format!("plaintext is not valid UTF-8: {e}")))?;

    // Find the byte range of the EncryptedData element in the original XML
    let range = enc_data_node.range();
    let start = range.start;
    let end = range.end;

    match enc_type {
        ns::ENC_TYPE_ELEMENT => {
            // Replace EncryptedData with the decrypted element
            let mut result = String::with_capacity(xml.len());
            result.push_str(&xml[..start]);
            result.push_str(plaintext_str);
            result.push_str(&xml[end..]);
            Ok(result)
        }
        ns::ENC_TYPE_CONTENT => {
            // Replace EncryptedData with the decrypted content (children)
            let mut result = String::with_capacity(xml.len());
            result.push_str(&xml[..start]);
            result.push_str(plaintext_str);
            result.push_str(&xml[end..]);
            Ok(result)
        }
        _ => {
            // Default: replace the EncryptedData element entirely
            let mut result = String::with_capacity(xml.len());
            result.push_str(&xml[..start]);
            result.push_str(plaintext_str);
            result.push_str(&xml[end..]);
            Ok(result)
        }
    }
}

// ── Helper functions ─────────────────────────────────────────────────

fn find_element<'a>(
    doc: &'a roxmltree::Document<'a>,
    ns_uri: &str,
    local_name: &str,
) -> Option<roxmltree::Node<'a, 'a>> {
    doc.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == local_name
            && n.tag_name().namespace().unwrap_or("") == ns_uri
    })
}

fn find_child_element<'a>(
    parent: roxmltree::Node<'a, 'a>,
    ns_uri: &str,
    local_name: &str,
) -> Option<roxmltree::Node<'a, 'a>> {
    parent.children().find(|n| {
        n.is_element()
            && n.tag_name().name() == local_name
            && n.tag_name().namespace().unwrap_or("") == ns_uri
    })
}

fn build_id_map(
    doc: &roxmltree::Document<'_>,
    attr_names: &[&str],
) -> HashMap<String, roxmltree::NodeId> {
    let mut map = HashMap::new();
    for node in doc.descendants() {
        if node.is_element() {
            for attr_name in attr_names {
                if let Some(val) = node.attribute(*attr_name) {
                    map.insert(val.to_owned(), node.id());
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_cipher_data_base64() {
        // Simple test with a CipherValue element
        let xml = r#"<xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
            <xenc:CipherValue>SGVsbG8gV29ybGQ=</xenc:CipherValue>
        </xenc:CipherData>"#;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let root = doc.root_element();
        let result = read_cipher_data(root).unwrap();
        assert_eq!(result, b"Hello World");
    }
}
