#![forbid(unsafe_code)]

//! XML-Enc encryption.
//!
//! Takes a template with an empty `<EncryptedData>` element and fills
//! in the `<CipherValue>` with the encrypted data.

use crate::context::EncContext;
use bergshamra_core::{algorithm, ns, Error};

/// Encrypt XML data using a template.
///
/// The template must contain an `<EncryptedData>` element with an empty
/// `<CipherValue>`. The target data (either an element or content to
/// encrypt) is provided separately.
///
/// Returns the XML document with `<EncryptedData>` populated.
pub fn encrypt(ctx: &EncContext, template_xml: &str, data: &[u8]) -> Result<String, Error> {
    let doc = roxmltree::Document::parse(template_xml)
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    // Find EncryptedData element
    let enc_data_node = find_element(&doc, ns::ENC, ns::node::ENCRYPTED_DATA)
        .ok_or_else(|| Error::MissingElement("EncryptedData".into()))?;

    // Read EncryptionMethod
    let enc_method_node = find_child_element(enc_data_node, ns::ENC, ns::node::ENCRYPTION_METHOD)
        .ok_or_else(|| Error::MissingElement("EncryptionMethod".into()))?;
    let enc_uri = enc_method_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on EncryptionMethod".into()))?;

    // Resolve encryption key
    let key_bytes = resolve_encryption_key(ctx, enc_data_node, enc_uri)?;

    // Encrypt the data
    let cipher_alg = bergshamra_crypto::cipher::from_uri(enc_uri)?;
    let ciphertext = cipher_alg.encrypt(&key_bytes, data)?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let cipher_b64 = engine.encode(&ciphertext);

    // Replace empty CipherValue in template
    let mut result = template_xml.to_owned();

    // Try various prefix patterns
    let patterns = [
        "<xenc:CipherValue></xenc:CipherValue>",
        "<xenc:CipherValue/>",
        "<CipherValue></CipherValue>",
        "<CipherValue/>",
        "<enc:CipherValue></enc:CipherValue>",
        "<enc:CipherValue/>",
    ];

    let replacements = [
        format!("<xenc:CipherValue>{cipher_b64}</xenc:CipherValue>"),
        format!("<xenc:CipherValue>{cipher_b64}</xenc:CipherValue>"),
        format!("<CipherValue>{cipher_b64}</CipherValue>"),
        format!("<CipherValue>{cipher_b64}</CipherValue>"),
        format!("<enc:CipherValue>{cipher_b64}</enc:CipherValue>"),
        format!("<enc:CipherValue>{cipher_b64}</enc:CipherValue>"),
    ];

    for (pattern, replacement) in patterns.iter().zip(replacements.iter()) {
        if result.contains(pattern) {
            result = result.replacen(pattern, replacement, 1);
            break;
        }
    }

    // Handle EncryptedKey if present
    result = encrypt_session_key(ctx, &result, enc_uri, &key_bytes)?;

    Ok(result)
}

/// Resolve the encryption key — either from the manager or generate a session key.
fn resolve_encryption_key(
    ctx: &EncContext,
    enc_data_node: roxmltree::Node<'_, '_>,
    enc_uri: &str,
) -> Result<Vec<u8>, Error> {
    // Check KeyInfo for a key name
    let key_info = find_child_element(enc_data_node, ns::DSIG, ns::node::KEY_INFO);

    if let Some(ki) = key_info {
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

            // Check for EncryptedKey — we need a session key
            if child_ns == ns::ENC && child_local == ns::node::ENCRYPTED_KEY {
                // Generate a random session key of the right size
                return generate_session_key(enc_uri);
            }
        }
    }

    // Fallback: try first symmetric key
    let key = ctx.keys_manager.first_key()?;
    if let Some(bytes) = key.symmetric_key_bytes() {
        Ok(bytes.to_vec())
    } else {
        // Generate a session key
        generate_session_key(enc_uri)
    }
}

/// Generate a random session key for the given cipher algorithm.
fn generate_session_key(enc_uri: &str) -> Result<Vec<u8>, Error> {
    use rand::RngCore;

    let key_size = match enc_uri {
        algorithm::AES128_CBC | algorithm::AES128_GCM => 16,
        algorithm::AES192_CBC | algorithm::AES192_GCM => 24,
        algorithm::AES256_CBC | algorithm::AES256_GCM => 32,
        algorithm::TRIPLEDES_CBC => 24,
        _ => return Err(Error::UnsupportedAlgorithm(format!("cannot determine key size for: {enc_uri}"))),
    };

    let mut key = vec![0u8; key_size];
    rand::thread_rng().fill_bytes(&mut key);
    Ok(key)
}

/// Encrypt the session key into any EncryptedKey elements in the template.
fn encrypt_session_key(
    ctx: &EncContext,
    xml: &str,
    _data_enc_uri: &str,
    session_key: &[u8],
) -> Result<String, Error> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    // Find EncryptedKey elements
    let mut result = xml.to_owned();
    for node in doc.descendants() {
        if !node.is_element()
            || node.tag_name().name() != ns::node::ENCRYPTED_KEY
            || node.tag_name().namespace().unwrap_or("") != ns::ENC
        {
            continue;
        }

        // Read EncryptionMethod on EncryptedKey
        let enc_method = match find_child_element(node, ns::ENC, ns::node::ENCRYPTION_METHOD) {
            Some(m) => m,
            None => continue,
        };
        let enc_uri = match enc_method.attribute(ns::attr::ALGORITHM) {
            Some(u) => u,
            None => continue,
        };

        // Check if CipherValue is empty
        let cipher_data = match find_child_element(node, ns::ENC, ns::node::CIPHER_DATA) {
            Some(cd) => cd,
            None => continue,
        };
        let cipher_value = match find_child_element(cipher_data, ns::ENC, ns::node::CIPHER_VALUE) {
            Some(cv) => cv,
            None => continue,
        };
        let cv_text = cipher_value.text().unwrap_or("").trim();
        if !cv_text.is_empty() {
            continue; // Already filled
        }

        // Encrypt the session key
        let encrypted_key_bytes = match enc_uri {
            algorithm::RSA_PKCS1 | algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
                let transport = bergshamra_crypto::keytransport::from_uri(enc_uri)?;
                let rsa_key = ctx.keys_manager.find_rsa()
                    .ok_or_else(|| Error::Key("no RSA key for EncryptedKey".into()))?;
                let public_key = rsa_key.rsa_public_key()
                    .ok_or_else(|| Error::Key("RSA public key required".into()))?;
                transport.encrypt(public_key, session_key)?
            }
            algorithm::KW_AES128 | algorithm::KW_AES192 | algorithm::KW_AES256 => {
                let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
                let aes_key = ctx.keys_manager.find_aes()
                    .ok_or_else(|| Error::Key("no AES key for key wrap".into()))?;
                let kek_bytes = aes_key.symmetric_key_bytes()
                    .ok_or_else(|| Error::Key("AES key has no bytes".into()))?;
                kw.wrap(kek_bytes, session_key)?
            }
            _ => return Err(Error::UnsupportedAlgorithm(format!("EncryptedKey method: {enc_uri}"))),
        };

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let ek_b64 = engine.encode(&encrypted_key_bytes);

        // Replace the empty CipherValue for this EncryptedKey
        // Use text replacement based on the element's byte range
        let cv_range = cipher_value.range();
        let cv_xml = &xml[cv_range.start..cv_range.end];

        // Build the replacement
        // The original is something like <xenc:CipherValue/> or <xenc:CipherValue></xenc:CipherValue>
        // We need to figure out the prefix used
        let prefix = extract_prefix(cv_xml, "CipherValue");
        let replacement = if prefix.is_empty() {
            format!("<CipherValue>{ek_b64}</CipherValue>")
        } else {
            format!("<{prefix}:CipherValue>{ek_b64}</{prefix}:CipherValue>")
        };

        result = result.replacen(cv_xml, &replacement, 1);
    }

    Ok(result)
}

/// Extract namespace prefix from an element tag like "<xenc:CipherValue...>"
fn extract_prefix<'a>(xml_fragment: &'a str, local_name: &str) -> &'a str {
    // Look for <prefix:localName or <localName
    let trimmed = xml_fragment.trim_start_matches('<');
    if let Some(colon_pos) = trimmed.find(':') {
        let after_colon = &trimmed[colon_pos + 1..];
        if after_colon.starts_with(local_name) {
            return &trimmed[..colon_pos];
        }
    }
    ""
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
