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
    let bytes = decrypt_to_bytes(ctx, xml)?;
    String::from_utf8(bytes)
        .map_err(|e| Error::Decryption(format!("plaintext is not valid UTF-8: {e}")))
}

/// Decrypt an XML document containing `<EncryptedData>`.
///
/// Returns the raw decrypted bytes, supporting non-UTF-8 content.
pub fn decrypt_to_bytes(ctx: &EncContext, xml: &str) -> Result<Vec<u8>, Error> {
    let doc = roxmltree::Document::parse_with_options(xml, bergshamra_xml::parsing_options())
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
    let key_bytes = resolve_decryption_key(ctx, enc_data_node, &doc, &id_map, enc_uri)?;

    // Read CipherData/CipherValue
    let cipher_data_node = find_child_element(enc_data_node, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData".into()))?;

    let cipher_bytes = read_cipher_data(ctx, cipher_data_node, &doc, &id_map)?;

    // Truncate the session key to the cipher's expected size if it's longer.
    // xmlsec1 may wrap a larger key than the EncryptionMethod requires
    // (e.g. --session-key aes-256 with aes128-gcm EncryptionMethod).
    let expected_key_size = key_length_for_algorithm(enc_uri);
    let effective_key = if key_bytes.len() > expected_key_size && expected_key_size > 0 {
        &key_bytes[..expected_key_size]
    } else {
        &key_bytes
    };

    // Decrypt
    let cipher_alg = bergshamra_crypto::cipher::from_uri(enc_uri)?;
    let plaintext = cipher_alg.decrypt(effective_key, &cipher_bytes)?;

    // Replace EncryptedData with plaintext
    let result = replace_encrypted_data_bytes(xml, enc_data_node, enc_type, &plaintext)?;

    // If the document declares a non-UTF-8 encoding (e.g., ISO-8859-1),
    // convert the UTF-8 output to that encoding. The decrypted content from
    // the cipher is always UTF-8 (xmlsec1/libxml2 stores UTF-8 internally),
    // but the original document may use a different encoding.
    Ok(maybe_convert_encoding(&result))
}

/// If the output declares `encoding="ISO-8859-1"` (or similar Latin-1 variant),
/// convert UTF-8 bytes to Latin-1. Returns the input unchanged if no conversion needed.
fn maybe_convert_encoding(data: &[u8]) -> Vec<u8> {
    // Quick check: look for encoding declaration in the first ~200 bytes
    let header = &data[..data.len().min(200)];
    let header_str = match std::str::from_utf8(header) {
        Ok(s) => s,
        Err(_) => return data.to_vec(),
    };
    let header_lower = header_str.to_lowercase();
    if !header_lower.contains("encoding=\"iso-8859-1\"")
        && !header_lower.contains("encoding='iso-8859-1'")
    {
        return data.to_vec();
    }
    // Convert UTF-8 → ISO-8859-1
    utf8_to_latin1(data)
}

/// Convert UTF-8 bytes to ISO-8859-1. Characters in U+0080..U+00FF become
/// single bytes. Characters outside U+0000..U+00FF are passed through as-is
/// (they can't be represented in Latin-1 but we preserve them for safety).
fn utf8_to_latin1(data: &[u8]) -> Vec<u8> {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return data.to_vec(),
    };
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        if (ch as u32) <= 0xFF {
            out.push(ch as u8);
        } else {
            // Can't represent in Latin-1; encode as UTF-8 bytes
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf);
            out.extend_from_slice(encoded.as_bytes());
        }
    }
    out
}

/// Resolve the decryption key from KeyInfo or EncryptedKey.
fn resolve_decryption_key(
    ctx: &EncContext,
    enc_data_node: roxmltree::Node<'_, '_>,
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
    enc_uri: &str,
) -> Result<Vec<u8>, Error> {
    let key_info_node = find_child_element(enc_data_node, ns::DSIG, ns::node::KEY_INFO);

    if let Some(ki) = key_info_node {
        // Try all EncryptedKey elements inside KeyInfo — use the first that succeeds
        let mut last_ek_error = None;
        for child in ki.children() {
            if !child.is_element() {
                continue;
            }
            let child_ns = child.tag_name().namespace().unwrap_or("");
            let child_local = child.tag_name().name();

            if child_ns == ns::ENC && child_local == ns::node::ENCRYPTED_KEY {
                match decrypt_encrypted_key(ctx, child, doc, id_map) {
                    Ok(key) => return Ok(key),
                    Err(e) => {
                        last_ek_error = Some(e);
                    }
                }
            }

            // Try DerivedKey (ConcatKDF / PBKDF2)
            if child_ns == ns::ENC11 && child_local == ns::node::DERIVED_KEY {
                if let Ok(key) = resolve_derived_key(ctx, child, enc_uri) {
                    return Ok(key);
                }
            }
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
                                    let target = doc.get_node(node_id).ok_or_else(|| {
                                        Error::InvalidUri(format!("cannot resolve #{id}"))
                                    })?;
                                    return decrypt_encrypted_key(ctx, target, doc, id_map);
                                }
                            }
                        }
                    }
                }
            }
        }

        // If we tried EncryptedKey elements but all failed, return the last error
        if let Some(e) = last_ek_error {
            return Err(e);
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
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
) -> Result<Vec<u8>, Error> {
    // Read EncryptionMethod on EncryptedKey
    let enc_method = find_child_element(enc_key_node, ns::ENC, ns::node::ENCRYPTION_METHOD)
        .ok_or_else(|| Error::MissingElement("EncryptionMethod on EncryptedKey".into()))?;
    let enc_uri = enc_method.attribute(ns::attr::ALGORITHM).ok_or_else(|| {
        Error::MissingAttribute("Algorithm on EncryptedKey EncryptionMethod".into())
    })?;

    // Read CipherData/CipherValue
    let cipher_data = find_child_element(enc_key_node, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData on EncryptedKey".into()))?;
    let cipher_bytes = read_cipher_data(ctx, cipher_data, doc, id_map)?;

    // Determine key unwrap method
    match enc_uri {
        // RSA key transport
        algorithm::RSA_PKCS1 | algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
            // Extract OAEP params from EncryptionMethod child elements
            let oaep_params = read_oaep_params(enc_method);
            let transport =
                bergshamra_crypto::keytransport::from_uri_with_params(enc_uri, oaep_params)?;
            // Prefer RSA private key; fall back to first RSA key
            let rsa_key = ctx
                .keys_manager
                .find_rsa_private()
                .or_else(|| ctx.keys_manager.find_rsa())
                .ok_or_else(|| Error::Key("no RSA key for EncryptedKey decryption".into()))?;
            let private_key = rsa_key
                .rsa_private_key()
                .ok_or_else(|| Error::Key("RSA private key required for key transport".into()))?;
            transport.decrypt(private_key, &cipher_bytes)
        }

        // AES Key Wrap — select key by expected size, or derive via ECDH-ES
        algorithm::KW_AES128 | algorithm::KW_AES192 | algorithm::KW_AES256 => {
            let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
            let expected_kek_size = match enc_uri {
                algorithm::KW_AES128 => 16,
                algorithm::KW_AES192 => 24,
                algorithm::KW_AES256 => 32,
                _ => 0,
            };
            // Try ECDH-ES key agreement first
            if let Some(kek) = resolve_agreement_method_kek(ctx, enc_key_node, expected_kek_size)? {
                return kw.unwrap(&kek, &cipher_bytes);
            }
            // Fall back to named/static AES key
            let aes_key = ctx
                .keys_manager
                .find_aes_by_size(expected_kek_size)
                .or_else(|| ctx.keys_manager.find_aes())
                .ok_or_else(|| Error::Key("no AES key for key unwrap".into()))?;
            let kek_bytes = aes_key
                .symmetric_key_bytes()
                .ok_or_else(|| Error::Key("AES key has no bytes".into()))?;
            kw.unwrap(kek_bytes, &cipher_bytes)
        }

        // 3DES Key Wrap
        algorithm::KW_TRIPLEDES => {
            let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
            let des_key = ctx
                .keys_manager
                .find_des3()
                .or_else(|| ctx.keys_manager.first_key().ok())
                .ok_or_else(|| Error::Key("no symmetric key for 3DES key unwrap".into()))?;
            let kek_bytes = des_key
                .symmetric_key_bytes()
                .ok_or_else(|| Error::Key("no symmetric key for 3DES key unwrap".into()))?;
            kw.unwrap(kek_bytes, &cipher_bytes)
        }

        // Regular cipher (AES-CBC/GCM, 3DES-CBC) used to encrypt key material
        algorithm::AES128_CBC
        | algorithm::AES192_CBC
        | algorithm::AES256_CBC
        | algorithm::AES128_GCM
        | algorithm::AES192_GCM
        | algorithm::AES256_GCM
        | algorithm::TRIPLEDES_CBC => {
            let cipher = bergshamra_crypto::cipher::from_uri(enc_uri)?;
            let kek_bytes = resolve_encrypted_key_kek(ctx, enc_key_node)?;
            cipher.decrypt(&kek_bytes, &cipher_bytes)
        }

        _ => Err(Error::UnsupportedAlgorithm(format!(
            "EncryptedKey method: {enc_uri}"
        ))),
    }
}

/// Resolve the key-encryption key (KEK) for an EncryptedKey that uses a regular cipher.
fn resolve_encrypted_key_kek(
    ctx: &EncContext,
    enc_key_node: roxmltree::Node<'_, '_>,
) -> Result<Vec<u8>, Error> {
    if let Some(ki) = find_child_element(enc_key_node, ns::DSIG, ns::node::KEY_INFO) {
        // Try KeyName lookup
        if let Some(key_name_node) = find_child_element(ki, ns::DSIG, ns::node::KEY_NAME) {
            let name = key_name_node.text().unwrap_or("").trim();
            if !name.is_empty() {
                if let Some(key) = ctx.keys_manager.find_by_name(name) {
                    if let Some(bytes) = key.symmetric_key_bytes() {
                        return Ok(bytes.to_vec());
                    }
                }
            }
        }
    }
    // Fallback: try first symmetric key from manager
    let key = ctx.keys_manager.first_key()?;
    key.symmetric_key_bytes()
        .map(|b| b.to_vec())
        .ok_or_else(|| Error::Key("no symmetric key for EncryptedKey cipher decryption".into()))
}

/// Resolve KEK via key agreement (ECDH-ES or DH-ES) in EncryptedKey KeyInfo.
///
/// Returns `Ok(Some(kek))` if an AgreementMethod was found and key agreement succeeded,
/// `Ok(None)` if no AgreementMethod is present, or `Err` on failure.
fn resolve_agreement_method_kek(
    ctx: &EncContext,
    enc_key_node: roxmltree::Node<'_, '_>,
    kek_len: usize,
) -> Result<Option<Vec<u8>>, Error> {
    let ki = match find_child_element(enc_key_node, ns::DSIG, ns::node::KEY_INFO) {
        Some(ki) => ki,
        None => return Ok(None),
    };

    // Look for <AgreementMethod> (in xenc namespace)
    let agreement = match find_child_element(ki, ns::ENC, ns::node::AGREEMENT_METHOD) {
        Some(a) => a,
        None => return Ok(None),
    };

    let agreement_alg = agreement.attribute(ns::attr::ALGORITHM).unwrap_or("");

    // Extract originator's public key from <OriginatorKeyInfo>
    let originator_ki = find_child_element(agreement, ns::ENC, ns::node::ORIGINATOR_KEY_INFO)
        .ok_or_else(|| Error::MissingElement("OriginatorKeyInfo".into()))?;

    // Compute shared secret based on agreement algorithm
    let shared_secret = match agreement_alg {
        algorithm::ECDH_ES => {
            let originator_public_bytes = extract_ec_public_key_bytes(originator_ki)?;
            let recipient_key = resolve_recipient_key(ctx, agreement)?;

            match &recipient_key.data {
                bergshamra_keys::key::KeyData::EcP256 {
                    private: Some(sk), ..
                } => {
                    let secret = p256::SecretKey::from_bytes(&sk.to_bytes())
                        .map_err(|e| Error::Key(format!("P-256 secret key: {e}")))?;
                    bergshamra_crypto::keyagreement::ecdh_p256(&originator_public_bytes, &secret)?
                }
                bergshamra_keys::key::KeyData::EcP384 {
                    private: Some(sk), ..
                } => {
                    let secret = p384::SecretKey::from_bytes(&sk.to_bytes())
                        .map_err(|e| Error::Key(format!("P-384 secret key: {e}")))?;
                    bergshamra_crypto::keyagreement::ecdh_p384(&originator_public_bytes, &secret)?
                }
                bergshamra_keys::key::KeyData::EcP521 {
                    private: Some(sk), ..
                } => {
                    use p521::elliptic_curve::generic_array::GenericArray;
                    let bytes = sk.to_bytes();
                    let secret = p521::SecretKey::from_bytes(GenericArray::from_slice(&bytes))
                        .map_err(|e| Error::Key(format!("P-521 secret key: {e}")))?;
                    bergshamra_crypto::keyagreement::ecdh_p521(&originator_public_bytes, &secret)?
                }
                _ => {
                    return Err(Error::Key("recipient key is not an EC private key".into()));
                }
            }
        }
        algorithm::DH_ES => {
            // Finite-field Diffie-Hellman key agreement
            let originator_dh = extract_dh_public_key_from_xml(originator_ki)?;
            let recipient_key = resolve_recipient_key(ctx, agreement)?;

            match &recipient_key.data {
                bergshamra_keys::key::KeyData::Dh {
                    p,
                    q,
                    private_key: Some(x),
                    ..
                } => {
                    let q_bytes = q.as_deref().ok_or_else(|| {
                        Error::Key("DH subgroup order q is required for DH-ES".into())
                    })?;
                    bergshamra_crypto::keyagreement::dh_compute(
                        &originator_dh.public_key,
                        x,
                        p,
                        Some(q_bytes),
                    )?
                }
                _ => {
                    return Err(Error::Key("recipient key is not a DH private key".into()));
                }
            }
        }
        _ => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "key agreement: {agreement_alg}"
            )));
        }
    };

    // Apply KDF to derive KEK
    let kdf_method = find_child_element(agreement, ns::ENC11, ns::node::KEY_DERIVATION_METHOD);
    let kek = match kdf_method {
        Some(kdm) => {
            let kdf_uri = kdm.attribute(ns::attr::ALGORITHM).unwrap_or("");
            match kdf_uri {
                algorithm::CONCAT_KDF => {
                    let params = parse_concat_kdf_params(kdm)?;
                    bergshamra_crypto::kdf::concat_kdf(&shared_secret, kek_len, &params)?
                }
                algorithm::PBKDF2 => {
                    let params = parse_pbkdf2_params(kdm, kek_len)?;
                    bergshamra_crypto::kdf::pbkdf2_derive(&shared_secret, &params)?
                }
                _ => {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "key derivation: {kdf_uri}"
                    )));
                }
            }
        }
        None => {
            // No KDF — use raw shared secret (truncated to kek_len)
            shared_secret[..kek_len.min(shared_secret.len())].to_vec()
        }
    };

    Ok(Some(kek))
}

/// Extract raw EC public key bytes (SEC1 uncompressed point) from a KeyInfo-like element.
fn extract_ec_public_key_bytes(key_info_node: roxmltree::Node<'_, '_>) -> Result<Vec<u8>, Error> {
    // Look for <KeyValue><ECKeyValue><PublicKey>
    let key_value = find_child_element(key_info_node, ns::DSIG, ns::node::KEY_VALUE)
        .ok_or_else(|| Error::MissingElement("KeyValue in OriginatorKeyInfo".into()))?;

    let ec_kv = key_value
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == ns::node::EC_KEY_VALUE
                && (n.tag_name().namespace().unwrap_or("") == ns::DSIG11
                    || n.tag_name().namespace().unwrap_or("") == ns::DSIG)
        })
        .ok_or_else(|| Error::MissingElement("ECKeyValue".into()))?;

    let public_key_b64 = ec_kv
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == ns::node::PUBLIC_KEY)
        .and_then(|n| n.text())
        .ok_or_else(|| Error::MissingElement("PublicKey in ECKeyValue".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    engine
        .decode(public_key_b64.trim().replace(['\n', '\r', ' '], ""))
        .map_err(|e| Error::Base64(format!("EC PublicKey: {e}")))
}

/// Resolve the recipient's private key from AgreementMethod (EC or DH).
fn resolve_recipient_key<'a>(
    ctx: &'a EncContext,
    agreement_node: roxmltree::Node<'_, '_>,
) -> Result<&'a bergshamra_keys::key::Key, Error> {
    // Try RecipientKeyInfo → KeyName
    if let Some(rki) = find_child_element(agreement_node, ns::ENC, ns::node::RECIPIENT_KEY_INFO) {
        if let Some(key_name_node) = find_child_element(rki, ns::DSIG, ns::node::KEY_NAME) {
            let name = key_name_node.text().unwrap_or("").trim();
            if !name.is_empty() {
                if let Some(key) = ctx.keys_manager.find_by_name(name) {
                    return Ok(key);
                }
            }
        }
    }

    // Fallback: try first DH key, then EC key with a private key
    if let Some(dh_key) = ctx.keys_manager.find_dh() {
        if matches!(
            &dh_key.data,
            bergshamra_keys::key::KeyData::Dh {
                private_key: Some(_),
                ..
            }
        ) {
            return Ok(dh_key);
        }
    }
    ctx.keys_manager
        .find_ec_p256()
        .filter(|k| {
            matches!(
                &k.data,
                bergshamra_keys::key::KeyData::EcP256 {
                    private: Some(_),
                    ..
                }
            )
        })
        .or_else(|| {
            ctx.keys_manager.find_ec_p384().filter(|k| {
                matches!(
                    &k.data,
                    bergshamra_keys::key::KeyData::EcP384 {
                        private: Some(_),
                        ..
                    }
                )
            })
        })
        .or_else(|| {
            ctx.keys_manager.find_ec_p521().filter(|k| {
                matches!(
                    &k.data,
                    bergshamra_keys::key::KeyData::EcP521 {
                        private: Some(_),
                        ..
                    }
                )
            })
        })
        .ok_or_else(|| Error::Key("no private key for key agreement".into()))
}

/// Parsed DH public key parameters from XML DHKeyValue.
struct DhPublicKeyXml {
    public_key: Vec<u8>,
}

/// Extract DH public key bytes from a KeyInfo element containing DHKeyValue.
///
/// Looks for `<KeyValue><DHKeyValue><Public>...</Public></DHKeyValue></KeyValue>`.
/// The P, G, Q parameters are also in the DHKeyValue but we don't need them here
/// (they come from the recipient's stored key).
fn extract_dh_public_key_from_xml(
    key_info_node: roxmltree::Node<'_, '_>,
) -> Result<DhPublicKeyXml, Error> {
    let key_value = find_child_element(key_info_node, ns::DSIG, ns::node::KEY_VALUE)
        .ok_or_else(|| Error::MissingElement("KeyValue in OriginatorKeyInfo".into()))?;

    let dh_kv = key_value
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == ns::node::DH_KEY_VALUE
                && (n.tag_name().namespace().unwrap_or("") == ns::ENC
                    || n.tag_name().namespace().unwrap_or("") == ns::DSIG)
        })
        .ok_or_else(|| Error::MissingElement("DHKeyValue".into()))?;

    let public_b64 = dh_kv
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Public")
        .and_then(|n| n.text())
        .ok_or_else(|| Error::MissingElement("Public in DHKeyValue".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let public_key = engine
        .decode(public_b64.trim().replace(['\n', '\r', ' '], ""))
        .map_err(|e| Error::Base64(format!("DH Public: {e}")))?;

    Ok(DhPublicKeyXml { public_key })
}

/// Resolve a DerivedKey element to get the encryption key via ConcatKDF or PBKDF2.
pub(crate) fn resolve_derived_key(
    ctx: &EncContext,
    derived_key_node: roxmltree::Node<'_, '_>,
    enc_uri: &str,
) -> Result<Vec<u8>, Error> {
    // Get the master key name
    let master_key_name =
        find_child_element(derived_key_node, ns::ENC11, ns::node::MASTER_KEY_NAME)
            .and_then(|n| n.text())
            .map(|t| t.trim())
            .unwrap_or("");

    // Look up master key in keys manager
    let master_key_bytes = if !master_key_name.is_empty() {
        if let Some(key) = ctx.keys_manager.find_by_name(master_key_name) {
            key.symmetric_key_bytes()
                .map(|b| b.to_vec())
                .ok_or_else(|| {
                    Error::Key(format!(
                        "master key '{}' has no symmetric data",
                        master_key_name
                    ))
                })?
        } else {
            return Err(Error::KeyNotFound(format!(
                "master key '{}' not found",
                master_key_name
            )));
        }
    } else {
        // Fall back to first key
        let key = ctx.keys_manager.first_key()?;
        key.symmetric_key_bytes()
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Key("no master key for DerivedKey".into()))?
    };

    // Parse KeyDerivationMethod
    let kd_method =
        find_child_element(derived_key_node, ns::ENC11, ns::node::KEY_DERIVATION_METHOD)
            .ok_or_else(|| Error::MissingElement("KeyDerivationMethod".into()))?;
    let kd_alg = kd_method
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on KeyDerivationMethod".into()))?;

    // Determine key length from the encryption algorithm
    let key_len = key_length_for_algorithm(enc_uri);

    match kd_alg {
        algorithm::CONCAT_KDF => {
            let params = parse_concat_kdf_params(kd_method)?;
            bergshamra_crypto::kdf::concat_kdf(&master_key_bytes, key_len, &params)
        }
        algorithm::PBKDF2 => {
            let params = parse_pbkdf2_params(kd_method, key_len)?;
            bergshamra_crypto::kdf::pbkdf2_derive(&master_key_bytes, &params)
        }
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "key derivation method: {kd_alg}"
        ))),
    }
}

/// Determine the required key length in bytes for an encryption algorithm.
fn key_length_for_algorithm(uri: &str) -> usize {
    match uri {
        algorithm::AES128_CBC | algorithm::AES128_GCM => 16,
        algorithm::AES192_CBC | algorithm::AES192_GCM => 24,
        algorithm::AES256_CBC | algorithm::AES256_GCM => 32,
        algorithm::TRIPLEDES_CBC => 24,
        _ => 32, // default
    }
}

/// Parse ConcatKDF parameters from a KeyDerivationMethod element.
pub(crate) fn parse_concat_kdf_params(
    kd_method: roxmltree::Node<'_, '_>,
) -> Result<bergshamra_crypto::kdf::ConcatKdfParams, Error> {
    let mut params = bergshamra_crypto::kdf::ConcatKdfParams::default();

    let concat_params = find_child_element(kd_method, ns::ENC11, ns::node::CONCAT_KDF_PARAMS);
    if let Some(cp) = concat_params {
        // Parse hex-encoded attributes.
        // Per NIST SP 800-56A, the first byte is a padding indicator (00 = byte-aligned).
        // xmlsec strips this leading byte before using the data.
        if let Some(alg_id) = cp.attribute("AlgorithmID") {
            params.algorithm_id = hex_decode_strip_pad(alg_id).ok();
        }
        if let Some(party_u) = cp.attribute("PartyUInfo") {
            params.party_u_info = hex_decode_strip_pad(party_u).ok();
        }
        if let Some(party_v) = cp.attribute("PartyVInfo") {
            params.party_v_info = hex_decode_strip_pad(party_v).ok();
        }
        // DigestMethod child
        if let Some(dm) = find_child_element(cp, ns::DSIG, ns::node::DIGEST_METHOD) {
            params.digest_uri = dm.attribute(ns::attr::ALGORITHM).map(|s| s.to_owned());
        }
    }

    Ok(params)
}

/// Parse PBKDF2 parameters from a KeyDerivationMethod element.
pub(crate) fn parse_pbkdf2_params(
    kd_method: roxmltree::Node<'_, '_>,
    default_key_len: usize,
) -> Result<bergshamra_crypto::kdf::Pbkdf2Params, Error> {
    let pbkdf2_params_node = find_child_element(kd_method, ns::ENC11, ns::node::PBKDF2_PARAMS)
        .ok_or_else(|| Error::MissingElement("PBKDF2-params".into()))?;

    // Salt
    let salt_node = find_child_element(pbkdf2_params_node, ns::ENC11, ns::node::PBKDF2_SALT)
        .ok_or_else(|| Error::MissingElement("Salt in PBKDF2-params".into()))?;
    let specified_node = find_child_element(salt_node, ns::ENC11, ns::node::PBKDF2_SALT_SPECIFIED)
        .ok_or_else(|| Error::MissingElement("Specified in Salt".into()))?;
    let salt_b64 = specified_node.text().unwrap_or("").trim();
    let salt = {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let clean: String = salt_b64.chars().filter(|c| !c.is_whitespace()).collect();
        engine
            .decode(&clean)
            .map_err(|e| Error::Base64(format!("PBKDF2 salt: {e}")))?
    };

    // IterationCount
    let iter_count_node = find_child_element(
        pbkdf2_params_node,
        ns::ENC11,
        ns::node::PBKDF2_ITERATION_COUNT,
    )
    .ok_or_else(|| Error::MissingElement("IterationCount in PBKDF2-params".into()))?;
    let iteration_count: u32 = iter_count_node
        .text()
        .unwrap_or("0")
        .trim()
        .parse()
        .map_err(|_| Error::XmlStructure("invalid IterationCount".into()))?;

    // KeyLength (optional, defaults to encryption algorithm key length)
    let key_length = if let Some(kl_node) =
        find_child_element(pbkdf2_params_node, ns::ENC11, ns::node::PBKDF2_KEY_LENGTH)
    {
        kl_node
            .text()
            .unwrap_or("0")
            .trim()
            .parse::<usize>()
            .unwrap_or(default_key_len)
    } else {
        default_key_len
    };

    // PRF (pseudo-random function)
    let prf_node = find_child_element(pbkdf2_params_node, ns::ENC11, ns::node::PBKDF2_PRF)
        .ok_or_else(|| Error::MissingElement("PRF in PBKDF2-params".into()))?;
    let prf_uri = prf_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on PRF".into()))?
        .to_owned();

    Ok(bergshamra_crypto::kdf::Pbkdf2Params {
        prf_uri,
        salt,
        iteration_count,
        key_length,
    })
}

/// Decode a hex string.
fn hex_decode(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim();
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    // Ensure even length
    let hex_str = if hex_str.len() % 2 != 0 {
        format!("0{hex_str}")
    } else {
        hex_str.to_owned()
    };
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|_| Error::Other(format!("invalid hex: {s}")))
        })
        .collect()
}

/// Decode a hex string and strip the NIST SP 800-56A padding indicator byte.
/// The first byte indicates how many bits in the last byte are padding (00 = byte-aligned).
fn hex_decode_strip_pad(s: &str) -> Result<Vec<u8>, Error> {
    let bytes = hex_decode(s)?;
    if bytes.len() > 1 {
        Ok(bytes[1..].to_vec())
    } else {
        Ok(bytes)
    }
}

/// Read RSA-OAEP parameters from EncryptionMethod child elements.
fn read_oaep_params(
    enc_method: roxmltree::Node<'_, '_>,
) -> bergshamra_crypto::keytransport::OaepParams {
    let mut params = bergshamra_crypto::keytransport::OaepParams::default();

    for child in enc_method.children() {
        if !child.is_element() {
            continue;
        }
        let local = child.tag_name().name();
        let child_ns = child.tag_name().namespace().unwrap_or("");

        // DigestMethod (in dsig namespace)
        if local == ns::node::DIGEST_METHOD && (child_ns == ns::DSIG || child_ns == ns::ENC) {
            if let Some(alg) = child.attribute(ns::attr::ALGORITHM) {
                params.digest_uri = Some(alg.to_owned());
            }
        }
        // MGF (in xmlenc11 namespace)
        if local == ns::node::RSA_MGF && (child_ns == ns::ENC11 || child_ns == ns::ENC) {
            if let Some(alg) = child.attribute(ns::attr::ALGORITHM) {
                params.mgf_uri = Some(alg.to_owned());
            }
        }
        // OAEPparams (in xmlenc namespace)
        if local == ns::node::RSA_OAEP_PARAMS {
            if let Some(text) = child.text() {
                let clean: String = text.trim().chars().filter(|c| !c.is_whitespace()).collect();
                use base64::Engine;
                let engine = base64::engine::general_purpose::STANDARD;
                if let Ok(bytes) = engine.decode(&clean) {
                    params.oaep_params = Some(bytes);
                }
            }
        }
    }

    params
}

/// Read CipherData — extract CipherValue (Base64) or CipherReference.
fn read_cipher_data(
    ctx: &EncContext,
    cipher_data_node: roxmltree::Node<'_, '_>,
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
) -> Result<Vec<u8>, Error> {
    // Try CipherValue first
    if let Some(cipher_value) =
        find_child_element(cipher_data_node, ns::ENC, ns::node::CIPHER_VALUE)
    {
        let b64_text = cipher_value.text().unwrap_or("").trim();
        let clean: String = b64_text.chars().filter(|c| !c.is_whitespace()).collect();

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        return engine
            .decode(&clean)
            .map_err(|e| Error::Base64(format!("CipherValue: {e}")));
    }

    // CipherReference: resolve URI and apply transforms
    if let Some(cipher_ref) =
        find_child_element(cipher_data_node, ns::ENC, ns::node::CIPHER_REFERENCE)
    {
        if ctx.disable_cipher_reference {
            return Err(Error::Other(
                "CipherReference resolution is disabled".into(),
            ));
        }
        return resolve_cipher_reference(cipher_ref, doc, id_map);
    }

    Err(Error::MissingElement(
        "CipherValue or CipherReference".into(),
    ))
}

/// Resolve a CipherReference element to get cipher bytes.
fn resolve_cipher_reference(
    cipher_ref: roxmltree::Node<'_, '_>,
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
) -> Result<Vec<u8>, Error> {
    let uri = cipher_ref
        .attribute(ns::attr::URI)
        .ok_or_else(|| Error::MissingAttribute("URI on CipherReference".into()))?;

    // Resolve same-document URI reference
    let data = if uri.is_empty() {
        // URI="" means the whole document — transforms will select specific content
        // Collect all text content from all nodes
        let mut text = String::new();
        for node in doc.root().descendants() {
            if node.is_text() {
                if let Some(t) = node.text() {
                    text.push_str(t);
                }
            }
        }
        text.into_bytes()
    } else if let Some(id) = uri.strip_prefix('#') {
        // Look up by ID
        let &node_id = id_map
            .get(id)
            .ok_or_else(|| Error::InvalidUri(format!("cannot resolve CipherReference #{id}")))?;
        let target = doc
            .get_node(node_id)
            .ok_or_else(|| Error::InvalidUri(format!("cannot resolve CipherReference #{id}")))?;
        // Collect all text content from the target element
        collect_text_content(target).into_bytes()
    } else {
        return Err(Error::UnsupportedAlgorithm(format!(
            "CipherReference with non-fragment URI not supported: {uri}"
        )));
    };

    // Apply transforms if present
    let transforms_node = find_child_element(cipher_ref, ns::ENC, ns::node::TRANSFORMS)
        .or_else(|| find_child_element(cipher_ref, ns::DSIG, ns::node::TRANSFORMS));

    let mut result = data;
    if let Some(transforms) = transforms_node {
        for child in transforms.children() {
            if !child.is_element() {
                continue;
            }
            if child.tag_name().name() != ns::node::TRANSFORM {
                continue;
            }
            let alg = child.attribute(ns::attr::ALGORITHM).unwrap_or("");
            match alg {
                algorithm::BASE64 => {
                    use base64::Engine;
                    let engine = base64::engine::general_purpose::STANDARD;
                    let text = String::from_utf8_lossy(&result);
                    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                    result = engine.decode(&clean).map_err(|e| {
                        Error::Base64(format!("CipherReference base64 transform: {e}"))
                    })?;
                }
                algorithm::XPATH => {
                    // XPath transform for CipherReference: evaluate XPath on the
                    // document and collect matching text content.
                    result = apply_cipher_ref_xpath(doc, id_map, &child)?;
                }
                _ => {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "CipherReference transform: {alg}"
                    )));
                }
            }
        }
    }

    Ok(result)
}

/// Apply an XPath transform for CipherReference.
///
/// Supports the pattern:
///   `self::text()[parent::PREFIX:ELEM[@Id="VALUE"]]`
/// which selects text nodes whose parent element matches the given
/// namespace-qualified name and has Id=VALUE.
fn apply_cipher_ref_xpath(
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
    transform_node: &roxmltree::Node<'_, '_>,
) -> Result<Vec<u8>, Error> {
    // Get the XPath expression text
    let xpath_node = transform_node
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "XPath")
        .ok_or_else(|| Error::MissingElement("XPath in CipherReference transform".into()))?;
    let xpath_text = xpath_node.text().unwrap_or("").trim();

    // Parse: self::text()[parent::PREFIX:ELEM[@Id="VALUE"]]
    // A simple regex-style parser for this specific pattern
    if let Some(rest) = xpath_text.strip_prefix("self::text()[parent::") {
        if let Some(rest) = rest.strip_suffix(']') {
            // rest = PREFIX:ELEM[@Id="VALUE"]
            // Split off the predicate
            if let Some(bracket_pos) = rest.find('[') {
                let name_part = &rest[..bracket_pos]; // PREFIX:ELEM
                let pred_part = &rest[bracket_pos..]; // [@Id="VALUE"]

                // Parse the element name (PREFIX:LOCAL)
                let (prefix, local_name) = if let Some(colon_pos) = name_part.find(':') {
                    (&name_part[..colon_pos], &name_part[colon_pos + 1..])
                } else {
                    ("", name_part)
                };

                // Resolve prefix to namespace URI using the XPath element's namespace declarations
                let ns_uri = if prefix.is_empty() {
                    ""
                } else {
                    xpath_node.lookup_namespace_uri(Some(prefix)).unwrap_or("")
                };

                // Parse predicate: [@Id="VALUE"] or [@Id='VALUE']
                let id_value = parse_attr_predicate(pred_part, "Id");

                // Find matching element and collect its text children
                if let Some(id_val) = id_value {
                    // Look up by ID first for efficiency
                    if let Some(&node_id) = id_map.get(id_val) {
                        if let Some(target) = doc.get_node(node_id) {
                            let target_ns = target.tag_name().namespace().unwrap_or("");
                            let target_local = target.tag_name().name();
                            if target_ns == ns_uri && target_local == local_name {
                                return Ok(collect_text_content(target).into_bytes());
                            }
                        }
                    }
                }

                // Fall back to scanning all elements
                for node in doc.root().descendants() {
                    if !node.is_element() {
                        continue;
                    }
                    let node_ns = node.tag_name().namespace().unwrap_or("");
                    let node_local = node.tag_name().name();
                    if node_ns == ns_uri && node_local == local_name {
                        if let Some(id_val) = id_value {
                            let node_id_attr = node.attribute("Id").unwrap_or("");
                            if node_id_attr != id_val {
                                continue;
                            }
                        }
                        return Ok(collect_text_content(node).into_bytes());
                    }
                }

                return Err(Error::Transform(format!(
                    "CipherReference XPath: no matching element for {xpath_text}"
                )));
            }
        }
    }

    Err(Error::UnsupportedAlgorithm(format!(
        "CipherReference XPath expression not supported: {xpath_text}"
    )))
}

/// Parse a simple attribute predicate like `[@Id="VALUE"]` or `[@Id='VALUE']`.
/// Returns the attribute value if matched.
fn parse_attr_predicate<'a>(pred: &'a str, attr_name: &str) -> Option<&'a str> {
    // Expected format: [@Name="Value"] or [@Name='Value']
    let inner = pred.strip_prefix("[@")?.strip_suffix(']')?;
    let rest = inner.strip_prefix(attr_name)?.strip_prefix('=')?;
    // Handle both single and double quotes
    if let Some(val) = rest.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Some(val);
    }
    if let Some(val) = rest.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return Some(val);
    }
    None
}

/// Collect all text content from a node and its descendants.
fn collect_text_content(node: roxmltree::Node<'_, '_>) -> String {
    let mut text = String::new();
    for descendant in node.descendants() {
        if descendant.is_text() {
            if let Some(t) = descendant.text() {
                text.push_str(t);
            }
        }
    }
    text
}

/// Replace the <EncryptedData> element in the XML string with the decrypted plaintext (bytes).
fn replace_encrypted_data_bytes(
    xml: &str,
    enc_data_node: roxmltree::Node<'_, '_>,
    enc_type: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    // When Type is not Element or Content (e.g., MimeType="text/plain" with no Type,
    // or any non-XML type), the plaintext is opaque data — return it as-is.
    let is_xml_type =
        enc_type.is_empty() || enc_type.ends_with("#Element") || enc_type.ends_with("#Content");
    if !is_xml_type {
        return Ok(plaintext.to_vec());
    }

    // If no Type is specified but EncryptedData has a MimeType that's not XML,
    // treat the plaintext as opaque data.
    if enc_type.is_empty() {
        let mime = enc_data_node.attribute("MimeType").unwrap_or("");
        if !mime.is_empty() && !mime.contains("xml") {
            return Ok(plaintext.to_vec());
        }
    }

    let range = enc_data_node.range();
    let start = range.start;
    let end = range.end;

    // Check if plaintext looks like XML (starts with '<' after trimming whitespace)
    let plaintext_str = std::str::from_utf8(plaintext).ok();
    let plaintext_trimmed = plaintext_str.map(|s| s.trim_start()).unwrap_or("");
    let plaintext_is_xml = plaintext_trimmed.starts_with('<');
    let plaintext_has_decl = plaintext_trimmed.starts_with("<?xml");

    let output_bytes = if plaintext_is_xml {
        // Normalize XML line endings per XML spec section 2.11:
        // CRLF → LF, standalone CR → LF
        let normalized = normalize_line_endings(plaintext);
        let normalized = normalize_empty_elements(&normalized);
        normalize_self_closing_space(&normalized)
    } else {
        plaintext.to_vec()
    };

    // Check if EncryptedData is the root element
    let before = xml[..start].trim();
    let after = xml[end..].trim();
    let before_is_decl = before.is_empty() || is_xml_prolog(before);
    if before_is_decl && after.is_empty() {
        if plaintext_is_xml && !plaintext_has_decl {
            // Prepend XML declaration (matching xmlsec1/libxml2 behavior).
            // Only when the plaintext doesn't already have one.
            let mut result = Vec::new();
            if before.starts_with("<?xml") {
                result.extend_from_slice(before.as_bytes());
            } else {
                result.extend_from_slice(b"<?xml version=\"1.0\"?>");
            }
            result.push(b'\n');
            result.extend_from_slice(&output_bytes);
            if !output_bytes.ends_with(b"\n") {
                result.push(b'\n');
            }
            return Ok(result);
        }
        return Ok(output_bytes);
    }

    let mut result = Vec::with_capacity(xml.len());
    result.extend_from_slice(xml[..start].as_bytes());
    result.extend_from_slice(&output_bytes);
    result.extend_from_slice(xml[end..].as_bytes());

    // Normalize the surrounding document: the encrypted XML may have " />"
    // where the original had "/>" and "<tag></tag>" where the original had "<tag/>".
    result = normalize_empty_elements(&result);
    result = normalize_self_closing_space(&result);
    Ok(result)
}

/// Normalize XML line endings per XML spec section 2.11.
/// Converts CRLF → LF and standalone CR → LF.
fn normalize_line_endings(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\r' {
            result.push(b'\n');
            // Skip the LF in a CRLF pair
            if i + 1 < data.len() && data[i + 1] == b'\n' {
                i += 1;
            }
        } else {
            result.push(data[i]);
        }
        i += 1;
    }
    result
}

/// Normalize empty XML elements from `<tag ...></tag>` to `<tag .../>` form.
/// This matches xmlsec1/libxml2 re-serialization behavior.
fn normalize_empty_elements(data: &[u8]) -> Vec<u8> {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return data.to_vec(),
    };

    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut result = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        // Look for '>' immediately followed by '</' (empty element pattern)
        if bytes[i] == b'>' && i + 2 < len && bytes[i + 1] == b'<' && bytes[i + 2] == b'/' {
            // Find the end of the closing tag
            let mut close_end = i + 3;
            while close_end < len && bytes[close_end] != b'>' {
                close_end += 1;
            }
            if close_end < len {
                let close_name = &s[i + 3..close_end];
                if !close_name.is_empty()
                    && !close_name
                        .bytes()
                        .any(|b| b == b' ' || b == b'<' || b == b'>')
                {
                    // Scan backwards to find the matching opening '<'
                    let mut open_start = i;
                    while open_start > 0 && bytes[open_start - 1] != b'<' {
                        open_start -= 1;
                    }
                    if open_start > 0 {
                        open_start -= 1;
                    }
                    if open_start < i
                        && bytes[open_start] == b'<'
                        && bytes[open_start + 1] != b'/'
                        && bytes[open_start + 1] != b'!'
                        && bytes[open_start + 1] != b'?'
                    {
                        // Extract opening tag name
                        let mut name_end = open_start + 1;
                        while name_end < i
                            && bytes[name_end] != b' '
                            && bytes[name_end] != b'\t'
                            && bytes[name_end] != b'\n'
                            && bytes[name_end] != b'\r'
                            && bytes[name_end] != b'>'
                        {
                            name_end += 1;
                        }
                        let open_name = &s[open_start + 1..name_end];

                        if open_name == close_name {
                            // Match! Replace '></tag>' with '/>'
                            result.push(b'/');
                            result.push(b'>');
                            i = close_end + 1;
                            continue;
                        }
                    }
                }
            }
        }

        result.push(bytes[i]);
        i += 1;
    }

    result
}

/// Remove spaces before `/>` in self-closing tags.
/// Matches xmlsec1/libxml2 which serializes `<tag />` as `<tag/>`.
fn normalize_self_closing_space(data: &[u8]) -> Vec<u8> {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return data.to_vec(),
    };
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut result = Vec::with_capacity(len);
    let mut in_tag = false;
    let mut in_attr_dq = false; // inside double-quoted attribute value
    let mut in_attr_sq = false; // inside single-quoted attribute value
    let mut i = 0;

    while i < len {
        if in_attr_dq {
            if bytes[i] == b'"' {
                in_attr_dq = false;
            }
            result.push(bytes[i]);
        } else if in_attr_sq {
            if bytes[i] == b'\'' {
                in_attr_sq = false;
            }
            result.push(bytes[i]);
        } else if in_tag {
            if bytes[i] == b'"' {
                in_attr_dq = true;
                result.push(bytes[i]);
            } else if bytes[i] == b'\'' {
                in_attr_sq = true;
                result.push(bytes[i]);
            } else if bytes[i] == b'>' {
                in_tag = false;
                result.push(bytes[i]);
            } else if bytes[i] == b' '
                && i + 2 < len
                && bytes[i + 1] == b'/'
                && bytes[i + 2] == b'>'
            {
                // Skip the space before "/>"
            } else {
                result.push(bytes[i]);
            }
        } else {
            if bytes[i] == b'<' {
                in_tag = true;
            }
            result.push(bytes[i]);
        }
        i += 1;
    }
    result
}

/// Check if a string is just an XML prolog (optional XML declaration + optional DOCTYPE).
fn is_xml_prolog(s: &str) -> bool {
    let mut rest = s;
    // Skip optional XML declaration
    if rest.starts_with("<?xml") {
        if let Some(end) = rest.find("?>") {
            rest = rest[end + 2..].trim();
        } else {
            return false;
        }
    }
    // Skip optional DOCTYPE declaration
    if rest.starts_with("<!DOCTYPE") {
        // DOCTYPE may have an internal subset: <!DOCTYPE name [ ... ]>
        if let Some(bracket_pos) = rest.find('[') {
            if let Some(close_pos) = rest[bracket_pos..].find("]>") {
                rest = rest[bracket_pos + close_pos + 2..].trim();
            } else {
                return false;
            }
        } else if let Some(close_pos) = rest.find('>') {
            rest = rest[close_pos + 1..].trim();
        } else {
            return false;
        }
    }
    // After removing XML decl and DOCTYPE, nothing should remain
    rest.is_empty()
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
        let id_map = build_id_map(&doc, &["Id", "ID", "id"]);
        let root = doc.root_element();
        let ctx = EncContext::new(bergshamra_keys::KeysManager::new());
        let result = read_cipher_data(&ctx, root, &doc, &id_map).unwrap();
        assert_eq!(result, b"Hello World");
    }
}
