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
use uppsala::{Document, NodeId};

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
    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;

    // Build ID map
    let mut id_attrs: Vec<&str> = vec!["Id", "ID", "id", "AssertionID"];
    let extra: Vec<&str> = ctx.id_attrs.iter().map(|s| s.as_str()).collect();
    id_attrs.extend(extra);
    let id_map = build_id_map(&doc, &id_attrs);

    // Find first <EncryptedData> element
    let enc_data_id = find_element(&doc, ns::ENC, ns::node::ENCRYPTED_DATA)
        .ok_or_else(|| Error::MissingElement("EncryptedData".into()))?;

    // Read Type attribute (Element or Content)
    let enc_type = doc
        .element(enc_data_id)
        .unwrap()
        .get_attribute(ns::attr::TYPE)
        .unwrap_or("");

    // Read EncryptionMethod
    let enc_method_id = find_child_element(&doc, enc_data_id, ns::ENC, ns::node::ENCRYPTION_METHOD)
        .ok_or_else(|| Error::MissingElement("EncryptionMethod".into()))?;
    let enc_uri = doc
        .element(enc_method_id)
        .unwrap()
        .get_attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on EncryptionMethod".into()))?;

    // Resolve decryption key
    let key_bytes = resolve_decryption_key(ctx, &doc, enc_data_id, &id_map, enc_uri)?;

    // Read CipherData/CipherValue
    let cipher_data_id = find_child_element(&doc, enc_data_id, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData".into()))?;

    let cipher_bytes = read_cipher_data(ctx, &doc, cipher_data_id, &id_map)?;

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
    let result = replace_encrypted_data_bytes(xml, &doc, enc_data_id, enc_type, &plaintext)?;

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
    // Convert UTF-8 -> ISO-8859-1
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
    doc: &Document<'_>,
    enc_data_id: NodeId,
    id_map: &HashMap<String, NodeId>,
    enc_uri: &str,
) -> Result<Vec<u8>, Error> {
    let key_info_id = find_child_element(doc, enc_data_id, ns::DSIG, ns::node::KEY_INFO);

    if let Some(ki_id) = key_info_id {
        // Try all EncryptedKey elements inside KeyInfo -- use the first that succeeds
        let mut last_ek_error = None;
        for child_id in doc.children(ki_id) {
            let elem = match doc.element(child_id) {
                Some(e) => e,
                None => continue,
            };
            let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
            let child_local = &*elem.name.local_name;

            if child_ns == ns::ENC && child_local == ns::node::ENCRYPTED_KEY {
                match decrypt_encrypted_key(ctx, doc, child_id, id_map) {
                    Ok(key) => return Ok(key),
                    Err(e) => {
                        last_ek_error = Some(e);
                    }
                }
            }

            // Try DerivedKey (ConcatKDF / PBKDF2)
            if child_ns == ns::ENC11 && child_local == ns::node::DERIVED_KEY {
                if let Ok(key) = resolve_derived_key(ctx, doc, child_id, enc_uri) {
                    return Ok(key);
                }
            }
        }

        // Check for KeyName
        for child_id in doc.children(ki_id) {
            let elem = match doc.element(child_id) {
                Some(e) => e,
                None => continue,
            };
            let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
            let child_local = &*elem.name.local_name;

            if child_ns == ns::DSIG && child_local == ns::node::KEY_NAME {
                let name = doc.text_content_deep(child_id);
                let name = name.trim();
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
                if let Some(retrieval_uri) = elem.get_attribute(ns::attr::URI) {
                    if let Some(retrieval_type) = elem.get_attribute(ns::attr::TYPE) {
                        if retrieval_type.contains("EncryptedKey") {
                            if let Some(id) = retrieval_uri.strip_prefix('#') {
                                if let Some(&target_id) = id_map.get(id) {
                                    // Verify that the target node is an element
                                    if doc.element(target_id).is_some() {
                                        return decrypt_encrypted_key(ctx, doc, target_id, id_map);
                                    } else {
                                        return Err(Error::InvalidUri(format!(
                                            "cannot resolve #{id}"
                                        )));
                                    }
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
    doc: &Document<'_>,
    enc_key_id: NodeId,
    id_map: &HashMap<String, NodeId>,
) -> Result<Vec<u8>, Error> {
    // Read EncryptionMethod on EncryptedKey
    let enc_method_id =
        find_child_element(doc, enc_key_id, ns::ENC, ns::node::ENCRYPTION_METHOD)
            .ok_or_else(|| Error::MissingElement("EncryptionMethod on EncryptedKey".into()))?;
    let enc_uri = doc
        .element(enc_method_id)
        .unwrap()
        .get_attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| {
            Error::MissingAttribute("Algorithm on EncryptedKey EncryptionMethod".into())
        })?;

    // Read CipherData/CipherValue
    let cipher_data_id = find_child_element(doc, enc_key_id, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData on EncryptedKey".into()))?;
    let cipher_bytes = read_cipher_data(ctx, doc, cipher_data_id, id_map)?;

    // Determine key unwrap method
    match enc_uri {
        // RSA key transport
        algorithm::RSA_PKCS1 | algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
            // Extract OAEP params from EncryptionMethod child elements
            let oaep_params = read_oaep_params(doc, enc_method_id);
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

        // AES Key Wrap -- select key by expected size, or derive via ECDH-ES
        algorithm::KW_AES128 | algorithm::KW_AES192 | algorithm::KW_AES256 => {
            let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
            let expected_kek_size = match enc_uri {
                algorithm::KW_AES128 => 16,
                algorithm::KW_AES192 => 24,
                algorithm::KW_AES256 => 32,
                _ => 0,
            };
            // Try ECDH-ES key agreement first
            if let Some(kek) =
                resolve_agreement_method_kek(ctx, doc, enc_key_id, expected_kek_size)?
            {
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
            let kek_bytes = resolve_encrypted_key_kek(ctx, doc, enc_key_id)?;
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
    doc: &Document<'_>,
    enc_key_id: NodeId,
) -> Result<Vec<u8>, Error> {
    if let Some(ki_id) = find_child_element(doc, enc_key_id, ns::DSIG, ns::node::KEY_INFO) {
        // Try KeyName lookup
        if let Some(key_name_id) = find_child_element(doc, ki_id, ns::DSIG, ns::node::KEY_NAME) {
            let name = doc.text_content_deep(key_name_id);
            let name = name.trim();
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
    doc: &Document<'_>,
    enc_key_id: NodeId,
    kek_len: usize,
) -> Result<Option<Vec<u8>>, Error> {
    let ki_id = match find_child_element(doc, enc_key_id, ns::DSIG, ns::node::KEY_INFO) {
        Some(ki) => ki,
        None => return Ok(None),
    };

    // Look for <AgreementMethod> (in xenc namespace)
    let agreement_id = match find_child_element(doc, ki_id, ns::ENC, ns::node::AGREEMENT_METHOD) {
        Some(a) => a,
        None => return Ok(None),
    };

    let agreement_alg = doc
        .element(agreement_id)
        .unwrap()
        .get_attribute(ns::attr::ALGORITHM)
        .unwrap_or("");

    // Extract originator's public key from <OriginatorKeyInfo>
    let originator_ki_id =
        find_child_element(doc, agreement_id, ns::ENC, ns::node::ORIGINATOR_KEY_INFO)
            .ok_or_else(|| Error::MissingElement("OriginatorKeyInfo".into()))?;

    // Compute shared secret based on agreement algorithm
    let shared_secret = match agreement_alg {
        algorithm::ECDH_ES => {
            let originator_public_bytes = extract_ec_public_key_bytes(doc, originator_ki_id)?;
            let recipient_key = resolve_recipient_key(ctx, doc, agreement_id)?;

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
            let originator_dh = extract_dh_public_key_from_xml(doc, originator_ki_id)?;
            let recipient_key = resolve_recipient_key(ctx, doc, agreement_id)?;

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
        algorithm::X25519 => {
            // X25519 key agreement (ECDH over Curve25519)
            let originator_public_bytes = extract_ec_public_key_bytes(doc, originator_ki_id)?;
            if originator_public_bytes.len() != 32 {
                return Err(Error::Key(format!(
                    "X25519 public key must be 32 bytes, got {}",
                    originator_public_bytes.len()
                )));
            }
            let recipient_key = resolve_recipient_key(ctx, doc, agreement_id)?;

            match &recipient_key.data {
                bergshamra_keys::key::KeyData::X25519 {
                    private: Some(priv_bytes),
                    ..
                } => bergshamra_crypto::keyagreement::ecdh_x25519(
                    &originator_public_bytes,
                    priv_bytes,
                )?,
                _ => {
                    return Err(Error::Key(
                        "recipient key is not an X25519 private key".into(),
                    ));
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
    let kdf_method_id = find_child_element(
        doc,
        agreement_id,
        ns::ENC11,
        ns::node::KEY_DERIVATION_METHOD,
    );
    let kek = match kdf_method_id {
        Some(kdm_id) => {
            let kdf_uri = doc
                .element(kdm_id)
                .unwrap()
                .get_attribute(ns::attr::ALGORITHM)
                .unwrap_or("");
            match kdf_uri {
                algorithm::CONCAT_KDF => {
                    let params = parse_concat_kdf_params(doc, kdm_id)?;
                    bergshamra_crypto::kdf::concat_kdf(&shared_secret, kek_len, &params)?
                }
                algorithm::PBKDF2 => {
                    let params = parse_pbkdf2_params(doc, kdm_id, kek_len)?;
                    bergshamra_crypto::kdf::pbkdf2_derive(&shared_secret, &params)?
                }
                algorithm::HKDF => {
                    let params = parse_hkdf_params(doc, kdm_id, kek_len)?;
                    bergshamra_crypto::kdf::hkdf_derive(&shared_secret, kek_len, &params)?
                }
                _ => {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "key derivation: {kdf_uri}"
                    )));
                }
            }
        }
        None => {
            // No KDF -- use raw shared secret (truncated to kek_len)
            shared_secret[..kek_len.min(shared_secret.len())].to_vec()
        }
    };

    Ok(Some(kek))
}

/// Extract raw EC public key bytes (SEC1 uncompressed point) from a KeyInfo-like element.
fn extract_ec_public_key_bytes(doc: &Document<'_>, key_info_id: NodeId) -> Result<Vec<u8>, Error> {
    // Look for <KeyValue><ECKeyValue><PublicKey>
    let key_value_id = find_child_element(doc, key_info_id, ns::DSIG, ns::node::KEY_VALUE)
        .ok_or_else(|| Error::MissingElement("KeyValue in OriginatorKeyInfo".into()))?;

    let ec_kv_id = doc
        .children(key_value_id)
        .into_iter()
        .find(|&child_id| {
            if let Some(elem) = doc.element(child_id) {
                &*elem.name.local_name == ns::node::EC_KEY_VALUE
                    && (elem.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG11
                        || elem.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG)
            } else {
                false
            }
        })
        .ok_or_else(|| Error::MissingElement("ECKeyValue".into()))?;

    let public_key_id = doc
        .children(ec_kv_id)
        .into_iter()
        .find(|&child_id| {
            if let Some(elem) = doc.element(child_id) {
                &*elem.name.local_name == ns::node::PUBLIC_KEY
            } else {
                false
            }
        })
        .ok_or_else(|| Error::MissingElement("PublicKey in ECKeyValue".into()))?;

    let public_key_b64 = doc.text_content_deep(public_key_id);
    if public_key_b64.trim().is_empty() {
        return Err(Error::MissingElement("PublicKey in ECKeyValue".into()));
    }

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    engine
        .decode(public_key_b64.trim().replace(['\n', '\r', ' '], ""))
        .map_err(|e| Error::Base64(format!("EC PublicKey: {e}")))
}

/// Resolve the recipient's private key from AgreementMethod (EC or DH).
fn resolve_recipient_key<'a>(
    ctx: &'a EncContext,
    doc: &Document<'_>,
    agreement_id: NodeId,
) -> Result<&'a bergshamra_keys::key::Key, Error> {
    // Try RecipientKeyInfo -> KeyName
    if let Some(rki_id) =
        find_child_element(doc, agreement_id, ns::ENC, ns::node::RECIPIENT_KEY_INFO)
    {
        if let Some(key_name_id) = find_child_element(doc, rki_id, ns::DSIG, ns::node::KEY_NAME) {
            let name = doc.text_content_deep(key_name_id);
            let name = name.trim();
            if !name.is_empty() {
                if let Some(key) = ctx.keys_manager.find_by_name(name) {
                    return Ok(key);
                }
            }
        }
    }

    // Fallback: try first DH key, then X25519 key, then EC key with a private key
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
    if let Some(x25519_key) = ctx.keys_manager.find_x25519() {
        if matches!(
            &x25519_key.data,
            bergshamra_keys::key::KeyData::X25519 {
                private: Some(_),
                ..
            }
        ) {
            return Ok(x25519_key);
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
    doc: &Document<'_>,
    key_info_id: NodeId,
) -> Result<DhPublicKeyXml, Error> {
    let key_value_id = find_child_element(doc, key_info_id, ns::DSIG, ns::node::KEY_VALUE)
        .ok_or_else(|| Error::MissingElement("KeyValue in OriginatorKeyInfo".into()))?;

    let dh_kv_id = doc
        .children(key_value_id)
        .into_iter()
        .find(|&child_id| {
            if let Some(elem) = doc.element(child_id) {
                &*elem.name.local_name == ns::node::DH_KEY_VALUE
                    && (elem.name.namespace_uri.as_deref().unwrap_or("") == ns::ENC
                        || elem.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG)
            } else {
                false
            }
        })
        .ok_or_else(|| Error::MissingElement("DHKeyValue".into()))?;

    let public_id = doc
        .children(dh_kv_id)
        .into_iter()
        .find(|&child_id| {
            if let Some(elem) = doc.element(child_id) {
                &*elem.name.local_name == "Public"
            } else {
                false
            }
        })
        .ok_or_else(|| Error::MissingElement("Public in DHKeyValue".into()))?;

    let public_b64 = doc.text_content_deep(public_id);
    if public_b64.trim().is_empty() {
        return Err(Error::MissingElement("Public in DHKeyValue".into()));
    }

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
    doc: &Document<'_>,
    derived_key_id: NodeId,
    enc_uri: &str,
) -> Result<Vec<u8>, Error> {
    // Get the master key name
    let master_key_name =
        find_child_element(doc, derived_key_id, ns::ENC11, ns::node::MASTER_KEY_NAME)
            .map(|id| {
                let t = doc.text_content_deep(id);
                t.trim().to_owned()
            })
            .unwrap_or_default();

    // Look up master key in keys manager
    let master_key_bytes = if !master_key_name.is_empty() {
        if let Some(key) = ctx.keys_manager.find_by_name(&master_key_name) {
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
    let kd_method_id = find_child_element(
        doc,
        derived_key_id,
        ns::ENC11,
        ns::node::KEY_DERIVATION_METHOD,
    )
    .ok_or_else(|| Error::MissingElement("KeyDerivationMethod".into()))?;
    let kd_alg = doc
        .element(kd_method_id)
        .unwrap()
        .get_attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on KeyDerivationMethod".into()))?;

    // Determine key length from the encryption algorithm
    let key_len = key_length_for_algorithm(enc_uri);

    match kd_alg {
        algorithm::CONCAT_KDF => {
            let params = parse_concat_kdf_params(doc, kd_method_id)?;
            bergshamra_crypto::kdf::concat_kdf(&master_key_bytes, key_len, &params)
        }
        algorithm::PBKDF2 => {
            let params = parse_pbkdf2_params(doc, kd_method_id, key_len)?;
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
    doc: &Document<'_>,
    kd_method_id: NodeId,
) -> Result<bergshamra_crypto::kdf::ConcatKdfParams, Error> {
    let mut params = bergshamra_crypto::kdf::ConcatKdfParams::default();

    let concat_params_id =
        find_child_element(doc, kd_method_id, ns::ENC11, ns::node::CONCAT_KDF_PARAMS);
    if let Some(cp_id) = concat_params_id {
        let cp_elem = doc.element(cp_id).unwrap();
        // Parse hex-encoded attributes.
        // Per NIST SP 800-56A, the first byte is a padding indicator (00 = byte-aligned).
        // xmlsec strips this leading byte before using the data.
        if let Some(alg_id) = cp_elem.get_attribute("AlgorithmID") {
            params.algorithm_id = hex_decode_strip_pad(alg_id).ok();
        }
        if let Some(party_u) = cp_elem.get_attribute("PartyUInfo") {
            params.party_u_info = hex_decode_strip_pad(party_u).ok();
        }
        if let Some(party_v) = cp_elem.get_attribute("PartyVInfo") {
            params.party_v_info = hex_decode_strip_pad(party_v).ok();
        }
        // DigestMethod child
        if let Some(dm_id) = find_child_element(doc, cp_id, ns::DSIG, ns::node::DIGEST_METHOD) {
            params.digest_uri = doc
                .element(dm_id)
                .unwrap()
                .get_attribute(ns::attr::ALGORITHM)
                .map(|s| s.to_owned());
        }
    }

    Ok(params)
}

/// Parse PBKDF2 parameters from a KeyDerivationMethod element.
pub(crate) fn parse_pbkdf2_params(
    doc: &Document<'_>,
    kd_method_id: NodeId,
    default_key_len: usize,
) -> Result<bergshamra_crypto::kdf::Pbkdf2Params, Error> {
    let pbkdf2_params_id =
        find_child_element(doc, kd_method_id, ns::ENC11, ns::node::PBKDF2_PARAMS)
            .ok_or_else(|| Error::MissingElement("PBKDF2-params".into()))?;

    // Salt
    let salt_id = find_child_element(doc, pbkdf2_params_id, ns::ENC11, ns::node::PBKDF2_SALT)
        .ok_or_else(|| Error::MissingElement("Salt in PBKDF2-params".into()))?;
    let specified_id = find_child_element(doc, salt_id, ns::ENC11, ns::node::PBKDF2_SALT_SPECIFIED)
        .ok_or_else(|| Error::MissingElement("Specified in Salt".into()))?;
    let salt_b64 = doc.text_content_deep(specified_id);
    let salt_b64 = salt_b64.trim();
    let salt = {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let clean: String = salt_b64.chars().filter(|c| !c.is_whitespace()).collect();
        engine
            .decode(&clean)
            .map_err(|e| Error::Base64(format!("PBKDF2 salt: {e}")))?
    };

    // IterationCount
    let iter_count_id = find_child_element(
        doc,
        pbkdf2_params_id,
        ns::ENC11,
        ns::node::PBKDF2_ITERATION_COUNT,
    )
    .ok_or_else(|| Error::MissingElement("IterationCount in PBKDF2-params".into()))?;
    let iter_text = doc.text_content_deep(iter_count_id);
    let iteration_count: u32 = iter_text
        .trim()
        .parse()
        .map_err(|_| Error::XmlStructure("invalid IterationCount".into()))?;

    // KeyLength (optional, defaults to encryption algorithm key length)
    let key_length = if let Some(kl_id) = find_child_element(
        doc,
        pbkdf2_params_id,
        ns::ENC11,
        ns::node::PBKDF2_KEY_LENGTH,
    ) {
        let kl_text = doc.text_content_deep(kl_id);
        kl_text.trim().parse::<usize>().unwrap_or(default_key_len)
    } else {
        default_key_len
    };

    // PRF (pseudo-random function)
    let prf_id = find_child_element(doc, pbkdf2_params_id, ns::ENC11, ns::node::PBKDF2_PRF)
        .ok_or_else(|| Error::MissingElement("PRF in PBKDF2-params".into()))?;
    let prf_uri = doc
        .element(prf_id)
        .unwrap()
        .get_attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on PRF".into()))?
        .to_owned();

    Ok(bergshamra_crypto::kdf::Pbkdf2Params {
        prf_uri,
        salt,
        iteration_count,
        key_length,
    })
}

/// Parse HKDF parameters from a KeyDerivationMethod element.
///
/// HKDFParams is in the `http://www.w3.org/2001/04/xmldsig-more#` namespace.
/// Structure:
/// ```xml
/// <dsig-more:HKDFParams xmlns:dsig-more="http://www.w3.org/2001/04/xmldsig-more#">
///   <dsig-more:PRF Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>
///   <dsig-more:Salt><dsig-more:Specified>base64...</dsig-more:Specified></dsig-more:Salt>
///   <dsig-more:Info>base64...</dsig-more:Info>
///   <dsig-more:KeyLength>128</dsig-more:KeyLength>
/// </dsig-more:HKDFParams>
/// ```
pub(crate) fn parse_hkdf_params(
    doc: &Document<'_>,
    kd_method_id: NodeId,
    default_key_len: usize,
) -> Result<bergshamra_crypto::kdf::HkdfParams, Error> {
    // Try to find HKDFParams in DSIG_MORE namespace first, fall back to any-namespace match
    let hkdf_params_id =
        find_child_element(doc, kd_method_id, ns::DSIG_MORE, ns::node::HKDF_PARAMS)
            .or_else(|| find_child_element_any_ns(doc, kd_method_id, ns::node::HKDF_PARAMS))
            .ok_or_else(|| Error::MissingElement("HKDFParams".into()))?;

    // PRF (pseudo-random function) — default is HMAC-SHA256
    let prf_uri = find_child_element(doc, hkdf_params_id, ns::DSIG_MORE, ns::node::HKDF_PRF)
        .or_else(|| find_child_element_any_ns(doc, hkdf_params_id, ns::node::HKDF_PRF))
        .and_then(|prf_id| {
            doc.element(prf_id)
                .unwrap()
                .get_attribute(ns::attr::ALGORITHM)
                .map(|s| s.to_owned())
        })
        .unwrap_or_else(|| algorithm::HMAC_SHA256.to_owned());

    // Salt (optional)
    let salt = find_child_element(doc, hkdf_params_id, ns::DSIG_MORE, ns::node::HKDF_SALT)
        .or_else(|| find_child_element_any_ns(doc, hkdf_params_id, ns::node::HKDF_SALT))
        .and_then(|salt_id| {
            find_child_element(doc, salt_id, ns::DSIG_MORE, ns::node::HKDF_SALT_SPECIFIED)
                .or_else(|| find_child_element_any_ns(doc, salt_id, ns::node::HKDF_SALT_SPECIFIED))
        })
        .and_then(|specified_id| {
            let b64 = doc.text_content_deep(specified_id);
            let b64 = b64.trim();
            if b64.is_empty() {
                return None;
            }
            use base64::Engine;
            let engine = base64::engine::general_purpose::STANDARD;
            let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            engine.decode(&clean).ok()
        });

    // Info (optional)
    let info = find_child_element(doc, hkdf_params_id, ns::DSIG_MORE, ns::node::HKDF_INFO)
        .or_else(|| find_child_element_any_ns(doc, hkdf_params_id, ns::node::HKDF_INFO))
        .and_then(|info_id| {
            let b64 = doc.text_content_deep(info_id);
            let b64 = b64.trim();
            if b64.is_empty() {
                return None;
            }
            use base64::Engine;
            let engine = base64::engine::general_purpose::STANDARD;
            let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            engine.decode(&clean).ok()
        });

    // KeyLength (in bits, optional — default to kek_len * 8)
    let key_length_bits = find_child_element(
        doc,
        hkdf_params_id,
        ns::DSIG_MORE,
        ns::node::HKDF_KEY_LENGTH,
    )
    .or_else(|| find_child_element_any_ns(doc, hkdf_params_id, ns::node::HKDF_KEY_LENGTH))
    .and_then(|kl_id| {
        let text = doc.text_content_deep(kl_id);
        text.trim().parse::<u32>().ok()
    })
    .unwrap_or((default_key_len * 8) as u32);

    Ok(bergshamra_crypto::kdf::HkdfParams {
        prf_uri: Some(prf_uri),
        salt,
        info,
        key_length_bits,
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
    doc: &Document<'_>,
    enc_method_id: NodeId,
) -> bergshamra_crypto::keytransport::OaepParams {
    let mut params = bergshamra_crypto::keytransport::OaepParams::default();

    for child_id in doc.children(enc_method_id) {
        let elem = match doc.element(child_id) {
            Some(e) => e,
            None => continue,
        };
        let local = &*elem.name.local_name;
        let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");

        // DigestMethod (in dsig namespace)
        if local == ns::node::DIGEST_METHOD && (child_ns == ns::DSIG || child_ns == ns::ENC) {
            if let Some(alg) = elem.get_attribute(ns::attr::ALGORITHM) {
                params.digest_uri = Some(alg.to_owned());
            }
        }
        // MGF (in xmlenc11 namespace)
        if local == ns::node::RSA_MGF && (child_ns == ns::ENC11 || child_ns == ns::ENC) {
            if let Some(alg) = elem.get_attribute(ns::attr::ALGORITHM) {
                params.mgf_uri = Some(alg.to_owned());
            }
        }
        // OAEPparams (in xmlenc namespace)
        if local == ns::node::RSA_OAEP_PARAMS {
            let text = doc.text_content_deep(child_id);
            let clean: String = text.trim().chars().filter(|c| !c.is_whitespace()).collect();
            if !clean.is_empty() {
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

/// Read CipherData -- extract CipherValue (Base64) or CipherReference.
fn read_cipher_data(
    ctx: &EncContext,
    doc: &Document<'_>,
    cipher_data_id: NodeId,
    id_map: &HashMap<String, NodeId>,
) -> Result<Vec<u8>, Error> {
    // Try CipherValue first
    if let Some(cipher_value_id) =
        find_child_element(doc, cipher_data_id, ns::ENC, ns::node::CIPHER_VALUE)
    {
        let b64_text = doc.text_content_deep(cipher_value_id);
        let b64_text = b64_text.trim();
        let clean: String = b64_text.chars().filter(|c| !c.is_whitespace()).collect();

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        return engine
            .decode(&clean)
            .map_err(|e| Error::Base64(format!("CipherValue: {e}")));
    }

    // CipherReference: resolve URI and apply transforms
    if let Some(cipher_ref_id) =
        find_child_element(doc, cipher_data_id, ns::ENC, ns::node::CIPHER_REFERENCE)
    {
        if ctx.disable_cipher_reference {
            return Err(Error::Other(
                "CipherReference resolution is disabled".into(),
            ));
        }
        return resolve_cipher_reference(doc, cipher_ref_id, id_map);
    }

    Err(Error::MissingElement(
        "CipherValue or CipherReference".into(),
    ))
}

/// Resolve a CipherReference element to get cipher bytes.
fn resolve_cipher_reference(
    doc: &Document<'_>,
    cipher_ref_id: NodeId,
    id_map: &HashMap<String, NodeId>,
) -> Result<Vec<u8>, Error> {
    let uri = doc
        .element(cipher_ref_id)
        .unwrap()
        .get_attribute(ns::attr::URI)
        .ok_or_else(|| Error::MissingAttribute("URI on CipherReference".into()))?;

    // Resolve same-document URI reference
    let data = if uri.is_empty() {
        // URI="" means the whole document -- transforms will select specific content
        // Collect all text content from all nodes
        let mut text = String::new();
        for node_id in doc.descendants(doc.root()) {
            if let Some(t) = doc.text_content(node_id) {
                text.push_str(t);
            }
        }
        text.into_bytes()
    } else if let Some(id) = uri.strip_prefix('#') {
        // Look up by ID
        let &target_id = id_map
            .get(id)
            .ok_or_else(|| Error::InvalidUri(format!("cannot resolve CipherReference #{id}")))?;
        // Verify that the target is valid
        if doc.node_kind(target_id).is_none() {
            return Err(Error::InvalidUri(format!(
                "cannot resolve CipherReference #{id}"
            )));
        }
        // Collect all text content from the target element
        collect_text_content(doc, target_id).into_bytes()
    } else {
        return Err(Error::UnsupportedAlgorithm(format!(
            "CipherReference with non-fragment URI not supported: {uri}"
        )));
    };

    // Apply transforms if present
    let transforms_id = find_child_element(doc, cipher_ref_id, ns::ENC, ns::node::TRANSFORMS)
        .or_else(|| find_child_element(doc, cipher_ref_id, ns::DSIG, ns::node::TRANSFORMS));

    let mut result = data;
    if let Some(transforms_id) = transforms_id {
        for child_id in doc.children(transforms_id) {
            let elem = match doc.element(child_id) {
                Some(e) => e,
                None => continue,
            };
            if &*elem.name.local_name != ns::node::TRANSFORM {
                continue;
            }
            let alg = elem.get_attribute(ns::attr::ALGORITHM).unwrap_or("");
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
                    result = apply_cipher_ref_xpath(doc, id_map, child_id)?;
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
    doc: &Document<'_>,
    id_map: &HashMap<String, NodeId>,
    transform_id: NodeId,
) -> Result<Vec<u8>, Error> {
    // Get the XPath expression text
    let xpath_id = doc
        .children(transform_id)
        .into_iter()
        .find(|&child_id| {
            if let Some(elem) = doc.element(child_id) {
                &*elem.name.local_name == "XPath"
            } else {
                false
            }
        })
        .ok_or_else(|| Error::MissingElement("XPath in CipherReference transform".into()))?;
    let xpath_text = doc.text_content_deep(xpath_id);
    let xpath_text = xpath_text.trim();

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
                    resolve_prefix_on_element(doc, xpath_id, prefix).unwrap_or("")
                };

                // Parse predicate: [@Id="VALUE"] or [@Id='VALUE']
                let id_value = parse_attr_predicate(pred_part, "Id");

                // Find matching element and collect its text children
                if let Some(id_val) = id_value {
                    // Look up by ID first for efficiency
                    if let Some(&target_id) = id_map.get(id_val) {
                        if let Some(elem) = doc.element(target_id) {
                            let target_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
                            let target_local = &*elem.name.local_name;
                            if target_ns == ns_uri && target_local == local_name {
                                return Ok(collect_text_content(doc, target_id).into_bytes());
                            }
                        }
                    }
                }

                // Fall back to scanning all elements
                for node_id in doc.descendants(doc.root()) {
                    let elem = match doc.element(node_id) {
                        Some(e) => e,
                        None => continue,
                    };
                    let node_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
                    let node_local = &*elem.name.local_name;
                    if node_ns == ns_uri && node_local == local_name {
                        if let Some(id_val) = id_value {
                            let node_id_attr = elem.get_attribute("Id").unwrap_or("");
                            if node_id_attr != id_val {
                                continue;
                            }
                        }
                        return Ok(collect_text_content(doc, node_id).into_bytes());
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

/// Resolve a namespace prefix by walking up the element's ancestors looking at
/// namespace declarations. This replaces roxmltree's `lookup_namespace_uri`.
fn resolve_prefix_on_element<'a>(
    doc: &'a Document<'_>,
    node_id: NodeId,
    prefix: &str,
) -> Option<&'a str> {
    let mut current = Some(node_id);
    while let Some(nid) = current {
        if let Some(elem) = doc.element(nid) {
            if let Some((_, uri)) = elem
                .namespace_declarations
                .iter()
                .find(|(p, _)| &**p == prefix)
            {
                return Some(uri);
            }
        }
        current = doc.parent(nid);
    }
    None
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
fn collect_text_content(doc: &Document<'_>, node_id: NodeId) -> String {
    doc.text_content_deep(node_id)
}

/// Replace the <EncryptedData> element in the XML string with the decrypted plaintext (bytes).
fn replace_encrypted_data_bytes(
    xml: &str,
    doc: &Document<'_>,
    enc_data_id: NodeId,
    enc_type: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    // When Type is not Element or Content (e.g., MimeType="text/plain" with no Type,
    // or any non-XML type), the plaintext is opaque data -- return it as-is.
    let is_xml_type =
        enc_type.is_empty() || enc_type.ends_with("#Element") || enc_type.ends_with("#Content");
    if !is_xml_type {
        return Ok(plaintext.to_vec());
    }

    // If no Type is specified but EncryptedData has a MimeType that's not XML,
    // treat the plaintext as opaque data.
    if enc_type.is_empty() {
        let mime = doc
            .element(enc_data_id)
            .unwrap()
            .get_attribute("MimeType")
            .unwrap_or("");
        if !mime.is_empty() && !mime.contains("xml") {
            return Ok(plaintext.to_vec());
        }
    }

    let range = doc.node_range(enc_data_id).unwrap();
    let start = range.start;
    let end = range.end;

    // Check if plaintext looks like XML (starts with '<' after trimming whitespace)
    let plaintext_str = std::str::from_utf8(plaintext).ok();
    let plaintext_trimmed = plaintext_str.map(|s| s.trim_start()).unwrap_or("");
    let plaintext_is_xml = plaintext_trimmed.starts_with('<');
    let plaintext_has_decl = plaintext_trimmed.starts_with("<?xml");

    let output_bytes = if plaintext_is_xml {
        // Normalize XML line endings per XML spec section 2.11:
        // CRLF -> LF, standalone CR -> LF
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
    result.extend_from_slice(&xml.as_bytes()[..start]);
    result.extend_from_slice(&output_bytes);
    result.extend_from_slice(&xml.as_bytes()[end..]);

    // Normalize the surrounding document: the encrypted XML may have " />"
    // where the original had "/>" and "<tag></tag>" where the original had "<tag/>".
    result = normalize_empty_elements(&result);
    result = normalize_self_closing_space(&result);
    Ok(result)
}

/// Normalize XML line endings per XML spec section 2.11.
/// Converts CRLF -> LF and standalone CR -> LF.
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
                    open_start = open_start.saturating_sub(1);
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

// -- Helper functions --

fn find_element(doc: &Document<'_>, ns_uri: &str, local_name: &str) -> Option<NodeId> {
    for id in doc.descendants(doc.root()) {
        if let Some(elem) = doc.element(id) {
            if &*elem.name.local_name == local_name
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
            {
                return Some(id);
            }
        }
    }
    None
}

fn find_child_element(
    doc: &Document<'_>,
    parent_id: NodeId,
    ns_uri: &str,
    local_name: &str,
) -> Option<NodeId> {
    for child_id in doc.children(parent_id) {
        if let Some(elem) = doc.element(child_id) {
            if &*elem.name.local_name == local_name
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
            {
                return Some(child_id);
            }
        }
    }
    None
}

/// Find a child element by local name, ignoring namespace.
///
/// Used as a fallback when the exact namespace is uncertain (e.g., HKDFParams
/// may appear with or without a namespace declaration).
fn find_child_element_any_ns(
    doc: &Document<'_>,
    parent_id: NodeId,
    local_name: &str,
) -> Option<NodeId> {
    for child_id in doc.children(parent_id) {
        if let Some(elem) = doc.element(child_id) {
            if &*elem.name.local_name == local_name {
                return Some(child_id);
            }
        }
    }
    None
}

fn build_id_map(doc: &Document<'_>, attr_names: &[&str]) -> HashMap<String, NodeId> {
    let mut map = HashMap::new();
    for node_id in doc.descendants(doc.root()) {
        if let Some(elem) = doc.element(node_id) {
            for attr_name in attr_names {
                if let Some(val) = elem.get_attribute(attr_name) {
                    map.insert(val.to_owned(), node_id);
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
        let doc = uppsala::parse(xml).unwrap();
        let id_map = build_id_map(&doc, &["Id", "ID", "id"]);
        let root = doc.document_element().unwrap();
        let ctx = EncContext::new(bergshamra_keys::KeysManager::new());
        let result = read_cipher_data(&ctx, &doc, root, &id_map).unwrap();
        assert_eq!(result, b"Hello World");
    }
}
