#![forbid(unsafe_code)]

//! XML-Enc encryption.
//!
//! Takes a template with an empty `<EncryptedData>` element and fills
//! in the `<CipherValue>` with the encrypted data.

use crate::context::EncContext;
use bergshamra_core::{algorithm, ns, Error};
use uppsala::{Document, NodeId};

/// Encrypt XML data using a template.
///
/// The template must contain an `<EncryptedData>` element with an empty
/// `<CipherValue>`. The target data (either an element or content to
/// encrypt) is provided separately.
///
/// Returns the XML document with `<EncryptedData>` populated.
pub fn encrypt(ctx: &EncContext, template_xml: &str, data: &[u8]) -> Result<String, Error> {
    let doc =
        uppsala::parse(template_xml).map_err(|e| Error::XmlParse(e.to_string()))?;

    // Find EncryptedData element
    let enc_data_id = find_element(&doc, ns::ENC, ns::node::ENCRYPTED_DATA)
        .ok_or_else(|| Error::MissingElement("EncryptedData".into()))?;

    // Read EncryptionMethod
    let enc_method_id = find_child_element(&doc, enc_data_id, ns::ENC, ns::node::ENCRYPTION_METHOD)
        .ok_or_else(|| Error::MissingElement("EncryptionMethod".into()))?;
    let enc_uri = doc
        .element(enc_method_id)
        .unwrap()
        .get_attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on EncryptionMethod".into()))?;

    // Resolve encryption key
    let key_bytes = resolve_encryption_key(ctx, &doc, enc_data_id, enc_uri)?;

    // Encrypt the data
    let cipher_alg = bergshamra_crypto::cipher::from_uri(enc_uri)?;
    let ciphertext = cipher_alg.encrypt(&key_bytes, data)?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let cipher_b64 = engine.encode(&ciphertext);

    // Replace empty CipherValue in EncryptedData using node range
    let cipher_data_id = find_child_element(&doc, enc_data_id, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData".into()))?;
    let cipher_value_id =
        find_child_element(&doc, cipher_data_id, ns::ENC, ns::node::CIPHER_VALUE)
            .ok_or_else(|| Error::MissingElement("CipherValue".into()))?;

    let cv_range = doc.node_range(cipher_value_id).unwrap();
    let cv_xml = &template_xml[cv_range.start..cv_range.end];
    let prefix = extract_prefix(cv_xml, "CipherValue");
    let replacement = if prefix.is_empty() {
        format!("<CipherValue>{cipher_b64}</CipherValue>")
    } else {
        // Check if the prefix's namespace declaration is on this element itself
        // (e.g. <enc:CipherValue xmlns:enc="..."/>). If so, we need to include it
        // in the replacement, or just use unprefixed since the default namespace
        // (from EncryptedData) is already xmlenc.
        let ns_decl = format!("xmlns:{prefix}=");
        if cv_xml.contains(&ns_decl) {
            // Namespace is declared on the element itself — use unprefixed instead
            format!("<CipherValue>{cipher_b64}</CipherValue>")
        } else {
            format!("<{prefix}:CipherValue>{cipher_b64}</{prefix}:CipherValue>")
        }
    };

    let mut result = String::with_capacity(template_xml.len() + cipher_b64.len());
    result.push_str(&template_xml[..cv_range.start]);
    result.push_str(&replacement);
    result.push_str(&template_xml[cv_range.end..]);

    // Handle EncryptedKey if present
    result = encrypt_session_key(ctx, &result, enc_uri, &key_bytes)?;

    Ok(result)
}

/// Resolve the encryption key — either from the manager or generate a session key.
fn resolve_encryption_key(
    ctx: &EncContext,
    doc: &Document<'_>,
    enc_data_id: NodeId,
    enc_uri: &str,
) -> Result<Vec<u8>, Error> {
    // Check KeyInfo for a key name
    let key_info = find_child_element(doc, enc_data_id, ns::DSIG, ns::node::KEY_INFO);

    if let Some(ki_id) = key_info {
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

            // Check for EncryptedKey — we need a session key
            if child_ns == ns::ENC && child_local == ns::node::ENCRYPTED_KEY {
                // Generate a random session key of the right size
                return generate_session_key(enc_uri);
            }

            // Check for DerivedKey (ConcatKDF / PBKDF2)
            if child_ns == ns::ENC11 && child_local == ns::node::DERIVED_KEY {
                if let Ok(key) = crate::decrypt::resolve_derived_key(ctx, doc, child_id, enc_uri) {
                    return Ok(key);
                }
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
        _ => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "cannot determine key size for: {enc_uri}"
            )))
        }
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
    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;

    // Find EncryptedKey elements
    let mut result = xml.to_owned();
    for node_id in doc.descendants(doc.root()) {
        let elem = match doc.element(node_id) {
            Some(e) => e,
            None => continue,
        };
        if &*elem.name.local_name != ns::node::ENCRYPTED_KEY
            || elem.name.namespace_uri.as_deref().unwrap_or("") != ns::ENC
        {
            continue;
        }

        // Read EncryptionMethod on EncryptedKey
        let enc_method_id =
            match find_child_element(&doc, node_id, ns::ENC, ns::node::ENCRYPTION_METHOD) {
                Some(m) => m,
                None => continue,
            };
        let enc_uri = match doc
            .element(enc_method_id)
            .unwrap()
            .get_attribute(ns::attr::ALGORITHM)
        {
            Some(u) => u,
            None => continue,
        };

        // Check if CipherValue is empty
        let cipher_data_id =
            match find_child_element(&doc, node_id, ns::ENC, ns::node::CIPHER_DATA) {
                Some(cd) => cd,
                None => continue,
            };
        let cipher_value_id =
            match find_child_element(&doc, cipher_data_id, ns::ENC, ns::node::CIPHER_VALUE) {
                Some(cv) => cv,
                None => continue,
            };
        let cv_text = doc.text_content_deep(cipher_value_id);
        let cv_text = cv_text.trim();
        if !cv_text.is_empty() {
            continue; // Already filled
        }

        // Encrypt the session key
        let encrypted_key_bytes = match enc_uri {
            algorithm::RSA_PKCS1 | algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
                let oaep_params = read_oaep_params(&doc, enc_method_id);
                let transport =
                    bergshamra_crypto::keytransport::from_uri_with_params(enc_uri, oaep_params)?;
                // Look for KeyName in this EncryptedKey's KeyInfo to select the
                // correct RSA key (important for multi-recipient encryption).
                let rsa_key = resolve_encrypted_key_rsa(ctx, &doc, node_id)?;
                let public_key = rsa_key
                    .rsa_public_key()
                    .ok_or_else(|| Error::Key("RSA public key required".into()))?;
                transport.encrypt(public_key, session_key)?
            }
            algorithm::KW_AES128 | algorithm::KW_AES192 | algorithm::KW_AES256 => {
                let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
                let expected_kek_size = match enc_uri {
                    algorithm::KW_AES128 => 16,
                    algorithm::KW_AES192 => 24,
                    algorithm::KW_AES256 => 32,
                    _ => 0,
                };
                // Check for ECDH-ES key agreement (AgreementMethod in KeyInfo)
                if let Some(kek) =
                    resolve_agreement_method_encrypt(ctx, &doc, node_id, expected_kek_size)?
                {
                    // Fill in OriginatorKeyInfo's KeyValue with the originator's public key
                    result = fill_originator_key_value(ctx, &doc, node_id, &result)?;
                    kw.wrap(&kek, session_key)?
                } else {
                    let aes_key = ctx
                        .keys_manager
                        .find_aes_by_size(expected_kek_size)
                        .or_else(|| ctx.keys_manager.find_aes())
                        .ok_or_else(|| Error::Key("no AES key for key wrap".into()))?;
                    let kek_bytes = aes_key
                        .symmetric_key_bytes()
                        .ok_or_else(|| Error::Key("AES key has no bytes".into()))?;
                    kw.wrap(kek_bytes, session_key)?
                }
            }
            algorithm::KW_TRIPLEDES => {
                let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
                let des_key = ctx
                    .keys_manager
                    .find_des3()
                    .or_else(|| ctx.keys_manager.first_key().ok())
                    .ok_or_else(|| Error::Key("no key for 3DES key wrap".into()))?;
                let kek_bytes = des_key
                    .symmetric_key_bytes()
                    .ok_or_else(|| Error::Key("no symmetric key for 3DES key wrap".into()))?;
                kw.wrap(kek_bytes, session_key)?
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
                let kek_bytes = resolve_encrypted_key_kek(ctx, &doc, node_id)?;
                cipher.encrypt(&kek_bytes, session_key)?
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "EncryptedKey method: {enc_uri}"
                )))
            }
        };

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let ek_b64 = engine.encode(&encrypted_key_bytes);

        // Replace the empty CipherValue for this EncryptedKey
        // Use text replacement based on the element's byte range
        let cv_range = doc.node_range(cipher_value_id).unwrap();
        let cv_xml = &xml[cv_range.start..cv_range.end];

        // Build the replacement
        // The original is something like <xenc:CipherValue/> or <xenc:CipherValue></xenc:CipherValue>
        // We need to figure out the prefix used
        let prefix = extract_prefix(cv_xml, "CipherValue");
        let replacement = if prefix.is_empty() {
            format!("<CipherValue>{ek_b64}</CipherValue>")
        } else {
            let ns_decl = format!("xmlns:{prefix}=");
            if cv_xml.contains(&ns_decl) {
                format!("<CipherValue>{ek_b64}</CipherValue>")
            } else {
                format!("<{prefix}:CipherValue>{ek_b64}</{prefix}:CipherValue>")
            }
        };

        result = result.replacen(cv_xml, &replacement, 1);
    }

    Ok(result)
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
        .ok_or_else(|| Error::Key("no symmetric key for EncryptedKey cipher encryption".into()))
}

/// Resolve the RSA public key for an EncryptedKey element.
/// Checks KeyName inside the EncryptedKey's KeyInfo to find the correct key
/// (needed for multi-recipient encryption where each EncryptedKey targets a different key).
fn resolve_encrypted_key_rsa<'a>(
    ctx: &'a EncContext,
    doc: &Document<'_>,
    enc_key_id: NodeId,
) -> Result<&'a bergshamra_keys::Key, Error> {
    if let Some(ki_id) = find_child_element(doc, enc_key_id, ns::DSIG, ns::node::KEY_INFO) {
        if let Some(key_name_id) = find_child_element(doc, ki_id, ns::DSIG, ns::node::KEY_NAME) {
            let name = doc.text_content_deep(key_name_id);
            let name = name.trim();
            if !name.is_empty() {
                if let Some(key) = ctx.keys_manager.find_by_name(name) {
                    if key.rsa_public_key().is_some() {
                        return Ok(key);
                    }
                }
            }
        }
    }
    // Fallback: first RSA key
    ctx.keys_manager
        .find_rsa()
        .ok_or_else(|| Error::Key("no RSA key for EncryptedKey".into()))
}

/// Resolve KEK via key agreement (ECDH-ES or DH-ES) for encryption.
///
/// Returns `Ok(Some(kek))` if AgreementMethod is present in the EncryptedKey's KeyInfo,
/// `Ok(None)` if no AgreementMethod found, or `Err` on failure.
fn resolve_agreement_method_encrypt(
    ctx: &EncContext,
    doc: &Document<'_>,
    enc_key_id: NodeId,
    kek_len: usize,
) -> Result<Option<Vec<u8>>, Error> {
    let ki_id = match find_child_element(doc, enc_key_id, ns::DSIG, ns::node::KEY_INFO) {
        Some(ki) => ki,
        None => return Ok(None),
    };

    let agreement_id = match find_child_element(doc, ki_id, ns::ENC, ns::node::AGREEMENT_METHOD) {
        Some(a) => a,
        None => return Ok(None),
    };

    let agreement_alg = doc
        .element(agreement_id)
        .unwrap()
        .get_attribute(ns::attr::ALGORITHM)
        .unwrap_or("");

    // For encryption, we use:
    //   originator's PRIVATE key + recipient's PUBLIC key -> shared secret
    // Then derive KEK from the shared secret via ConcatKDF or PBKDF2.

    // Resolve originator private key (by name in OriginatorKeyInfo)
    let originator_key = resolve_originator_key(ctx, doc, agreement_id)?;

    // Resolve recipient public key (by name in RecipientKeyInfo)
    let recipient_key = resolve_recipient_public_key(ctx, doc, agreement_id)?;

    let shared_secret = match agreement_alg {
        algorithm::ECDH_ES => {
            // Get recipient's public key bytes (SEC1 uncompressed point)
            let recipient_public_bytes = recipient_key
                .ec_public_key_bytes()
                .ok_or_else(|| Error::Key("recipient key has no EC public key bytes".into()))?;

            // Compute ECDH shared secret: originator_private x recipient_public
            match &originator_key.data {
                bergshamra_keys::key::KeyData::EcP256 {
                    private: Some(sk), ..
                } => {
                    let secret = p256::SecretKey::from_bytes(&sk.to_bytes())
                        .map_err(|e| Error::Key(format!("P-256 secret key: {e}")))?;
                    bergshamra_crypto::keyagreement::ecdh_p256(&recipient_public_bytes, &secret)?
                }
                bergshamra_keys::key::KeyData::EcP384 {
                    private: Some(sk), ..
                } => {
                    let secret = p384::SecretKey::from_bytes(&sk.to_bytes())
                        .map_err(|e| Error::Key(format!("P-384 secret key: {e}")))?;
                    bergshamra_crypto::keyagreement::ecdh_p384(&recipient_public_bytes, &secret)?
                }
                bergshamra_keys::key::KeyData::EcP521 {
                    private: Some(sk), ..
                } => {
                    use p521::elliptic_curve::generic_array::GenericArray;
                    let bytes = sk.to_bytes();
                    let secret = p521::SecretKey::from_bytes(GenericArray::from_slice(&bytes))
                        .map_err(|e| Error::Key(format!("P-521 secret key: {e}")))?;
                    bergshamra_crypto::keyagreement::ecdh_p521(&recipient_public_bytes, &secret)?
                }
                _ => {
                    return Err(Error::Key("originator key is not an EC private key".into()));
                }
            }
        }
        algorithm::DH_ES => {
            // Finite-field DH: shared_secret = recipient_public ^ originator_private mod p
            match (&originator_key.data, &recipient_key.data) {
                (
                    bergshamra_keys::key::KeyData::Dh {
                        p,
                        q,
                        private_key: Some(x),
                        ..
                    },
                    bergshamra_keys::key::KeyData::Dh {
                        public_key: recipient_pub,
                        ..
                    },
                ) => {
                    let q_bytes = q.as_deref().ok_or_else(|| {
                        Error::Key("DH subgroup order q is required for DH-ES".into())
                    })?;
                    bergshamra_crypto::keyagreement::dh_compute(recipient_pub, x, p, Some(q_bytes))?
                }
                _ => {
                    return Err(Error::Key(
                        "originator must be DH private key and recipient DH public key".into(),
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
    let kdf_method_id =
        find_child_element(doc, agreement_id, ns::ENC11, ns::node::KEY_DERIVATION_METHOD);
    let kek = match kdf_method_id {
        Some(kdm_id) => {
            let kdf_uri = doc
                .element(kdm_id)
                .unwrap()
                .get_attribute(ns::attr::ALGORITHM)
                .unwrap_or("");
            match kdf_uri {
                algorithm::CONCAT_KDF => {
                    let params = crate::decrypt::parse_concat_kdf_params(doc, kdm_id)?;
                    bergshamra_crypto::kdf::concat_kdf(&shared_secret, kek_len, &params)?
                }
                algorithm::PBKDF2 => {
                    let params = crate::decrypt::parse_pbkdf2_params(doc, kdm_id, kek_len)?;
                    bergshamra_crypto::kdf::pbkdf2_derive(&shared_secret, &params)?
                }
                _ => {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "key derivation: {kdf_uri}"
                    )));
                }
            }
        }
        None => shared_secret[..kek_len.min(shared_secret.len())].to_vec(),
    };

    Ok(Some(kek))
}

/// Resolve the originator's private key from AgreementMethod (EC or DH, for encryption).
fn resolve_originator_key<'a>(
    ctx: &'a EncContext,
    doc: &Document<'_>,
    agreement_id: NodeId,
) -> Result<&'a bergshamra_keys::key::Key, Error> {
    if let Some(oki_id) =
        find_child_element(doc, agreement_id, ns::ENC, ns::node::ORIGINATOR_KEY_INFO)
    {
        if let Some(key_name_id) = find_child_element(doc, oki_id, ns::DSIG, ns::node::KEY_NAME) {
            let name = doc.text_content_deep(key_name_id);
            let name = name.trim();
            if !name.is_empty() {
                if let Some(key) = ctx.keys_manager.find_by_name(name) {
                    return Ok(key);
                }
            }
        }
    }
    // Fallback: first DH key with private, then EC key with a private key
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
        .ok_or_else(|| Error::Key("no private key for key agreement originator".into()))
}

/// Resolve the recipient's public key from AgreementMethod (EC or DH, for encryption).
fn resolve_recipient_public_key<'a>(
    ctx: &'a EncContext,
    doc: &Document<'_>,
    agreement_id: NodeId,
) -> Result<&'a bergshamra_keys::key::Key, Error> {
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
    Err(Error::Key(
        "no public key for key agreement recipient".into(),
    ))
}

/// Fill in the empty `<dsig:KeyValue/>` in OriginatorKeyInfo with the originator's EC public key.
fn fill_originator_key_value(
    ctx: &EncContext,
    doc: &Document<'_>,
    enc_key_id: NodeId,
    xml: &str,
) -> Result<String, Error> {
    let ki_id = match find_child_element(doc, enc_key_id, ns::DSIG, ns::node::KEY_INFO) {
        Some(ki) => ki,
        None => return Ok(xml.to_owned()),
    };
    let agreement_id = match find_child_element(doc, ki_id, ns::ENC, ns::node::AGREEMENT_METHOD) {
        Some(a) => a,
        None => return Ok(xml.to_owned()),
    };
    let oki_id = match find_child_element(doc, agreement_id, ns::ENC, ns::node::ORIGINATOR_KEY_INFO)
    {
        Some(oki) => oki,
        None => return Ok(xml.to_owned()),
    };
    let key_value_id = match find_child_element(doc, oki_id, ns::DSIG, ns::node::KEY_VALUE) {
        Some(kv) => kv,
        None => return Ok(xml.to_owned()),
    };

    // Get the originator's key and generate KeyValue XML
    let originator_key = resolve_originator_key(ctx, doc, agreement_id)?;
    let kv_xml_content = originator_key
        .data
        .to_key_value_xml("")
        .ok_or_else(|| Error::Key("originator key has no KeyValue XML representation".into()))?;

    // Build the prefix for KeyValue tag from the template
    let kv_range = doc.node_range(key_value_id).unwrap();
    let kv_xml = &xml[kv_range.start..kv_range.end];
    let prefix = extract_prefix(kv_xml, "KeyValue");

    let replacement = if prefix.is_empty() {
        format!("<KeyValue>{kv_xml_content}</KeyValue>")
    } else {
        format!("<{prefix}:KeyValue>{kv_xml_content}</{prefix}:KeyValue>")
    };

    Ok(xml.replacen(kv_xml, &replacement, 1))
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

        if local == ns::node::DIGEST_METHOD && (child_ns == ns::DSIG || child_ns == ns::ENC) {
            if let Some(alg) = elem.get_attribute(ns::attr::ALGORITHM) {
                params.digest_uri = Some(alg.to_owned());
            }
        }
        if local == ns::node::RSA_MGF && (child_ns == ns::ENC11 || child_ns == ns::ENC) {
            if let Some(alg) = elem.get_attribute(ns::attr::ALGORITHM) {
                params.mgf_uri = Some(alg.to_owned());
            }
        }
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
