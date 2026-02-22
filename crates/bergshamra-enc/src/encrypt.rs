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
    let doc =
        roxmltree::Document::parse_with_options(template_xml, bergshamra_xml::parsing_options())
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

    // Replace empty CipherValue in EncryptedData using node range
    let cipher_data = find_child_element(enc_data_node, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData".into()))?;
    let cipher_value = find_child_element(cipher_data, ns::ENC, ns::node::CIPHER_VALUE)
        .ok_or_else(|| Error::MissingElement("CipherValue".into()))?;

    let cv_range = cipher_value.range();
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

            // Check for DerivedKey (ConcatKDF / PBKDF2)
            if child_ns == ns::ENC11 && child_local == ns::node::DERIVED_KEY {
                if let Ok(key) = crate::decrypt::resolve_derived_key(ctx, child, enc_uri) {
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
    let doc = roxmltree::Document::parse_with_options(xml, bergshamra_xml::parsing_options())
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
                let oaep_params = read_oaep_params(enc_method);
                let transport =
                    bergshamra_crypto::keytransport::from_uri_with_params(enc_uri, oaep_params)?;
                // Look for KeyName in this EncryptedKey's KeyInfo to select the
                // correct RSA key (important for multi-recipient encryption).
                let rsa_key = resolve_encrypted_key_rsa(ctx, node)?;
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
                if let Some(kek) = resolve_agreement_method_encrypt(ctx, node, expected_kek_size)? {
                    // Fill in OriginatorKeyInfo's KeyValue with the originator's public key
                    result = fill_originator_key_value(ctx, node, &result)?;
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
                let kek_bytes = resolve_encrypted_key_kek(ctx, node)?;
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
        let cv_range = cipher_value.range();
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
        .ok_or_else(|| Error::Key("no symmetric key for EncryptedKey cipher encryption".into()))
}

/// Resolve the RSA public key for an EncryptedKey element.
/// Checks KeyName inside the EncryptedKey's KeyInfo to find the correct key
/// (needed for multi-recipient encryption where each EncryptedKey targets a different key).
fn resolve_encrypted_key_rsa<'a>(
    ctx: &'a EncContext,
    enc_key_node: roxmltree::Node<'_, '_>,
) -> Result<&'a bergshamra_keys::Key, Error> {
    if let Some(ki) = find_child_element(enc_key_node, ns::DSIG, ns::node::KEY_INFO) {
        if let Some(key_name_node) = find_child_element(ki, ns::DSIG, ns::node::KEY_NAME) {
            let name = key_name_node.text().unwrap_or("").trim();
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
    enc_key_node: roxmltree::Node<'_, '_>,
    kek_len: usize,
) -> Result<Option<Vec<u8>>, Error> {
    let ki = match find_child_element(enc_key_node, ns::DSIG, ns::node::KEY_INFO) {
        Some(ki) => ki,
        None => return Ok(None),
    };

    let agreement = match find_child_element(ki, ns::ENC, ns::node::AGREEMENT_METHOD) {
        Some(a) => a,
        None => return Ok(None),
    };

    let agreement_alg = agreement.attribute(ns::attr::ALGORITHM).unwrap_or("");

    // For encryption, we use:
    //   originator's PRIVATE key + recipient's PUBLIC key → shared secret
    // Then derive KEK from the shared secret via ConcatKDF or PBKDF2.

    // Resolve originator private key (by name in OriginatorKeyInfo)
    let originator_key = resolve_originator_key(ctx, agreement)?;

    // Resolve recipient public key (by name in RecipientKeyInfo)
    let recipient_key = resolve_recipient_public_key(ctx, agreement)?;

    let shared_secret = match agreement_alg {
        algorithm::ECDH_ES => {
            // Get recipient's public key bytes (SEC1 uncompressed point)
            let recipient_public_bytes = recipient_key
                .ec_public_key_bytes()
                .ok_or_else(|| Error::Key("recipient key has no EC public key bytes".into()))?;

            // Compute ECDH shared secret: originator_private × recipient_public
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
    let kdf_method = find_child_element(agreement, ns::ENC11, ns::node::KEY_DERIVATION_METHOD);
    let kek = match kdf_method {
        Some(kdm) => {
            let kdf_uri = kdm.attribute(ns::attr::ALGORITHM).unwrap_or("");
            match kdf_uri {
                algorithm::CONCAT_KDF => {
                    let params = crate::decrypt::parse_concat_kdf_params(kdm)?;
                    bergshamra_crypto::kdf::concat_kdf(&shared_secret, kek_len, &params)?
                }
                algorithm::PBKDF2 => {
                    let params = crate::decrypt::parse_pbkdf2_params(kdm, kek_len)?;
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
    agreement_node: roxmltree::Node<'_, '_>,
) -> Result<&'a bergshamra_keys::key::Key, Error> {
    if let Some(oki) = find_child_element(agreement_node, ns::ENC, ns::node::ORIGINATOR_KEY_INFO) {
        if let Some(key_name_node) = find_child_element(oki, ns::DSIG, ns::node::KEY_NAME) {
            let name = key_name_node.text().unwrap_or("").trim();
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
    agreement_node: roxmltree::Node<'_, '_>,
) -> Result<&'a bergshamra_keys::key::Key, Error> {
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
    Err(Error::Key(
        "no public key for key agreement recipient".into(),
    ))
}

/// Fill in the empty `<dsig:KeyValue/>` in OriginatorKeyInfo with the originator's EC public key.
fn fill_originator_key_value(
    ctx: &EncContext,
    enc_key_node: roxmltree::Node<'_, '_>,
    xml: &str,
) -> Result<String, Error> {
    let ki = match find_child_element(enc_key_node, ns::DSIG, ns::node::KEY_INFO) {
        Some(ki) => ki,
        None => return Ok(xml.to_owned()),
    };
    let agreement = match find_child_element(ki, ns::ENC, ns::node::AGREEMENT_METHOD) {
        Some(a) => a,
        None => return Ok(xml.to_owned()),
    };
    let oki = match find_child_element(agreement, ns::ENC, ns::node::ORIGINATOR_KEY_INFO) {
        Some(oki) => oki,
        None => return Ok(xml.to_owned()),
    };
    let key_value = match find_child_element(oki, ns::DSIG, ns::node::KEY_VALUE) {
        Some(kv) => kv,
        None => return Ok(xml.to_owned()),
    };

    // Get the originator's key and generate KeyValue XML
    let originator_key = resolve_originator_key(ctx, agreement)?;
    let kv_xml_content = originator_key
        .data
        .to_key_value_xml("")
        .ok_or_else(|| Error::Key("originator key has no KeyValue XML representation".into()))?;

    // Build the prefix for KeyValue tag from the template
    let kv_range = key_value.range();
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
    enc_method: roxmltree::Node<'_, '_>,
) -> bergshamra_crypto::keytransport::OaepParams {
    let mut params = bergshamra_crypto::keytransport::OaepParams::default();

    for child in enc_method.children() {
        if !child.is_element() {
            continue;
        }
        let local = child.tag_name().name();
        let child_ns = child.tag_name().namespace().unwrap_or("");

        if local == ns::node::DIGEST_METHOD && (child_ns == ns::DSIG || child_ns == ns::ENC) {
            if let Some(alg) = child.attribute(ns::attr::ALGORITHM) {
                params.digest_uri = Some(alg.to_owned());
            }
        }
        if local == ns::node::RSA_MGF && (child_ns == ns::ENC11 || child_ns == ns::ENC) {
            if let Some(alg) = child.attribute(ns::attr::ALGORITHM) {
                params.mgf_uri = Some(alg.to_owned());
            }
        }
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
