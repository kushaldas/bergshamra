#![forbid(unsafe_code)]

//! XML-DSig signature creation.
//!
//! Signs an XML document using a template with empty DigestValue/SignatureValue.

use crate::context::DsigContext;
use bergshamra_c14n::C14nMode;
use bergshamra_core::{algorithm, ns, Error};
use bergshamra_crypto::digest;
use bergshamra_xml::nodeset::NodeSet;
use std::collections::HashMap;
use uppsala::{Document, NodeId, XmlWriter};

/// Sign an XML template document.
///
/// The template must contain a `<Signature>` element with empty
/// `<DigestValue>` and `<SignatureValue>` elements.
///
/// Returns the signed XML document as a string.
///
/// This convenience wrapper borrows `template_xml` and clones it into an owned
/// string before signing. Use [`sign_owned`] when the caller can transfer
/// ownership and wants to avoid that initial clone.
///
/// # Errors
///
/// Returns an error when the template is malformed, required DSig elements are
/// missing, an algorithm is unsupported, key material cannot be resolved, a
/// transform fails, or the final signature cannot be produced.
pub fn sign(ctx: &DsigContext, template_xml: &str) -> Result<String, Error> {
    sign_owned(ctx, template_xml.to_owned())
}

/// Sign an owned XML template document without cloning the full template first.
///
/// This is useful for bindings that construct a template string immediately
/// before signing and can transfer ownership into the signer.
///
/// The function fills each empty `<DigestValue>` in document order and then
/// signs the updated `<SignedInfo>`. The document is reparsed after each digest
/// replacement so later same-document references see earlier digest values, as
/// required by XML-DSig template signing.
///
/// Same-document fallback transforms borrow this owned string instead of
/// cloning it, and empty `<DigestValue>` / `<SignatureValue>` replacements are
/// applied in place after the parsed document is dropped. This keeps peak memory
/// lower for large templates while preserving the same returned XML.
///
/// # Errors
///
/// Returns an error when parsing, reference resolution, transform execution,
/// digesting, key resolution, or signature generation fails.
pub fn sign_owned(ctx: &DsigContext, mut result_xml: String) -> Result<String, Error> {
    let doc = uppsala::parse(&result_xml).map_err(|e| Error::XmlParse(e.to_string()))?;

    // Build ID map
    let mut id_attrs: Vec<&str> = vec!["Id", "ID", "id", "AssertionID"];
    let extra: Vec<&str> = ctx.id_attrs.iter().map(|s| s.as_str()).collect();
    id_attrs.extend(extra);
    let _id_map = build_id_map(&doc, &id_attrs)?;

    // Find Signature element
    let sig_node = find_element(&doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;
    let signed_info = find_child_element(&doc, sig_node, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    // Read CanonicalizationMethod
    let c14n_method = find_child_element(
        &doc,
        signed_info,
        ns::DSIG,
        ns::node::CANONICALIZATION_METHOD,
    )
    .ok_or_else(|| Error::MissingElement("CanonicalizationMethod".into()))?;
    let c14n_uri = doc
        .element(c14n_method)
        .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
        .ok_or_else(|| Error::MissingAttribute("Algorithm on CanonicalizationMethod".into()))?
        .to_owned();
    let c14n_mode = C14nMode::from_uri(&c14n_uri)
        .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {c14n_uri}")))?;
    let inclusive_prefixes = read_inclusive_prefixes(&doc, c14n_method);

    // Read SignatureMethod
    let sig_method = find_child_element(&doc, signed_info, ns::DSIG, ns::node::SIGNATURE_METHOD)
        .ok_or_else(|| Error::MissingElement("SignatureMethod".into()))?;
    let sig_method_uri = doc
        .element(sig_method)
        .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
        .ok_or_else(|| Error::MissingAttribute("Algorithm on SignatureMethod".into()))?
        .to_owned();

    // Process each Reference to compute digests.
    // We re-parse result_xml on each iteration so that same-document references
    // (e.g. URI=#reference-1) see DigestValues filled in by earlier iterations.
    let ref_count = find_child_elements(&doc, signed_info, ns::DSIG, ns::node::REFERENCE).len();
    drop(doc);
    // DigestValue and SignatureValue inserts are small. Reserving after the
    // initial parse keeps later in-place replacements from reallocating while a
    // document tree is live.
    result_xml.reserve(4096);

    for ref_idx in 0..ref_count {
        // Re-parse current state so same-document refs see filled DigestValues
        let cur_doc = uppsala::parse(&result_xml).map_err(|e| Error::XmlParse(e.to_string()))?;
        let cur_id_map = build_id_map(&cur_doc, &id_attrs)?;
        let cur_sig = find_element(&cur_doc, ns::DSIG, ns::node::SIGNATURE)
            .ok_or_else(|| Error::MissingElement("Signature".into()))?;
        let cur_signed_info =
            find_child_element(&cur_doc, cur_sig, ns::DSIG, ns::node::SIGNED_INFO)
                .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;
        let cur_refs =
            find_child_elements(&cur_doc, cur_signed_info, ns::DSIG, ns::node::REFERENCE);
        let reference = cur_refs[ref_idx];

        let uri = cur_doc
            .element(reference)
            .and_then(|e| e.get_attribute(ns::attr::URI))
            .unwrap_or("");

        // Skip cid: URIs — these reference MIME attachments outside the XML document
        // (common in WS-Security). Digests are pre-computed by the caller.
        // See docs/adr/0002-cid-uri-scheme-skip.md
        if uri.starts_with("cid:") {
            continue;
        }

        let digest_method =
            find_child_element(&cur_doc, reference, ns::DSIG, ns::node::DIGEST_METHOD)
                .ok_or_else(|| Error::MissingElement("DigestMethod".into()))?;
        let digest_uri = cur_doc
            .element(digest_method)
            .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
            .ok_or_else(|| Error::MissingAttribute("Algorithm on DigestMethod".into()))?;

        let transforms_node =
            find_child_element(&cur_doc, reference, ns::DSIG, ns::node::TRANSFORMS);

        // The common enveloped-signature + C14N case can be digested directly
        // from the parsed document. Any transform chain outside that narrow
        // shape returns `None` and is handled by the generic pipeline below.
        let fast_digest = reference_node_set_for_fast(&cur_doc, &cur_id_map, uri)?
            .and_then(|node_set| {
                try_fast_reference_digest(&cur_doc, cur_sig, node_set, transforms_node, digest_uri)
                    .transpose()
            })
            .transpose()?;

        let computed = if let Some(computed) = fast_digest {
            computed
        } else {
            // Resolve reference and apply the generic transform pipeline.
            let mut data = if uri.is_empty() {
                // Per W3C spec: URI="" selects whole document without comments
                let ns = NodeSet::all_without_comments(&cur_doc);
                bergshamra_transforms::TransformData::xml_borrowed(&result_xml, Some(ns))
            } else if let Some(fragment) = bergshamra_xml::xpath::parse_same_document_ref(uri) {
                if fragment == "xpointer(/)" {
                    bergshamra_transforms::TransformData::xml_borrowed(&result_xml, None)
                } else {
                    let is_xpointer = bergshamra_xml::xpath::parse_xpointer_id(fragment).is_some();
                    let frag_id =
                        bergshamra_xml::xpath::parse_xpointer_id(fragment).unwrap_or(fragment);
                    let resolved_id =
                        bergshamra_xml::xpath::resolve_id(&cur_doc, &cur_id_map, frag_id)?;
                    let ns = if is_xpointer {
                        NodeSet::tree_with_comments(resolved_id, &cur_doc)
                    } else {
                        NodeSet::tree_without_comments(resolved_id, &cur_doc)
                    };
                    bergshamra_transforms::TransformData::xml_borrowed(&result_xml, Some(ns))
                }
            } else {
                // Try url-map for external URIs
                let mut resolved = None;
                for (map_url, file_path) in &ctx.url_maps {
                    if uri == map_url || uri.starts_with(map_url) {
                        let bytes = std::fs::read(file_path)
                            .map_err(|e| Error::Other(format!("url-map {file_path}: {e}")))?;
                        resolved = Some(bergshamra_transforms::TransformData::Binary(bytes));
                        break;
                    }
                }
                // Try resolving as a relative file path (no scheme = local file)
                if resolved.is_none() && !uri.contains("://") {
                    if let Some(base) = &ctx.base_dir {
                        let path = std::path::Path::new(base).join(uri);
                        if path.exists() {
                            let bytes = std::fs::read(&path)
                                .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
                            resolved = Some(bergshamra_transforms::TransformData::Binary(bytes));
                        }
                    }
                    if resolved.is_none() {
                        let path = std::path::Path::new(uri);
                        if path.exists() {
                            let bytes = std::fs::read(path)
                                .map_err(|e| Error::Other(format!("{uri}: {e}")))?;
                            resolved = Some(bergshamra_transforms::TransformData::Binary(bytes));
                        }
                    }
                }
                resolved.ok_or_else(|| Error::InvalidUri(format!("unsupported URI: {uri}")))?
            };

            if let Some(transforms_id) = transforms_node {
                for t_node in cur_doc.children(transforms_id) {
                    let is_transform = cur_doc
                        .element(t_node)
                        .is_some_and(|e| &*e.name.local_name == ns::node::TRANSFORM);
                    if !is_transform {
                        continue;
                    }
                    let t_uri = cur_doc
                        .element(t_node)
                        .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
                        .unwrap_or("");
                    data = crate::verify::apply_transform(t_uri, data, t_node, cur_sig, &cur_doc)?;
                }
            }

            let bytes = data.to_binary()?;
            let computed = digest::digest(digest_uri, &bytes)?;
            drop(bytes);
            computed
        };

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let digest_b64 = engine.encode(&computed);

        // Capture replacement metadata while the parsed document is live, then
        // drop it before mutating `result_xml`. This avoids allocating a second
        // document-sized XML string while the DOM still holds the first one.
        let mut needs_digest_fallback = false;
        let digest_replacement = if let Some(digest_value_id) =
            find_child_element(&cur_doc, reference, ns::DSIG, ns::node::DIGEST_VALUE)
        {
            let digest_value_text = cur_doc.text_content_deep(digest_value_id);
            if digest_value_text.trim().is_empty() {
                empty_element_replacement(&result_xml, &cur_doc, digest_value_id, "DigestValue")
            } else {
                None
            }
        } else {
            needs_digest_fallback = true;
            None
        };
        drop(cur_doc);

        if let Some(replacement) = digest_replacement {
            replace_element_in_place(&mut result_xml, replacement, &digest_b64);
        } else if needs_digest_fallback {
            replace_first_empty_element_in_place(&mut result_xml, "DigestValue", &digest_b64);
        }
    }

    // Now canonicalize SignedInfo and compute signature
    // Re-parse the updated XML
    let updated_doc = uppsala::parse(&result_xml).map_err(|e| Error::XmlParse(e.to_string()))?;
    let updated_sig = find_element(&updated_doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;
    let updated_signed_info =
        find_child_element(&updated_doc, updated_sig, ns::DSIG, ns::node::SIGNED_INFO)
            .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    let signed_info_ns = NodeSet::tree_without_comments(updated_signed_info, &updated_doc);
    let c14n_signed_info = bergshamra_c14n::canonicalize_doc(
        &updated_doc,
        c14n_mode,
        Some(&signed_info_ns),
        &inclusive_prefixes,
    )?;

    // Sign
    let signature = if let Some(ref hsm_signer) = ctx.hsm_signer {
        // HSM signer path — key material stays on the HSM.
        // The HSM signer already knows its algorithm, so we skip PQ context
        // extraction and software key lookup. But we MUST cross-check that the
        // signer's algorithm matches the template's <SignatureMethod> URI:
        // otherwise the emitted document would declare one algorithm while the
        // SignatureValue was produced with another, making it self-inconsistent
        // and likely to fail interop verification.
        let signer_uri = bergshamra_crypto::sign::kryptering_algorithm_uri(hsm_signer.algorithm());
        if signer_uri != Some(sig_method_uri.as_str()) {
            return Err(Error::UnsupportedAlgorithm(format!(
                "HSM signer algorithm {:?} (URI {}) does not match the template's SignatureMethod {sig_method_uri}",
                hsm_signer.algorithm(),
                signer_uri.unwrap_or("<unmapped>"),
            )));
        }
        hsm_signer
            .sign(&c14n_signed_info)
            .map_err(crate::map_kryptering_err)?
    } else {
        // Software key path (existing behaviour)
        let key_ref = ctx.keys_manager.first_key()?;
        let signing_key = key_ref
            .to_signing_key()
            .ok_or_else(|| Error::Key("no signing key".into()))?;

        // Re-find sig_method in the updated doc for PQ context / HMAC length extraction
        let updated_sig_method = find_child_element(
            &updated_doc,
            updated_signed_info,
            ns::DSIG,
            ns::node::SIGNATURE_METHOD,
        )
        .ok_or_else(|| Error::MissingElement("SignatureMethod".into()))?;

        // Extract PQ context string for ML-DSA/SLH-DSA signing
        let pq_context: Option<Vec<u8>> =
            if bergshamra_crypto::sign::is_pq_algorithm(&sig_method_uri) {
                let ctx_node = find_child_element(
                    &updated_doc,
                    updated_sig_method,
                    ns::XMLSEC_PQ,
                    ns::node::MLDSA_CONTEXT_STRING,
                )
                .or_else(|| {
                    find_child_element(
                        &updated_doc,
                        updated_sig_method,
                        ns::XMLSEC_PQ,
                        ns::node::SLHDSA_CONTEXT_STRING,
                    )
                });
                if let Some(cn) = ctx_node {
                    let b64_text = updated_doc.text_content_deep(cn);
                    let b64 = b64_text.trim();
                    if b64.is_empty() {
                        None
                    } else {
                        use base64::Engine as _;
                        let engine = base64::engine::general_purpose::STANDARD;
                        let decoded = engine
                            .decode(b64)
                            .map_err(|e| Error::Base64(format!("PQ context string: {e}")))?;
                        Some(decoded)
                    }
                } else {
                    None
                }
            } else {
                None
            };

        let sig_alg = bergshamra_crypto::sign::from_uri_with_context(&sig_method_uri, pq_context)?;
        let mut sig = sig_alg.sign(&signing_key, &c14n_signed_info)?;

        // Truncate HMAC output if HMACOutputLength is specified
        if bergshamra_crypto::sign::is_hmac_algorithm(&sig_method_uri) {
            if let Some(hmac_len_id) = find_child_element(
                &updated_doc,
                updated_sig_method,
                ns::DSIG,
                ns::node::HMAC_OUTPUT_LENGTH,
            ) {
                let len_text_owned = updated_doc.text_content_deep(hmac_len_id);
                let len_text = len_text_owned.trim();
                if let Ok(bits) = len_text.parse::<usize>() {
                    if bits % 8 == 0 {
                        let bytes = bits / 8;
                        if bytes < sig.len() {
                            sig.truncate(bytes);
                        }
                    }
                }
            }
        }

        sig
    };

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let sig_b64 = engine.encode(&signature);
    drop(c14n_signed_info);

    // Replace empty SignatureValue
    let mut needs_signature_fallback = false;
    let signature_replacement = if let Some(sig_value_id) = find_child_element(
        &updated_doc,
        updated_sig,
        ns::DSIG,
        ns::node::SIGNATURE_VALUE,
    ) {
        let sig_value_text = updated_doc.text_content_deep(sig_value_id);
        if sig_value_text.trim().is_empty() {
            empty_element_replacement(&result_xml, &updated_doc, sig_value_id, "SignatureValue")
        } else {
            None
        }
    } else {
        needs_signature_fallback = true;
        None
    };
    drop(updated_doc);

    if let Some(replacement) = signature_replacement {
        replace_element_in_place(&mut result_xml, replacement, &sig_b64);
    } else if needs_signature_fallback {
        replace_first_empty_element_in_place(&mut result_xml, "SignatureValue", &sig_b64);
    }

    // Populate KeyInfo elements from the software key (skipped for HSM signers
    // because the key material lives on the HSM and is not available here).
    if ctx.hsm_signer.is_none() {
        let key = ctx.keys_manager.first_key()?;

        // Populate empty X509Data with certificate(s) from the signing key
        if !key.x509_chain.is_empty() {
            result_xml = populate_x509_data(&result_xml, &key.x509_chain)?;
        }

        // Populate empty KeyValue with the public key
        result_xml = populate_key_value(&result_xml, &key.data)?;

        // Populate empty DEREncodedKeyValue with SPKI DER
        result_xml = populate_der_encoded_key_value(&result_xml, &key.data)?;

        // Encrypt session key into EncryptedKey elements with empty CipherValue
        result_xml = encrypt_session_key_in_template(&result_xml, key, &ctx.keys_manager)?;
    }

    Ok(result_xml)
}

// Re-use helpers from verify module
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
    parent: NodeId,
    ns_uri: &str,
    local_name: &str,
) -> Option<NodeId> {
    for id in doc.children(parent) {
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

fn find_child_elements(
    doc: &Document<'_>,
    parent: NodeId,
    ns_uri: &str,
    local_name: &str,
) -> Vec<NodeId> {
    doc.children(parent)
        .into_iter()
        .filter(|&id| {
            doc.element(id).is_some_and(|elem| {
                &*elem.name.local_name == local_name
                    && elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
            })
        })
        .collect()
}

fn build_id_map(doc: &Document<'_>, attr_names: &[&str]) -> Result<HashMap<String, NodeId>, Error> {
    let mut map = HashMap::new();
    for id in doc.descendants(doc.root()) {
        if let Some(elem) = doc.element(id) {
            for attr_name in attr_names {
                if let Some(val) = elem.get_attribute(attr_name) {
                    if map.insert(val.to_owned(), id).is_some() {
                        return Err(Error::XmlStructure(format!("duplicate ID: {val}")));
                    }
                }
            }
            // Also check xml:id
            if let Some(val) = elem.get_attribute_ns("http://www.w3.org/XML/1998/namespace", "id") {
                if map.insert(val.to_owned(), id).is_some() {
                    return Err(Error::XmlStructure(format!("duplicate ID: {val}")));
                }
            }
        }
    }
    Ok(map)
}

/// Resolve a reference URI into the node-set shape used by the signing fast path.
///
/// Returns:
///
/// - `Ok(None)` when the URI is not a same-document reference and must use the
///   generic pipeline.
/// - `Ok(Some(None))` for `#xpointer(/)`, which means "the whole parsed
///   document" and therefore no subset node set.
/// - `Ok(Some(Some(node_set)))` for empty URI, bare `#id`, and
///   `#xpointer(id(...))` references that the fast path can canonicalize.
fn reference_node_set_for_fast(
    doc: &Document<'_>,
    id_map: &HashMap<String, NodeId>,
    uri: &str,
) -> Result<Option<Option<NodeSet>>, Error> {
    if uri.is_empty() {
        return Ok(Some(Some(NodeSet::all_without_comments(doc))));
    }

    let Some(fragment) = bergshamra_xml::xpath::parse_same_document_ref(uri) else {
        return Ok(None);
    };

    if fragment == "xpointer(/)" {
        return Ok(Some(None));
    }

    let is_xpointer = bergshamra_xml::xpath::parse_xpointer_id(fragment).is_some();
    let frag_id = bergshamra_xml::xpath::parse_xpointer_id(fragment).unwrap_or(fragment);
    let resolved_id = bergshamra_xml::xpath::resolve_id(doc, id_map, frag_id)?;
    let node_set = if is_xpointer {
        NodeSet::tree_with_comments(resolved_id, doc)
    } else {
        NodeSet::tree_without_comments(resolved_id, doc)
    };
    Ok(Some(Some(node_set)))
}

/// C14N sink that feeds canonical bytes into a digest stream.
///
/// Signing only needs the reference digest, not the full pre-digest byte
/// buffer, so this sink avoids allocating a document-sized `Vec<u8>` on the
/// fast path.
struct ReferenceDigestSink {
    inner: Box<dyn digest::DigestAlgorithm>,
}

impl ReferenceDigestSink {
    /// Create a digest sink for an XML Security digest algorithm URI.
    fn new(uri: &str) -> Result<Self, Error> {
        Ok(Self {
            inner: digest::from_uri(uri)?,
        })
    }

    /// Finalize the digest stream and return the computed digest bytes.
    fn finalize(self) -> Vec<u8> {
        self.inner.finalize()
    }
}

impl bergshamra_c14n::C14nSink for ReferenceDigestSink {
    /// Feed canonicalized bytes into the underlying digest.
    fn write(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }
}

/// Canonicalization mode, InclusiveNamespaces PrefixList, and selected node-set.
type FastC14nParams = (C14nMode, Vec<String>, Option<NodeSet>);

/// Compute a reference digest through the fast C14N path.
///
/// Returns `Ok(None)` when the transform list contains anything other than the
/// supported fast-path sequence. The caller must then run the generic transform
/// pipeline to preserve full XML-DSig behavior.
fn try_fast_reference_digest(
    doc: &Document<'_>,
    sig_node: NodeId,
    node_set: Option<NodeSet>,
    transforms_node: Option<NodeId>,
    digest_uri: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let Some((c14n_mode, inclusive_prefixes, node_set)) =
        fast_reference_c14n_params(doc, sig_node, node_set, transforms_node)?
    else {
        return Ok(None);
    };

    let mut sink = ReferenceDigestSink::new(digest_uri)?;
    bergshamra_c14n::canonicalize_doc_to(
        doc,
        c14n_mode,
        node_set.as_ref(),
        &inclusive_prefixes,
        &mut sink,
    )?;
    Ok(Some(sink.finalize()))
}

/// Parse the fast-path transform list and return canonicalization parameters.
///
/// The fast path accepts only:
///
/// - zero or one enveloped-signature transform before C14N
/// - zero or one C14N transform
///
/// Any other transform, missing algorithm URI, duplicate C14N transform, or
/// enveloped-signature after C14N returns `Ok(None)` so the caller can fall
/// back to generic transform execution.
fn fast_reference_c14n_params(
    doc: &Document<'_>,
    sig_node: NodeId,
    mut node_set: Option<NodeSet>,
    transforms_node: Option<NodeId>,
) -> Result<Option<FastC14nParams>, Error> {
    let mut c14n_mode = C14nMode::Inclusive;
    let mut inclusive_prefixes = Vec::new();
    let mut saw_c14n = false;

    if let Some(transforms_id) = transforms_node {
        for t_node in doc.children(transforms_id) {
            let is_transform = doc
                .element(t_node)
                .is_some_and(|e| &*e.name.local_name == ns::node::TRANSFORM);
            if !is_transform {
                continue;
            }
            let Some(t_uri) = doc
                .element(t_node)
                .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
            else {
                return Ok(None);
            };

            match t_uri {
                algorithm::ENVELOPED_SIGNATURE => {
                    if saw_c14n {
                        return Ok(None);
                    }
                    let ns = node_set.get_or_insert_with(|| NodeSet::all(doc));
                    remove_subtree_from_node_set(sig_node, doc, ns);
                }
                algorithm::C14N
                | algorithm::C14N_WITH_COMMENTS
                | algorithm::C14N11
                | algorithm::C14N11_WITH_COMMENTS
                | algorithm::EXC_C14N
                | algorithm::EXC_C14N_WITH_COMMENTS => {
                    if saw_c14n {
                        return Ok(None);
                    }
                    c14n_mode = C14nMode::from_uri(t_uri)
                        .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {t_uri}")))?;
                    inclusive_prefixes = read_inclusive_prefixes(doc, t_node);
                    saw_c14n = true;
                }
                _ => return Ok(None),
            }
        }
    }

    Ok(Some((c14n_mode, inclusive_prefixes, node_set)))
}

/// Remove a node and all descendants from `node_set`.
///
/// This implements the enveloped-signature transform for the fast path. It uses
/// [`NodeSet::remove_id`], so it works for both normal and inverted node sets.
fn remove_subtree_from_node_set(id: NodeId, doc: &Document<'_>, node_set: &mut NodeSet) {
    node_set.remove_id(id);
    for child in doc.children(id) {
        remove_subtree_from_node_set(child, doc, node_set);
    }
}

/// Byte range and tag name needed to replace an empty XML element.
struct ElementReplacement {
    /// Byte range of the parsed element in the current XML string.
    range: std::ops::Range<usize>,
    /// Qualified tag name to write back, preserving the original namespace
    /// prefix when the template used one.
    tag: String,
}

/// Locate an empty element by parsed node id without allocating replacement XML.
///
/// The returned range is valid only for the exact `xml` string that was parsed
/// into `doc`. Callers must finish using `doc`, drop it, and then apply the
/// replacement before reparsing or making additional range-based edits.
fn empty_element_replacement(
    xml: &str,
    doc: &Document<'_>,
    id: NodeId,
    local_name: &str,
) -> Option<ElementReplacement> {
    let range = doc.node_range(id)?;
    let original = &xml[range.clone()];
    let prefix = extract_tag_prefix(original, local_name);
    let tag = pname(prefix, local_name);
    Some(ElementReplacement { range, tag })
}

/// Replace an element range in-place with `<tag>new_content</tag>`.
///
/// This allocates only the small replacement fragment, then lets `String`
/// shift the existing buffer. The caller is responsible for ensuring no parsed
/// `Document` still borrows `xml`.
fn replace_element_in_place(xml: &mut String, replacement: ElementReplacement, new_content: &str) {
    let mut w = XmlWriter::new();
    w.start_element(&replacement.tag, &[]);
    w.text(new_content);
    w.end_element(&replacement.tag);
    let replacement_xml = w.into_string();
    xml.replace_range(replacement.range, &replacement_xml);
}

/// Replace the first empty element in-place.
///
/// This is the fallback for unusual templates where the caller did not locate
/// the exact parsed node first. It still avoids returning a second full XML
/// string: the document is parsed only to find the range, then the mutation is
/// applied after that parse result has gone out of scope.
fn replace_first_empty_element_in_place(
    xml: &mut String,
    local_name: &str,
    new_content: &str,
) -> bool {
    // Use uppsala to find the element's byte range for accurate replacement
    let replacement = if let Ok(doc) = uppsala::parse(xml.as_str()) {
        let mut replacement = None;
        for id in doc.descendants(doc.root()) {
            let elem = match doc.element(id) {
                Some(e) => e,
                None => continue,
            };
            if &*elem.name.local_name != local_name {
                continue;
            }
            // Check if this is a dsig element (or unnamespaced)
            let elem_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
            if !elem_ns.is_empty() && elem_ns != ns::DSIG {
                continue;
            }
            // Check if content is empty or whitespace-only
            let text = doc.text_content_deep(id);
            if !text.trim().is_empty() {
                continue;
            }
            // Found an empty element — replace it
            replacement = empty_element_replacement(xml, &doc, id, local_name);
            break;
        }
        replacement
    } else {
        None
    };

    if let Some(replacement) = replacement {
        replace_element_in_place(xml, replacement, new_content);
        true
    } else {
        false
    }
}

/// Build a prefixed element name like `"ds:Foo"` or just `"Foo"`.
fn pname(prefix: &str, local: &str) -> String {
    if prefix.is_empty() {
        local.to_string()
    } else {
        format!("{prefix}:{local}")
    }
}

/// Extract namespace prefix from a raw XML tag fragment like `<ds:SignatureValue/>`.
fn extract_tag_prefix<'a>(xml_fragment: &'a str, local_name: &str) -> &'a str {
    let trimmed = xml_fragment.trim_start_matches('<');
    if let Some(colon_pos) = trimmed.find(':') {
        let after_colon = &trimmed[colon_pos + 1..];
        if after_colon.starts_with(local_name) {
            return &trimmed[..colon_pos];
        }
    }
    ""
}

/// Extract the opening tag from a raw XML fragment, preserving all attributes
/// and namespace declarations. Converts self-closing `/>` to `>`.
///
/// E.g. `<dsig11:Foo xmlns:dsig11="..."/>` → `<dsig11:Foo xmlns:dsig11="...">`
fn extract_open_tag(raw_xml: &str) -> String {
    if let Some(slash_gt) = raw_xml.find("/>") {
        format!("{}>", &raw_xml[..slash_gt])
    } else if let Some(gt) = raw_xml.find('>') {
        raw_xml[..=gt].to_string()
    } else {
        raw_xml.to_string()
    }
}

/// Populate empty `<X509Data/>` element in the signed XML with certificates.
///
/// Handles two cases:
/// 1. `<X509Data/>` (self-closing, no children) — inserts X509Certificate elements
/// 2. `<X509Data>` with empty child template elements like `<X509SubjectName/>`,
///    `<X509IssuerSerial/>`, `<X509SKI/>`, `<X509Certificate/>` — populates each
fn populate_x509_data(xml: &str, x509_chain: &[Vec<u8>]) -> Result<String, Error> {
    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;

    // Find X509Data element in KeyInfo
    let x509_data_id = doc.descendants(doc.root()).into_iter().find(|&id| {
        doc.element(id).is_some_and(|elem| {
            &*elem.name.local_name == ns::node::X509_DATA
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG
        })
    });

    let x509_data_id = match x509_data_id {
        Some(id) => id,
        None => return Ok(xml.to_owned()),
    };

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    // Check if empty (no child elements) — simple case
    let has_children = doc
        .children(x509_data_id)
        .iter()
        .any(|&c| doc.element(c).is_some());
    if !has_children {
        // Build X509Certificate elements
        let x509_range = doc.node_range(x509_data_id).unwrap();
        let prefix = extract_tag_prefix(&xml[x509_range.start..x509_range.end], "X509Data");
        let cert_tag = pname(prefix, "X509Certificate");

        let mut cw = XmlWriter::new();
        for cert_der in x509_chain {
            let cert_b64 = engine.encode(cert_der);
            cw.start_element(&cert_tag, &[]);
            cw.text(&cert_b64);
            cw.end_element(&cert_tag);
        }
        let certs_xml = cw.into_string();

        let data_tag = if !prefix.is_empty() {
            let orig = &xml[x509_range.start..x509_range.end];
            let ns_decl = format!("xmlns:{prefix}=");
            if orig.contains(&ns_decl) {
                "X509Data".to_string()
            } else {
                pname(prefix, "X509Data")
            }
        } else {
            "X509Data".to_string()
        };
        let mut w = XmlWriter::new();
        w.start_element(&data_tag, &[]);
        w.raw(&certs_xml);
        w.end_element(&data_tag);
        let replacement = w.into_string();

        let mut result = String::with_capacity(xml.len() + certs_xml.len());
        result.push_str(&xml[..x509_range.start]);
        result.push_str(&replacement);
        result.push_str(&xml[x509_range.end..]);
        return Ok(result);
    }

    // Template case: X509Data has child elements that need populating
    // Parse the first certificate to extract subject, issuer, serial, SKI
    let first_cert_der = match x509_chain.first() {
        Some(c) => c,
        None => return Ok(xml.to_owned()),
    };

    let cert_info = extract_x509_info(first_cert_der);

    // Process child elements — replace each empty one with populated content
    let mut result = xml.to_owned();
    // Process in reverse order of byte offset so replacements don't shift ranges
    let mut children_to_process: Vec<NodeId> = doc
        .children(x509_data_id)
        .into_iter()
        .filter(|&c| doc.element(c).is_some())
        .collect();
    children_to_process.sort_by(|a, b| {
        let ra = doc.node_range(*a).unwrap();
        let rb = doc.node_range(*b).unwrap();
        rb.start.cmp(&ra.start)
    });

    for child_id in children_to_process {
        let elem = doc.element(child_id).unwrap();
        let name = &*elem.name.local_name;
        let child_text = doc.text_content_deep(child_id);
        if !child_text.trim().is_empty() {
            continue; // Already has content
        }

        let child_range = doc.node_range(child_id).unwrap();
        let raw = &result[child_range.start..child_range.end];
        let prefix = extract_tag_prefix(raw, name);

        let replacement = match name {
            "X509Certificate" => {
                // Emit the full certificate chain (leaf + any intermediates +
                // root present on the signing key), one <X509Certificate> per
                // cert, so a verifier configured with only the root anchor can
                // still build the path. A single <X509Certificate/> placeholder
                // is expanded into N sibling elements.
                let tag = pname(prefix, "X509Certificate");
                let mut w = XmlWriter::new();
                for cert_der in x509_chain {
                    let cert_b64 = engine.encode(cert_der);
                    w.start_element(&tag, &[]);
                    w.text(&cert_b64);
                    w.end_element(&tag);
                }
                w.into_string()
            }
            "X509SubjectName" => {
                if let Some(ref subj) = cert_info.subject_name {
                    let tag = pname(prefix, "X509SubjectName");
                    let mut w = XmlWriter::new();
                    w.start_element(&tag, &[]);
                    w.text(subj);
                    w.end_element(&tag);
                    w.into_string()
                } else {
                    continue;
                }
            }
            "X509IssuerSerial" => {
                if let (Some(ref issuer), Some(ref serial)) =
                    (&cert_info.issuer_name, &cert_info.serial_number)
                {
                    let serial_tag = pname(prefix, "X509IssuerSerial");
                    let issuer_tag = pname(prefix, "X509IssuerName");
                    let num_tag = pname(prefix, "X509SerialNumber");
                    let mut w = XmlWriter::new();
                    w.start_element(&serial_tag, &[]);
                    w.start_element(&issuer_tag, &[]);
                    w.text(issuer);
                    w.end_element(&issuer_tag);
                    w.start_element(&num_tag, &[]);
                    w.text(serial);
                    w.end_element(&num_tag);
                    w.end_element(&serial_tag);
                    w.into_string()
                } else {
                    continue;
                }
            }
            "X509SKI" => {
                if let Some(ref ski_b64) = cert_info.ski_b64 {
                    let tag = pname(prefix, "X509SKI");
                    let mut w = XmlWriter::new();
                    w.start_element(&tag, &[]);
                    w.text(ski_b64);
                    w.end_element(&tag);
                    w.into_string()
                } else {
                    continue;
                }
            }
            _ => continue, // X509CRL and others — skip
        };

        let mut new_result = String::with_capacity(result.len() + replacement.len());
        new_result.push_str(&result[..child_range.start]);
        new_result.push_str(&replacement);
        new_result.push_str(&result[child_range.end..]);
        result = new_result;
    }

    Ok(result)
}

/// Extracted X.509 certificate info for template population.
struct X509Info {
    subject_name: Option<String>,
    issuer_name: Option<String>,
    serial_number: Option<String>,
    ski_b64: Option<String>,
}

/// Extract X.509 info from a DER-encoded certificate.
fn extract_x509_info(cert_der: &[u8]) -> X509Info {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = match Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => {
            return X509Info {
                subject_name: None,
                issuer_name: None,
                serial_number: None,
                ski_b64: None,
            }
        }
    };

    let subject_name = Some(format_rdn_sequence(&cert.tbs_certificate.subject));
    let issuer_name = Some(format_rdn_sequence(&cert.tbs_certificate.issuer));
    let serial_number = Some(format_serial(&cert.tbs_certificate.serial_number));

    // Extract SKI from extensions
    let ski_b64 = extract_ski(&cert);

    X509Info {
        subject_name,
        issuer_name,
        serial_number,
        ski_b64,
    }
}

/// Format an X.500 Name (RDN sequence) as a comma-separated string.
/// Uses the RFC 2253 / xmlsec convention.
fn format_rdn_sequence(name: &x509_cert::name::Name) -> String {
    use der::oid::db::rfc4519;
    use std::fmt::Write;

    let mut parts = Vec::new();
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            let oid = &atv.oid;
            let prefix = if *oid == rfc4519::CN {
                "CN"
            } else if *oid == rfc4519::O {
                "O"
            } else if *oid == rfc4519::OU {
                "OU"
            } else if *oid == rfc4519::C {
                "C"
            } else if *oid == rfc4519::ST {
                "ST"
            } else if *oid == rfc4519::L {
                "L"
            } else if *oid == rfc4519::SERIAL_NUMBER {
                "serialNumber"
            } else {
                // Use OID dot notation for unknown types
                let mut s = String::new();
                let _ = write!(s, "{oid}");
                parts.push(s);
                continue;
            };

            // Decode the value - try UTF8String, then PrintableString, then raw bytes
            let val = decode_atv_value(&atv.value);
            parts.push(format!("{prefix}={val}"));
        }
    }

    // xmlsec outputs in reverse order (most specific first)
    parts.reverse();
    parts.join(",")
}

/// Decode an AttributeValue (ASN.1 Any) to a string.
fn decode_atv_value(val: &der::Any) -> String {
    use der::Decode;

    // Try UTF8String
    if let Ok(s) = der::asn1::Utf8StringRef::from_der(val.value()) {
        return s.as_str().to_string();
    }
    // Try PrintableString
    if let Ok(s) = der::asn1::PrintableStringRef::from_der(val.value()) {
        return s.as_str().to_string();
    }
    // Try IA5String
    if let Ok(s) = der::asn1::Ia5StringRef::from_der(val.value()) {
        return s.as_str().to_string();
    }
    // Fall back to raw UTF-8 interpretation of the value bytes
    String::from_utf8_lossy(val.value()).to_string()
}

/// Format serial number as a decimal string.
fn format_serial(serial: &x509_cert::serial_number::SerialNumber) -> String {
    // SerialNumber is an ASN.1 INTEGER — get the raw bytes
    let bytes = serial.as_bytes();

    // Convert big-endian bytes to decimal
    if bytes.is_empty() {
        return "0".to_string();
    }

    // Check if negative (high bit set)
    let is_negative = bytes[0] & 0x80 != 0;
    if is_negative {
        // Two's complement — rare for serial numbers but handle it
        return format_negative_serial(bytes);
    }

    // Positive: convert bytes to decimal
    let mut result = Vec::new();
    let mut remainder = bytes.to_vec();

    // Simple big-integer division
    loop {
        let (quotient, rem) = big_divmod(&remainder, 10);
        result.push(b'0' + rem);
        if quotient.is_empty() || (quotient.len() == 1 && quotient[0] == 0) {
            break;
        }
        remainder = quotient;
    }

    result.reverse();
    String::from_utf8(result).unwrap_or_else(|_| "0".to_string())
}

fn format_negative_serial(bytes: &[u8]) -> String {
    // Negate the two's complement and prepend minus sign
    let mut negated = bytes.to_vec();
    let mut carry = true;
    for b in negated.iter_mut().rev() {
        *b = !*b;
        if carry {
            let (val, c) = b.overflowing_add(1);
            *b = val;
            carry = c;
        }
    }
    let result = format_serial_bytes(&negated);
    format!("-{result}")
}

fn format_serial_bytes(bytes: &[u8]) -> String {
    let mut result = Vec::new();
    let mut remainder = bytes.to_vec();
    loop {
        let (quotient, rem) = big_divmod(&remainder, 10);
        result.push(b'0' + rem);
        if quotient.is_empty() || (quotient.len() == 1 && quotient[0] == 0) {
            break;
        }
        remainder = quotient;
    }
    result.reverse();
    String::from_utf8(result).unwrap_or_else(|_| "0".to_string())
}

/// Divide a big-endian byte array by a small divisor, return (quotient, remainder).
fn big_divmod(bytes: &[u8], divisor: u8) -> (Vec<u8>, u8) {
    let mut quotient = Vec::with_capacity(bytes.len());
    let mut rem: u16 = 0;
    for &b in bytes {
        rem = rem * 256 + b as u16;
        quotient.push((rem / divisor as u16) as u8);
        rem %= divisor as u16;
    }
    // Strip leading zeros
    while quotient.len() > 1 && quotient[0] == 0 {
        quotient.remove(0);
    }
    (quotient, rem as u8)
}

/// Extract Subject Key Identifier from certificate extensions.
fn extract_ski(cert: &x509_cert::Certificate) -> Option<String> {
    use base64::Engine;
    use der::Decode;

    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        // SKI OID: 2.5.29.14
        if ext.extn_id == der::oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER {
            // The value is an OCTET STRING wrapping an OCTET STRING
            let octet = der::asn1::OctetString::from_der(ext.extn_value.as_bytes()).ok()?;
            return Some(base64::engine::general_purpose::STANDARD.encode(octet.as_bytes()));
        }
    }
    None
}

/// Populate an empty `<KeyValue/>` element with the signing key's public key.
fn populate_key_value(
    xml: &str,
    key_data: &bergshamra_keys::key::KeyData,
) -> Result<String, Error> {
    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;

    let kv_id = doc.descendants(doc.root()).into_iter().find(|&id| {
        doc.element(id).is_some_and(|elem| {
            &*elem.name.local_name == ns::node::KEY_VALUE
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG
        })
    });

    let kv_id = match kv_id {
        Some(id) => id,
        None => return Ok(xml.to_owned()),
    };

    // Only populate if empty
    if doc
        .children(kv_id)
        .iter()
        .any(|&c| doc.element(c).is_some())
    {
        return Ok(xml.to_owned());
    }
    let text = doc.text_content_deep(kv_id);
    if !text.trim().is_empty() {
        return Ok(xml.to_owned());
    }

    let kv_range = doc.node_range(kv_id).unwrap();
    let prefix = extract_tag_prefix(&xml[kv_range.start..kv_range.end], "KeyValue");
    let inner_xml = match key_data.to_key_value_xml(prefix) {
        Some(xml_fragment) => xml_fragment,
        None => return Ok(xml.to_owned()),
    };

    let tag = pname(prefix, "KeyValue");
    let mut w = XmlWriter::new();
    w.start_element(&tag, &[]);
    w.raw(&inner_xml);
    w.end_element(&tag);
    let replacement = w.into_string();

    let mut result = String::with_capacity(xml.len() + replacement.len());
    result.push_str(&xml[..kv_range.start]);
    result.push_str(&replacement);
    result.push_str(&xml[kv_range.end..]);
    Ok(result)
}

/// Populate an empty `<DEREncodedKeyValue/>` element with the SPKI DER of the signing key.
fn populate_der_encoded_key_value(
    xml: &str,
    key_data: &bergshamra_keys::key::KeyData,
) -> Result<String, Error> {
    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;

    let dek_id = doc.descendants(doc.root()).into_iter().find(|&id| {
        doc.element(id).is_some_and(|elem| {
            &*elem.name.local_name == ns::node::DER_ENCODED_KEY_VALUE
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG11
        })
    });

    let dek_id = match dek_id {
        Some(id) => id,
        None => return Ok(xml.to_owned()),
    };

    // Only populate if empty
    if doc
        .children(dek_id)
        .iter()
        .any(|&c| doc.element(c).is_some())
    {
        return Ok(xml.to_owned());
    }
    let text = doc.text_content_deep(dek_id);
    if !text.trim().is_empty() {
        return Ok(xml.to_owned());
    }

    let spki_der = match key_data.to_spki_der() {
        Some(der) => der,
        None => return Ok(xml.to_owned()),
    };

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&spki_der);

    // Reconstruct the element with the base64 content, preserving namespace declarations.
    let dek_range = doc.node_range(dek_id).unwrap();
    let raw_tag = &xml[dek_range.start..dek_range.end];
    let prefix = extract_tag_prefix(raw_tag, ns::node::DER_ENCODED_KEY_VALUE);

    // Extract the opening tag with all its attributes/xmlns declarations
    let open_tag = extract_open_tag(raw_tag);
    let closing_tag = if prefix.is_empty() {
        "</DEREncodedKeyValue>".to_string()
    } else {
        format!("</{prefix}:DEREncodedKeyValue>")
    };
    let replacement = format!("{open_tag}{b64}{closing_tag}");

    let mut result = String::with_capacity(xml.len() + replacement.len());
    result.push_str(&xml[..dek_range.start]);
    result.push_str(&replacement);
    result.push_str(&xml[dek_range.end..]);
    Ok(result)
}

fn read_inclusive_prefixes(doc: &Document<'_>, node: NodeId) -> Vec<String> {
    for child in doc.children(node) {
        if let Some(elem) = doc.element(child) {
            if &*elem.name.local_name == ns::node::INCLUSIVE_NAMESPACES {
                if let Some(prefix_list) = elem.get_attribute(ns::attr::PREFIX_LIST) {
                    return prefix_list
                        .split_whitespace()
                        .map(|s| s.to_owned())
                        .collect();
                }
            }
        }
    }
    Vec::new()
}

/// Encrypt a session key into empty EncryptedKey CipherValue in the signed template.
///
/// When `--session-key` is used, the template may contain `<EncryptedKey>` elements
/// with empty `<CipherValue>`. This function encrypts the session key (used for signing)
/// using the key wrap algorithm and wrapping key specified in each EncryptedKey.
fn encrypt_session_key_in_template(
    xml: &str,
    signing_key: &bergshamra_keys::Key,
    manager: &bergshamra_keys::KeysManager,
) -> Result<String, Error> {
    // Only relevant for symmetric signing keys (HMAC)
    let session_bytes = match signing_key.symmetric_key_bytes() {
        Some(b) => b.to_vec(),
        None => return Ok(xml.to_owned()),
    };

    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;

    // Find EncryptedKey elements with empty CipherValue
    let mut replacements: Vec<(std::ops::Range<usize>, String)> = Vec::new();

    for node_id in doc.descendants(doc.root()) {
        let elem = match doc.element(node_id) {
            Some(e) => e,
            None => continue,
        };
        let ns_uri = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;

        if local != "EncryptedKey" || (ns_uri != ns::ENC && !ns_uri.is_empty()) {
            continue;
        }

        // Check for empty CipherValue
        let cv_id = match find_descendant_element_by_local(&doc, node_id, "CipherValue") {
            Some(id) => id,
            None => continue,
        };
        let cv_text = doc.text_content_deep(cv_id);
        if !cv_text.trim().is_empty() {
            continue; // Already filled
        }

        // Get EncryptionMethod algorithm
        let enc_method = match find_child_element(&doc, node_id, ns::ENC, "EncryptionMethod") {
            Some(id) => id,
            None => continue,
        };
        let alg_uri = match doc
            .element(enc_method)
            .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
        {
            Some(u) => u,
            None => continue,
        };

        // Find the wrapping key via KeyName in EncryptedKey's KeyInfo
        let ki = find_child_element(&doc, node_id, ns::DSIG, ns::node::KEY_INFO);
        let wrap_key = if let Some(ki_id) = ki {
            let key_name_id = find_child_element(&doc, ki_id, ns::DSIG, ns::node::KEY_NAME);
            if let Some(kn_id) = key_name_id {
                let name = doc.text_content_deep(kn_id);
                let name = name.trim();
                if name.is_empty() {
                    None
                } else {
                    manager.find_by_name(name)
                }
            } else {
                None
            }
        } else {
            None
        };

        let wrap_key = match wrap_key {
            Some(k) => k,
            None => continue,
        };

        let kek_bytes = match wrap_key.symmetric_key_bytes() {
            Some(b) => b,
            None => continue,
        };

        // Perform key wrapping
        let kw = bergshamra_crypto::keywrap::from_uri(alg_uri)?;
        let wrapped = kw.wrap(kek_bytes, &session_bytes)?;

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wrapped);

        // Record range of CipherValue to replace
        let cv_range = doc.node_range(cv_id).unwrap();
        replacements.push((
            cv_range.clone(),
            format_cipher_value_element_range(xml, &cv_range, &b64),
        ));
    }

    if replacements.is_empty() {
        return Ok(xml.to_owned());
    }

    // Apply replacements in reverse order (to preserve offsets)
    let mut result = xml.to_owned();
    replacements.sort_by_key(|r| std::cmp::Reverse(r.0.start));
    for (range, replacement) in replacements {
        result.replace_range(range, &replacement);
    }

    Ok(result)
}

/// Format a CipherValue element replacement preserving its tag structure.
fn format_cipher_value_element_range(
    xml: &str,
    range: &std::ops::Range<usize>,
    b64_content: &str,
) -> String {
    let raw_tag = &xml[range.start..range.end];
    let open_tag = extract_open_tag(raw_tag);
    let prefix = extract_tag_prefix(raw_tag, "CipherValue");
    let closing_tag = if prefix.is_empty() {
        "</CipherValue>".to_string()
    } else {
        format!("</{prefix}:CipherValue>")
    };
    format!("{open_tag}\n          {b64_content}\n        {closing_tag}")
}

/// Find a descendant element by local name (any namespace).
fn find_descendant_element_by_local(
    doc: &Document<'_>,
    node_id: NodeId,
    local_name: &str,
) -> Option<NodeId> {
    for desc in doc.descendants(node_id) {
        if let Some(elem) = doc.element(desc) {
            if &*elem.name.local_name == local_name {
                return Some(desc);
            }
        }
    }
    None
}
