#![forbid(unsafe_code)]

//! XML-DSig signature verification.
//!
//! Processing order per spec Section 3.2:
//! 1. Parse <Signature>, register ID attributes
//! 2. Read <SignedInfo>: CanonicalizationMethod, SignatureMethod
//! 3. For each <Reference>: resolve URI, run transforms, compute digest, compare
//! 4. Resolve signing key from <KeyInfo>
//! 5. Canonicalize <SignedInfo>
//! 6. Verify <SignatureValue>

use crate::context::DsigContext;
use bergshamra_c14n::C14nMode;
use bergshamra_core::{algorithm, ns, Error};
use bergshamra_crypto::digest;
use bergshamra_xml::nodeset::NodeSet;
use bergshamra_xml::xpath;
use std::collections::HashMap;

/// Result of signature verification.
#[derive(Debug)]
pub enum VerifyResult {
    /// Signature is valid.
    Valid,
    /// Signature is invalid.
    Invalid {
        reason: String,
    },
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerifyResult::Valid)
    }
}

/// Verify a signed XML document.
pub fn verify(ctx: &DsigContext, xml: &str) -> Result<VerifyResult, Error> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    // Build ID map
    let mut id_attrs: Vec<&str> = vec!["Id", "ID", "id"];
    let extra: Vec<&str> = ctx.id_attrs.iter().map(|s| s.as_str()).collect();
    id_attrs.extend(extra);
    let id_map = build_id_map(&doc, &id_attrs);

    // Find <Signature> element
    let sig_node = find_element(&doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;

    // Find <SignedInfo>
    let signed_info = find_child_element(sig_node, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    // Read CanonicalizationMethod
    let c14n_method_node = find_child_element(signed_info, ns::DSIG, ns::node::CANONICALIZATION_METHOD)
        .ok_or_else(|| Error::MissingElement("CanonicalizationMethod".into()))?;
    let c14n_uri = c14n_method_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on CanonicalizationMethod".into()))?;
    let c14n_mode = C14nMode::from_uri(c14n_uri)
        .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {c14n_uri}")))?;

    // Read SignatureMethod
    let sig_method_node = find_child_element(signed_info, ns::DSIG, ns::node::SIGNATURE_METHOD)
        .ok_or_else(|| Error::MissingElement("SignatureMethod".into()))?;
    let sig_method_uri = sig_method_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on SignatureMethod".into()))?;

    // Read exc-C14N PrefixList if applicable
    let inclusive_prefixes = read_inclusive_prefixes(c14n_method_node);

    // 3. Verify each Reference
    let references = find_child_elements(signed_info, ns::DSIG, ns::node::REFERENCE);
    for reference in &references {
        let result = verify_reference(reference, &doc, &id_map, xml, sig_node)?;
        if let VerifyResult::Invalid { reason } = result {
            return Ok(VerifyResult::Invalid {
                reason: format!("Reference digest failed: {reason}"),
            });
        }
    }

    // 4. Resolve signing key
    let key_info_node = find_child_element(sig_node, ns::DSIG, ns::node::KEY_INFO);
    let key = if let Some(ki) = key_info_node {
        bergshamra_keys::keyinfo::resolve_key_info(ki, &ctx.keys_manager)?
    } else {
        ctx.keys_manager.first_key()?
    };

    // 5. Canonicalize <SignedInfo>
    // We need to canonicalize the SignedInfo element as a document subset
    let signed_info_ns = NodeSet::tree_without_comments(signed_info);
    let c14n_signed_info = bergshamra_c14n::canonicalize_doc(
        &doc,
        c14n_mode,
        Some(&signed_info_ns),
        &inclusive_prefixes,
    )?;

    // 6. Verify SignatureValue
    let sig_value_node = find_child_element(sig_node, ns::DSIG, ns::node::SIGNATURE_VALUE)
        .ok_or_else(|| Error::MissingElement("SignatureValue".into()))?;
    let sig_value_b64 = sig_value_node.text().unwrap_or("").trim();
    let sig_value_clean: String = sig_value_b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let sig_value = engine
        .decode(&sig_value_clean)
        .map_err(|e| Error::Base64(format!("SignatureValue: {e}")))?;

    let signing_key = key
        .to_signing_key()
        .ok_or_else(|| Error::Key("no signing key available".into()))?;

    let sig_alg = bergshamra_crypto::sign::from_uri(sig_method_uri)?;
    let valid = sig_alg.verify(&signing_key, &c14n_signed_info, &sig_value)?;

    if valid {
        Ok(VerifyResult::Valid)
    } else {
        Ok(VerifyResult::Invalid {
            reason: "signature value verification failed".into(),
        })
    }
}

/// Verify a single <Reference> element.
fn verify_reference(
    reference: &roxmltree::Node<'_, '_>,
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
    xml: &str,
    sig_node: roxmltree::Node<'_, '_>,
) -> Result<VerifyResult, Error> {
    // Read URI attribute
    let uri = reference.attribute(ns::attr::URI).unwrap_or("");

    // Read DigestMethod
    let digest_method_node = find_child_element(*reference, ns::DSIG, ns::node::DIGEST_METHOD)
        .ok_or_else(|| Error::MissingElement("DigestMethod".into()))?;
    let digest_uri = digest_method_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on DigestMethod".into()))?;

    // Read expected DigestValue
    let digest_value_node = find_child_element(*reference, ns::DSIG, ns::node::DIGEST_VALUE)
        .ok_or_else(|| Error::MissingElement("DigestValue".into()))?;
    let expected_b64 = digest_value_node.text().unwrap_or("").trim();
    let expected_clean: String = expected_b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let expected_digest = engine
        .decode(&expected_clean)
        .map_err(|e| Error::Base64(format!("DigestValue: {e}")))?;

    // Resolve URI and get initial data
    let (ref_xml, initial_ns) = resolve_reference_uri(uri, doc, id_map, xml)?;

    // Read and apply transforms
    let transforms_node = find_child_element(*reference, ns::DSIG, ns::node::TRANSFORMS);
    let mut data = bergshamra_transforms::TransformData::Xml {
        xml_text: ref_xml,
        node_set: initial_ns,
    };

    if let Some(transforms) = transforms_node {
        for transform_node in transforms.children() {
            if !transform_node.is_element() || transform_node.tag_name().name() != ns::node::TRANSFORM {
                continue;
            }
            let transform_uri = transform_node
                .attribute(ns::attr::ALGORITHM)
                .unwrap_or("");

            data = apply_transform(transform_uri, data, &transform_node, sig_node)?;
        }
    }

    // Convert to binary for digesting
    let bytes = data.to_binary()?;

    // Compute digest
    let computed = digest::digest(digest_uri, &bytes)?;

    // Compare
    if computed == expected_digest {
        Ok(VerifyResult::Valid)
    } else {
        Ok(VerifyResult::Invalid {
            reason: format!(
                "URI={uri}: expected digest does not match computed digest"
            ),
        })
    }
}

/// Resolve a reference URI to (xml_text, optional node_set).
fn resolve_reference_uri(
    uri: &str,
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
    xml: &str,
) -> Result<(String, Option<NodeSet>), Error> {
    if uri.is_empty() {
        // Whole document
        Ok((xml.to_owned(), None))
    } else if let Some(id) = xpath::parse_same_document_ref(uri) {
        let node = xpath::resolve_id(doc, id_map, id)?;
        let ns = NodeSet::tree_without_comments(node);
        Ok((xml.to_owned(), Some(ns)))
    } else {
        Err(Error::InvalidUri(format!("external URI not supported: {uri}")))
    }
}

/// Apply a single transform.
pub(crate) fn apply_transform(
    uri: &str,
    data: bergshamra_transforms::TransformData,
    transform_node: &roxmltree::Node<'_, '_>,
    sig_node: roxmltree::Node<'_, '_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_transforms::pipeline::{C14nTransform, Transform};

    match uri {
        algorithm::ENVELOPED_SIGNATURE => {
            let t = bergshamra_transforms::enveloped::EnvelopedSignatureTransform::from_node(sig_node);
            t.execute(data)
        }
        algorithm::C14N | algorithm::C14N_WITH_COMMENTS
        | algorithm::C14N11 | algorithm::C14N11_WITH_COMMENTS
        | algorithm::EXC_C14N | algorithm::EXC_C14N_WITH_COMMENTS => {
            let mode = C14nMode::from_uri(uri)
                .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {uri}")))?;
            let prefixes = read_inclusive_prefixes(*transform_node);
            let t = C14nTransform::new(mode, prefixes);
            t.execute(data)
        }
        algorithm::BASE64 => {
            let t = bergshamra_transforms::base64_transform::Base64DecodeTransform;
            t.execute(data)
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("transform: {uri}"))),
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

fn find_child_elements<'a>(
    parent: roxmltree::Node<'a, 'a>,
    ns_uri: &str,
    local_name: &str,
) -> Vec<roxmltree::Node<'a, 'a>> {
    parent
        .children()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == local_name
                && n.tag_name().namespace().unwrap_or("") == ns_uri
        })
        .collect()
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

fn read_inclusive_prefixes(node: roxmltree::Node<'_, '_>) -> Vec<String> {
    // Look for <InclusiveNamespaces PrefixList="..."> child
    for child in node.children() {
        if child.is_element() && child.tag_name().name() == ns::node::INCLUSIVE_NAMESPACES {
            if let Some(prefix_list) = child.attribute(ns::attr::PREFIX_LIST) {
                return prefix_list
                    .split_whitespace()
                    .map(|s| s.to_owned())
                    .collect();
            }
        }
    }
    Vec::new()
}
