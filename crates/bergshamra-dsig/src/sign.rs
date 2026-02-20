#![forbid(unsafe_code)]

//! XML-DSig signature creation.
//!
//! Signs an XML document using a template with empty DigestValue/SignatureValue.

use crate::context::DsigContext;
use bergshamra_c14n::C14nMode;
use bergshamra_core::{ns, Error};
use bergshamra_crypto::digest;
use bergshamra_xml::nodeset::NodeSet;
use std::collections::HashMap;

/// Sign an XML template document.
///
/// The template must contain a `<Signature>` element with empty
/// `<DigestValue>` and `<SignatureValue>` elements.
///
/// Returns the signed XML document as a string.
pub fn sign(ctx: &DsigContext, template_xml: &str) -> Result<String, Error> {
    let doc = roxmltree::Document::parse(template_xml)
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    // Build ID map
    let mut id_attrs: Vec<&str> = vec!["Id", "ID", "id"];
    let extra: Vec<&str> = ctx.id_attrs.iter().map(|s| s.as_str()).collect();
    id_attrs.extend(extra);
    let id_map = build_id_map(&doc, &id_attrs);

    // Find Signature element
    let sig_node = find_element(&doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;
    let signed_info = find_child_element(sig_node, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    // Read CanonicalizationMethod
    let c14n_method = find_child_element(signed_info, ns::DSIG, ns::node::CANONICALIZATION_METHOD)
        .ok_or_else(|| Error::MissingElement("CanonicalizationMethod".into()))?;
    let c14n_uri = c14n_method
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on CanonicalizationMethod".into()))?;
    let c14n_mode = C14nMode::from_uri(c14n_uri)
        .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {c14n_uri}")))?;
    let inclusive_prefixes = read_inclusive_prefixes(c14n_method);

    // Read SignatureMethod
    let sig_method = find_child_element(signed_info, ns::DSIG, ns::node::SIGNATURE_METHOD)
        .ok_or_else(|| Error::MissingElement("SignatureMethod".into()))?;
    let sig_method_uri = sig_method
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on SignatureMethod".into()))?;

    // Process each Reference to compute digests
    let mut result_xml = template_xml.to_owned();
    let references = find_child_elements(signed_info, ns::DSIG, ns::node::REFERENCE);

    for reference in &references {
        let uri = reference.attribute(ns::attr::URI).unwrap_or("");
        let digest_method = find_child_element(*reference, ns::DSIG, ns::node::DIGEST_METHOD)
            .ok_or_else(|| Error::MissingElement("DigestMethod".into()))?;
        let digest_uri = digest_method
            .attribute(ns::attr::ALGORITHM)
            .ok_or_else(|| Error::MissingAttribute("Algorithm on DigestMethod".into()))?;

        // Resolve reference and apply transforms
        let (ref_xml, initial_ns) = if uri.is_empty() {
            (template_xml.to_owned(), None)
        } else if let Some(id) = bergshamra_xml::xpath::parse_same_document_ref(uri) {
            let node = bergshamra_xml::xpath::resolve_id(&doc, &id_map, id)?;
            let ns = NodeSet::tree_without_comments(node);
            (template_xml.to_owned(), Some(ns))
        } else {
            return Err(Error::InvalidUri(format!("unsupported URI: {uri}")));
        };

        // Apply transforms
        let mut data = bergshamra_transforms::TransformData::Xml {
            xml_text: ref_xml,
            node_set: initial_ns,
        };
        let transforms_node = find_child_element(*reference, ns::DSIG, ns::node::TRANSFORMS);
        if let Some(transforms) = transforms_node {
            for t_node in transforms.children() {
                if !t_node.is_element() || t_node.tag_name().name() != ns::node::TRANSFORM {
                    continue;
                }
                let t_uri = t_node.attribute(ns::attr::ALGORITHM).unwrap_or("");
                data = crate::verify::apply_transform(t_uri, data, &t_node, sig_node)?;
            }
        }

        let bytes = data.to_binary()?;
        let computed = digest::digest(digest_uri, &bytes)?;

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let digest_b64 = engine.encode(&computed);

        // Replace the empty DigestValue in the result XML
        // This is a simple text replacement — works for templates
        // where DigestValue elements are initially empty.
        let digest_value_text = find_child_element(*reference, ns::DSIG, ns::node::DIGEST_VALUE)
            .and_then(|n| n.text())
            .unwrap_or("");

        if digest_value_text.trim().is_empty() {
            // Find and replace in result_xml
            // Simple approach: replace the first empty <DigestValue></DigestValue>
            result_xml = result_xml.replacen(
                "<ds:DigestValue></ds:DigestValue>",
                &format!("<ds:DigestValue>{digest_b64}</ds:DigestValue>"),
                1,
            );
            // Also try without prefix
            result_xml = result_xml.replacen(
                "<DigestValue></DigestValue>",
                &format!("<DigestValue>{digest_b64}</DigestValue>"),
                1,
            );
        }
    }

    // Now canonicalize SignedInfo and compute signature
    // Re-parse the updated XML
    let updated_doc = roxmltree::Document::parse(&result_xml)
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;
    let updated_sig = find_element(&updated_doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;
    let updated_signed_info = find_child_element(updated_sig, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    let signed_info_ns = NodeSet::tree_without_comments(updated_signed_info);
    let c14n_signed_info = bergshamra_c14n::canonicalize_doc(
        &updated_doc,
        c14n_mode,
        Some(&signed_info_ns),
        &inclusive_prefixes,
    )?;

    // Sign
    let key = ctx.keys_manager.first_key()?;
    let signing_key = key
        .to_signing_key()
        .ok_or_else(|| Error::Key("no signing key".into()))?;

    let sig_alg = bergshamra_crypto::sign::from_uri(sig_method_uri)?;
    let signature = sig_alg.sign(&signing_key, &c14n_signed_info)?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let sig_b64 = engine.encode(&signature);

    // Replace empty SignatureValue
    result_xml = result_xml.replacen(
        "<ds:SignatureValue></ds:SignatureValue>",
        &format!("<ds:SignatureValue>{sig_b64}</ds:SignatureValue>"),
        1,
    );
    result_xml = result_xml.replacen(
        "<SignatureValue></SignatureValue>",
        &format!("<SignatureValue>{sig_b64}</SignatureValue>"),
        1,
    );

    Ok(result_xml)
}

// Re-use helpers from verify module
fn find_element<'a>(doc: &'a roxmltree::Document<'a>, ns_uri: &str, local_name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    doc.descendants().find(|n| n.is_element() && n.tag_name().name() == local_name && n.tag_name().namespace().unwrap_or("") == ns_uri)
}

fn find_child_element<'a>(parent: roxmltree::Node<'a, 'a>, ns_uri: &str, local_name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    parent.children().find(|n| n.is_element() && n.tag_name().name() == local_name && n.tag_name().namespace().unwrap_or("") == ns_uri)
}

fn find_child_elements<'a>(parent: roxmltree::Node<'a, 'a>, ns_uri: &str, local_name: &str) -> Vec<roxmltree::Node<'a, 'a>> {
    parent.children().filter(|n| n.is_element() && n.tag_name().name() == local_name && n.tag_name().namespace().unwrap_or("") == ns_uri).collect()
}

fn build_id_map(doc: &roxmltree::Document<'_>, attr_names: &[&str]) -> HashMap<String, roxmltree::NodeId> {
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
    for child in node.children() {
        if child.is_element() && child.tag_name().name() == ns::node::INCLUSIVE_NAMESPACES {
            if let Some(prefix_list) = child.attribute(ns::attr::PREFIX_LIST) {
                return prefix_list.split_whitespace().map(|s| s.to_owned()).collect();
            }
        }
    }
    Vec::new()
}
