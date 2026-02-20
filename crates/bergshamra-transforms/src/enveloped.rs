#![forbid(unsafe_code)]

//! Enveloped signature transform.
//!
//! Removes the ancestor `<Signature>` element from the node set.

use crate::pipeline::{Transform, TransformData};
use bergshamra_core::{algorithm, Error};
use bergshamra_xml::NodeSet;
use bergshamra_xml::nodeset::node_index;

/// The enveloped signature transform — removes the `<Signature>` element
/// and its descendants from the node set.
pub struct EnvelopedSignatureTransform {
    /// The node index of the `<Signature>` element to remove.
    signature_node_index: usize,
}

impl EnvelopedSignatureTransform {
    /// Create with the node index of the Signature element to remove.
    pub fn new(signature_node_index: usize) -> Self {
        Self { signature_node_index }
    }

    /// Create from a roxmltree Node.
    pub fn from_node(sig_node: roxmltree::Node<'_, '_>) -> Self {
        Self {
            signature_node_index: node_index(sig_node),
        }
    }
}

impl Transform for EnvelopedSignatureTransform {
    fn uri(&self) -> &str {
        algorithm::ENVELOPED_SIGNATURE
    }

    fn execute(&self, input: TransformData) -> Result<TransformData, Error> {
        match input {
            TransformData::Xml { xml_text, node_set } => {
                let doc = roxmltree::Document::parse_with_options(&xml_text, bergshamra_xml::parsing_options())
                    .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

                // Build a node set that excludes the Signature subtree
                let mut ns = node_set.unwrap_or_else(|| NodeSet::all(&doc));

                // Find the signature node and remove it + all descendants
                if let Some(sig_node) = find_node_by_index(&doc, self.signature_node_index) {
                    remove_subtree(&sig_node, &mut ns);
                }

                Ok(TransformData::Xml {
                    xml_text,
                    node_set: Some(ns),
                })
            }
            TransformData::Binary(_) => {
                Err(Error::Transform(
                    "enveloped-signature transform requires XML input".into(),
                ))
            }
        }
    }
}

fn find_node_by_index<'a>(
    doc: &'a roxmltree::Document<'a>,
    target_index: usize,
) -> Option<roxmltree::Node<'a, 'a>> {
    doc.descendants().find(|n| node_index(*n) == target_index)
}

fn remove_subtree(node: &roxmltree::Node<'_, '_>, ns: &mut NodeSet) {
    ns.remove(node);
    for child in node.children() {
        remove_subtree(&child, ns);
    }
}
