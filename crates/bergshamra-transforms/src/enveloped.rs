#![forbid(unsafe_code)]

//! Enveloped signature transform.
//!
//! Removes the ancestor `<Signature>` element from the node set.

use crate::pipeline::{Transform, TransformData};
use bergshamra_core::{algorithm, Error};
use bergshamra_xml::NodeSet;
use uppsala::{Document, NodeId};

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

    /// Create from a NodeId.
    pub fn from_node_id(sig_id: NodeId) -> Self {
        Self {
            signature_node_index: sig_id.index(),
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
                let doc = uppsala::parse(&xml_text)
                    .map_err(|e| Error::XmlParse(e.to_string()))?;

                // Build a node set that excludes the Signature subtree
                let mut ns = node_set.unwrap_or_else(|| NodeSet::all(&doc));

                // Find the signature node and remove it + all descendants
                let sig_id = NodeId::new(self.signature_node_index);
                remove_subtree(sig_id, &doc, &mut ns);

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

fn remove_subtree(id: NodeId, doc: &Document<'_>, ns: &mut NodeSet) {
    ns.remove_id(id);
    for child in doc.children(id) {
        remove_subtree(child, doc, ns);
    }
}
