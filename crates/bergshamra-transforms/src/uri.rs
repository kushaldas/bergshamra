#![forbid(unsafe_code)]

//! URI resolution for XML-DSig references.
//!
//! Handles:
//! - Empty URI ("") — the entire document minus comments
//! - Same-document references ("#id") — XPointer id() resolution
//! - External references (not supported initially)

use bergshamra_core::Error;
use bergshamra_xml::NodeSet;
use bergshamra_xml::xpath;
use std::collections::HashMap;

/// Resolve a URI reference and return the data to process.
pub fn resolve_uri<'a>(
    uri: &str,
    doc: &'a roxmltree::Document<'a>,
    id_map: &HashMap<String, roxmltree::NodeId>,
    xml_text: &str,
) -> Result<(String, Option<NodeSet>), Error> {
    if uri.is_empty() {
        // Empty URI = whole document minus comments
        let ns = NodeSet::all(doc);
        Ok((xml_text.to_owned(), Some(ns)))
    } else if let Some(id) = xpath::parse_same_document_ref(uri) {
        // Same-document reference: #id → TreeWithoutComments
        let node = xpath::resolve_id(doc, id_map, id)?;
        let ns = NodeSet::tree_without_comments(node);
        Ok((xml_text.to_owned(), Some(ns)))
    } else {
        // External URI — not supported yet
        Err(Error::InvalidUri(format!("external URI not supported: {uri}")))
    }
}

/// Resolve a same-document reference and return the subtree node set.
pub fn resolve_same_document<'a>(
    id: &str,
    doc: &'a roxmltree::Document<'a>,
    id_map: &HashMap<String, roxmltree::NodeId>,
) -> Result<NodeSet, Error> {
    let node = xpath::resolve_id(doc, id_map, id)?;
    Ok(NodeSet::tree_without_comments(node))
}
