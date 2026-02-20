#![forbid(unsafe_code)]

//! Minimal XPath subset for XML-DSig processing.
//!
//! Only supports the patterns actually used by XML-DSig:
//! - `id('...')` — resolve an element by registered ID
//! - Same-document URI references: `#id-value`
//! - The ancestor-or-self axis (needed for enveloped transform)

use bergshamra_core::Error;
use std::collections::HashMap;

/// Parse a same-document reference (e.g., `#foo` → `foo`).
pub fn parse_same_document_ref(uri: &str) -> Option<&str> {
    uri.strip_prefix('#')
}

/// Resolve an ID value in a parsed document using a pre-built ID map.
pub fn resolve_id<'a>(
    doc: &'a roxmltree::Document<'a>,
    id_map: &HashMap<String, roxmltree::NodeId>,
    id: &str,
) -> Result<roxmltree::Node<'a, 'a>, Error> {
    id_map
        .get(id)
        .and_then(|nid| doc.get_node(*nid))
        .ok_or_else(|| Error::InvalidUri(format!("ID not found: {id}")))
}

/// Parse an `xpointer(id('...'))` expression and return the ID value.
pub fn parse_xpointer_id(expr: &str) -> Option<&str> {
    let inner = expr.strip_prefix("xpointer(id('")?;
    let inner = inner.strip_suffix("'))")?;
    Some(inner)
}

/// Check if `ancestor` is an ancestor-or-self of `node`.
pub fn is_ancestor_or_self(
    ancestor: roxmltree::Node<'_, '_>,
    node: roxmltree::Node<'_, '_>,
) -> bool {
    let mut current = Some(node);
    while let Some(n) = current {
        if n.id() == ancestor.id() {
            return true;
        }
        current = n.parent();
    }
    false
}

/// Collect the ancestor-or-self axis for a node (node IDs from the node up to root).
pub fn ancestor_or_self(node: roxmltree::Node<'_, '_>) -> Vec<roxmltree::NodeId> {
    let mut result = vec![node.id()];
    let mut current = node.parent();
    while let Some(n) = current {
        result.push(n.id());
        current = n.parent();
    }
    result
}
