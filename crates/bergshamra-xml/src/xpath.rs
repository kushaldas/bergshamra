#![forbid(unsafe_code)]

//! Minimal XPath subset for XML-DSig processing.
//!
//! Only supports the patterns actually used by XML-DSig:
//! - `id('...')` — resolve an element by registered ID
//! - Same-document URI references: `#id-value`
//! - The ancestor-or-self axis (needed for enveloped transform)

use bergshamra_core::Error;
use std::collections::HashMap;
use uppsala::{Document, NodeId};

/// Parse a same-document reference (e.g., `#foo` → `foo`).
pub fn parse_same_document_ref(uri: &str) -> Option<&str> {
    uri.strip_prefix('#')
}

/// Resolve an ID value in a parsed document using a pre-built ID map.
pub fn resolve_id(
    _doc: &Document<'_>,
    id_map: &HashMap<String, NodeId>,
    id: &str,
) -> Result<NodeId, Error> {
    id_map
        .get(id)
        .copied()
        .ok_or_else(|| Error::InvalidUri(format!("ID not found: {id}")))
}

/// Parse an `xpointer(id('...'))` or `xpointer(id("..."))` expression and return the ID value.
pub fn parse_xpointer_id(expr: &str) -> Option<&str> {
    // Try single quotes first: xpointer(id('...'))
    if let Some(inner) = expr.strip_prefix("xpointer(id('") {
        return inner.strip_suffix("'))");
    }
    // Try double quotes: xpointer(id("..."))
    if let Some(inner) = expr.strip_prefix("xpointer(id(\"") {
        return inner.strip_suffix("\"))");
    }
    None
}

/// Check if `ancestor_id` is an ancestor-or-self of `node_id`.
pub fn is_ancestor_or_self(
    doc: &Document<'_>,
    ancestor_id: NodeId,
    node_id: NodeId,
) -> bool {
    let mut current = Some(node_id);
    while let Some(n) = current {
        if n == ancestor_id {
            return true;
        }
        current = doc.parent(n);
    }
    false
}

/// Collect the ancestor-or-self axis for a node (node IDs from the node up to root).
pub fn ancestor_or_self(doc: &Document<'_>, node_id: NodeId) -> Vec<NodeId> {
    let mut result = vec![node_id];
    let mut current = doc.parent(node_id);
    while let Some(n) = current {
        result.push(n);
        current = doc.parent(n);
    }
    result
}
