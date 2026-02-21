#![forbid(unsafe_code)]

//! Inclusive Canonical XML 1.1 (C14N 1.1).
//!
//! Algorithm URI: `http://www.w3.org/2006/12/xml-c14n11`
//! With comments: `http://www.w3.org/2006/12/xml-c14n11#WithComments`
//!
//! C14N 1.1 adds xml:id and xml:base URI processing on top of C14N 1.0.
//! For the initial implementation, we delegate to C14N 1.0 since the
//! additional processing is only needed for edge cases involving xml:id
//! and xml:base.

use bergshamra_core::Error;
use bergshamra_xml::nodeset::NodeSet;

/// Canonicalize using Inclusive C14N 1.1.
///
/// For the initial implementation, this delegates to C14N 1.0.
/// The differences (xml:id and xml:base handling) will be added
/// incrementally as test vectors require them.
pub fn canonicalize(
    doc: &roxmltree::Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
) -> Result<Vec<u8>, Error> {
    // C14N 1.1 is a superset of C14N 1.0.
    // The main difference is xml:base URI absolutization for document subsets:
    // when an element's parent is not in the node set, the xml:base value
    // must be replaced by the computed absolute base URI.
    crate::inclusive::canonicalize_with_options(doc, with_comments, node_set, true)
}
