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

use crate::C14nSink;
use bergshamra_core::Error;
use bergshamra_xml::nodeset::NodeSet;
use uppsala::Document;

/// Canonicalize using Inclusive C14N 1.1.
///
/// This delegates to the Inclusive C14N implementation with C14N 1.1 options
/// enabled. In particular, document-subset canonicalization may synthesize or
/// absolutize `xml:base` when the selected element's parent is outside the node
/// set.
///
/// # Errors
///
/// Returns an error if canonicalization cannot be completed.
pub fn canonicalize(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    canonicalize_to(doc, with_comments, node_set, &mut output)?;
    Ok(output)
}

/// Canonicalize using Inclusive C14N 1.1 into a byte sink.
///
/// This is the streaming form of [`canonicalize`]. It writes the exact
/// canonical byte stream into `output`.
///
/// # Errors
///
/// Returns the same errors as [`canonicalize`].
pub fn canonicalize_to<W: C14nSink>(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    output: &mut W,
) -> Result<(), Error> {
    // C14N 1.1 is a superset of C14N 1.0.
    // The main difference is xml:base URI absolutization for document subsets:
    // when an element's parent is not in the node set, the xml:base value
    // must be replaced by the computed absolute base URI.
    crate::inclusive::canonicalize_with_options_to(doc, with_comments, node_set, true, output)
}
