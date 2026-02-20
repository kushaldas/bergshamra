#![forbid(unsafe_code)]

//! XML document abstraction for the Bergshamra XML Security library.
//!
//! Provides a DOM-like interface over `roxmltree`, plus `NodeSet` operations
//! needed for canonicalization and signature transforms.

pub mod document;
pub mod nodeset;
pub mod xpath;
pub mod writer;

pub use document::XmlDocument;
pub use nodeset::NodeSet;

/// Return roxmltree parsing options that allow DTD.
///
/// DTD is allowed because roxmltree does not expand external entities or
/// perform entity substitution beyond the five predefined XML entities,
/// so it is safe. Many xmlsec test vectors use DTDs for entity definitions.
pub fn parsing_options() -> roxmltree::ParsingOptions {
    roxmltree::ParsingOptions {
        allow_dtd: true,
        ..roxmltree::ParsingOptions::default()
    }
}
