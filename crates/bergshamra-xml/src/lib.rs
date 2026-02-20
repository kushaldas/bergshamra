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
