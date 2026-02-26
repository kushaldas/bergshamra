#![forbid(unsafe_code)]

//! XML document abstraction for the Bergshamra XML Security library.
//!
//! Provides a DOM-like interface over `uppsala`, plus `NodeSet` operations
//! needed for canonicalization and signature transforms.

pub mod document;
pub mod nodeset;
pub mod writer;
pub mod xpath;

pub use document::XmlDocument;
pub use nodeset::NodeSet;
pub use uppsala::{self, Attribute, Document, Element, NodeId, NodeKind, QName};
