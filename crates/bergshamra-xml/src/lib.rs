#![forbid(unsafe_code)]

//! XML document abstraction for the Bergshamra XML Security library.
//!
//! Provides a DOM-like interface over `uppsala`, plus `NodeSet` operations
//! needed for canonicalization and signature transforms.
//!
//! `XmlDocument::build_id_map` returns a `Result` and rejects duplicate ID
//! values across the default XML Signature ID attributes and any
//! caller-registered ID attributes with
//! `bergshamra_core::Error::XmlStructure("duplicate ID: ...".into())`. This prevents public helper
//! consumers from accidentally resolving an attacker supplied duplicate element
//! after a silent map overwrite.

pub mod document;
pub mod nodeset;
pub mod writer;
pub mod xpath;

pub use document::XmlDocument;
pub use nodeset::NodeSet;
pub use uppsala::{self, Attribute, Document, Element, NodeId, NodeKind, QName};
