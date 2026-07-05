#![forbid(unsafe_code)]

//! Shared rendering utilities for C14N output.
//!
//! The C14N algorithms collect namespace declarations and attributes, sort
//! them according to the canonical XML rules, and then render each item with
//! the required escaping. Most users should call the `canonicalize*` functions
//! instead of using this module directly.

use crate::escape;

/// A namespace declaration prepared for canonical XML output.
///
/// Declarations sort by canonical namespace order: the default namespace
/// declaration (`xmlns="..."`) sorts before prefixed declarations, and prefixed
/// declarations sort lexicographically by prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsDecl {
    /// The prefix ("" for default namespace).
    pub prefix: String,
    /// The namespace URI.
    pub uri: String,
}

impl NsDecl {
    /// Render this namespace declaration as canonical XML.
    ///
    /// The returned string includes the leading space before `xmlns`, so it can
    /// be appended directly to an element start tag. Namespace URI characters
    /// are escaped with canonical XML attribute escaping.
    pub fn render(&self) -> String {
        if self.prefix.is_empty() {
            format!(" xmlns=\"{}\"", escape::escape_attr(&self.uri))
        } else {
            format!(
                " xmlns:{}=\"{}\"",
                self.prefix,
                escape::escape_attr(&self.uri)
            )
        }
    }
}

impl Ord for NsDecl {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Default namespace (empty prefix) sorts first.
        // Then sort by prefix lexicographically.
        match (self.prefix.is_empty(), other.prefix.is_empty()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => self.prefix.cmp(&other.prefix),
        }
    }
}

impl PartialOrd for NsDecl {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An attribute prepared for canonical XML output.
///
/// Attributes sort by canonical XML order: unqualified attributes first by
/// local name, followed by namespaced attributes by namespace URI and local
/// name. Namespace declaration attributes are represented separately as
/// [`NsDecl`] values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    /// The namespace URI of the attribute ("" for no namespace).
    pub ns_uri: String,
    /// The local name.
    pub local_name: String,
    /// The qualified name (prefix:local or just local).
    pub qualified_name: String,
    /// The attribute value.
    pub value: String,
}

impl Attr {
    /// Render this attribute as canonical XML.
    ///
    /// The returned string includes the leading space before the attribute
    /// name, so it can be appended directly to an element start tag. The
    /// attribute value is escaped with canonical XML attribute escaping.
    pub fn render(&self) -> String {
        format!(
            " {}=\"{}\"",
            self.qualified_name,
            escape::escape_attr(&self.value)
        )
    }
}

impl Ord for Attr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Attributes with no namespace come before those with a namespace.
        // Among those with namespaces, sort by (ns_uri, local_name).
        // Among those without namespaces, sort by local_name.
        match (self.ns_uri.is_empty(), other.ns_uri.is_empty()) {
            (true, true) => self.local_name.cmp(&other.local_name),
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (false, false) => self
                .ns_uri
                .cmp(&other.ns_uri)
                .then(self.local_name.cmp(&other.local_name)),
        }
    }
}

impl PartialOrd for Attr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
