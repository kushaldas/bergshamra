#![forbid(unsafe_code)]

//! Shared rendering utilities for C14N output.

use crate::escape;

/// A namespace declaration to be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsDecl {
    /// The prefix ("" for default namespace).
    pub prefix: String,
    /// The namespace URI.
    pub uri: String,
}

impl NsDecl {
    /// Render this namespace declaration to a string.
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

/// An attribute to be rendered.
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
    /// Render this attribute to a string.
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
