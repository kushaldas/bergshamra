#![forbid(unsafe_code)]

//! Shared rendering utilities for C14N output.
//!
//! The C14N algorithms collect namespace declarations and attributes, sort
//! them according to the canonical XML rules, and then render each item with
//! the required escaping. Most users should call the `canonicalize*` functions
//! instead of using this module directly.

use std::borrow::Cow;

use crate::{escape, C14nSink};

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
    /// Write this namespace declaration directly into a canonical byte sink.
    ///
    /// Unlike [`Self::render`], this streaming form does not allocate a
    /// temporary `String`. The leading space and canonical escaping are
    /// identical to the buffered representation.
    pub fn write_to<W: C14nSink>(&self, output: &mut W) {
        output.write(b" xmlns");
        if !self.prefix.is_empty() {
            output.write_byte(b':');
            output.write(self.prefix.as_bytes());
        }
        output.write(b"=\"");
        escape::escape_attr_into(output, &self.uri);
        output.write_byte(b'"');
    }

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
///
/// All names are borrowed from the document arena and the value is a
/// copy-on-write over the arena string, so rendering an attribute costs no
/// allocation (the previous four owned `String`s per attribute were the
/// dominant per-element allocation source on attribute-heavy documents).
///
/// Equality and ordering follow the canonical ordering key (namespace URI and
/// local name) and are implemented by hand below; `Debug` and `Clone` are
/// derived so the type stays as usable as the owned version it replaced.
#[derive(Debug, Clone)]
pub struct Attr<'a> {
    /// The namespace URI of the attribute ("" for no namespace).
    pub ns_uri: Cow<'a, str>,
    /// The attribute prefix for the qualified name. `None` renders an
    /// unqualified name; `Some("xml")` is used for synthesized `xml:*`
    /// inheritance attributes.
    pub prefix: Option<Cow<'a, str>>,
    /// The local name.
    pub local_name: Cow<'a, str>,
    /// The attribute value: borrowed from the arena when possible.
    pub value: Cow<'a, str>,
}

impl<'a> Attr<'a> {
    /// Write this attribute directly into a canonical byte sink.
    ///
    /// This avoids allocating the escaped value and formatted attribute
    /// string separately. Output remains byte-for-byte equivalent to
    /// [`Self::render`], including its leading space.
    pub fn write_to<W: C14nSink>(&self, output: &mut W) {
        output.write_byte(b' ');
        if let Some(prefix) = &self.prefix {
            output.write(prefix.as_bytes());
            output.write_byte(b':');
        }
        output.write(self.local_name.as_bytes());
        output.write(b"=\"");
        escape::escape_attr_into(output, &self.value);
        output.write_byte(b'"');
    }

    /// Render this attribute as canonical XML.
    ///
    /// The returned string includes the leading space before the attribute
    /// name, so it can be appended directly to an element start tag. The
    /// attribute value is escaped with canonical XML attribute escaping.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push(' ');
        if let Some(prefix) = &self.prefix {
            out.push_str(prefix.as_ref());
            out.push(':');
        }
        out.push_str(self.local_name.as_ref());
        out.push_str("=\"");
        out.push_str(&escape::escape_attr(&self.value));
        out.push('"');
        out
    }
}

impl<'a> PartialEq for Attr<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.ns_uri.as_ref() == other.ns_uri.as_ref()
            && self.local_name.as_ref() == other.local_name.as_ref()
    }
}

impl<'a> Eq for Attr<'a> {}

impl Ord for Attr<'_> {
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

impl PartialOrd for Attr<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_namespace_render_matches_allocating_render() {
        let declaration = NsDecl {
            prefix: "schema".to_owned(),
            uri: "urn:test&\"<\t\n\r".to_owned(),
        };
        let mut streamed = Vec::new();
        declaration.write_to(&mut streamed);
        assert_eq!(streamed, declaration.render().as_bytes());
    }

    #[test]
    fn streaming_attribute_render_matches_allocating_render() {
        let attribute = Attr {
            ns_uri: Cow::Borrowed("urn:test"),
            prefix: Some(Cow::Borrowed("schema")),
            local_name: Cow::Borrowed("type"),
            value: Cow::Borrowed("A&B\"<\t\n\r"),
        };
        let mut streamed = Vec::new();
        attribute.write_to(&mut streamed);
        assert_eq!(streamed, attribute.render().as_bytes());
    }
}
