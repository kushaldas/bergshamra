#![forbid(unsafe_code)]

//! XML document wrapper over uppsala with ID attribute registration.

use bergshamra_core::Error;
use std::collections::HashMap;
use uppsala::{Document, NodeId};

/// An owned XML document.  Stores the text and pre-computed metadata.
///
/// To work with the parsed tree, call [`XmlDocument::parse_doc`] which
/// returns a temporary `Document` borrowing from the text.
pub struct XmlDocument {
    text: String,
    /// Additional ID attribute names to register (beyond the default `Id`, `ID`, `id`).
    extra_id_attrs: Vec<String>,
}

impl XmlDocument {
    /// Parse and validate XML from a string, taking ownership.
    pub fn parse(text: String) -> Result<Self, Error> {
        // Validate that the XML parses successfully.
        let _doc = uppsala::parse(&text).map_err(|e| Error::XmlParse(e.to_string()))?;
        Ok(Self {
            text,
            extra_id_attrs: Vec::new(),
        })
    }

    /// Parse and validate XML from bytes.
    pub fn parse_bytes(data: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(data)
            .map_err(|e| Error::XmlParse(format!("invalid UTF-8: {e}")))?
            .to_owned();
        Self::parse(text)
    }

    /// Get the raw XML text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Register additional ID attribute names (e.g., `"wsu:Id"`).
    pub fn add_id_attr(&mut self, name: &str) {
        self.extra_id_attrs.push(name.to_owned());
    }

    /// Parse the document and return a temporary `Document`.
    ///
    /// This re-parses the XML from the stored text.  For performance,
    /// call this once at the top of a processing pipeline and pass the
    /// resulting document reference down through the call chain.
    pub fn parse_doc(&self) -> Result<Document<'_>, Error> {
        uppsala::parse(&self.text).map_err(|e| Error::XmlParse(e.to_string()))
    }

    /// Build the ID → NodeId mapping for a parsed document.
    ///
    /// Returns an error if the same ID value appears more than once across the
    /// default ID attributes (`Id`, `ID`, `id`) or any caller-registered
    /// attributes. Silent duplicate overwrites are unsafe for security-sensitive
    /// XML lookup because an attacker could make the map point at a different
    /// element than the one a signature or policy was intended to cover.
    pub fn build_id_map(&self, doc: &Document<'_>) -> Result<HashMap<String, NodeId>, Error> {
        let default_attrs = ["Id", "ID", "id"];
        let mut map = HashMap::new();
        for id in doc.descendants(doc.root()) {
            if let Some(elem) = doc.element(id) {
                for attr_name in &default_attrs {
                    if let Some(val) = elem.get_attribute(attr_name) {
                        if map.insert(val.to_owned(), id).is_some() {
                            return Err(Error::XmlStructure(format!("duplicate ID: {val}")));
                        }
                    }
                }
                for attr_name in &self.extra_id_attrs {
                    if let Some(val) = elem.get_attribute(attr_name.as_str()) {
                        if map.insert(val.to_owned(), id).is_some() {
                            return Err(Error::XmlStructure(format!("duplicate ID: {val}")));
                        }
                    }
                }
            }
        }
        Ok(map)
    }

    /// Find an element by its registered ID value in a parsed document.
    pub fn find_by_id(
        _doc: &Document<'_>,
        id_map: &HashMap<String, NodeId>,
        id: &str,
    ) -> Option<NodeId> {
        id_map.get(id).copied()
    }

    /// Find the first descendant element with the given local name and namespace.
    pub fn find_element(doc: &Document<'_>, ns: &str, local_name: &str) -> Option<NodeId> {
        let results = doc.get_elements_by_tag_name_ns(ns, local_name);
        results.into_iter().next()
    }

    /// Find all descendant elements with the given local name and namespace.
    pub fn find_elements(doc: &Document<'_>, ns: &str, local_name: &str) -> Vec<NodeId> {
        doc.get_elements_by_tag_name_ns(ns, local_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn duplicate_error_message(result: Result<HashMap<String, NodeId>, Error>) -> String {
        result
            .expect_err("duplicate IDs must be rejected")
            .to_string()
    }

    /// Baseline: unique ID values across default attributes are indexed and can
    /// be found through the public helper API.
    #[test]
    fn build_id_map_indexes_unique_default_ids() {
        let xdoc =
            XmlDocument::parse(r#"<root><a Id="a1"/><b ID="b1"/><c id="c1"/></root>"#.into())
                .expect("valid XML");
        let doc = xdoc.parse_doc().expect("parse document");
        let id_map = xdoc.build_id_map(&doc).expect("unique IDs should map");

        assert_eq!(id_map.len(), 3);
        assert!(
            XmlDocument::find_by_id(&doc, &id_map, "a1").is_some(),
            "default Id value should be registered"
        );
        assert!(
            XmlDocument::find_by_id(&doc, &id_map, "b1").is_some(),
            "default ID value should be registered"
        );
        assert!(
            XmlDocument::find_by_id(&doc, &id_map, "c1").is_some(),
            "default id value should be registered"
        );
    }

    /// A repeated `Id` value must fail closed instead of letting the later node
    /// overwrite the earlier map entry.
    #[test]
    fn build_id_map_rejects_duplicate_id_attribute() {
        let xdoc = XmlDocument::parse(r#"<root><a Id="dup"/><b Id="dup"/></root>"#.into())
            .expect("valid XML");
        let doc = xdoc.parse_doc().expect("parse document");
        let msg = duplicate_error_message(xdoc.build_id_map(&doc));

        assert!(
            msg.contains("duplicate ID: dup"),
            "error should name the duplicated value, got: {msg}"
        );
    }

    /// Duplicate values across the default `Id`, `ID`, and `id` attributes are
    /// just as ambiguous as duplicates on the same attribute name.
    #[test]
    fn build_id_map_rejects_cross_default_attribute_duplicate() {
        let xdoc = XmlDocument::parse(r#"<root><a Id="dup"/><b ID="dup"/></root>"#.into())
            .expect("valid XML");
        let doc = xdoc.parse_doc().expect("parse document");
        let msg = duplicate_error_message(xdoc.build_id_map(&doc));

        assert!(
            msg.contains("duplicate ID: dup"),
            "error should name the duplicated value, got: {msg}"
        );
    }

    /// Caller-registered ID attributes participate in the same duplicate-ID
    /// invariant as the built-in XML Signature ID names.
    #[test]
    fn build_id_map_rejects_custom_attribute_duplicate() {
        let mut xdoc =
            XmlDocument::parse(r#"<root><a CustomId="dup"/><b Id="dup"/></root>"#.into())
                .expect("valid XML");
        xdoc.add_id_attr("CustomId");
        let doc = xdoc.parse_doc().expect("parse document");
        let msg = duplicate_error_message(xdoc.build_id_map(&doc));

        assert!(
            msg.contains("duplicate ID: dup"),
            "error should name the duplicated value, got: {msg}"
        );
    }
}
