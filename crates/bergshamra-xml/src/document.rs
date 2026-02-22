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
    pub fn build_id_map(
        &self,
        doc: &Document<'_>,
    ) -> HashMap<String, NodeId> {
        let default_attrs = ["Id", "ID", "id"];
        let mut map = HashMap::new();
        for id in doc.descendants(doc.root()) {
            if let Some(elem) = doc.element(id) {
                for attr_name in &default_attrs {
                    if let Some(val) = elem.get_attribute(attr_name) {
                        map.insert(val.to_owned(), id);
                    }
                }
                for attr_name in &self.extra_id_attrs {
                    if let Some(val) = elem.get_attribute(attr_name.as_str()) {
                        map.insert(val.to_owned(), id);
                    }
                }
            }
        }
        map
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
    pub fn find_element(
        doc: &Document<'_>,
        ns: &str,
        local_name: &str,
    ) -> Option<NodeId> {
        let results = doc.get_elements_by_tag_name_ns(ns, local_name);
        results.into_iter().next()
    }

    /// Find all descendant elements with the given local name and namespace.
    pub fn find_elements(
        doc: &Document<'_>,
        ns: &str,
        local_name: &str,
    ) -> Vec<NodeId> {
        doc.get_elements_by_tag_name_ns(ns, local_name)
    }
}
