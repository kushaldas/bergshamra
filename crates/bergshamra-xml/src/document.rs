#![forbid(unsafe_code)]

//! XML document wrapper over roxmltree with ID attribute registration.

use bergshamra_core::Error;
use std::collections::HashMap;

/// An owned XML document.  Stores the text and pre-computed metadata.
///
/// To work with the parsed tree, call [`XmlDocument::parse_doc`] which
/// returns a temporary `roxmltree::Document` borrowing from the text.
pub struct XmlDocument {
    text: String,
    /// Additional ID attribute names to register (beyond the default `Id`, `ID`, `id`).
    extra_id_attrs: Vec<String>,
}

impl XmlDocument {
    /// Parse and validate XML from a string, taking ownership.
    pub fn parse(text: String) -> Result<Self, Error> {
        // Validate that the XML parses successfully.
        let _doc =
            roxmltree::Document::parse(&text).map_err(|e| Error::XmlParse(e.to_string()))?;
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

    /// Parse the document and return a temporary `roxmltree::Document`.
    ///
    /// This re-parses the XML from the stored text.  For performance,
    /// call this once at the top of a processing pipeline and pass the
    /// resulting document reference down through the call chain.
    pub fn parse_doc(&self) -> Result<roxmltree::Document<'_>, Error> {
        roxmltree::Document::parse(&self.text).map_err(|e| Error::XmlParse(e.to_string()))
    }

    /// Build the ID → NodeId mapping for a parsed document.
    pub fn build_id_map<'a>(
        &self,
        doc: &'a roxmltree::Document<'a>,
    ) -> HashMap<String, roxmltree::NodeId> {
        let default_attrs = ["Id", "ID", "id"];
        let mut map = HashMap::new();
        for node in doc.descendants() {
            if node.is_element() {
                for attr_name in &default_attrs {
                    if let Some(val) = node.attribute(*attr_name) {
                        map.insert(val.to_owned(), node.id());
                    }
                }
                for attr_name in &self.extra_id_attrs {
                    if let Some(val) = node.attribute(attr_name.as_str()) {
                        map.insert(val.to_owned(), node.id());
                    }
                }
            }
        }
        map
    }

    /// Find an element by its registered ID value in a parsed document.
    pub fn find_by_id<'a>(
        doc: &'a roxmltree::Document<'a>,
        id_map: &HashMap<String, roxmltree::NodeId>,
        id: &str,
    ) -> Option<roxmltree::Node<'a, 'a>> {
        let node_id = id_map.get(id)?;
        doc.get_node(*node_id)
    }

    /// Find the first descendant element with the given local name and namespace.
    pub fn find_element<'a>(
        doc: &'a roxmltree::Document<'a>,
        ns: &str,
        local_name: &str,
    ) -> Option<roxmltree::Node<'a, 'a>> {
        doc.descendants().find(|n| {
            n.is_element()
                && n.tag_name().name() == local_name
                && n.tag_name().namespace().unwrap_or("") == ns
        })
    }

    /// Find all descendant elements with the given local name and namespace.
    pub fn find_elements<'a>(
        doc: &'a roxmltree::Document<'a>,
        ns: &str,
        local_name: &str,
    ) -> Vec<roxmltree::Node<'a, 'a>> {
        doc.descendants()
            .filter(|n| {
                n.is_element()
                    && n.tag_name().name() == local_name
                    && n.tag_name().namespace().unwrap_or("") == ns
            })
            .collect()
    }
}
