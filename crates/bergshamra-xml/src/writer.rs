#![forbid(unsafe_code)]

//! XML writing utilities using quick-xml for template building.

use bergshamra_core::Error;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::io::Cursor;

/// A simple XML writer wrapping quick-xml.
pub struct XmlWriter {
    writer: Writer<Cursor<Vec<u8>>>,
}

impl XmlWriter {
    /// Create a new XML writer.
    pub fn new() -> Self {
        Self {
            writer: Writer::new(Cursor::new(Vec::new())),
        }
    }

    /// Write the XML declaration.
    pub fn write_declaration(&mut self) -> Result<(), Error> {
        self.writer
            .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
            .map_err(|e| Error::Other(format!("XML write error: {e}")))?;
        Ok(())
    }

    /// Start an element with the given name and optional attributes.
    pub fn start_element(
        &mut self,
        name: &str,
        attrs: &[(&str, &str)],
    ) -> Result<(), Error> {
        let mut elem = BytesStart::new(name);
        for (key, val) in attrs {
            elem.push_attribute((*key, *val));
        }
        self.writer
            .write_event(Event::Start(elem))
            .map_err(|e| Error::Other(format!("XML write error: {e}")))?;
        Ok(())
    }

    /// Write an empty element (self-closing).
    pub fn empty_element(
        &mut self,
        name: &str,
        attrs: &[(&str, &str)],
    ) -> Result<(), Error> {
        let mut elem = BytesStart::new(name);
        for (key, val) in attrs {
            elem.push_attribute((*key, *val));
        }
        self.writer
            .write_event(Event::Empty(elem))
            .map_err(|e| Error::Other(format!("XML write error: {e}")))?;
        Ok(())
    }

    /// End the current element.
    pub fn end_element(&mut self, name: &str) -> Result<(), Error> {
        self.writer
            .write_event(Event::End(BytesEnd::new(name)))
            .map_err(|e| Error::Other(format!("XML write error: {e}")))?;
        Ok(())
    }

    /// Write text content.
    pub fn write_text(&mut self, text: &str) -> Result<(), Error> {
        self.writer
            .write_event(Event::Text(BytesText::new(text)))
            .map_err(|e| Error::Other(format!("XML write error: {e}")))?;
        Ok(())
    }

    /// Finish writing and return the XML bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.writer.into_inner().into_inner()
    }

    /// Finish writing and return the XML as a string.
    pub fn into_string(self) -> Result<String, Error> {
        let bytes = self.into_bytes();
        String::from_utf8(bytes).map_err(|e| Error::Other(format!("invalid UTF-8: {e}")))
    }
}

impl Default for XmlWriter {
    fn default() -> Self {
        Self::new()
    }
}
