#![forbid(unsafe_code)]

//! XML writing utilities using uppsala's XmlWriter for template building.

use bergshamra_core::Error;

/// A simple XML writer wrapping uppsala's XmlWriter.
pub struct XmlWriter {
    writer: uppsala::XmlWriter,
}

impl XmlWriter {
    /// Create a new XML writer.
    pub fn new() -> Self {
        Self {
            writer: uppsala::XmlWriter::new(),
        }
    }

    /// Write the XML declaration.
    pub fn write_declaration(&mut self) -> Result<(), Error> {
        self.writer.write_declaration();
        Ok(())
    }

    /// Start an element with the given name and optional attributes.
    pub fn start_element(
        &mut self,
        name: &str,
        attrs: &[(&str, &str)],
    ) -> Result<(), Error> {
        self.writer.start_element(name, attrs);
        Ok(())
    }

    /// Write an empty element (self-closing).
    pub fn empty_element(
        &mut self,
        name: &str,
        attrs: &[(&str, &str)],
    ) -> Result<(), Error> {
        self.writer.empty_element(name, attrs);
        Ok(())
    }

    /// End the current element.
    pub fn end_element(&mut self, name: &str) -> Result<(), Error> {
        self.writer.end_element(name);
        Ok(())
    }

    /// Write text content.
    pub fn write_text(&mut self, text: &str) -> Result<(), Error> {
        self.writer.text(text);
        Ok(())
    }

    /// Finish writing and return the XML bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.writer.into_bytes()
    }

    /// Finish writing and return the XML as a string.
    pub fn into_string(self) -> Result<String, Error> {
        Ok(self.writer.into_string())
    }
}

impl Default for XmlWriter {
    fn default() -> Self {
        Self::new()
    }
}
