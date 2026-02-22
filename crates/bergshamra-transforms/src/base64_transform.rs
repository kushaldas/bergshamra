#![forbid(unsafe_code)]

//! Base64 decode transform.

use crate::pipeline::{Transform, TransformData};
use bergshamra_core::{algorithm, Error};
use bergshamra_xml::NodeSet;
use uppsala::NodeKind;

/// Extract text content from an XML document, optionally filtered by a node set.
fn extract_text_content(xml_text: &str, node_set: Option<&NodeSet>) -> Result<String, Error> {
    let doc = uppsala::parse(xml_text)
        .map_err(|e| Error::Transform(format!("base64: XML parse: {e}")))?;
    let mut text = String::new();
    let root = doc.root();
    for id in doc.descendants(root) {
        if let Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) = doc.node_kind(id) {
            if let Some(ns) = node_set {
                if ns.contains_id(id) {
                    text.push_str(t);
                }
            } else {
                text.push_str(t);
            }
        }
    }
    Ok(text)
}

/// Base64 decode transform — decodes Base64-encoded data.
pub struct Base64DecodeTransform;

impl Transform for Base64DecodeTransform {
    fn uri(&self) -> &str {
        algorithm::BASE64
    }

    fn execute(&self, input: TransformData) -> Result<TransformData, Error> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;

        let text = match &input {
            TransformData::Binary(data) => {
                std::str::from_utf8(data)
                    .map_err(|e| Error::Transform(format!("base64 input not UTF-8: {e}")))?
                    .to_owned()
            }
            TransformData::Xml { xml_text, node_set } => {
                // Extract text content from the node set, not the full XML.
                // Per W3C: "removes the tags and extracts the content".
                extract_text_content(xml_text, node_set.as_ref())?
            }
        };

        let cleaned: String = text
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        let decoded = engine
            .decode(&cleaned)
            .map_err(|e| Error::Base64(format!("decode error: {e}")))?;

        Ok(TransformData::Binary(decoded))
    }
}
