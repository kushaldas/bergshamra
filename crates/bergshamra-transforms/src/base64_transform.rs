#![forbid(unsafe_code)]

//! Base64 decode transform.

use crate::pipeline::{Transform, TransformData};
use bergshamra_core::{algorithm, Error};

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
            TransformData::Xml { xml_text, .. } => xml_text.clone(),
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
