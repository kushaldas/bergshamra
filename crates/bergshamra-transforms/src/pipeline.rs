#![forbid(unsafe_code)]

//! Transform pipeline and trait definitions.

use bergshamra_core::Error;
use bergshamra_xml::NodeSet;

/// Data flowing through the transform pipeline.
pub enum TransformData {
    /// XML node set (for XML-aware transforms like C14N).
    Xml {
        xml_text: String,
        node_set: Option<NodeSet>,
    },
    /// Raw binary data.
    Binary(Vec<u8>),
}

impl TransformData {
    /// Convert to binary (applying C14N if needed).
    pub fn to_binary(&self) -> Result<Vec<u8>, Error> {
        match self {
            TransformData::Binary(data) => Ok(data.clone()),
            TransformData::Xml { xml_text, node_set } => {
                // Default: inclusive C14N without comments
                let mode = bergshamra_c14n::C14nMode::Inclusive;
                bergshamra_c14n::canonicalize(xml_text, mode, node_set.as_ref(), &[])
            }
        }
    }
}

/// Trait for individual transforms.
pub trait Transform: Send {
    /// The algorithm URI for this transform.
    fn uri(&self) -> &str;

    /// Execute the transform on the given data.
    fn execute(&self, input: TransformData) -> Result<TransformData, Error>;
}

/// A pipeline of transforms executed in sequence.
pub struct TransformPipeline {
    transforms: Vec<Box<dyn Transform>>,
}

impl TransformPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    /// Add a transform to the pipeline.
    pub fn push(&mut self, transform: Box<dyn Transform>) {
        self.transforms.push(transform);
    }

    /// Execute all transforms in order.
    pub fn execute(&self, input: TransformData) -> Result<TransformData, Error> {
        let mut data = input;
        for transform in &self.transforms {
            data = transform.execute(data)?;
        }
        Ok(data)
    }

    /// Number of transforms in the pipeline.
    pub fn len(&self) -> usize {
        self.transforms.len()
    }

    /// Check if pipeline is empty.
    pub fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
}

impl Default for TransformPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ── C14N Transform ───────────────────────────────────────────────────

/// A canonicalization transform.
pub struct C14nTransform {
    mode: bergshamra_c14n::C14nMode,
    inclusive_prefixes: Vec<String>,
}

impl C14nTransform {
    pub fn new(mode: bergshamra_c14n::C14nMode, inclusive_prefixes: Vec<String>) -> Self {
        Self {
            mode,
            inclusive_prefixes,
        }
    }
}

impl Transform for C14nTransform {
    fn uri(&self) -> &str {
        self.mode.uri()
    }

    fn execute(&self, input: TransformData) -> Result<TransformData, Error> {
        match input {
            TransformData::Xml { xml_text, node_set } => {
                let bytes = bergshamra_c14n::canonicalize(
                    &xml_text,
                    self.mode,
                    node_set.as_ref(),
                    &self.inclusive_prefixes,
                )?;
                Ok(TransformData::Binary(bytes))
            }
            TransformData::Binary(data) => {
                // Parse XML, canonicalize
                let bytes = bergshamra_c14n::canonicalize(
                    std::str::from_utf8(&data)
                        .map_err(|e| Error::Transform(format!("invalid UTF-8: {e}")))?,
                    self.mode,
                    None,
                    &self.inclusive_prefixes,
                )?;
                Ok(TransformData::Binary(bytes))
            }
        }
    }
}
