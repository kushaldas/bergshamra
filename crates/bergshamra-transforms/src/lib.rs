#![forbid(unsafe_code)]

//! Transform pipeline engine for the Bergshamra XML Security library.
//!
//! Implements the transform chain model from XML-DSig: each reference
//! contains a sequence of transforms that are applied in order.

pub mod pipeline;
pub mod base64_transform;
pub mod enveloped;
pub mod uri;

pub use pipeline::{Transform, TransformData, TransformPipeline};
