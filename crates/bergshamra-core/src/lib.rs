#![forbid(unsafe_code)]

//! Shared Bergshamra core definitions.
//!
//! This crate contains common XML Security algorithm URI constants,
//! namespace/name constants, and the shared [`Error`] type used by the
//! signing, encryption, transform, key, and canonicalization crates.

/// XML Security algorithm URI constants.
pub mod algorithm;
/// Shared error and result types.
pub mod error;
/// XML namespace, element-name, attribute-name, and transform-name constants.
pub mod ns;

/// Shared Bergshamra error type.
pub use error::Error;
