#![forbid(unsafe_code)]

//! XML Digital Signature (XML-DSig) implementation.
//!
//! Provides signature verification and creation per the W3C XML-DSig spec.

pub mod context;
pub mod verify;
pub mod sign;

pub use context::DsigContext;
pub use verify::VerifyResult;
