#![forbid(unsafe_code)]

//! XML Encryption (XML-Enc) implementation.
//!
//! Provides encryption and decryption per the W3C XML Encryption spec.

pub mod context;
pub mod decrypt;
pub mod encrypt;

pub use context::EncContext;
