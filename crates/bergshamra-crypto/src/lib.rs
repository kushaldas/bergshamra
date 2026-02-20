#![forbid(unsafe_code)]

//! Cryptographic algorithm implementations for Bergshamra XML Security library.
//!
//! Provides traits and implementations for all crypto operations needed by
//! XML-DSig and XML-Enc: digests, signatures, block ciphers, key wrapping,
//! and key transport.

pub mod digest;
pub mod sign;
pub mod cipher;
pub mod keywrap;
pub mod keytransport;
pub mod registry;

pub use digest::DigestAlgorithm;
pub use registry::AlgorithmRegistry;
