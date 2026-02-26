#![forbid(unsafe_code)]

//! Cryptographic algorithm implementations for Bergshamra XML Security library.
//!
//! Provides traits and implementations for all crypto operations needed by
//! XML-DSig and XML-Enc: digests, signatures, block ciphers, key wrapping,
//! and key transport.

pub mod cipher;
pub mod digest;
pub mod kdf;
pub mod keyagreement;
pub mod keytransport;
pub mod keywrap;
pub mod registry;
pub mod sign;

pub use digest::DigestAlgorithm;
pub use registry::AlgorithmRegistry;
