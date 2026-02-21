#![forbid(unsafe_code)]

//! Key management for the Bergshamra XML Security library.
//!
//! Supports loading keys from PEM, DER, PKCS#8, PKCS#12, and raw binary formats.
//! Provides a `KeysManager` for named key lookup and a `KeyInfo` XML processor.

pub mod key;
pub mod keyinfo;
pub mod keysxml;
pub mod loader;
pub mod manager;
pub mod x509;

pub use key::{Key, KeyData, KeyUsage};
pub use manager::KeysManager;
