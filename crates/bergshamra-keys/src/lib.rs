#![forbid(unsafe_code)]

//! Key management for the Bergshamra XML Security library.
//!
//! Supports loading keys from PEM, DER, PKCS#8, PKCS#12, and raw binary formats.
//! Provides a `KeysManager` for named key lookup and a `KeyInfo` XML processor.
//!
//! ## Shared infrastructure
//!
//! Trust store management, certificate chain building/verification, and
//! cryptographic algorithm support are re-exported from the shared [`tsp_ltv`]
//! crate. This follows the same "thin facade" pattern used by underskrift
//! (PDF signing library).

#[cfg(feature = "rustcrypto")]
pub mod key;
#[cfg(not(feature = "rustcrypto"))]
#[path = "alternate/key.rs"]
pub mod key;
pub mod keyinfo;
pub mod keysxml;
#[cfg(feature = "rustcrypto")]
pub mod loader;
#[cfg(not(feature = "rustcrypto"))]
#[path = "alternate/loader.rs"]
pub mod loader;
pub mod manager;
pub mod trust;
pub mod x509;

// Re-export shared infrastructure from tsp-ltv
pub use tsp_ltv::crypto as tsp_crypto;
pub use tsp_ltv::error as tsp_error;

pub use key::{Key, KeyData, KeyUsage};
pub use keyinfo::{build_x509_key_info, build_x509_key_info_from_der};
pub use manager::KeysManager;
