#![forbid(unsafe_code)]

//! Public facade for Bergshamra XML security.
//!
//! This crate re-exports the main Bergshamra subcrates and the most common
//! entry points for XML Signature and XML Encryption work. For signing and
//! verification, start with [`DsigContext`], [`sign`], [`verify`], and
//! [`verify_all`]. For encryption and decryption, start with [`EncContext`],
//! [`encrypt`], [`decrypt`], and [`decrypt_to_bytes`].
//!
//! Lower-level modules remain available when callers need direct access to
//! canonical XML (`c14n`), key loading and lookup (`keys`), transform handling
//! (`transforms`), or algorithm implementations (`crypto`).

/// Canonical XML support, including inclusive, exclusive, and C14N 1.1 modes.
pub use bergshamra_c14n as c14n;
/// Core shared types, XML security namespace constants, and the error type.
pub use bergshamra_core as core;
/// Cryptographic algorithm implementations and registries.
pub use bergshamra_crypto as crypto;
/// XML Digital Signature signing and verification.
pub use bergshamra_dsig as dsig;
/// XML Encryption encryption and decryption.
pub use bergshamra_enc as enc;
/// Key representations, key stores, KeyInfo helpers, and X.509 validation.
pub use bergshamra_keys as keys;
/// XML Signature transform implementations and transform pipelines.
pub use bergshamra_transforms as transforms;
/// XML document helpers and node-set support used by transforms and C14N.
pub use bergshamra_xml as xml;

/// Bergshamra's shared error type.
pub use bergshamra_core::Error;
/// Digital signature configuration and verification result types.
pub use bergshamra_dsig::{DsigContext, VerifiedKeyInfo, VerifiedReference, VerifyResult};
/// Encryption configuration.
pub use bergshamra_enc::EncContext;
/// Key types and the in-memory key manager.
pub use bergshamra_keys::{Key, KeyData, KeyUsage, KeysManager};
/// Compile-time provider metadata, capabilities, and explicit initialization.
pub use kryptering::{
    backend_info, capabilities, initialize_backend, supports, BackendId, BackendInfo, Capability,
    FipsStatus, Operation, SoftwareKey, TlsBackendId,
};

/// Sign an XML signature template.
pub use bergshamra_dsig::sign::sign;
/// Verify the first signature, or all signatures, in an XML document.
pub use bergshamra_dsig::verify::{verify, verify_all};
/// Decrypt XML Encryption content as UTF-8 text or raw bytes.
pub use bergshamra_enc::decrypt::{decrypt, decrypt_to_bytes};
/// Encrypt bytes into an XML Encryption template.
pub use bergshamra_enc::encrypt::encrypt;
