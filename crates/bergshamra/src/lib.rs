#![forbid(unsafe_code)]

pub use bergshamra_c14n as c14n;
pub use bergshamra_core as core;
pub use bergshamra_crypto as crypto;
pub use bergshamra_dsig as dsig;
pub use bergshamra_enc as enc;
pub use bergshamra_keys as keys;
pub use bergshamra_transforms as transforms;
pub use bergshamra_xml as xml;

// Convenience re-exports for commonly used types.
pub use bergshamra_core::Error;
pub use bergshamra_dsig::{DsigContext, VerifiedKeyInfo, VerifiedReference, VerifyResult};
pub use bergshamra_enc::EncContext;
pub use bergshamra_keys::{Key, KeyData, KeyUsage, KeysManager};

// Re-export entry-point functions.
pub use bergshamra_dsig::sign::sign;
pub use bergshamra_dsig::verify::verify;
pub use bergshamra_enc::decrypt::{decrypt, decrypt_to_bytes};
pub use bergshamra_enc::encrypt::encrypt;
