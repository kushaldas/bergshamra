#![forbid(unsafe_code)]

/// Errors produced by the Bergshamra XML Security library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("XML parsing error: {0}")]
    XmlParse(String),

    #[error("invalid XML structure: {0}")]
    XmlStructure(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("digest mismatch for reference: {0}")]
    DigestMismatch(String),

    #[error("canonicalization error: {0}")]
    Canonicalization(String),

    #[error("transform error: {0}")]
    Transform(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("base64 decode error: {0}")]
    Base64(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("missing required element: {0}")]
    MissingElement(String),

    #[error("missing required attribute: {0}")]
    MissingAttribute(String),

    #[error("invalid URI reference: {0}")]
    InvalidUri(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
