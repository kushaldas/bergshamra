#![forbid(unsafe_code)]

//! Error and result types shared by Bergshamra crates.

/// Errors produced by the Bergshamra XML Security library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// XML parsing failed before a document tree could be built.
    #[error("XML parsing error: {0}")]
    XmlParse(String),

    /// XML parsed successfully but did not have the structure required by the
    /// requested XML Security operation.
    #[error("invalid XML structure: {0}")]
    XmlStructure(String),

    /// The document or caller requested an algorithm URI that Bergshamra does
    /// not support in the current build.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// A cryptographic primitive failed.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Key loading, parsing, lookup, or conversion failed.
    #[error("key error: {0}")]
    Key(String),

    /// Signature verification completed and the signature was not valid.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    /// A computed reference digest did not match the signed digest value.
    #[error("digest mismatch for reference: {0}")]
    DigestMismatch(String),

    /// Canonical XML serialization failed.
    #[error("canonicalization error: {0}")]
    Canonicalization(String),

    /// An XML Signature transform failed.
    #[error("transform error: {0}")]
    Transform(String),

    /// XML Encryption failed while producing encrypted XML.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// XML Encryption failed while decrypting XML.
    #[error("decryption error: {0}")]
    Decryption(String),

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(String),

    /// File or stream I/O failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// No configured key matched the requested name, usage, or algorithm.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// A required XML element was missing.
    #[error("missing required element: {0}")]
    MissingElement(String),

    /// A required XML attribute was missing.
    #[error("missing required attribute: {0}")]
    MissingAttribute(String),

    /// A URI reference was syntactically invalid or could not be resolved.
    #[error("invalid URI reference: {0}")]
    InvalidUri(String),

    /// Certificate parsing or validation failed.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// General-purpose error for cases without a more specific variant.
    #[error("{0}")]
    Other(String),
}

/// Convenient result alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
