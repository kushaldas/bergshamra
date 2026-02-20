#![forbid(unsafe_code)]

//! Algorithm registry mapping URIs to factory functions.

use bergshamra_core::Error;
use crate::digest::DigestAlgorithm;
use crate::sign::SignatureAlgorithm;
use crate::cipher::CipherAlgorithm;
use crate::keywrap::KeyWrapAlgorithm;
use crate::keytransport::KeyTransportAlgorithm;

/// Central registry for all cryptographic algorithms.
pub struct AlgorithmRegistry;

impl AlgorithmRegistry {
    /// Look up a digest algorithm by URI.
    pub fn digest(uri: &str) -> Result<Box<dyn DigestAlgorithm>, Error> {
        crate::digest::from_uri(uri)
    }

    /// Look up a signature algorithm by URI.
    pub fn signature(uri: &str) -> Result<Box<dyn SignatureAlgorithm>, Error> {
        crate::sign::from_uri(uri)
    }

    /// Look up a cipher algorithm by URI.
    pub fn cipher(uri: &str) -> Result<Box<dyn CipherAlgorithm>, Error> {
        crate::cipher::from_uri(uri)
    }

    /// Look up a key wrap algorithm by URI.
    pub fn key_wrap(uri: &str) -> Result<Box<dyn KeyWrapAlgorithm>, Error> {
        crate::keywrap::from_uri(uri)
    }

    /// Look up a key transport algorithm by URI.
    pub fn key_transport(uri: &str) -> Result<Box<dyn KeyTransportAlgorithm>, Error> {
        crate::keytransport::from_uri(uri)
    }
}
