#![forbid(unsafe_code)]

//! Digest (hash) algorithm implementations.

use bergshamra_core::{algorithm, Error};
use digest::Digest;

/// Trait for digest algorithms.
pub trait DigestAlgorithm: Send {
    /// Feed data into the hash.
    fn update(&mut self, data: &[u8]);
    /// Finalize and return the hash value.
    fn finalize(self: Box<Self>) -> Vec<u8>;
    /// Algorithm URI.
    fn uri(&self) -> &'static str;
}

/// Create a digest algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn DigestAlgorithm>, Error> {
    match uri {
        algorithm::SHA1 => Ok(Box::new(Sha1Digest::new())),
        algorithm::SHA224 => Ok(Box::new(Sha224Digest::new())),
        algorithm::SHA256 => Ok(Box::new(Sha256Digest::new())),
        algorithm::SHA384 => Ok(Box::new(Sha384Digest::new())),
        algorithm::SHA512 => Ok(Box::new(Sha512Digest::new())),
        algorithm::SHA3_224 => Ok(Box::new(Sha3_224Digest::new())),
        algorithm::SHA3_256 => Ok(Box::new(Sha3_256Digest::new())),
        algorithm::SHA3_384 => Ok(Box::new(Sha3_384Digest::new())),
        algorithm::SHA3_512 => Ok(Box::new(Sha3_512Digest::new())),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::MD5 => Ok(Box::new(Md5Digest::new())),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::RIPEMD160 => Ok(Box::new(Ripemd160Digest::new())),
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "digest algorithm: {uri}"
        ))),
    }
}

/// Compute a digest in one shot.
pub fn digest(uri: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut hasher = from_uri(uri)?;
    hasher.update(data);
    Ok(hasher.finalize())
}

// ── Concrete implementations ─────────────────────────────────────────

macro_rules! impl_digest {
    ($name:ident, $hasher:ty, $uri:expr) => {
        struct $name {
            inner: $hasher,
        }

        impl $name {
            fn new() -> Self {
                Self {
                    inner: <$hasher>::new(),
                }
            }
        }

        impl DigestAlgorithm for $name {
            fn update(&mut self, data: &[u8]) {
                Digest::update(&mut self.inner, data);
            }

            fn finalize(self: Box<Self>) -> Vec<u8> {
                Digest::finalize(self.inner).to_vec()
            }

            fn uri(&self) -> &'static str {
                $uri
            }
        }
    };
}

impl_digest!(Sha1Digest, sha1::Sha1, algorithm::SHA1);
impl_digest!(Sha224Digest, sha2::Sha224, algorithm::SHA224);
impl_digest!(Sha256Digest, sha2::Sha256, algorithm::SHA256);
impl_digest!(Sha384Digest, sha2::Sha384, algorithm::SHA384);
impl_digest!(Sha512Digest, sha2::Sha512, algorithm::SHA512);
impl_digest!(Sha3_224Digest, sha3::Sha3_224, algorithm::SHA3_224);
impl_digest!(Sha3_256Digest, sha3::Sha3_256, algorithm::SHA3_256);
impl_digest!(Sha3_384Digest, sha3::Sha3_384, algorithm::SHA3_384);
impl_digest!(Sha3_512Digest, sha3::Sha3_512, algorithm::SHA3_512);

#[cfg(feature = "legacy-algorithms")]
impl_digest!(Md5Digest, md5::Md5, algorithm::MD5);

#[cfg(feature = "legacy-algorithms")]
impl_digest!(Ripemd160Digest, ripemd::Ripemd160, algorithm::RIPEMD160);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let result = digest(algorithm::SHA256, b"hello").unwrap();
        assert_eq!(result.len(), 32);
        // Known SHA-256 of "hello"
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn test_sha1() {
        let result = digest(algorithm::SHA1, b"hello").unwrap();
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_sha512() {
        let result = digest(algorithm::SHA512, b"hello").unwrap();
        assert_eq!(result.len(), 64);
    }
}
