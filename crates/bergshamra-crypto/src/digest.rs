#![forbid(unsafe_code)]

//! Digest (hash) algorithm implementations.

use bergshamra_core::{algorithm, Error};
use kryptering::HashAlgorithm;

/// Trait for digest algorithms.
pub trait DigestAlgorithm: Send {
    /// Feed data into the hash.
    fn update(&mut self, data: &[u8]);
    /// Finalize and return the hash value.
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, Error>;
    /// Algorithm URI.
    fn uri(&self) -> &'static str;
}

/// Map an XML algorithm URI to a `kryptering::HashAlgorithm`.
fn uri_to_hash(uri: &str) -> Result<HashAlgorithm, Error> {
    match uri {
        algorithm::SHA1 => Ok(HashAlgorithm::Sha1),
        algorithm::SHA224 => Ok(HashAlgorithm::Sha224),
        algorithm::SHA256 => Ok(HashAlgorithm::Sha256),
        algorithm::SHA384 => Ok(HashAlgorithm::Sha384),
        algorithm::SHA512 => Ok(HashAlgorithm::Sha512),
        algorithm::SHA3_224 => Ok(HashAlgorithm::Sha3_224),
        algorithm::SHA3_256 => Ok(HashAlgorithm::Sha3_256),
        algorithm::SHA3_384 => Ok(HashAlgorithm::Sha3_384),
        algorithm::SHA3_512 => Ok(HashAlgorithm::Sha3_512),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::MD5 => Ok(HashAlgorithm::Md5),
        #[cfg(feature = "legacy-algorithms")]
        algorithm::RIPEMD160 => Ok(HashAlgorithm::Ripemd160),
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "digest algorithm: {uri}"
        ))),
    }
}

/// Map a `kryptering::HashAlgorithm` back to an XML algorithm URI.
fn hash_to_uri(algo: HashAlgorithm) -> &'static str {
    match algo {
        HashAlgorithm::Sha1 => algorithm::SHA1,
        HashAlgorithm::Sha224 => algorithm::SHA224,
        HashAlgorithm::Sha256 => algorithm::SHA256,
        HashAlgorithm::Sha384 => algorithm::SHA384,
        HashAlgorithm::Sha512 => algorithm::SHA512,
        HashAlgorithm::Sha3_224 => algorithm::SHA3_224,
        HashAlgorithm::Sha3_256 => algorithm::SHA3_256,
        HashAlgorithm::Sha3_384 => algorithm::SHA3_384,
        HashAlgorithm::Sha3_512 => algorithm::SHA3_512,
        #[cfg(feature = "legacy-algorithms")]
        HashAlgorithm::Md5 => algorithm::MD5,
        #[cfg(feature = "legacy-algorithms")]
        HashAlgorithm::Ripemd160 => algorithm::RIPEMD160,
        // Catch variants enabled by kryptering features not matched above.
        #[allow(unreachable_patterns)]
        _ => "unsupported",
    }
}

/// Create a digest algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn DigestAlgorithm>, Error> {
    let algo = uri_to_hash(uri)?;
    let inner = kryptering::digest::new_digest(algo).map_err(crate::map_kryptering_err)?;
    Ok(Box::new(KrypteringDigest {
        uri: hash_to_uri(algo),
        inner,
    }))
}

/// Compute a digest in one shot.
pub fn digest(uri: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    let algo = uri_to_hash(uri)?;
    kryptering::digest::digest(algo, data).map_err(crate::map_kryptering_err)
}

// ── Wrapper that delegates to kryptering ────────────────────────────

struct KrypteringDigest {
    uri: &'static str,
    inner: Box<dyn kryptering::digest::DigestStream>,
}

impl DigestAlgorithm for KrypteringDigest {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, Error> {
        self.inner.finalize().map_err(crate::map_kryptering_err)
    }

    fn uri(&self) -> &'static str {
        self.uri
    }
}

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
