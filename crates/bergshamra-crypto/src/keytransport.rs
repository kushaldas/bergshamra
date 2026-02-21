#![forbid(unsafe_code)]

//! Key transport algorithms (RSA PKCS#1 v1.5, RSA-OAEP).

use bergshamra_core::{algorithm, Error};

/// Trait for key transport algorithms.
pub trait KeyTransportAlgorithm: Send {
    fn uri(&self) -> &'static str;
    fn encrypt(&self, public_key: &rsa::RsaPublicKey, key_data: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(
        &self,
        private_key: &rsa::RsaPrivateKey,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

/// RSA-OAEP configuration parameters.
#[derive(Debug, Clone)]
pub struct OaepParams {
    /// Digest algorithm URI (default: SHA-1)
    pub digest_uri: Option<String>,
    /// MGF algorithm URI (default: MGF1 with same digest)
    pub mgf_uri: Option<String>,
    /// OAEPparams (optional label, base64-decoded)
    pub oaep_params: Option<Vec<u8>>,
}

impl Default for OaepParams {
    fn default() -> Self {
        Self {
            digest_uri: None,
            mgf_uri: None,
            oaep_params: None,
        }
    }
}

/// Create a key transport algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn KeyTransportAlgorithm>, Error> {
    from_uri_with_params(uri, OaepParams::default())
}

/// Create a key transport algorithm from its URI with RSA-OAEP parameters.
pub fn from_uri_with_params(uri: &str, params: OaepParams) -> Result<Box<dyn KeyTransportAlgorithm>, Error> {
    match uri {
        algorithm::RSA_PKCS1 => Ok(Box::new(RsaPkcs1Transport)),
        algorithm::RSA_OAEP => Ok(Box::new(RsaOaepTransport {
            uri: algorithm::RSA_OAEP,
            params,
        })),
        algorithm::RSA_OAEP_ENC11 => Ok(Box::new(RsaOaepTransport {
            uri: algorithm::RSA_OAEP_ENC11,
            params,
        })),
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "key transport: {uri}"
        ))),
    }
}

struct RsaPkcs1Transport;

impl KeyTransportAlgorithm for RsaPkcs1Transport {
    fn uri(&self) -> &'static str {
        algorithm::RSA_PKCS1
    }

    fn encrypt(&self, public_key: &rsa::RsaPublicKey, key_data: &[u8]) -> Result<Vec<u8>, Error> {
        use rsa::Pkcs1v15Encrypt;
        let mut rng = rand::thread_rng();
        public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, key_data)
            .map_err(|e| Error::Crypto(format!("RSA PKCS#1 encrypt: {e}")))
    }

    fn decrypt(
        &self,
        private_key: &rsa::RsaPrivateKey,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use rsa::Pkcs1v15Encrypt;
        private_key
            .decrypt(Pkcs1v15Encrypt, encrypted)
            .map_err(|e| Error::Crypto(format!("RSA PKCS#1 decrypt: {e}")))
    }
}

struct RsaOaepTransport {
    uri: &'static str,
    params: OaepParams,
}

/// Resolve the MGF hash for OAEP.
///
/// For `rsa-oaep-mgf1p` (XML Enc 1.0): MGF1 always uses SHA-1 unless an explicit
/// MGF element overrides it.  The DigestMethod only controls the OAEP label hash.
///
/// For `rsa-oaep` (XML Enc 1.1): MGF defaults to the same hash as DigestMethod
/// when no explicit MGF element is present.
fn resolve_oaep_mgf(uri: &str, params: &OaepParams, digest: &str) -> &'static str {
    // If an explicit MGF element is present, use it
    if let Some(mgf) = resolve_mgf(params.mgf_uri.as_deref()) {
        return mgf;
    }
    // rsa-oaep-mgf1p: MGF1 defaults to SHA-1
    if uri == algorithm::RSA_OAEP {
        return "sha1";
    }
    // rsa-oaep (enc11): MGF defaults to same as digest
    match digest {
        "sha1" => "sha1",
        "sha224" => "sha224",
        "sha256" => "sha256",
        "sha384" => "sha384",
        "sha512" => "sha512",
        _ => "sha1",
    }
}

/// Helper macro to avoid duplicating the OAEP padding creation logic.
/// Returns a boxed PaddingScheme for the given digest+MGF combination.
macro_rules! oaep_decrypt {
    ($private_key:expr, $encrypted:expr, $digest:ty, $mgf:ty, $label:expr) => {{
        use rsa::Oaep;
        let mut padding = Oaep::new_with_mgf_hash::<$digest, $mgf>();
        if let Some(ref label_bytes) = $label {
            padding.label = Some(String::from_utf8_lossy(label_bytes).into_owned());
        }
        $private_key
            .decrypt(padding, $encrypted)
            .map_err(|e| Error::Crypto(format!("RSA-OAEP decrypt: {e}")))
    }};
}

/// Dispatch to the correct OAEP encrypt based on (digest, mgf) string pair.
macro_rules! oaep_dispatch_encrypt {
    ($pk:expr, $data:expr, $digest:expr, $mgf:expr, $label:expr) => {{
        // Map each MGF to the right inner call, for the given digest.
        macro_rules! with_mgf {
            ($d:ty) => {
                match $mgf {
                    "sha1" => oaep_encrypt!($pk, $data, $d, sha1::Sha1, $label),
                    "sha224" => oaep_encrypt!($pk, $data, $d, sha2::Sha224, $label),
                    "sha256" => oaep_encrypt!($pk, $data, $d, sha2::Sha256, $label),
                    "sha384" => oaep_encrypt!($pk, $data, $d, sha2::Sha384, $label),
                    "sha512" => oaep_encrypt!($pk, $data, $d, sha2::Sha512, $label),
                    _ => oaep_encrypt!($pk, $data, $d, sha1::Sha1, $label),
                }
            };
        }
        match $digest {
            "sha1" => with_mgf!(sha1::Sha1),
            "sha224" => with_mgf!(sha2::Sha224),
            "sha256" => with_mgf!(sha2::Sha256),
            "sha384" => with_mgf!(sha2::Sha384),
            "sha512" => with_mgf!(sha2::Sha512),
            #[cfg(feature = "legacy-algorithms")]
            "md5" => with_mgf!(md5::Md5),
            #[cfg(feature = "legacy-algorithms")]
            "ripemd160" => with_mgf!(ripemd::Ripemd160),
            _ => oaep_encrypt!($pk, $data, sha1::Sha1, sha1::Sha1, $label),
        }
    }};
}

/// Dispatch to the correct OAEP decrypt based on (digest, mgf) string pair.
macro_rules! oaep_dispatch_decrypt {
    ($pk:expr, $data:expr, $digest:expr, $mgf:expr, $label:expr) => {{
        macro_rules! with_mgf {
            ($d:ty) => {
                match $mgf {
                    "sha1" => oaep_decrypt!($pk, $data, $d, sha1::Sha1, $label),
                    "sha224" => oaep_decrypt!($pk, $data, $d, sha2::Sha224, $label),
                    "sha256" => oaep_decrypt!($pk, $data, $d, sha2::Sha256, $label),
                    "sha384" => oaep_decrypt!($pk, $data, $d, sha2::Sha384, $label),
                    "sha512" => oaep_decrypt!($pk, $data, $d, sha2::Sha512, $label),
                    _ => oaep_decrypt!($pk, $data, $d, sha1::Sha1, $label),
                }
            };
        }
        match $digest {
            "sha1" => with_mgf!(sha1::Sha1),
            "sha224" => with_mgf!(sha2::Sha224),
            "sha256" => with_mgf!(sha2::Sha256),
            "sha384" => with_mgf!(sha2::Sha384),
            "sha512" => with_mgf!(sha2::Sha512),
            #[cfg(feature = "legacy-algorithms")]
            "md5" => with_mgf!(md5::Md5),
            #[cfg(feature = "legacy-algorithms")]
            "ripemd160" => with_mgf!(ripemd::Ripemd160),
            _ => oaep_decrypt!($pk, $data, sha1::Sha1, sha1::Sha1, $label),
        }
    }};
}

macro_rules! oaep_encrypt {
    ($public_key:expr, $key_data:expr, $digest:ty, $mgf:ty, $label:expr) => {{
        use rsa::Oaep;
        let mut rng = rand::thread_rng();
        let mut padding = Oaep::new_with_mgf_hash::<$digest, $mgf>();
        if let Some(ref label_bytes) = $label {
            padding.label = Some(String::from_utf8_lossy(label_bytes).into_owned());
        }
        $public_key
            .encrypt(&mut rng, padding, $key_data)
            .map_err(|e| Error::Crypto(format!("RSA-OAEP encrypt: {e}")))
    }};
}

/// Resolve the digest URI to a concrete hash type identifier.
fn resolve_digest(uri: Option<&str>) -> &str {
    match uri {
        Some(algorithm::SHA256) => "sha256",
        Some(algorithm::SHA384) => "sha384",
        Some(algorithm::SHA512) => "sha512",
        Some(algorithm::SHA224) => "sha224",
        Some(algorithm::SHA1) | None => "sha1",
        Some(other) => {
            // Unknown digest — try sha1 as fallback for ripemd160/md5 etc.
            if other.contains("ripemd160") {
                "ripemd160"
            } else if other.contains("md5") {
                "md5"
            } else {
                "sha1"
            }
        }
    }
}

/// Resolve the MGF URI to a hash type identifier.
fn resolve_mgf(uri: Option<&str>) -> Option<&'static str> {
    match uri {
        Some(algorithm::MGF1_SHA1) => Some("sha1"),
        Some(algorithm::MGF1_SHA224) => Some("sha224"),
        Some(algorithm::MGF1_SHA256) => Some("sha256"),
        Some(algorithm::MGF1_SHA384) => Some("sha384"),
        Some(algorithm::MGF1_SHA512) => Some("sha512"),
        _ => None,
    }
}

impl KeyTransportAlgorithm for RsaOaepTransport {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn encrypt(&self, public_key: &rsa::RsaPublicKey, key_data: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = resolve_digest(self.params.digest_uri.as_deref());
        let mgf = resolve_oaep_mgf(self.uri, &self.params, digest);
        let label = &self.params.oaep_params;

        oaep_dispatch_encrypt!(public_key, key_data, digest, mgf, label)
    }

    fn decrypt(
        &self,
        private_key: &rsa::RsaPrivateKey,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let digest = resolve_digest(self.params.digest_uri.as_deref());
        let mgf = resolve_oaep_mgf(self.uri, &self.params, digest);
        let label = &self.params.oaep_params;

        oaep_dispatch_decrypt!(private_key, encrypted, digest, mgf, label)
    }
}
