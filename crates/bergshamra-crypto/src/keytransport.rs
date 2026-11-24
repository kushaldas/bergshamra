#![forbid(unsafe_code)]

//! Key transport algorithms (RSA PKCS#1 v1.5, RSA-OAEP).

use bergshamra_core::{algorithm, Error};
use kryptering::algorithm::{
    HashAlgorithm, KeyTransportAlgorithm as KKeyTransportAlgorithm, OaepConfig,
};

/// Trait for key transport algorithms.
pub trait KeyTransportAlgorithm: Send {
    /// Return the XML Encryption algorithm URI implemented by this transport.
    fn uri(&self) -> &'static str;

    /// Encrypt a content-encryption key or key-wrapping key for `public_key`.
    fn encrypt(
        &self,
        public_key: &kryptering::SoftwareKey,
        key_data: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Decrypt transported key bytes with `private_key`.
    fn decrypt(
        &self,
        private_key: &kryptering::SoftwareKey,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

/// RSA-OAEP configuration parameters.
#[derive(Debug, Clone, Default)]
pub struct OaepParams {
    /// Digest algorithm URI (default: SHA-1)
    pub digest_uri: Option<String>,
    /// MGF algorithm URI (default: MGF1 with SHA-1)
    pub mgf_uri: Option<String>,
    /// OAEPparams (optional label, base64-decoded)
    pub oaep_params: Option<Vec<u8>>,
}

/// Create a key transport algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn KeyTransportAlgorithm>, Error> {
    from_uri_with_params(uri, OaepParams::default())
}

/// Create a key transport algorithm from its URI with RSA-OAEP parameters.
pub fn from_uri_with_params(
    uri: &str,
    params: OaepParams,
) -> Result<Box<dyn KeyTransportAlgorithm>, Error> {
    match uri {
        algorithm::RSA_PKCS1 => {
            #[cfg(feature = "legacy-algorithms")]
            return Ok(Box::new(KrypteringKeyTransport {
                uri: algorithm::RSA_PKCS1,
                algo: KKeyTransportAlgorithm::RsaPkcs1v15,
                label: None,
            }));
            #[cfg(not(feature = "legacy-algorithms"))]
            return Err(Error::UnsupportedAlgorithm(
                "RSA PKCS#1 v1.5 transport requires legacy-algorithms".into(),
            ));
        }
        algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
            let static_uri = if uri == algorithm::RSA_OAEP {
                algorithm::RSA_OAEP
            } else {
                algorithm::RSA_OAEP_ENC11
            };
            let config = OaepConfig {
                digest: resolve_digest(params.digest_uri.as_deref())?,
                mgf_digest: resolve_mgf(params.mgf_uri.as_deref())?,
            };
            Ok(Box::new(KrypteringKeyTransport {
                uri: static_uri,
                algo: KKeyTransportAlgorithm::RsaOaep(config),
                label: params.oaep_params,
            }))
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("key transport: {uri}"))),
    }
}

// ── URI resolution helpers ──────────────────────────────────────────

/// Resolve the OAEP DigestMethod URI to a `HashAlgorithm`.
///
/// When the DigestMethod is *absent* (`None`), RSA-OAEP defaults to SHA-1 per
/// the XML Encryption spec. But when a DigestMethod is *present yet
/// unrecognized*, we fail closed with an error rather than silently downgrading
/// to SHA-1 — a silent fallback would mask algorithm-downgrade attempts and
/// produce confusing interop mismatches.
fn resolve_digest(uri: Option<&str>) -> Result<HashAlgorithm, Error> {
    match uri {
        // DigestMethod absent: spec default for RSA-OAEP is SHA-1.
        None | Some(algorithm::SHA1) => Ok(HashAlgorithm::Sha1),
        Some(algorithm::SHA256) => Ok(HashAlgorithm::Sha256),
        Some(algorithm::SHA384) => Ok(HashAlgorithm::Sha384),
        Some(algorithm::SHA512) => Ok(HashAlgorithm::Sha512),
        Some(algorithm::SHA224) => Ok(HashAlgorithm::Sha224),
        #[cfg(feature = "legacy-algorithms")]
        Some(algorithm::RIPEMD160) => Ok(HashAlgorithm::Ripemd160),
        #[cfg(feature = "legacy-algorithms")]
        Some(algorithm::MD5) => Ok(HashAlgorithm::Md5),
        Some(other) => {
            // Present-but-unsupported DigestMethod: fail closed.
            Err(Error::UnsupportedAlgorithm(format!(
                "unsupported OAEP DigestMethod: {other}"
            )))
        }
    }
}

/// Resolve the MGF URI to a `HashAlgorithm`.
fn resolve_mgf(uri: Option<&str>) -> Result<HashAlgorithm, Error> {
    match uri {
        None | Some(algorithm::MGF1_SHA1) => Ok(HashAlgorithm::Sha1),
        Some(algorithm::MGF1_SHA224) => Ok(HashAlgorithm::Sha224),
        Some(algorithm::MGF1_SHA256) => Ok(HashAlgorithm::Sha256),
        Some(algorithm::MGF1_SHA384) => Ok(HashAlgorithm::Sha384),
        Some(algorithm::MGF1_SHA512) => Ok(HashAlgorithm::Sha512),
        Some(other) => Err(Error::UnsupportedAlgorithm(format!(
            "unsupported OAEP MGF: {other}"
        ))),
    }
}

// ── Wrapper that delegates to kryptering ────────────────────────────

struct KrypteringKeyTransport {
    uri: &'static str,
    algo: KKeyTransportAlgorithm,
    label: Option<Vec<u8>>,
}

impl KeyTransportAlgorithm for KrypteringKeyTransport {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn encrypt(
        &self,
        public_key: &kryptering::SoftwareKey,
        key_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        kryptering::keytransport::kt_encrypt(self.algo, public_key, key_data, self.label.as_deref())
            .map_err(crate::map_kryptering_err)
    }

    fn decrypt(
        &self,
        private_key: &kryptering::SoftwareKey,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        kryptering::keytransport::kt_decrypt(
            self.algo,
            private_key,
            encrypted,
            self.label.as_deref(),
        )
        .map_err(crate::map_kryptering_err)
    }
}

#[cfg(test)]
mod tests {
    use super::{from_uri_with_params, resolve_digest, resolve_mgf, OaepParams};
    use bergshamra_core::algorithm;
    use kryptering::algorithm::HashAlgorithm;

    #[test]
    fn resolve_digest_defaults_only_when_absent() {
        assert_eq!(resolve_digest(None).unwrap(), HashAlgorithm::Sha1);
        assert!(resolve_digest(Some("urn:test:unsupported-digest")).is_err());
    }

    #[cfg(feature = "legacy-algorithms")]
    #[test]
    fn resolve_digest_rejects_substring_match_uris() {
        assert!(resolve_digest(Some("urn:test:ripemd160")).is_err());
        assert!(resolve_digest(Some("urn:test:md5")).is_err());
    }

    #[test]
    fn resolve_mgf_rejects_unknown_uri() {
        assert_eq!(
            resolve_mgf(Some(algorithm::MGF1_SHA256)).unwrap(),
            HashAlgorithm::Sha256
        );
        assert!(resolve_mgf(Some("urn:test:unsupported-mgf")).is_err());
    }

    #[test]
    fn from_uri_with_params_rejects_unknown_oaep_mgf() {
        let params = OaepParams {
            digest_uri: Some(algorithm::SHA256.to_owned()),
            mgf_uri: Some("urn:test:unsupported-mgf".to_owned()),
            oaep_params: None,
        };

        assert!(from_uri_with_params(algorithm::RSA_OAEP_ENC11, params).is_err());
    }

    #[test]
    fn rsa_oaep_sha256_round_trip_uses_selected_provider() {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let mut rng = getrandom::SysRng;
        let private = rsa::PrivateKey::new(&mut rng, 2048).unwrap();
        let public = rsa::PublicKey::from(&private);
        let private_der = private.to_pkcs8_der().unwrap();
        let public_der = public.to_public_key_der().unwrap();
        let private = kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Rsa,
            private_der.as_bytes(),
        )
        .unwrap();
        let public = kryptering::SoftwareKey::from_spki_der(
            kryptering::KeyAlgorithm::Rsa,
            public_der.as_bytes(),
        )
        .unwrap();
        let transport = from_uri_with_params(
            algorithm::RSA_OAEP_ENC11,
            OaepParams {
                digest_uri: Some(algorithm::SHA256.to_owned()),
                mgf_uri: Some(algorithm::MGF1_SHA256.to_owned()),
                oaep_params: Some(b"bergshamra-provider-test".to_vec()),
            },
        )
        .unwrap();
        let plaintext = b"document content-encryption key";

        let encrypted = transport.encrypt(&public, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(transport.decrypt(&private, &encrypted).unwrap(), plaintext);
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn rsa_oaep_enc11_omitted_mgf_uses_sha1_with_sha256_digest() {
        use kryptering::algorithm::{KeyTransportAlgorithm, OaepConfig};
        use rsa::pkcs8::EncodePrivateKey;

        let private = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        let private_der = private.to_pkcs8_der().unwrap();
        let key = kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Rsa,
            private_der.as_bytes(),
        )
        .unwrap();
        let plaintext = b"document content-encryption key";
        let expected_algorithm = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha1,
        });
        let encrypted =
            kryptering::keytransport::kt_encrypt(expected_algorithm, &key, plaintext, None)
                .expect("provider should encrypt with SHA-256 and MGF1-SHA1");

        let transport = from_uri_with_params(
            algorithm::RSA_OAEP_ENC11,
            OaepParams {
                digest_uri: Some(algorithm::SHA256.to_owned()),
                ..OaepParams::default()
            },
        )
        .unwrap();
        let decrypted = transport
            .decrypt(&key, &encrypted)
            .expect("omitted MGF should decrypt with MGF1-SHA1");
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "legacy-algorithms")]
    #[test]
    fn rsa_pkcs1_round_trip_uses_selected_provider() {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let mut rng = getrandom::SysRng;
        let private = rsa::PrivateKey::new(&mut rng, 2048).unwrap();
        let public = rsa::PublicKey::from(&private);
        let private_der = private.to_pkcs8_der().unwrap();
        let public_der = public.to_public_key_der().unwrap();
        let private = kryptering::SoftwareKey::from_pkcs8_der(
            kryptering::KeyAlgorithm::Rsa,
            private_der.as_bytes(),
        )
        .unwrap();
        let public = kryptering::SoftwareKey::from_spki_der(
            kryptering::KeyAlgorithm::Rsa,
            public_der.as_bytes(),
        )
        .unwrap();
        let transport = from_uri_with_params(algorithm::RSA_PKCS1, OaepParams::default()).unwrap();
        let plaintext = b"legacy document content-encryption key";

        let encrypted = transport.encrypt(&public, plaintext).unwrap();
        assert_eq!(transport.decrypt(&private, &encrypted).unwrap(), plaintext);
    }
}
