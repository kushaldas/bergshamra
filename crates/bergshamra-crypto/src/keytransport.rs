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

/// Create a key transport algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn KeyTransportAlgorithm>, Error> {
    match uri {
        algorithm::RSA_PKCS1 => Ok(Box::new(RsaPkcs1Transport)),
        algorithm::RSA_OAEP => Ok(Box::new(RsaOaepTransport {
            uri: algorithm::RSA_OAEP,
        })),
        algorithm::RSA_OAEP_ENC11 => Ok(Box::new(RsaOaepTransport {
            uri: algorithm::RSA_OAEP_ENC11,
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
}

impl KeyTransportAlgorithm for RsaOaepTransport {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn encrypt(&self, public_key: &rsa::RsaPublicKey, key_data: &[u8]) -> Result<Vec<u8>, Error> {
        use rsa::Oaep;
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<sha1::Sha1>();
        public_key
            .encrypt(&mut rng, padding, key_data)
            .map_err(|e| Error::Crypto(format!("RSA-OAEP encrypt: {e}")))
    }

    fn decrypt(
        &self,
        private_key: &rsa::RsaPrivateKey,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use rsa::Oaep;
        let padding = Oaep::new::<sha1::Sha1>();
        private_key
            .decrypt(padding, encrypted)
            .map_err(|e| Error::Crypto(format!("RSA-OAEP decrypt: {e}")))
    }
}
