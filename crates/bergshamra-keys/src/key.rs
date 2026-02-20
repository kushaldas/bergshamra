#![forbid(unsafe_code)]

//! Key types and data structures.

/// Usage flags for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Any,
}

/// The underlying key data.
pub enum KeyData {
    Rsa {
        private: Option<rsa::RsaPrivateKey>,
        public: rsa::RsaPublicKey,
    },
    EcP256 {
        private: Option<p256::ecdsa::SigningKey>,
        public: p256::ecdsa::VerifyingKey,
    },
    EcP384 {
        private: Option<p384::ecdsa::SigningKey>,
        public: p384::ecdsa::VerifyingKey,
    },
    Hmac(Vec<u8>),
    Aes(Vec<u8>),
    Des3(Vec<u8>),
}

impl std::fmt::Debug for KeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa { private, .. } => {
                if private.is_some() {
                    write!(f, "RSA private+public key")
                } else {
                    write!(f, "RSA public key")
                }
            }
            Self::EcP256 { private, .. } => {
                if private.is_some() {
                    write!(f, "EC P-256 private+public key")
                } else {
                    write!(f, "EC P-256 public key")
                }
            }
            Self::EcP384 { private, .. } => {
                if private.is_some() {
                    write!(f, "EC P-384 private+public key")
                } else {
                    write!(f, "EC P-384 public key")
                }
            }
            Self::Hmac(k) => write!(f, "HMAC key ({} bytes)", k.len()),
            Self::Aes(k) => write!(f, "AES key ({} bytes)", k.len()),
            Self::Des3(_) => write!(f, "3DES key"),
        }
    }
}

/// A named key with associated data.
#[derive(Debug)]
pub struct Key {
    /// Optional name for key lookup.
    pub name: Option<String>,
    /// The key data.
    pub data: KeyData,
    /// The intended usage.
    pub usage: KeyUsage,
    /// Optional X.509 certificate chain (DER-encoded).
    pub x509_chain: Vec<Vec<u8>>,
}

impl Key {
    /// Create a new key.
    pub fn new(data: KeyData, usage: KeyUsage) -> Self {
        Self {
            name: None,
            data,
            usage,
            x509_chain: Vec::new(),
        }
    }

    /// Set the key name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Convert to a `SigningKey` for use with crypto algorithms.
    pub fn to_signing_key(&self) -> Option<bergshamra_crypto::sign::SigningKey> {
        match &self.data {
            KeyData::Rsa { private: Some(pk), .. } => {
                Some(bergshamra_crypto::sign::SigningKey::Rsa(pk.clone()))
            }
            KeyData::Rsa { public, .. } => {
                Some(bergshamra_crypto::sign::SigningKey::RsaPublic(public.clone()))
            }
            KeyData::EcP256 { private: Some(sk), .. } => {
                Some(bergshamra_crypto::sign::SigningKey::EcP256(sk.clone()))
            }
            KeyData::EcP256 { public, .. } => {
                Some(bergshamra_crypto::sign::SigningKey::EcP256Public(*public))
            }
            KeyData::EcP384 { private: Some(sk), .. } => {
                Some(bergshamra_crypto::sign::SigningKey::EcP384(sk.clone()))
            }
            KeyData::EcP384 { public, .. } => {
                Some(bergshamra_crypto::sign::SigningKey::EcP384Public(*public))
            }
            KeyData::Hmac(k) => Some(bergshamra_crypto::sign::SigningKey::Hmac(k.clone())),
            _ => None,
        }
    }

    /// Get the raw symmetric key bytes (for AES, 3DES, HMAC).
    pub fn symmetric_key_bytes(&self) -> Option<&[u8]> {
        match &self.data {
            KeyData::Hmac(k) | KeyData::Aes(k) | KeyData::Des3(k) => Some(k),
            _ => None,
        }
    }

    /// Get the RSA public key if available.
    pub fn rsa_public_key(&self) -> Option<&rsa::RsaPublicKey> {
        match &self.data {
            KeyData::Rsa { public, .. } => Some(public),
            _ => None,
        }
    }

    /// Get the RSA private key if available.
    pub fn rsa_private_key(&self) -> Option<&rsa::RsaPrivateKey> {
        match &self.data {
            KeyData::Rsa { private: Some(pk), .. } => Some(pk),
            _ => None,
        }
    }
}
