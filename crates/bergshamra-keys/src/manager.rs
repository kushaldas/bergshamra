#![forbid(unsafe_code)]

//! Key manager with named key store.

use crate::key::{Key, KeyUsage};
use bergshamra_core::Error;

/// Manages a collection of keys for lookup during signature/encryption processing.
pub struct KeysManager {
    keys: Vec<Key>,
    /// Trusted CA certificates (DER-encoded).
    trusted_certs: Vec<Vec<u8>>,
    /// Untrusted intermediate certificates (DER-encoded).
    untrusted_certs: Vec<Vec<u8>>,
    /// Certificate Revocation Lists (DER-encoded).
    crls: Vec<Vec<u8>>,
}

impl KeysManager {
    /// Create an empty keys manager.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            trusted_certs: Vec::new(),
            untrusted_certs: Vec::new(),
            crls: Vec::new(),
        }
    }

    /// Add a key to the manager.
    pub fn add_key(&mut self, key: Key) {
        self.keys.push(key);
    }

    /// Insert a key at the front of the manager (takes priority for first_key).
    pub fn insert_key_first(&mut self, key: Key) {
        self.keys.insert(0, key);
    }

    /// Find a key by name.
    pub fn find_by_name(&self, name: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.name.as_deref() == Some(name))
    }

    /// Find the first key matching the given usage.
    pub fn find_by_usage(&self, usage: KeyUsage) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| k.usage == usage || k.usage == KeyUsage::Any)
    }

    /// Find the first key that has an RSA public key.
    pub fn find_rsa(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::Rsa { .. }))
    }

    /// Find the first key that has an EC P-256 key.
    pub fn find_ec_p256(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::EcP256 { .. }))
    }

    /// Find the first key that has an EC P-384 key.
    pub fn find_ec_p384(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::EcP384 { .. }))
    }

    /// Find the first key that has an EC P-521 key.
    pub fn find_ec_p521(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::EcP521 { .. }))
    }

    /// Find the first HMAC key.
    pub fn find_hmac(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::Hmac(_)))
    }

    /// Find the first AES key.
    pub fn find_aes(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::Aes(_)))
    }

    /// Find an AES key with the specified byte length.
    pub fn find_aes_by_size(&self, size_bytes: usize) -> Option<&Key> {
        self.keys.iter().find(|k| {
            if let crate::key::KeyData::Aes(ref bytes) = k.data {
                bytes.len() == size_bytes
            } else {
                false
            }
        })
    }

    /// Find the first 3DES key.
    pub fn find_des3(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::Des3(_)))
    }

    /// Find the first post-quantum key.
    pub fn find_pq(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::PostQuantum { .. }))
    }

    /// Find the first DH key.
    pub fn find_dh(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::Dh { .. }))
    }

    /// Find the first Ed25519 key.
    pub fn find_ed25519(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::Ed25519 { .. }))
    }

    /// Find the first X25519 key.
    pub fn find_x25519(&self) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| matches!(&k.data, crate::key::KeyData::X25519 { .. }))
    }

    /// Find an RSA key with a private key component.
    pub fn find_rsa_private(&self) -> Option<&Key> {
        self.keys.iter().find(|k| {
            matches!(
                &k.data,
                crate::key::KeyData::Rsa {
                    private: Some(_),
                    ..
                }
            )
        })
    }

    /// Iterator over all keys.
    pub fn keys(&self) -> impl Iterator<Item = &Key> {
        self.keys.iter()
    }

    /// Get the first key available (for simple single-key scenarios).
    pub fn first_key(&self) -> Result<&Key, Error> {
        self.keys
            .first()
            .ok_or_else(|| Error::KeyNotFound("no keys in manager".into()))
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Add a trusted CA certificate (DER-encoded).
    pub fn add_trusted_cert(&mut self, der: Vec<u8>) {
        self.trusted_certs.push(der);
    }

    /// Add an untrusted intermediate certificate (DER-encoded).
    pub fn add_untrusted_cert(&mut self, der: Vec<u8>) {
        self.untrusted_certs.push(der);
    }

    /// Add a CRL (DER-encoded).
    pub fn add_crl(&mut self, der: Vec<u8>) {
        self.crls.push(der);
    }

    /// Get the trusted CA certificates.
    pub fn trusted_certs(&self) -> &[Vec<u8>] {
        &self.trusted_certs
    }

    /// Get the untrusted intermediate certificates.
    pub fn untrusted_certs(&self) -> &[Vec<u8>] {
        &self.untrusted_certs
    }

    /// Get the CRLs.
    pub fn crls(&self) -> &[Vec<u8>] {
        &self.crls
    }

    /// Check if any trusted certificates are loaded.
    pub fn has_trusted_certs(&self) -> bool {
        !self.trusted_certs.is_empty()
    }
}

impl Default for KeysManager {
    fn default() -> Self {
        Self::new()
    }
}
