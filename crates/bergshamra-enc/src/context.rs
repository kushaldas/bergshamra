#![forbid(unsafe_code)]

//! Encryption context — holds keys and configuration.

use bergshamra_keys::KeysManager;

/// Context for XML-Enc operations.
pub struct EncContext {
    /// Keys manager for key lookup.
    pub keys_manager: KeysManager,
    /// Additional ID attribute names.
    pub id_attrs: Vec<String>,
    /// Whether CipherReference resolution is disabled.
    pub disable_cipher_reference: bool,
}

impl EncContext {
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            id_attrs: Vec::new(),
            disable_cipher_reference: false,
        }
    }

    pub fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }
}
