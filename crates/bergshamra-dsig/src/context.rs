#![forbid(unsafe_code)]

//! DSig context — holds keys and configuration for signature operations.

use bergshamra_keys::KeysManager;

/// Context for XML-DSig operations.
pub struct DsigContext {
    /// Keys manager for key lookup.
    pub keys_manager: KeysManager,
    /// Additional ID attribute names to register.
    pub id_attrs: Vec<String>,
}

impl DsigContext {
    /// Create a new DSig context with the given keys manager.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            id_attrs: Vec::new(),
        }
    }

    /// Add an ID attribute name to register during processing.
    pub fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }
}
