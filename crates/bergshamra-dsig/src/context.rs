#![forbid(unsafe_code)]

//! DSig context — holds keys and configuration for signature operations.

use bergshamra_keys::KeysManager;

/// Context for XML-DSig operations.
pub struct DsigContext {
    /// Keys manager for key lookup.
    pub keys_manager: KeysManager,
    /// Additional ID attribute names to register.
    pub id_attrs: Vec<String>,
    /// URL-to-file mappings for external URI resolution.
    pub url_maps: Vec<(String, String)>,
    /// Minimum HMAC output length in bits (0 = use spec default).
    pub hmac_min_out_len: usize,
    /// Debug mode: print pre-digest and pre-signature data to stderr.
    pub debug: bool,
    /// Base directory for resolving relative external URI references.
    pub base_dir: Option<String>,
}

impl DsigContext {
    /// Create a new DSig context with the given keys manager.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            id_attrs: Vec::new(),
            url_maps: Vec::new(),
            hmac_min_out_len: 0,
            debug: false,
            base_dir: None,
        }
    }

    /// Add an ID attribute name to register during processing.
    pub fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }

    /// Map an external URI to a local file path.
    pub fn add_url_map(&mut self, url: &str, file_path: &str) {
        self.url_maps.push((url.to_owned(), file_path.to_owned()));
    }
}
