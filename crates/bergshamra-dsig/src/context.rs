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
    /// Insecure mode: skip all certificate validation.
    pub insecure: bool,
    /// Verify keys: validate certificates for keys loaded from files.
    pub verify_keys: bool,
    /// Override verification time (format: "YYYY-MM-DD+HH:MM:SS").
    pub verification_time: Option<String>,
    /// Skip X.509 time checks (NotBefore/NotAfter).
    pub skip_time_checks: bool,
    /// Whether --enabled-key-data includes x509.
    pub enabled_key_data_x509: bool,
    /// When true, only use keys from the KeysManager for verification.
    /// Skip extraction of inline keys from KeyInfo (KeyValue, X509Certificate, etc.).
    /// This is the secure mode for SAML: only trust pre-configured IdP keys,
    /// not whatever an attacker embeds in the XML signature's KeyInfo.
    pub trusted_keys_only: bool,
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
            insecure: false,
            verify_keys: false,
            verification_time: None,
            skip_time_checks: false,
            enabled_key_data_x509: false,
            trusted_keys_only: false,
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
