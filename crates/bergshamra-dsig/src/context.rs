#![forbid(unsafe_code)]

//! DSig context — holds keys and configuration for signature operations.

use bergshamra_keys::KeysManager;

/// Context for XML-DSig operations.
#[derive(Debug)]
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
    /// When true, enforce that each reference target is either the document element,
    /// an ancestor of the Signature, or a sibling of the Signature. This prevents
    /// XML Signature Wrapping (XSW) attacks where signed content is moved to an
    /// unexpected position in the document.
    pub strict_verification: bool,
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
            strict_verification: false,
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

    /// Set debug mode (builder style).
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Set insecure mode (builder style).
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Set verify keys (builder style).
    pub fn with_verify_keys(mut self, verify_keys: bool) -> Self {
        self.verify_keys = verify_keys;
        self
    }

    /// Set verification time override (builder style).
    pub fn with_verification_time(mut self, time: impl Into<String>) -> Self {
        self.verification_time = Some(time.into());
        self
    }

    /// Set skip time checks (builder style).
    pub fn with_skip_time_checks(mut self, skip: bool) -> Self {
        self.skip_time_checks = skip;
        self
    }

    /// Set enabled key data x509 (builder style).
    pub fn with_enabled_key_data_x509(mut self, enabled: bool) -> Self {
        self.enabled_key_data_x509 = enabled;
        self
    }

    /// Set trusted keys only (builder style).
    pub fn with_trusted_keys_only(mut self, trusted: bool) -> Self {
        self.trusted_keys_only = trusted;
        self
    }

    /// Set strict verification (builder style).
    pub fn with_strict_verification(mut self, strict: bool) -> Self {
        self.strict_verification = strict;
        self
    }

    /// Set minimum HMAC output length in bits (builder style).
    pub fn with_hmac_min_out_len(mut self, bits: usize) -> Self {
        self.hmac_min_out_len = bits;
        self
    }

    /// Set base directory for resolving relative URIs (builder style).
    pub fn with_base_dir(mut self, dir: impl Into<String>) -> Self {
        self.base_dir = Some(dir.into());
        self
    }
}
