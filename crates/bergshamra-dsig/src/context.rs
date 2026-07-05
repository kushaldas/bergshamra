#![forbid(unsafe_code)]

//! DSig context — holds keys and configuration for signature operations.

use bergshamra_keys::KeysManager;
use kryptering::traits::{Signer, Verifier};

/// Context for XML-DSig operations.
pub struct DsigContext {
    /// Keys manager for key lookup.
    pub keys_manager: KeysManager,
    /// Additional ID attribute names to register.
    pub id_attrs: Vec<String>,
    /// Explicit URL-to-file mappings for external URI resolution.
    ///
    /// Prefer these mappings for detached `<Reference>` bytes when the URI is
    /// not a simple document-relative file. Verification rejects absolute paths
    /// and parent-directory traversal, and redacts detached bytes from raw
    /// debug output.
    pub url_maps: Vec<(String, String)>,
    /// Minimum HMAC output length in bits (0 = use spec default).
    pub hmac_min_out_len: usize,
    /// Debug mode: print pre-digest and pre-signature data to stderr.
    pub debug: bool,
    /// Base directory for signing-time relative references, verifier
    /// document-relative references, and retrieval-method key resolution.
    ///
    /// This is not an unrestricted filesystem root: verifier `<Reference>`
    /// resolution rejects absolute paths and `..` traversal.
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
    /// When true, a valid `SignatureValue` is still reported invalid unless at
    /// least one `Reference` digest was computed locally and every reference
    /// digest was locally verified.
    ///
    /// Disable this only for detached-content profiles, such as WS-Security
    /// `cid:` attachments, after the caller verifies those external bytes
    /// out-of-band.
    pub require_reference_digests: bool,
    /// Optional HSM-backed signer. When set, bypasses KeysManager for signing.
    pub hsm_signer: Option<Box<dyn Signer>>,
    /// Optional HSM-backed verifier. When set, bypasses KeysManager for verification.
    pub hsm_verifier: Option<Box<dyn Verifier>>,
}

impl std::fmt::Debug for DsigContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format `keys_manager` directly: `KeysManager`/`Key` derive
        // `Debug`, which would print private RSA/EC key material and raw
        // HMAC/AES bytes into logs and crash reports. Redact to a key count.
        f.debug_struct("DsigContext")
            .field(
                "keys_manager",
                &format_args!("<{} key(s), redacted>", self.keys_manager.len()),
            )
            .field("id_attrs", &self.id_attrs)
            .field("url_maps", &self.url_maps)
            .field("hmac_min_out_len", &self.hmac_min_out_len)
            .field("debug", &self.debug)
            .field("base_dir", &self.base_dir)
            .field("insecure", &self.insecure)
            .field("verify_keys", &self.verify_keys)
            .field("verification_time", &self.verification_time)
            .field("skip_time_checks", &self.skip_time_checks)
            .field("enabled_key_data_x509", &self.enabled_key_data_x509)
            .field("trusted_keys_only", &self.trusted_keys_only)
            .field("strict_verification", &self.strict_verification)
            .field("require_reference_digests", &self.require_reference_digests)
            .field(
                "hsm_signer",
                &self.hsm_signer.as_ref().map(|_| "<hsm_signer>"),
            )
            .field(
                "hsm_verifier",
                &self.hsm_verifier.as_ref().map(|_| "<hsm_verifier>"),
            )
            .finish()
    }
}

impl DsigContext {
    /// Create a new DSig context with secure defaults.
    ///
    /// The defaults are hardened for federated identity (SAML, WS-Security):
    /// - **`trusted_keys_only = true`** — reject inline keys from `<KeyInfo>` (KeyValue,
    ///   X509Certificate, etc.); only use pre-configured keys from the `KeysManager`.
    /// - **`strict_verification = true`** — reject references to nodes that are not
    ///   ancestors, siblings, or the document element relative to the `<Signature>`
    ///   (XSW protection).
    /// - **`hmac_min_out_len = 160`** — enforce minimum HMAC output length of 160 bits
    ///   to prevent truncation attacks (CVE-2009-0217).
    /// - **`require_reference_digests = true`** — require the signed
    ///   `<SignedInfo>` to contain at least one `<Reference>` and require every
    ///   `<Reference>` digest to be verified locally.
    ///
    /// Use [`new_permissive()`](Self::new_permissive) if you need inline-key and
    /// relaxed structural behavior for self-contained signatures.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            trusted_keys_only: true,
            strict_verification: true,
            hmac_min_out_len: 160,
            ..Self::new_permissive(keys_manager)
        }
    }

    /// Create a DSig context with permissive key and structure defaults.
    ///
    /// This accepts inline keys from `<KeyInfo>`, does not enforce reference positions,
    /// and does not enforce a minimum HMAC output length. It still requires local
    /// reference-digest coverage by default so a valid `SignatureValue` cannot be
    /// confused for payload integrity when no XML bytes were digested.
    ///
    /// Suitable for document signing with self-contained signatures, or when the
    /// caller overrides all security-relevant fields explicitly.
    ///
    /// **For SAML, WS-Security, or any protocol with pre-established key trust, use
    /// [`new()`](Self::new) instead.**
    pub fn new_permissive(keys_manager: KeysManager) -> Self {
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
            require_reference_digests: true,
            hsm_signer: None,
            hsm_verifier: None,
        }
    }

    /// Add an ID attribute name to register during processing.
    pub fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }

    /// Map an external URI to a local file path.
    ///
    /// Use this for detached `<Reference>` values that are external URIs or
    /// require a path outside the document-adjacent relative-file policy.
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

    /// Set whether verification requires local reference-digest coverage.
    ///
    /// Keep this enabled for ordinary XML signature verification. Set it to
    /// `false` only when the caller has a separate policy for validating
    /// detached content, such as `cid:` attachment bytes.
    pub fn with_require_reference_digests(mut self, require: bool) -> Self {
        self.require_reference_digests = require;
        self
    }

    /// Set minimum HMAC output length in bits (builder style).
    pub fn with_hmac_min_out_len(mut self, bits: usize) -> Self {
        self.hmac_min_out_len = bits;
        self
    }

    /// Set base directory for signing-time relative URIs, verifier
    /// document-relative URIs, and key retrieval.
    ///
    /// Verifier `<Reference>` resolution only accepts simple relative paths
    /// under this directory; absolute paths and parent traversal are rejected.
    pub fn with_base_dir(mut self, dir: impl Into<String>) -> Self {
        self.base_dir = Some(dir.into());
        self
    }

    /// Set an HSM-backed signer (builder style).
    ///
    /// When set, signing operations bypass the `KeysManager` and delegate
    /// to the provided [`kryptering::Signer`] implementation. Key material
    /// never leaves the HSM.
    pub fn with_hsm_signer(mut self, signer: Box<dyn kryptering::Signer>) -> Self {
        self.hsm_signer = Some(signer);
        self
    }

    /// Set an HSM-backed verifier (builder style).
    ///
    /// When set, signature verification bypasses the `KeysManager` and
    /// delegates to the provided [`kryptering::Verifier`] implementation.
    pub fn with_hsm_verifier(mut self, verifier: Box<dyn kryptering::Verifier>) -> Self {
        self.hsm_verifier = Some(verifier);
        self
    }
}
