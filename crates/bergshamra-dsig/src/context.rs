#![forbid(unsafe_code)]

//! DSig context — holds keys and configuration for signature operations.

use bergshamra_core::Error;
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
    /// not a simple document-relative file. Signing and verification reject
    /// absolute paths, URI schemes, and parent-directory traversal for local
    /// fallback; verifier debug output redacts detached bytes.
    pub url_maps: Vec<(String, String)>,
    /// Minimum HMAC output length in bits (0 = use spec default).
    pub hmac_min_out_len: usize,
    /// Debug mode: print pre-digest and pre-signature data to stderr.
    pub debug: bool,
    /// Base directory for signing-time relative references, verifier
    /// document-relative references, and retrieval-method key resolution.
    ///
    /// This is not an unrestricted filesystem root: signing and verifier
    /// `<Reference>` resolution reject URI schemes, absolute paths, and `..`
    /// traversal for local-file fallback.
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
    /// Allow raw inline `<KeyValue>` / `<DEREncodedKeyValue>` even when trust
    /// anchors are configured.
    ///
    /// Keep this `false` for normal verification. It exists for xmlsec
    /// compatibility suites that intentionally combine trusted CA flags with
    /// raw inline test keys.
    pub allow_raw_inline_keyinfo_with_trust_anchors: bool,
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
            .field(
                "allow_raw_inline_keyinfo_with_trust_anchors",
                &self.allow_raw_inline_keyinfo_with_trust_anchors,
            )
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
            allow_raw_inline_keyinfo_with_trust_anchors: false,
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
    /// Resolution matches the URI exactly, or matches the same URI followed by
    /// a `#fragment` suffix.
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

    /// Set whether raw inline KeyInfo keys may satisfy verification when trust
    /// anchors are configured.
    ///
    /// This is a compatibility escape hatch for xmlsec interop suites. Leave it
    /// disabled for normal verification so a raw document-controlled `<KeyValue>`
    /// cannot bypass configured trust anchors.
    pub fn with_allow_raw_inline_keyinfo_with_trust_anchors(mut self, allow: bool) -> Self {
        self.allow_raw_inline_keyinfo_with_trust_anchors = allow;
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
    /// Signing and verifier `<Reference>` resolution try simple relative paths
    /// under this directory first, then the current working directory. URI
    /// schemes, absolute paths, and parent traversal are rejected for local-file
    /// fallback.
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

/// Return whether a configured URL map applies to a `<Reference URI>`.
///
/// URL maps are exact by default. The only non-exact match accepted here is a
/// fragment suffix on the same mapped resource, such as mapping
/// `https://example.test/doc.xml` for `https://example.test/doc.xml#payload`.
/// This avoids treating lookalike prefixes such as
/// `https://example.test.evil/...` as the mapped resource.
pub(crate) fn url_map_matches(uri: &str, map_url: &str) -> bool {
    uri == map_url
        || uri
            .strip_prefix(map_url)
            .is_some_and(|suffix| suffix.starts_with('#'))
}

/// Return whether `uri` begins with an RFC-style scheme name.
///
/// This keeps `urn:...` and `http:...` out of local-file fallback paths even
/// when they do not contain `://`.
pub(crate) fn uri_has_scheme(uri: &str) -> bool {
    let Some((scheme, _)) = uri.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Validate a `<Reference URI>` before considering local relative-file lookup.
///
/// Absolute paths, Windows path prefixes, root components, and parent traversal
/// are rejected before scheme detection. That ordering matters on Windows,
/// where drive-letter paths such as `C:\secret.txt` can otherwise look like a
/// one-letter URI scheme.
pub(crate) fn local_reference_relative_path(uri: &str) -> Result<Option<&std::path::Path>, Error> {
    let path = std::path::Path::new(uri);
    if path.is_absolute() {
        return Err(Error::InvalidUri(format!(
            "absolute local file Reference URI not allowed: {uri}"
        )));
    }

    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                return Err(Error::InvalidUri(format!(
                    "absolute local file Reference URI not allowed: {uri}"
                )));
            }
            std::path::Component::ParentDir => {
                return Err(Error::InvalidUri(format!(
                    "parent-directory Reference URI not allowed: {uri}"
                )));
            }
            _ => {}
        }
    }

    if uri_has_scheme(uri) {
        return Ok(None);
    }

    Ok(Some(path))
}

/// Read `relative_path` under `base` only when canonical resolution stays below
/// that same canonical base directory.
///
/// This prevents local `<Reference URI>` resolution from following a symlink
/// inside the lookup directory to an arbitrary local file.
pub(crate) fn read_existing_relative_file(
    base: &std::path::Path,
    relative_path: &std::path::Path,
    uri: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let full = base.join(relative_path);
    if !full.exists() {
        return Ok(None);
    }

    let canonical_base = base
        .canonicalize()
        .map_err(|e| Error::Other(format!("{}: {e}", base.display())))?;
    let canonical_full = full
        .canonicalize()
        .map_err(|e| Error::Other(format!("{}: {e}", full.display())))?;
    if !canonical_full.starts_with(&canonical_base) {
        return Err(Error::InvalidUri(format!(
            "local file Reference URI escapes base directory: {uri}"
        )));
    }

    let data = std::fs::read(&canonical_full)
        .map_err(|e| Error::Other(format!("{}: {e}", canonical_full.display())))?;
    Ok(Some(data))
}
