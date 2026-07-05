#![forbid(unsafe_code)]

//! Encryption context — holds keys and configuration.

use bergshamra_core::Error;
use bergshamra_keys::KeysManager;

/// Context for XML-Enc operations.
pub struct EncContext {
    /// Keys manager for key lookup.
    pub keys_manager: KeysManager,
    /// Additional ID attribute names.
    pub id_attrs: Vec<String>,
    /// Whether CipherReference resolution is disabled.
    pub disable_cipher_reference: bool,
    /// Optional HSM-backed decryptor for RSA key transport.
    /// When set, EncryptedKey elements are decrypted using this instead of software RSA keys.
    pub hsm_decryptor: Option<Box<dyn kryptering::Decryptor>>,
    /// Allowed EncryptionMethod Algorithm URIs for the HSM decryptor.
    /// Empty means "unbound" and fails closed at runtime.
    pub hsm_decryptor_algorithms: Vec<String>,
    /// Optional HSM-backed key unwrapper for AES-KW key unwrapping.
    pub hsm_key_unwrapper: Option<Box<dyn kryptering::KeyWrapper>>,
    /// Allowed EncryptionMethod Algorithm URIs for the HSM key unwrapper.
    /// Empty means "unbound" and fails closed at runtime.
    pub hsm_key_unwrapper_algorithms: Vec<String>,
    /// Optional HSM-backed encryptor for RSA key transport encryption.
    pub hsm_encryptor: Option<Box<dyn kryptering::Encryptor>>,
    /// Allowed EncryptionMethod Algorithm URIs for the HSM encryptor.
    /// Empty means "unbound" and fails closed at runtime.
    pub hsm_encryptor_algorithms: Vec<String>,
    /// Optional HSM-backed key wrapper for AES-KW key wrapping.
    pub hsm_key_wrapper: Option<Box<dyn kryptering::KeyWrapper>>,
    /// Allowed EncryptionMethod Algorithm URIs for the HSM key wrapper.
    /// Empty means "unbound" and fails closed at runtime.
    pub hsm_key_wrapper_algorithms: Vec<String>,
}

impl std::fmt::Debug for EncContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format `keys_manager` directly: `KeysManager`/`Key` derive
        // `Debug`, which would print private RSA/EC key material and raw
        // HMAC/AES bytes into logs and crash reports. Redact to a key count.
        f.debug_struct("EncContext")
            .field(
                "keys_manager",
                &format_args!("<{} key(s), redacted>", self.keys_manager.len()),
            )
            .field("id_attrs", &self.id_attrs)
            .field("disable_cipher_reference", &self.disable_cipher_reference)
            .field(
                "hsm_decryptor",
                &self.hsm_decryptor.as_ref().map(|_| "<hsm_decryptor>"),
            )
            .field("hsm_decryptor_algorithms", &self.hsm_decryptor_algorithms)
            .field(
                "hsm_key_unwrapper",
                &self
                    .hsm_key_unwrapper
                    .as_ref()
                    .map(|_| "<hsm_key_unwrapper>"),
            )
            .field(
                "hsm_key_unwrapper_algorithms",
                &self.hsm_key_unwrapper_algorithms,
            )
            .field(
                "hsm_encryptor",
                &self.hsm_encryptor.as_ref().map(|_| "<hsm_encryptor>"),
            )
            .field("hsm_encryptor_algorithms", &self.hsm_encryptor_algorithms)
            .field(
                "hsm_key_wrapper",
                &self.hsm_key_wrapper.as_ref().map(|_| "<hsm_key_wrapper>"),
            )
            .field(
                "hsm_key_wrapper_algorithms",
                &self.hsm_key_wrapper_algorithms,
            )
            .finish()
    }
}

impl EncContext {
    /// Create an XML Encryption context using the provided key manager.
    ///
    /// The context starts with no extra ID attributes, CipherReference support
    /// enabled, and no HSM delegates configured. Use the builder methods to
    /// bind HSM operations to explicit XML Encryption algorithm URIs.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            id_attrs: Vec::new(),
            disable_cipher_reference: false,
            hsm_decryptor: None,
            hsm_decryptor_algorithms: Vec::new(),
            hsm_key_unwrapper: None,
            hsm_key_unwrapper_algorithms: Vec::new(),
            hsm_encryptor: None,
            hsm_encryptor_algorithms: Vec::new(),
            hsm_key_wrapper: None,
            hsm_key_wrapper_algorithms: Vec::new(),
        }
    }

    /// Register an additional ID attribute name for XML Encryption processing.
    ///
    /// This is useful for protocol-specific ID attributes such as `wsu:Id`.
    /// Registered names are considered when resolving same-document references.
    pub fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }

    /// Set disable cipher reference (builder style).
    pub fn with_disable_cipher_reference(mut self, disable: bool) -> Self {
        self.disable_cipher_reference = disable;
        self
    }

    /// Set an HSM-backed decryptor for RSA key transport (builder style).
    ///
    /// When set, RSA key transport decryption (unwrapping session keys)
    /// bypasses the `KeysManager` and delegates to the provided
    /// [`kryptering::Decryptor`] implementation. Key material never leaves the HSM.
    ///
    /// `allowed_algorithms` must list the XML `EncryptionMethod` Algorithm URI(s)
    /// this decryptor is allowed to service (for example
    /// `rsa-1_5`, `rsa-oaep-mgf1p`, or `rsa-oaep`). Bergshamra checks that the
    /// document's declared algorithm is in this allow-list before delegating to
    /// the HSM, so a misconfigured decryptor fails closed.
    pub fn with_hsm_decryptor(
        mut self,
        decryptor: Box<dyn kryptering::Decryptor>,
        allowed_algorithms: &[&str],
    ) -> Self {
        self.hsm_decryptor = Some(decryptor);
        self.hsm_decryptor_algorithms = copy_algorithm_uris(allowed_algorithms);
        self
    }

    /// Set an HSM-backed key unwrapper for AES-KW key unwrapping (builder style).
    ///
    /// When set, AES key unwrap operations bypass the `KeysManager` and
    /// delegate to the provided [`kryptering::KeyWrapper`] implementation.
    ///
    /// `allowed_algorithms` must list the XML `EncryptionMethod` Algorithm URI(s)
    /// this unwrapper is allowed to service (for example `kw-aes128`).
    pub fn with_hsm_key_unwrapper(
        mut self,
        unwrapper: Box<dyn kryptering::KeyWrapper>,
        allowed_algorithms: &[&str],
    ) -> Self {
        self.hsm_key_unwrapper = Some(unwrapper);
        self.hsm_key_unwrapper_algorithms = copy_algorithm_uris(allowed_algorithms);
        self
    }

    /// Set an HSM-backed encryptor for RSA key transport encryption (builder style).
    ///
    /// When set, RSA key transport encryption (wrapping session keys)
    /// bypasses the `KeysManager` and delegates to the provided
    /// [`kryptering::Encryptor`] implementation.
    ///
    /// `allowed_algorithms` must list the XML `EncryptionMethod` Algorithm URI(s)
    /// this encryptor is allowed to service. Bergshamra checks the template's
    /// declared algorithm against this allow-list before delegating to the HSM.
    pub fn with_hsm_encryptor(
        mut self,
        encryptor: Box<dyn kryptering::Encryptor>,
        allowed_algorithms: &[&str],
    ) -> Self {
        self.hsm_encryptor = Some(encryptor);
        self.hsm_encryptor_algorithms = copy_algorithm_uris(allowed_algorithms);
        self
    }

    /// Set an HSM-backed key wrapper for AES-KW key wrapping (builder style).
    ///
    /// When set, AES key wrap operations bypass the `KeysManager` and
    /// delegate to the provided [`kryptering::KeyWrapper`] implementation.
    ///
    /// `allowed_algorithms` must list the XML `EncryptionMethod` Algorithm URI(s)
    /// this wrapper is allowed to service.
    pub fn with_hsm_key_wrapper(
        mut self,
        wrapper: Box<dyn kryptering::KeyWrapper>,
        allowed_algorithms: &[&str],
    ) -> Self {
        self.hsm_key_wrapper = Some(wrapper);
        self.hsm_key_wrapper_algorithms = copy_algorithm_uris(allowed_algorithms);
        self
    }

    pub(crate) fn ensure_hsm_decryptor_matches(&self, enc_uri: &str) -> Result<(), Error> {
        ensure_hsm_binding(
            self.hsm_decryptor.is_some(),
            &self.hsm_decryptor_algorithms,
            enc_uri,
            "HSM decryptor",
        )
    }

    pub(crate) fn ensure_hsm_key_unwrapper_matches(&self, enc_uri: &str) -> Result<(), Error> {
        ensure_hsm_binding(
            self.hsm_key_unwrapper.is_some(),
            &self.hsm_key_unwrapper_algorithms,
            enc_uri,
            "HSM key unwrapper",
        )
    }

    pub(crate) fn ensure_hsm_encryptor_matches(&self, enc_uri: &str) -> Result<(), Error> {
        ensure_hsm_binding(
            self.hsm_encryptor.is_some(),
            &self.hsm_encryptor_algorithms,
            enc_uri,
            "HSM encryptor",
        )
    }

    pub(crate) fn ensure_hsm_key_wrapper_matches(&self, enc_uri: &str) -> Result<(), Error> {
        ensure_hsm_binding(
            self.hsm_key_wrapper.is_some(),
            &self.hsm_key_wrapper_algorithms,
            enc_uri,
            "HSM key wrapper",
        )
    }
}

fn copy_algorithm_uris(algorithms: &[&str]) -> Vec<String> {
    algorithms.iter().map(|uri| (*uri).to_owned()).collect()
}

fn ensure_hsm_binding(
    is_configured: bool,
    allowed_algorithms: &[String],
    enc_uri: &str,
    binding_name: &str,
) -> Result<(), Error> {
    if !is_configured {
        return Ok(());
    }
    if allowed_algorithms.iter().any(|allowed| allowed == enc_uri) {
        return Ok(());
    }
    let allowed = if allowed_algorithms.is_empty() {
        "<none>".to_owned()
    } else {
        allowed_algorithms.join(", ")
    };
    Err(Error::UnsupportedAlgorithm(format!(
        "{binding_name} is not bound to EncryptionMethod {enc_uri} (allowed: {allowed})"
    )))
}

#[cfg(test)]
mod tests {
    use super::EncContext;
    use bergshamra_core::algorithm;
    use bergshamra_keys::KeysManager;

    struct DummyDecryptor;
    impl kryptering::Decryptor for DummyDecryptor {
        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, kryptering::Error> {
            Ok(ciphertext.to_vec())
        }
    }

    struct DummyEncryptor;
    impl kryptering::Encryptor for DummyEncryptor {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, kryptering::Error> {
            Ok(plaintext.to_vec())
        }
    }

    struct DummyWrapper;
    impl kryptering::KeyWrapper for DummyWrapper {
        fn wrap(&self, key_data: &[u8]) -> Result<Vec<u8>, kryptering::Error> {
            Ok(key_data.to_vec())
        }

        fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, kryptering::Error> {
            Ok(wrapped.to_vec())
        }
    }

    #[test]
    fn hsm_decryptor_rejects_unbound_algorithm() {
        let ctx = EncContext::new(KeysManager::new())
            .with_hsm_decryptor(Box::new(DummyDecryptor), &[algorithm::RSA_OAEP]);

        assert!(ctx
            .ensure_hsm_decryptor_matches(algorithm::RSA_OAEP)
            .is_ok());
        assert!(ctx
            .ensure_hsm_decryptor_matches(algorithm::RSA_PKCS1)
            .is_err());
    }

    #[test]
    fn hsm_encryptor_rejects_unbound_algorithm() {
        let ctx = EncContext::new(KeysManager::new())
            .with_hsm_encryptor(Box::new(DummyEncryptor), &[algorithm::RSA_PKCS1]);

        assert!(ctx
            .ensure_hsm_encryptor_matches(algorithm::RSA_PKCS1)
            .is_ok());
        assert!(ctx
            .ensure_hsm_encryptor_matches(algorithm::RSA_OAEP_ENC11)
            .is_err());
    }

    #[test]
    fn hsm_key_wrapper_rejects_unbound_algorithm() {
        let ctx = EncContext::new(KeysManager::new())
            .with_hsm_key_wrapper(Box::new(DummyWrapper), &[algorithm::KW_AES256]);

        assert!(ctx
            .ensure_hsm_key_wrapper_matches(algorithm::KW_AES256)
            .is_ok());
        assert!(ctx
            .ensure_hsm_key_wrapper_matches(algorithm::KW_AES128)
            .is_err());
    }

    #[test]
    fn hsm_key_unwrapper_rejects_unbound_algorithm() {
        let ctx = EncContext::new(KeysManager::new())
            .with_hsm_key_unwrapper(Box::new(DummyWrapper), &[algorithm::KW_AES192]);

        assert!(ctx
            .ensure_hsm_key_unwrapper_matches(algorithm::KW_AES192)
            .is_ok());
        assert!(ctx
            .ensure_hsm_key_unwrapper_matches(algorithm::KW_AES256)
            .is_err());
    }
}
