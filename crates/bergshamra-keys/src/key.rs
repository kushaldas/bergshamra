#![forbid(unsafe_code)]

//! Key types and data structures.

use std::sync::{Arc, OnceLock};

/// Usage flags for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    /// Key may be used to create signatures.
    Sign,
    /// Key may be used to verify signatures.
    Verify,
    /// Key may be used for encryption or key wrapping.
    Encrypt,
    /// Key may be used for decryption or key unwrapping.
    Decrypt,
    /// Key may be used for any operation supported by its key type.
    Any,
}

/// Provider-independent parsed key material retained for XML serialization.
#[derive(Clone)]
pub(crate) enum KeyMaterial {
    /// RSA key pair or public key.
    Rsa {
        /// Private RSA key, present when signing or decryption is supported.
        private: Option<rsa::RsaPrivateKey>,
        /// Public RSA key.
        public: rsa::RsaPublicKey,
    },
    /// ECDSA P-256 key pair or public key.
    EcP256 {
        /// Private ECDSA signing key, present when signing is supported.
        private: Option<p256::ecdsa::SigningKey>,
        /// Public ECDSA verification key.
        public: p256::ecdsa::VerifyingKey,
    },
    /// ECDSA P-384 key pair or public key.
    EcP384 {
        /// Private ECDSA signing key, present when signing is supported.
        private: Option<p384::ecdsa::SigningKey>,
        /// Public ECDSA verification key.
        public: p384::ecdsa::VerifyingKey,
    },
    /// ECDSA P-521 key pair or public key.
    EcP521 {
        /// Private ECDSA signing key, present when signing is supported.
        private: Option<p521::ecdsa::SigningKey>,
        /// Public ECDSA verification key.
        public: p521::ecdsa::VerifyingKey,
    },
    /// DSA key pair or public key.
    Dsa {
        /// Private DSA signing key, present when signing is supported.
        private: Option<dsa::SigningKey>,
        /// Public DSA verification key.
        public: dsa::VerifyingKey,
    },
    /// Finite-field Diffie-Hellman (X9.42 DH) key.
    Dh {
        /// Prime modulus p (big-endian bytes).
        p: Vec<u8>,
        /// Generator g (big-endian bytes).
        g: Vec<u8>,
        /// Subgroup order q (big-endian bytes, optional).
        q: Option<Vec<u8>>,
        /// Private key x (big-endian bytes, optional).
        private_key: Option<Vec<u8>>,
        /// Public key y = g^x mod p (big-endian bytes).
        public_key: Vec<u8>,
    },
    /// Ed25519 (EdDSA over Curve25519) key.
    Ed25519 {
        /// Private Ed25519 signing key, present when signing is supported.
        private: Option<ed25519_dalek::SigningKey>,
        /// Public Ed25519 verification key.
        public: ed25519_dalek::VerifyingKey,
    },
    /// X25519 (ECDH over Curve25519) key for key agreement.
    X25519 {
        /// Private scalar bytes, present when deriving a shared secret.
        private: Option<[u8; 32]>,
        /// Public X25519 key bytes.
        public: [u8; 32],
    },
    /// HMAC shared secret bytes.
    Hmac(Vec<u8>),
    /// AES symmetric key bytes.
    Aes(Vec<u8>),
    /// Triple-DES symmetric key bytes.
    Des3(Vec<u8>),
    /// Post-quantum key (ML-DSA or SLH-DSA) stored as raw DER bytes.
    #[allow(dead_code)]
    PostQuantum {
        /// Post-quantum signature algorithm for the DER blobs.
        algorithm: bergshamra_crypto::sign::PqAlgorithm,
        /// Optional private key DER, present when signing is supported.
        private_der: Option<Vec<u8>>,
        /// Public key DER, always present for verification.
        public_der: Vec<u8>,
    },
    /// A key imported directly through Kryptering's neutral API.
    Opaque(kryptering::SoftwareKey),
}

impl std::fmt::Debug for KeyMaterial {
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
            Self::EcP521 { private, .. } => {
                if private.is_some() {
                    write!(f, "EC P-521 private+public key")
                } else {
                    write!(f, "EC P-521 public key")
                }
            }
            Self::Dsa { private, .. } => {
                if private.is_some() {
                    write!(f, "DSA private+public key")
                } else {
                    write!(f, "DSA public key")
                }
            }
            Self::Dh { private_key, p, .. } => {
                let bits = p.len() * 8;
                if private_key.is_some() {
                    write!(f, "DH-{bits} private+public key")
                } else {
                    write!(f, "DH-{bits} public key")
                }
            }
            Self::Ed25519 { private, .. } => {
                if private.is_some() {
                    write!(f, "Ed25519 private+public key")
                } else {
                    write!(f, "Ed25519 public key")
                }
            }
            Self::X25519 { private, .. } => {
                if private.is_some() {
                    write!(f, "X25519 private+public key")
                } else {
                    write!(f, "X25519 public key")
                }
            }
            Self::Hmac(k) => write!(f, "HMAC key ({} bytes)", k.len()),
            Self::Aes(k) => write!(f, "AES key ({} bytes)", k.len()),
            Self::Des3(_) => write!(f, "3DES key"),
            Self::PostQuantum {
                algorithm,
                private_der,
                ..
            } => {
                if private_der.is_some() {
                    write!(f, "{} private+public key", algorithm.name())
                } else {
                    write!(f, "{} public key", algorithm.name())
                }
            }
            Self::Opaque(key) => std::fmt::Debug::fmt(key, f),
        }
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        match self {
            Self::Dh {
                private_key: Some(private),
                ..
            } => private.zeroize(),
            Self::X25519 {
                private: Some(private),
                ..
            } => private.zeroize(),
            Self::Hmac(secret) | Self::Aes(secret) | Self::Des3(secret) => secret.zeroize(),
            Self::PostQuantum {
                private_der: Some(private),
                ..
            } => private.zeroize(),
            _ => {}
        }
    }
}

impl KeyMaterial {
    /// Return a short human-readable algorithm name.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Rsa { .. } => "RSA",
            Self::EcP256 { .. } => "EC-P256",
            Self::EcP384 { .. } => "EC-P384",
            Self::EcP521 { .. } => "EC-P521",
            Self::Dsa { .. } => "DSA",
            Self::Dh { .. } => "DH",
            Self::Ed25519 { .. } => "Ed25519",
            Self::X25519 { .. } => "X25519",
            Self::Hmac(_) => "HMAC",
            Self::Aes(_) => "AES",
            Self::Des3(_) => "3DES",
            Self::PostQuantum { algorithm, .. } => algorithm.name(),
            Self::Opaque(key) => key_algorithm_name(key.algorithm()),
        }
    }

    /// Encode the public key as SPKI DER bytes. Returns `None` for symmetric keys.
    pub fn to_spki_der(&self) -> Option<Vec<u8>> {
        use spki::EncodePublicKey;
        match self {
            Self::Rsa { public, .. } => public.to_public_key_der().ok().map(|d| d.to_vec()),
            Self::EcP256 { public, .. } => {
                let pk = p256::PublicKey::from(public);
                pk.to_public_key_der().ok().map(|d| d.to_vec())
            }
            Self::EcP384 { public, .. } => {
                let pk = p384::PublicKey::from(public);
                pk.to_public_key_der().ok().map(|d| d.to_vec())
            }
            Self::EcP521 { public, .. } => {
                let point = public.to_encoded_point(false);
                let pk = p521::PublicKey::from_sec1_bytes(point.as_bytes()).ok()?;
                pk.to_public_key_der().ok().map(|d| d.to_vec())
            }
            Self::PostQuantum { public_der, .. } => Some(public_der.clone()),
            Self::Ed25519 { public, .. } => {
                use ed25519_dalek::pkcs8::spki::EncodePublicKey;
                public.to_public_key_der().ok().map(|d| d.to_vec())
            }
            Self::Opaque(key) => key.public_component().ok(),
            _ => None,
        }
    }

    /// Serialize the public key as an XML fragment suitable for embedding
    /// inside a `<KeyValue>` element. Returns `None` for symmetric keys.
    pub fn to_key_value_xml(&self, dsig_prefix: &str) -> Option<String> {
        use base64::Engine;
        use bergshamra_core::ns;
        use uppsala::XmlWriter;

        let engine = base64::engine::general_purpose::STANDARD;

        // Helper: build a prefixed element name like "ds:Foo" or just "Foo".
        let pname = |local: &str| -> String {
            if dsig_prefix.is_empty() {
                local.to_string()
            } else {
                format!("{dsig_prefix}:{local}")
            }
        };

        match self {
            Self::Rsa { public, .. } => {
                use rsa::traits::PublicKeyParts;
                let modulus_b64 = engine.encode(public.n().to_bytes_be());
                let exponent_b64 = engine.encode(public.e().to_bytes_be());
                let mut w = XmlWriter::new();
                let tag = pname(ns::node::RSA_KEY_VALUE);
                let mod_tag = pname(ns::node::RSA_MODULUS);
                let exp_tag = pname(ns::node::RSA_EXPONENT);
                w.start_element(&tag, &[]);
                w.start_element(&mod_tag, &[]);
                w.text(&modulus_b64);
                w.end_element(&mod_tag);
                w.start_element(&exp_tag, &[]);
                w.text(&exponent_b64);
                w.end_element(&exp_tag);
                w.end_element(&tag);
                Some(w.into_string())
            }
            Self::EcP256 { public, .. } => {
                let point = public.to_encoded_point(false);
                let pub_b64 = engine.encode(point.as_bytes());
                Some(build_ec_key_value_xml(
                    &pub_b64,
                    "urn:oid:1.2.840.10045.3.1.7",
                ))
            }
            Self::EcP384 { public, .. } => {
                let point = public.to_encoded_point(false);
                let pub_b64 = engine.encode(point.as_bytes());
                Some(build_ec_key_value_xml(&pub_b64, "urn:oid:1.3.132.0.34"))
            }
            Self::EcP521 { public, .. } => {
                let point = public.to_encoded_point(false);
                let pub_b64 = engine.encode(point.as_bytes());
                Some(build_ec_key_value_xml(&pub_b64, "urn:oid:1.3.132.0.35"))
            }
            Self::Dsa { public, .. } => {
                let components = public.components();
                let p_b64 = engine.encode(components.p().to_bytes_be());
                let q_b64 = engine.encode(components.q().to_bytes_be());
                let g_b64 = engine.encode(components.g().to_bytes_be());
                let y_b64 = engine.encode(public.y().to_bytes_be());
                let mut w = XmlWriter::new();
                let tag = pname(ns::node::DSA_KEY_VALUE);
                let p_tag = pname(ns::node::DSA_P);
                let q_tag = pname(ns::node::DSA_Q);
                let g_tag = pname(ns::node::DSA_G);
                let y_tag = pname(ns::node::DSA_Y);
                w.start_element(&tag, &[]);
                w.start_element(&p_tag, &[]);
                w.text(&p_b64);
                w.end_element(&p_tag);
                w.start_element(&q_tag, &[]);
                w.text(&q_b64);
                w.end_element(&q_tag);
                w.start_element(&g_tag, &[]);
                w.text(&g_b64);
                w.end_element(&g_tag);
                w.start_element(&y_tag, &[]);
                w.text(&y_b64);
                w.end_element(&y_tag);
                w.end_element(&tag);
                Some(w.into_string())
            }
            Self::Dh {
                p,
                g,
                q,
                public_key,
                ..
            } => {
                let p_b64 = engine.encode(p);
                let g_b64 = engine.encode(g);
                let pub_b64 = engine.encode(public_key);
                let mut w = XmlWriter::new();
                w.start_element("xenc:DHKeyValue", &[("xmlns:xenc", ns::ENC)]);
                w.start_element("xenc:P", &[]);
                w.text(&p_b64);
                w.end_element("xenc:P");
                if let Some(q_bytes) = q {
                    let q_b64 = engine.encode(q_bytes);
                    w.start_element("xenc:Q", &[]);
                    w.text(&q_b64);
                    w.end_element("xenc:Q");
                }
                w.start_element("xenc:Generator", &[]);
                w.text(&g_b64);
                w.end_element("xenc:Generator");
                w.start_element("xenc:Public", &[]);
                w.text(&pub_b64);
                w.end_element("xenc:Public");
                w.end_element("xenc:DHKeyValue");
                Some(w.into_string())
            }
            Self::X25519 { public, .. } => {
                let pub_b64 = engine.encode(public);
                Some(build_ec_key_value_xml(
                    &pub_b64,
                    "urn:ietf:params:xml:ns:keyprov:curve:x25519",
                ))
            }
            Self::Opaque(_) => None,
            _ => None,
        }
    }
}

/// Opaque, cloneable Bergshamra key data.
///
/// The public handle contains no provider-specific key type. Cloning shares
/// parsed material and a lazily populated [`kryptering::SoftwareKey`] through
/// `Arc`; secret-bearing debug output is always redacted.
#[derive(Clone)]
pub struct KeyData {
    material: Arc<KeyMaterial>,
    software: Arc<OnceLock<kryptering::SoftwareKey>>,
}

impl std::fmt::Debug for KeyData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyData")
            .field("algorithm", &self.algorithm_name())
            .field("has_private_key", &self.has_private_key())
            .finish_non_exhaustive()
    }
}

impl From<KeyMaterial> for KeyData {
    fn from(material: KeyMaterial) -> Self {
        Self {
            material: Arc::new(material),
            software: Arc::new(OnceLock::new()),
        }
    }
}

impl From<kryptering::SoftwareKey> for KeyData {
    fn from(key: kryptering::SoftwareKey) -> Self {
        let software = OnceLock::new();
        let _ = software.set(key.clone());
        Self {
            material: Arc::new(KeyMaterial::Opaque(key)),
            software: Arc::new(software),
        }
    }
}

impl KeyData {
    /// Wrap a key imported through Kryptering's neutral provider API.
    pub fn from_software_key(key: kryptering::SoftwareKey) -> Self {
        key.into()
    }

    /// Import a PKCS#8 private key using the selected document provider.
    pub fn from_pkcs8_der(
        algorithm: kryptering::KeyAlgorithm,
        der: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        kryptering::SoftwareKey::from_pkcs8_der(algorithm, der)
            .map(Self::from)
            .map_err(map_kryptering_error)
    }

    /// Import an SPKI public key using the selected document provider.
    pub fn from_spki_der(
        algorithm: kryptering::KeyAlgorithm,
        der: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        kryptering::SoftwareKey::from_spki_der(algorithm, der)
            .map(Self::from)
            .map_err(map_kryptering_error)
    }

    /// Import raw symmetric key bytes using the selected document provider.
    pub fn from_symmetric_bytes(
        algorithm: kryptering::KeyAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        let key = kryptering::SoftwareKey::from_symmetric_bytes(algorithm, bytes)
            .map_err(map_kryptering_error)?;
        let material = match algorithm {
            kryptering::KeyAlgorithm::Hmac => KeyMaterial::Hmac(bytes.to_vec()),
            kryptering::KeyAlgorithm::Aes => KeyMaterial::Aes(bytes.to_vec()),
            kryptering::KeyAlgorithm::TripleDes => KeyMaterial::Des3(bytes.to_vec()),
            _ => {
                return Err(bergshamra_core::Error::Key(format!(
                    "{algorithm:?} is not a symmetric key family"
                )))
            }
        };
        let data = Self::from(material);
        data.cache_software_key(&key);
        Ok(data)
    }

    /// Import raw X25519 components using the selected document provider.
    pub fn from_x25519(
        private: Option<&[u8]>,
        public: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        let key =
            kryptering::SoftwareKey::from_x25519(private, public).map_err(map_kryptering_error)?;
        let private = private.map(<[u8; 32]>::try_from).transpose().map_err(|_| {
            bergshamra_core::Error::Key("X25519 private key must be 32 bytes".into())
        })?;
        let public = <[u8; 32]>::try_from(public).map_err(|_| {
            bergshamra_core::Error::Key("X25519 public key must be 32 bytes".into())
        })?;
        let data = Self::from(KeyMaterial::X25519 { private, public });
        data.cache_software_key(&key);
        Ok(data)
    }

    /// Import provider-neutral finite-field DH components.
    pub fn from_dh_parameters(
        p: &[u8],
        g: &[u8],
        q: Option<&[u8]>,
        private: Option<&[u8]>,
        public: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        let key = kryptering::SoftwareKey::from_dh_parameters(p, g, q, private, public)
            .map_err(map_kryptering_error)?;
        let data = Self::from(KeyMaterial::Dh {
            p: p.to_vec(),
            g: g.to_vec(),
            q: q.map(<[u8]>::to_vec),
            private_key: private.map(<[u8]>::to_vec),
            public_key: public.to_vec(),
        });
        data.cache_software_key(&key);
        Ok(data)
    }

    /// Return the neutral key family.
    pub fn algorithm(&self) -> kryptering::KeyAlgorithm {
        match self.material.as_ref() {
            KeyMaterial::Rsa { .. } => kryptering::KeyAlgorithm::Rsa,
            KeyMaterial::EcP256 { .. } => kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
            KeyMaterial::EcP384 { .. } => kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
            KeyMaterial::EcP521 { .. } => kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521),
            KeyMaterial::Dsa { .. } => kryptering::KeyAlgorithm::Dsa,
            KeyMaterial::Dh { .. } => kryptering::KeyAlgorithm::Dh,
            KeyMaterial::Ed25519 { .. } => kryptering::KeyAlgorithm::Ed25519,
            KeyMaterial::X25519 { .. } => kryptering::KeyAlgorithm::X25519,
            KeyMaterial::Hmac(_) => kryptering::KeyAlgorithm::Hmac,
            KeyMaterial::Aes(_) => kryptering::KeyAlgorithm::Aes,
            KeyMaterial::Des3(_) => kryptering::KeyAlgorithm::TripleDes,
            #[cfg(feature = "post-quantum")]
            KeyMaterial::PostQuantum { algorithm, .. } => {
                kryptering::KeyAlgorithm::PostQuantum(algorithm.to_kryptering())
            }
            #[cfg(not(feature = "post-quantum"))]
            KeyMaterial::PostQuantum { .. } => kryptering::KeyAlgorithm::Dh,
            KeyMaterial::Opaque(key) => key.algorithm(),
        }
    }

    /// Return a short human-readable algorithm name.
    pub fn algorithm_name(&self) -> &'static str {
        self.material.algorithm_name()
    }

    /// Encode the public key as SPKI DER, when applicable.
    pub fn to_spki_der(&self) -> Option<Vec<u8>> {
        self.material.to_spki_der()
    }

    /// Serialize public components as a `<KeyValue>` fragment, when applicable.
    pub fn to_key_value_xml(&self, dsig_prefix: &str) -> Option<String> {
        self.material.to_key_value_xml(dsig_prefix)
    }

    /// Return whether this handle includes private or symmetric secret material.
    pub fn has_private_key(&self) -> bool {
        match self.material.as_ref() {
            KeyMaterial::Rsa { private, .. } => private.is_some(),
            KeyMaterial::EcP256 { private, .. } => private.is_some(),
            KeyMaterial::EcP384 { private, .. } => private.is_some(),
            KeyMaterial::EcP521 { private, .. } => private.is_some(),
            KeyMaterial::Dsa { private, .. } => private.is_some(),
            KeyMaterial::Dh { private_key, .. } => private_key.is_some(),
            KeyMaterial::Ed25519 { private, .. } => private.is_some(),
            KeyMaterial::X25519 { private, .. } => private.is_some(),
            KeyMaterial::PostQuantum { private_der, .. } => private_der.is_some(),
            KeyMaterial::Hmac(_) | KeyMaterial::Aes(_) | KeyMaterial::Des3(_) => true,
            KeyMaterial::Opaque(key) => key.has_private_key(),
        }
    }

    /// Import or return the shared Kryptering handle for this key.
    pub fn software_key(&self) -> Result<Option<kryptering::SoftwareKey>, bergshamra_core::Error> {
        Key::new(self.clone(), KeyUsage::Any).software_key()
    }

    /// Explicitly export the neutral public component.
    pub fn export_public(&self) -> Result<Vec<u8>, bergshamra_core::Error> {
        self.software_key()?
            .ok_or_else(|| {
                bergshamra_core::Error::Key(format!(
                    "{} key has no software representation",
                    self.algorithm_name()
                ))
            })?
            .export_spki_der()
            .map_err(map_kryptering_error)
    }

    /// Explicitly export private or symmetric material in a zeroizing buffer.
    pub fn export_private(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, bergshamra_core::Error> {
        self.software_key()?
            .ok_or_else(|| {
                bergshamra_core::Error::Key(format!(
                    "{} key has no software representation",
                    self.algorithm_name()
                ))
            })?
            .export_private()
            .map_err(map_kryptering_error)
    }

    pub(crate) fn material(&self) -> &KeyMaterial {
        &self.material
    }

    fn cached_software_key(&self) -> Option<kryptering::SoftwareKey> {
        self.software.get().cloned()
    }

    fn cache_software_key(&self, key: &kryptering::SoftwareKey) {
        let _ = self.software.set(key.clone());
    }
}

fn key_algorithm_name(algorithm: kryptering::KeyAlgorithm) -> &'static str {
    match algorithm {
        kryptering::KeyAlgorithm::Rsa => "RSA",
        kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256) => "EC-P256",
        kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384) => "EC-P384",
        kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521) => "EC-P521",
        kryptering::KeyAlgorithm::Ed25519 => "Ed25519",
        kryptering::KeyAlgorithm::X25519 => "X25519",
        kryptering::KeyAlgorithm::Hmac => "HMAC",
        kryptering::KeyAlgorithm::Aes => "AES",
        kryptering::KeyAlgorithm::Dh => "DH",
        kryptering::KeyAlgorithm::Dsa => "DSA",
        kryptering::KeyAlgorithm::TripleDes => "3DES",
        #[cfg(feature = "post-quantum")]
        kryptering::KeyAlgorithm::PostQuantum(algorithm) => algorithm.name(),
        #[allow(unreachable_patterns)]
        _ => "unsupported",
    }
}

pub(crate) use KeyMaterial as InternalKeyData;

/// Build an `<ECKeyValue>` XML fragment using XmlWriter.
///
/// Used for EC (P-256, P-384, P-521) and X25519 keys. The `ECKeyValue` element
/// lives in the DSig 1.1 namespace.
fn build_ec_key_value_xml(pub_b64: &str, curve_uri: &str) -> String {
    use bergshamra_core::ns;
    use uppsala::XmlWriter;

    let mut w = XmlWriter::new();
    w.start_element(ns::node::EC_KEY_VALUE, &[("xmlns", ns::DSIG11)]);
    w.empty_element(ns::node::NAMED_CURVE, &[("URI", curve_uri)]);
    w.start_element(ns::node::PUBLIC_KEY, &[]);
    w.text(pub_b64);
    w.end_element(ns::node::PUBLIC_KEY);
    w.end_element(ns::node::EC_KEY_VALUE);
    w.into_string()
}

/// A named key with associated data.
#[derive(Debug, Clone)]
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
    pub fn new(data: impl Into<KeyData>, usage: KeyUsage) -> Self {
        Self {
            name: None,
            data: data.into(),
            usage,
            x509_chain: Vec::new(),
        }
    }

    /// Set the key name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Import this key into the selected document provider for an operation.
    pub fn software_key(
        &self,
    ) -> Result<Option<bergshamra_crypto::sign::SigningKey>, bergshamra_core::Error> {
        if let Some(key) = self.data.cached_software_key() {
            return Ok(Some(key));
        }
        use pkcs8::{EncodePrivateKey, EncodePublicKey};

        let imported = match self.data.material() {
            KeyMaterial::Rsa {
                private: Some(key), ..
            } => {
                let der = key
                    .to_pkcs8_der()
                    .map_err(|e| bergshamra_core::Error::Key(format!("RSA PKCS#8 encode: {e}")))?;
                Some(kryptering::SoftwareKey::from_pkcs8_der(
                    kryptering::KeyAlgorithm::Rsa,
                    der.as_bytes(),
                ))
            }
            KeyMaterial::Rsa { public, .. } => {
                let der = public
                    .to_public_key_der()
                    .map_err(|e| bergshamra_core::Error::Key(format!("RSA SPKI encode: {e}")))?;
                Some(kryptering::SoftwareKey::from_spki_der(
                    kryptering::KeyAlgorithm::Rsa,
                    der.as_bytes(),
                ))
            }
            KeyMaterial::EcP256 {
                private: Some(key), ..
            } => {
                let der = key.to_pkcs8_der().map_err(|e| {
                    bergshamra_core::Error::Key(format!("P-256 PKCS#8 encode: {e}"))
                })?;
                Some(kryptering::SoftwareKey::from_pkcs8_der(
                    kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
                    der.as_bytes(),
                ))
            }
            KeyMaterial::EcP256 { public, .. } => {
                let der = public
                    .to_public_key_der()
                    .map_err(|e| bergshamra_core::Error::Key(format!("P-256 SPKI encode: {e}")))?;
                Some(kryptering::SoftwareKey::from_spki_der(
                    kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
                    der.as_bytes(),
                ))
            }
            KeyMaterial::EcP384 {
                private: Some(key), ..
            } => {
                let der = key.to_pkcs8_der().map_err(|e| {
                    bergshamra_core::Error::Key(format!("P-384 PKCS#8 encode: {e}"))
                })?;
                Some(kryptering::SoftwareKey::from_pkcs8_der(
                    kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
                    der.as_bytes(),
                ))
            }
            KeyMaterial::EcP384 { public, .. } => {
                let der = public
                    .to_public_key_der()
                    .map_err(|e| bergshamra_core::Error::Key(format!("P-384 SPKI encode: {e}")))?;
                Some(kryptering::SoftwareKey::from_spki_der(
                    kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
                    der.as_bytes(),
                ))
            }
            KeyMaterial::EcP521 {
                private: Some(key), ..
            } => {
                let secret =
                    p521::SecretKey::from_slice(key.to_bytes().as_slice()).map_err(|e| {
                        bergshamra_core::Error::Key(format!("P-521 private conversion: {e}"))
                    })?;
                let der = secret.to_pkcs8_der().map_err(|e| {
                    bergshamra_core::Error::Key(format!("P-521 PKCS#8 encode: {e}"))
                })?;
                Some(kryptering::SoftwareKey::from_pkcs8_der(
                    kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521),
                    der.as_bytes(),
                ))
            }
            KeyMaterial::EcP521 { public, .. } => {
                let public =
                    p521::PublicKey::from_sec1_bytes(public.to_encoded_point(false).as_bytes())
                        .map_err(|e| {
                            bergshamra_core::Error::Key(format!("P-521 public conversion: {e}"))
                        })?;
                let der = public
                    .to_public_key_der()
                    .map_err(|e| bergshamra_core::Error::Key(format!("P-521 SPKI encode: {e}")))?;
                Some(kryptering::SoftwareKey::from_spki_der(
                    kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P521),
                    der.as_bytes(),
                ))
            }
            KeyMaterial::Dsa {
                private: Some(key), ..
            } => {
                let der = key
                    .to_pkcs8_der()
                    .map_err(|e| bergshamra_core::Error::Key(format!("DSA PKCS#8 encode: {e}")))?;
                Some(kryptering::SoftwareKey::from_pkcs8_der(
                    kryptering::KeyAlgorithm::Dsa,
                    der.as_bytes(),
                ))
            }
            KeyMaterial::Dsa { public, .. } => {
                let der = public
                    .to_public_key_der()
                    .map_err(|e| bergshamra_core::Error::Key(format!("DSA SPKI encode: {e}")))?;
                Some(kryptering::SoftwareKey::from_spki_der(
                    kryptering::KeyAlgorithm::Dsa,
                    der.as_bytes(),
                ))
            }
            KeyMaterial::Ed25519 {
                private: Some(key), ..
            } => {
                let der = key.to_pkcs8_der().map_err(|e| {
                    bergshamra_core::Error::Key(format!("Ed25519 PKCS#8 encode: {e}"))
                })?;
                Some(kryptering::SoftwareKey::from_pkcs8_der(
                    kryptering::KeyAlgorithm::Ed25519,
                    der.as_bytes(),
                ))
            }
            KeyMaterial::Ed25519 { public, .. } => {
                let der = public.to_public_key_der().map_err(|e| {
                    bergshamra_core::Error::Key(format!("Ed25519 SPKI encode: {e}"))
                })?;
                Some(kryptering::SoftwareKey::from_spki_der(
                    kryptering::KeyAlgorithm::Ed25519,
                    der.as_bytes(),
                ))
            }
            KeyMaterial::Hmac(bytes) => Some(kryptering::SoftwareKey::from_symmetric_bytes(
                kryptering::KeyAlgorithm::Hmac,
                bytes,
            )),
            #[cfg(feature = "post-quantum")]
            KeyMaterial::PostQuantum {
                algorithm,
                private_der,
                public_der,
            } => Some(kryptering::SoftwareKey::from_post_quantum_der(
                algorithm.to_kryptering(),
                private_der.as_deref(),
                public_der,
            )),
            #[cfg(not(feature = "post-quantum"))]
            KeyMaterial::PostQuantum { .. } => None,
            KeyMaterial::X25519 { private, public } => Some(kryptering::SoftwareKey::from_x25519(
                private.as_ref().map(|value| value.as_slice()),
                public,
            )),
            KeyMaterial::Dh {
                p,
                g,
                q,
                private_key,
                public_key,
            } => Some(kryptering::SoftwareKey::from_dh_parameters(
                p,
                g,
                q.as_deref(),
                private_key.as_deref(),
                public_key,
            )),
            KeyMaterial::Aes(bytes) => Some(kryptering::SoftwareKey::from_symmetric_bytes(
                kryptering::KeyAlgorithm::Aes,
                bytes,
            )),
            #[cfg(feature = "legacy-algorithms")]
            KeyMaterial::Des3(bytes) => Some(kryptering::SoftwareKey::from_symmetric_bytes(
                kryptering::KeyAlgorithm::TripleDes,
                bytes,
            )),
            #[cfg(not(feature = "legacy-algorithms"))]
            KeyMaterial::Des3(_) => None,
            KeyMaterial::Opaque(key) => return Ok(Some(key.clone())),
        };
        let imported = imported
            .map(|result| result.map_err(map_kryptering_error))
            .transpose()?;
        if let Some(key) = &imported {
            self.data.cache_software_key(key);
        }
        Ok(imported)
    }

    /// Backward-compatible operation-oriented alias used by XML-DSig.
    pub fn to_signing_key(
        &self,
    ) -> Result<Option<bergshamra_crypto::sign::SigningKey>, bergshamra_core::Error> {
        self.software_key()
    }

    /// Returns the algorithm name for this key (delegates to KeyData).
    pub fn algorithm_name(&self) -> &'static str {
        self.data.algorithm_name()
    }

    /// Returns the SPKI DER encoding if available (delegates to KeyData).
    pub fn to_spki_der(&self) -> Option<Vec<u8>> {
        self.data.to_spki_der()
    }

    /// Returns the KeyValue XML fragment if available (delegates to KeyData).
    pub fn to_key_value_xml(&self, dsig_prefix: &str) -> Option<String> {
        self.data.to_key_value_xml(dsig_prefix)
    }

    /// Returns true if this key contains private key material.
    pub fn has_private_key(&self) -> bool {
        self.data.has_private_key()
    }

    /// Get the raw symmetric key bytes (for AES, 3DES, HMAC).
    pub fn symmetric_key_bytes(&self) -> Option<&[u8]> {
        match self.data.material() {
            KeyMaterial::Hmac(k) | KeyMaterial::Aes(k) | KeyMaterial::Des3(k) => Some(k),
            _ => None,
        }
    }

    /// Get the DH key data if available.
    /// Return provider-neutral public finite-field DH parameters.
    ///
    /// The private exponent is deliberately not exposed. Agreement is
    /// performed with [`Self::software_key`] through Kryptering.
    pub fn dh_parameters(
        &self,
    ) -> Result<Option<kryptering::DhParameters>, bergshamra_core::Error> {
        Ok(self
            .software_key()?
            .and_then(|key| key.dh_parameters().cloned()))
    }

    /// Get the EC public key as SEC1 uncompressed point bytes.
    pub fn ec_public_key_bytes(&self) -> Option<Vec<u8>> {
        match self.data.material() {
            KeyMaterial::EcP256 { public, .. } => {
                Some(public.to_encoded_point(false).as_bytes().to_vec())
            }
            KeyMaterial::EcP384 { public, .. } => {
                Some(public.to_encoded_point(false).as_bytes().to_vec())
            }
            KeyMaterial::EcP521 { public, .. } => {
                Some(public.to_encoded_point(false).as_bytes().to_vec())
            }
            _ => None,
        }
    }
}

fn map_kryptering_error(error: kryptering::Error) -> bergshamra_core::Error {
    match error {
        kryptering::Error::Key(message) => bergshamra_core::Error::Key(message),
        kryptering::Error::Crypto(message) => bergshamra_core::Error::Crypto(message),
        error @ kryptering::Error::UnsupportedAlgorithm { .. } => {
            bergshamra_core::Error::UnsupportedAlgorithm(error.to_string())
        }
        kryptering::Error::Io(error) => bergshamra_core::Error::Io(error),
        #[allow(unreachable_patterns)]
        error => bergshamra_core::Error::Crypto(error.to_string()),
    }
}
