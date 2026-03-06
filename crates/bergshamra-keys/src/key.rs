#![forbid(unsafe_code)]

//! Key types and data structures.

/// Usage flags for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Any,
}

/// The underlying key data.
#[derive(Clone)]
pub enum KeyData {
    Rsa {
        private: Option<rsa::RsaPrivateKey>,
        public: rsa::RsaPublicKey,
    },
    EcP256 {
        private: Option<p256::ecdsa::SigningKey>,
        public: p256::ecdsa::VerifyingKey,
    },
    EcP384 {
        private: Option<p384::ecdsa::SigningKey>,
        public: p384::ecdsa::VerifyingKey,
    },
    EcP521 {
        private: Option<p521::ecdsa::SigningKey>,
        public: p521::ecdsa::VerifyingKey,
    },
    Dsa {
        private: Option<dsa::SigningKey>,
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
        private: Option<ed25519_dalek::SigningKey>,
        public: ed25519_dalek::VerifyingKey,
    },
    /// X25519 (ECDH over Curve25519) key for key agreement.
    X25519 {
        private: Option<[u8; 32]>,
        public: [u8; 32],
    },
    Hmac(Vec<u8>),
    Aes(Vec<u8>),
    Des3(Vec<u8>),
    /// Post-quantum key (ML-DSA or SLH-DSA) stored as raw DER bytes.
    PostQuantum {
        algorithm: bergshamra_crypto::sign::PqAlgorithm,
        private_der: Option<Vec<u8>>,
        public_der: Vec<u8>,
    },
}

impl std::fmt::Debug for KeyData {
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
        }
    }
}

impl KeyData {
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
            _ => None,
        }
    }
}

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
    pub fn new(data: KeyData, usage: KeyUsage) -> Self {
        Self {
            name: None,
            data,
            usage,
            x509_chain: Vec::new(),
        }
    }

    /// Set the key name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Convert to a `SigningKey` for use with crypto algorithms.
    pub fn to_signing_key(&self) -> Option<bergshamra_crypto::sign::SigningKey> {
        match &self.data {
            KeyData::Rsa {
                private: Some(pk), ..
            } => Some(bergshamra_crypto::sign::SigningKey::Rsa(pk.clone())),
            KeyData::Rsa { public, .. } => Some(bergshamra_crypto::sign::SigningKey::RsaPublic(
                public.clone(),
            )),
            KeyData::EcP256 {
                private: Some(sk), ..
            } => Some(bergshamra_crypto::sign::SigningKey::EcP256(sk.clone())),
            KeyData::EcP256 { public, .. } => {
                Some(bergshamra_crypto::sign::SigningKey::EcP256Public(*public))
            }
            KeyData::EcP384 {
                private: Some(sk), ..
            } => Some(bergshamra_crypto::sign::SigningKey::EcP384(sk.clone())),
            KeyData::EcP384 { public, .. } => {
                Some(bergshamra_crypto::sign::SigningKey::EcP384Public(*public))
            }
            KeyData::EcP521 {
                private: Some(sk), ..
            } => Some(bergshamra_crypto::sign::SigningKey::EcP521(sk.clone())),
            KeyData::EcP521 { public, .. } => Some(
                bergshamra_crypto::sign::SigningKey::EcP521Public(public.clone()),
            ),
            KeyData::Dsa {
                private: Some(sk), ..
            } => Some(bergshamra_crypto::sign::SigningKey::Dsa(sk.clone())),
            KeyData::Dsa { public, .. } => Some(bergshamra_crypto::sign::SigningKey::DsaPublic(
                public.clone(),
            )),
            KeyData::Ed25519 {
                private: Some(sk), ..
            } => Some(bergshamra_crypto::sign::SigningKey::Ed25519(sk.clone())),
            KeyData::Ed25519 { public, .. } => {
                Some(bergshamra_crypto::sign::SigningKey::Ed25519Public(*public))
            }
            KeyData::Hmac(k) => Some(bergshamra_crypto::sign::SigningKey::Hmac(k.clone())),
            KeyData::PostQuantum {
                algorithm,
                private_der,
                public_der,
            } => Some(bergshamra_crypto::sign::SigningKey::PostQuantum {
                algorithm: *algorithm,
                private_der: private_der.clone(),
                public_der: public_der.clone(),
            }),
            _ => None,
        }
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
        match &self.data {
            KeyData::Rsa { private, .. } => private.is_some(),
            KeyData::EcP256 { private, .. } => private.is_some(),
            KeyData::EcP384 { private, .. } => private.is_some(),
            KeyData::EcP521 { private, .. } => private.is_some(),
            KeyData::Dsa { private, .. } => private.is_some(),
            KeyData::Dh { private_key, .. } => private_key.is_some(),
            KeyData::Ed25519 { private, .. } => private.is_some(),
            KeyData::X25519 { private, .. } => private.is_some(),
            KeyData::PostQuantum { private_der, .. } => private_der.is_some(),
            // Symmetric keys inherently contain secret material
            KeyData::Hmac(_) | KeyData::Aes(_) | KeyData::Des3(_) => true,
        }
    }

    /// Get the raw symmetric key bytes (for AES, 3DES, HMAC).
    pub fn symmetric_key_bytes(&self) -> Option<&[u8]> {
        match &self.data {
            KeyData::Hmac(k) | KeyData::Aes(k) | KeyData::Des3(k) => Some(k),
            _ => None,
        }
    }

    /// Get the RSA public key if available.
    pub fn rsa_public_key(&self) -> Option<&rsa::RsaPublicKey> {
        match &self.data {
            KeyData::Rsa { public, .. } => Some(public),
            _ => None,
        }
    }

    /// Get the RSA private key if available.
    pub fn rsa_private_key(&self) -> Option<&rsa::RsaPrivateKey> {
        match &self.data {
            KeyData::Rsa {
                private: Some(pk), ..
            } => Some(pk),
            _ => None,
        }
    }

    /// Get the DH key data if available.
    #[allow(clippy::type_complexity)]
    pub fn dh_data(&self) -> Option<(&[u8], &[u8], Option<&[u8]>, Option<&[u8]>, &[u8])> {
        match &self.data {
            KeyData::Dh {
                p,
                g,
                q,
                private_key,
                public_key,
            } => Some((p, g, q.as_deref(), private_key.as_deref(), public_key)),
            _ => None,
        }
    }

    /// Get the EC public key as SEC1 uncompressed point bytes.
    pub fn ec_public_key_bytes(&self) -> Option<Vec<u8>> {
        match &self.data {
            KeyData::EcP256 { public, .. } => {
                Some(public.to_encoded_point(false).as_bytes().to_vec())
            }
            KeyData::EcP384 { public, .. } => {
                Some(public.to_encoded_point(false).as_bytes().to_vec())
            }
            KeyData::EcP521 { public, .. } => {
                Some(public.to_encoded_point(false).as_bytes().to_vec())
            }
            _ => None,
        }
    }

    /// Get the X25519 public key bytes (32 bytes).
    pub fn x25519_public_key_bytes(&self) -> Option<&[u8; 32]> {
        match &self.data {
            KeyData::X25519 { public, .. } => Some(public),
            _ => None,
        }
    }

    /// Get the X25519 private key bytes (32 bytes), if available.
    pub fn x25519_private_key_bytes(&self) -> Option<&[u8; 32]> {
        match &self.data {
            KeyData::X25519 {
                private: Some(pk), ..
            } => Some(pk),
            _ => None,
        }
    }
}
