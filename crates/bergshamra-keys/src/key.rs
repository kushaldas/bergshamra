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
        let engine = base64::engine::general_purpose::STANDARD;

        match self {
            Self::Rsa { public, .. } => {
                use rsa::traits::PublicKeyParts;
                let modulus_b64 = engine.encode(public.n().to_bytes_be());
                let exponent_b64 = engine.encode(public.e().to_bytes_be());
                if dsig_prefix.is_empty() {
                    Some(format!(
                        "<RSAKeyValue><Modulus>{modulus_b64}</Modulus><Exponent>{exponent_b64}</Exponent></RSAKeyValue>"
                    ))
                } else {
                    Some(format!(
                        "<{dsig_prefix}:RSAKeyValue><{dsig_prefix}:Modulus>{modulus_b64}</{dsig_prefix}:Modulus><{dsig_prefix}:Exponent>{exponent_b64}</{dsig_prefix}:Exponent></{dsig_prefix}:RSAKeyValue>"
                    ))
                }
            }
            Self::EcP256 { public, .. } => {
                let point = public.to_encoded_point(false);
                let pub_b64 = engine.encode(point.as_bytes());
                Some(format!(
                    "<ECKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\"><NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/><PublicKey>{pub_b64}</PublicKey></ECKeyValue>"
                ))
            }
            Self::EcP384 { public, .. } => {
                let point = public.to_encoded_point(false);
                let pub_b64 = engine.encode(point.as_bytes());
                Some(format!(
                    "<ECKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\"><NamedCurve URI=\"urn:oid:1.3.132.0.34\"/><PublicKey>{pub_b64}</PublicKey></ECKeyValue>"
                ))
            }
            Self::EcP521 { public, .. } => {
                let point = public.to_encoded_point(false);
                let pub_b64 = engine.encode(point.as_bytes());
                Some(format!(
                    "<ECKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\"><NamedCurve URI=\"urn:oid:1.3.132.0.35\"/><PublicKey>{pub_b64}</PublicKey></ECKeyValue>"
                ))
            }
            Self::Dsa { public, .. } => {
                let components = public.components();
                let p_b64 = engine.encode(components.p().to_bytes_be());
                let q_b64 = engine.encode(components.q().to_bytes_be());
                let g_b64 = engine.encode(components.g().to_bytes_be());
                let y_b64 = engine.encode(public.y().to_bytes_be());
                if dsig_prefix.is_empty() {
                    Some(format!(
                        "<DSAKeyValue><P>{p_b64}</P><Q>{q_b64}</Q><G>{g_b64}</G><Y>{y_b64}</Y></DSAKeyValue>"
                    ))
                } else {
                    Some(format!(
                        "<{dsig_prefix}:DSAKeyValue><{dsig_prefix}:P>{p_b64}</{dsig_prefix}:P><{dsig_prefix}:Q>{q_b64}</{dsig_prefix}:Q><{dsig_prefix}:G>{g_b64}</{dsig_prefix}:G><{dsig_prefix}:Y>{y_b64}</{dsig_prefix}:Y></{dsig_prefix}:DSAKeyValue>"
                    ))
                }
            }
            Self::Dh {
                p,
                g,
                q,
                public_key,
                ..
            } => {
                let enc_ns = "http://www.w3.org/2001/04/xmlenc#";
                let p_b64 = engine.encode(p);
                let g_b64 = engine.encode(g);
                let pub_b64 = engine.encode(public_key);
                let mut xml =
                    format!("<xenc:DHKeyValue xmlns:xenc=\"{enc_ns}\"><xenc:P>{p_b64}</xenc:P>");
                if let Some(q_bytes) = q {
                    let q_b64 = engine.encode(q_bytes);
                    xml.push_str(&format!("<xenc:Q>{q_b64}</xenc:Q>"));
                }
                xml.push_str(&format!(
                    "<xenc:Generator>{g_b64}</xenc:Generator><xenc:Public>{pub_b64}</xenc:Public></xenc:DHKeyValue>"
                ));
                Some(xml)
            }
            Self::X25519 { public, .. } => {
                let pub_b64 = engine.encode(public);
                Some(format!(
                    "<ECKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\"><NamedCurve URI=\"urn:ietf:params:xml:ns:keyprov:curve:x25519\"/><PublicKey>{pub_b64}</PublicKey></ECKeyValue>"
                ))
            }
            _ => None,
        }
    }
}

/// A named key with associated data.
#[derive(Debug)]
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
