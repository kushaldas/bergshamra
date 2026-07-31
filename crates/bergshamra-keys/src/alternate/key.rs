#![forbid(unsafe_code)]

//! Provider-neutral key representation for AWS-LC builds.

use std::sync::Arc;

use base64::Engine;
use der::Decode;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Any,
}

#[allow(dead_code)]
#[derive(Clone)]
struct DhMaterial {
    key: kryptering::SoftwareKey,
    p: Vec<u8>,
    g: Vec<u8>,
    q: Option<Vec<u8>>,
    private: Option<Zeroizing<Vec<u8>>>,
    public: Vec<u8>,
}

#[derive(Clone)]
enum Material {
    Software {
        key: kryptering::SoftwareKey,
        spki: Option<Vec<u8>>,
        raw_public: Option<Vec<u8>>,
        symmetric: Option<Zeroizing<Vec<u8>>>,
    },
    #[allow(dead_code)]
    Dh(DhMaterial),
}

/// Opaque, shared key data without concrete provider types.
#[derive(Clone)]
pub struct KeyData(Arc<Material>);

impl std::fmt::Debug for KeyData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyData")
            .field("algorithm", &self.algorithm_name())
            .field("has_private_key", &self.has_private_key())
            .finish_non_exhaustive()
    }
}

impl From<kryptering::SoftwareKey> for KeyData {
    fn from(key: kryptering::SoftwareKey) -> Self {
        let component = key.public_component().ok();
        let (spki, raw_public) = classify_public(key.algorithm(), component);
        Self(Arc::new(Material::Software {
            key,
            spki,
            raw_public,
            symmetric: None,
        }))
    }
}

impl KeyData {
    pub fn from_software_key(key: kryptering::SoftwareKey) -> Self {
        key.into()
    }

    pub fn from_pkcs8_der(
        algorithm: kryptering::KeyAlgorithm,
        der: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        kryptering::SoftwareKey::from_pkcs8_der(algorithm, der)
            .map(Self::from)
            .map_err(map_kryptering_error)
    }

    pub fn from_spki_der(
        algorithm: kryptering::KeyAlgorithm,
        der: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        let key =
            kryptering::SoftwareKey::from_spki_der(algorithm, der).map_err(map_kryptering_error)?;
        let raw_public = spki_public_bytes(der).map(<[u8]>::to_vec);
        Ok(Self(Arc::new(Material::Software {
            key,
            spki: Some(der.to_vec()),
            raw_public,
            symmetric: None,
        })))
    }

    pub fn from_symmetric_bytes(
        algorithm: kryptering::KeyAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        let key = kryptering::SoftwareKey::from_symmetric_bytes(algorithm, bytes)
            .map_err(map_kryptering_error)?;
        Ok(Self(Arc::new(Material::Software {
            key,
            spki: None,
            raw_public: None,
            symmetric: Some(Zeroizing::new(bytes.to_vec())),
        })))
    }

    pub fn from_x25519(
        private: Option<&[u8]>,
        public: &[u8],
    ) -> Result<Self, bergshamra_core::Error> {
        let key =
            kryptering::SoftwareKey::from_x25519(private, public).map_err(map_kryptering_error)?;
        Ok(Self(Arc::new(Material::Software {
            key,
            spki: None,
            raw_public: Some(public.to_vec()),
            symmetric: None,
        })))
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
        Ok(Self(Arc::new(Material::Dh(DhMaterial {
            key,
            p: p.to_vec(),
            g: g.to_vec(),
            q: q.map(<[u8]>::to_vec),
            private: private.map(|value| Zeroizing::new(value.to_vec())),
            public: public.to_vec(),
        }))))
    }

    pub fn algorithm(&self) -> kryptering::KeyAlgorithm {
        match self.0.as_ref() {
            Material::Software { key, .. } => key.algorithm(),
            Material::Dh(_) => kryptering::KeyAlgorithm::Dh,
        }
    }

    pub fn algorithm_name(&self) -> &'static str {
        algorithm_name(self.algorithm())
    }

    pub fn to_spki_der(&self) -> Option<Vec<u8>> {
        match self.0.as_ref() {
            Material::Software { key, spki, .. } => {
                spki.clone().or_else(|| key.public_component().ok())
            }
            Material::Dh(_) => None,
        }
    }

    pub fn to_key_value_xml(&self, prefix: &str) -> Option<String> {
        match self.0.as_ref() {
            Material::Software {
                key,
                spki,
                raw_public,
                ..
            } => match key.algorithm() {
                kryptering::KeyAlgorithm::Rsa => rsa_key_value(spki.as_deref()?, prefix),
                kryptering::KeyAlgorithm::Ec(curve) => {
                    ec_key_value(raw_public.as_deref()?, curve_uri(curve))
                }
                kryptering::KeyAlgorithm::X25519 => ec_key_value(
                    raw_public.as_deref()?,
                    "urn:ietf:params:xml:ns:keyprov:curve:x25519",
                ),
                kryptering::KeyAlgorithm::Dsa => dsa_key_value(spki.as_deref()?, prefix),
                _ => None,
            },
            Material::Dh(dh) => Some(dh_key_value(dh)),
        }
    }

    pub fn has_private_key(&self) -> bool {
        match self.0.as_ref() {
            Material::Software { key, .. } => key.has_private_key(),
            Material::Dh(dh) => dh.private.is_some(),
        }
    }

    pub fn software_key(&self) -> Result<Option<kryptering::SoftwareKey>, bergshamra_core::Error> {
        Ok(match self.0.as_ref() {
            Material::Software { key, .. } => Some(key.clone()),
            Material::Dh(dh) => Some(dh.key.clone()),
        })
    }

    pub fn export_public(&self) -> Result<Vec<u8>, bergshamra_core::Error> {
        self.software_key()?
            .ok_or_else(|| bergshamra_core::Error::Key("key has no provider handle".into()))?
            .export_spki_der()
            .map_err(map_kryptering_error)
    }

    pub fn export_private(&self) -> Result<Zeroizing<Vec<u8>>, bergshamra_core::Error> {
        match self.0.as_ref() {
            Material::Software { key, .. } => key.export_private().map_err(map_kryptering_error),
            Material::Dh(dh) => dh
                .private
                .as_ref()
                .map(|value| Zeroizing::new(value.to_vec()))
                .ok_or_else(|| {
                    bergshamra_core::Error::Key("DH key has no private material".into())
                }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Key {
    pub name: Option<String>,
    pub data: KeyData,
    pub usage: KeyUsage,
    pub x509_chain: Vec<Vec<u8>>,
}

impl Key {
    pub fn new(data: impl Into<KeyData>, usage: KeyUsage) -> Self {
        Self {
            name: None,
            data: data.into(),
            usage,
            x509_chain: Vec::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn software_key(
        &self,
    ) -> Result<Option<bergshamra_crypto::sign::SigningKey>, bergshamra_core::Error> {
        self.data.software_key()
    }

    pub fn to_signing_key(
        &self,
    ) -> Result<Option<bergshamra_crypto::sign::SigningKey>, bergshamra_core::Error> {
        self.software_key()
    }

    pub fn algorithm_name(&self) -> &'static str {
        self.data.algorithm_name()
    }

    pub fn to_spki_der(&self) -> Option<Vec<u8>> {
        self.data.to_spki_der()
    }

    pub fn to_key_value_xml(&self, prefix: &str) -> Option<String> {
        self.data.to_key_value_xml(prefix)
    }

    pub fn has_private_key(&self) -> bool {
        self.data.has_private_key()
    }

    pub fn symmetric_key_bytes(&self) -> Option<&[u8]> {
        match self.data.0.as_ref() {
            Material::Software {
                symmetric: Some(bytes),
                ..
            } => Some(bytes),
            _ => None,
        }
    }

    /// Return provider-neutral public finite-field DH parameters without
    /// exposing the private exponent.
    pub fn dh_parameters(
        &self,
    ) -> Result<Option<kryptering::DhParameters>, bergshamra_core::Error> {
        Ok(self
            .software_key()?
            .and_then(|key| key.dh_parameters().cloned()))
    }

    pub fn ec_public_key_bytes(&self) -> Option<Vec<u8>> {
        match self.data.0.as_ref() {
            Material::Software {
                key, raw_public, ..
            } if matches!(key.algorithm(), kryptering::KeyAlgorithm::Ec(_)) => raw_public.clone(),
            _ => None,
        }
    }
}

fn classify_public(
    algorithm: kryptering::KeyAlgorithm,
    component: Option<Vec<u8>>,
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    match (algorithm, component) {
        (kryptering::KeyAlgorithm::X25519, component) => (None, component),
        (_, Some(spki)) => {
            let raw = spki_public_bytes(&spki).map(<[u8]>::to_vec);
            (Some(spki), raw)
        }
        (_, None) => (None, None),
    }
}

fn spki_public_bytes(der: &[u8]) -> Option<&[u8]> {
    spki::SubjectPublicKeyInfoRef::from_der(der)
        .ok()
        .map(|value| value.subject_public_key.raw_bytes())
}

fn rsa_key_value(spki_der: &[u8], prefix: &str) -> Option<String> {
    let rsa_der = spki_public_bytes(spki_der)?;
    let (_, sequence) = read_tlv(rsa_der, 0x30)?;
    let (rest, modulus) = read_tlv(sequence, 0x02)?;
    let (_, exponent) = read_tlv(rest, 0x02)?;
    let modulus = modulus.strip_prefix(&[0]).unwrap_or(modulus);
    let exponent = exponent.strip_prefix(&[0]).unwrap_or(exponent);
    let engine = base64::engine::general_purpose::STANDARD;
    let pname = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}:{name}")
        }
    };
    let mut writer = uppsala::XmlWriter::new();
    let root = pname(bergshamra_core::ns::node::RSA_KEY_VALUE);
    let modulus_tag = pname(bergshamra_core::ns::node::RSA_MODULUS);
    let exponent_tag = pname(bergshamra_core::ns::node::RSA_EXPONENT);
    writer.start_element(&root, &[]);
    writer.start_element(&modulus_tag, &[]);
    writer.text(&engine.encode(modulus));
    writer.end_element(&modulus_tag);
    writer.start_element(&exponent_tag, &[]);
    writer.text(&engine.encode(exponent));
    writer.end_element(&exponent_tag);
    writer.end_element(&root);
    Some(writer.into_string())
}

fn dsa_key_value(spki_der: &[u8], prefix: &str) -> Option<String> {
    let (_, spki) = read_tlv(spki_der, 0x30)?;
    let (after_algorithm, algorithm) = read_tlv(spki, 0x30)?;
    let (parameters, _) = read_tlv(algorithm, 0x06)?;
    let (_, parameters) = read_tlv(parameters, 0x30)?;
    let (parameters, p) = read_tlv(parameters, 0x02)?;
    let (parameters, q) = read_tlv(parameters, 0x02)?;
    let (_, g) = read_tlv(parameters, 0x02)?;
    let (_, subject_public_key) = read_tlv(after_algorithm, 0x03)?;
    let (_, y) = read_tlv(subject_public_key.strip_prefix(&[0])?, 0x02)?;
    let engine = base64::engine::general_purpose::STANDARD;
    let pname = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}:{name}")
        }
    };
    let mut writer = uppsala::XmlWriter::new();
    let root = pname(bergshamra_core::ns::node::DSA_KEY_VALUE);
    writer.start_element(&root, &[]);
    for (name, value) in [
        (bergshamra_core::ns::node::DSA_P, p),
        (bergshamra_core::ns::node::DSA_Q, q),
        (bergshamra_core::ns::node::DSA_G, g),
        (bergshamra_core::ns::node::DSA_Y, y),
    ] {
        let tag = pname(name);
        writer.start_element(&tag, &[]);
        writer.text(&engine.encode(unsigned_integer(value)));
        writer.end_element(&tag);
    }
    writer.end_element(&root);
    Some(writer.into_string())
}

fn unsigned_integer(value: &[u8]) -> &[u8] {
    value.strip_prefix(&[0]).unwrap_or(value)
}

fn ec_key_value(public: &[u8], curve: &str) -> Option<String> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(public);
    let mut writer = uppsala::XmlWriter::new();
    writer.start_element(
        bergshamra_core::ns::node::EC_KEY_VALUE,
        &[("xmlns", bergshamra_core::ns::DSIG11)],
    );
    writer.empty_element(bergshamra_core::ns::node::NAMED_CURVE, &[("URI", curve)]);
    writer.start_element(bergshamra_core::ns::node::PUBLIC_KEY, &[]);
    writer.text(&encoded);
    writer.end_element(bergshamra_core::ns::node::PUBLIC_KEY);
    writer.end_element(bergshamra_core::ns::node::EC_KEY_VALUE);
    Some(writer.into_string())
}

fn dh_key_value(dh: &DhMaterial) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut writer = uppsala::XmlWriter::new();
    writer.start_element(
        "xenc:DHKeyValue",
        &[("xmlns:xenc", bergshamra_core::ns::ENC)],
    );
    for (name, value) in [
        ("P", Some(dh.p.as_slice())),
        ("Q", dh.q.as_deref()),
        ("Generator", Some(dh.g.as_slice())),
        ("Public", Some(dh.public.as_slice())),
    ] {
        if let Some(value) = value {
            let tag = format!("xenc:{name}");
            writer.start_element(&tag, &[]);
            writer.text(&engine.encode(value));
            writer.end_element(&tag);
        }
    }
    writer.end_element("xenc:DHKeyValue");
    writer.into_string()
}

fn read_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if input.first().copied()? != tag {
        return None;
    }
    let first = *input.get(1)?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || input.len() < 2 + count {
            return None;
        }
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    Some((input.get(end..)?, input.get(header..end)?))
}

fn curve_uri(curve: kryptering::EcCurve) -> &'static str {
    match curve {
        kryptering::EcCurve::P256 => "urn:oid:1.2.840.10045.3.1.7",
        kryptering::EcCurve::P384 => "urn:oid:1.3.132.0.34",
        kryptering::EcCurve::P521 => "urn:oid:1.3.132.0.35",
    }
}

fn algorithm_name(algorithm: kryptering::KeyAlgorithm) -> &'static str {
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

fn map_kryptering_error(error: kryptering::Error) -> bergshamra_core::Error {
    match error {
        kryptering::Error::Key(message) => bergshamra_core::Error::Key(message),
        kryptering::Error::Crypto(message) => bergshamra_core::Error::Crypto(message),
        error @ kryptering::Error::UnsupportedAlgorithm { .. } => {
            bergshamra_core::Error::UnsupportedAlgorithm(error.to_string())
        }
        error => bergshamra_core::Error::Crypto(error.to_string()),
    }
}
