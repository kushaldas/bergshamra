#![forbid(unsafe_code)]

//! KeyInfo XML processing — reads `<ds:KeyInfo>` elements to extract key material.

use crate::key::{Key, KeyData, KeyUsage};
use crate::manager::KeysManager;
use bergshamra_core::{ns, Error};
use uppsala::{Document, NodeId};

/// Decode a CryptoBinary value that may be base64 or hex encoded.
///
/// Some XML Security test vectors (particularly from NIST/xmlenc interop) encode
/// RSA modulus/exponent values as hex strings rather than base64. This function
/// detects the encoding and decodes accordingly.
fn decode_crypto_binary(text: &str, engine: &impl base64::Engine) -> Result<Vec<u8>, String> {
    let clean: String = text.trim().chars().filter(|c| !c.is_whitespace()).collect();

    if clean.is_empty() {
        return Err("empty value".into());
    }

    // Try base64 first
    if let Ok(bytes) = engine.decode(&clean) {
        return Ok(bytes);
    }

    // If base64 fails, try hex decoding (some test vectors use hex).
    // XML CryptoBinary hex requires complete byte pairs; reject odd lengths,
    // including a single hex digit, before chunking so malformed KeyInfo stays
    // a recoverable parse error.
    if clean.chars().all(|c| c.is_ascii_hexdigit()) {
        if clean.len() % 2 != 0 {
            return Err("odd-length hex CryptoBinary value".into());
        }

        let bytes: Result<Vec<u8>, _> = clean
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hex = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
                u8::from_str_radix(hex, 16).map_err(|e| e.to_string())
            })
            .collect();
        if let Ok(bytes) = bytes {
            return Ok(bytes);
        }
    }

    let preview: String = clean.chars().take(20).collect();
    Err(format!("invalid CryptoBinary value near {}", preview))
}

/// Process a `<KeyInfo>` element and attempt to resolve a key from the manager.
pub fn resolve_key_info<'a>(
    key_info_node: NodeId,
    doc: &Document<'_>,
    manager: &'a KeysManager,
) -> Result<&'a Key, Error> {
    // Try <KeyName> first
    for child in doc.children(key_info_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let ns_uri = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;

        if ns_uri == ns::DSIG && local == ns::node::KEY_NAME {
            let name_text = doc.text_content_deep(child);
            let name_text = name_text.trim();
            if !name_text.is_empty() {
                if let Some(key) = manager.find_by_name(name_text) {
                    return Ok(key);
                }
            }
        }
    }

    // Try <X509Data><X509IssuerSerial> — match cert by issuer+serial
    for child in doc.children(key_info_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let ns_uri = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;

        if local == ns::node::X509_DATA && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            // Collect serial numbers from X509IssuerSerial elements
            for issuer_serial in doc.children(child) {
                let is_elem = match doc.element(issuer_serial) {
                    Some(e) => e,
                    None => continue,
                };
                if &*is_elem.name.local_name != ns::node::X509_ISSUER_SERIAL {
                    continue;
                }
                let serial_text = doc
                    .children(issuer_serial)
                    .into_iter()
                    .find(|&n| {
                        doc.element(n)
                            .map(|e| &*e.name.local_name == ns::node::X509_SERIAL_NUMBER)
                            .unwrap_or(false)
                    })
                    .map(|n| doc.text_content_deep(n))
                    .unwrap_or_default()
                    .trim()
                    .to_string();

                if serial_text.is_empty() {
                    continue;
                }

                // Try to match against keys in the manager
                if let Some(key) = find_key_by_serial(manager, &serial_text) {
                    return Ok(key);
                }
            }
        }
    }

    // Try <KeyValue> — extract RSA or EC public key from inline XML
    for child in doc.children(key_info_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let ns_uri = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;

        if local == ns::node::KEY_VALUE && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            // Try RSA KeyValue
            if let Ok(_key) = parse_rsa_key_value(child, doc) {
                // We can't return an owned key from a borrow-based API,
                // so we need a different approach. For now, fall through
                // to first_key() which will be reached below.
                // The caller (verify.rs) handles KeyValue extraction directly.
            }
        }
    }

    // Fallback: return the first key in the manager
    manager.first_key()
}

/// Find a key in the manager by matching X.509 certificate serial number.
///
/// Iterates over all keys, parses their X.509 certificate (if present),
/// and compares the serial number as a decimal string.
fn find_key_by_serial<'a>(manager: &'a KeysManager, serial_text: &str) -> Option<&'a Key> {
    use der::Decode;

    // Parse the expected serial as big-endian bytes for comparison
    // Serial numbers in XML are decimal strings which may be very large
    for key in manager.keys() {
        if key.x509_chain.is_empty() {
            continue;
        }
        // Check the leaf cert (first in chain)
        let cert_der = &key.x509_chain[0];
        if let Ok(cert) = x509_cert::Certificate::from_der(cert_der) {
            let cert_serial = cert.tbs_certificate.serial_number;
            let cert_serial_str = format_serial_decimal(cert_serial.as_bytes());
            if cert_serial_str == serial_text {
                return Some(key);
            }
        }
    }
    None
}

/// Convert a big-endian signed integer (ASN.1 INTEGER) to a decimal string.
///
/// X.509 serial numbers are ASN.1 INTEGERs (signed, big-endian).
/// XML-DSig uses unsigned decimal representation.
fn format_serial_decimal(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }

    // Treat as unsigned big-endian integer and convert to decimal
    // ASN.1 serial numbers are positive integers, but may have a leading 0x00
    // byte for sign. We treat them as unsigned.
    let mut result = vec![0u8]; // accumulator in decimal digits
    for &byte in bytes {
        // Multiply result by 256
        let mut carry: u16 = 0;
        for digit in result.iter_mut() {
            let val = (*digit as u16) * 256 + carry;
            *digit = (val % 10) as u8;
            carry = val / 10;
        }
        while carry > 0 {
            result.push((carry % 10) as u8);
            carry /= 10;
        }
        // Add byte value
        let mut carry: u16 = byte as u16;
        for digit in result.iter_mut() {
            let val = (*digit as u16) + carry;
            *digit = (val % 10) as u8;
            carry = val / 10;
        }
        while carry > 0 {
            result.push((carry % 10) as u8);
            carry /= 10;
        }
    }

    // result is in little-endian digit order, reverse and convert to string
    result
        .iter()
        .rev()
        .map(|d| (b'0' + d) as char)
        .collect::<String>()
        .trim_start_matches('0')
        .to_string()
        .chars()
        .next()
        .map_or("0".to_string(), |_| {
            result
                .iter()
                .rev()
                .map(|d| (b'0' + d) as char)
                .collect::<String>()
                .trim_start_matches('0')
                .to_string()
        })
}

/// Try to extract a certificate-backed inline key from `<KeyInfo>`.
///
/// This only considers `<X509Data><X509Certificate>` entries and ignores raw
/// inline keys such as `<KeyValue>` and `<DEREncodedKeyValue>`. Verifiers use
/// this when trust anchors are configured so an anchorable certificate chain is
/// preferred over document-controlled raw key material.
pub fn extract_x509_key_value(key_info_node: NodeId, doc: &Document<'_>) -> Option<Key> {
    for child in doc.children(key_info_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let ns_uri = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;

        if local == ns::node::X509_DATA && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            if let Some(key) = extract_x509_certificate(child, doc) {
                return Some(key);
            }
        }
    }
    None
}

/// Try to extract an inline key from `<KeyInfo>` (RSA, EC, DSA KeyValue, or X509Certificate).
///
/// Returns `Some(Key)` if a KeyValue or X509Certificate was found and parsed, `None` otherwise.
pub fn extract_key_value(key_info_node: NodeId, doc: &Document<'_>) -> Option<Key> {
    for child in doc.children(key_info_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let ns_uri = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;

        if local == ns::node::KEY_VALUE && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            // Try RSA KeyValue
            if let Ok(key) = parse_rsa_key_value(child, doc) {
                return Some(key);
            }
            // Try EC KeyValue
            if let Ok(key) = parse_ec_key_value(child, doc) {
                return Some(key);
            }
            // Try DSA KeyValue
            if let Ok(key) = parse_dsa_key_value(child, doc) {
                return Some(key);
            }
        }

        // Try X509Data > X509Certificate
        if local == ns::node::X509_DATA && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            if let Some(key) = extract_x509_certificate(child, doc) {
                return Some(key);
            }
        }

        // Try DEREncodedKeyValue (dsig11 namespace)
        if local == ns::node::DER_ENCODED_KEY_VALUE && ns_uri == ns::DSIG11 {
            if let Some(key) = parse_der_encoded_key_value(child, doc) {
                return Some(key);
            }
        }
    }
    None
}

/// Parsed X.509 certificate with its raw DER and extracted key.
struct ParsedCert {
    /// The x509_cert parsed certificate.
    cert: x509_cert::Certificate,
    /// The raw DER bytes.
    der: Vec<u8>,
}

impl ParsedCert {
    /// Check if this certificate is a CA (has BasicConstraints with cA=true).
    fn is_ca(&self) -> bool {
        use der::Decode;
        // BasicConstraints OID: 2.5.29.19
        let bc_oid = der::oid::ObjectIdentifier::new_unwrap("2.5.29.19");
        if let Some(exts) = &self.cert.tbs_certificate.extensions {
            for ext in exts.iter() {
                if ext.extn_id == bc_oid {
                    if let Ok(bc) =
                        x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes())
                    {
                        return bc.ca;
                    }
                }
            }
        }
        false
    }

    /// Get the subject as DER bytes (for issuer/subject matching).
    fn subject_der(&self) -> Vec<u8> {
        use der::Encode;
        self.cert
            .tbs_certificate
            .subject
            .to_der()
            .unwrap_or_default()
    }

    /// Get the issuer as DER bytes.
    fn issuer_der(&self) -> Vec<u8> {
        use der::Encode;
        self.cert
            .tbs_certificate
            .issuer
            .to_der()
            .unwrap_or_default()
    }
}

/// Find the end-entity (leaf) certificate from a list of parsed certificates.
///
/// Uses two heuristics:
/// 1. BasicConstraints: prefer certs where cA is false or absent
/// 2. Issuer graph: the leaf cert's subject should not appear as an issuer
///    of any other cert in the chain
///
/// Falls back to the last cert if all appear to be CAs.
fn find_leaf_cert(certs: &[ParsedCert]) -> usize {
    if certs.len() <= 1 {
        return 0;
    }

    // Collect all subjects
    let subjects: Vec<Vec<u8>> = certs.iter().map(|c| c.subject_der()).collect();
    let issuers: Vec<Vec<u8>> = certs.iter().map(|c| c.issuer_der()).collect();

    // Build set of subjects that are issuers of other certs
    let mut is_issuer_of_other = vec![false; certs.len()];
    for (i, subj) in subjects.iter().enumerate() {
        for (j, iss) in issuers.iter().enumerate() {
            if i != j && subj == iss {
                is_issuer_of_other[i] = true;
                break;
            }
        }
    }

    // Strategy 1: non-CA certs that are NOT issuers of other certs
    let mut candidates: Vec<usize> = (0..certs.len())
        .filter(|&i| !certs[i].is_ca() && !is_issuer_of_other[i])
        .collect();

    if candidates.len() == 1 {
        return candidates[0];
    }

    // Strategy 2: certs that are NOT issuers of other certs (even if CA flag missing)
    if candidates.is_empty() {
        candidates = (0..certs.len())
            .filter(|&i| !is_issuer_of_other[i])
            .collect();
    }

    if candidates.len() == 1 {
        return candidates[0];
    }

    // Strategy 3: non-CA certs (even if they appear as issuers — shouldn't happen normally)
    if candidates.is_empty() {
        candidates = (0..certs.len()).filter(|&i| !certs[i].is_ca()).collect();
    }

    // If we have multiple candidates, prefer the one with the largest key
    // (end-entity certs in test suites often have the largest key)
    if candidates.len() > 1 {
        // Pick the last non-CA, non-issuer candidate (often the leaf in ordered chains)
        return *candidates.last().unwrap();
    }

    if candidates.len() == 1 {
        return candidates[0];
    }

    // All look like CAs — return the last one (most likely to be leaf in ordered chains)
    certs.len() - 1
}

/// Extract a public key from `<X509Data><X509Certificate>` (base64-encoded DER).
///
/// If multiple certificates are present, uses X.509 chain analysis to find the
/// end-entity (leaf) certificate: checks BasicConstraints and builds an
/// issuer/subject graph to identify which cert is NOT a CA and NOT an issuer
/// of any other cert in the chain.
fn extract_x509_certificate(x509_data_node: NodeId, doc: &Document<'_>) -> Option<Key> {
    use base64::Engine;
    use der::Decode;
    let engine = base64::engine::general_purpose::STANDARD;

    let mut parsed_certs = Vec::new();
    for child in doc.children(x509_data_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        if &*elem.name.local_name == ns::node::X509_CERTIFICATE {
            let b64 = doc.text_content_deep(child);
            let b64 = b64.trim();
            let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            if let Ok(der) = engine.decode(&clean) {
                if let Ok(cert) = x509_cert::Certificate::from_der(&der) {
                    parsed_certs.push(ParsedCert { cert, der });
                }
            }
        }
    }

    if parsed_certs.is_empty() {
        return None;
    }

    let leaf_idx = find_leaf_cert(&parsed_certs);
    let leaf = &parsed_certs[leaf_idx];
    let mut key = crate::loader::load_x509_cert_der(&leaf.der).ok()?;
    // Populate x509_chain with ALL certs from the XML, but place the selected
    // leaf FIRST. Downstream chain validation (bergshamra-dsig verify.rs) treats
    // `x509_chain[0]` as the leaf and validates *it* against the trust anchors,
    // while the signature itself is verified with this key's public key — which
    // is the leaf's key (`load_x509_cert_der(&leaf.der)` above). If `x509_chain[0]`
    // were merely the first cert in document order, those two could be different
    // certificates: an attacker could place a legitimately-anchored cert at
    // index 0 (which passes chain validation) while `find_leaf_cert` selected a
    // *different*, attacker-controlled cert as the signature key — a key/leaf
    // confusion trust bypass. Anchoring `x509_chain[0]` to the signature key
    // closes that gap. See docs/adr/0006-x509-leaf-binding.md.
    let mut chain: Vec<Vec<u8>> = Vec::with_capacity(parsed_certs.len());
    chain.push(leaf.der.clone());
    for (i, c) in parsed_certs.iter().enumerate() {
        if i != leaf_idx {
            chain.push(c.der.clone());
        }
    }
    key.x509_chain = chain;
    Some(key)
}

/// Parse a `<dsig11:DEREncodedKeyValue>` element containing base64-encoded SPKI DER.
fn parse_der_encoded_key_value(node: NodeId, doc: &Document<'_>) -> Option<Key> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let b64_text = doc.text_content_deep(node);
    let b64_text = b64_text.trim();
    let clean: String = b64_text.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return None;
    }
    let der_bytes = engine.decode(&clean).ok()?;
    crate::loader::load_spki_der(&der_bytes).ok()
}

/// Extract an RSA public key from a `<KeyValue><RSAKeyValue>` element.
pub fn parse_rsa_key_value(key_value_node: NodeId, doc: &Document<'_>) -> Result<Key, Error> {
    let rsa_kv = doc
        .children(key_value_node)
        .into_iter()
        .find(|&n| {
            doc.element(n)
                .map(|e| {
                    &*e.name.local_name == ns::node::RSA_KEY_VALUE
                        && e.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| Error::MissingElement("RSAKeyValue".into()))?;

    let modulus_b64 = doc
        .children(rsa_kv)
        .into_iter()
        .find(|&n| {
            doc.element(n)
                .map(|e| &*e.name.local_name == ns::node::RSA_MODULUS)
                .unwrap_or(false)
        })
        .map(|n| doc.text_content_deep(n))
        .ok_or_else(|| Error::MissingElement("Modulus".into()))?;

    let exponent_b64 = doc
        .children(rsa_kv)
        .into_iter()
        .find(|&n| {
            doc.element(n)
                .map(|e| &*e.name.local_name == ns::node::RSA_EXPONENT)
                .unwrap_or(false)
        })
        .map(|n| doc.text_content_deep(n))
        .ok_or_else(|| Error::MissingElement("Exponent".into()))?;

    let engine = base64::engine::general_purpose::STANDARD;
    let modulus_bytes = decode_crypto_binary(&modulus_b64, &engine)
        .map_err(|e| Error::Base64(format!("Modulus: {e}")))?;
    let exponent_bytes = decode_crypto_binary(&exponent_b64, &engine)
        .map_err(|e| Error::Base64(format!("Exponent: {e}")))?;

    let n = rsa::BigUint::from_bytes_be(&modulus_bytes);
    let e = rsa::BigUint::from_bytes_be(&exponent_bytes);
    let public = rsa::RsaPublicKey::new(n, e)
        .map_err(|err| Error::Key(format!("invalid RSA public key: {err}")))?;

    Ok(Key::new(
        KeyData::Rsa {
            private: None,
            public,
        },
        KeyUsage::Verify,
    ))
}

/// Extract a DSA public key from a `<KeyValue><DSAKeyValue>` element.
///
/// DSAKeyValue contains P, Q, G (domain parameters) and Y (public key).
pub fn parse_dsa_key_value(key_value_node: NodeId, doc: &Document<'_>) -> Result<Key, Error> {
    let dsa_kv = doc
        .children(key_value_node)
        .into_iter()
        .find(|&n| {
            doc.element(n)
                .map(|e| {
                    &*e.name.local_name == ns::node::DSA_KEY_VALUE
                        && e.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| Error::MissingElement("DSAKeyValue".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let decode_elem = |name: &str| -> Result<Vec<u8>, Error> {
        let b64 = doc
            .children(dsa_kv)
            .into_iter()
            .find(|&n| {
                doc.element(n)
                    .map(|e| &*e.name.local_name == name)
                    .unwrap_or(false)
            })
            .map(|n| doc.text_content_deep(n))
            .ok_or_else(|| Error::MissingElement(name.into()))?;
        let clean: String = b64.trim().chars().filter(|c| !c.is_whitespace()).collect();
        engine
            .decode(&clean)
            .map_err(|e| Error::Base64(format!("{name}: {e}")))
    };

    let p_bytes = decode_elem(ns::node::DSA_P)?;
    let q_bytes = decode_elem(ns::node::DSA_Q)?;
    let g_bytes = decode_elem(ns::node::DSA_G)?;
    let y_bytes = decode_elem(ns::node::DSA_Y)?;

    let p = dsa::BigUint::from_bytes_be(&p_bytes);
    let q = dsa::BigUint::from_bytes_be(&q_bytes);
    let g = dsa::BigUint::from_bytes_be(&g_bytes);
    let y = dsa::BigUint::from_bytes_be(&y_bytes);

    let components = dsa::Components::from_components(p, q, g)
        .map_err(|e| Error::Key(format!("invalid DSA components: {e}")))?;
    let vk = dsa::VerifyingKey::from_components(components, y)
        .map_err(|e| Error::Key(format!("invalid DSA public key: {e}")))?;

    Ok(Key::new(
        KeyData::Dsa {
            private: None,
            public: vk,
        },
        KeyUsage::Verify,
    ))
}

/// Extract an EC public key from a `<KeyValue><ECKeyValue>` element.
///
/// Supports P-256, P-384, P-521 curves via NamedCurve OID.
pub fn parse_ec_key_value(key_value_node: NodeId, doc: &Document<'_>) -> Result<Key, Error> {
    // ECKeyValue is in the xmldsig11 namespace
    let ec_kv = doc
        .children(key_value_node)
        .into_iter()
        .find(|&n| {
            doc.element(n)
                .map(|e| {
                    &*e.name.local_name == ns::node::EC_KEY_VALUE
                        && (e.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG11
                            || e.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG)
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| Error::MissingElement("ECKeyValue".into()))?;

    // Read NamedCurve URI
    let named_curve = doc
        .children(ec_kv)
        .into_iter()
        .find(|&n| {
            doc.element(n)
                .map(|e| &*e.name.local_name == ns::node::NAMED_CURVE)
                .unwrap_or(false)
        })
        .ok_or_else(|| Error::MissingElement("NamedCurve".into()))?;

    let curve_uri = doc
        .element(named_curve)
        .unwrap()
        .get_attribute(ns::attr::URI)
        .ok_or_else(|| Error::MissingAttribute("URI on NamedCurve".into()))?
        .to_string();

    // Read PublicKey (base64-encoded uncompressed point)
    let public_key_b64 = doc
        .children(ec_kv)
        .into_iter()
        .find(|&n| {
            doc.element(n)
                .map(|e| &*e.name.local_name == ns::node::PUBLIC_KEY)
                .unwrap_or(false)
        })
        .map(|n| doc.text_content_deep(n))
        .ok_or_else(|| Error::MissingElement("PublicKey".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let point_bytes = engine
        .decode(public_key_b64.trim().replace(['\n', '\r', ' '], ""))
        .map_err(|e| Error::Base64(format!("EC PublicKey: {e}")))?;

    match &*curve_uri {
        "urn:oid:1.2.840.10045.3.1.7" => {
            // P-256
            use p256::elliptic_curve::sec1::FromEncodedPoint;
            let encoded = p256::EncodedPoint::from_bytes(&point_bytes)
                .map_err(|e| Error::Key(format!("invalid P-256 point: {e}")))?;
            let point = p256::PublicKey::from_encoded_point(&encoded);
            if point.is_none().into() {
                return Err(Error::Key("invalid P-256 public key point".into()));
            }
            let vk = p256::ecdsa::VerifyingKey::from(point.unwrap());
            Ok(Key::new(
                KeyData::EcP256 {
                    private: None,
                    public: vk,
                },
                KeyUsage::Verify,
            ))
        }
        "urn:oid:1.3.132.0.34" => {
            // P-384
            use p384::elliptic_curve::sec1::FromEncodedPoint;
            let encoded = p384::EncodedPoint::from_bytes(&point_bytes)
                .map_err(|e| Error::Key(format!("invalid P-384 point: {e}")))?;
            let point = p384::PublicKey::from_encoded_point(&encoded);
            if point.is_none().into() {
                return Err(Error::Key("invalid P-384 public key point".into()));
            }
            let vk = p384::ecdsa::VerifyingKey::from(point.unwrap());
            Ok(Key::new(
                KeyData::EcP384 {
                    private: None,
                    public: vk,
                },
                KeyUsage::Verify,
            ))
        }
        "urn:oid:1.3.132.0.35" => {
            // P-521
            use p521::elliptic_curve::sec1::FromEncodedPoint;
            let encoded = p521::EncodedPoint::from_bytes(&point_bytes)
                .map_err(|e| Error::Key(format!("invalid P-521 point: {e}")))?;
            let point = p521::PublicKey::from_encoded_point(&encoded);
            if point.is_none().into() {
                return Err(Error::Key("invalid P-521 public key point".into()));
            }
            let vk = p521::ecdsa::VerifyingKey::from(ecdsa::VerifyingKey::from(point.unwrap()));
            Ok(Key::new(
                KeyData::EcP521 {
                    private: None,
                    public: vk,
                },
                KeyUsage::Verify,
            ))
        }
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "EC curve: {curve_uri}"
        ))),
    }
}

// ── KeyInfo XML construction ─────────────────────────────────────────

/// Build a `<ds:KeyInfo>` XML fragment containing one or more X.509 certificates.
///
/// Certificates should be provided as base64-encoded DER strings (the content
/// that goes inside `<ds:X509Certificate>`).
///
/// # Example output
///
/// ```xml
/// <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MII...</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
/// ```
pub fn build_x509_key_info(certs_b64: &[&str]) -> String {
    use uppsala::XmlWriter;

    let mut w = XmlWriter::new();
    w.start_element("ds:KeyInfo", &[("xmlns:ds", ns::DSIG)]);
    w.start_element("ds:X509Data", &[]);
    for cert in certs_b64 {
        w.start_element("ds:X509Certificate", &[]);
        // Base64 content contains no XML-special characters, but text() is
        // correct regardless and avoids any injection risk.
        w.text(cert);
        w.end_element("ds:X509Certificate");
    }
    w.end_element("ds:X509Data");
    w.end_element("ds:KeyInfo");
    w.into_string()
}

/// Build a `<ds:KeyInfo>` XML fragment from DER-encoded certificate bytes.
///
/// The certificates are base64-encoded internally before embedding.
pub fn build_x509_key_info_from_der(certs_der: &[impl AsRef<[u8]>]) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let b64_certs: Vec<String> = certs_der
        .iter()
        .map(|der| engine.encode(der.as_ref()))
        .collect();
    let refs: Vec<&str> = b64_certs.iter().map(|s| s.as_str()).collect();
    build_x509_key_info(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_x509_key_info_single_cert() {
        let cert = "MIIBojCCAUmgAwIBAgIJAL==";
        let xml = build_x509_key_info(&[cert]);
        assert_eq!(
            xml,
            concat!(
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                "<ds:X509Data>",
                "<ds:X509Certificate>MIIBojCCAUmgAwIBAgIJAL==</ds:X509Certificate>",
                "</ds:X509Data>",
                "</ds:KeyInfo>",
            )
        );
    }

    #[test]
    fn test_build_x509_key_info_multiple_certs() {
        let xml = build_x509_key_info(&["AAAA", "BBBB"]);
        assert!(xml.contains("<ds:X509Certificate>AAAA</ds:X509Certificate>"));
        assert!(xml.contains("<ds:X509Certificate>BBBB</ds:X509Certificate>"));
        // Single X509Data wrapping both certs
        assert_eq!(xml.matches("<ds:X509Data>").count(), 1);
    }

    #[test]
    fn test_build_x509_key_info_from_der() {
        let der_bytes = b"\x30\x82\x01\x22"; // dummy DER
        let xml = build_x509_key_info_from_der(&[der_bytes.as_slice()]);
        assert!(xml.starts_with(r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#));
        assert!(xml.contains("<ds:X509Certificate>"));
        assert!(xml.ends_with("</ds:KeyInfo>"));
    }

    #[test]
    fn test_build_x509_key_info_namespace_uses_constant() {
        let xml = build_x509_key_info(&["AAAA"]);
        assert!(xml.contains(ns::DSIG));
    }

    // Aleksey xmlsec interop chain (from keys/rsa/rsa-2048-key.p12): the
    // end-entity leaf "Test Key rsa-2048" and the self-signed "Aleksey Sanin /
    // Root CA". Used to lock the leaf-binding invariant (see
    // docs/adr/0006-x509-leaf-binding.md).
    const LEAF_B64: &str = "MIIEJDCCA86gAwIBAgIJAK+ii7kzrdrVMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tMCAXDTI1MTIyMTE1MjgzMFoYDzIxMjUxMTI3MTUyODMwWjB9MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEaMBgGA1UEAxMRVGVzdCBLZXkgcnNhLTIwNDgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxgGODQPffOmBsNcqYlo0wP8BmEqWjmw2qkfdzZn0SOv/fBXKBaZSvsXfr1JfyIPQYkedQ0X7b4Ch7PHe4ut1Q/x14A14PpHKXWDiAKRTrme2bILdRmyKRt6IIlwEyNzH3Zq8eN4U5THkdR1rTuYOzoNmF0xVeJ5xbK8Kv9CJof2y6gJGPimESvlcYGEyQZssWplj5s7AiwT/liBbhSN+ljmxVBFIiu6E+FdBYfI0yu1iZTe0qg7TAyk9xbD6+b7RQeOR7NmhA7gqg4HqzzrMfMou7fAeeaOv3LZP0zIRiyuy3ZUtCnwBHp2PgVyC8lHsezSxQ9VAO6efNc4cZCC/hAgMBAAGjggFFMIIBQTAMBgNVHRMEBTADAQH/MCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUfLcVH/BQDOsKB+e4exlYAtcz44MwgeMGA1UdIwSB2zCB2IAU/uTsUyTwlZXHELXhRLVdOWVa436hgbSkgbEwga4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMT0wOwYDVQQKEzRYTUwgU2VjdXJpdHkgTGlicmFyeSAoaHR0cDovL3d3dy5hbGVrc2V5LmNvbS94bWxzZWMpMRAwDgYDVQQLEwdSb290IENBMRYwFAYDVQQDEw1BbGVrc2V5IFNhbmluMSEwHwYJKoZIhvcNAQkBFhJ4bWxzZWNAYWxla3NleS5jb22CCQCvoou5M63arTANBgkqhkiG9w0BAQUFAANBAAOsjTIFAqagx0xAd+zha/Enk/4Qe6ZiQ4MYPi7U11mxnGLry5PHUjk6fzLfF4VRPSyqBZY70Ypzm246fauuHZw=";
    const ROOT_B64: &str = "MIID9zCCA2CgAwIBAgIJAK+ii7kzrdqsMA0GCSqGSIb3DQEBBQUAMIGuMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEQMA4GA1UECxMHUm9vdCBDQTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tMCAXDTE0MDUyMzE3NTA1OVoYDzIxMTQwNDI5MTc1MDU5WjCBrjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxEDAOBgNVBAsTB1Jvb3QgQ0ExFjAUBgNVBAMTDUFsZWtzZXkgU2FuaW4xITAfBgkqhkiG9w0BCQEWEnhtbHNlY0BhbGVrc2V5LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtY4MCNj/qrOzVuex1BD/PuCYTDDOLLVjtpKXQteQPqy0kgMwuQgRwdNnICIHQbnFKL40XoyACJVWKM7b0LkvWJNeyVzXPqEE9ZPmNxWGUjVcr7powT7v8V7S2QflUnr8ZvR4XWwkZJ9EYKNhenijgJ5yYDrXCWdvC+fnjBjv2LcCAwEAAaOCARcwggETMB0GA1UdDgQWBBQGtaSsp6p1ROoVnE/fBYNPah7+CzCB4wYDVR0jBIHbMIHYgBQGtaSsp6p1ROoVnE/fBYNPah7+C6GBtKSBsTCBrjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxEDAOBgNVBAsTB1Jvb3QgQ0ExFjAUBgNVBAMTDUFsZWtzZXkgU2FuaW4xITAfBgkqhkiG9w0BCQEWEnhtbHNlY0BhbGVrc2V5LmNvbYIJAK+ii7kzrdqsMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEARpb86RP/ck55X+NunXeIX81i763bj7Z1VJwFbA/QfupzxnqJ2IP/lxC8YxJ3Bp2IJMI7rC9r0poa41ZxI5rGHip97DpgsxPF9lkRUmKBBQjkICOq1w/4d2DRInBoqXttD+0WsqDfNDVK+7kSE07ytn3RzHCjj0gv0PdxmuCsR/E=";

    fn find_key_info(doc: &Document<'_>) -> NodeId {
        doc.descendants(doc.root())
            .into_iter()
            .find(|&id| {
                doc.element(id)
                    .is_some_and(|e| &*e.name.local_name == ns::node::KEY_INFO)
            })
            .expect("KeyInfo element present")
    }

    /// Build an RSA `KeyValue` fixture with caller-selected CryptoBinary text.
    ///
    /// The malformed-value regression tests use this helper to keep the XML
    /// shape realistic while changing only the modulus or exponent payload.
    fn rsa_key_value_xml(modulus: &str, exponent: &str) -> String {
        format!(
            concat!(
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                "<ds:KeyValue>",
                "<ds:RSAKeyValue>",
                "<ds:Modulus>{modulus}</ds:Modulus>",
                "<ds:Exponent>{exponent}</ds:Exponent>",
                "</ds:RSAKeyValue>",
                "</ds:KeyValue>",
                "</ds:KeyInfo>",
            ),
            modulus = modulus,
            exponent = exponent,
        )
    }

    fn find_key_value(doc: &Document<'_>) -> NodeId {
        doc.descendants(doc.root())
            .into_iter()
            .find(|&id| {
                doc.element(id)
                    .is_some_and(|e| &*e.name.local_name == ns::node::KEY_VALUE)
            })
            .expect("KeyValue element present")
    }

    /// A single hex digit is still an odd-length CryptoBinary value.
    ///
    /// This keeps diagnostics consistent for all-hex odd lengths, including
    /// the length-one case that never reaches byte-pair decoding.
    #[test]
    fn test_decode_crypto_binary_rejects_single_hex_digit_as_odd_length() {
        let engine = base64::engine::general_purpose::STANDARD;
        let err = decode_crypto_binary("a", &engine).expect_err("single hex digit must fail");

        assert!(
            err.contains("odd-length hex"),
            "single hex digit should be reported as odd-length hex: {err}"
        );
    }

    /// Odd-length hex in an RSA modulus must be a recoverable parse error.
    ///
    /// This is a regression test for malformed inline `KeyValue` XML that used
    /// to panic while slicing the final incomplete hex byte.
    #[test]
    fn test_rsa_key_value_rejects_odd_length_hex_modulus_without_panic() {
        let xml = rsa_key_value_xml("abc", "010001");
        let doc = uppsala::parse(&xml).expect("parse XML");

        let err = parse_rsa_key_value(find_key_value(&doc), &doc)
            .expect_err("odd-length modulus must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("Modulus"), "error should name Modulus: {msg}");
        assert!(
            msg.contains("odd-length hex"),
            "error should explain the malformed hex length: {msg}"
        );
    }

    /// Odd-length hex in an RSA exponent must also stay recoverable.
    ///
    /// The modulus is even-length hex so the test reaches exponent decoding and
    /// proves both RSA CryptoBinary fields are guarded.
    #[test]
    fn test_rsa_key_value_rejects_odd_length_hex_exponent_without_panic() {
        let xml = rsa_key_value_xml("010203", "abc");
        let doc = uppsala::parse(&xml).expect("parse XML");

        let err = parse_rsa_key_value(find_key_value(&doc), &doc)
            .expect_err("odd-length exponent must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Exponent"),
            "error should name Exponent: {msg}"
        );
        assert!(
            msg.contains("odd-length hex"),
            "error should explain the malformed hex length: {msg}"
        );
    }

    /// Regression test for the X.509 leaf-binding trust bypass
    /// (docs/adr/0006-x509-leaf-binding.md): even when the end-entity leaf is
    /// NOT the first `<X509Certificate>` in document order, the extracted
    /// `x509_chain[0]` must be the leaf whose public key becomes the signing
    /// key. Downstream chain validation uses `x509_chain[0]`; if it were merely
    /// the document-order-first cert, an attacker could get one cert validated
    /// against the anchors while the signature was checked with a different one.
    #[test]
    fn test_x509data_places_selected_leaf_first() {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let leaf_der = engine.decode(LEAF_B64).unwrap();

        // Adversarial ordering: CA/root FIRST, end-entity leaf SECOND.
        let xml = format!(
            concat!(
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                "<ds:X509Data>",
                "<ds:X509Certificate>{root}</ds:X509Certificate>",
                "<ds:X509Certificate>{leaf}</ds:X509Certificate>",
                "</ds:X509Data></ds:KeyInfo>"
            ),
            root = ROOT_B64,
            leaf = LEAF_B64
        );
        let doc = uppsala::parse(&xml).unwrap();
        let key = extract_key_value(find_key_info(&doc), &doc).expect("extract X509 key");

        assert_eq!(key.x509_chain.len(), 2, "all certs preserved in the chain");
        assert_eq!(
            key.x509_chain[0], leaf_der,
            "selected leaf must be x509_chain[0] regardless of document order"
        );
    }

    /// Sanity: the honest single-cert case is unchanged — the sole cert is the
    /// leaf and remains at index 0.
    #[test]
    fn test_x509data_single_cert_is_leaf() {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let leaf_der = engine.decode(LEAF_B64).unwrap();
        let xml = format!(
            concat!(
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                "<ds:X509Data><ds:X509Certificate>{leaf}</ds:X509Certificate></ds:X509Data>",
                "</ds:KeyInfo>"
            ),
            leaf = LEAF_B64
        );
        let doc = uppsala::parse(&xml).unwrap();
        let key = extract_key_value(find_key_info(&doc), &doc).expect("extract X509 key");
        assert_eq!(key.x509_chain, vec![leaf_der]);
    }

    /// Certificate-only extraction skips raw `KeyValue` entries even when they
    /// appear first in document order.
    ///
    /// Anchored DSig verification uses this helper to prefer an anchorable
    /// `<X509Data>` chain over raw document-controlled key material.
    #[test]
    fn test_extract_x509_key_value_skips_earlier_raw_keyvalue() {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let leaf_der = engine.decode(LEAF_B64).unwrap();
        let xml = format!(
            concat!(
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                "<ds:KeyValue>",
                "<ds:RSAKeyValue>",
                "<ds:Modulus>srryidgrlDw994IT7eEPDIpXrB8VW26cin5mm62FaQxlQ5jiiqd9+6iVGWfeSn8JV20do9M8iliZr0cVMfj7Ew==</ds:Modulus>",
                "<ds:Exponent>AQAB</ds:Exponent>",
                "</ds:RSAKeyValue>",
                "</ds:KeyValue>",
                "<ds:X509Data><ds:X509Certificate>{leaf}</ds:X509Certificate></ds:X509Data>",
                "</ds:KeyInfo>"
            ),
            leaf = LEAF_B64
        );
        let doc = uppsala::parse(&xml).unwrap();
        let key = extract_x509_key_value(find_key_info(&doc), &doc).expect("extract X509 key");
        assert_eq!(key.x509_chain, vec![leaf_der]);
    }
}
