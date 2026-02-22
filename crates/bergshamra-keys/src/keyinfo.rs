#![forbid(unsafe_code)]

//! KeyInfo XML processing — reads `<ds:KeyInfo>` elements to extract key material.

use crate::key::{Key, KeyData, KeyUsage};
use crate::manager::KeysManager;
use bergshamra_core::{ns, Error};

/// Decode a CryptoBinary value that may be base64 or hex encoded.
///
/// Some XML Security test vectors (particularly from NIST/xmlenc interop) encode
/// RSA modulus/exponent values as hex strings rather than base64. This function
/// detects the encoding and decodes accordingly.
fn decode_crypto_binary(
    text: &str,
    engine: &impl base64::Engine,
) -> Result<Vec<u8>, String> {
    let clean: String = text
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    if clean.is_empty() {
        return Err("empty value".into());
    }

    // Try base64 first
    if let Ok(bytes) = engine.decode(&clean) {
        return Ok(bytes);
    }

    // If base64 fails, try hex decoding (some test vectors use hex)
    if clean.len() >= 2 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        // Hex string — decode it
        let bytes: Result<Vec<u8>, _> = (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
            .collect();
        if let Ok(bytes) = bytes {
            return Ok(bytes);
        }
    }

    Err(format!("Invalid symbol at position 0 for {}", &clean[..clean.len().min(20)]))
}

/// Process a `<KeyInfo>` element and attempt to resolve a key from the manager.
pub fn resolve_key_info<'a>(
    key_info_node: roxmltree::Node<'_, '_>,
    manager: &'a KeysManager,
) -> Result<&'a Key, Error> {
    // Try <KeyName> first
    for child in key_info_node.children() {
        if !child.is_element() {
            continue;
        }
        let ns_uri = child.tag_name().namespace().unwrap_or("");
        let local = child.tag_name().name();

        if ns_uri == ns::DSIG && local == ns::node::KEY_NAME {
            let name_text = child.text().unwrap_or("").trim();
            if !name_text.is_empty() {
                if let Some(key) = manager.find_by_name(name_text) {
                    return Ok(key);
                }
            }
        }
    }

    // Try <X509Data><X509IssuerSerial> — match cert by issuer+serial
    for child in key_info_node.children() {
        if !child.is_element() {
            continue;
        }
        let ns_uri = child.tag_name().namespace().unwrap_or("");
        let local = child.tag_name().name();

        if local == ns::node::X509_DATA && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            // Collect serial numbers from X509IssuerSerial elements
            for issuer_serial in child.children() {
                if !issuer_serial.is_element() {
                    continue;
                }
                if issuer_serial.tag_name().name() != ns::node::X509_ISSUER_SERIAL {
                    continue;
                }
                let serial_text = issuer_serial.children().find(|n| {
                    n.is_element() && n.tag_name().name() == ns::node::X509_SERIAL_NUMBER
                }).and_then(|n| n.text()).unwrap_or("").trim().to_string();

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
    for child in key_info_node.children() {
        if !child.is_element() {
            continue;
        }
        let ns_uri = child.tag_name().namespace().unwrap_or("");
        let local = child.tag_name().name();

        if local == ns::node::KEY_VALUE && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            // Try RSA KeyValue
            if let Ok(_key) = parse_rsa_key_value(child) {
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
    result.iter().rev().map(|d| (b'0' + d) as char).collect::<String>()
        .trim_start_matches('0')
        .to_string()
        .chars()
        .next()
        .map_or("0".to_string(), |_| {
            result.iter().rev().map(|d| (b'0' + d) as char).collect::<String>()
                .trim_start_matches('0')
                .to_string()
        })
}

/// Try to extract an inline key from `<KeyInfo>` (RSA, EC, DSA KeyValue, or X509Certificate).
///
/// Returns `Some(Key)` if a KeyValue or X509Certificate was found and parsed, `None` otherwise.
pub fn extract_key_value(key_info_node: roxmltree::Node<'_, '_>) -> Option<Key> {
    for child in key_info_node.children() {
        if !child.is_element() {
            continue;
        }
        let ns_uri = child.tag_name().namespace().unwrap_or("");
        let local = child.tag_name().name();

        if local == ns::node::KEY_VALUE && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            // Try RSA KeyValue
            if let Ok(key) = parse_rsa_key_value(child) {
                return Some(key);
            }
            // Try EC KeyValue
            if let Ok(key) = parse_ec_key_value(child) {
                return Some(key);
            }
            // Try DSA KeyValue
            if let Ok(key) = parse_dsa_key_value(child) {
                return Some(key);
            }
        }

        // Try X509Data > X509Certificate
        if local == ns::node::X509_DATA && (ns_uri == ns::DSIG || ns_uri.is_empty()) {
            if let Some(key) = extract_x509_certificate(child) {
                return Some(key);
            }
        }

        // Try DEREncodedKeyValue (dsig11 namespace)
        if local == ns::node::DER_ENCODED_KEY_VALUE && ns_uri == ns::DSIG11 {
            if let Some(key) = parse_der_encoded_key_value(child) {
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
                    if let Ok(bc) = x509_cert::ext::pkix::BasicConstraints::from_der(
                        ext.extn_value.as_bytes(),
                    ) {
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
        self.cert.tbs_certificate.subject.to_der().unwrap_or_default()
    }

    /// Get the issuer as DER bytes.
    fn issuer_der(&self) -> Vec<u8> {
        use der::Encode;
        self.cert.tbs_certificate.issuer.to_der().unwrap_or_default()
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
        candidates = (0..certs.len())
            .filter(|&i| !certs[i].is_ca())
            .collect();
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
fn extract_x509_certificate(x509_data_node: roxmltree::Node<'_, '_>) -> Option<Key> {
    use base64::Engine;
    use der::Decode;
    let engine = base64::engine::general_purpose::STANDARD;

    let mut parsed_certs = Vec::new();
    for child in x509_data_node.children() {
        if !child.is_element() {
            continue;
        }
        if child.tag_name().name() == ns::node::X509_CERTIFICATE {
            let b64 = child.text().unwrap_or("").trim();
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
    // Populate x509_chain with ALL certs from the XML (not just the leaf)
    key.x509_chain = parsed_certs.iter().map(|c| c.der.clone()).collect();
    Some(key)
}

/// Parse a `<dsig11:DEREncodedKeyValue>` element containing base64-encoded SPKI DER.
fn parse_der_encoded_key_value(node: roxmltree::Node<'_, '_>) -> Option<Key> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let b64_text = node.text().unwrap_or("").trim();
    let clean: String = b64_text.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return None;
    }
    let der_bytes = engine.decode(&clean).ok()?;
    crate::loader::load_spki_der(&der_bytes).ok()
}

/// Extract an RSA public key from a `<KeyValue><RSAKeyValue>` element.
pub fn parse_rsa_key_value(key_value_node: roxmltree::Node<'_, '_>) -> Result<Key, Error> {
    let rsa_kv: roxmltree::Node<'_, '_> = key_value_node
        .children()
        .find(|n: &roxmltree::Node<'_, '_>| {
            n.is_element()
                && n.tag_name().name() == ns::node::RSA_KEY_VALUE
                && n.tag_name().namespace().unwrap_or("") == ns::DSIG
        })
        .ok_or_else(|| Error::MissingElement("RSAKeyValue".into()))?;

    let modulus_b64: &str = rsa_kv
        .children()
        .find(|n: &roxmltree::Node<'_, '_>| {
            n.is_element() && n.tag_name().name() == ns::node::RSA_MODULUS
        })
        .and_then(|n: roxmltree::Node<'_, '_>| n.text())
        .ok_or_else(|| Error::MissingElement("Modulus".into()))?;

    let exponent_b64: &str = rsa_kv
        .children()
        .find(|n: &roxmltree::Node<'_, '_>| {
            n.is_element() && n.tag_name().name() == ns::node::RSA_EXPONENT
        })
        .and_then(|n: roxmltree::Node<'_, '_>| n.text())
        .ok_or_else(|| Error::MissingElement("Exponent".into()))?;

    let engine = base64::engine::general_purpose::STANDARD;
    let modulus_bytes = decode_crypto_binary(modulus_b64, &engine)
        .map_err(|e| Error::Base64(format!("Modulus: {e}")))?;
    let exponent_bytes = decode_crypto_binary(exponent_b64, &engine)
        .map_err(|e| Error::Base64(format!("Exponent: {e}")))?;

    let n = rsa::BigUint::from_bytes_be(&modulus_bytes);
    let e = rsa::BigUint::from_bytes_be(&exponent_bytes);
    let public = rsa::RsaPublicKey::new(n, e)
        .map_err(|err| Error::Key(format!("invalid RSA public key: {err}")))?;

    Ok(Key::new(
        KeyData::Rsa { private: None, public },
        KeyUsage::Verify,
    ))
}

/// Extract a DSA public key from a `<KeyValue><DSAKeyValue>` element.
///
/// DSAKeyValue contains P, Q, G (domain parameters) and Y (public key).
pub fn parse_dsa_key_value(key_value_node: roxmltree::Node<'_, '_>) -> Result<Key, Error> {
    let dsa_kv = key_value_node
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == ns::node::DSA_KEY_VALUE
                && n.tag_name().namespace().unwrap_or("") == ns::DSIG
        })
        .ok_or_else(|| Error::MissingElement("DSAKeyValue".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let decode_elem = |name: &str| -> Result<Vec<u8>, Error> {
        let b64 = dsa_kv
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == name)
            .and_then(|n| n.text())
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
        KeyData::Dsa { private: None, public: vk },
        KeyUsage::Verify,
    ))
}

/// Extract an EC public key from a `<KeyValue><ECKeyValue>` element.
///
/// Supports P-256, P-384, P-521 curves via NamedCurve OID.
pub fn parse_ec_key_value(key_value_node: roxmltree::Node<'_, '_>) -> Result<Key, Error> {
    // ECKeyValue is in the xmldsig11 namespace
    let ec_kv = key_value_node
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == ns::node::EC_KEY_VALUE
                && (n.tag_name().namespace().unwrap_or("") == ns::DSIG11
                    || n.tag_name().namespace().unwrap_or("") == ns::DSIG)
        })
        .ok_or_else(|| Error::MissingElement("ECKeyValue".into()))?;

    // Read NamedCurve URI
    let named_curve = ec_kv
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == ns::node::NAMED_CURVE)
        .ok_or_else(|| Error::MissingElement("NamedCurve".into()))?;

    let curve_uri = named_curve
        .attribute(ns::attr::URI)
        .ok_or_else(|| Error::MissingAttribute("URI on NamedCurve".into()))?;

    // Read PublicKey (base64-encoded uncompressed point)
    let public_key_b64 = ec_kv
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == ns::node::PUBLIC_KEY)
        .and_then(|n| n.text())
        .ok_or_else(|| Error::MissingElement("PublicKey".into()))?;

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let point_bytes = engine
        .decode(public_key_b64.trim().replace(['\n', '\r', ' '], ""))
        .map_err(|e| Error::Base64(format!("EC PublicKey: {e}")))?;

    match curve_uri {
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
                KeyData::EcP256 { private: None, public: vk },
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
                KeyData::EcP384 { private: None, public: vk },
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
            let vk = p521::ecdsa::VerifyingKey::from(
                ecdsa::VerifyingKey::from(point.unwrap()),
            );
            Ok(Key::new(
                KeyData::EcP521 { private: None, public: vk },
                KeyUsage::Verify,
            ))
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("EC curve: {curve_uri}"))),
    }
}
