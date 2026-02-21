#![forbid(unsafe_code)]

//! XML-DSig signature creation.
//!
//! Signs an XML document using a template with empty DigestValue/SignatureValue.

use crate::context::DsigContext;
use bergshamra_c14n::C14nMode;
use bergshamra_core::{ns, Error};
use bergshamra_crypto::digest;
use bergshamra_xml::nodeset::NodeSet;
use std::collections::HashMap;

/// Sign an XML template document.
///
/// The template must contain a `<Signature>` element with empty
/// `<DigestValue>` and `<SignatureValue>` elements.
///
/// Returns the signed XML document as a string.
pub fn sign(ctx: &DsigContext, template_xml: &str) -> Result<String, Error> {
    let doc = roxmltree::Document::parse_with_options(template_xml, bergshamra_xml::parsing_options())
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    // Build ID map
    let mut id_attrs: Vec<&str> = vec!["Id", "ID", "id"];
    let extra: Vec<&str> = ctx.id_attrs.iter().map(|s| s.as_str()).collect();
    id_attrs.extend(extra);
    let id_map = build_id_map(&doc, &id_attrs);

    // Find Signature element
    let sig_node = find_element(&doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;
    let signed_info = find_child_element(sig_node, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    // Read CanonicalizationMethod
    let c14n_method = find_child_element(signed_info, ns::DSIG, ns::node::CANONICALIZATION_METHOD)
        .ok_or_else(|| Error::MissingElement("CanonicalizationMethod".into()))?;
    let c14n_uri = c14n_method
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on CanonicalizationMethod".into()))?;
    let c14n_mode = C14nMode::from_uri(c14n_uri)
        .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {c14n_uri}")))?;
    let inclusive_prefixes = read_inclusive_prefixes(c14n_method);

    // Read SignatureMethod
    let sig_method = find_child_element(signed_info, ns::DSIG, ns::node::SIGNATURE_METHOD)
        .ok_or_else(|| Error::MissingElement("SignatureMethod".into()))?;
    let sig_method_uri = sig_method
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on SignatureMethod".into()))?;

    // Process each Reference to compute digests
    let mut result_xml = template_xml.to_owned();
    let references = find_child_elements(signed_info, ns::DSIG, ns::node::REFERENCE);

    for reference in &references {
        let uri = reference.attribute(ns::attr::URI).unwrap_or("");
        let digest_method = find_child_element(*reference, ns::DSIG, ns::node::DIGEST_METHOD)
            .ok_or_else(|| Error::MissingElement("DigestMethod".into()))?;
        let digest_uri = digest_method
            .attribute(ns::attr::ALGORITHM)
            .ok_or_else(|| Error::MissingAttribute("Algorithm on DigestMethod".into()))?;

        // Resolve reference and apply transforms
        let mut data = if uri.is_empty() {
            // Per W3C spec: URI="" selects whole document without comments
            let ns = NodeSet::all_without_comments(&doc);
            bergshamra_transforms::TransformData::Xml {
                xml_text: template_xml.to_owned(),
                node_set: Some(ns),
            }
        } else if let Some(fragment) = bergshamra_xml::xpath::parse_same_document_ref(uri) {
            if fragment == "xpointer(/)" {
                bergshamra_transforms::TransformData::Xml {
                    xml_text: template_xml.to_owned(),
                    node_set: None,
                }
            } else {
                let is_xpointer = bergshamra_xml::xpath::parse_xpointer_id(fragment).is_some();
                let id = bergshamra_xml::xpath::parse_xpointer_id(fragment).unwrap_or(fragment);
                let node = bergshamra_xml::xpath::resolve_id(&doc, &id_map, id)?;
                let ns = if is_xpointer {
                    NodeSet::tree_with_comments(node)
                } else {
                    NodeSet::tree_without_comments(node)
                };
                bergshamra_transforms::TransformData::Xml {
                    xml_text: template_xml.to_owned(),
                    node_set: Some(ns),
                }
            }
        } else {
            // Try url-map for external URIs
            let mut resolved = None;
            for (map_url, file_path) in &ctx.url_maps {
                if uri == map_url || uri.starts_with(map_url) {
                    let bytes = std::fs::read(file_path)
                        .map_err(|e| Error::Other(format!("url-map {file_path}: {e}")))?;
                    resolved = Some(bergshamra_transforms::TransformData::Binary(bytes));
                    break;
                }
            }
            // Try resolving as a relative file path (no scheme = local file)
            if resolved.is_none() && !uri.contains("://") {
                if let Some(base) = &ctx.base_dir {
                    let path = std::path::Path::new(base).join(uri);
                    if path.exists() {
                        let bytes = std::fs::read(&path)
                            .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
                        resolved = Some(bergshamra_transforms::TransformData::Binary(bytes));
                    }
                }
                if resolved.is_none() {
                    let path = std::path::Path::new(uri);
                    if path.exists() {
                        let bytes = std::fs::read(path)
                            .map_err(|e| Error::Other(format!("{uri}: {e}")))?;
                        resolved = Some(bergshamra_transforms::TransformData::Binary(bytes));
                    }
                }
            }
            resolved.ok_or_else(|| Error::InvalidUri(format!("unsupported URI: {uri}")))?
        };
        let transforms_node = find_child_element(*reference, ns::DSIG, ns::node::TRANSFORMS);
        if let Some(transforms) = transforms_node {
            for t_node in transforms.children() {
                if !t_node.is_element() || t_node.tag_name().name() != ns::node::TRANSFORM {
                    continue;
                }
                let t_uri = t_node.attribute(ns::attr::ALGORITHM).unwrap_or("");
                data = crate::verify::apply_transform(t_uri, data, &t_node, sig_node)?;
            }
        }

        let bytes = data.to_binary()?;
        let computed = digest::digest(digest_uri, &bytes)?;

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let digest_b64 = engine.encode(&computed);

        // Replace the empty DigestValue in the result XML
        // This is a simple text replacement — works for templates
        // where DigestValue elements are initially empty.
        let digest_value_text = find_child_element(*reference, ns::DSIG, ns::node::DIGEST_VALUE)
            .and_then(|n| n.text())
            .unwrap_or("");

        if digest_value_text.trim().is_empty() {
            result_xml = replace_first_empty_element(&result_xml, "DigestValue", &digest_b64);
        }
    }

    // Now canonicalize SignedInfo and compute signature
    // Re-parse the updated XML
    let updated_doc = roxmltree::Document::parse_with_options(&result_xml, bergshamra_xml::parsing_options())
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;
    let updated_sig = find_element(&updated_doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;
    let updated_signed_info = find_child_element(updated_sig, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    let signed_info_ns = NodeSet::tree_without_comments(updated_signed_info);
    let c14n_signed_info = bergshamra_c14n::canonicalize_doc(
        &updated_doc,
        c14n_mode,
        Some(&signed_info_ns),
        &inclusive_prefixes,
    )?;

    // Sign
    let key = ctx.keys_manager.first_key()?;
    let signing_key = key
        .to_signing_key()
        .ok_or_else(|| Error::Key("no signing key".into()))?;

    // Extract PQ context string for ML-DSA/SLH-DSA signing
    let pq_context: Option<Vec<u8>> = if bergshamra_crypto::sign::is_pq_algorithm(sig_method_uri) {
        let ctx_node = find_child_element(sig_method, ns::XMLSEC_PQ, ns::node::MLDSA_CONTEXT_STRING)
            .or_else(|| find_child_element(sig_method, ns::XMLSEC_PQ, ns::node::SLHDSA_CONTEXT_STRING));
        if let Some(cn) = ctx_node {
            let b64 = cn.text().unwrap_or("").trim();
            if b64.is_empty() {
                None
            } else {
                use base64::Engine as _;
                let engine = base64::engine::general_purpose::STANDARD;
                let decoded = engine.decode(b64)
                    .map_err(|e| Error::Base64(format!("PQ context string: {e}")))?;
                Some(decoded)
            }
        } else {
            None
        }
    } else {
        None
    };

    let sig_alg = bergshamra_crypto::sign::from_uri_with_context(sig_method_uri, pq_context)?;
    let mut signature = sig_alg.sign(&signing_key, &c14n_signed_info)?;

    // Truncate HMAC output if HMACOutputLength is specified
    if bergshamra_crypto::sign::is_hmac_algorithm(sig_method_uri) {
        if let Some(hmac_len_node) = find_child_element(sig_method, ns::DSIG, ns::node::HMAC_OUTPUT_LENGTH) {
            let len_text = hmac_len_node.text().unwrap_or("").trim();
            if let Ok(bits) = len_text.parse::<usize>() {
                if bits % 8 == 0 {
                    let bytes = bits / 8;
                    if bytes < signature.len() {
                        signature.truncate(bytes);
                    }
                }
            }
        }
    }

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let sig_b64 = engine.encode(&signature);

    // Replace empty SignatureValue
    result_xml = replace_first_empty_element(&result_xml, "SignatureValue", &sig_b64);

    // Populate empty X509Data with certificate(s) from the signing key
    if !key.x509_chain.is_empty() {
        result_xml = populate_x509_data(&result_xml, &key.x509_chain)?;
    }

    // Populate empty KeyValue with the public key
    result_xml = populate_key_value(&result_xml, &key.data)?;

    // Populate empty DEREncodedKeyValue with SPKI DER
    result_xml = populate_der_encoded_key_value(&result_xml, &key.data)?;

    Ok(result_xml)
}

// Re-use helpers from verify module
fn find_element<'a>(doc: &'a roxmltree::Document<'a>, ns_uri: &str, local_name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    doc.descendants().find(|n| n.is_element() && n.tag_name().name() == local_name && n.tag_name().namespace().unwrap_or("") == ns_uri)
}

fn find_child_element<'a>(parent: roxmltree::Node<'a, 'a>, ns_uri: &str, local_name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    parent.children().find(|n| n.is_element() && n.tag_name().name() == local_name && n.tag_name().namespace().unwrap_or("") == ns_uri)
}

fn find_child_elements<'a>(parent: roxmltree::Node<'a, 'a>, ns_uri: &str, local_name: &str) -> Vec<roxmltree::Node<'a, 'a>> {
    parent.children().filter(|n| n.is_element() && n.tag_name().name() == local_name && n.tag_name().namespace().unwrap_or("") == ns_uri).collect()
}

fn build_id_map(doc: &roxmltree::Document<'_>, attr_names: &[&str]) -> HashMap<String, roxmltree::NodeId> {
    let mut map = HashMap::new();
    for node in doc.descendants() {
        if node.is_element() {
            for attr_name in attr_names {
                if let Some(val) = node.attribute(*attr_name) {
                    map.insert(val.to_owned(), node.id());
                }
            }
            // Also check xml:id (XML namespace)
            if let Some(val) = node.attribute(("http://www.w3.org/XML/1998/namespace", "id")) {
                map.insert(val.to_owned(), node.id());
            }
        }
    }
    map
}

/// Replace the text content of the first XML element whose body is empty or
/// whitespace-only.  Handles self-closing tags and arbitrary namespace prefixes.
fn replace_first_empty_element(xml: &str, local_name: &str, new_content: &str) -> String {
    // Use roxmltree to find the element's byte range for accurate replacement
    if let Ok(doc) = roxmltree::Document::parse_with_options(xml, bergshamra_xml::parsing_options()) {
        for node in doc.descendants() {
            if !node.is_element() || node.tag_name().name() != local_name {
                continue;
            }
            // Check if this is a dsig element (or unnamespaced)
            let ns = node.tag_name().namespace().unwrap_or("");
            if !ns.is_empty() && ns != ns::DSIG {
                continue;
            }
            // Check if content is empty or whitespace-only
            let text = node.text().unwrap_or("").trim();
            if !text.is_empty() {
                continue;
            }
            // Found an empty element — replace it
            let range = node.range();
            let original = &xml[range.start..range.end];
            // Extract the tag prefix from the original XML
            let prefix = extract_tag_prefix(original, local_name);
            let replacement = if prefix.is_empty() {
                format!("<{local_name}>{new_content}</{local_name}>")
            } else {
                format!("<{prefix}:{local_name}>{new_content}</{prefix}:{local_name}>")
            };
            let mut result = String::with_capacity(xml.len() + new_content.len());
            result.push_str(&xml[..range.start]);
            result.push_str(&replacement);
            result.push_str(&xml[range.end..]);
            return result;
        }
    }
    xml.to_string()
}

/// Extract namespace prefix from a raw XML tag fragment like `<ds:SignatureValue/>`.
fn extract_tag_prefix<'a>(xml_fragment: &'a str, local_name: &str) -> &'a str {
    let trimmed = xml_fragment.trim_start_matches('<');
    if let Some(colon_pos) = trimmed.find(':') {
        let after_colon = &trimmed[colon_pos + 1..];
        if after_colon.starts_with(local_name) {
            return &trimmed[..colon_pos];
        }
    }
    ""
}

/// Extract the opening tag from a raw XML fragment, preserving all attributes
/// and namespace declarations. Converts self-closing `/>` to `>`.
///
/// E.g. `<dsig11:Foo xmlns:dsig11="..."/>` → `<dsig11:Foo xmlns:dsig11="...">`
fn extract_open_tag(raw_xml: &str) -> String {
    if let Some(slash_gt) = raw_xml.find("/>") {
        format!("{}>", &raw_xml[..slash_gt])
    } else if let Some(gt) = raw_xml.find('>') {
        raw_xml[..=gt].to_string()
    } else {
        raw_xml.to_string()
    }
}

/// Populate empty `<X509Data/>` element in the signed XML with certificates.
///
/// Handles two cases:
/// 1. `<X509Data/>` (self-closing, no children) — inserts X509Certificate elements
/// 2. `<X509Data>` with empty child template elements like `<X509SubjectName/>`,
///    `<X509IssuerSerial/>`, `<X509SKI/>`, `<X509Certificate/>` — populates each
fn populate_x509_data(xml: &str, x509_chain: &[Vec<u8>]) -> Result<String, Error> {
    let doc = roxmltree::Document::parse_with_options(xml, bergshamra_xml::parsing_options())
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    // Find X509Data element in KeyInfo
    let x509_data = doc.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == ns::node::X509_DATA
            && n.tag_name().namespace().unwrap_or("") == ns::DSIG
    });

    let x509_data = match x509_data {
        Some(n) => n,
        None => return Ok(xml.to_owned()),
    };

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    // Check if empty (no child elements) — simple case
    let has_children = x509_data.children().any(|c| c.is_element());
    if !has_children {
        // Build X509Certificate elements
        let mut certs_xml = String::new();
        let prefix = extract_tag_prefix(&xml[x509_data.range().start..x509_data.range().end], "X509Data");
        for cert_der in x509_chain {
            let cert_b64 = engine.encode(cert_der);
            if prefix.is_empty() {
                certs_xml.push_str(&format!("<X509Certificate>{cert_b64}</X509Certificate>"));
            } else {
                certs_xml.push_str(&format!("<{prefix}:X509Certificate>{cert_b64}</{prefix}:X509Certificate>"));
            }
        }

        let range = x509_data.range();
        let replacement = if prefix.is_empty() {
            format!("<X509Data>{certs_xml}</X509Data>")
        } else {
            let orig = &xml[range.start..range.end];
            let ns_decl = format!("xmlns:{prefix}=");
            if orig.contains(&ns_decl) {
                format!("<X509Data>{certs_xml}</X509Data>")
            } else {
                format!("<{prefix}:X509Data>{certs_xml}</{prefix}:X509Data>")
            }
        };

        let mut result = String::with_capacity(xml.len() + certs_xml.len());
        result.push_str(&xml[..range.start]);
        result.push_str(&replacement);
        result.push_str(&xml[range.end..]);
        return Ok(result);
    }

    // Template case: X509Data has child elements that need populating
    // Parse the first certificate to extract subject, issuer, serial, SKI
    let first_cert_der = match x509_chain.first() {
        Some(c) => c,
        None => return Ok(xml.to_owned()),
    };

    let cert_info = extract_x509_info(first_cert_der);

    // Process child elements — replace each empty one with populated content
    let mut result = xml.to_owned();
    // Process in reverse order of byte offset so replacements don't shift ranges
    let mut children_to_process: Vec<_> = x509_data.children()
        .filter(|c| c.is_element())
        .collect();
    children_to_process.sort_by(|a, b| b.range().start.cmp(&a.range().start));

    for child in children_to_process {
        let name = child.tag_name().name();
        let child_text = child.text().unwrap_or("").trim();
        if !child_text.is_empty() {
            continue; // Already has content
        }

        let raw = &result[child.range().start..child.range().end];
        let prefix = extract_tag_prefix(raw, name);

        let replacement = match name {
            "X509Certificate" => {
                let cert_b64 = engine.encode(first_cert_der);
                if prefix.is_empty() {
                    format!("<X509Certificate>{cert_b64}</X509Certificate>")
                } else {
                    format!("<{prefix}:X509Certificate>{cert_b64}</{prefix}:X509Certificate>")
                }
            }
            "X509SubjectName" => {
                if let Some(ref subj) = cert_info.subject_name {
                    if prefix.is_empty() {
                        format!("<X509SubjectName>{subj}</X509SubjectName>")
                    } else {
                        format!("<{prefix}:X509SubjectName>{subj}</{prefix}:X509SubjectName>")
                    }
                } else {
                    continue;
                }
            }
            "X509IssuerSerial" => {
                if let (Some(ref issuer), Some(ref serial)) = (&cert_info.issuer_name, &cert_info.serial_number) {
                    if prefix.is_empty() {
                        format!("<X509IssuerSerial><X509IssuerName>{issuer}</X509IssuerName><X509SerialNumber>{serial}</X509SerialNumber></X509IssuerSerial>")
                    } else {
                        format!("<{prefix}:X509IssuerSerial><{prefix}:X509IssuerName>{issuer}</{prefix}:X509IssuerName><{prefix}:X509SerialNumber>{serial}</{prefix}:X509SerialNumber></{prefix}:X509IssuerSerial>")
                    }
                } else {
                    continue;
                }
            }
            "X509SKI" => {
                if let Some(ref ski_b64) = cert_info.ski_b64 {
                    if prefix.is_empty() {
                        format!("<X509SKI>{ski_b64}</X509SKI>")
                    } else {
                        format!("<{prefix}:X509SKI>{ski_b64}</{prefix}:X509SKI>")
                    }
                } else {
                    continue;
                }
            }
            _ => continue, // X509CRL and others — skip
        };

        let range = child.range();
        let mut new_result = String::with_capacity(result.len() + replacement.len());
        new_result.push_str(&result[..range.start]);
        new_result.push_str(&replacement);
        new_result.push_str(&result[range.end..]);
        result = new_result;
    }

    Ok(result)
}

/// Extracted X.509 certificate info for template population.
struct X509Info {
    subject_name: Option<String>,
    issuer_name: Option<String>,
    serial_number: Option<String>,
    ski_b64: Option<String>,
}

/// Extract X.509 info from a DER-encoded certificate.
fn extract_x509_info(cert_der: &[u8]) -> X509Info {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = match Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => return X509Info { subject_name: None, issuer_name: None, serial_number: None, ski_b64: None },
    };

    let subject_name = Some(format_rdn_sequence(&cert.tbs_certificate.subject));
    let issuer_name = Some(format_rdn_sequence(&cert.tbs_certificate.issuer));
    let serial_number = Some(format_serial(&cert.tbs_certificate.serial_number));

    // Extract SKI from extensions
    let ski_b64 = extract_ski(&cert);

    X509Info { subject_name, issuer_name, serial_number, ski_b64 }
}

/// Format an X.500 Name (RDN sequence) as a comma-separated string.
/// Uses the RFC 2253 / xmlsec convention.
fn format_rdn_sequence(name: &x509_cert::name::Name) -> String {
    use der::oid::db::rfc4519;
    use der::Decode;
    use std::fmt::Write;

    let mut parts = Vec::new();
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            let oid = &atv.oid;
            let prefix = if *oid == rfc4519::CN {
                "CN"
            } else if *oid == rfc4519::O {
                "O"
            } else if *oid == rfc4519::OU {
                "OU"
            } else if *oid == rfc4519::C {
                "C"
            } else if *oid == rfc4519::ST {
                "ST"
            } else if *oid == rfc4519::L {
                "L"
            } else if *oid == rfc4519::SERIAL_NUMBER {
                "serialNumber"
            } else {
                // Use OID dot notation for unknown types
                let mut s = String::new();
                let _ = write!(s, "{oid}");
                parts.push(s);
                continue;
            };

            // Decode the value - try UTF8String, then PrintableString, then raw bytes
            let val = decode_atv_value(&atv.value);
            parts.push(format!("{prefix}={val}"));
        }
    }

    // xmlsec outputs in reverse order (most specific first)
    parts.reverse();
    parts.join(",")
}

/// Decode an AttributeValue (ASN.1 Any) to a string.
fn decode_atv_value(val: &der::Any) -> String {
    use der::Decode;

    // Try UTF8String
    if let Ok(s) = der::asn1::Utf8StringRef::from_der(val.value()) {
        return s.as_str().to_string();
    }
    // Try PrintableString
    if let Ok(s) = der::asn1::PrintableStringRef::from_der(val.value()) {
        return s.as_str().to_string();
    }
    // Try IA5String
    if let Ok(s) = der::asn1::Ia5StringRef::from_der(val.value()) {
        return s.as_str().to_string();
    }
    // Fall back to raw UTF-8 interpretation of the value bytes
    String::from_utf8_lossy(val.value()).to_string()
}

/// Format serial number as a decimal string.
fn format_serial(serial: &x509_cert::serial_number::SerialNumber) -> String {
    // SerialNumber is an ASN.1 INTEGER — get the raw bytes
    let bytes = serial.as_bytes();

    // Convert big-endian bytes to decimal
    if bytes.is_empty() {
        return "0".to_string();
    }

    // Check if negative (high bit set)
    let is_negative = bytes[0] & 0x80 != 0;
    if is_negative {
        // Two's complement — rare for serial numbers but handle it
        return format_negative_serial(bytes);
    }

    // Positive: convert bytes to decimal
    let mut result = Vec::new();
    let mut remainder = bytes.to_vec();

    // Simple big-integer division
    loop {
        let (quotient, rem) = big_divmod(&remainder, 10);
        result.push(b'0' + rem);
        if quotient.is_empty() || (quotient.len() == 1 && quotient[0] == 0) {
            break;
        }
        remainder = quotient;
    }

    result.reverse();
    String::from_utf8(result).unwrap_or_else(|_| "0".to_string())
}

fn format_negative_serial(bytes: &[u8]) -> String {
    // Negate the two's complement and prepend minus sign
    let mut negated = bytes.to_vec();
    let mut carry = true;
    for b in negated.iter_mut().rev() {
        *b = !*b;
        if carry {
            let (val, c) = b.overflowing_add(1);
            *b = val;
            carry = c;
        }
    }
    let result = format_serial_bytes(&negated);
    format!("-{result}")
}

fn format_serial_bytes(bytes: &[u8]) -> String {
    let mut result = Vec::new();
    let mut remainder = bytes.to_vec();
    loop {
        let (quotient, rem) = big_divmod(&remainder, 10);
        result.push(b'0' + rem);
        if quotient.is_empty() || (quotient.len() == 1 && quotient[0] == 0) {
            break;
        }
        remainder = quotient;
    }
    result.reverse();
    String::from_utf8(result).unwrap_or_else(|_| "0".to_string())
}

/// Divide a big-endian byte array by a small divisor, return (quotient, remainder).
fn big_divmod(bytes: &[u8], divisor: u8) -> (Vec<u8>, u8) {
    let mut quotient = Vec::with_capacity(bytes.len());
    let mut rem: u16 = 0;
    for &b in bytes {
        rem = rem * 256 + b as u16;
        quotient.push((rem / divisor as u16) as u8);
        rem %= divisor as u16;
    }
    // Strip leading zeros
    while quotient.len() > 1 && quotient[0] == 0 {
        quotient.remove(0);
    }
    (quotient, rem as u8)
}

/// Extract Subject Key Identifier from certificate extensions.
fn extract_ski(cert: &x509_cert::Certificate) -> Option<String> {
    use base64::Engine;
    use der::Decode;

    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        // SKI OID: 2.5.29.14
        if ext.extn_id == der::oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER {
            // The value is an OCTET STRING wrapping an OCTET STRING
            let octet = der::asn1::OctetString::from_der(ext.extn_value.as_bytes()).ok()?;
            return Some(base64::engine::general_purpose::STANDARD.encode(octet.as_bytes()));
        }
    }
    None
}

/// Populate an empty `<KeyValue/>` element with the signing key's public key.
fn populate_key_value(xml: &str, key_data: &bergshamra_keys::key::KeyData) -> Result<String, Error> {
    let doc = roxmltree::Document::parse_with_options(xml, bergshamra_xml::parsing_options())
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    let kv_node = doc.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == ns::node::KEY_VALUE
            && n.tag_name().namespace().unwrap_or("") == ns::DSIG
    });

    let kv_node = match kv_node {
        Some(n) => n,
        None => return Ok(xml.to_owned()),
    };

    // Only populate if empty
    if kv_node.children().any(|c| c.is_element()) {
        return Ok(xml.to_owned());
    }
    let text = kv_node.text().unwrap_or("").trim();
    if !text.is_empty() {
        return Ok(xml.to_owned());
    }

    let prefix = extract_tag_prefix(&xml[kv_node.range().start..kv_node.range().end], "KeyValue");
    let inner_xml = match key_data.to_key_value_xml(prefix) {
        Some(xml_fragment) => xml_fragment,
        None => return Ok(xml.to_owned()),
    };

    let range = kv_node.range();
    let replacement = if prefix.is_empty() {
        format!("<KeyValue>{inner_xml}</KeyValue>")
    } else {
        format!("<{prefix}:KeyValue>{inner_xml}</{prefix}:KeyValue>")
    };

    let mut result = String::with_capacity(xml.len() + replacement.len());
    result.push_str(&xml[..range.start]);
    result.push_str(&replacement);
    result.push_str(&xml[range.end..]);
    Ok(result)
}

/// Populate an empty `<DEREncodedKeyValue/>` element with the SPKI DER of the signing key.
fn populate_der_encoded_key_value(xml: &str, key_data: &bergshamra_keys::key::KeyData) -> Result<String, Error> {
    let doc = roxmltree::Document::parse_with_options(xml, bergshamra_xml::parsing_options())
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    let dek_node = doc.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == ns::node::DER_ENCODED_KEY_VALUE
            && n.tag_name().namespace().unwrap_or("") == ns::DSIG11
    });

    let dek_node = match dek_node {
        Some(n) => n,
        None => return Ok(xml.to_owned()),
    };

    // Only populate if empty
    if dek_node.children().any(|c| c.is_element()) {
        return Ok(xml.to_owned());
    }
    let text = dek_node.text().unwrap_or("").trim();
    if !text.is_empty() {
        return Ok(xml.to_owned());
    }

    let spki_der = match key_data.to_spki_der() {
        Some(der) => der,
        None => return Ok(xml.to_owned()),
    };

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&spki_der);

    // Reconstruct the element with the base64 content, preserving namespace declarations.
    let raw_tag = &xml[dek_node.range().start..dek_node.range().end];
    let prefix = extract_tag_prefix(raw_tag, ns::node::DER_ENCODED_KEY_VALUE);

    // Extract the opening tag with all its attributes/xmlns declarations
    let open_tag = extract_open_tag(raw_tag);
    let closing_tag = if prefix.is_empty() {
        "</DEREncodedKeyValue>".to_string()
    } else {
        format!("</{prefix}:DEREncodedKeyValue>")
    };
    let replacement = format!("{open_tag}{b64}{closing_tag}");

    let range = dek_node.range();
    let mut result = String::with_capacity(xml.len() + replacement.len());
    result.push_str(&xml[..range.start]);
    result.push_str(&replacement);
    result.push_str(&xml[range.end..]);
    Ok(result)
}

fn read_inclusive_prefixes(node: roxmltree::Node<'_, '_>) -> Vec<String> {
    for child in node.children() {
        if child.is_element() && child.tag_name().name() == ns::node::INCLUSIVE_NAMESPACES {
            if let Some(prefix_list) = child.attribute(ns::attr::PREFIX_LIST) {
                return prefix_list.split_whitespace().map(|s| s.to_owned()).collect();
            }
        }
    }
    Vec::new()
}
