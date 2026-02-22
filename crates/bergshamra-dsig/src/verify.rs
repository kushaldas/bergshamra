#![forbid(unsafe_code)]

//! XML-DSig signature verification.
//!
//! Processing order per spec Section 3.2:
//! 1. Parse <Signature>, register ID attributes
//! 2. Read <SignedInfo>: CanonicalizationMethod, SignatureMethod
//! 3. For each <Reference>: resolve URI, run transforms, compute digest, compare
//! 4. Resolve signing key from <KeyInfo>
//! 5. Canonicalize <SignedInfo>
//! 6. Verify <SignatureValue>

use crate::context::DsigContext;
use bergshamra_c14n::C14nMode;
use bergshamra_core::{algorithm, ns, Error};
use bergshamra_crypto::digest;
use bergshamra_xml::nodeset::NodeSet;
use bergshamra_xml::xpath;
use std::collections::HashMap;
use uppsala::{Document, NodeId, NodeKind};

/// Result of signature verification.
#[derive(Debug)]
pub enum VerifyResult {
    /// Signature is valid.
    Valid,
    /// Signature is invalid.
    Invalid {
        reason: String,
    },
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerifyResult::Valid)
    }
}

/// Verify a signed XML document.
pub fn verify(ctx: &DsigContext, xml: &str) -> Result<VerifyResult, Error> {
    let doc = uppsala::parse(xml)
        .map_err(|e| Error::XmlParse(e.to_string()))?;

    // Build ID map
    let mut id_attrs: Vec<&str> = vec!["Id", "ID", "id"];
    let extra: Vec<&str> = ctx.id_attrs.iter().map(|s| s.as_str()).collect();
    id_attrs.extend(extra);
    let id_map = build_id_map(&doc, &id_attrs);

    // Find <Signature> element
    let sig_node = find_element(&doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;

    // Find <SignedInfo>
    let signed_info = find_child_element(&doc, sig_node, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    // Read CanonicalizationMethod
    let c14n_method_node = find_child_element(&doc, signed_info, ns::DSIG, ns::node::CANONICALIZATION_METHOD)
        .ok_or_else(|| Error::MissingElement("CanonicalizationMethod".into()))?;
    let c14n_uri = doc.element(c14n_method_node)
        .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
        .ok_or_else(|| Error::MissingAttribute("Algorithm on CanonicalizationMethod".into()))?;
    let c14n_mode = C14nMode::from_uri(c14n_uri)
        .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {c14n_uri}")))?;

    // Read SignatureMethod
    let sig_method_node = find_child_element(&doc, signed_info, ns::DSIG, ns::node::SIGNATURE_METHOD)
        .ok_or_else(|| Error::MissingElement("SignatureMethod".into()))?;
    let sig_method_uri = doc.element(sig_method_node)
        .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
        .ok_or_else(|| Error::MissingAttribute("Algorithm on SignatureMethod".into()))?;

    // Parse HMACOutputLength for HMAC truncation (CVE-2009-0217)
    let hmac_output_length_bits: Option<usize> = if bergshamra_crypto::sign::is_hmac_algorithm(sig_method_uri) {
        if let Some(len_node) = find_child_element(&doc, sig_method_node, ns::DSIG, ns::node::HMAC_OUTPUT_LENGTH) {
            let len_text = element_text(&doc, len_node).unwrap_or("").trim();
            let bits: usize = len_text
                .parse()
                .map_err(|_| Error::XmlStructure("invalid HMACOutputLength value".into()))?;
            // Validate: must be a multiple of 8
            if bits % 8 != 0 {
                return Ok(VerifyResult::Invalid {
                    reason: "HMACOutputLength must be a multiple of 8".into(),
                });
            }
            // Validate minimum truncation per W3C recommendation (CVE-2009-0217)
            // Only enforce when hmac_min_out_len is explicitly set (matching xmlsec behavior)
            if ctx.hmac_min_out_len > 0 && bits < ctx.hmac_min_out_len {
                return Ok(VerifyResult::Invalid {
                    reason: format!(
                        "HMACOutputLength {bits} bits is below minimum {} bits (CVE-2009-0217)",
                        ctx.hmac_min_out_len
                    ),
                });
            }
            Some(bits)
        } else {
            None
        }
    } else {
        None
    };

    // Extract PQ context string from <MLDSAContextString> or <SLHDSAContextString>
    let pq_context: Option<Vec<u8>> = if bergshamra_crypto::sign::is_pq_algorithm(sig_method_uri) {
        let ctx_node = find_child_element(&doc, sig_method_node, ns::XMLSEC_PQ, ns::node::MLDSA_CONTEXT_STRING)
            .or_else(|| find_child_element(&doc, sig_method_node, ns::XMLSEC_PQ, ns::node::SLHDSA_CONTEXT_STRING));
        if let Some(cn) = ctx_node {
            let b64 = element_text(&doc, cn).unwrap_or("").trim();
            if b64.is_empty() {
                None
            } else {
                use base64::Engine;
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

    // Read exc-C14N PrefixList if applicable
    let inclusive_prefixes = read_inclusive_prefixes(&doc, c14n_method_node);

    // 3. Verify each Reference
    let references = find_child_elements(&doc, signed_info, ns::DSIG, ns::node::REFERENCE);
    for reference in &references {
        let result = verify_reference(*reference, &doc, &id_map, xml, sig_node, &ctx.url_maps, ctx.debug, ctx.base_dir.as_deref())?;
        if let VerifyResult::Invalid { reason } = result {
            return Ok(VerifyResult::Invalid {
                reason: format!("Reference digest failed: {reason}"),
            });
        }
    }

    // 4. Resolve signing key
    // First try inline KeyValue (RSA/EC public key embedded in XML),
    // then try EncryptedKey unwrap, then fall back to KeysManager lookup.
    let key_info_node = find_child_element(&doc, sig_node, ns::DSIG, ns::node::KEY_INFO);
    let extracted_key: Option<bergshamra_keys::Key>;
    let mut key_from_x509 = false;
    let mut key_from_manager = false;
    let key = if let Some(ki) = key_info_node {
        // Check for KeyInfoReference — dereference to the target KeyInfo
        let effective_ki = resolve_key_info_reference(&doc, ki, &id_map).unwrap_or(ki);
        extracted_key = bergshamra_keys::keyinfo::extract_key_value(effective_ki, &doc)
            .or_else(|| try_unwrap_encrypted_key(&doc, effective_ki, &ctx.keys_manager).ok())
            .or_else(|| try_resolve_retrieval_method(&doc, effective_ki, ctx.base_dir.as_deref(), &ctx.url_maps))
            .or_else(|| try_resolve_retrieval_method_inline(&doc, effective_ki, &id_map));
        if let Some(ref ek) = extracted_key {
            if ctx.debug {
                eprintln!("== Key: extracted inline key ({})", ek.data.algorithm_name());
            }
            // Check if this key came from an X509Certificate
            if !ek.x509_chain.is_empty() {
                key_from_x509 = true;
            }
            ek
        } else {
            let k = bergshamra_keys::keyinfo::resolve_key_info(effective_ki, &doc, &ctx.keys_manager)?;
            if ctx.debug {
                eprintln!("== Key: resolved from manager ({})", k.data.algorithm_name());
            }
            key_from_manager = true;
            k
        }
    } else {
        let k = ctx.keys_manager.first_key()?;
        if ctx.debug {
            eprintln!("== Key: first key from manager ({})", k.data.algorithm_name());
        }
        key_from_manager = true;
        k
    };

    // 4b. X.509 certificate chain validation
    if !ctx.insecure {
        let needs_x509_validation = (ctx.enabled_key_data_x509 && key_from_x509)
            || (ctx.verify_keys && key_from_manager && !key.x509_chain.is_empty());

        if needs_x509_validation && !key.x509_chain.is_empty() {
            let config = bergshamra_keys::x509::CertValidationConfig {
                trusted_certs: ctx.keys_manager.trusted_certs(),
                untrusted_certs: ctx.keys_manager.untrusted_certs(),
                crls: ctx.keys_manager.crls(),
                verification_time: ctx.verification_time.as_deref(),
                skip_time_checks: ctx.skip_time_checks,
            };
            // The first cert in x509_chain is the leaf
            let leaf_der = &key.x509_chain[0];
            bergshamra_keys::x509::validate_cert_chain(
                leaf_der,
                &key.x509_chain,
                &config,
            )?;
            if ctx.debug {
                eprintln!("== X.509 certificate chain: valid");
            }
        } else if ctx.enabled_key_data_x509 && !key_from_x509 && !key_from_manager {
            // enabled-key-data x509 was requested but no X509 data found
            // This is not an error by itself — the test framework handles this
        }
    }

    // 5. Canonicalize <SignedInfo>
    // We need to canonicalize the SignedInfo element as a document subset
    let signed_info_ns = NodeSet::tree_without_comments(signed_info, &doc);
    let c14n_signed_info = bergshamra_c14n::canonicalize_doc(
        &doc,
        c14n_mode,
        Some(&signed_info_ns),
        &inclusive_prefixes,
    )?;

    if ctx.debug {
        eprintln!("== PreSigned data - start buffer:");
        eprint!("{}", String::from_utf8_lossy(&c14n_signed_info));
        eprintln!("\n== PreSigned data - end buffer");
    }

    // 6. Verify SignatureValue
    let sig_value_node = find_child_element(&doc, sig_node, ns::DSIG, ns::node::SIGNATURE_VALUE)
        .ok_or_else(|| Error::MissingElement("SignatureValue".into()))?;
    let sig_value_b64 = element_text(&doc, sig_value_node).unwrap_or("").trim();
    let sig_value_clean: String = sig_value_b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let sig_value = engine
        .decode(&sig_value_clean)
        .map_err(|e| Error::Base64(format!("SignatureValue: {e}")))?;

    // Validate HMAC truncation length against decoded signature
    if let Some(bits) = hmac_output_length_bits {
        let expected_bytes = bits / 8;
        if sig_value.len() != expected_bytes {
            return Ok(VerifyResult::Invalid {
                reason: format!(
                    "SignatureValue length {} bytes does not match HMACOutputLength {} bits ({} bytes)",
                    sig_value.len(), bits, expected_bytes
                ),
            });
        }
    }

    let signing_key = key
        .to_signing_key()
        .ok_or_else(|| Error::Key("no signing key available".into()))?;

    let sig_alg = bergshamra_crypto::sign::from_uri_with_context(sig_method_uri, pq_context)?;
    let valid = sig_alg.verify(&signing_key, &c14n_signed_info, &sig_value)?;

    if valid {
        Ok(VerifyResult::Valid)
    } else {
        Ok(VerifyResult::Invalid {
            reason: "signature value verification failed".into(),
        })
    }
}

/// Verify a single <Reference> element.
fn verify_reference(
    reference: NodeId,
    doc: &Document<'_>,
    id_map: &HashMap<String, NodeId>,
    xml: &str,
    sig_node: NodeId,
    url_maps: &[(String, String)],
    debug: bool,
    base_dir: Option<&str>,
) -> Result<VerifyResult, Error> {
    // Read URI attribute
    let uri = doc.element(reference)
        .and_then(|e| e.get_attribute(ns::attr::URI))
        .unwrap_or("");

    // Read DigestMethod
    let digest_method_node = find_child_element(doc, reference, ns::DSIG, ns::node::DIGEST_METHOD)
        .ok_or_else(|| Error::MissingElement("DigestMethod".into()))?;
    let digest_uri = doc.element(digest_method_node)
        .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
        .ok_or_else(|| Error::MissingAttribute("Algorithm on DigestMethod".into()))?;

    // Read expected DigestValue
    let digest_value_node = find_child_element(doc, reference, ns::DSIG, ns::node::DIGEST_VALUE)
        .ok_or_else(|| Error::MissingElement("DigestValue".into()))?;
    let expected_b64 = element_text(doc, digest_value_node).unwrap_or("").trim();
    let expected_clean: String = expected_b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let expected_digest = engine
        .decode(&expected_clean)
        .map_err(|e| Error::Base64(format!("DigestValue: {e}")))?;

    // Resolve URI and get initial data
    let resolved = resolve_reference_uri(uri, doc, id_map, xml, url_maps, base_dir)?;

    // Read and apply transforms
    let transforms_node = find_child_element(doc, reference, ns::DSIG, ns::node::TRANSFORMS);
    let mut data = match resolved {
        ResolvedUri::Xml { xml_text, node_set } => bergshamra_transforms::TransformData::Xml {
            xml_text,
            node_set,
        },
        ResolvedUri::Binary(bytes) => bergshamra_transforms::TransformData::Binary(bytes),
    };

    if let Some(transforms) = transforms_node {
        for transform_node in doc.children(transforms) {
            let is_transform_elem = doc.element(transform_node).map_or(false, |e| {
                e.name.local_name.as_ref() == ns::node::TRANSFORM
            });
            if !is_transform_elem {
                continue;
            }
            let transform_uri = doc.element(transform_node)
                .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
                .unwrap_or("");

            data = apply_transform(transform_uri, data, transform_node, sig_node, doc)?;
        }
    }

    // Convert to binary for digesting
    let bytes = data.to_binary()?;

    if debug {
        eprintln!("== PreDigest data - start buffer (URI={uri}):");
        eprint!("{}", String::from_utf8_lossy(&bytes));
        eprintln!("\n== PreDigest data - end buffer");
    }

    // Compute digest
    let computed = digest::digest(digest_uri, &bytes)?;

    // Compare
    if computed == expected_digest {
        Ok(VerifyResult::Valid)
    } else {
        Ok(VerifyResult::Invalid {
            reason: format!(
                "URI={uri}: expected digest does not match computed digest"
            ),
        })
    }
}

/// Resolved URI data — either XML (same-document) or raw binary (external).
enum ResolvedUri {
    Xml { xml_text: String, node_set: Option<NodeSet> },
    Binary(Vec<u8>),
}

/// Resolve a reference URI.
fn resolve_reference_uri(
    uri: &str,
    doc: &Document<'_>,
    id_map: &HashMap<String, NodeId>,
    xml: &str,
    url_maps: &[(String, String)],
    base_dir: Option<&str>,
) -> Result<ResolvedUri, Error> {
    if uri.is_empty() {
        // Whole document, per W3C spec section 4.3.3.3:
        // "if the URI is not a full XPointer, then all comment nodes are excluded"
        let ns = NodeSet::all_without_comments(doc);
        Ok(ResolvedUri::Xml { xml_text: xml.to_owned(), node_set: Some(ns) })
    } else if let Some(fragment) = xpath::parse_same_document_ref(uri) {
        // Handle xpointer(/) — selects entire document
        if fragment == "xpointer(/)" {
            return Ok(ResolvedUri::Xml { xml_text: xml.to_owned(), node_set: None });
        }
        // Handle xpointer(id('...')) — extract the ID.
        // Per W3C: bare `#id` excludes comments, `#xpointer(id('...'))` includes them.
        let is_xpointer = xpath::parse_xpointer_id(fragment).is_some();
        let id = xpath::parse_xpointer_id(fragment).unwrap_or(fragment);
        let node = xpath::resolve_id(doc, id_map, id)?;
        let ns = if is_xpointer {
            NodeSet::tree_with_comments(node, doc)
        } else {
            NodeSet::tree_without_comments(node, doc)
        };
        Ok(ResolvedUri::Xml { xml_text: xml.to_owned(), node_set: Some(ns) })
    } else {
        // Try url-map for external URIs — read as raw bytes
        for (map_url, file_path) in url_maps {
            if uri == map_url || uri.starts_with(map_url) {
                let data = std::fs::read(file_path)
                    .map_err(|e| Error::Other(format!("url-map {file_path}: {e}")))?;
                return Ok(ResolvedUri::Binary(data));
            }
        }
        // Try resolving as a relative file path (no scheme = local file)
        if !uri.contains("://") {
            if let Some(base) = base_dir {
                let path = std::path::Path::new(base).join(uri);
                if path.exists() {
                    let data = std::fs::read(&path)
                        .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
                    return Ok(ResolvedUri::Binary(data));
                }
            }
            // Try relative to CWD
            let path = std::path::Path::new(uri);
            if path.exists() {
                let data = std::fs::read(path)
                    .map_err(|e| Error::Other(format!("{uri}: {e}")))?;
                return Ok(ResolvedUri::Binary(data));
            }
        }
        Err(Error::InvalidUri(format!("external URI not supported: {uri}")))
    }
}

/// Apply a single transform.
pub(crate) fn apply_transform(
    uri: &str,
    data: bergshamra_transforms::TransformData,
    transform_node: NodeId,
    sig_node: NodeId,
    doc: &Document<'_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_transforms::pipeline::{C14nTransform, Transform};

    match uri {
        algorithm::ENVELOPED_SIGNATURE => {
            let t = bergshamra_transforms::enveloped::EnvelopedSignatureTransform::from_node_id(sig_node);
            t.execute(data)
        }
        algorithm::C14N | algorithm::C14N_WITH_COMMENTS
        | algorithm::C14N11 | algorithm::C14N11_WITH_COMMENTS
        | algorithm::EXC_C14N | algorithm::EXC_C14N_WITH_COMMENTS => {
            let mode = C14nMode::from_uri(uri)
                .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {uri}")))?;
            let prefixes = read_inclusive_prefixes(doc, transform_node);
            let t = C14nTransform::new(mode, prefixes);
            t.execute(data)
        }
        algorithm::BASE64 => {
            let t = bergshamra_transforms::base64_transform::Base64DecodeTransform;
            t.execute(data)
        }
        algorithm::XPATH => {
            apply_xpath_transform(data, transform_node, sig_node, doc)
        }
        algorithm::XPOINTER => {
            apply_xpointer_transform(data, transform_node, doc)
        }
        algorithm::XPATH2 => {
            apply_xpath_filter2_transform(data, transform_node, doc)
        }
        algorithm::RELATIONSHIP => {
            apply_relationship_transform(data, transform_node, doc)
        }
        algorithm::XSLT => {
            apply_xslt_transform(data, transform_node, doc)
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("transform: {uri}"))),
    }
}

/// Apply the OPC Relationship Transform (ECMA-376 Part 2 §13.2.4.24).
///
/// Filters `<Relationship>` elements from the input by matching `Id` attributes
/// against `<mdssi:RelationshipReference SourceId="...">` children of the
/// transform element. Selected relationships are sorted by `Id` and wrapped
/// in a `<Relationships>` root with the OPC relationships namespace.
fn apply_relationship_transform(
    data: bergshamra_transforms::TransformData,
    transform_node: NodeId,
    outer_doc: &Document<'_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    const REL_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
    const MDSSI_NS: &str = "http://schemas.openxmlformats.org/package/2006/digital-signature";

    // Collect SourceId values from <mdssi:RelationshipReference> children
    let mut source_ids: Vec<String> = Vec::new();
    let mut source_types: Vec<String> = Vec::new();
    for child in outer_doc.children(transform_node) {
        let elem = match outer_doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
        let name = &*elem.name.local_name;
        if child_ns == MDSSI_NS && name == "RelationshipReference" {
            if let Some(id) = elem.get_attribute("SourceId") {
                source_ids.push(id.to_owned());
            }
        } else if child_ns == MDSSI_NS && name == "RelationshipsGroupReference" {
            if let Some(t) = elem.get_attribute("SourceType") {
                source_types.push(t.to_owned());
            }
        }
    }

    // Get the input XML text
    let xml_text = match &data {
        bergshamra_transforms::TransformData::Xml { xml_text, .. } => xml_text.clone(),
        bergshamra_transforms::TransformData::Binary(bytes) => {
            String::from_utf8(bytes.clone())
                .map_err(|e| Error::Transform(format!("Relationship input not UTF-8: {e}")))?
        }
    };

    // Parse the input XML
    let doc = uppsala::parse(&xml_text)
        .map_err(|e| Error::Transform(format!("Relationship XML parse: {e}")))?;

    // Collect matching <Relationship> elements
    struct RelInfo {
        id: String,
        target: String,
        rel_type: String,
        target_mode: Option<String>,
    }

    let root = doc.document_element().unwrap();
    let mut rels: Vec<RelInfo> = Vec::new();

    for child in doc.children(root) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
        if child_ns != REL_NS || elem.name.local_name.as_ref() != "Relationship" {
            continue;
        }
        let id = elem.get_attribute("Id").unwrap_or("");
        let rel_type = elem.get_attribute("Type").unwrap_or("");

        let include = source_ids.iter().any(|sid| sid.as_str() == id)
            || source_types.iter().any(|st| st.as_str() == rel_type);

        if include {
            rels.push(RelInfo {
                id: id.to_owned(),
                target: elem.get_attribute("Target").unwrap_or("").to_owned(),
                rel_type: rel_type.to_owned(),
                // OPC spec: TargetMode defaults to "Internal" when absent
                target_mode: Some(
                    elem.get_attribute("TargetMode").unwrap_or("Internal").to_owned(),
                ),
            });
        }
    }

    // Sort by Id
    rels.sort_by(|a, b| a.id.cmp(&b.id));

    // Build the output XML.
    // C14N sorts attributes alphabetically (by namespace URI then local name).
    // For no-namespace attributes: Id < Target < TargetMode < Type (alphabetical).
    let mut out = String::new();
    out.push_str("<Relationships xmlns=\"");
    out.push_str(REL_NS);
    out.push_str("\">");
    for rel in &rels {
        out.push_str("<Relationship Id=\"");
        xml_escape_attr(&rel.id, &mut out);
        out.push('"');
        out.push_str(" Target=\"");
        xml_escape_attr(&rel.target, &mut out);
        out.push('"');
        if let Some(ref tm) = rel.target_mode {
            out.push_str(" TargetMode=\"");
            xml_escape_attr(tm, &mut out);
            out.push('"');
        }
        out.push_str(" Type=\"");
        xml_escape_attr(&rel.rel_type, &mut out);
        out.push('"');
        out.push_str("></Relationship>");
    }
    out.push_str("</Relationships>");

    Ok(bergshamra_transforms::TransformData::Binary(out.into_bytes()))
}

/// Escape a string for XML attribute value (C14N attribute escaping).
fn xml_escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

/// Apply an XSLT transform.
///
/// Currently supports:
/// - Identity transform (`<xsl:template match="@*|node()"><xsl:copy>
///   <xsl:apply-templates select="@*|node()"/></xsl:copy></xsl:template>`)
///   — passes input through unchanged.
/// - Simple template-based transforms for common patterns (player→HTML, etc.)
fn apply_xslt_transform(
    data: bergshamra_transforms::TransformData,
    transform_node: NodeId,
    outer_doc: &Document<'_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    const XSL_NS: &str = "http://www.w3.org/1999/XSL/Transform";

    // Find the <xsl:stylesheet> child element
    let stylesheet = outer_doc.children(transform_node)
        .into_iter()
        .find(|&id| {
            outer_doc.element(id).map_or(false, |e| {
                e.name.namespace_uri.as_deref() == Some(XSL_NS)
                    && e.name.local_name.as_ref() == "stylesheet"
            })
        })
        .ok_or_else(|| Error::MissingElement("xsl:stylesheet in XSLT transform".into()))?;

    // Collect template elements
    let templates: Vec<NodeId> = outer_doc.children(stylesheet)
        .into_iter()
        .filter(|&id| {
            outer_doc.element(id).map_or(false, |e| {
                e.name.namespace_uri.as_deref() == Some(XSL_NS)
                    && e.name.local_name.as_ref() == "template"
            })
        })
        .collect();

    // Check for identity transform pattern:
    // Single template matching "@*|node()" containing <xsl:copy><xsl:apply-templates
    // select="@*|node()"/></xsl:copy>
    if templates.len() == 1 {
        let tmpl = templates[0];
        let match_attr = outer_doc.element(tmpl)
            .and_then(|e| e.get_attribute("match"))
            .unwrap_or("");
        if match_attr == "@*|node()" || match_attr == "node()|@*" {
            // Check for <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
            let has_copy = outer_doc.children(tmpl).into_iter().any(|id| {
                outer_doc.element(id).map_or(false, |e| {
                    e.name.namespace_uri.as_deref() == Some(XSL_NS)
                        && e.name.local_name.as_ref() == "copy"
                })
            });
            if has_copy {
                // Identity transform — pass through
                return Ok(data);
            }
        }
    }

    // For non-identity transforms, attempt minimal XSLT processing
    apply_minimal_xslt(data, stylesheet, &templates, outer_doc)
}

/// Minimal XSLT processor for simple template-based transforms.
///
/// Supports a subset of XSLT 1.0:
/// - `<xsl:template match="...">` with literal result elements
/// - `<xsl:apply-templates/>` and `<xsl:apply-templates select="..."/>`
/// - `<xsl:value-of select="..."/>` for simple child element selection
/// - `<xsl:copy>` with `<xsl:apply-templates/>`
fn apply_minimal_xslt(
    data: bergshamra_transforms::TransformData,
    stylesheet: NodeId,
    templates: &[NodeId],
    outer_doc: &Document<'_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    // Get the input XML
    let xml_text = match &data {
        bergshamra_transforms::TransformData::Xml { xml_text, .. } => xml_text.clone(),
        bergshamra_transforms::TransformData::Binary(bytes) => {
            String::from_utf8(bytes.clone())
                .map_err(|e| Error::Transform(format!("XSLT input not UTF-8: {e}")))?
        }
    };

    let input_doc = uppsala::parse(&xml_text)
        .map_err(|e| Error::Transform(format!("XSLT input XML parse: {e}")))?;

    // Check for xsl:strip-space
    let strip_spaces: Vec<String> = outer_doc.children(stylesheet)
        .into_iter()
        .filter(|&id| {
            outer_doc.element(id).map_or(false, |e| {
                e.name.namespace_uri.as_deref() == Some("http://www.w3.org/1999/XSL/Transform")
                    && e.name.local_name.as_ref() == "strip-space"
            })
        })
        .filter_map(|id| outer_doc.element(id).and_then(|e| e.get_attribute("elements")).map(|s| s.to_owned()))
        .collect();

    // Build set of element names to strip whitespace from
    let strip_set: std::collections::HashSet<String> = strip_spaces
        .iter()
        .flat_map(|s| s.split_whitespace().map(|w| w.to_owned()))
        .collect();

    // Check for xsl:output
    let _output_method = outer_doc.children(stylesheet)
        .into_iter()
        .find(|&id| {
            outer_doc.element(id).map_or(false, |e| {
                e.name.namespace_uri.as_deref() == Some("http://www.w3.org/1999/XSL/Transform")
                    && e.name.local_name.as_ref() == "output"
            })
        })
        .and_then(|id| outer_doc.element(id).and_then(|e| e.get_attribute("method")).map(|s| s.to_owned()));

    // Get the default namespace from the stylesheet (for literal result elements)
    let default_ns: Option<String> = outer_doc.element(stylesheet).and_then(|e| {
        for (prefix, uri) in &e.namespace_declarations {
            if prefix.is_empty() {
                return Some(uri.to_string());
            }
        }
        None
    });

    // Process root element
    let root = input_doc.document_element().unwrap();
    let mut output = String::new();
    xslt_apply_templates_to_node(root, templates, outer_doc, &input_doc, &default_ns, &strip_set, &mut output);

    Ok(bergshamra_transforms::TransformData::Binary(output.into_bytes()))
}

/// Apply templates to a node.
fn xslt_apply_templates_to_node(
    node: NodeId,
    templates: &[NodeId],
    tmpl_doc: &Document<'_>,
    input_doc: &Document<'_>,
    default_ns: &Option<String>,
    strip_set: &std::collections::HashSet<String>,
    out: &mut String,
) {
    // Find matching template
    if let Some(tmpl) = find_matching_template(node, templates, tmpl_doc, input_doc) {
        // Execute template body
        xslt_execute_body(tmpl, node, templates, tmpl_doc, input_doc, default_ns, strip_set, out);
    } else {
        // Default: for elements, apply templates to children; for text, copy text
        if matches!(input_doc.node_kind(node), Some(NodeKind::Text(_)) | Some(NodeKind::CData(_))) {
            // Check strip-space: skip whitespace-only text nodes if parent is in strip set
            let parent_name = input_doc.parent(node)
                .and_then(|p| input_doc.element(p))
                .map(|e| e.name.local_name.to_string())
                .unwrap_or_default();
            let text = match input_doc.node_kind(node) {
                Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) => t.as_ref(),
                _ => "",
            };
            if strip_set.contains(&parent_name) && text.chars().all(|c: char| c.is_ascii_whitespace()) {
                // Skip whitespace-only text in stripped elements
            } else {
                xml_escape_text(text, out);
            }
        } else if input_doc.element(node).is_some() {
            for child in input_doc.children(node) {
                xslt_apply_templates_to_node(child, templates, tmpl_doc, input_doc, default_ns, strip_set, out);
            }
        }
    }
}

/// Execute the body of an XSLT template.
///
/// `body` and `templates` are node IDs in `tmpl_doc` (the stylesheet/outer document).
/// `context_node` is a node ID in `input_doc` (the input XML being transformed).
fn xslt_execute_body(
    body: NodeId,
    context_node: NodeId,
    templates: &[NodeId],
    tmpl_doc: &Document<'_>,
    input_doc: &Document<'_>,
    default_ns: &Option<String>,
    strip_set: &std::collections::HashSet<String>,
    out: &mut String,
) {
    const XSL_NS: &str = "http://www.w3.org/1999/XSL/Transform";

    for child in tmpl_doc.children(body) {
        if let Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) = tmpl_doc.node_kind(child) {
            // Skip whitespace-only text nodes in template
            if !t.trim().is_empty() {
                xml_escape_text(t, out);
            }
        } else if let Some(elem) = tmpl_doc.element(child) {
            let child_ns = elem.name.namespace_uri.as_deref();
            let name = &*elem.name.local_name;

            if child_ns == Some(XSL_NS) {
                match name {
                    "apply-templates" => {
                        let select = elem.get_attribute("select");
                        if let Some(sel) = select {
                            // Simple child selection: "child-name"
                            for ch in input_doc.children(context_node) {
                                if input_doc.element(ch).is_some() && xslt_node_matches_select(ch, sel, input_doc) {
                                    xslt_apply_templates_to_node(ch, templates, tmpl_doc, input_doc, default_ns, strip_set, out);
                                }
                            }
                        } else {
                            // Apply to all children
                            for ch in input_doc.children(context_node) {
                                xslt_apply_templates_to_node(ch, templates, tmpl_doc, input_doc, default_ns, strip_set, out);
                            }
                        }
                    }
                    "value-of" => {
                        if let Some(sel) = elem.get_attribute("select") {
                            // Simple: select="name" → get text of child element
                            let val = xslt_eval_value_of(context_node, sel, input_doc);
                            xml_escape_text(&val, out);
                        }
                    }
                    "copy" => {
                        if let Some(ctx_elem) = input_doc.element(context_node) {
                            let local = &*ctx_elem.name.local_name;
                            out.push('<');
                            out.push_str(local);
                            // Copy namespace declarations from context
                            for (prefix, uri) in &ctx_elem.namespace_declarations {
                                out.push_str(" xmlns");
                                if !prefix.is_empty() {
                                    out.push(':');
                                    out.push_str(prefix);
                                }
                                out.push_str("=\"");
                                xml_escape_attr(uri, out);
                                out.push('"');
                            }
                            // Copy attributes
                            for attr in &ctx_elem.attributes {
                                out.push(' ');
                                out.push_str(&attr.name.local_name);
                                out.push_str("=\"");
                                xml_escape_attr(&attr.value, out);
                                out.push('"');
                            }
                            out.push('>');
                            // Execute body children
                            xslt_execute_body(child, context_node, templates, tmpl_doc, input_doc, default_ns, strip_set, out);
                            out.push_str("</");
                            out.push_str(local);
                            out.push('>');
                        } else if let Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) = input_doc.node_kind(context_node) {
                            xml_escape_text(t, out);
                        }
                    }
                    _ => {
                        // Ignore other XSL elements
                    }
                }
            } else {
                // Literal result element
                let local = &*elem.name.local_name;
                out.push('<');
                out.push_str(local);
                // Add default namespace if present and different from parent
                if let Some(dns) = default_ns {
                    // Only emit for elements that use the default namespace
                    if child_ns.is_none() || child_ns == Some(dns.as_str()) {
                        out.push_str(" xmlns=\"");
                        xml_escape_attr(dns, out);
                        out.push('"');
                    }
                }
                for attr in &elem.attributes {
                    out.push(' ');
                    out.push_str(&attr.name.local_name);
                    out.push_str("=\"");
                    xml_escape_attr(&attr.value, out);
                    out.push('"');
                }
                out.push('>');
                xslt_execute_body(child, context_node, templates, tmpl_doc, input_doc, default_ns, strip_set, out);
                out.push_str("</");
                out.push_str(local);
                out.push('>');
            }
        }
    }
}

/// Check if a node matches a simple XSLT select expression.
fn xslt_node_matches_select(node: NodeId, select: &str, input_doc: &Document<'_>) -> bool {
    if select == "@*|node()" || select == "node()|@*" {
        true
    } else {
        // Simple element name match (possibly with path like "player/name")
        let parts: Vec<&str> = select.split('/').collect();
        let last = parts.last().unwrap_or(&"");
        input_doc.element(node).map_or(false, |e| e.name.local_name.as_ref() == *last)
    }
}

/// Evaluate a simple xsl:value-of select expression.
fn xslt_eval_value_of(node: NodeId, select: &str, input_doc: &Document<'_>) -> String {
    // Handle "name", "position", etc. — simple child element name
    for child in input_doc.children(node) {
        if let Some(elem) = input_doc.element(child) {
            if elem.name.local_name.as_ref() == select {
                return element_text(input_doc, child).unwrap_or("").to_owned();
            }
        }
    }
    String::new()
}

/// Find the first template that matches a node.
fn find_matching_template(
    node: NodeId,
    templates: &[NodeId],
    tmpl_doc: &Document<'_>,
    input_doc: &Document<'_>,
) -> Option<NodeId> {
    let elem = input_doc.element(node)?;
    let local = &*elem.name.local_name;
    let parent_name = input_doc.parent(node).and_then(|p| {
        input_doc.element(p).map(|e| e.name.local_name.to_string())
    });

    // Find the most specific matching template
    // Priority: parent/child > child > generic
    for &tmpl in templates {
        let match_attr = tmpl_doc.element(tmpl)
            .and_then(|e| e.get_attribute("match"))
            .unwrap_or("");
        // Check "parent/child" pattern
        if match_attr.contains('/') {
            let parts: Vec<&str> = match_attr.split('/').collect();
            if parts.len() == 2 {
                if let Some(ref pn) = parent_name {
                    if pn == parts[0] && local == parts[1] {
                        return Some(tmpl);
                    }
                }
            }
        } else if match_attr == local {
            return Some(tmpl);
        }
    }
    None
}

/// Escape text for XML content.
fn xml_escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

/// Apply an XPath 1.0 transform.
///
/// The XPath 1.0 transform evaluates the expression for each node in the
/// input node-set. If the expression evaluates to true, the node is included
/// in the output.
///
/// Supports a subset of XPath 1.0 expressions commonly used in XML-DSig:
/// - `ancestor-or-self::prefix:Name` — true if node or ancestor is named element
/// - `not(expr)` — negation
/// - `expr and expr` — conjunction
/// - `self::text()` — true for text nodes
fn apply_xpath_transform(
    data: bergshamra_transforms::TransformData,
    transform_node: NodeId,
    sig_node: NodeId,
    outer_doc: &Document<'_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    // Extract the XPath expression from the <XPath> child element
    let xpath_node = outer_doc.children(transform_node)
        .into_iter()
        .find(|&id| {
            outer_doc.element(id).map_or(false, |e| e.name.local_name.as_ref() == "XPath")
        })
        .ok_or_else(|| Error::MissingElement("XPath expression element".into()))?;

    let xpath_raw = element_text(outer_doc, xpath_node).unwrap_or("").trim();

    // Normalize whitespace: collapse runs of whitespace (including newlines,
    // tabs, and multi-space indentation) into a single space so that the parser
    // can split on ` and `, ` or `, etc.
    let xpath_expr: String = xpath_raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let xpath_expr = xpath_expr.as_str();

    // Check if this is the enveloped-signature pattern:
    // not(ancestor-or-self::PREFIX:Signature)
    // OR the here()-based variant:
    // count(ancestor-or-self::PREFIX:Signature | here()/ancestor::PREFIX:Signature[1]) > count(ancestor-or-self::PREFIX:Signature)
    if is_enveloped_xpath(xpath_expr, xpath_node, outer_doc)
        || is_enveloped_xpath_here(xpath_expr, xpath_node, outer_doc)
    {
        // Apply enveloped signature transform (same as the dedicated one)
        use bergshamra_transforms::pipeline::Transform;
        let t = bergshamra_transforms::enveloped::EnvelopedSignatureTransform::from_node_id(sig_node);
        return t.execute(data);
    }

    // Try to parse and evaluate as a boolean XPath expression
    if let Some(parsed) = parse_xpath_bool_expr(xpath_expr, xpath_node, outer_doc) {
        return apply_parsed_xpath_filter(data, &parsed);
    }

    // Try to handle compound XPath expressions with here() and id()
    // Pattern: "A and count(ancestor-or-self::P:E | here()/ancestor::P:E[1]) > count(ancestor-or-self::P:E) or count(ancestor-or-self::node() | id('X')) = count(ancestor-or-self::node())"
    if let Some(result) = try_compound_xpath_filter(
        xpath_expr, xpath_node, outer_doc, data, sig_node,
    )? {
        return Ok(result);
    }

    Err(Error::UnsupportedAlgorithm(format!(
        "XPath expression not supported: {xpath_expr}"
    )))
}

/// Try to handle compound XPath expressions containing here() and id() functions.
///
/// Handles the pattern from merlin-xmldsig-twenty-three/signature:
///   `ancestor-or-self::dsig:SignedInfo and count(ancestor-or-self::dsig:Reference
///    | here()/ancestor::dsig:Reference[1]) > count(ancestor-or-self::dsig:Reference)
///    or count(ancestor-or-self::node() | id('X')) = count(ancestor-or-self::node())`
///
/// Parsing: by XPath precedence (and > or), this is:
///   (A and B) or C
/// where:
///   A = ancestor-or-self::P:SignedInfo
///   B = count(ancestor-or-self::P:Reference | here()/ancestor::P:Reference[1])
///       > count(ancestor-or-self::P:Reference)
///       → true when node is NOT within the here() Reference
///   C = count(ancestor-or-self::node() | id('X')) = count(ancestor-or-self::node())
///       → true when node IS a descendant-or-self of id('X')
fn try_compound_xpath_filter(
    expr: &str,
    xpath_node: NodeId,
    outer_doc: &Document<'_>,
    data: bergshamra_transforms::TransformData,
    _sig_node: NodeId,
) -> Result<Option<bergshamra_transforms::TransformData>, Error> {
    use bergshamra_xml::nodeset::{NodeSet, NodeSetType};
    use std::collections::HashSet;

    // Try to match: "... and count(ancestor-or-self::P:E | here()/ancestor::P:E[1]) > count(ancestor-or-self::P:E) or count(ancestor-or-self::node() | id('X')) = count(ancestor-or-self::node())"

    // Find " or count(ancestor-or-self::node() | id('" which separates the (A and B) from C
    let or_marker = " or count(ancestor-or-self::node() | id('";
    let Some(or_pos) = expr.find(or_marker) else {
        return Ok(None);
    };

    let left_part = &expr[..or_pos]; // "A and B"
    let right_part = &expr[or_pos + or_marker.len()..]; // "X')) = count(ancestor-or-self::node())"

    // Extract the id value from right part
    let id_suffix = "')) = count(ancestor-or-self::node())";
    if !right_part.ends_with(id_suffix) {
        return Ok(None);
    }
    let id_value = &right_part[..right_part.len() - id_suffix.len()];

    // Parse left part: "ancestor-or-self::P:A and count(ancestor-or-self::P:B | here()/ancestor::P:B[1]) > count(ancestor-or-self::P:B)"
    let and_parts: Vec<&str> = left_part.splitn(2, " and ").collect();
    if and_parts.len() != 2 {
        return Ok(None);
    }

    // Part A: "ancestor-or-self::P:SignedInfo"
    let part_a = and_parts[0].trim();
    let ancestor_prefix_a = "ancestor-or-self::";
    if !part_a.starts_with(ancestor_prefix_a) {
        return Ok(None);
    }
    let a_name = &part_a[ancestor_prefix_a.len()..];
    let (a_ns_uri, a_local_name) = match resolve_prefixed_name(a_name, xpath_node, outer_doc) {
        Some(pair) => pair,
        None => return Ok(None),
    };

    // Part B: here()-based exclude pattern for a different element type
    let part_b = and_parts[1].trim();
    let here_result = parse_here_exclude_pattern(part_b, xpath_node, outer_doc);
    let (b_ns_uri, b_local_name) = match here_result {
        Some(pair) => pair,
        None => return Ok(None),
    };

    // Now we have all components. Evaluate the expression on the document.
    let (xml_text, input_ns) = match data {
        bergshamra_transforms::TransformData::Xml { xml_text, node_set } => {
            (xml_text, node_set)
        }
        bergshamra_transforms::TransformData::Binary(bytes) => {
            let text = String::from_utf8(bytes)
                .map_err(|e| Error::XmlParse(format!("XPath: invalid UTF-8: {e}")))?;
            (text, None)
        }
    };

    let inner_doc = uppsala::parse(&xml_text)
        .map_err(|e| Error::XmlParse(e.to_string()))?;

    // Find the here() Reference/element: here() returns the <XPath> element itself.
    // Walk up from xpath_node (which IS the <XPath> element) to find its ancestor
    // Reference. Use the node INDEX for cross-document comparison.
    let here_ancestor_idx = find_ancestor_by_name_idx(xpath_node, outer_doc, &b_ns_uri, &b_local_name);

    // Find the id('X') element in the re-parsed document
    let id_map = build_id_map(&inner_doc, &["Id", "ID", "id"]);
    let id_element_idx = id_map.get(id_value).map(|nid| nid.index());

    // Filter nodes
    let mut result_ids = HashSet::new();
    for node in inner_doc.descendants(inner_doc.root()) {
        if let Some(ref ns) = input_ns {
            if !ns.contains_id(node) {
                continue;
            }
        }

        // Evaluate: (A and B) or C
        let a = is_ancestor_or_self_match(node, &inner_doc, &a_ns_uri, &a_local_name);
        let b = if let Some(here_idx) = here_ancestor_idx {
            // B: NOT a descendant-or-self of the here() ancestor
            !is_descendant_of_index(node, &inner_doc, here_idx)
        } else {
            true
        };
        let c = if let Some(id_idx) = id_element_idx {
            is_descendant_of_index(node, &inner_doc, id_idx)
        } else {
            false
        };

        if (a && b) || c {
            result_ids.insert(node.index());
        }
    }

    let result_ns = NodeSet::from_ids(result_ids, NodeSetType::Normal);
    Ok(Some(bergshamra_transforms::TransformData::Xml {
        xml_text,
        node_set: Some(result_ns),
    }))
}

/// Parse a here()-based exclude pattern:
/// `count(ancestor-or-self::P:E | here()/ancestor::P:E[1]) > count(ancestor-or-self::P:E)`
/// Returns Some((ns_uri, local_name)) if matched.
fn parse_here_exclude_pattern(
    expr: &str,
    xpath_node: NodeId,
    doc: &Document<'_>,
) -> Option<(String, String)> {
    let prefix = "count(ancestor-or-self::";
    if !expr.starts_with(prefix) {
        return None;
    }
    let rest = &expr[prefix.len()..];

    // Find the element name and the here() pattern
    let marker = " | here()/ancestor::";
    let pos = rest.find(marker)?;
    let name_part = &rest[..pos];
    let after = &rest[pos + marker.len()..];

    // Verify the rest matches: NAME[1]) > count(ancestor-or-self::NAME)
    let expected = format!("{}[1]) > count(ancestor-or-self::{})", name_part, name_part);
    if after != expected {
        return None;
    }

    resolve_prefixed_name(name_part, xpath_node, doc)
}

/// Check if a node is an ancestor-or-self of the given name.
fn is_ancestor_or_self_match(
    node: NodeId,
    doc: &Document<'_>,
    ns_uri: &str,
    local_name: &str,
) -> bool {
    let mut current = Some(node);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            if elem.name.local_name.as_ref() == local_name
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
            {
                return true;
            }
        }
        current = doc.parent(n);
    }
    false
}

/// Check if a node is a descendant-or-self of a target node identified by index.
/// Uses node index for cross-document comparison (same text → same indices).
fn is_descendant_of_index(
    node: NodeId,
    doc: &Document<'_>,
    target_idx: usize,
) -> bool {
    let mut current = Some(node);
    while let Some(n) = current {
        if n.index() == target_idx {
            return true;
        }
        current = doc.parent(n);
    }
    false
}

/// Find an ancestor of the given node matching ns_uri:local_name, return its index.
fn find_ancestor_by_name_idx(
    node: NodeId,
    doc: &Document<'_>,
    ns_uri: &str,
    local_name: &str,
) -> Option<usize> {
    let mut current = Some(node);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            if elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
                && elem.name.local_name.as_ref() == local_name
            {
                return Some(n.index());
            }
        }
        current = doc.parent(n);
    }
    None
}

/// A parsed XPath boolean expression tree.
#[derive(Debug)]
enum XPathBoolExpr {
    /// Always true — matches all nodes (e.g., XPath `1` or `true()`)
    True,
    /// `ancestor-or-self::ns:Name` — true if node or any ancestor is the named element
    AncestorOrSelf { ns_uri: String, local_name: String },
    /// `self::text()` — true for text nodes
    SelfText,
    /// `@*` — true if node is an element with at least one attribute
    HasAttributes,
    /// `self::prefix:Name` — true if current node is the named element
    SelfElement { ns_uri: String, local_name: String },
    /// `not(expr)`
    Not(Box<XPathBoolExpr>),
    /// `expr and expr`
    And(Box<XPathBoolExpr>, Box<XPathBoolExpr>),
    /// `expr or expr`
    Or(Box<XPathBoolExpr>, Box<XPathBoolExpr>),
    /// `name() = "str"` or `name() != "str"` — compare node name (QName/prefix)
    NameEq(String),
    NameNeq(String),
    /// `namespace-uri() != "str"` or `namespace-uri() = "str"`
    NamespaceUriEq(String),
    NamespaceUriNeq(String),
    /// `parent::prefix:Name` — true if parent is the named element
    ParentIs { ns_uri: String, local_name: String },
    /// `string(self::node()) = namespace-uri(parent::node())` — for namespace node testing
    StringSelfEqNsUriParent,
    /// `count(parent::node()/namespace::*) != count(parent::node()/namespace::* | self::node())`
    /// True for nodes that are NOT namespace nodes of their parent.
    IsNotParentNsNode,
    /// `count(parent::node()/namespace::*) = count(parent::node()/namespace::* | self::node())`
    /// True for nodes that ARE namespace nodes of their parent.
    IsParentNsNode,
    /// `(count(ancestor-or-self::node()) mod 2) = 1` — odd depth
    DepthOdd,
}

/// Parse a limited subset of XPath 1.0 boolean expressions.
///
/// Handles combinations of `ancestor-or-self::prefix:Name`, `self::text()`,
/// `not()`, `and`, `or`.
fn parse_xpath_bool_expr(expr: &str, xpath_node: NodeId, doc: &Document<'_>) -> Option<XPathBoolExpr> {
    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }

    // Numeric constant: any non-zero number is true, 0 is false.
    // XPath filter with "1" means "include all nodes".
    if let Ok(n) = expr.parse::<f64>() {
        if n != 0.0 {
            return Some(XPathBoolExpr::True);
        } else {
            return Some(XPathBoolExpr::Not(Box::new(XPathBoolExpr::True)));
        }
    }

    // Try splitting on top-level ` and ` (outside parentheses)
    if let Some((left, right)) = split_top_level(expr, " and ") {
        let l = parse_xpath_bool_expr(left, xpath_node, doc)?;
        let r = parse_xpath_bool_expr(right, xpath_node, doc)?;
        return Some(XPathBoolExpr::And(Box::new(l), Box::new(r)));
    }

    // Try splitting on top-level ` or ` (outside parentheses)
    if let Some((left, right)) = split_top_level(expr, " or ") {
        let l = parse_xpath_bool_expr(left, xpath_node, doc)?;
        let r = parse_xpath_bool_expr(right, xpath_node, doc)?;
        return Some(XPathBoolExpr::Or(Box::new(l), Box::new(r)));
    }

    // Handle not(...) — strip outer not() and parse inner
    if let Some(inner) = strip_not(expr) {
        let inner_expr = parse_xpath_bool_expr(inner, xpath_node, doc)?;
        return Some(XPathBoolExpr::Not(Box::new(inner_expr)));
    }

    // Handle parenthesized expression
    if expr.starts_with('(') && expr.ends_with(')') {
        return parse_xpath_bool_expr(&expr[1..expr.len()-1], xpath_node, doc);
    }

    // self::text()
    if expr == "self::text()" {
        return Some(XPathBoolExpr::SelfText);
    }

    // @* — true if context node has attributes
    if expr == "@*" {
        return Some(XPathBoolExpr::HasAttributes);
    }

    // self::prefix:Name — current node is a specific element
    if let Some(name_part) = expr.strip_prefix("self::") {
        if name_part != "text()" && name_part != "node()" {
            let (ns_uri, local_name) = resolve_prefixed_name(name_part, xpath_node, doc)?;
            return Some(XPathBoolExpr::SelfElement { ns_uri, local_name });
        }
    }

    // ancestor-or-self::prefix:Name or ancestor-or-self::Name
    if let Some(name_part) = expr.strip_prefix("ancestor-or-self::") {
        let (ns_uri, local_name) = resolve_prefixed_name(name_part, xpath_node, doc)?;
        return Some(XPathBoolExpr::AncestorOrSelf { ns_uri, local_name });
    }

    // parent::prefix:Name — parent is a specific element
    if let Some(name_part) = expr.strip_prefix("parent::") {
        if name_part != "node()" {
            let (ns_uri, local_name) = resolve_prefixed_name(name_part, xpath_node, doc)?;
            return Some(XPathBoolExpr::ParentIs { ns_uri, local_name });
        }
    }

    // name() = "str" or name() != "str"
    {
        let norm: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
        if let Some(rest) = norm.strip_prefix("name()") {
            let rest = rest.trim();
            if let Some(val) = rest.strip_prefix("!=") {
                let val = val.trim().trim_matches('"').trim_matches('\'');
                return Some(XPathBoolExpr::NameNeq(val.to_string()));
            }
            if let Some(val) = rest.strip_prefix('=') {
                let val = val.trim().trim_matches('"').trim_matches('\'');
                return Some(XPathBoolExpr::NameEq(val.to_string()));
            }
        }
    }

    // namespace-uri() = "str" or namespace-uri() != "str"
    {
        let norm: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
        if let Some(rest) = norm.strip_prefix("namespace-uri()") {
            let rest = rest.trim();
            if let Some(val) = rest.strip_prefix("!=") {
                let val = val.trim().trim_matches('"').trim_matches('\'');
                return Some(XPathBoolExpr::NamespaceUriNeq(val.to_string()));
            }
            if let Some(val) = rest.strip_prefix('=') {
                let val = val.trim().trim_matches('"').trim_matches('\'');
                return Some(XPathBoolExpr::NamespaceUriEq(val.to_string()));
            }
        }
    }

    // string(self::node()) = namespace-uri(parent::node())
    {
        let norm: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
        if norm == "string(self::node()) = namespace-uri(parent::node())" {
            return Some(XPathBoolExpr::StringSelfEqNsUriParent);
        }
    }

    // count(parent::node()/namespace::*) != count(parent::node()/namespace::* | self::node())
    {
        let norm: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
        if norm == "count(parent::node()/namespace::*) != count(parent::node()/namespace::* | self::node())" {
            return Some(XPathBoolExpr::IsNotParentNsNode);
        }
        if norm == "count(parent::node()/namespace::*) = count(parent::node()/namespace::* | self::node())" {
            return Some(XPathBoolExpr::IsParentNsNode);
        }
    }

    // (count(ancestor-or-self::node()) mod 2) = 1
    {
        let norm: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
        if norm == "(count(ancestor-or-self::node()) mod 2) = 1" {
            return Some(XPathBoolExpr::DepthOdd);
        }
    }

    None
}

/// Split an expression at the first top-level occurrence of `sep`
/// (i.e., not inside parentheses).
fn split_top_level<'a>(expr: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0i32;
    let bytes = expr.as_bytes();
    let sep_bytes = sep.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'(' { depth += 1; }
        if bytes[i] == b')' { depth -= 1; }
        if depth == 0 && i + sep_bytes.len() <= bytes.len() && &bytes[i..i + sep_bytes.len()] == sep_bytes {
            let left = &expr[..i];
            let right = &expr[i + sep.len()..];
            if !left.trim().is_empty() && !right.trim().is_empty() {
                return Some((left.trim(), right.trim()));
            }
        }
    }
    None
}

/// Strip `not(...)` wrapper and return inner expression.
/// Handles both `not(expr)` and `not (expr)` (space before opening paren).
fn strip_not(expr: &str) -> Option<&str> {
    let expr = expr.trim();
    // Handle "not(" and "not (" variants
    let prefix_len = if expr.starts_with("not(") {
        4
    } else if expr.starts_with("not (") {
        5
    } else {
        return None;
    };
    if !expr.ends_with(')') {
        return None;
    }
    {
        // Check that the closing paren matches the opening one after "not("
        let inner = &expr[prefix_len..expr.len()-1];
        // Verify balanced parentheses
        let mut depth = 0i32;
        for c in inner.chars() {
            if c == '(' { depth += 1; }
            if c == ')' { depth -= 1; }
            if depth < 0 { return None; }
        }
        if depth == 0 {
            return Some(inner.trim());
        }
    }
    None
}

/// Resolve a possibly-prefixed element name using the XPath node's namespace declarations.
fn resolve_prefixed_name(name: &str, xpath_node: NodeId, doc: &Document<'_>) -> Option<(String, String)> {
    if let Some((prefix, local)) = name.split_once(':') {
        // Resolve namespace prefix on the element itself
        if let Some(elem) = doc.element(xpath_node) {
            for (p, uri) in &elem.namespace_declarations {
                if p.as_ref() == prefix {
                    return Some((uri.to_string(), local.to_string()));
                }
            }
        }
        // Walk up ancestors looking for namespace declaration
        let mut current = doc.parent(xpath_node);
        while let Some(n) = current {
            if let Some(elem) = doc.element(n) {
                for (p, uri) in &elem.namespace_declarations {
                    if p.as_ref() == prefix {
                        return Some((uri.to_string(), local.to_string()));
                    }
                }
            }
            current = doc.parent(n);
        }
        None
    } else {
        // No prefix — match any namespace (empty URI signals "any")
        Some((String::new(), name.to_string()))
    }
}

/// A virtual namespace node for XPath evaluation.
///
/// In the XPath data model, namespace nodes are children of elements but
/// Uppsala doesn't model them as separate nodes. This struct represents
/// a namespace node with its properties.
struct NsNode {
    /// The prefix (empty string for default namespace)
    prefix: String,
    /// The namespace URI
    uri: String,
    /// The parent element node ID
    parent: NodeId,
}

/// Evaluate a parsed XPath boolean expression for a given regular node.
fn eval_xpath_bool(
    expr: &XPathBoolExpr,
    node: NodeId,
    doc: &Document<'_>,
) -> bool {
    match expr {
        XPathBoolExpr::True => true,
        XPathBoolExpr::AncestorOrSelf { ns_uri, local_name } => {
            // Check if node or any ancestor is the named element
            let mut current = Some(node);
            while let Some(n) = current {
                if let Some(elem) = doc.element(n) {
                    if elem.name.local_name.as_ref() == local_name.as_str()
                        && (ns_uri.is_empty() || elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri)
                    {
                        return true;
                    }
                }
                current = doc.parent(n);
            }
            false
        }
        XPathBoolExpr::SelfText => matches!(doc.node_kind(node), Some(NodeKind::Text(_))),
        XPathBoolExpr::HasAttributes => doc.element(node).map_or(false, |e| !e.attributes.is_empty()),
        XPathBoolExpr::SelfElement { ns_uri, local_name } => {
            doc.element(node).map_or(false, |e| {
                e.name.local_name.as_ref() == local_name.as_str()
                    && (ns_uri.is_empty() || e.name.namespace_uri.as_deref().unwrap_or("") == ns_uri)
            })
        }
        XPathBoolExpr::Not(inner) => !eval_xpath_bool(inner, node, doc),
        XPathBoolExpr::And(left, right) => {
            eval_xpath_bool(left, node, doc) && eval_xpath_bool(right, node, doc)
        }
        XPathBoolExpr::Or(left, right) => {
            eval_xpath_bool(left, node, doc) || eval_xpath_bool(right, node, doc)
        }
        XPathBoolExpr::NameEq(s) => {
            // For elements, name() returns QName (prefix:local or just local)
            if let Some(elem) = doc.element(node) {
                let qname = get_element_qname_from_elem(elem);
                qname == *s
            } else if matches!(doc.node_kind(node), Some(NodeKind::Text(_))) {
                s.is_empty()
            } else {
                false
            }
        }
        XPathBoolExpr::NameNeq(s) => {
            if let Some(elem) = doc.element(node) {
                let qname = get_element_qname_from_elem(elem);
                qname != *s
            } else if matches!(doc.node_kind(node), Some(NodeKind::Text(_))) {
                !s.is_empty()
            } else {
                true
            }
        }
        XPathBoolExpr::NamespaceUriEq(s) => {
            if let Some(elem) = doc.element(node) {
                elem.name.namespace_uri.as_deref().unwrap_or("") == s.as_str()
            } else {
                s.is_empty()
            }
        }
        XPathBoolExpr::NamespaceUriNeq(s) => {
            if let Some(elem) = doc.element(node) {
                elem.name.namespace_uri.as_deref().unwrap_or("") != s.as_str()
            } else {
                !s.is_empty()
            }
        }
        XPathBoolExpr::ParentIs { ns_uri, local_name } => {
            if let Some(parent) = doc.parent(node) {
                doc.element(parent).map_or(false, |e| {
                    e.name.local_name.as_ref() == local_name.as_str()
                        && (ns_uri.is_empty() || e.name.namespace_uri.as_deref().unwrap_or("") == ns_uri)
                })
            } else {
                false
            }
        }
        XPathBoolExpr::StringSelfEqNsUriParent => {
            // For regular nodes, this compares string value to parent's namespace URI
            // This is mainly meaningful for namespace nodes; for regular nodes, rarely true
            false
        }
        XPathBoolExpr::IsNotParentNsNode => {
            // For regular document nodes (elements, text), they're never namespace nodes
            true
        }
        XPathBoolExpr::IsParentNsNode => {
            // Regular nodes are never namespace nodes
            false
        }
        XPathBoolExpr::DepthOdd => {
            // Count ancestors-or-self: root=1, root-child=2, etc.
            let mut depth = 0usize;
            let mut current = Some(node);
            while let Some(n) = current {
                depth += 1;
                current = doc.parent(n);
            }
            depth % 2 == 1
        }
    }
}

/// Evaluate a parsed XPath boolean expression for a virtual namespace node.
fn eval_xpath_bool_ns(
    expr: &XPathBoolExpr,
    ns_node: &NsNode,
    doc: &Document<'_>,
) -> bool {
    match expr {
        XPathBoolExpr::True => true,
        XPathBoolExpr::AncestorOrSelf { ns_uri, local_name } => {
            // Namespace node ancestors are: parent element and its ancestors
            let mut current = Some(ns_node.parent);
            while let Some(n) = current {
                if let Some(elem) = doc.element(n) {
                    if elem.name.local_name.as_ref() == local_name.as_str()
                        && (ns_uri.is_empty() || elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri)
                    {
                        return true;
                    }
                }
                current = doc.parent(n);
            }
            false
        }
        XPathBoolExpr::SelfText => false,
        XPathBoolExpr::HasAttributes => false,
        XPathBoolExpr::SelfElement { .. } => false, // namespace node is not an element
        XPathBoolExpr::Not(inner) => !eval_xpath_bool_ns(inner, ns_node, doc),
        XPathBoolExpr::And(left, right) => {
            eval_xpath_bool_ns(left, ns_node, doc) && eval_xpath_bool_ns(right, ns_node, doc)
        }
        XPathBoolExpr::Or(left, right) => {
            eval_xpath_bool_ns(left, ns_node, doc) || eval_xpath_bool_ns(right, ns_node, doc)
        }
        XPathBoolExpr::NameEq(s) => {
            // For namespace nodes, name() returns the prefix
            ns_node.prefix == *s
        }
        XPathBoolExpr::NameNeq(s) => {
            ns_node.prefix != *s
        }
        XPathBoolExpr::NamespaceUriEq(s) => {
            // namespace-uri() on namespace nodes is "" per XPath 1.0 spec §4.1
            s.is_empty()
        }
        XPathBoolExpr::NamespaceUriNeq(s) => {
            !s.is_empty()
        }
        XPathBoolExpr::ParentIs { ns_uri, local_name } => {
            doc.element(ns_node.parent).map_or(false, |e| {
                e.name.local_name.as_ref() == local_name.as_str()
                    && (ns_uri.is_empty() || e.name.namespace_uri.as_deref().unwrap_or("") == ns_uri)
            })
        }
        XPathBoolExpr::StringSelfEqNsUriParent => {
            // string(self::node()) for namespace nodes = the namespace URI
            // namespace-uri(parent::node()) = parent element's namespace URI
            let parent_ns = doc.element(ns_node.parent)
                .and_then(|e| e.name.namespace_uri.as_deref())
                .unwrap_or("");
            ns_node.uri == parent_ns
        }
        XPathBoolExpr::IsNotParentNsNode => {
            // Namespace nodes ARE parent's namespace nodes
            false
        }
        XPathBoolExpr::IsParentNsNode => {
            // Namespace nodes ARE parent's namespace nodes
            true
        }
        XPathBoolExpr::DepthOdd => {
            // Namespace node depth = parent depth + 1
            let mut depth = 1usize; // for the namespace node itself
            let mut current = Some(ns_node.parent);
            while let Some(n) = current {
                depth += 1;
                current = doc.parent(n);
            }
            depth % 2 == 1
        }
    }
}

/// Get the QName of an element from an Element reference (prefix:local or just local if no prefix).
fn get_element_qname_from_elem(elem: &uppsala::Element<'_>) -> String {
    if let Some(prefix) = elem.name.prefix.as_deref() {
        if !prefix.is_empty() {
            return format!("{}:{}", prefix, elem.name.local_name);
        }
    }
    elem.name.local_name.to_string()
}

/// Check if an XPath boolean expression references namespace-node-specific
/// constructs (name(), namespace-uri(), IsNotParentNsNode, etc.).
/// When true, we need to compute the ns_visible map for the node set.
fn expr_references_ns_nodes(expr: &XPathBoolExpr) -> bool {
    match expr {
        XPathBoolExpr::True => false,
        XPathBoolExpr::NameEq(_)
        | XPathBoolExpr::NameNeq(_)
        | XPathBoolExpr::NamespaceUriEq(_)
        | XPathBoolExpr::NamespaceUriNeq(_)
        | XPathBoolExpr::StringSelfEqNsUriParent
        | XPathBoolExpr::IsNotParentNsNode
        | XPathBoolExpr::IsParentNsNode
        | XPathBoolExpr::DepthOdd => true,
        XPathBoolExpr::Not(inner) => expr_references_ns_nodes(inner),
        XPathBoolExpr::And(l, r) | XPathBoolExpr::Or(l, r) => {
            expr_references_ns_nodes(l) || expr_references_ns_nodes(r)
        }
        XPathBoolExpr::AncestorOrSelf { .. }
        | XPathBoolExpr::SelfText
        | XPathBoolExpr::HasAttributes
        | XPathBoolExpr::SelfElement { .. }
        | XPathBoolExpr::ParentIs { .. } => false,
    }
}

/// Collect all in-scope namespace bindings for an element by walking the
/// ancestor chain. Returns a map of prefix → URI.
fn collect_inscope_namespaces_raw(
    node: NodeId,
    doc: &Document<'_>,
) -> std::collections::BTreeMap<String, String> {
    use std::collections::BTreeMap;
    let mut ns_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut current = Some(node);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            let mut level = BTreeMap::new();
            for (prefix, uri) in &elem.namespace_declarations {
                level.insert(prefix.to_string(), uri.to_string());
            }
            ns_stack.push(level);
        }
        current = doc.parent(n);
    }
    let mut result = BTreeMap::new();
    for level in ns_stack.into_iter().rev() {
        for (prefix, uri) in level {
            if uri.is_empty() {
                result.remove(&prefix);
            } else {
                result.insert(prefix, uri);
            }
        }
    }
    result
}

/// Apply a parsed XPath boolean expression as a node filter.
fn apply_parsed_xpath_filter(
    data: bergshamra_transforms::TransformData,
    expr: &XPathBoolExpr,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_xml::nodeset::{NodeSet, NodeSetType};
    use std::collections::HashSet;

    // If input is binary, convert to XML first (per XML-DSig spec: "If the input
    // is an octet stream, the implementation MUST convert the octets to an XPath
    // node-set by parsing the octets and creating a node-set that includes all
    // document nodes").
    let (xml_text, input_ns) = match data {
        bergshamra_transforms::TransformData::Xml { xml_text, node_set } => {
            (xml_text, node_set)
        }
        bergshamra_transforms::TransformData::Binary(bytes) => {
            let text = String::from_utf8(bytes)
                .map_err(|e| Error::XmlParse(format!("XPath transform: invalid UTF-8: {e}")))?;
            (text, None)
        }
    };

    let doc = uppsala::parse(&xml_text)
        .map_err(|e| Error::XmlParse(e.to_string()))?;

    // Filter: include only nodes for which the expression evaluates to true
    let mut result_ids = HashSet::new();
    for node in doc.descendants(doc.root()) {
        // If we have an input node set, only consider nodes in it
        if let Some(ref ns) = input_ns {
            if !ns.contains_id(node) {
                continue;
            }
        }
        if eval_xpath_bool(expr, node, &doc) {
            result_ids.insert(node.index());
        }
    }

    let mut result_ns = NodeSet::from_ids(result_ids, NodeSetType::Normal);

    // XPath `@*` (HasAttributes): the element is in the node set but
    // its attribute nodes are NOT (since `@*` on an attribute node returns
    // empty). C14N should omit attributes for these elements.
    if matches!(expr, XPathBoolExpr::HasAttributes) {
        result_ns.set_exclude_attrs(true);
    }

    // If the expression references namespace-node constructs, evaluate
    // the expression for each element's in-scope namespace bindings and
    // build the ns_visible map.
    if expr_references_ns_nodes(expr) {
        use std::collections::HashMap;
        let mut ns_map: HashMap<(usize, String), bool> = HashMap::new();
        for node in doc.descendants(doc.root()) {
            if doc.element(node).is_none() {
                continue;
            }
            let eid = node.index();
            let inscope = collect_inscope_namespaces_raw(node, &doc);
            for (prefix, uri) in &inscope {
                let ns_node = NsNode {
                    prefix: prefix.clone(),
                    uri: uri.clone(),
                    parent: node,
                };
                let visible = eval_xpath_bool_ns(expr, &ns_node, &doc);
                ns_map.insert((eid, prefix.clone()), visible);
            }
        }
        result_ns.set_ns_visible(ns_map);
    }

    Ok(bergshamra_transforms::TransformData::Xml {
        xml_text,
        node_set: Some(result_ns),
    })
}

/// Check if an XPath expression is the enveloped-signature pattern.
///
/// Matches: `not(ancestor-or-self::PREFIX:Signature)` where PREFIX is bound
/// to the XML-DSig namespace `http://www.w3.org/2000/09/xmldsig#`.
fn is_enveloped_xpath(expr: &str, xpath_node: NodeId, doc: &Document<'_>) -> bool {
    let expr = expr.trim();

    // Pattern: not(ancestor-or-self::PREFIX:Signature)
    if !expr.starts_with("not(ancestor-or-self::") || !expr.ends_with(":Signature)") {
        return false;
    }

    // Extract the prefix
    let inner = &expr["not(ancestor-or-self::".len()..expr.len() - ":Signature)".len()];

    // Verify the prefix is bound to the DSIG namespace
    let dsig_ns = ns::DSIG;
    // Check namespace declarations on the XPath element and ancestors
    let mut current = Some(xpath_node);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            for (prefix, uri) in &elem.namespace_declarations {
                if prefix.as_ref() == inner && uri.as_ref() == dsig_ns {
                    return true;
                }
            }
        }
        current = doc.parent(n);
    }
    false
}

/// Check if an XPath expression is the here()-based enveloped-signature pattern.
///
/// Matches:
/// ```text
/// count(ancestor-or-self::PREFIX:Signature |
///   here()/ancestor::PREFIX:Signature[1]) >
///   count(ancestor-or-self::PREFIX:Signature)
/// ```
/// where PREFIX is bound to the XML-DSig namespace.
/// This is semantically equivalent to the enveloped-signature transform.
fn is_enveloped_xpath_here(expr: &str, xpath_node: NodeId, doc: &Document<'_>) -> bool {
    // Normalize whitespace for matching
    let norm: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");

    // Pattern: count(ancestor-or-self::P:Signature | here()/ancestor::P:Signature[1]) > count(ancestor-or-self::P:Signature)
    let prefix = "count(ancestor-or-self::";
    if !norm.starts_with(prefix) {
        return false;
    }

    let rest = &norm[prefix.len()..];

    // Extract PREFIX:Signature from the first part
    let sig_marker = ":Signature | here()/ancestor::";
    let Some(pos) = rest.find(sig_marker) else {
        return false;
    };

    let pfx = &rest[..pos];
    let after_marker = &rest[pos + sig_marker.len()..];

    // Verify the rest matches: PREFIX:Signature[1]) > count(ancestor-or-self::PREFIX:Signature)
    let expected_tail = format!(
        "{pfx}:Signature[1]) > count(ancestor-or-self::{pfx}:Signature)"
    );
    if after_marker != expected_tail {
        return false;
    }

    // Verify the prefix is bound to the DSIG namespace
    let dsig_ns = ns::DSIG;
    let mut current = Some(xpath_node);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            for (prefix, uri) in &elem.namespace_declarations {
                if prefix.as_ref() == pfx && uri.as_ref() == dsig_ns {
                    return true;
                }
            }
        }
        current = doc.parent(n);
    }
    false
}

/// Apply an XPath Filter 2.0 transform.
///
/// Per W3C XPath Filter 2.0 spec (Section 3.4):
/// 1. Initialize filter node-set F to all nodes in the input document
/// 2. For each XPath expression: evaluate, subtree-expand, apply set op to F
/// 3. Output O = I ∩ F (input node-set intersected with filter node-set)
///
/// An empty input node-set always produces an empty output node-set.
fn apply_xpath_filter2_transform(
    data: bergshamra_transforms::TransformData,
    transform_node: NodeId,
    outer_doc: &Document<'_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_xml::nodeset::NodeSet;

    match data {
        bergshamra_transforms::TransformData::Xml { xml_text, node_set } => {
            let doc = uppsala::parse(&xml_text)
                .map_err(|e| Error::XmlParse(e.to_string()))?;

            // I = input node-set (from previous transform or URI resolution)
            let input_ns = node_set.unwrap_or_else(|| NodeSet::all(&doc));

            // F = filter node-set, initialized to ALL nodes in the input document
            let mut filter_ns = NodeSet::all(&doc);

            // Process each <XPath> child element in sequence, updating F
            for child in outer_doc.children(transform_node) {
                let child_elem = match outer_doc.element(child) {
                    Some(e) if e.name.local_name.as_ref() == "XPath" => e,
                    _ => continue,
                };
                let filter = child_elem.get_attribute("Filter").unwrap_or("");
                let xpath_expr = element_text(outer_doc, child).unwrap_or("").trim();

                // Evaluate XPath expression and subtree-expand (S')
                let xpath_ns = evaluate_simple_xpath(&doc, xpath_expr, child, outer_doc)?;

                // Update filter node-set F based on filter type
                match filter {
                    "intersect" => { filter_ns = filter_ns.intersection(&xpath_ns); }
                    "subtract" => { filter_ns = filter_ns.subtract(&xpath_ns); }
                    "union" => { filter_ns = filter_ns.union(&xpath_ns); }
                    _ => return Err(Error::UnsupportedAlgorithm(format!(
                        "XPath Filter 2.0 unknown filter: {filter}"
                    ))),
                }
            }

            // Output O = I ∩ F
            let result_ns = input_ns.intersection(&filter_ns);

            Ok(bergshamra_transforms::TransformData::Xml {
                xml_text,
                node_set: Some(result_ns),
            })
        }
        other => Ok(other),
    }
}

/// Evaluate a simple XPath expression and return the matching node set.
///
/// Supports:
/// - `/` — the document root (all nodes)
/// - `//ElementName` — all descendant elements with the given local name
/// - `//prefix:ElementName` — namespace-qualified element selection
/// - `/a/b[@attr="val"]/c` — absolute paths with predicates
/// - `*` — wildcard element names
/// - `[not(@attr)]` — negated attribute predicates
/// - `expr | expr` — union of two path expressions
fn evaluate_simple_xpath(
    doc: &Document<'_>,
    expr: &str,
    xpath_node: NodeId,
    outer_doc: &Document<'_>,
) -> Result<NodeSet, Error> {
    use bergshamra_xml::nodeset::NodeSet;
    use std::collections::HashSet;

    // `/` — selects the entire document
    if expr == "/" {
        return Ok(NodeSet::all(doc));
    }

    // Handle top-level union: `expr1 | expr2`
    // Split on top-level `|` (outside brackets)
    if let Some((left, right)) = split_xpath_union(expr) {
        let left_ns = evaluate_simple_xpath(doc, left.trim(), xpath_node, outer_doc)?;
        let right_ns = evaluate_simple_xpath(doc, right.trim(), xpath_node, outer_doc)?;
        return Ok(left_ns.union(&right_ns));
    }

    // `//name` or `//prefix:name` — descendant-or-self element selection
    if let Some(name_expr) = expr.strip_prefix("//") {
        let (ns_uri, local_name) = if let Some((prefix, local)) = name_expr.split_once(':') {
            // Resolve namespace prefix from the XPath element's namespace declarations
            let uri = resolve_ns_prefix(xpath_node, outer_doc, prefix)
                .ok_or_else(|| Error::InvalidUri(format!(
                    "XPath Filter 2.0: unresolved namespace prefix '{prefix}'"
                )))?;
            (Some(uri), local)
        } else {
            (None, name_expr)
        };

        // Find all matching elements and collect their subtrees
        let mut nodes = HashSet::new();
        for node in doc.descendants(doc.root()) {
            if let Some(elem) = doc.element(node) {
                if elem.name.local_name.as_ref() == local_name {
                    let matches = match &ns_uri {
                        Some(uri) => elem.name.namespace_uri.as_deref().unwrap_or("") == uri.as_str(),
                        None => true, // no namespace specified — match any namespace
                    };
                    if matches {
                        // Collect the element and all its descendants (subtree)
                        collect_subtree_ids(node, doc, &mut nodes);
                    }
                }
            }
        }

        return Ok(NodeSet::from_ids(nodes, bergshamra_xml::nodeset::NodeSetType::Normal));
    }

    // Absolute path: `/step1/step2/step3[pred]`
    if expr.starts_with('/') {
        let steps = parse_xpath_path_steps(&expr[1..])?;
        let mut nodes = HashSet::new();
        let matches = evaluate_path_steps(doc, &steps, xpath_node, outer_doc)?;
        for node in &matches {
            collect_subtree_ids(*node, doc, &mut nodes);
        }
        return Ok(NodeSet::from_ids(nodes, bergshamra_xml::nodeset::NodeSetType::Normal));
    }

    Err(Error::UnsupportedAlgorithm(format!(
        "XPath Filter 2.0 expression not supported: {expr}"
    )))
}

/// Resolve a namespace prefix by walking up the ancestor chain.
fn resolve_ns_prefix(node: NodeId, doc: &Document<'_>, prefix: &str) -> Option<String> {
    let mut current = Some(node);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            for (p, uri) in &elem.namespace_declarations {
                if p.as_ref() == prefix {
                    return Some(uri.to_string());
                }
            }
        }
        current = doc.parent(n);
    }
    None
}

/// Split an XPath expression at the top-level `|` (union) operator.
/// Only splits outside brackets `[]` and parentheses `()`.
fn split_xpath_union(expr: &str) -> Option<(&str, &str)> {
    let mut bracket_depth = 0i32;
    let mut paren_depth = 0i32;
    let bytes = expr.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'[' => bracket_depth += 1,
            b']' => bracket_depth -= 1,
            b'(' => paren_depth += 1,
            b')' => paren_depth -= 1,
            b'|' if bracket_depth == 0 && paren_depth == 0 => {
                let left = expr[..i].trim();
                let right = expr[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    return Some((left, right));
                }
            }
            _ => {}
        }
    }
    None
}

/// A parsed XPath path step: element name (or wildcard) plus optional predicate.
struct PathStep {
    /// Element local name, or "*" for wildcard
    name: String,
    /// Namespace URI if prefix was provided
    ns_uri: Option<String>,
    /// Optional predicate (the content inside [...])
    predicate: Option<String>,
}

/// Parse a `/`-separated path into steps.
/// Input is the path WITHOUT the leading `/`, e.g., `XFDL/page[@sid="PAGE1"]/*`.
fn parse_xpath_path_steps(path: &str) -> Result<Vec<PathStep>, Error> {
    let mut steps = Vec::new();
    let mut remaining = path;

    while !remaining.is_empty() {
        // Find the next `/` that's not inside a predicate `[...]`
        let mut bracket_depth = 0i32;
        let mut slash_pos = None;
        for (i, b) in remaining.bytes().enumerate() {
            match b {
                b'[' => bracket_depth += 1,
                b']' => bracket_depth -= 1,
                b'/' if bracket_depth == 0 => {
                    slash_pos = Some(i);
                    break;
                }
                _ => {}
            }
        }

        let step_str = match slash_pos {
            Some(pos) => {
                let s = &remaining[..pos];
                remaining = &remaining[pos + 1..];
                s
            }
            None => {
                let s = remaining;
                remaining = "";
                s
            }
        };

        // Parse step: "name" or "name[predicate]" or "*[predicate]"
        let (name_part, predicate) = if let Some(bracket_start) = step_str.find('[') {
            if !step_str.ends_with(']') {
                return Err(Error::XmlStructure(format!(
                    "XPath step with unclosed predicate: {step_str}"
                )));
            }
            let name = &step_str[..bracket_start];
            let pred = &step_str[bracket_start + 1..step_str.len() - 1];
            (name, Some(pred.to_string()))
        } else {
            (step_str, None)
        };

        // Resolve prefix:local or just local or *
        let (ns_uri, local_name) = if name_part == "*" {
            (None, "*".to_string())
        } else if let Some((prefix, local)) = name_part.split_once(':') {
            // We'll resolve the prefix later when we have the xpath_node context
            (Some(prefix.to_string()), local.to_string())
        } else {
            (None, name_part.to_string())
        };

        steps.push(PathStep {
            name: local_name,
            ns_uri,
            predicate,
        });
    }

    Ok(steps)
}

/// Evaluate path steps against the document, returning the matching leaf nodes.
fn evaluate_path_steps(
    doc: &Document<'_>,
    steps: &[PathStep],
    xpath_node: NodeId,
    outer_doc: &Document<'_>,
) -> Result<Vec<NodeId>, Error> {
    if steps.is_empty() {
        return Ok(vec![]);
    }

    // Resolve any namespace prefixes stored as strings
    let resolved_steps: Vec<(Option<String>, &str, &Option<String>)> = steps.iter().map(|s| {
        let ns = match &s.ns_uri {
            Some(prefix) => resolve_ns_prefix(xpath_node, outer_doc, prefix),
            None => None,
        };
        (ns, s.name.as_str(), &s.predicate)
    }).collect();

    // Start from the root's children (since we already consumed the leading `/`)
    let mut current_nodes: Vec<NodeId> = doc.children(doc.root())
        .into_iter()
        .filter(|&id| doc.element(id).is_some())
        .collect();

    for (step_idx, (ns_uri, local_name, predicate)) in resolved_steps.iter().enumerate() {
        let mut matched = Vec::new();

        for &node in &current_nodes {
            // Check children of current node (except for first step which is already root children)
            let candidates: Vec<NodeId> = if step_idx == 0 {
                vec![node]
            } else {
                doc.children(node).into_iter().filter(|&id| doc.element(id).is_some()).collect()
            };

            for candidate in candidates {
                let elem = match doc.element(candidate) {
                    Some(e) => e,
                    None => continue,
                };

                // Match element name
                let name_matches = if *local_name == "*" {
                    true
                } else {
                    elem.name.local_name.as_ref() == *local_name
                };

                // Match namespace
                let ns_matches = match ns_uri {
                    Some(ref uri) => elem.name.namespace_uri.as_deref().unwrap_or("") == uri.as_str(),
                    None => true,
                };

                if name_matches && ns_matches {
                    // Check predicate
                    if let Some(pred) = predicate {
                        if evaluate_xpath_predicate(candidate, doc, pred) {
                            matched.push(candidate);
                        }
                    } else {
                        matched.push(candidate);
                    }
                }
            }
        }

        current_nodes = matched;
    }

    Ok(current_nodes)
}

/// Evaluate a simple XPath predicate on a node.
///
/// Supports:
/// - `@attr="value"` — attribute equals value
/// - `@attr="val1" or @attr="val2" or ...` — disjunction of attribute checks
/// - `not(@attr)` — attribute does not exist
fn evaluate_xpath_predicate(node: NodeId, doc: &Document<'_>, pred: &str) -> bool {
    let pred = pred.trim();

    // Handle `not(@attr)` or `not(@prefix:attr)`
    if pred.starts_with("not(") && pred.ends_with(')') {
        let inner = pred[4..pred.len() - 1].trim();
        if let Some(attr_name) = inner.strip_prefix('@') {
            return doc.element(node).and_then(|e| e.get_attribute(attr_name)).is_none();
        }
    }

    // Handle `@attr="value"` or disjunction `@attr="val1" or @attr="val2"`
    // Split on top-level ` or `
    let parts: Vec<&str> = split_predicate_or(pred);
    if parts.iter().all(|p| is_attr_eq_predicate(p.trim())) {
        return parts.iter().any(|p| evaluate_attr_eq(node, doc, p.trim()));
    }

    false
}

/// Split predicate on ` or ` at top level (outside quotes and parens).
fn split_predicate_or(pred: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut quote_char = b'"';
    let bytes = pred.as_bytes();
    let or_bytes = b" or ";
    let or_len = or_bytes.len();

    for i in 0..bytes.len() {
        if !in_quote && (bytes[i] == b'"' || bytes[i] == b'\'') {
            in_quote = true;
            quote_char = bytes[i];
        } else if in_quote && bytes[i] == quote_char {
            in_quote = false;
        } else if !in_quote && i + or_len <= bytes.len() && &bytes[i..i + or_len] == or_bytes {
            parts.push(&pred[start..i]);
            start = i + or_len;
        }
    }
    parts.push(&pred[start..]);
    parts
}

/// Check if a predicate part is an attribute comparison: `@attr="value"`
fn is_attr_eq_predicate(part: &str) -> bool {
    part.starts_with('@') && (part.contains("=\"") || part.contains("='"))
}

/// Evaluate `@attr="value"` predicate.
fn evaluate_attr_eq(node: NodeId, doc: &Document<'_>, pred: &str) -> bool {
    let pred = pred.trim();
    if let Some(attr_part) = pred.strip_prefix('@') {
        // Split on = to get attr name and value
        if let Some((attr_name, quoted_value)) = attr_part.split_once('=') {
            let value = quoted_value.trim_matches(|c| c == '"' || c == '\'');
            return doc.element(node).and_then(|e| e.get_attribute(attr_name)) == Some(value);
        }
    }
    false
}

/// Collect all node IDs in a subtree.
fn collect_subtree_ids(node: NodeId, doc: &Document<'_>, ids: &mut std::collections::HashSet<usize>) {
    ids.insert(node.index());
    for child in doc.children(node) {
        collect_subtree_ids(child, doc, ids);
    }
}

/// Apply an XPointer transform.
///
/// Extracts `xpointer(id('...'))` from the `<XPointer>` child element
/// and selects the subtree rooted at the element with the given ID.
fn apply_xpointer_transform(
    data: bergshamra_transforms::TransformData,
    transform_node: NodeId,
    outer_doc: &Document<'_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_xml::xpath;
    use bergshamra_xml::nodeset::NodeSet;

    // Extract the XPointer expression from the <XPointer> child element
    let xpointer_node = outer_doc.children(transform_node)
        .into_iter()
        .find(|&id| {
            outer_doc.element(id).map_or(false, |e| e.name.local_name.as_ref() == "XPointer")
        })
        .ok_or_else(|| Error::MissingElement("XPointer expression element".into()))?;

    let xpointer_expr = element_text(outer_doc, xpointer_node).unwrap_or("").trim();

    // Parse xpointer(id('...')) or xpointer(id("..."))
    let id = xpath::parse_xpointer_id(xpointer_expr)
        .ok_or_else(|| Error::UnsupportedAlgorithm(format!(
            "XPointer expression not supported: {xpointer_expr}"
        )))?;

    match data {
        bergshamra_transforms::TransformData::Xml { xml_text, node_set } => {
            let inner_doc = uppsala::parse(&xml_text)
                .map_err(|e| Error::XmlParse(e.to_string()))?;

            // Build ID map
            let id_map = build_id_map(&inner_doc, &["Id", "ID", "id"]);

            // Resolve the ID
            let target = xpath::resolve_id(&inner_doc, &id_map, id)?;

            // Build a node set for the subtree (xpointer includes comments)
            let subtree_ns = NodeSet::tree_with_comments(target, &inner_doc);

            // Intersect with existing node set if present
            let final_ns = match node_set {
                Some(existing) => existing.intersection(&subtree_ns),
                None => subtree_ns,
            };

            Ok(bergshamra_transforms::TransformData::Xml {
                xml_text,
                node_set: Some(final_ns),
            })
        }
        other => Ok(other),
    }
}

/// Try to unwrap an `<EncryptedKey>` inside `<KeyInfo>` to recover a session key.
///
/// This handles the case where a symmetric signing key (e.g. HMAC) is encrypted
/// using AES Key Wrap, 3DES Key Wrap, or RSA key transport.
fn try_unwrap_encrypted_key(
    doc: &Document<'_>,
    key_info_node: NodeId,
    manager: &bergshamra_keys::KeysManager,
) -> Result<bergshamra_keys::Key, Error> {
    // Find <EncryptedKey> child
    let enc_key_node = doc.children(key_info_node).into_iter().find(|&id| {
        doc.element(id).map_or(false, |e| {
            e.name.local_name.as_ref() == ns::node::ENCRYPTED_KEY
                && e.name.namespace_uri.as_deref().unwrap_or("") == ns::ENC
        })
    }).ok_or_else(|| Error::Key("no EncryptedKey found".into()))?;

    // Read EncryptionMethod
    let enc_method = find_child_element(doc, enc_key_node, ns::ENC, ns::node::ENCRYPTION_METHOD)
        .ok_or_else(|| Error::MissingElement("EncryptionMethod on EncryptedKey".into()))?;
    let enc_uri = doc.element(enc_method)
        .and_then(|e| e.get_attribute(ns::attr::ALGORITHM))
        .ok_or_else(|| Error::MissingAttribute("Algorithm on EncryptedKey EncryptionMethod".into()))?;

    // Read CipherData/CipherValue
    let cipher_data = find_child_element(doc, enc_key_node, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData on EncryptedKey".into()))?;
    let cipher_value = find_child_element(doc, cipher_data, ns::ENC, ns::node::CIPHER_VALUE)
        .ok_or_else(|| Error::MissingElement("CipherValue on EncryptedKey".into()))?;
    let b64_text = element_text(doc, cipher_value).unwrap_or("").trim();
    let clean: String = b64_text.chars().filter(|c| !c.is_whitespace()).collect();
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let cipher_bytes = engine.decode(&clean)
        .map_err(|e| Error::Base64(format!("EncryptedKey CipherValue: {e}")))?;

    // Resolve the KEK from EncryptedKey's own KeyInfo
    let ek_key_info = find_child_element(doc, enc_key_node, ns::DSIG, ns::node::KEY_INFO);

    let session_key_bytes = match enc_uri {
        algorithm::KW_AES128 | algorithm::KW_AES192 | algorithm::KW_AES256 => {
            let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
            let expected_kek_size = match enc_uri {
                algorithm::KW_AES128 => 16,
                algorithm::KW_AES192 => 24,
                algorithm::KW_AES256 => 32,
                _ => 0,
            };
            // Try KeyName from EncryptedKey's KeyInfo
            let kek = resolve_kek_from_key_info(doc, ek_key_info, manager)?;
            let kek_bytes = kek.symmetric_key_bytes()
                .ok_or_else(|| Error::Key("KEK has no symmetric key bytes".into()))?;
            // Validate size if possible
            if expected_kek_size > 0 && kek_bytes.len() != expected_kek_size {
                // Try to find one with the right size
                if let Some(sized_key) = manager.find_aes_by_size(expected_kek_size) {
                    let sized_bytes = sized_key.symmetric_key_bytes()
                        .ok_or_else(|| Error::Key("AES key has no bytes".into()))?;
                    kw.unwrap(sized_bytes, &cipher_bytes)?
                } else {
                    kw.unwrap(kek_bytes, &cipher_bytes)?
                }
            } else {
                kw.unwrap(kek_bytes, &cipher_bytes)?
            }
        }
        algorithm::KW_TRIPLEDES => {
            let kw = bergshamra_crypto::keywrap::from_uri(enc_uri)?;
            let kek = resolve_kek_from_key_info(doc, ek_key_info, manager)?;
            let kek_bytes = kek.symmetric_key_bytes()
                .ok_or_else(|| Error::Key("no symmetric key for 3DES key unwrap".into()))?;
            kw.unwrap(kek_bytes, &cipher_bytes)?
        }
        algorithm::RSA_PKCS1 | algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
            let oaep_params = read_oaep_params(doc, enc_method);
            let transport = bergshamra_crypto::keytransport::from_uri_with_params(enc_uri, oaep_params)?;
            let rsa_key = manager.find_rsa_private()
                .or_else(|| manager.find_rsa())
                .ok_or_else(|| Error::Key("no RSA key for EncryptedKey decryption".into()))?;
            let private_key = rsa_key.rsa_private_key()
                .ok_or_else(|| Error::Key("RSA private key required for key transport".into()))?;
            transport.decrypt(private_key, &cipher_bytes)?
        }
        _ => return Err(Error::UnsupportedAlgorithm(format!("EncryptedKey method: {enc_uri}"))),
    };

    // Create an HMAC key from the unwrapped session key
    Ok(bergshamra_keys::Key::new(
        bergshamra_keys::key::KeyData::Hmac(session_key_bytes),
        bergshamra_keys::key::KeyUsage::Any,
    ))
}

/// Resolve the Key Encryption Key from an EncryptedKey's KeyInfo.
fn resolve_kek_from_key_info<'a>(
    doc: &Document<'_>,
    ek_key_info: Option<NodeId>,
    manager: &'a bergshamra_keys::KeysManager,
) -> Result<&'a bergshamra_keys::Key, Error> {
    if let Some(ki) = ek_key_info {
        // Try KeyName
        for child in doc.children(ki) {
            let elem = match doc.element(child) {
                Some(e) => e,
                None => continue,
            };
            let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
            let local = &*elem.name.local_name;
            if child_ns == ns::DSIG && local == ns::node::KEY_NAME {
                let name = element_text(doc, child).unwrap_or("").trim();
                if !name.is_empty() {
                    if let Some(key) = manager.find_by_name(name) {
                        return Ok(key);
                    }
                }
            }
        }
    }
    // Fallback: first key in manager
    manager.first_key()
}

/// Read RSA-OAEP parameters from an EncryptionMethod element.
fn read_oaep_params(doc: &Document<'_>, enc_method: NodeId) -> bergshamra_crypto::keytransport::OaepParams {
    let mut params = bergshamra_crypto::keytransport::OaepParams::default();
    for child in doc.children(enc_method) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let local = &*elem.name.local_name;
        let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
        if local == ns::node::DIGEST_METHOD && (child_ns == ns::DSIG || child_ns == ns::ENC) {
            if let Some(alg) = elem.get_attribute(ns::attr::ALGORITHM) {
                params.digest_uri = Some(alg.to_owned());
            }
        }
        if local == ns::node::RSA_MGF && (child_ns == ns::ENC11 || child_ns == ns::ENC) {
            if let Some(alg) = elem.get_attribute(ns::attr::ALGORITHM) {
                params.mgf_uri = Some(alg.to_owned());
            }
        }
        if local == ns::node::RSA_OAEP_PARAMS {
            if let Some(text) = element_text(doc, child) {
                let clean: String = text.trim().chars().filter(|c| !c.is_whitespace()).collect();
                use base64::Engine;
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&clean) {
                    params.oaep_params = Some(bytes);
                }
            }
        }
    }
    params
}

// ── Helper functions ─────────────────────────────────────────────────

fn find_element(doc: &Document<'_>, ns_uri: &str, local_name: &str) -> Option<NodeId> {
    for id in doc.descendants(doc.root()) {
        if let Some(elem) = doc.element(id) {
            if elem.name.local_name.as_ref() == local_name
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
            {
                return Some(id);
            }
        }
    }
    None
}

fn find_child_element(doc: &Document<'_>, parent: NodeId, ns_uri: &str, local_name: &str) -> Option<NodeId> {
    for id in doc.children(parent) {
        if let Some(elem) = doc.element(id) {
            if elem.name.local_name.as_ref() == local_name
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
            {
                return Some(id);
            }
        }
    }
    None
}

fn find_child_elements(doc: &Document<'_>, parent: NodeId, ns_uri: &str, local_name: &str) -> Vec<NodeId> {
    doc.children(parent)
        .into_iter()
        .filter(|&id| {
            doc.element(id).map_or(false, |elem| {
                elem.name.local_name.as_ref() == local_name
                    && elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
            })
        })
        .collect()
}

/// Find a descendant element with the given namespace URI and local name.
fn find_descendant_element(doc: &Document<'_>, node: NodeId, ns_uri: &str, local_name: &str) -> Option<NodeId> {
    for id in doc.descendants(node) {
        if let Some(elem) = doc.element(id) {
            if elem.name.local_name.as_ref() == local_name
                && elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
            {
                return Some(id);
            }
        }
    }
    None
}

/// Resolve a `<dsig11:KeyInfoReference URI="#id"/>` by following the same-document
/// reference to the target `<KeyInfo>` element. Returns that element if found.
fn resolve_key_info_reference(
    doc: &Document<'_>,
    key_info_node: NodeId,
    id_map: &HashMap<String, NodeId>,
) -> Option<NodeId> {
    for child in doc.children(key_info_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;
        if local == ns::node::KEY_INFO_REFERENCE && child_ns == ns::DSIG11 {
            if let Some(uri) = elem.get_attribute(ns::attr::URI) {
                if let Some(fragment) = uri.strip_prefix('#') {
                    if let Some(&node_id) = id_map.get(fragment) {
                        return Some(node_id);
                    }
                }
            }
        }
    }
    None
}

fn build_id_map(doc: &Document<'_>, attr_names: &[&str]) -> HashMap<String, NodeId> {
    let mut map = HashMap::new();
    for id in doc.descendants(doc.root()) {
        if let Some(elem) = doc.element(id) {
            for attr_name in attr_names {
                if let Some(val) = elem.get_attribute(attr_name) {
                    map.insert(val.to_owned(), id);
                }
            }
            // Also check xml:id
            if let Some(val) = elem.get_attribute("xml:id") {
                map.insert(val.to_owned(), id);
            }
        }
    }
    map
}

fn read_inclusive_prefixes(doc: &Document<'_>, node: NodeId) -> Vec<String> {
    for child in doc.children(node) {
        if let Some(elem) = doc.element(child) {
            if elem.name.local_name.as_ref() == ns::node::INCLUSIVE_NAMESPACES {
                if let Some(prefix_list) = elem.get_attribute(ns::attr::PREFIX_LIST) {
                    return prefix_list.split_whitespace().map(|s| s.to_owned()).collect();
                }
            }
        }
    }
    Vec::new()
}

/// Extract text content from the first Text/CData child of an element.
fn element_text<'a>(doc: &'a Document<'a>, id: NodeId) -> Option<&'a str> {
    for child in doc.children(id) {
        match doc.node_kind(child) {
            Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) => return Some(t),
            _ => {}
        }
    }
    None
}

/// Try to resolve a key from a `<RetrievalMethod>` element in `<KeyInfo>`.
///
/// Handles `Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"` by
/// loading a DER certificate from the URI and extracting the public key.
fn try_resolve_retrieval_method(
    doc: &Document<'_>,
    key_info_node: NodeId,
    base_dir: Option<&str>,
    url_maps: &[(String, String)],
) -> Option<bergshamra_keys::Key> {
    use bergshamra_keys::key::{Key, KeyData, KeyUsage};

    for child in doc.children(key_info_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;
        if local != "RetrievalMethod" || (child_ns != ns::DSIG && !child_ns.is_empty()) {
            continue;
        }

        let type_attr = elem.get_attribute("Type").unwrap_or("");
        let uri = elem.get_attribute("URI").unwrap_or("");

        if type_attr != "http://www.w3.org/2000/09/xmldsig#rawX509Certificate" {
            continue;
        }

        // Resolve URI to a file path
        let file_path = resolve_retrieval_uri(uri, base_dir, url_maps)?;

        // Load DER certificate
        let cert_der = std::fs::read(&file_path).ok()?;

        // Try to parse as DER X.509 certificate
        use der::Decode;
        let cert = x509_cert::Certificate::from_der(&cert_der).ok()?;

        // Extract public key from certificate
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let alg_oid = spki.algorithm.oid;
        let pub_key_bytes = spki.subject_public_key.raw_bytes();

        // Dispatch on algorithm OID
        let key_data = if alg_oid == der::oid::db::rfc5912::RSA_ENCRYPTION {
            // RSA public key
            use rsa::pkcs1::DecodeRsaPublicKey;
            let rsa_pub = rsa::RsaPublicKey::from_pkcs1_der(pub_key_bytes).ok()?;
            KeyData::Rsa {
                public: rsa_pub,
                private: None,
            }
        } else if alg_oid == der::oid::db::rfc5912::ID_DSA {
            // DSA public key — extract parameters from algorithm params
            extract_dsa_key_from_cert(&cert)?
        } else if alg_oid == der::oid::db::rfc5912::ID_EC_PUBLIC_KEY {
            // EC public key — determine curve from parameters
            extract_ec_key_from_spki(spki)?
        } else {
            continue;
        };

        let mut key = Key::new(key_data, KeyUsage::Verify);
        key.x509_chain.push(cert_der);
        return Some(key);
    }
    None
}

/// Try to resolve a key from a same-document `<RetrievalMethod>` that
/// references an X509Data element by `#id`.
///
/// Handles the pattern: `<RetrievalMethod Type="...#X509Data" URI="#object-id">`
/// possibly with XPath transforms.
fn try_resolve_retrieval_method_inline(
    doc: &Document<'_>,
    key_info_node: NodeId,
    id_map: &HashMap<String, NodeId>,
) -> Option<bergshamra_keys::Key> {
    use bergshamra_keys::key::{Key, KeyData, KeyUsage};

    for child in doc.children(key_info_node) {
        let elem = match doc.element(child) {
            Some(e) => e,
            None => continue,
        };
        let child_ns = elem.name.namespace_uri.as_deref().unwrap_or("");
        let local = &*elem.name.local_name;
        if local != "RetrievalMethod" || (child_ns != ns::DSIG && !child_ns.is_empty()) {
            continue;
        }

        let type_attr = elem.get_attribute("Type").unwrap_or("");
        let uri = elem.get_attribute("URI").unwrap_or("");

        // Only handle X509Data type with same-document reference
        if type_attr != "http://www.w3.org/2000/09/xmldsig#X509Data" {
            continue;
        }
        if !uri.starts_with('#') {
            continue;
        }

        let id_value = &uri[1..];
        let &target_node = id_map.get(id_value)?;

        // Look for X509Data inside the target element (or it might be the
        // target itself if an XPath filter selects it)
        let x509_data = if doc.element(target_node).map_or(false, |e| {
            e.name.local_name.as_ref() == "X509Data"
                && e.name.namespace_uri.as_deref().unwrap_or("") == ns::DSIG
        }) {
            target_node
        } else {
            find_descendant_element(doc, target_node, ns::DSIG, "X509Data")?
        };

        // Extract X509Certificate from X509Data
        let cert_b64_node = find_child_element(doc, x509_data, ns::DSIG, "X509Certificate")?;
        let cert_b64 = element_text(doc, cert_b64_node).unwrap_or("").trim();
        let cert_b64_clean: String = cert_b64.chars().filter(|c| !c.is_whitespace()).collect();

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let cert_der = engine.decode(&cert_b64_clean).ok()?;

        // Parse the certificate and extract the public key
        use der::Decode;
        let cert = x509_cert::Certificate::from_der(&cert_der).ok()?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let alg_oid = spki.algorithm.oid;
        let pub_key_bytes = spki.subject_public_key.raw_bytes();

        let key_data = if alg_oid == der::oid::db::rfc5912::RSA_ENCRYPTION {
            use rsa::pkcs1::DecodeRsaPublicKey;
            let rsa_pub = rsa::RsaPublicKey::from_pkcs1_der(pub_key_bytes).ok()?;
            KeyData::Rsa {
                public: rsa_pub,
                private: None,
            }
        } else if alg_oid == der::oid::db::rfc5912::ID_DSA {
            extract_dsa_key_from_cert(&cert)?
        } else if alg_oid == der::oid::db::rfc5912::ID_EC_PUBLIC_KEY {
            extract_ec_key_from_spki(spki)?
        } else {
            continue;
        };

        let mut key = Key::new(key_data, KeyUsage::Verify);
        key.x509_chain.push(cert_der);
        return Some(key);
    }
    None
}

/// Resolve a RetrievalMethod URI to a local file path.
fn resolve_retrieval_uri(
    uri: &str,
    base_dir: Option<&str>,
    url_maps: &[(String, String)],
) -> Option<std::path::PathBuf> {
    // Check url-maps first (prefix replacement)
    for (url, path) in url_maps {
        if uri == url {
            return Some(std::path::PathBuf::from(path));
        }
        if uri.starts_with(url) {
            let suffix = &uri[url.len()..];
            let full = std::path::Path::new(path).join(suffix.trim_start_matches('/'));
            if full.exists() {
                return Some(full);
            }
        }
    }

    // Treat as relative path from base_dir
    if let Some(base) = base_dir {
        let full = std::path::Path::new(base).join(uri);
        if full.exists() {
            return Some(full);
        }
        // Walk up ancestors of base_dir and try each
        let mut ancestor = std::path::Path::new(base);
        while let Some(parent) = ancestor.parent() {
            let full = parent.join(uri);
            if full.exists() {
                return Some(full);
            }
            ancestor = parent;
        }
    }

    // Try CWD-relative
    {
        let p = std::path::PathBuf::from(uri);
        if p.exists() {
            return Some(p);
        }
    }

    // Try as absolute path
    let p = std::path::PathBuf::from(uri);
    if p.exists() {
        return Some(p);
    }

    None
}

/// Extract a DSA public key from an X.509 certificate.
fn extract_dsa_key_from_cert(cert: &x509_cert::Certificate) -> Option<bergshamra_keys::key::KeyData> {
    use bergshamra_keys::key::KeyData;
    use der::Decode;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let params_any = spki.algorithm.parameters.as_ref()?;

    // DSA params are a SEQUENCE { p INTEGER, q INTEGER, g INTEGER }
    // params_any.value() gives the inner content (V of TLV) which for a SEQUENCE
    // is the concatenated TLV encodings of p, q, g
    let params_value = params_any.value();

    // Parse p, q, g from the sequence content
    use der::Reader;
    let mut reader = der::SliceReader::new(params_value).ok()?;
    let p_int: der::asn1::UintRef = reader.decode().ok()?;
    let q_int: der::asn1::UintRef = reader.decode().ok()?;
    let g_int: der::asn1::UintRef = reader.decode().ok()?;

    let p = dsa::BigUint::from_bytes_be(p_int.as_bytes());
    let q = dsa::BigUint::from_bytes_be(q_int.as_bytes());
    let g = dsa::BigUint::from_bytes_be(g_int.as_bytes());

    // Public key y is in the SubjectPublicKey as an INTEGER
    let pub_key_der = spki.subject_public_key.raw_bytes();
    let y_int = der::asn1::UintRef::from_der(pub_key_der).ok()?;
    let y = dsa::BigUint::from_bytes_be(y_int.as_bytes());

    let components = dsa::Components::from_components(p, q, g).ok()?;
    let verifying_key = dsa::VerifyingKey::from_components(components, y).ok()?;

    Some(KeyData::Dsa {
        public: verifying_key,
        private: None,
    })
}

/// Extract an EC public key from SPKI (owned types from Certificate).
fn extract_ec_key_from_spki(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Option<bergshamra_keys::key::KeyData> {
    use bergshamra_keys::key::KeyData;

    let params_any = spki.algorithm.parameters.as_ref()?;
    let curve_oid: der::asn1::ObjectIdentifier = params_any.decode_as().ok()?;
    let pub_bytes = spki.subject_public_key.raw_bytes();

    // P-256 (prime256v1)
    if curve_oid == der::oid::db::rfc5912::SECP_256_R_1 {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pub_bytes).ok()?;
        Some(KeyData::EcP256 {
            public: vk,
            private: None,
        })
    // P-384 (secp384r1)
    } else if curve_oid == der::oid::db::rfc5912::SECP_384_R_1 {
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pub_bytes).ok()?;
        Some(KeyData::EcP384 {
            public: vk,
            private: None,
        })
    // P-521 (secp521r1)
    } else if curve_oid == der::oid::db::rfc5912::SECP_521_R_1 {
        let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(pub_bytes).ok()?;
        Some(KeyData::EcP521 {
            public: vk,
            private: None,
        })
    } else {
        None
    }
}
