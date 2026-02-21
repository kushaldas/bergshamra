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
    let doc = roxmltree::Document::parse_with_options(xml, bergshamra_xml::parsing_options())
        .map_err(|e: roxmltree::Error| Error::XmlParse(e.to_string()))?;

    // Build ID map
    let mut id_attrs: Vec<&str> = vec!["Id", "ID", "id"];
    let extra: Vec<&str> = ctx.id_attrs.iter().map(|s| s.as_str()).collect();
    id_attrs.extend(extra);
    let id_map = build_id_map(&doc, &id_attrs);

    // Find <Signature> element
    let sig_node = find_element(&doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;

    // Find <SignedInfo>
    let signed_info = find_child_element(sig_node, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;

    // Read CanonicalizationMethod
    let c14n_method_node = find_child_element(signed_info, ns::DSIG, ns::node::CANONICALIZATION_METHOD)
        .ok_or_else(|| Error::MissingElement("CanonicalizationMethod".into()))?;
    let c14n_uri = c14n_method_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on CanonicalizationMethod".into()))?;
    let c14n_mode = C14nMode::from_uri(c14n_uri)
        .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {c14n_uri}")))?;

    // Read SignatureMethod
    let sig_method_node = find_child_element(signed_info, ns::DSIG, ns::node::SIGNATURE_METHOD)
        .ok_or_else(|| Error::MissingElement("SignatureMethod".into()))?;
    let sig_method_uri = sig_method_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on SignatureMethod".into()))?;

    // Parse HMACOutputLength for HMAC truncation (CVE-2009-0217)
    let hmac_output_length_bits: Option<usize> = if bergshamra_crypto::sign::is_hmac_algorithm(sig_method_uri) {
        if let Some(len_node) = find_child_element(sig_method_node, ns::DSIG, ns::node::HMAC_OUTPUT_LENGTH) {
            let len_text = len_node.text().unwrap_or("").trim();
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

    // Read exc-C14N PrefixList if applicable
    let inclusive_prefixes = read_inclusive_prefixes(c14n_method_node);

    // 3. Verify each Reference
    let references = find_child_elements(signed_info, ns::DSIG, ns::node::REFERENCE);
    for reference in &references {
        let result = verify_reference(reference, &doc, &id_map, xml, sig_node, &ctx.url_maps, ctx.debug, ctx.base_dir.as_deref())?;
        if let VerifyResult::Invalid { reason } = result {
            return Ok(VerifyResult::Invalid {
                reason: format!("Reference digest failed: {reason}"),
            });
        }
    }

    // 4. Resolve signing key
    // First try inline KeyValue (RSA/EC public key embedded in XML),
    // then try EncryptedKey unwrap, then fall back to KeysManager lookup.
    let key_info_node = find_child_element(sig_node, ns::DSIG, ns::node::KEY_INFO);
    let extracted_key: Option<bergshamra_keys::Key>;
    let key = if let Some(ki) = key_info_node {
        // Check for KeyInfoReference — dereference to the target KeyInfo
        let effective_ki = resolve_key_info_reference(ki, &doc, &id_map).unwrap_or(ki);
        extracted_key = bergshamra_keys::keyinfo::extract_key_value(effective_ki)
            .or_else(|| try_unwrap_encrypted_key(effective_ki, &ctx.keys_manager).ok());
        if let Some(ref ek) = extracted_key {
            if ctx.debug {
                eprintln!("== Key: extracted inline key ({})", ek.data.algorithm_name());
            }
            ek
        } else {
            let k = bergshamra_keys::keyinfo::resolve_key_info(effective_ki, &ctx.keys_manager)?;
            if ctx.debug {
                eprintln!("== Key: resolved from manager ({})", k.data.algorithm_name());
            }
            k
        }
    } else {
        let k = ctx.keys_manager.first_key()?;
        if ctx.debug {
            eprintln!("== Key: first key from manager ({})", k.data.algorithm_name());
        }
        k
    };

    // 5. Canonicalize <SignedInfo>
    // We need to canonicalize the SignedInfo element as a document subset
    let signed_info_ns = NodeSet::tree_without_comments(signed_info);
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
    let sig_value_node = find_child_element(sig_node, ns::DSIG, ns::node::SIGNATURE_VALUE)
        .ok_or_else(|| Error::MissingElement("SignatureValue".into()))?;
    let sig_value_b64 = sig_value_node.text().unwrap_or("").trim();
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

    let sig_alg = bergshamra_crypto::sign::from_uri(sig_method_uri)?;
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
    reference: &roxmltree::Node<'_, '_>,
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
    xml: &str,
    sig_node: roxmltree::Node<'_, '_>,
    url_maps: &[(String, String)],
    debug: bool,
    base_dir: Option<&str>,
) -> Result<VerifyResult, Error> {
    // Read URI attribute
    let uri = reference.attribute(ns::attr::URI).unwrap_or("");

    // Read DigestMethod
    let digest_method_node = find_child_element(*reference, ns::DSIG, ns::node::DIGEST_METHOD)
        .ok_or_else(|| Error::MissingElement("DigestMethod".into()))?;
    let digest_uri = digest_method_node
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on DigestMethod".into()))?;

    // Read expected DigestValue
    let digest_value_node = find_child_element(*reference, ns::DSIG, ns::node::DIGEST_VALUE)
        .ok_or_else(|| Error::MissingElement("DigestValue".into()))?;
    let expected_b64 = digest_value_node.text().unwrap_or("").trim();
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
    let transforms_node = find_child_element(*reference, ns::DSIG, ns::node::TRANSFORMS);
    let mut data = match resolved {
        ResolvedUri::Xml { xml_text, node_set } => bergshamra_transforms::TransformData::Xml {
            xml_text,
            node_set,
        },
        ResolvedUri::Binary(bytes) => bergshamra_transforms::TransformData::Binary(bytes),
    };

    if let Some(transforms) = transforms_node {
        for transform_node in transforms.children() {
            if !transform_node.is_element() || transform_node.tag_name().name() != ns::node::TRANSFORM {
                continue;
            }
            let transform_uri = transform_node
                .attribute(ns::attr::ALGORITHM)
                .unwrap_or("");

            data = apply_transform(transform_uri, data, &transform_node, sig_node)?;
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
    doc: &roxmltree::Document<'_>,
    id_map: &HashMap<String, roxmltree::NodeId>,
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
            NodeSet::tree_with_comments(node)
        } else {
            NodeSet::tree_without_comments(node)
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
    transform_node: &roxmltree::Node<'_, '_>,
    sig_node: roxmltree::Node<'_, '_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_transforms::pipeline::{C14nTransform, Transform};

    match uri {
        algorithm::ENVELOPED_SIGNATURE => {
            let t = bergshamra_transforms::enveloped::EnvelopedSignatureTransform::from_node(sig_node);
            t.execute(data)
        }
        algorithm::C14N | algorithm::C14N_WITH_COMMENTS
        | algorithm::C14N11 | algorithm::C14N11_WITH_COMMENTS
        | algorithm::EXC_C14N | algorithm::EXC_C14N_WITH_COMMENTS => {
            let mode = C14nMode::from_uri(uri)
                .ok_or_else(|| Error::UnsupportedAlgorithm(format!("C14N: {uri}")))?;
            let prefixes = read_inclusive_prefixes(*transform_node);
            let t = C14nTransform::new(mode, prefixes);
            t.execute(data)
        }
        algorithm::BASE64 => {
            let t = bergshamra_transforms::base64_transform::Base64DecodeTransform;
            t.execute(data)
        }
        algorithm::XPATH => {
            apply_xpath_transform(data, transform_node, sig_node)
        }
        algorithm::XPOINTER => {
            apply_xpointer_transform(data, transform_node)
        }
        algorithm::XPATH2 => {
            apply_xpath_filter2_transform(data, transform_node)
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("transform: {uri}"))),
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
    transform_node: &roxmltree::Node<'_, '_>,
    sig_node: roxmltree::Node<'_, '_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    // Extract the XPath expression from the <XPath> child element
    let xpath_node = transform_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "XPath")
        .ok_or_else(|| Error::MissingElement("XPath expression element".into()))?;

    let xpath_expr = xpath_node.text().unwrap_or("").trim();

    // Check if this is the enveloped-signature pattern:
    // not(ancestor-or-self::PREFIX:Signature)
    if is_enveloped_xpath(xpath_expr, &xpath_node) {
        // Apply enveloped signature transform (same as the dedicated one)
        use bergshamra_transforms::pipeline::Transform;
        let t = bergshamra_transforms::enveloped::EnvelopedSignatureTransform::from_node(sig_node);
        return t.execute(data);
    }

    // Try to parse and evaluate as a boolean XPath expression
    if let Some(parsed) = parse_xpath_bool_expr(xpath_expr, &xpath_node) {
        return apply_parsed_xpath_filter(data, &parsed);
    }

    Err(Error::UnsupportedAlgorithm(format!(
        "XPath expression not supported: {xpath_expr}"
    )))
}

/// A parsed XPath boolean expression tree.
#[derive(Debug)]
enum XPathBoolExpr {
    /// `ancestor-or-self::ns:Name` — true if node or any ancestor is the named element
    AncestorOrSelf { ns_uri: String, local_name: String },
    /// `self::text()` — true for text nodes
    SelfText,
    /// `not(expr)`
    Not(Box<XPathBoolExpr>),
    /// `expr and expr`
    And(Box<XPathBoolExpr>, Box<XPathBoolExpr>),
    /// `expr or expr`
    Or(Box<XPathBoolExpr>, Box<XPathBoolExpr>),
}

/// Parse a limited subset of XPath 1.0 boolean expressions.
///
/// Handles combinations of `ancestor-or-self::prefix:Name`, `self::text()`,
/// `not()`, `and`, `or`.
fn parse_xpath_bool_expr(expr: &str, xpath_node: &roxmltree::Node<'_, '_>) -> Option<XPathBoolExpr> {
    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }

    // Try splitting on top-level ` and ` (outside parentheses)
    if let Some((left, right)) = split_top_level(expr, " and ") {
        let l = parse_xpath_bool_expr(left, xpath_node)?;
        let r = parse_xpath_bool_expr(right, xpath_node)?;
        return Some(XPathBoolExpr::And(Box::new(l), Box::new(r)));
    }

    // Try splitting on top-level ` or ` (outside parentheses)
    if let Some((left, right)) = split_top_level(expr, " or ") {
        let l = parse_xpath_bool_expr(left, xpath_node)?;
        let r = parse_xpath_bool_expr(right, xpath_node)?;
        return Some(XPathBoolExpr::Or(Box::new(l), Box::new(r)));
    }

    // Handle not(...) — strip outer not() and parse inner
    if let Some(inner) = strip_not(expr) {
        let inner_expr = parse_xpath_bool_expr(inner, xpath_node)?;
        return Some(XPathBoolExpr::Not(Box::new(inner_expr)));
    }

    // Handle parenthesized expression
    if expr.starts_with('(') && expr.ends_with(')') {
        return parse_xpath_bool_expr(&expr[1..expr.len()-1], xpath_node);
    }

    // self::text()
    if expr == "self::text()" {
        return Some(XPathBoolExpr::SelfText);
    }

    // ancestor-or-self::prefix:Name or ancestor-or-self::Name
    if let Some(name_part) = expr.strip_prefix("ancestor-or-self::") {
        let (ns_uri, local_name) = resolve_prefixed_name(name_part, xpath_node)?;
        return Some(XPathBoolExpr::AncestorOrSelf { ns_uri, local_name });
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
fn strip_not(expr: &str) -> Option<&str> {
    let expr = expr.trim();
    if expr.starts_with("not(") && expr.ends_with(')') {
        // Check that the closing paren matches the opening one after "not("
        let inner = &expr[4..expr.len()-1];
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
fn resolve_prefixed_name(name: &str, xpath_node: &roxmltree::Node<'_, '_>) -> Option<(String, String)> {
    if let Some((prefix, local)) = name.split_once(':') {
        // Resolve namespace prefix
        let uri = xpath_node.namespaces()
            .find(|ns| ns.name() == Some(prefix))
            .map(|ns| ns.uri())?;
        Some((uri.to_string(), local.to_string()))
    } else {
        // No prefix — match any namespace (empty URI signals "any")
        Some((String::new(), name.to_string()))
    }
}

/// Evaluate a parsed XPath boolean expression for a given node.
fn eval_xpath_bool(
    expr: &XPathBoolExpr,
    node: roxmltree::Node<'_, '_>,
) -> bool {
    match expr {
        XPathBoolExpr::AncestorOrSelf { ns_uri, local_name } => {
            // Check if node or any ancestor is the named element
            let mut current = Some(node);
            while let Some(n) = current {
                if n.is_element() && n.tag_name().name() == local_name
                    && (ns_uri.is_empty() || n.tag_name().namespace().unwrap_or("") == ns_uri)
                {
                    return true;
                }
                current = n.parent();
            }
            false
        }
        XPathBoolExpr::SelfText => node.is_text(),
        XPathBoolExpr::Not(inner) => !eval_xpath_bool(inner, node),
        XPathBoolExpr::And(left, right) => {
            eval_xpath_bool(left, node) && eval_xpath_bool(right, node)
        }
        XPathBoolExpr::Or(left, right) => {
            eval_xpath_bool(left, node) || eval_xpath_bool(right, node)
        }
    }
}

/// Apply a parsed XPath boolean expression as a node filter.
fn apply_parsed_xpath_filter(
    data: bergshamra_transforms::TransformData,
    expr: &XPathBoolExpr,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_xml::nodeset::{NodeSet, NodeSetType, node_index};
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

    let doc = roxmltree::Document::parse_with_options(
        &xml_text, bergshamra_xml::parsing_options(),
    ).map_err(|e| Error::XmlParse(e.to_string()))?;

    // Filter: include only nodes for which the expression evaluates to true
    let mut result_ids = HashSet::new();
    for node in doc.descendants() {
        // If we have an input node set, only consider nodes in it
        if let Some(ref ns) = input_ns {
            if !ns.contains(&node) {
                continue;
            }
        }
        if eval_xpath_bool(expr, node) {
            result_ids.insert(node_index(node));
        }
    }

    Ok(bergshamra_transforms::TransformData::Xml {
        xml_text,
        node_set: Some(NodeSet::from_ids(result_ids, NodeSetType::Normal)),
    })
}

/// Check if an XPath expression is the enveloped-signature pattern.
///
/// Matches: `not(ancestor-or-self::PREFIX:Signature)` where PREFIX is bound
/// to the XML-DSig namespace `http://www.w3.org/2000/09/xmldsig#`.
fn is_enveloped_xpath(expr: &str, xpath_node: &roxmltree::Node<'_, '_>) -> bool {
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
    xpath_node.namespaces().any(|ns_decl| {
        ns_decl.name() == Some(inner) && ns_decl.uri() == dsig_ns
    })
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
    transform_node: &roxmltree::Node<'_, '_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_xml::nodeset::NodeSet;

    match data {
        bergshamra_transforms::TransformData::Xml { xml_text, node_set } => {
            let doc = roxmltree::Document::parse_with_options(
                &xml_text, bergshamra_xml::parsing_options(),
            ).map_err(|e| Error::XmlParse(e.to_string()))?;

            // I = input node-set (from previous transform or URI resolution)
            let input_ns = node_set.unwrap_or_else(|| NodeSet::all(&doc));

            // F = filter node-set, initialized to ALL nodes in the input document
            let mut filter_ns = NodeSet::all(&doc);

            // Process each <XPath> child element in sequence, updating F
            for child in transform_node.children() {
                if !child.is_element() || child.tag_name().name() != "XPath" {
                    continue;
                }
                let filter = child.attribute("Filter").unwrap_or("");
                let xpath_expr = child.text().unwrap_or("").trim();

                // Evaluate XPath expression and subtree-expand (S')
                let xpath_ns = evaluate_simple_xpath(&doc, xpath_expr, &child)?;

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
fn evaluate_simple_xpath(
    doc: &roxmltree::Document<'_>,
    expr: &str,
    xpath_node: &roxmltree::Node<'_, '_>,
) -> Result<NodeSet, Error> {
    use bergshamra_xml::nodeset::NodeSet;
    use std::collections::HashSet;

    // `/` — selects the entire document
    if expr == "/" {
        return Ok(NodeSet::all(doc));
    }

    // `//name` or `//prefix:name` — descendant-or-self element selection
    if let Some(name_expr) = expr.strip_prefix("//") {
        let (ns_uri, local_name) = if let Some((prefix, local)) = name_expr.split_once(':') {
            // Resolve namespace prefix from the XPath element's namespace declarations
            let uri = xpath_node.namespaces()
                .find(|ns| ns.name() == Some(prefix))
                .map(|ns| ns.uri())
                .ok_or_else(|| Error::InvalidUri(format!(
                    "XPath Filter 2.0: unresolved namespace prefix '{prefix}'"
                )))?;
            (Some(uri), local)
        } else {
            (None, name_expr)
        };

        // Find all matching elements and collect their subtrees
        let mut nodes = HashSet::new();
        for node in doc.descendants() {
            if node.is_element() && node.tag_name().name() == local_name {
                let matches = match ns_uri {
                    Some(uri) => node.tag_name().namespace().unwrap_or("") == uri,
                    None => true, // no namespace specified — match any namespace
                };
                if matches {
                    // Collect the element and all its descendants (subtree)
                    collect_subtree_ids(node, &mut nodes);
                }
            }
        }

        return Ok(NodeSet::from_ids(nodes, bergshamra_xml::nodeset::NodeSetType::Normal));
    }

    Err(Error::UnsupportedAlgorithm(format!(
        "XPath Filter 2.0 expression not supported: {expr}"
    )))
}

/// Collect all node IDs in a subtree.
fn collect_subtree_ids(node: roxmltree::Node<'_, '_>, ids: &mut std::collections::HashSet<usize>) {
    use bergshamra_xml::nodeset::node_index;
    ids.insert(node_index(node));
    for child in node.children() {
        collect_subtree_ids(child, ids);
    }
}

/// Apply an XPointer transform.
///
/// Extracts `xpointer(id('...'))` from the `<XPointer>` child element
/// and selects the subtree rooted at the element with the given ID.
fn apply_xpointer_transform(
    data: bergshamra_transforms::TransformData,
    transform_node: &roxmltree::Node<'_, '_>,
) -> Result<bergshamra_transforms::TransformData, Error> {
    use bergshamra_xml::xpath;
    use bergshamra_xml::nodeset::NodeSet;

    // Extract the XPointer expression from the <XPointer> child element
    let xpointer_node = transform_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "XPointer")
        .ok_or_else(|| Error::MissingElement("XPointer expression element".into()))?;

    let xpointer_expr = xpointer_node.text().unwrap_or("").trim();

    // Parse xpointer(id('...')) or xpointer(id("..."))
    let id = xpath::parse_xpointer_id(xpointer_expr)
        .ok_or_else(|| Error::UnsupportedAlgorithm(format!(
            "XPointer expression not supported: {xpointer_expr}"
        )))?;

    match data {
        bergshamra_transforms::TransformData::Xml { xml_text, node_set } => {
            let doc = roxmltree::Document::parse_with_options(
                &xml_text, bergshamra_xml::parsing_options(),
            ).map_err(|e| Error::XmlParse(e.to_string()))?;

            // Build ID map
            let id_map = build_id_map(&doc, &["Id", "ID", "id"]);

            // Resolve the ID
            let target = xpath::resolve_id(&doc, &id_map, id)?;

            // Build a node set for the subtree (xpointer includes comments)
            let subtree_ns = NodeSet::tree_with_comments(target);

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
    key_info_node: roxmltree::Node<'_, '_>,
    manager: &bergshamra_keys::KeysManager,
) -> Result<bergshamra_keys::Key, Error> {
    // Find <EncryptedKey> child
    let enc_key_node = key_info_node.children().find(|n| {
        n.is_element()
            && n.tag_name().name() == ns::node::ENCRYPTED_KEY
            && n.tag_name().namespace().unwrap_or("") == ns::ENC
    }).ok_or_else(|| Error::Key("no EncryptedKey found".into()))?;

    // Read EncryptionMethod
    let enc_method = find_child_element(enc_key_node, ns::ENC, ns::node::ENCRYPTION_METHOD)
        .ok_or_else(|| Error::MissingElement("EncryptionMethod on EncryptedKey".into()))?;
    let enc_uri = enc_method
        .attribute(ns::attr::ALGORITHM)
        .ok_or_else(|| Error::MissingAttribute("Algorithm on EncryptedKey EncryptionMethod".into()))?;

    // Read CipherData/CipherValue
    let cipher_data = find_child_element(enc_key_node, ns::ENC, ns::node::CIPHER_DATA)
        .ok_or_else(|| Error::MissingElement("CipherData on EncryptedKey".into()))?;
    let cipher_value = find_child_element(cipher_data, ns::ENC, ns::node::CIPHER_VALUE)
        .ok_or_else(|| Error::MissingElement("CipherValue on EncryptedKey".into()))?;
    let b64_text = cipher_value.text().unwrap_or("").trim();
    let clean: String = b64_text.chars().filter(|c| !c.is_whitespace()).collect();
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let cipher_bytes = engine.decode(&clean)
        .map_err(|e| Error::Base64(format!("EncryptedKey CipherValue: {e}")))?;

    // Resolve the KEK from EncryptedKey's own KeyInfo
    let ek_key_info = find_child_element(enc_key_node, ns::DSIG, ns::node::KEY_INFO);

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
            let kek = resolve_kek_from_key_info(ek_key_info, manager)?;
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
            let kek = resolve_kek_from_key_info(ek_key_info, manager)?;
            let kek_bytes = kek.symmetric_key_bytes()
                .ok_or_else(|| Error::Key("no symmetric key for 3DES key unwrap".into()))?;
            kw.unwrap(kek_bytes, &cipher_bytes)?
        }
        algorithm::RSA_PKCS1 | algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
            let oaep_params = read_oaep_params(enc_method);
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
    ek_key_info: Option<roxmltree::Node<'_, '_>>,
    manager: &'a bergshamra_keys::KeysManager,
) -> Result<&'a bergshamra_keys::Key, Error> {
    if let Some(ki) = ek_key_info {
        // Try KeyName
        for child in ki.children() {
            if !child.is_element() {
                continue;
            }
            let ns_uri = child.tag_name().namespace().unwrap_or("");
            let local = child.tag_name().name();
            if ns_uri == ns::DSIG && local == ns::node::KEY_NAME {
                let name = child.text().unwrap_or("").trim();
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
fn read_oaep_params(enc_method: roxmltree::Node<'_, '_>) -> bergshamra_crypto::keytransport::OaepParams {
    let mut params = bergshamra_crypto::keytransport::OaepParams::default();
    for child in enc_method.children() {
        if !child.is_element() {
            continue;
        }
        let local = child.tag_name().name();
        let child_ns = child.tag_name().namespace().unwrap_or("");
        if local == ns::node::DIGEST_METHOD && (child_ns == ns::DSIG || child_ns == ns::ENC) {
            if let Some(alg) = child.attribute(ns::attr::ALGORITHM) {
                params.digest_uri = Some(alg.to_owned());
            }
        }
        if local == ns::node::RSA_MGF && (child_ns == ns::ENC11 || child_ns == ns::ENC) {
            if let Some(alg) = child.attribute(ns::attr::ALGORITHM) {
                params.mgf_uri = Some(alg.to_owned());
            }
        }
        if local == ns::node::RSA_OAEP_PARAMS {
            if let Some(text) = child.text() {
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

fn find_element<'a>(
    doc: &'a roxmltree::Document<'a>,
    ns_uri: &str,
    local_name: &str,
) -> Option<roxmltree::Node<'a, 'a>> {
    doc.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == local_name
            && n.tag_name().namespace().unwrap_or("") == ns_uri
    })
}

fn find_child_element<'a>(
    parent: roxmltree::Node<'a, 'a>,
    ns_uri: &str,
    local_name: &str,
) -> Option<roxmltree::Node<'a, 'a>> {
    parent.children().find(|n| {
        n.is_element()
            && n.tag_name().name() == local_name
            && n.tag_name().namespace().unwrap_or("") == ns_uri
    })
}

fn find_child_elements<'a>(
    parent: roxmltree::Node<'a, 'a>,
    ns_uri: &str,
    local_name: &str,
) -> Vec<roxmltree::Node<'a, 'a>> {
    parent
        .children()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == local_name
                && n.tag_name().namespace().unwrap_or("") == ns_uri
        })
        .collect()
}

/// Resolve a `<dsig11:KeyInfoReference URI="#id"/>` by following the same-document
/// reference to the target `<KeyInfo>` element. Returns that element if found.
fn resolve_key_info_reference<'a, 'b>(
    key_info_node: roxmltree::Node<'a, 'b>,
    doc: &'a roxmltree::Document<'b>,
    id_map: &HashMap<String, roxmltree::NodeId>,
) -> Option<roxmltree::Node<'a, 'b>> {
    for child in key_info_node.children() {
        if !child.is_element() {
            continue;
        }
        let ns_uri = child.tag_name().namespace().unwrap_or("");
        let local = child.tag_name().name();
        if local == ns::node::KEY_INFO_REFERENCE && ns_uri == ns::DSIG11 {
            if let Some(uri) = child.attribute(ns::attr::URI) {
                if let Some(fragment) = uri.strip_prefix('#') {
                    if let Some(&node_id) = id_map.get(fragment) {
                        return doc.get_node(node_id);
                    }
                }
            }
        }
    }
    None
}

fn build_id_map(
    doc: &roxmltree::Document<'_>,
    attr_names: &[&str],
) -> HashMap<String, roxmltree::NodeId> {
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

fn read_inclusive_prefixes(node: roxmltree::Node<'_, '_>) -> Vec<String> {
    // Look for <InclusiveNamespaces PrefixList="..."> child
    for child in node.children() {
        if child.is_element() && child.tag_name().name() == ns::node::INCLUSIVE_NAMESPACES {
            if let Some(prefix_list) = child.attribute(ns::attr::PREFIX_LIST) {
                return prefix_list
                    .split_whitespace()
                    .map(|s| s.to_owned())
                    .collect();
            }
        }
    }
    Vec::new()
}
