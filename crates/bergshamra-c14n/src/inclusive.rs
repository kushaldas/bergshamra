#![forbid(unsafe_code)]

//! Inclusive Canonical XML 1.0 (C14N 1.0).
//!
//! Algorithm URI: `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
//! With comments: `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`
//!
//! Per the spec, the canonical form:
//! - Outputs namespace declarations sorted by prefix (default first)
//! - Outputs attributes sorted by (namespace-URI, local-name)
//! - Escapes text and attribute values per C14N rules
//! - Optionally preserves or strips comments
//! - Supports document-subset canonicalization via NodeSet

use crate::escape;
use crate::render::{Attr, NsDecl};
use bergshamra_core::Error;
use bergshamra_xml::nodeset::NodeSet;
use std::collections::BTreeMap;
use uppsala::{Document, NodeId, NodeKind};

/// Canonicalize a document using Inclusive C14N 1.0.
pub fn canonicalize(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
) -> Result<Vec<u8>, Error> {
    canonicalize_with_options(doc, with_comments, node_set, false)
}

/// Canonicalize with optional C14N 1.1 xml:base absolutization.
pub fn canonicalize_with_options(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    c14n11_mode: bool,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut ctx = C14nContext {
        doc,
        with_comments,
        node_set,
        c14n11_mode,
    };
    ctx.process_node(doc.root(), &mut output, &BTreeMap::new())?;
    Ok(output)
}

struct C14nContext<'a, 'doc> {
    doc: &'a Document<'doc>,
    with_comments: bool,
    node_set: Option<&'a NodeSet>,
    c14n11_mode: bool,
}

impl<'a, 'doc> C14nContext<'a, 'doc> {
    fn is_visible(&self, id: NodeId) -> bool {
        match self.node_set {
            None => true,
            Some(ns) => ns.contains_id(id),
        }
    }

    fn process_node(
        &mut self,
        id: NodeId,
        output: &mut Vec<u8>,
        inherited_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        match self.doc.node_kind(id) {
            Some(NodeKind::Document) => {
                for child in self.doc.children(id) {
                    self.process_node(child, output, inherited_ns)?;
                }
            }
            Some(NodeKind::Element(_)) => {
                self.process_element(id, output, inherited_ns)?;
            }
            Some(NodeKind::Text(text)) | Some(NodeKind::CData(text)) => {
                if self.is_visible(id) {
                    let text = text.clone();
                    output.extend_from_slice(escape::escape_text(&text).as_bytes());
                }
            }
            Some(NodeKind::Comment(text)) => {
                if self.with_comments && self.is_visible(id) {
                    let text = text.clone();
                    // Check if we need newlines around comments at the document level
                    let parent_is_root = self.doc
                        .parent(id)
                        .is_some_and(|p| matches!(self.doc.node_kind(p), Some(NodeKind::Document)));

                    if parent_is_root {
                        // Before document element: comment\n
                        // After document element: \ncomment
                        let has_preceding_element = has_preceding_element(self.doc, id);
                        if has_preceding_element {
                            output.push(b'\n');
                        }
                    }

                    output.extend_from_slice(b"<!--");
                    output.extend_from_slice(text.as_bytes());
                    output.extend_from_slice(b"-->");

                    if parent_is_root {
                        let has_following_element = has_following_element(self.doc, id);
                        if has_following_element {
                            output.push(b'\n');
                        }
                    }
                }
            }
            Some(NodeKind::ProcessingInstruction(pi)) => {
                if self.is_visible(id) {
                    let target = pi.target.clone();
                    let data = pi.data.clone();

                    let parent_is_root = self.doc
                        .parent(id)
                        .is_some_and(|p| matches!(self.doc.node_kind(p), Some(NodeKind::Document)));

                    if parent_is_root {
                        let has_preceding_element = has_preceding_element(self.doc, id);
                        if has_preceding_element {
                            output.push(b'\n');
                        }
                    }

                    output.extend_from_slice(b"<?");
                    output.extend_from_slice(target.as_bytes());
                    if let Some(value) = &data {
                        if !value.is_empty() {
                            output.push(b' ');
                            output.extend_from_slice(escape::escape_pi(value).as_bytes());
                        }
                    }
                    output.extend_from_slice(b"?>");

                    if parent_is_root {
                        let has_following_element = has_following_element(self.doc, id);
                        if has_following_element {
                            output.push(b'\n');
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn process_element(
        &mut self,
        id: NodeId,
        output: &mut Vec<u8>,
        inherited_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let visible = self.is_visible(id);

        if visible {
            // Collect all namespace declarations that are "in scope" at this element.
            // For inclusive C14N, this means all namespaces declared on this element
            // and all ancestors that haven't been overridden.
            let current_ns = collect_inscope_namespaces(self.doc, id);

            // If the node set has namespace node visibility filtering,
            // restrict in-scope namespaces to only those whose namespace
            // node is in the node-set (per C14N spec section 2.3).
            let has_ns_filter = self.node_set
                .map_or(false, |ns| ns.has_ns_visible());
            let visible_ns: BTreeMap<String, String> = if has_ns_filter {
                let eid = id.index();
                let ns = self.node_set.unwrap();
                current_ns.into_iter()
                    .filter(|(prefix, _)| ns.is_ns_visible(eid, prefix))
                    .collect()
            } else {
                current_ns
            };

            // Determine which namespace declarations to output:
            // Output a namespace declaration if:
            // 1. It's not the xml namespace (never output xmlns:xml=...)
            // 2. It's new or different from what was inherited
            let mut ns_decls: Vec<NsDecl> = Vec::new();
            for (prefix, uri) in &visible_ns {
                // Skip xml namespace
                if prefix == "xml" {
                    continue;
                }
                // Only output if different from inherited
                let inherited_val = inherited_ns.get(prefix);
                if inherited_val != Some(uri) {
                    // C14N spec step 3e: if the prefix is not in the
                    // inherited/rendered set and the URI is empty,
                    // do nothing (don't output xmlns="" when no ancestor
                    // had a default namespace to undeclare).
                    if uri.is_empty() && inherited_val.is_none() {
                        continue;
                    }
                    ns_decls.push(NsDecl {
                        prefix: prefix.clone(),
                        uri: uri.clone(),
                    });
                }
            }

            // C14N spec: if the nearest visible ancestor had a non-empty
            // default namespace but this element's default namespace node
            // is NOT in the node set, output xmlns="" to undeclare it.
            if has_ns_filter {
                if let Some(inherited_default) = inherited_ns.get("") {
                    if !inherited_default.is_empty() && !visible_ns.contains_key("") {
                        ns_decls.push(NsDecl {
                            prefix: String::new(),
                            uri: String::new(),
                        });
                    }
                }
            }

            ns_decls.sort();

            // Collect attributes (non-namespace)
            // Skip if the node set excludes attribute nodes entirely.
            let attrs_excluded = self.node_set
                .map_or(false, |ns| ns.excludes_attrs());
            let mut attrs: Vec<Attr> = Vec::new();
            if !attrs_excluded {
                let elem = self.doc.element(id).unwrap();
                for attr in &elem.attributes {
                    let ns_uri = attr.name.namespace_uri.as_deref().unwrap_or("");
                    // Build qualified name
                    let qname = if let Some(prefix) = find_attr_prefix(attr) {
                        format!("{}:{}", prefix, attr.name.local_name)
                    } else {
                        attr.name.local_name.to_string()
                    };
                    attrs.push(Attr {
                        ns_uri: ns_uri.to_owned(),
                        local_name: attr.name.local_name.to_string(),
                        qualified_name: qname,
                        value: attr.value.to_string(),
                    });
                }
            } // end if !attrs_excluded
            attrs.sort();

            // Also check for xml:* attributes that need to be inherited.
            // Per C14N 1.0 spec (and libxml2): xml:* inheritance only happens
            // when the element is visible but its immediate parent is NOT
            // visible in the node set. If the parent IS visible, it will
            // output its own xml:* attrs, so no inheritance is needed.
            // Skip when attribute nodes are excluded from the node set.
            if self.node_set.is_some() && !attrs_excluded {
                let parent_not_visible = self.doc
                    .parent(id)
                    .map_or(true, |p| self.doc.element(p).is_none() || !self.is_visible(p));
                if parent_not_visible {
                    let extra = self.collect_inherited_xml_attrs(id, &attrs);
                    attrs.extend(extra);

                    // C14N 1.1: absolutize xml:base for elements whose parent
                    // is not in the node set.
                    if self.c14n11_mode {
                        let abs_base = compute_absolute_base_uri(self.doc, id);
                        let xml_ns = "http://www.w3.org/XML/1998/namespace";
                        if let Some(attr) = attrs
                            .iter_mut()
                            .find(|a| a.ns_uri == xml_ns && a.local_name == "base")
                        {
                            // Replace the value with the absolute base URI
                            if !abs_base.is_empty() {
                                attr.value = abs_base;
                            }
                        } else if !abs_base.is_empty() {
                            // Synthesize xml:base if there are ancestor base URIs
                            // that would change the effective base
                            attrs.push(Attr {
                                ns_uri: xml_ns.to_owned(),
                                local_name: "base".to_owned(),
                                qualified_name: "xml:base".to_owned(),
                                value: abs_base,
                            });
                        }
                    }
                }
            }
            // Re-sort after possible additions
            attrs.sort();

            // Build qualified element name
            let elem_name = qualified_element_name(self.doc, id);

            // Output: <name ns-decls attrs>
            output.push(b'<');
            output.extend_from_slice(elem_name.as_bytes());
            for ns_decl in &ns_decls {
                output.extend_from_slice(ns_decl.render().as_bytes());
            }
            for attr in &attrs {
                output.extend_from_slice(attr.render().as_bytes());
            }
            output.push(b'>');

            // Process children with updated namespace context.
            // Per C14N spec (section 2.3): the "nearest ancestor element in
            // the node-set" check for namespace output means children should
            // only see namespace declarations that this element has in its
            // namespace node-set. When ns filtering is active, child_ns is
            // set to this element's visible_ns (not accumulated from ancestors).
            let child_ns = if has_ns_filter {
                // With namespace node filtering: children see only this
                // element's visible namespace nodes. This ensures that when
                // a child has a namespace node in its set that the parent
                // didn't, it correctly outputs a new declaration.
                let mut cn = BTreeMap::new();
                for (prefix, uri) in &visible_ns {
                    if prefix != "xml" {
                        cn.insert(prefix.clone(), uri.clone());
                    }
                }
                cn
            } else {
                let mut cn = inherited_ns.clone();
                for (prefix, uri) in &visible_ns {
                    if prefix != "xml" {
                        cn.insert(prefix.clone(), uri.clone());
                    }
                }
                cn
            };

            for child in self.doc.children(id) {
                self.process_node(child, output, &child_ns)?;
            }

            // Close tag
            output.extend_from_slice(b"</");
            output.extend_from_slice(elem_name.as_bytes());
            output.push(b'>');
        } else {
            // Element not visible, but per C14N 1.0 spec (section 2.3):
            // "If the element is not in the node-set, then the result is
            // obtained by processing the namespace axis, then the attribute
            // axis, then the child nodes of the element that are in the
            // node-set."
            //
            // When namespace node filtering is active, visible namespace
            // nodes on invisible elements are output as text (not attached
            // to an element tag). This produces the ` xmlns:prefix="URI"`
            // text that appears "floating" in the canonical form.
            let has_ns_filter = self.node_set
                .map_or(false, |ns| ns.has_ns_visible());
            if has_ns_filter {
                let eid = id.index();
                let ns = self.node_set.unwrap();

                // Collect this element's in-scope namespaces
                let current_ns = collect_inscope_namespaces(self.doc, id);

                // Filter by ns_visible
                let visible_ns: BTreeMap<String, String> = current_ns.into_iter()
                    .filter(|(prefix, _)| ns.is_ns_visible(eid, prefix))
                    .collect();

                // Output namespace declarations for visible ns nodes
                // that differ from what was inherited (nearest visible ancestor).
                let mut ns_decls: Vec<NsDecl> = Vec::new();
                for (prefix, uri) in &visible_ns {
                    if prefix == "xml" {
                        continue;
                    }
                    let inherited_val = inherited_ns.get(prefix);
                    if inherited_val != Some(uri) {
                        // C14N spec step 3e: skip empty URI when not
                        // previously rendered
                        if uri.is_empty() && inherited_val.is_none() {
                            continue;
                        }
                        ns_decls.push(NsDecl {
                            prefix: prefix.clone(),
                            uri: uri.clone(),
                        });
                    }
                }
                ns_decls.sort();
                for ns_decl in &ns_decls {
                    output.extend_from_slice(ns_decl.render().as_bytes());
                }
            }

            // Children inherit the SAME inherited_ns (not the invisible
            // element's visible_ns). Per C14N spec, the "nearest ancestor
            // element in the node-set" check is based on visible ancestors
            // only. Invisible element ns output does not affect what
            // visible descendants render.
            for child in self.doc.children(id) {
                self.process_node(child, output, inherited_ns)?;
            }
        }
        Ok(())
    }

    /// For document-subset C14N 1.0: collect xml:* attributes inherited from
    /// ancestors. Called only when the element's immediate parent is NOT
    /// visible. Per the spec and libxml2, we walk ALL ancestors (regardless
    /// of visibility) collecting xml:* attrs, then remove any already
    /// present on the element's own attribute axis.
    fn collect_inherited_xml_attrs(
        &self,
        id: NodeId,
        existing_attrs: &[Attr],
    ) -> Vec<Attr> {
        let xml_ns = "http://www.w3.org/XML/1998/namespace";
        let mut inherited_xml: BTreeMap<String, String> = BTreeMap::new();

        let mut current = self.doc.parent(id);
        while let Some(ancestor) = current {
            if let Some(elem) = self.doc.element(ancestor) {
                for attr in &elem.attributes {
                    if attr.name.namespace_uri.as_deref() == Some(xml_ns) {
                        let name = &*attr.name.local_name;
                        // Nearest ancestor value wins (first occurrence)
                        if !inherited_xml.contains_key(name) {
                            inherited_xml.insert(name.to_owned(), attr.value.to_string());
                        }
                    }
                }
            }
            current = self.doc.parent(ancestor);
        }

        let mut result = Vec::new();
        for (name, value) in &inherited_xml {
            let already_present = existing_attrs
                .iter()
                .any(|a| a.ns_uri == xml_ns && a.local_name == *name);
            if !already_present {
                result.push(Attr {
                    ns_uri: xml_ns.to_owned(),
                    local_name: name.clone(),
                    qualified_name: format!("xml:{name}"),
                    value: value.clone(),
                });
            }
        }
        result
    }
}

/// Check if any preceding sibling is an element.
fn has_preceding_element(doc: &Document<'_>, id: NodeId) -> bool {
    let mut sib = doc.previous_sibling(id);
    while let Some(s) = sib {
        if doc.element(s).is_some() {
            return true;
        }
        sib = doc.previous_sibling(s);
    }
    false
}

/// Check if any following sibling is an element.
fn has_following_element(doc: &Document<'_>, id: NodeId) -> bool {
    let mut sib = doc.next_sibling(id);
    while let Some(s) = sib {
        if doc.element(s).is_some() {
            return true;
        }
        sib = doc.next_sibling(s);
    }
    false
}

/// Collect all in-scope namespaces for an element.
///
/// This walks up the ancestor chain and collects all namespace declarations,
/// with closer declarations overriding more distant ones.
fn collect_inscope_namespaces(doc: &Document<'_>, id: NodeId) -> BTreeMap<String, String> {
    let mut ns_stack: Vec<BTreeMap<String, String>> = Vec::new();

    // Walk up to root, collecting namespaces at each level
    let mut current = Some(id);
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

    // Merge from root down (root is last in stack)
    let mut result = BTreeMap::new();
    for level in ns_stack.into_iter().rev() {
        for (prefix, uri) in level {
            if uri.is_empty() && prefix.is_empty() {
                // xmlns="" undeclares the default namespace.
                // Keep it as an empty-string entry so C14N can emit xmlns=""
                // when the inherited default was non-empty.
                result.insert(prefix, uri);
            } else if uri.is_empty() {
                // Undeclaration of a prefixed namespace (only valid in XML 1.1)
                result.remove(&prefix);
            } else {
                result.insert(prefix, uri);
            }
        }
    }
    result
}

/// Get the qualified element name (prefix:local or just local).
fn qualified_element_name(doc: &Document<'_>, id: NodeId) -> String {
    let elem = doc.element(id).unwrap();
    if let Some(prefix) = &elem.name.prefix {
        format!("{}:{}", prefix, elem.name.local_name)
    } else {
        elem.name.local_name.to_string()
    }
}

/// Find the prefix for an attribute's namespace.
fn find_attr_prefix(attr: &uppsala::Attribute<'_>) -> Option<String> {
    if let Some(ns_uri) = &attr.name.namespace_uri {
        if &**ns_uri == "http://www.w3.org/XML/1998/namespace" {
            return Some("xml".to_owned());
        }
        attr.name.prefix.as_ref().map(|p| p.to_string())
    } else {
        None
    }
}

/// Compute the absolute base URI for an element by walking up ancestors
/// and resolving xml:base attributes according to RFC 3986.
///
/// Used by C14N 1.1 for document-subset canonicalization when an element's
/// parent is not in the node set.
fn compute_absolute_base_uri(doc: &Document<'_>, id: NodeId) -> String {
    let xml_ns = "http://www.w3.org/XML/1998/namespace";

    // Collect xml:base values from the element up to the root.
    // Order: element first, then parent, grandparent, etc.
    let mut base_chain: Vec<String> = Vec::new();
    let mut current = Some(id);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            for attr in &elem.attributes {
                if attr.name.namespace_uri.as_deref() == Some(xml_ns)
                    && &*attr.name.local_name == "base"
                {
                    base_chain.push(attr.value.to_string());
                    break;
                }
            }
        }
        current = doc.parent(n);
    }

    if base_chain.is_empty() {
        return String::new();
    }

    // Resolve from root to element: the last item is closest to root.
    // Start with the most distant ancestor's base and resolve each
    // descendant's base against it.
    base_chain.reverse(); // now root-first order
    let mut absolute = String::new();
    for base_val in &base_chain {
        if absolute.is_empty() {
            absolute = base_val.clone();
        } else {
            absolute = resolve_uri_reference(&absolute, base_val);
        }
    }

    absolute
}

/// Simple RFC 3986 URI reference resolution.
///
/// Resolves `reference` against `base_uri`.
fn resolve_uri_reference(base: &str, reference: &str) -> String {
    // If reference has a scheme, it's absolute -- use as-is
    if reference.contains("://") {
        return reference.to_owned();
    }

    // Parse base URI components
    let (scheme, authority, base_path) = parse_uri_components(base);

    if reference.starts_with('/') {
        // Absolute path reference: keep scheme + authority, replace path
        format!("{scheme}{authority}{reference}")
    } else if reference.is_empty() {
        base.to_owned()
    } else {
        // Relative path: merge with base path
        let merged = if authority.is_empty() && base_path.is_empty() {
            format!("/{reference}")
        } else {
            // Remove everything after the last '/' in base path
            let last_slash = base_path.rfind('/').map_or(0, |i| i + 1);
            format!("{}{}", &base_path[..last_slash], reference)
        };
        format!("{scheme}{authority}{merged}")
    }
}

/// Parse a URI into (scheme_with_colon, authority_with_slashes, path).
/// E.g. "http://example.org/path/" -> ("http:", "//example.org", "/path/")
fn parse_uri_components(uri: &str) -> (String, String, String) {
    // Find scheme
    let (scheme, rest) = if let Some(pos) = uri.find("://") {
        (uri[..pos + 1].to_owned(), &uri[pos + 1..])
    } else {
        (String::new(), uri)
    };

    // Find authority
    let (authority, path) = if rest.starts_with("//") {
        // Authority is //host[:port] up to next '/'
        if let Some(slash_pos) = rest[2..].find('/') {
            (rest[..slash_pos + 2].to_owned(), rest[slash_pos + 2..].to_owned())
        } else {
            (rest.to_owned(), String::new())
        }
    } else {
        (String::new(), rest.to_owned())
    };

    (scheme, authority, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_c14n() {
        let xml = r#"<root><a b="1" a="2"/></root>"#;
        let doc = uppsala::parse(xml).unwrap();
        let result = canonicalize(
            &doc,
            false,
            None,
        )
        .unwrap();
        let output = String::from_utf8(result).unwrap();
        // Attributes should be sorted by local name (no namespace)
        assert_eq!(output, r#"<root><a a="2" b="1"></a></root>"#);
    }

    #[test]
    fn test_namespace_rendering() {
        let xml = r#"<root xmlns:a="http://a" xmlns:b="http://b"><a:child/></root>"#;
        let doc = uppsala::parse(xml).unwrap();
        let result = canonicalize(
            &doc,
            false,
            None,
        )
        .unwrap();
        let output = String::from_utf8(result).unwrap();
        assert!(output.contains("xmlns:a=\"http://a\""));
        assert!(output.contains("xmlns:b=\"http://b\""));
    }

    #[test]
    fn test_text_escaping() {
        let xml = r#"<root>a &amp; b &lt; c</root>"#;
        let doc = uppsala::parse(xml).unwrap();
        let result = canonicalize(
            &doc,
            false,
            None,
        )
        .unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "<root>a &amp; b &lt; c</root>");
    }
}
