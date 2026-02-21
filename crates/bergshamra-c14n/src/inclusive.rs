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

/// Canonicalize a document using Inclusive C14N 1.0.
pub fn canonicalize(
    doc: &roxmltree::Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut ctx = C14nContext {
        with_comments,
        node_set,
    };
    ctx.process_node(doc.root(), &mut output, &BTreeMap::new())?;
    Ok(output)
}

struct C14nContext<'a> {
    with_comments: bool,
    node_set: Option<&'a NodeSet>,
}

impl<'a> C14nContext<'a> {
    fn is_visible(&self, node: &roxmltree::Node<'_, '_>) -> bool {
        match self.node_set {
            None => true,
            Some(ns) => ns.contains(node),
        }
    }

    fn process_node(
        &mut self,
        node: roxmltree::Node<'_, '_>,
        output: &mut Vec<u8>,
        inherited_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        match node.node_type() {
            roxmltree::NodeType::Root => {
                for child in node.children() {
                    self.process_node(child, output, inherited_ns)?;
                }
            }
            roxmltree::NodeType::Element => {
                self.process_element(node, output, inherited_ns)?;
            }
            roxmltree::NodeType::Text => {
                if self.is_visible(&node) {
                    let text = node.text().unwrap_or("");
                    output.extend_from_slice(escape::escape_text(text).as_bytes());
                }
            }
            roxmltree::NodeType::Comment => {
                if self.with_comments && self.is_visible(&node) {
                    // Check if we need newlines around comments at the document level
                    let parent_is_root = node
                        .parent()
                        .is_some_and(|p| p.node_type() == roxmltree::NodeType::Root);

                    if parent_is_root {
                        // Before document element: comment\n
                        // After document element: \ncomment
                        let has_preceding_element = node
                            .prev_siblings()
                            .any(|s| s.is_element());
                        if has_preceding_element {
                            output.push(b'\n');
                        }
                    }

                    output.extend_from_slice(b"<!--");
                    output.extend_from_slice(
                        node.text().unwrap_or("").as_bytes(),
                    );
                    output.extend_from_slice(b"-->");

                    if parent_is_root {
                        let has_following_element = node
                            .next_siblings()
                            .any(|s| s.is_element());
                        if has_following_element {
                            output.push(b'\n');
                        }
                    }
                }
            }
            roxmltree::NodeType::PI => {
                if self.is_visible(&node) {
                    let parent_is_root = node
                        .parent()
                        .is_some_and(|p| p.node_type() == roxmltree::NodeType::Root);

                    if parent_is_root {
                        let has_preceding_element = node
                            .prev_siblings()
                            .any(|s| s.is_element());
                        if has_preceding_element {
                            output.push(b'\n');
                        }
                    }

                    output.extend_from_slice(b"<?");
                    output.extend_from_slice(node.tag_name().name().as_bytes());
                    if let Some(value) = node.text() {
                        if !value.is_empty() {
                            output.push(b' ');
                            output.extend_from_slice(escape::escape_pi(value).as_bytes());
                        }
                    }
                    output.extend_from_slice(b"?>");

                    if parent_is_root {
                        let has_following_element = node
                            .next_siblings()
                            .any(|s| s.is_element());
                        if has_following_element {
                            output.push(b'\n');
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn process_element(
        &mut self,
        node: roxmltree::Node<'_, '_>,
        output: &mut Vec<u8>,
        inherited_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let visible = self.is_visible(&node);

        if visible {
            // Collect all namespace declarations that are "in scope" at this element.
            // For inclusive C14N, this means all namespaces declared on this element
            // and all ancestors that haven't been overridden.
            let current_ns = collect_inscope_namespaces(&node);

            // If the node set has namespace node visibility filtering,
            // restrict in-scope namespaces to only those whose namespace
            // node is in the node-set (per C14N spec section 2.3).
            let has_ns_filter = self.node_set
                .map_or(false, |ns| ns.has_ns_visible());
            let visible_ns: BTreeMap<String, String> = if has_ns_filter {
                let eid = bergshamra_xml::nodeset::node_index(node);
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
            let mut attrs: Vec<Attr> = Vec::new();
            for attr in node.attributes() {
                let ns_uri = attr.namespace().unwrap_or("");
                // Build qualified name
                let qname = if let Some(prefix) = find_attr_prefix(&node, &attr) {
                    format!("{}:{}", prefix, attr.name())
                } else {
                    attr.name().to_owned()
                };
                attrs.push(Attr {
                    ns_uri: ns_uri.to_owned(),
                    local_name: attr.name().to_owned(),
                    qualified_name: qname,
                    value: attr.value().to_owned(),
                });
            }
            attrs.sort();

            // Also check for xml:* attributes that need to be inherited.
            // Per C14N 1.0 spec (and libxml2): xml:* inheritance only happens
            // when the element is visible but its immediate parent is NOT
            // visible in the node set. If the parent IS visible, it will
            // output its own xml:* attrs, so no inheritance is needed.
            if self.node_set.is_some() {
                let parent_not_visible = node
                    .parent()
                    .map_or(true, |p| !p.is_element() || !self.is_visible(&p));
                if parent_not_visible {
                    let extra = self.collect_inherited_xml_attrs(&node, &attrs);
                    attrs.extend(extra);
                }
            }
            // Re-sort after possible additions
            attrs.sort();

            // Build qualified element name
            let elem_name = qualified_element_name(&node);

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

            for child in node.children() {
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
                let eid = bergshamra_xml::nodeset::node_index(node);
                let ns = self.node_set.unwrap();

                // Collect this element's in-scope namespaces
                let current_ns = collect_inscope_namespaces(&node);

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
                    if inherited_ns.get(prefix) != Some(uri) {
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
            for child in node.children() {
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
        node: &roxmltree::Node<'_, '_>,
        existing_attrs: &[Attr],
    ) -> Vec<Attr> {
        let xml_ns = "http://www.w3.org/XML/1998/namespace";
        let mut inherited_xml: BTreeMap<String, String> = BTreeMap::new();

        let mut current = node.parent();
        while let Some(ancestor) = current {
            if ancestor.is_element() {
                for attr in ancestor.attributes() {
                    if attr.namespace() == Some(xml_ns) {
                        let name = attr.name();
                        // Nearest ancestor value wins (first occurrence)
                        if !inherited_xml.contains_key(name) {
                            inherited_xml.insert(name.to_owned(), attr.value().to_owned());
                        }
                    }
                }
            }
            current = ancestor.parent();
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

/// Collect all in-scope namespaces for an element.
///
/// This walks up the ancestor chain and collects all namespace declarations,
/// with closer declarations overriding more distant ones.
fn collect_inscope_namespaces(node: &roxmltree::Node<'_, '_>) -> BTreeMap<String, String> {
    let mut ns_stack: Vec<BTreeMap<String, String>> = Vec::new();

    // Walk up to root, collecting namespaces at each level
    let mut current = Some(*node);
    while let Some(n) = current {
        if n.is_element() {
            let mut level = BTreeMap::new();
            for ns in n.namespaces() {
                let prefix = ns.name().unwrap_or("").to_owned();
                let uri = ns.uri().to_owned();
                level.insert(prefix, uri);
            }
            ns_stack.push(level);
        }
        current = n.parent();
    }

    // Merge from root down (root is last in stack)
    let mut result = BTreeMap::new();
    for level in ns_stack.into_iter().rev() {
        for (prefix, uri) in level {
            if uri.is_empty() {
                // Un-declaration of default namespace
                result.remove(&prefix);
            } else {
                result.insert(prefix, uri);
            }
        }
    }
    result
}

/// Get the qualified element name (prefix:local or just local).
fn qualified_element_name(node: &roxmltree::Node<'_, '_>) -> String {
    if let Some(prefix) = node.tag_name_prefix() {
        format!("{}:{}", prefix, node.tag_name().name())
    } else {
        node.tag_name().name().to_owned()
    }
}

/// Find the prefix for an attribute's namespace.
fn find_attr_prefix<'a>(
    _node: &roxmltree::Node<'a, 'a>,
    attr: &roxmltree::Attribute<'a, 'a>,
) -> Option<String> {
    if let Some(ns_uri) = attr.namespace() {
        if ns_uri == "http://www.w3.org/XML/1998/namespace" {
            return Some("xml".to_owned());
        }
        attr.prefix().map(|p| p.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_c14n() {
        let xml = r#"<root><a b="1" a="2"/></root>"#;
        let result = canonicalize(
            &roxmltree::Document::parse(xml).unwrap(),
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
        let result = canonicalize(
            &roxmltree::Document::parse(xml).unwrap(),
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
        let result = canonicalize(
            &roxmltree::Document::parse(xml).unwrap(),
            false,
            None,
        )
        .unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "<root>a &amp; b &lt; c</root>");
    }
}
