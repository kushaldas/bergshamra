#![forbid(unsafe_code)]

//! Exclusive Canonical XML 1.0 (exc-C14N).
//!
//! Algorithm URI: `http://www.w3.org/2001/10/xml-exc-c14n#`
//! With comments: `http://www.w3.org/2001/10/xml-exc-c14n#WithComments`
//!
//! The key difference from inclusive C14N: only "visibly utilized" namespace
//! declarations are output.  A namespace is visibly utilized if:
//! 1. Its prefix is used by the element's tag name, OR
//! 2. Its prefix is used by one of the element's attributes, OR
//! 3. The prefix appears in the InclusiveNamespaces PrefixList, OR
//! 4. It's the default namespace and the element is in that namespace.

use crate::escape;
use crate::render::{Attr, NsDecl};
use bergshamra_core::Error;
use bergshamra_xml::nodeset::NodeSet;
use std::collections::{BTreeMap, HashSet};

/// Canonicalize using Exclusive C14N 1.0.
pub fn canonicalize(
    doc: &roxmltree::Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>, Error> {
    let prefix_set: HashSet<String> = inclusive_prefixes.iter().cloned().collect();
    let mut output = Vec::new();
    let mut ctx = ExcC14nContext {
        with_comments,
        node_set,
        inclusive_prefixes: prefix_set,
    };
    ctx.process_node(doc.root(), &mut output, &BTreeMap::new())?;
    Ok(output)
}

struct ExcC14nContext<'a> {
    with_comments: bool,
    node_set: Option<&'a NodeSet>,
    inclusive_prefixes: HashSet<String>,
}

impl<'a> ExcC14nContext<'a> {
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
        rendered_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        match node.node_type() {
            roxmltree::NodeType::Root => {
                for child in node.children() {
                    self.process_node(child, output, rendered_ns)?;
                }
            }
            roxmltree::NodeType::Element => {
                self.process_element(node, output, rendered_ns)?;
            }
            roxmltree::NodeType::Text => {
                if self.is_visible(&node) {
                    let text = node.text().unwrap_or("");
                    output.extend_from_slice(escape::escape_text(text).as_bytes());
                }
            }
            roxmltree::NodeType::Comment => {
                if self.with_comments && self.is_visible(&node) {
                    let parent_is_root = node
                        .parent()
                        .is_some_and(|p| p.node_type() == roxmltree::NodeType::Root);

                    if parent_is_root {
                        let has_preceding_element = node.prev_siblings().any(|s| s.is_element());
                        if has_preceding_element {
                            output.push(b'\n');
                        }
                    }

                    output.extend_from_slice(b"<!--");
                    output.extend_from_slice(node.text().unwrap_or("").as_bytes());
                    output.extend_from_slice(b"-->");

                    if parent_is_root {
                        let has_following_element = node.next_siblings().any(|s| s.is_element());
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
                        let has_preceding_element = node.prev_siblings().any(|s| s.is_element());
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
                        let has_following_element = node.next_siblings().any(|s| s.is_element());
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
        rendered_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let visible = self.is_visible(&node);

        if visible {
            // Determine which namespace prefixes are "visibly utilized"
            let mut utilized_prefixes: HashSet<String> = HashSet::new();

            // 1. Prefix used by the element's tag name
            let elem_prefix = get_element_prefix(&node);
            utilized_prefixes.insert(elem_prefix.clone());

            // 2. Prefixes used by attributes
            for attr in node.attributes() {
                if let Some(prefix) = get_attr_prefix(&node, &attr) {
                    if !prefix.is_empty() {
                        utilized_prefixes.insert(prefix);
                    }
                }
            }

            // 3. Prefixes in the InclusiveNamespaces PrefixList
            // "#default" means the default namespace
            for p in &self.inclusive_prefixes {
                if p == "#default" {
                    utilized_prefixes.insert(String::new());
                } else {
                    utilized_prefixes.insert(p.clone());
                }
            }

            // Collect all in-scope namespaces
            let inscope_ns = collect_inscope_namespaces(&node);

            // If namespace node visibility filtering is active, restrict
            // to only namespace nodes that are in the node set.
            let has_ns_filter = self.node_set
                .map_or(false, |ns| ns.has_ns_visible());
            let visible_inscope_ns = if has_ns_filter {
                let eid = bergshamra_xml::nodeset::node_index(node);
                let ns = self.node_set.unwrap();
                inscope_ns.into_iter()
                    .filter(|(prefix, _)| ns.is_ns_visible(eid, prefix))
                    .collect()
            } else {
                inscope_ns
            };

            // Determine which namespace declarations to output
            let mut ns_decls: Vec<NsDecl> = Vec::new();
            for prefix in &utilized_prefixes {
                // Skip the xml namespace
                if prefix == "xml" {
                    continue;
                }

                if let Some(uri) = visible_inscope_ns.get(prefix) {
                    // Only output if different from what was previously rendered
                    let previously_rendered = rendered_ns.get(prefix);
                    if previously_rendered != Some(uri) {
                        ns_decls.push(NsDecl {
                            prefix: prefix.clone(),
                            uri: uri.clone(),
                        });
                    }
                } else if prefix.is_empty() {
                    // Default namespace: if it was previously non-empty and now should be empty,
                    // we need to output xmlns=""
                    let previously_rendered = rendered_ns.get("");
                    if previously_rendered.is_some() && !previously_rendered.unwrap().is_empty() {
                        ns_decls.push(NsDecl {
                            prefix: String::new(),
                            uri: String::new(),
                        });
                    }
                }
            }
            ns_decls.sort();

            // Collect attributes
            let mut attrs: Vec<Attr> = Vec::new();
            for attr in node.attributes() {
                let ns_uri = attr.namespace().unwrap_or("");
                let qname = if let Some(prefix) = get_attr_prefix(&node, &attr) {
                    if prefix.is_empty() {
                        attr.name().to_owned()
                    } else {
                        format!("{}:{}", prefix, attr.name())
                    }
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

            // Build qualified element name
            let elem_name = qualified_element_name(&node);

            // Output start tag
            output.push(b'<');
            output.extend_from_slice(elem_name.as_bytes());
            for ns_decl in &ns_decls {
                output.extend_from_slice(ns_decl.render().as_bytes());
            }
            for attr in &attrs {
                output.extend_from_slice(attr.render().as_bytes());
            }
            output.push(b'>');

            // Update rendered namespace context for children.
            let mut child_rendered_ns = rendered_ns.clone();
            for ns_decl in &ns_decls {
                child_rendered_ns.insert(ns_decl.prefix.clone(), ns_decl.uri.clone());
            }

            // When ns_visible filtering is active, break the rendering
            // chain for prefixes visibly utilized by this element whose
            // namespace node is NOT in the node-set.  Per the exc-c14n
            // spec, the "nearest output ancestor that visibly utilizes
            // the namespace prefix" must have its ns node in the
            // node-set for descendants to inherit the rendered binding.
            // Removing the prefix forces descendants to re-declare it.
            if has_ns_filter {
                for prefix in &utilized_prefixes {
                    if prefix == "xml" {
                        continue;
                    }
                    if !visible_inscope_ns.contains_key(prefix.as_str()) {
                        child_rendered_ns.remove(prefix.as_str());
                    }
                }
            }

            // Process children
            for child in node.children() {
                self.process_node(child, output, &child_rendered_ns)?;
            }

            // Close tag
            output.extend_from_slice(b"</");
            output.extend_from_slice(elem_name.as_bytes());
            output.push(b'>');
        } else {
            // Element not visible — in exclusive C14N, namespace
            // declarations are only rendered on visible element start
            // tags.  However, for prefixes in InclusiveNamespaces
            // PrefixList, we follow inclusive C14N rules which include
            // outputting namespace nodes on invisible elements.
            let has_ns_filter = self.node_set
                .map_or(false, |ns| ns.has_ns_visible());
            if has_ns_filter && !self.inclusive_prefixes.is_empty() {
                let eid = bergshamra_xml::nodeset::node_index(node);
                let ns = self.node_set.unwrap();
                let inscope = collect_inscope_namespaces(&node);
                let visible_ns: BTreeMap<String, String> = inscope.into_iter()
                    .filter(|(prefix, _)| ns.is_ns_visible(eid, prefix))
                    .filter(|(prefix, _)| {
                        // Only output for InclusiveNamespaces PrefixList
                        if prefix.is_empty() {
                            self.inclusive_prefixes.iter().any(|p| p == "#default")
                        } else {
                            self.inclusive_prefixes.contains(prefix)
                        }
                    })
                    .collect();
                let mut ns_decls: Vec<NsDecl> = Vec::new();
                for (prefix, uri) in &visible_ns {
                    if prefix == "xml" { continue; }
                    if rendered_ns.get(prefix) != Some(uri) {
                        ns_decls.push(NsDecl { prefix: prefix.clone(), uri: uri.clone() });
                    }
                }
                ns_decls.sort();
                for ns_decl in &ns_decls {
                    output.extend_from_slice(ns_decl.render().as_bytes());
                }
            }

            // Children inherit same rendered_ns (invisible element
            // doesn't affect the visible ancestor tracking).
            for child in node.children() {
                self.process_node(child, output, rendered_ns)?;
            }
        }
        Ok(())
    }
}

/// Get the prefix for an element's tag name.
fn get_element_prefix(node: &roxmltree::Node<'_, '_>) -> String {
    node.tag_name_prefix().unwrap_or("").to_owned()
}

/// Get the prefix for an attribute.
fn get_attr_prefix(
    _node: &roxmltree::Node<'_, '_>,
    attr: &roxmltree::Attribute<'_, '_>,
) -> Option<String> {
    if let Some(ns_uri) = attr.namespace() {
        if ns_uri == "http://www.w3.org/XML/1998/namespace" {
            return Some("xml".to_owned());
        }
        Some(attr.prefix().unwrap_or("").to_owned())
    } else {
        None
    }
}

/// Collect all in-scope namespaces for an element.
fn collect_inscope_namespaces(node: &roxmltree::Node<'_, '_>) -> BTreeMap<String, String> {
    let mut ns_stack: Vec<BTreeMap<String, String>> = Vec::new();
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

/// Get the qualified element name.
fn qualified_element_name(node: &roxmltree::Node<'_, '_>) -> String {
    if let Some(prefix) = node.tag_name_prefix() {
        format!("{}:{}", prefix, node.tag_name().name())
    } else {
        node.tag_name().name().to_owned()
    }
}
