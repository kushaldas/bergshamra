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
use uppsala::{Document, NodeId, NodeKind};

/// Canonicalize using Exclusive C14N 1.0.
pub fn canonicalize(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>, Error> {
    let prefix_set: HashSet<String> = inclusive_prefixes.iter().cloned().collect();
    let mut output = Vec::new();
    let mut ctx = ExcC14nContext {
        doc,
        with_comments,
        node_set,
        inclusive_prefixes: prefix_set,
    };
    ctx.process_node(doc.root(), &mut output, &BTreeMap::new())?;
    Ok(output)
}

struct ExcC14nContext<'a, 'doc> {
    doc: &'a Document<'doc>,
    with_comments: bool,
    node_set: Option<&'a NodeSet>,
    inclusive_prefixes: HashSet<String>,
}

impl<'a, 'doc> ExcC14nContext<'a, 'doc> {
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
        rendered_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        match self.doc.node_kind(id) {
            Some(NodeKind::Document) => {
                for child in self.doc.children(id) {
                    self.process_node(child, output, rendered_ns)?;
                }
            }
            Some(NodeKind::Element(_)) => {
                self.process_element(id, output, rendered_ns)?;
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
                    let parent_is_root = self.doc
                        .parent(id)
                        .is_some_and(|p| matches!(self.doc.node_kind(p), Some(NodeKind::Document)));

                    if parent_is_root {
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
        rendered_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let visible = self.is_visible(id);

        if visible {
            // Determine which namespace prefixes are "visibly utilized"
            let mut utilized_prefixes: HashSet<String> = HashSet::new();

            // 1. Prefix used by the element's tag name
            let elem_prefix = get_element_prefix(self.doc, id);
            utilized_prefixes.insert(elem_prefix.clone());

            // 2. Prefixes used by attributes
            {
                let elem = self.doc.element(id).unwrap();
                for attr in &elem.attributes {
                    if let Some(prefix) = get_attr_prefix(attr) {
                        if !prefix.is_empty() {
                            utilized_prefixes.insert(prefix);
                        }
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
            let inscope_ns = collect_inscope_namespaces(self.doc, id);

            // If namespace node visibility filtering is active, restrict
            // to only namespace nodes that are in the node set.
            let has_ns_filter = self.node_set
                .map_or(false, |ns| ns.has_ns_visible());
            let visible_inscope_ns = if has_ns_filter {
                let eid = id.index();
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
            {
                let elem = self.doc.element(id).unwrap();
                for attr in &elem.attributes {
                    let ns_uri = attr.name.namespace_uri.as_deref().unwrap_or("");
                    let qname = if let Some(prefix) = get_attr_prefix(attr) {
                        if prefix.is_empty() {
                            attr.name.local_name.to_string()
                        } else {
                            format!("{}:{}", prefix, attr.name.local_name)
                        }
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
            }
            attrs.sort();

            // Build qualified element name
            let elem_name = qualified_element_name(self.doc, id);

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
            for child in self.doc.children(id) {
                self.process_node(child, output, &child_rendered_ns)?;
            }

            // Close tag
            output.extend_from_slice(b"</");
            output.extend_from_slice(elem_name.as_bytes());
            output.push(b'>');
        } else {
            // Element not visible -- in exclusive C14N, namespace
            // declarations are only rendered on visible element start
            // tags.  However, for prefixes in InclusiveNamespaces
            // PrefixList, we follow inclusive C14N rules which include
            // outputting namespace nodes on invisible elements.
            let has_ns_filter = self.node_set
                .map_or(false, |ns| ns.has_ns_visible());
            if has_ns_filter && !self.inclusive_prefixes.is_empty() {
                let eid = id.index();
                let ns = self.node_set.unwrap();
                let inscope = collect_inscope_namespaces(self.doc, id);
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
            for child in self.doc.children(id) {
                self.process_node(child, output, rendered_ns)?;
            }
        }
        Ok(())
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

/// Get the prefix for an element's tag name.
fn get_element_prefix(doc: &Document<'_>, id: NodeId) -> String {
    let elem = doc.element(id).unwrap();
    elem.name.prefix.as_deref().unwrap_or("").to_owned()
}

/// Get the prefix for an attribute.
fn get_attr_prefix(attr: &uppsala::Attribute<'_>) -> Option<String> {
    if let Some(ns_uri) = &attr.name.namespace_uri {
        if &**ns_uri == "http://www.w3.org/XML/1998/namespace" {
            return Some("xml".to_owned());
        }
        Some(attr.name.prefix.as_deref().unwrap_or("").to_owned())
    } else {
        None
    }
}

/// Collect all in-scope namespaces for an element.
fn collect_inscope_namespaces(doc: &Document<'_>, id: NodeId) -> BTreeMap<String, String> {
    let mut ns_stack: Vec<BTreeMap<String, String>> = Vec::new();
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
fn qualified_element_name(doc: &Document<'_>, id: NodeId) -> String {
    let elem = doc.element(id).unwrap();
    if let Some(prefix) = &elem.name.prefix {
        format!("{}:{}", prefix, elem.name.local_name)
    } else {
        elem.name.local_name.to_string()
    }
}
