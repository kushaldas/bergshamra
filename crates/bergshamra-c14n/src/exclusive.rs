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

use crate::render::{Attr, NsDecl};
use crate::{escape, C14nSink};
use bergshamra_core::Error;
use bergshamra_xml::nodeset::NodeSet;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use uppsala::{Document, NodeId, NodeKind};

/// Canonicalize using Exclusive C14N 1.0.
///
/// `inclusive_prefixes` is the InclusiveNamespaces PrefixList from an
/// `ec:InclusiveNamespaces` transform parameter. Prefixes are compared after
/// converting each entry with [`AsRef<str>`]; use `"#default"` for the default
/// namespace as specified by Exclusive C14N.
///
/// # Errors
///
/// Returns an error if canonicalization cannot be completed.
pub fn canonicalize<S: AsRef<str>>(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[S],
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    canonicalize_to(
        doc,
        with_comments,
        node_set,
        inclusive_prefixes,
        &mut output,
    )?;
    Ok(output)
}

/// Canonicalize using Exclusive C14N 1.0 into a byte sink.
///
/// This is the streaming form of [`canonicalize`]. It writes the exact same
/// bytes into `output` without allocating a complete canonical byte vector.
///
/// # Errors
///
/// Returns the same errors as [`canonicalize`].
pub fn canonicalize_to<S: AsRef<str>, W: C14nSink>(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[S],
    output: &mut W,
) -> Result<(), Error> {
    let prefix_set: HashSet<String> = inclusive_prefixes
        .iter()
        .map(|s| s.as_ref().to_owned())
        .collect();
    let mut ctx = ExcC14nContext {
        doc,
        with_comments,
        node_set,
        inclusive_prefixes: prefix_set,
    };
    let mut rendered_ns = BTreeMap::new();
    let mut inscope_ns = BTreeMap::new();
    ctx.process_node(doc.root(), output, &mut rendered_ns, &mut inscope_ns)
}

struct ExcC14nContext<'a, 'doc> {
    doc: &'a Document<'doc>,
    with_comments: bool,
    node_set: Option<&'a NodeSet>,
    inclusive_prefixes: HashSet<String>,
}

impl<'a, 'doc> ExcC14nContext<'a, 'doc> {
    /// Return whether `id` is visible according to the optional document
    /// subset. Invisible elements can still affect traversal because selected
    /// descendants must be serialized.
    fn is_visible(&self, id: NodeId) -> bool {
        match self.node_set {
            None => true,
            Some(ns) => ns.contains_id(id),
        }
    }

    /// Process a node in document order.
    ///
    /// `rendered_ns` records namespace bindings that have already been emitted
    /// by visible ancestors. Exclusive C14N uses this to avoid repeating
    /// bindings unless the current element visibly uses a prefix that needs a
    /// new declaration.
    fn process_node<W: C14nSink>(
        &mut self,
        id: NodeId,
        output: &mut W,
        rendered_ns: &mut BTreeMap<String, String>,
        inscope_ns: &mut BTreeMap<String, String>,
    ) -> Result<(), Error> {
        match self.doc.node_kind(id) {
            Some(NodeKind::Document) => {
                for child in self.doc.children_iter(id) {
                    self.process_node(child, output, rendered_ns, inscope_ns)?;
                }
            }
            Some(NodeKind::Element(_)) => {
                // Namespace scope follows every element, including invisible
                // ones. Apply only this element's declarations and restore the
                // parent scope after its complete subtree has been visited.
                let scope_changes = apply_element_namespaces(self.doc, id, inscope_ns);
                let result = self.process_element(id, output, rendered_ns, inscope_ns);
                restore_namespaces(inscope_ns, scope_changes);
                result?;
            }
            Some(NodeKind::Text(text)) | Some(NodeKind::CData(text)) if self.is_visible(id) => {
                escape::escape_text_into(output, text);
            }
            Some(NodeKind::Comment(text)) if self.with_comments && self.is_visible(id) => {
                // Borrowed from the document arena; no per-node String.
                let parent_is_root = self
                    .doc
                    .parent(id)
                    .is_some_and(|p| matches!(self.doc.node_kind(p), Some(NodeKind::Document)));

                if parent_is_root {
                    let has_preceding_element = has_preceding_element(self.doc, id);
                    if has_preceding_element {
                        output.write_byte(b'\n');
                    }
                }

                output.write(b"<!--");
                output.write(text.as_bytes());
                output.write(b"-->");

                if parent_is_root {
                    let has_following_element = has_following_element(self.doc, id);
                    if has_following_element {
                        output.write_byte(b'\n');
                    }
                }
            }
            Some(NodeKind::ProcessingInstruction(pi)) if self.is_visible(id) => {
                // Borrowed from the document arena; no per-node Strings.
                let parent_is_root = self
                    .doc
                    .parent(id)
                    .is_some_and(|p| matches!(self.doc.node_kind(p), Some(NodeKind::Document)));

                if parent_is_root {
                    let has_preceding_element = has_preceding_element(self.doc, id);
                    if has_preceding_element {
                        output.write_byte(b'\n');
                    }
                }

                output.write(b"<?");
                output.write(pi.target.as_bytes());
                if let Some(value) = &pi.data {
                    if !value.is_empty() {
                        output.write_byte(b' ');
                        escape::escape_pi_into(output, value);
                    }
                }
                output.write(b"?>");

                if parent_is_root {
                    let has_following_element = has_following_element(self.doc, id);
                    if has_following_element {
                        output.write_byte(b'\n');
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Process an element according to Exclusive C14N visibility rules.
    ///
    /// Unlike inclusive C14N, namespace declarations are emitted only when the
    /// prefix is visibly utilized by the current element, its attributes, or
    /// the InclusiveNamespaces PrefixList. When namespace-node filtering is
    /// active, the rendered namespace chain may be broken so descendants
    /// re-declare prefixes whose namespace nodes were not visible here.
    fn process_element<W: C14nSink>(
        &mut self,
        id: NodeId,
        output: &mut W,
        rendered_ns: &mut BTreeMap<String, String>,
        inscope_ns: &mut BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let visible = self.is_visible(id);

        if visible {
            // Determine which namespace prefixes are "visibly utilized"
            let mut utilized_prefixes: HashSet<String> = HashSet::new();

            // 1. Prefix used by the element's tag name
            let elem_prefix = get_element_prefix(self.doc, id)?;
            utilized_prefixes.insert(elem_prefix);

            // 2. Prefixes used by attributes
            {
                let elem = element_of(self.doc, id)?;
                for attr in &elem.attributes {
                    if let Some(prefix) = get_attr_prefix(attr) {
                        if !prefix.is_empty() {
                            utilized_prefixes.insert(prefix.into_owned());
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

            let has_ns_filter = self.node_set.is_some_and(|ns| ns.has_ns_visible());

            // Determine which namespace declarations to output
            let mut ns_decls: Vec<NsDecl> = Vec::new();
            for prefix in &utilized_prefixes {
                // Skip the xml namespace
                if prefix == "xml" {
                    continue;
                }

                if let Some(uri) =
                    visible_namespace_uri(inscope_ns, self.node_set, id, prefix, has_ns_filter)
                {
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
                    if previously_rendered.is_some_and(|uri| !uri.is_empty()) {
                        ns_decls.push(NsDecl {
                            prefix: String::new(),
                            uri: String::new(),
                        });
                    }
                }
            }
            ns_decls.sort();

            // Collect attributes (borrowed from the arena; no per-attr Strings)
            let mut attrs: Vec<Attr> = Vec::new();
            {
                let elem = element_of(self.doc, id)?;
                for attr in &elem.attributes {
                    attrs.push(Attr {
                        ns_uri: attr.name.namespace_uri.clone().unwrap_or(Cow::Borrowed("")),
                        prefix: get_attr_prefix(attr),
                        local_name: attr.name.local_name.clone(),
                        value: attr.value.clone(),
                    });
                }
            }
            attrs.sort();

            // Output start tag (name streamed from the arena, no String)
            output.write_byte(b'<');
            {
                let elem = element_of(self.doc, id)?;
                if let Some(prefix) = &elem.name.prefix {
                    output.write(prefix.as_bytes());
                    output.write_byte(b':');
                }
                output.write(elem.name.local_name.as_bytes());
            }
            for ns_decl in &ns_decls {
                ns_decl.write_to(output);
            }
            for attr in &attrs {
                attr.write_to(output);
            }
            output.write_byte(b'>');

            // Update the shared rendered namespace context for children. An
            // undo log restores the parent bindings after this subtree,
            // avoiding a complete map clone for every visible element.
            let mut rendered_changes = Vec::new();
            for ns_decl in &ns_decls {
                let previous = rendered_ns.insert(ns_decl.prefix.clone(), ns_decl.uri.clone());
                rendered_changes.push((ns_decl.prefix.clone(), previous));
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
                    if visible_namespace_uri(inscope_ns, self.node_set, id, prefix, true).is_none()
                    {
                        let previous = rendered_ns.remove(prefix.as_str());
                        rendered_changes.push((prefix.clone(), previous));
                    }
                }
            }

            // Restore rendered bindings even if a descendant reports an
            // error, keeping the traversal state internally consistent.
            let child_result: Result<(), Error> = (|| {
                for child in self.doc.children_iter(id) {
                    self.process_node(child, output, rendered_ns, inscope_ns)?;
                }
                Ok(())
            })();
            restore_namespaces(rendered_ns, rendered_changes);
            child_result?;

            // Close tag (name written again from the arena; no String kept)
            output.write(b"</");
            {
                let elem = element_of(self.doc, id)?;
                if let Some(prefix) = &elem.name.prefix {
                    output.write(prefix.as_bytes());
                    output.write_byte(b':');
                }
                output.write(elem.name.local_name.as_bytes());
            }
            output.write_byte(b'>');
        } else {
            // Element not visible -- in exclusive C14N, namespace
            // declarations are only rendered on visible element start
            // tags.  However, for prefixes in InclusiveNamespaces
            // PrefixList, we follow inclusive C14N rules which include
            // outputting namespace nodes on invisible elements.
            let has_ns_filter = self.node_set.is_some_and(|ns| ns.has_ns_visible());
            if has_ns_filter && !self.inclusive_prefixes.is_empty() {
                let eid = id.index();
                // has_ns_filter guarantees this is Some; resolve it without a
                // panic-inducing unwrap so a corrupted arena errors instead.
                let Some(ns) = self.node_set else {
                    return Err(Error::Canonicalization(
                        "node set disappeared during canonicalization".into(),
                    ));
                };
                let visible_ns: BTreeMap<String, String> = inscope_ns
                    .iter()
                    .filter(|(prefix, _)| ns.is_ns_visible(eid, prefix))
                    .filter(|(prefix, _)| {
                        // Only output for InclusiveNamespaces PrefixList
                        if prefix.is_empty() {
                            self.inclusive_prefixes.iter().any(|p| p == "#default")
                        } else {
                            self.inclusive_prefixes.contains(prefix.as_str())
                        }
                    })
                    .map(|(prefix, uri)| (prefix.clone(), uri.clone()))
                    .collect();
                let mut ns_decls: Vec<NsDecl> = Vec::new();
                for (prefix, uri) in &visible_ns {
                    if prefix == "xml" {
                        continue;
                    }
                    if rendered_ns.get(prefix) != Some(uri) {
                        ns_decls.push(NsDecl {
                            prefix: prefix.clone(),
                            uri: uri.clone(),
                        });
                    }
                }
                ns_decls.sort();
                for ns_decl in &ns_decls {
                    ns_decl.write_to(output);
                }
            }

            // Children inherit same rendered_ns (invisible element
            // doesn't affect the visible ancestor tracking).
            for child in self.doc.children_iter(id) {
                self.process_node(child, output, rendered_ns, inscope_ns)?;
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
fn get_element_prefix(doc: &Document<'_>, id: NodeId) -> Result<String, Error> {
    let elem = element_of(doc, id)?;
    Ok(elem.name.prefix.as_deref().unwrap_or("").to_owned())
}

/// Resolve an element node from the arena, mapping a missing entry to a
/// canonicalization error instead of panicking mid-serialization.
///
/// Element node IDs always resolve while a document is alive; this guard
/// exists so an inconsistent arena can never abort the process inside a
/// security-critical serialization path.
fn element_of<'a, 'doc>(
    doc: &'a Document<'doc>,
    id: NodeId,
) -> Result<&'a uppsala::Element<'doc>, Error> {
    doc.element(id)
        .ok_or_else(|| Error::Canonicalization(format!("node {id:?} is not an element")))
}

/// Get the prefix for an attribute: `Some("xml")` for XML-namespace
/// attributes, otherwise the attribute's own prefix (empty string when the
/// attribute is namespaced but unprefixed, `None` when unqualified).
fn get_attr_prefix<'a>(attr: &uppsala::Attribute<'a>) -> Option<Cow<'a, str>> {
    if attr.name.namespace_uri.is_some() {
        if attr.name.namespace_uri.as_deref() == Some("http://www.w3.org/XML/1998/namespace") {
            return Some(Cow::Borrowed("xml"));
        }
        return attr.name.prefix.clone();
    }
    None
}

/// Record namespace-map mutations so a completed subtree can restore its
/// parent's bindings without cloning the entire map.
type NamespaceChanges = Vec<(String, Option<String>)>;

/// Apply one element's namespace declarations to the current in-scope map.
///
/// Empty namespace URIs undeclare their prefix. The returned undo log must be
/// passed to [`restore_namespaces`] after processing the element's subtree.
fn apply_element_namespaces(
    doc: &Document<'_>,
    id: NodeId,
    inscope_ns: &mut BTreeMap<String, String>,
) -> NamespaceChanges {
    let mut changes = Vec::new();
    if let Some(elem) = doc.element(id) {
        for (prefix, uri) in &elem.namespace_declarations {
            let prefix = prefix.to_string();
            let previous = if uri.is_empty() {
                inscope_ns.remove(&prefix)
            } else {
                inscope_ns.insert(prefix.clone(), uri.to_string())
            };
            changes.push((prefix, previous));
        }
    }
    changes
}

/// Restore namespace bindings from an undo log in reverse mutation order.
///
/// Reverse application is required when one traversal step changes the same
/// prefix more than once, as can happen when rendered namespace filtering
/// removes a declaration that was just emitted.
fn restore_namespaces(namespaces: &mut BTreeMap<String, String>, changes: NamespaceChanges) {
    for (prefix, previous) in changes.into_iter().rev() {
        if let Some(uri) = previous {
            namespaces.insert(prefix, uri);
        } else {
            namespaces.remove(&prefix);
        }
    }
}

/// Return an in-scope URI when its namespace node is visible for this element.
///
/// The visibility lookup stays on the borrowed incremental map, avoiding the
/// filtered map allocation previously performed for every visible element.
fn visible_namespace_uri<'a>(
    inscope_ns: &'a BTreeMap<String, String>,
    node_set: Option<&NodeSet>,
    id: NodeId,
    prefix: &str,
    has_ns_filter: bool,
) -> Option<&'a String> {
    if has_ns_filter && !node_set.is_some_and(|set| set.is_ns_visible(id.index(), prefix)) {
        return None;
    }
    inscope_ns.get(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- W3C C14N Spec Examples tested with Exclusive C14N ---
    // Ported from Go signedxml library canonicalization_test.go.
    // The Go library only implements exclusive C14N, so all its tests use
    // exclusive mode. Exclusive C14N differs from inclusive in namespace
    // handling, but for documents without namespaces, the output should be
    // identical.

    #[test]
    fn test_exc_c14n_example_3_1_without_comments() {
        // W3C Example 3.1: PIs, Comments, and Outside of Document Element
        let input = "<?xml version=\"1.0\"?>\n\n\
            <?xml-stylesheet   href=\"doc.xsl\" type=\"text/xsl\"   ?>\n\n\
            <doc>Hello, world!<!-- Comment 1 --></doc>\n\n\
            <?pi-without-data     ?>\n\n\
            <!-- Comment 2 -->\n\n\
            <!-- Comment 3 -->";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        let expected = "<?xml-stylesheet href=\"doc.xsl\" type=\"text/xsl\"   ?>\n\
            <doc>Hello, world!</doc>\n\
            <?pi-without-data?>";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_exc_c14n_example_3_1_with_comments() {
        let input = "<?xml version=\"1.0\"?>\n\n\
            <?xml-stylesheet   href=\"doc.xsl\" type=\"text/xsl\"   ?>\n\n\
            <doc>Hello, world!<!-- Comment 1 --></doc>\n\n\
            <?pi-without-data     ?>\n\n\
            <!-- Comment 2 -->\n\n\
            <!-- Comment 3 -->";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, true, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        let expected = "<?xml-stylesheet href=\"doc.xsl\" type=\"text/xsl\"   ?>\n\
            <doc>Hello, world!<!-- Comment 1 --></doc>\n\
            <?pi-without-data?>\n\
            <!-- Comment 2 -->\n\
            <!-- Comment 3 -->";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_exc_c14n_example_3_2_whitespace() {
        // W3C Example 3.2: Whitespace in Document Content
        let input = "<doc>\n\
            \x20\x20\x20<clean>   </clean>\n\
            \x20\x20\x20<dirty>   A   B   </dirty>\n\
            \x20\x20\x20<mixed>\n\
            \x20\x20\x20\x20\x20\x20A\n\
            \x20\x20\x20\x20\x20\x20<clean>   </clean>\n\
            \x20\x20\x20\x20\x20\x20B\n\
            \x20\x20\x20\x20\x20\x20<dirty>   A   B   </dirty>\n\
            \x20\x20\x20\x20\x20\x20C\n\
            \x20\x20\x20</mixed>\n\
            </doc>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn test_exc_c14n_example_3_4_character_modifications() {
        // W3C Example 3.4: Character references, CDATA, attribute escaping.
        // Modified output (no DTD processing), same as Go library.
        let input = "<doc>\n\
            \x20\x20\x20<text>First line&#x0d;&#10;Second line</text>\n\
            \x20\x20\x20<value>&#x32;</value>\n\
            \x20\x20\x20<compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n\
            \x20\x20\x20<compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n\
            \x20\x20\x20<norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n\
            \x20\x20\x20<normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>\n\
            </doc>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        let expected = "<doc>\n\
            \x20\x20\x20<text>First line&#xD;\n\
            Second line</text>\n\
            \x20\x20\x20<value>2</value>\n\
            \x20\x20\x20<compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n\
            \x20\x20\x20<compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n\
            \x20\x20\x20<norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n\
            \x20\x20\x20<normNames attr=\"   A    &#xD;&#xA;&#x9;   B   \"></normNames>\n\
            </doc>";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_exc_c14n_example_3_6_utf8() {
        // W3C Example 3.6: UTF-8 Encoding (copyright sign U+00A9)
        let input = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<doc>\u{00A9}</doc>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "<doc>\u{00A9}</doc>");
    }

    #[test]
    fn test_exc_c14n_comment_stripping() {
        // GitHub Issue #50 from Go signedxml: multiple adjacent comments stripped.
        let input = "<a><!-- comment0 --><!-- comment1 --><!-- comment2 --></a>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "<a></a>");
    }

    #[test]
    fn test_exc_c14n_namespace_not_visibly_utilized() {
        // Exclusive C14N only renders namespace declarations that are visibly
        // utilized by the element or its attributes. Unused prefixes from
        // ancestors should NOT appear.
        let input = r#"<root xmlns:a="http://a" xmlns:b="http://b"><a:child/></root>"#;
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        // In exclusive C14N, xmlns:b should NOT appear on <a:child> since
        // only xmlns:a is visibly utilized. But at the root level, both are
        // visibly utilized (root uses neither, but inclusive prefixes matter).
        // Actually for the root element with no prefix, neither a: nor b: is
        // visibly utilized. But we're canonicalizing the whole document, so
        // the root element gets no namespace decls in exclusive C14N unless
        // they're used. Check that a:child gets xmlns:a.
        assert!(output.contains("xmlns:a=\"http://a\""));
    }

    #[test]
    fn test_exc_c14n_with_inclusive_prefixes() {
        // Exclusive C14N with InclusiveNamespaces PrefixList.
        // When a prefix is in the PrefixList, it should be rendered even if
        // not visibly utilized by the element.
        let input =
            r#"<root xmlns:xs="http://www.w3.org/2001/XMLSchema"><child attr="val"/></root>"#;
        let doc = uppsala::parse(input).unwrap();
        let prefixes = vec!["xs".to_string()];
        let result = canonicalize(&doc, false, None, &prefixes).unwrap();
        let output = String::from_utf8(result).unwrap();
        // With "xs" in InclusiveNamespaces PrefixList, the xs namespace should
        // be rendered on elements even though it's not visibly utilized.
        assert!(output.contains("xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""));
    }

    #[test]
    fn test_exc_c14n_restores_namespace_bindings_between_siblings() {
        // A nested prefix rebind must not leak into a later sibling. This also
        // exercises incremental in-scope and rendered namespace undo logs.
        let input = r#"<r xmlns="urn:root" xmlns:p="urn:one"><p:a><x xmlns:p="urn:two"><p:b/></x></p:a><p:c/></r>"#;
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        let expected = r#"<r xmlns="urn:root"><p:a xmlns:p="urn:one"><x><p:b xmlns:p="urn:two"></p:b></x></p:a><p:c xmlns:p="urn:one"></p:c></r>"#;
        assert_eq!(output, expected);
    }

    #[test]
    fn test_exc_c14n_restores_default_namespace_after_undeclaration() {
        // The empty namespace applies only to the nested subtree; the final
        // sibling must inherit and render the root's default namespace.
        let input = r#"<r xmlns="urn:root"><plain xmlns=""><child/></plain><again/></r>"#;
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None, &[] as &[&str]).unwrap();
        let output = String::from_utf8(result).unwrap();
        let expected =
            r#"<r xmlns="urn:root"><plain xmlns=""><child></child></plain><again></again></r>"#;
        assert_eq!(output, expected);
    }
}
