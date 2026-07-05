#![forbid(unsafe_code)]

//! NodeSet type for XML canonicalization and transforms.
//!
//! A `NodeSet` represents a set of nodes from an XML document, identified by
//! their `NodeId`.  It supports the set operations needed by
//! XPath Filter 2.0 and the enveloped-signature transform.
//!
//! The implementation uses two storage shapes:
//! - [`NodeSetType::Normal`] stores the visible nodes directly.
//! - [`NodeSetType::Invert`] stores the excluded nodes; every other node is
//!   treated as visible.
//!
//! The inverted form is important for XML-DSig and C14N performance. Common
//! references such as "the whole document except comments" or "the document
//! element except the `<Signature>` subtree" can otherwise require a hash table
//! entry for every node in a large document.

use std::collections::{HashMap, HashSet};
use uppsala::{Document, NodeId, NodeKind};

/// The storage and interpretation mode for a [`NodeSet`].
///
/// The names mirror xmlsec's `xmlSecNodeSetType`, but Bergshamra currently
/// materializes tree-specific variants as normal sets except for the compact
/// whole-document/document-element cases documented on [`NodeSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeSetType {
    /// `nodes` contains exactly the visible nodes.
    Normal,
    /// `nodes` contains excluded nodes; all other nodes are visible.
    Invert,
    /// Tree-shaped selection with comments.
    Tree,
    /// Tree-shaped selection excluding comment nodes.
    TreeWithoutComments,
    /// Inverted tree-shaped selection.
    TreeInvert,
}

/// A set operation used by XPath Filter 2.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeSetOp {
    /// Keep nodes visible in both inputs.
    Intersection,
    /// Keep nodes visible in the left input and not visible in the right input.
    Subtraction,
    /// Keep nodes visible in either input.
    Union,
}

/// A set of XML document nodes identified by `NodeId`.
///
/// `NodeSet` is document-local: node IDs are arena indexes from an `uppsala`
/// [`Document`], so a set must only be used with the document it was built
/// from.
///
/// For [`NodeSetType::Invert`], `nodes` stores exclusions rather than visible
/// members. Use [`NodeSet::contains_id`] to test membership instead of reading
/// [`NodeSet::node_ids`] unless you intentionally need the raw storage.
#[derive(Debug, Clone)]
pub struct NodeSet {
    /// The node IDs in this set.
    nodes: HashSet<usize>,
    /// The type of this node set.
    set_type: NodeSetType,
    /// Optional namespace node visibility map.
    ///
    /// In the XPath data model, each element has namespace nodes for each
    /// in-scope namespace binding. XPath expressions can filter individual
    /// namespace nodes independently of their parent element.
    ///
    /// When `Some`, maps `(element_node_id, prefix)` → `true` if visible.
    /// The prefix is "" for the default namespace.
    /// When `None`, all namespace nodes are considered visible (default).
    ns_visible: Option<HashMap<(usize, String), bool>>,

    /// Whether attribute nodes are excluded from this node set.
    ///
    /// When `true`, C14N should not render element attributes even for
    /// elements that are in the node set. This happens when an XPath filter
    /// like `@*` includes elements-with-attributes but not the attribute
    /// nodes themselves (since `@*` on an attribute node returns empty).
    exclude_attrs: bool,
}

impl NodeSet {
    /// Create an empty normal node set.
    ///
    /// The resulting set contains no visible nodes.
    pub fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            set_type: NodeSetType::Normal,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set from raw node IDs and an explicit storage mode.
    ///
    /// For [`NodeSetType::Normal`], `ids` are visible nodes. For
    /// [`NodeSetType::Invert`], `ids` are excluded nodes. Tree-shaped variants
    /// are accepted for compatibility, but callers should prefer the
    /// constructor methods such as [`NodeSet::tree_without_comments`] because
    /// those choose the compact representation when possible.
    pub fn from_ids(ids: HashSet<usize>, set_type: NodeSetType) -> Self {
        Self {
            nodes: ids,
            set_type,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set containing all nodes in the document.
    ///
    /// This uses the compact inverted representation with no exclusions, so it
    /// does not allocate one hash entry per document node.
    pub fn all(_doc: &Document<'_>) -> Self {
        Self {
            nodes: HashSet::new(),
            set_type: NodeSetType::Invert,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set containing all nodes except comments.
    ///
    /// Per the XML-DSig reference processing rules, an empty URI selects the
    /// document without comments unless a full XPointer is used. This
    /// constructor stores only comment nodes as exclusions.
    pub fn all_without_comments(doc: &Document<'_>) -> Self {
        Self {
            nodes: collect_comment_ids(doc),
            set_type: NodeSetType::Invert,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set for a subtree rooted at `root_id`, excluding comments.
    ///
    /// When `root_id` is the document node or document element, this uses a
    /// compact inverted set. Other subtrees are materialized as visible IDs
    /// because `uppsala::NodeId` is an arena index and does not expose a stable
    /// public subtree-range contract.
    pub fn tree_without_comments(root_id: NodeId, doc: &Document<'_>) -> Self {
        if root_id == doc.root() {
            return Self::all_without_comments(doc);
        }
        if doc.document_element() == Some(root_id) {
            // Selecting the document element is equivalent to "all document
            // nodes except top-level siblings and comments". Inverting that
            // small exclusion set avoids materializing the full document tree.
            let mut nodes = collect_comment_ids(doc);
            collect_document_child_exclusions(root_id, doc, &mut nodes);
            return Self {
                nodes,
                set_type: NodeSetType::Invert,
                ns_visible: None,
                exclude_attrs: false,
            };
        }

        let mut nodes = HashSet::new();
        collect_subtree(root_id, doc, &mut nodes, false);
        Self {
            nodes,
            set_type: NodeSetType::Normal,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set for a subtree rooted at `root_id`, including comments.
    ///
    /// Like [`NodeSet::tree_without_comments`], document and document-element
    /// selections use compact inverted storage while arbitrary subtrees are
    /// materialized.
    pub fn tree_with_comments(root_id: NodeId, doc: &Document<'_>) -> Self {
        if root_id == doc.root() {
            return Self::all(doc);
        }
        if doc.document_element() == Some(root_id) {
            // The document element with comments includes almost everything in
            // the parsed document; only top-level comments/PIs outside that
            // element need to be excluded.
            let mut nodes = HashSet::new();
            collect_document_child_exclusions(root_id, doc, &mut nodes);
            return Self {
                nodes,
                set_type: NodeSetType::Invert,
                ns_visible: None,
                exclude_attrs: false,
            };
        }

        let mut nodes = HashSet::new();
        collect_subtree(root_id, doc, &mut nodes, true);
        Self {
            nodes,
            set_type: NodeSetType::Normal,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Check whether `id` is visible in this set.
    ///
    /// This is the membership API that respects both normal and inverted
    /// storage. Prefer it over inspecting [`NodeSet::node_ids`] directly.
    pub fn contains_id(&self, id: NodeId) -> bool {
        let idx = id.index();
        match self.set_type {
            NodeSetType::Normal => self.nodes.contains(&idx),
            NodeSetType::Invert => !self.nodes.contains(&idx),
            NodeSetType::Tree | NodeSetType::TreeWithoutComments | NodeSetType::TreeInvert => {
                self.nodes.contains(&idx)
            }
        }
    }

    /// Return the storage/interpretation mode for this node set.
    pub fn set_type(&self) -> NodeSetType {
        self.set_type
    }

    /// Return the raw stored node IDs.
    ///
    /// For [`NodeSetType::Normal`], these are visible nodes. For
    /// [`NodeSetType::Invert`], these are excluded nodes. This method exposes
    /// storage, not logical membership.
    pub fn node_ids(&self) -> &HashSet<usize> {
        &self.nodes
    }

    /// Make `id` visible in this set.
    ///
    /// For normal sets this inserts the node. For inverted sets this removes it
    /// from the exclusion list.
    pub fn insert_id(&mut self, id: NodeId) {
        match self.set_type {
            NodeSetType::Invert => {
                self.nodes.remove(&id.index());
            }
            _ => {
                self.nodes.insert(id.index());
            }
        }
    }

    /// Make `id` invisible in this set.
    ///
    /// For normal sets this removes the node. For inverted sets this adds the
    /// node to the exclusion list.
    pub fn remove_id(&mut self, id: NodeId) {
        match self.set_type {
            NodeSetType::Invert => {
                self.nodes.insert(id.index());
            }
            _ => {
                self.nodes.remove(&id.index());
            }
        }
    }

    /// Compute the logical intersection of two node sets.
    ///
    /// The result is normalized to either normal or inverted storage depending
    /// on which shape can represent the set operation directly.
    pub fn intersection(&self, other: &NodeSet) -> NodeSet {
        let ns_visible = merge_ns_visible_intersection(&self.ns_visible, &other.ns_visible);
        // Algebra over complements:
        // normal(A) & normal(B) = normal(A & B)
        // invert(A) & invert(B) = invert(A | B)
        // invert(A) & normal(B) = normal(B - A)
        // normal(A) & invert(B) = normal(A - B)
        let (nodes, set_type) = match (self.is_invert(), other.is_invert()) {
            (false, false) => (
                self.nodes.intersection(&other.nodes).copied().collect(),
                NodeSetType::Normal,
            ),
            (true, true) => (
                self.nodes.union(&other.nodes).copied().collect(),
                NodeSetType::Invert,
            ),
            (true, false) => (
                other.nodes.difference(&self.nodes).copied().collect(),
                NodeSetType::Normal,
            ),
            (false, true) => (
                self.nodes.difference(&other.nodes).copied().collect(),
                NodeSetType::Normal,
            ),
        };
        NodeSet {
            nodes,
            set_type,
            ns_visible,
            exclude_attrs: self.exclude_attrs || other.exclude_attrs,
        }
    }

    /// Compute the logical union of two node sets.
    ///
    /// Namespace visibility maps are merged using C14N/XPath node-set rules:
    /// if either side has every namespace visible, the union does too.
    pub fn union(&self, other: &NodeSet) -> NodeSet {
        let ns_visible = merge_ns_visible_union(&self.ns_visible, &other.ns_visible);
        // Algebra over complements:
        // normal(A) | normal(B) = normal(A | B)
        // invert(A) | invert(B) = invert(A & B)
        // invert(A) | normal(B) = invert(A - B)
        // normal(A) | invert(B) = invert(B - A)
        let (nodes, set_type) = match (self.is_invert(), other.is_invert()) {
            (false, false) => (
                self.nodes.union(&other.nodes).copied().collect(),
                NodeSetType::Normal,
            ),
            (true, true) => (
                self.nodes.intersection(&other.nodes).copied().collect(),
                NodeSetType::Invert,
            ),
            (true, false) => (
                self.nodes.difference(&other.nodes).copied().collect(),
                NodeSetType::Invert,
            ),
            (false, true) => (
                other.nodes.difference(&self.nodes).copied().collect(),
                NodeSetType::Invert,
            ),
        };
        NodeSet {
            nodes,
            set_type,
            ns_visible,
            exclude_attrs: self.exclude_attrs && other.exclude_attrs,
        }
    }

    /// Compute logical subtraction: `self - other`.
    ///
    /// The result contains nodes visible in `self` and not visible in `other`.
    pub fn subtract(&self, other: &NodeSet) -> NodeSet {
        let ns_visible = merge_ns_visible_subtract(&self.ns_visible, &other.ns_visible);
        // Algebra over complements:
        // normal(A) - normal(B) = normal(A - B)
        // normal(A) - invert(B) = normal(A & B)
        // invert(A) - normal(B) = invert(A | B)
        // invert(A) - invert(B) = normal(B - A)
        let (nodes, set_type) = match (self.is_invert(), other.is_invert()) {
            (false, false) => (
                self.nodes.difference(&other.nodes).copied().collect(),
                NodeSetType::Normal,
            ),
            (false, true) => (
                self.nodes.intersection(&other.nodes).copied().collect(),
                NodeSetType::Normal,
            ),
            (true, false) => (
                self.nodes.union(&other.nodes).copied().collect(),
                NodeSetType::Invert,
            ),
            (true, true) => (
                other.nodes.difference(&self.nodes).copied().collect(),
                NodeSetType::Normal,
            ),
        };
        NodeSet {
            nodes,
            set_type,
            ns_visible,
            exclude_attrs: self.exclude_attrs,
        }
    }

    /// Return whether this set has no visible nodes.
    ///
    /// Inverted sets represent "everything except these exclusions", so they
    /// are never known-empty without document-wide cardinality information.
    pub fn is_empty(&self) -> bool {
        !self.is_invert() && self.nodes.is_empty()
    }

    /// Return the number of raw stored IDs.
    ///
    /// For normal sets this is the number of visible nodes. For inverted sets
    /// this is the number of excluded nodes, not the number of visible nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Set per-element namespace-node visibility.
    ///
    /// XPath can select namespace nodes independently from their owning
    /// elements. C14N consults this map to decide which `xmlns` declarations are
    /// visible for each element.
    pub fn set_ns_visible(&mut self, map: HashMap<(usize, String), bool>) {
        self.ns_visible = Some(map);
    }

    /// Check whether a namespace node is visible for an element and prefix.
    ///
    /// Returns `true` if:
    /// - No ns_visible map exists (all namespace nodes visible by default)
    /// - The map contains `(element_id, prefix) → true`
    pub fn is_ns_visible(&self, element_id: usize, prefix: &str) -> bool {
        match &self.ns_visible {
            None => true,
            Some(map) => map
                .get(&(element_id, prefix.to_string()))
                .copied()
                .unwrap_or(false),
        }
    }

    /// Return whether this set carries per-namespace-node visibility state.
    pub fn has_ns_visible(&self) -> bool {
        self.ns_visible.is_some()
    }

    /// Set whether element attributes should be excluded during C14N.
    ///
    /// XPath filters can include elements but exclude their attribute nodes.
    /// This flag lets C14N render the element tags without rendering attributes.
    pub fn set_exclude_attrs(&mut self, val: bool) {
        self.exclude_attrs = val;
    }

    /// Return whether element attributes are excluded during C14N.
    pub fn excludes_attrs(&self) -> bool {
        self.exclude_attrs
    }

    /// Return whether raw stored IDs are exclusions.
    fn is_invert(&self) -> bool {
        self.set_type == NodeSetType::Invert
    }
}

impl Default for NodeSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Merge namespace visibility maps for intersection: both must agree.
fn merge_ns_visible_intersection(
    a: &Option<HashMap<(usize, String), bool>>,
    b: &Option<HashMap<(usize, String), bool>>,
) -> Option<HashMap<(usize, String), bool>> {
    match (a, b) {
        (None, None) => None,
        (Some(m), None) => Some(m.clone()),
        (None, Some(m)) => Some(m.clone()),
        (Some(ma), Some(mb)) => {
            // Intersection: key must be in both and true in both
            let mut result = HashMap::new();
            for (k, v) in ma {
                if *v && mb.get(k).copied().unwrap_or(false) {
                    result.insert(k.clone(), true);
                }
            }
            Some(result)
        }
    }
}

/// Merge namespace visibility maps for union: either one suffices.
fn merge_ns_visible_union(
    a: &Option<HashMap<(usize, String), bool>>,
    b: &Option<HashMap<(usize, String), bool>>,
) -> Option<HashMap<(usize, String), bool>> {
    match (a, b) {
        (None, _) | (_, None) => None, // One has all visible → union is all visible
        (Some(ma), Some(mb)) => {
            let mut result = ma.clone();
            for (k, v) in mb {
                if *v {
                    result.insert(k.clone(), true);
                }
            }
            Some(result)
        }
    }
}

/// Merge namespace visibility maps for subtraction: remove those in other.
fn merge_ns_visible_subtract(
    a: &Option<HashMap<(usize, String), bool>>,
    b: &Option<HashMap<(usize, String), bool>>,
) -> Option<HashMap<(usize, String), bool>> {
    match (a, b) {
        (None, None) => None,
        (Some(m), None) => Some(m.clone()),
        (None, Some(mb)) => {
            // All visible minus those in mb
            let mut result = HashMap::new();
            for (k, v) in mb {
                if *v {
                    result.insert(k.clone(), false);
                }
            }
            Some(result)
        }
        (Some(ma), Some(mb)) => {
            let mut result = ma.clone();
            for (k, v) in mb {
                if *v {
                    result.insert(k.clone(), false);
                }
            }
            Some(result)
        }
    }
}

/// Collect all nodes in a subtree into a HashSet.
fn collect_subtree(
    id: NodeId,
    doc: &Document<'_>,
    set: &mut HashSet<usize>,
    include_comments: bool,
) {
    if !include_comments && matches!(doc.node_kind(id), Some(NodeKind::Comment(_))) {
        return;
    }
    set.insert(id.index());

    for child in doc.children(id) {
        collect_subtree(child, doc, set, include_comments);
    }
}

/// Collect every comment node in the document.
///
/// Used as the exclusion list for compact "all nodes except comments" sets.
fn collect_comment_ids(doc: &Document<'_>) -> HashSet<usize> {
    let mut nodes = HashSet::new();
    for id in doc.descendants(doc.root()) {
        if matches!(doc.node_kind(id), Some(NodeKind::Comment(_))) {
            nodes.insert(id.index());
        }
    }
    nodes
}

/// Collect top-level document children other than `selected_root`.
///
/// A document-element subset should not include comments, processing
/// instructions, or other nodes that are siblings of the document element.
/// Those siblings are usually few, so they make a compact inverted set.
fn collect_document_child_exclusions(
    selected_root: NodeId,
    doc: &Document<'_>,
    set: &mut HashSet<usize>,
) {
    for child in doc.children_iter(doc.root()) {
        if child != selected_root {
            collect_subtree(child, doc, set, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(values: &[usize]) -> HashSet<usize> {
        values.iter().copied().collect()
    }

    #[test]
    fn all_without_comments_uses_inverted_comment_exclusions() {
        let doc = uppsala::parse("<root>text<!-- hidden --><child/></root>").unwrap();
        let ns = NodeSet::all_without_comments(&doc);

        assert_eq!(ns.set_type(), NodeSetType::Invert);
        for id in doc.descendants(doc.root()) {
            let is_comment = matches!(doc.node_kind(id), Some(NodeKind::Comment(_)));
            assert_eq!(ns.contains_id(id), !is_comment);
        }
    }

    #[test]
    fn document_element_subtree_excludes_top_level_siblings() {
        let xml = "<?pre value?><root><!-- hidden --><child/></root><?post value?>";
        let doc = uppsala::parse(xml).unwrap();
        let root = doc.document_element().unwrap();
        let ns = NodeSet::tree_without_comments(root, &doc);

        assert_eq!(ns.set_type(), NodeSetType::Invert);
        assert!(ns.contains_id(root));
        for id in doc.descendants(doc.root()) {
            let top_level_sibling = doc.parent(id) == Some(doc.root()) && id != root;
            let comment = matches!(doc.node_kind(id), Some(NodeKind::Comment(_)));
            assert_eq!(ns.contains_id(id), !(top_level_sibling || comment));
        }
    }

    #[test]
    fn inverted_intersection_with_normal_keeps_normal_visible_nodes() {
        let inverted = NodeSet::from_ids(ids(&[1]), NodeSetType::Invert);
        let normal = NodeSet::from_ids(ids(&[1, 2]), NodeSetType::Normal);

        let result = inverted.intersection(&normal);

        assert_eq!(result.set_type(), NodeSetType::Normal);
        assert!(!result.contains_id(NodeId::new(1)));
        assert!(result.contains_id(NodeId::new(2)));
        assert!(!result.contains_id(NodeId::new(3)));
    }

    #[test]
    fn inverted_subtract_inverted_returns_excluded_difference() {
        let left = NodeSet::from_ids(ids(&[1]), NodeSetType::Invert);
        let right = NodeSet::from_ids(ids(&[1, 2]), NodeSetType::Invert);

        let result = left.subtract(&right);

        assert_eq!(result.set_type(), NodeSetType::Normal);
        assert!(!result.contains_id(NodeId::new(1)));
        assert!(result.contains_id(NodeId::new(2)));
        assert!(!result.contains_id(NodeId::new(3)));
    }
}
