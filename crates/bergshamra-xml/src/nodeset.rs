#![forbid(unsafe_code)]

//! NodeSet type for XML canonicalization and transforms.
//!
//! A `NodeSet` represents a set of nodes from an XML document, identified by
//! their `NodeId`.  It supports the set operations needed by
//! XPath Filter 2.0 and the enveloped-signature transform.

use std::collections::{HashMap, HashSet};
use uppsala::{Document, NodeId, NodeKind};

/// The type of a node set, matching xmlsec's `xmlSecNodeSetType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeSetType {
    /// Normal: contains exactly the listed nodes.
    Normal,
    /// Invert: contains all nodes EXCEPT the listed ones.
    Invert,
    /// Tree: contains the listed nodes and all their descendants.
    Tree,
    /// TreeWithoutComments: like Tree but excluding comment nodes.
    TreeWithoutComments,
    /// TreeInvert: contains all nodes except those in the listed subtrees.
    TreeInvert,
}

/// An operation to combine two node sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeSetOp {
    Intersection,
    Subtraction,
    Union,
}

/// A set of XML document nodes identified by `NodeId`.
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
    pub fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            set_type: NodeSetType::Normal,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set from a set of node IDs.
    pub fn from_ids(ids: HashSet<usize>, set_type: NodeSetType) -> Self {
        Self {
            nodes: ids,
            set_type,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set containing all nodes in the document.
    pub fn all(doc: &Document<'_>) -> Self {
        let root = doc.root();
        let mut nodes: HashSet<usize> = HashSet::new();
        nodes.insert(root.index());
        for id in doc.descendants(root) {
            nodes.insert(id.index());
        }
        Self {
            nodes,
            set_type: NodeSetType::Normal,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set containing all nodes except comments.
    /// Per W3C DSig spec, `URI=""` selects the document without comments.
    pub fn all_without_comments(doc: &Document<'_>) -> Self {
        let root = doc.root();
        let mut nodes: HashSet<usize> = HashSet::new();
        nodes.insert(root.index());
        for id in doc.descendants(root) {
            if !matches!(doc.node_kind(id), Some(NodeKind::Comment(_))) {
                nodes.insert(id.index());
            }
        }
        Self {
            nodes,
            set_type: NodeSetType::Normal,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set for a subtree rooted at the given node (without comments).
    pub fn tree_without_comments(root_id: NodeId, doc: &Document<'_>) -> Self {
        let mut nodes = HashSet::new();
        collect_subtree(root_id, doc, &mut nodes, false);
        Self {
            nodes,
            set_type: NodeSetType::Normal,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Create a node set for a subtree rooted at the given node (with comments).
    pub fn tree_with_comments(root_id: NodeId, doc: &Document<'_>) -> Self {
        let mut nodes = HashSet::new();
        collect_subtree(root_id, doc, &mut nodes, true);
        Self {
            nodes,
            set_type: NodeSetType::Normal,
            ns_visible: None,
            exclude_attrs: false,
        }
    }

    /// Check if a node is in this set.
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

    /// Get the type of this node set.
    pub fn set_type(&self) -> NodeSetType {
        self.set_type
    }

    /// Get the raw node IDs.
    pub fn node_ids(&self) -> &HashSet<usize> {
        &self.nodes
    }

    /// Add a node to this set.
    pub fn insert_id(&mut self, id: NodeId) {
        self.nodes.insert(id.index());
    }

    /// Remove a node from this set.
    pub fn remove_id(&mut self, id: NodeId) {
        self.nodes.remove(&id.index());
    }

    /// Compute the intersection of two node sets.
    pub fn intersection(&self, other: &NodeSet) -> NodeSet {
        let ns_visible = merge_ns_visible_intersection(&self.ns_visible, &other.ns_visible);
        NodeSet {
            nodes: self.nodes.intersection(&other.nodes).copied().collect(),
            set_type: NodeSetType::Normal,
            ns_visible,
            exclude_attrs: self.exclude_attrs || other.exclude_attrs,
        }
    }

    /// Compute the union of two node sets.
    pub fn union(&self, other: &NodeSet) -> NodeSet {
        let ns_visible = merge_ns_visible_union(&self.ns_visible, &other.ns_visible);
        NodeSet {
            nodes: self.nodes.union(&other.nodes).copied().collect(),
            set_type: NodeSetType::Normal,
            ns_visible,
            exclude_attrs: self.exclude_attrs && other.exclude_attrs,
        }
    }

    /// Compute self - other (subtraction).
    pub fn subtract(&self, other: &NodeSet) -> NodeSet {
        let ns_visible = merge_ns_visible_subtract(&self.ns_visible, &other.ns_visible);
        NodeSet {
            nodes: self.nodes.difference(&other.nodes).copied().collect(),
            set_type: NodeSetType::Normal,
            ns_visible,
            exclude_attrs: self.exclude_attrs,
        }
    }

    /// Check if this set is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Number of nodes in the set.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Set the namespace visibility map.
    pub fn set_ns_visible(&mut self, map: HashMap<(usize, String), bool>) {
        self.ns_visible = Some(map);
    }

    /// Check if a namespace node is visible for the given element and prefix.
    ///
    /// Returns `true` if:
    /// - No ns_visible map exists (all namespace nodes visible by default)
    /// - The map contains `(element_id, prefix) → true`
    pub fn is_ns_visible(&self, element_id: usize, prefix: &str) -> bool {
        match &self.ns_visible {
            None => true,
            Some(map) => map.get(&(element_id, prefix.to_string())).copied().unwrap_or(false),
        }
    }

    /// Check if this node set has a namespace visibility map.
    pub fn has_ns_visible(&self) -> bool {
        self.ns_visible.is_some()
    }

    /// Set the exclude_attrs flag.
    pub fn set_exclude_attrs(&mut self, val: bool) {
        self.exclude_attrs = val;
    }

    /// Check if attribute nodes are excluded from this node set.
    pub fn excludes_attrs(&self) -> bool {
        self.exclude_attrs
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
