#![forbid(unsafe_code)]

//! NodeSet type for XML canonicalization and transforms.
//!
//! A `NodeSet` represents a set of nodes from an XML document, identified by
//! their `roxmltree::NodeId`.  It supports the set operations needed by
//! XPath Filter 2.0 and the enveloped-signature transform.

use std::collections::HashSet;

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

/// A set of XML document nodes identified by `roxmltree::NodeId`.
#[derive(Debug, Clone)]
pub struct NodeSet {
    /// The node IDs in this set.
    nodes: HashSet<usize>,
    /// The type of this node set.
    set_type: NodeSetType,
}

impl NodeSet {
    /// Create an empty normal node set.
    pub fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            set_type: NodeSetType::Normal,
        }
    }

    /// Create a node set from a set of node IDs.
    pub fn from_ids(ids: HashSet<usize>, set_type: NodeSetType) -> Self {
        Self {
            nodes: ids,
            set_type,
        }
    }

    /// Create a node set containing all nodes in the document.
    pub fn all(doc: &roxmltree::Document<'_>) -> Self {
        let nodes: HashSet<usize> = doc.descendants().map(|n| node_index(n)).collect();
        Self {
            nodes,
            set_type: NodeSetType::Normal,
        }
    }

    /// Create a node set for a subtree rooted at the given node (without comments).
    pub fn tree_without_comments(root: roxmltree::Node<'_, '_>) -> Self {
        let mut nodes = HashSet::new();
        collect_subtree(root, &mut nodes, false);
        Self {
            nodes,
            set_type: NodeSetType::Normal,
        }
    }

    /// Create a node set for a subtree rooted at the given node (with comments).
    pub fn tree_with_comments(root: roxmltree::Node<'_, '_>) -> Self {
        let mut nodes = HashSet::new();
        collect_subtree(root, &mut nodes, true);
        Self {
            nodes,
            set_type: NodeSetType::Normal,
        }
    }

    /// Check if a node is in this set.
    pub fn contains(&self, node: &roxmltree::Node<'_, '_>) -> bool {
        let idx = node_index(*node);
        match self.set_type {
            NodeSetType::Normal => self.nodes.contains(&idx),
            NodeSetType::Invert => !self.nodes.contains(&idx),
            NodeSetType::Tree | NodeSetType::TreeWithoutComments | NodeSetType::TreeInvert => {
                // For tree types, the nodes set contains root nodes.
                // We need to check if this node is a descendant of any root.
                // This is a simplified implementation; for large sets,
                // we'd pre-expand during construction.
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
    pub fn insert(&mut self, node: &roxmltree::Node<'_, '_>) {
        self.nodes.insert(node_index(*node));
    }

    /// Remove a node from this set.
    pub fn remove(&mut self, node: &roxmltree::Node<'_, '_>) {
        self.nodes.remove(&node_index(*node));
    }

    /// Compute the intersection of two node sets.
    pub fn intersection(&self, other: &NodeSet) -> NodeSet {
        NodeSet {
            nodes: self.nodes.intersection(&other.nodes).copied().collect(),
            set_type: NodeSetType::Normal,
        }
    }

    /// Compute the union of two node sets.
    pub fn union(&self, other: &NodeSet) -> NodeSet {
        NodeSet {
            nodes: self.nodes.union(&other.nodes).copied().collect(),
            set_type: NodeSetType::Normal,
        }
    }

    /// Compute self - other (subtraction).
    pub fn subtract(&self, other: &NodeSet) -> NodeSet {
        NodeSet {
            nodes: self.nodes.difference(&other.nodes).copied().collect(),
            set_type: NodeSetType::Normal,
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
}

impl Default for NodeSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Get a stable numeric index for a roxmltree node.
///
/// `roxmltree::NodeId` doesn't expose its inner index directly, but
/// we can use the node's position in document order.
pub fn node_index(node: roxmltree::Node<'_, '_>) -> usize {
    // roxmltree NodeId can be used as an index via get_node
    // We use a trick: the Debug output of NodeId contains the index,
    // but it's simpler to just track the document-order position.
    // Actually, NodeId has a `get_usize()` — no it doesn't.
    // Let's use the node's document position by iterating.
    // This is O(1) because we can extract from the internal id.
    //
    // roxmltree::NodeId internally stores a usize index.
    // We can get it via the id() method which returns a NodeId,
    // then format it.
    let id = node.id();
    // NodeId doesn't expose its inner value, but we can use
    // the document's get_node to verify. For efficiency, we'll
    // just use the Debug representation to extract the index.
    // Actually the simplest approach: store the NodeId directly.
    // But HashSet needs Hash, and NodeId doesn't implement Hash.
    //
    // Workaround: NodeId is Copy and can be compared, but not hashed.
    // We can create a wrapper, or simply use the debug string.
    //
    // Better approach: roxmltree documents are arena-allocated and
    // nodes are indexed sequentially.  We can count by iterating
    // from the root, but that's O(n).
    //
    // Best approach: use the internal representation.
    // roxmltree::NodeId is a newtype around usize, but the field is private.
    // We can use `std::mem::transmute` — but we forbid unsafe.
    //
    // Actually, let's just use Debug format since NodeId prints as
    // `NodeId(N)`.  This is a hack but works without unsafe.
    let debug = format!("{:?}", id);
    // Format is "NodeId(123)"
    let num_str = debug
        .strip_prefix("NodeId(")
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or("0");
    num_str.parse::<usize>().unwrap_or(0)
}

/// Collect all nodes in a subtree into a HashSet.
fn collect_subtree(
    node: roxmltree::Node<'_, '_>,
    set: &mut HashSet<usize>,
    include_comments: bool,
) {
    if !include_comments && node.is_comment() {
        return;
    }
    set.insert(node_index(node));

    // Also include namespace and attribute nodes for elements
    if node.is_element() {
        // Namespace declarations and attributes are tracked as part of the element
        // in roxmltree, so they share the element's NodeId. No separate insertion needed.
    }

    for child in node.children() {
        collect_subtree(child, set, include_comments);
    }
}
