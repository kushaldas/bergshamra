//! Explicit, bounded assessment of authenticated same-document Manifests.

use super::{
    build_verify_id_map, find_child_element, find_child_elements, find_element,
    verify_reference_with_limit, verify_signature_node_with_limit, VerifiedReference, VerifyResult,
};
use crate::DsigContext;
use bergshamra_c14n::C14nMode;
use bergshamra_core::{ns, Error};
use bergshamra_xml::xpath;
use std::collections::{HashMap, HashSet};
use uppsala::{Document, NodeId};

/// Limits for explicit Manifest verification. Outer references count toward the
/// same reference budget as Manifest members. Detached Reference reads are bounded;
/// at most `max_references * max_reference_bytes` resource bytes are read.
/// Existing KeyInfo/key-retrieval policy and I/O are separate from these limits.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ManifestLimits {
    /// Maximum Manifest graph depth; roots have depth one. Hard maximum: 64.
    pub max_depth: usize,
    /// Maximum number of distinct Manifests.
    pub max_manifests: usize,
    /// Maximum total outer and distinct Manifest-member references.
    pub max_references: usize,
    /// Maximum input XML bytes (serialized bytes for a source-less DOM).
    pub max_document_bytes: usize,
    /// Maximum bytes read from any single detached reference resource.
    pub max_reference_bytes: usize,
    /// Maximum nodes inspected while finding Manifest descendants.
    pub max_nodes: usize,
}

impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_manifests: 32,
            max_references: 128,
            max_document_bytes: 16 * 1024 * 1024,
            max_reference_bytes: 16 * 1024 * 1024,
            max_nodes: 100_000,
        }
    }
}

/// One authenticated same-document Manifest and its successfully checked members.
/// Node IDs belong to the supplied document; the string API parses the document
/// once. A member digest authenticates its transformed bytes, not automatically
/// an entire application file or every part of an OPC package.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedManifest {
    /// Original Manifest element, never a copied or synthetic SignedInfo.
    pub manifest_node: NodeId,
    /// Members in original document order. Every digest was locally verified.
    pub references: Vec<VerifiedReference>,
}

/// Successful explicit Manifest verification. Returned only after the outer
/// signature and every reachable supported Manifest member validate. Any failure
/// returns `Err`, including an invalid outer signature. Unreferenced Manifests
/// and unsigned package parts are not authenticated by this result.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ManifestVerificationResult {
    /// The valid outer signature and its direct references.
    pub signature: VerifyResult,
    /// Distinct reachable Manifests, parents before children; shared DAG nodes
    /// are assessed once. Their references retain the original URI and target.
    pub manifests: Vec<VerifiedManifest>,
}

/// Verify the first Signature and its authenticated same-document Manifests.
///
/// Unlike [`super::verify`], this never succeeds with only the outer signature
/// checked when a reachable Manifest member fails or cannot be read. Existing
/// verification APIs retain their behavior. The existing resolver, transform
/// dispatcher (including OPC RelationshipTransform) and digest code are reused.
///
/// A Manifest is followed only through a reference authenticating its complete
/// containing subtree: implicit C14N or explicit C14N transforms. Filtering
/// transforms on such a reference are refused because the source DOM alone
/// cannot prove that the Manifest survived the transform. Detached references
/// explicitly typed as Manifests are currently unsupported and fail closed;
/// detached payloads are checked but are not recursively interpreted as XML.
/// Cycles, excessive graph depth/counts and skipped `cid:` digests are errors.
///
/// This is XML signature assessment, not a claim of complete package coverage,
/// certificate trust beyond `ctx`, or OPC/XAdES application conformance.
pub fn verify_with_manifests(
    ctx: &DsigContext,
    xml: &str,
    limits: &ManifestLimits,
) -> Result<ManifestVerificationResult, Error> {
    if xml.len() > limits.max_document_bytes {
        return Err(limit_error("document bytes"));
    }
    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;
    verify_document_with_manifests(ctx, &doc, Some(xml), limits)
}

/// Assess the first Signature and Manifests in their original DOM positions.
/// `source_xml`, when supplied, must represent the current document state, as
/// with [`super::verify_document_with_source`]. No document is mutated.
pub fn verify_document_with_manifests(
    ctx: &DsigContext,
    doc: &Document<'_>,
    source_xml: Option<&str>,
    limits: &ManifestLimits,
) -> Result<ManifestVerificationResult, Error> {
    if limits.max_depth == 0 || limits.max_depth > 64 {
        return Err(limit_error("depth must be between 1 and 64"));
    }
    let serialized;
    let xml = match source_xml {
        Some(xml) => xml,
        None => {
            serialized = doc.to_xml();
            &serialized
        }
    };
    if xml.len() > limits.max_document_bytes {
        return Err(limit_error("document bytes"));
    }
    let id_map = build_verify_id_map(ctx, doc)?;
    let signature_node = find_element(doc, ns::DSIG, ns::node::SIGNATURE)
        .ok_or_else(|| Error::MissingElement("Signature".into()))?;
    let signed_info = find_child_element(doc, signature_node, ns::DSIG, ns::node::SIGNED_INFO)
        .ok_or_else(|| Error::MissingElement("SignedInfo".into()))?;
    let outer_refs = find_child_elements(doc, signed_info, ns::DSIG, ns::node::REFERENCE);
    if outer_refs.is_empty() {
        return Err(Error::XmlStructure(
            "Manifest verification requires outer references".into(),
        ));
    }
    let mut graph = Graph {
        doc,
        id_map: &id_map,
        limits,
        active: HashSet::new(),
        complete: HashMap::new(),
        references: outer_refs.len(),
        inspected_nodes: 0,
        plans: Vec::new(),
    };
    if graph.references > limits.max_references {
        return Err(limit_error("references"));
    }
    // Plan and bound the whole reachable graph before doing external I/O.
    for reference in &outer_refs {
        graph.follow(*reference, 1)?;
    }
    let signature = verify_signature_node_with_limit(
        ctx,
        doc,
        Some(xml),
        signature_node,
        &id_map,
        Some(limits.max_reference_bytes),
    )?;
    if let VerifyResult::Invalid { reason } = &signature {
        return Err(Error::SignatureInvalid(reason.clone()));
    }
    if !signature.all_reference_digests_verified() {
        return Err(Error::SignatureInvalid(
            "Manifest verification requires every outer digest".into(),
        ));
    }
    let mut manifests = Vec::with_capacity(graph.plans.len());
    // Reverse postorder is topological: authenticate every parent binding
    // before interpreting a descendant Manifest's resource declarations.
    for (manifest_node, references) in graph.plans.into_iter().rev() {
        let mut checked = Vec::with_capacity(references.len());
        for reference in references {
            let uri = doc
                .element(reference)
                .and_then(|e| e.get_attribute("URI"))
                .unwrap_or("");
            let (mismatch, result) = verify_reference_with_limit(
                reference,
                doc,
                &id_map,
                Some(xml),
                signature_node,
                &ctx.url_maps,
                ctx.debug,
                ctx.base_dir.as_deref(),
                Some(limits.max_reference_bytes),
            )
            .map_err(|e| {
                Error::Other(format!(
                    "Manifest {manifest_node:?} reference URI={uri}: {e}"
                ))
            })?;
            if let Some(reason) = mismatch {
                return Err(Error::DigestMismatch(format!(
                    "Manifest {manifest_node:?}: {reason}"
                )));
            }
            if !result.digest_verified {
                return Err(Error::DigestMismatch(format!(
                    "Manifest reference URI={uri}: digest was not verified"
                )));
            }
            checked.push(result);
        }
        manifests.push(VerifiedManifest {
            manifest_node,
            references: checked,
        });
    }
    Ok(ManifestVerificationResult {
        signature,
        manifests,
    })
}

fn limit_error(which: &str) -> Error {
    Error::XmlStructure(format!("Manifest verification limit exceeded: {which}"))
}

struct Graph<'a, 'doc> {
    doc: &'a Document<'doc>,
    id_map: &'a HashMap<String, NodeId>,
    limits: &'a ManifestLimits,
    active: HashSet<NodeId>,
    complete: HashMap<NodeId, usize>,
    references: usize,
    inspected_nodes: usize,
    plans: Vec<(NodeId, Vec<NodeId>)>,
}

impl Graph<'_, '_> {
    fn follow(&mut self, reference: NodeId, depth: usize) -> Result<usize, Error> {
        let element = self
            .doc
            .element(reference)
            .ok_or_else(|| Error::XmlStructure("Reference is not an element".into()))?;
        let uri = element.get_attribute("URI").unwrap_or("");
        if uri.starts_with("cid:") {
            return Err(Error::InvalidUri(format!(
                "Manifest verification cannot skip URI={uri}"
            )));
        }
        let target = if uri.is_empty() || uri == "#xpointer(/)" {
            Some(self.doc.root())
        } else if let Some(fragment) = xpath::parse_same_document_ref(uri) {
            let id = xpath::parse_xpointer_id(fragment).unwrap_or(fragment);
            Some(xpath::resolve_id(self.doc, self.id_map, id)?)
        } else {
            None
        };
        let Some(target) = target else {
            if element.get_attribute("Type") == Some("http://www.w3.org/2000/09/xmldsig#Manifest") {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "external Manifest URI={uri}"
                )));
            }
            return Ok(0);
        };
        if element.get_attribute("Type") == Some("http://www.w3.org/2000/09/xmldsig#Manifest")
            && !self
                .doc
                .element(target)
                .is_some_and(|e| e.matches_name_ns(ns::DSIG, ns::node::MANIFEST))
        {
            return Err(Error::XmlStructure(format!(
                "Manifest Type does not target a Manifest: URI={uri}"
            )));
        }
        let mut pending = vec![target];
        let mut manifests = Vec::new();
        while let Some(node) = pending.pop() {
            if self.inspected_nodes >= self.limits.max_nodes {
                return Err(limit_error("inspected nodes"));
            }
            self.inspected_nodes += 1;
            if self
                .doc
                .element(node)
                .is_some_and(|e| e.matches_name_ns(ns::DSIG, ns::node::MANIFEST))
            {
                manifests.push(node);
            } else {
                pending.extend(self.doc.children(node).into_iter().rev());
            }
        }
        let mut height = 0;
        if !manifests.is_empty() {
            if let Some(transforms) =
                find_child_element(self.doc, reference, ns::DSIG, ns::node::TRANSFORMS)
            {
                for transform in self.doc.children(transforms) {
                    if let Some(e) = self.doc.element(transform) {
                        let algorithm = e.get_attribute(ns::attr::ALGORITHM).unwrap_or("");
                        if !e.matches_name_ns(ns::DSIG, ns::node::TRANSFORM)
                            || C14nMode::from_uri(algorithm).is_none()
                        {
                            return Err(Error::UnsupportedAlgorithm(format!("Manifest coverage through filtering transform URI={uri}: {algorithm}")));
                        }
                    }
                }
            }
            for manifest in manifests {
                height = height.max(self.visit(manifest, depth)?);
            }
        }
        Ok(height)
    }

    fn visit(&mut self, manifest: NodeId, depth: usize) -> Result<usize, Error> {
        if depth > self.limits.max_depth {
            return Err(limit_error("depth"));
        }
        if self.active.contains(&manifest) {
            return Err(Error::XmlStructure(format!(
                "Manifest cycle at {manifest:?}"
            )));
        }
        if let Some(&height) = self.complete.get(&manifest) {
            // A shared subtree may be reached later through a longer path.
            if height > self.limits.max_depth - depth + 1 {
                return Err(limit_error("depth"));
            }
            return Ok(height);
        }
        if self.active.len() + self.complete.len() >= self.limits.max_manifests {
            return Err(limit_error("Manifests"));
        }
        self.active.insert(manifest);
        let references = find_child_elements(self.doc, manifest, ns::DSIG, ns::node::REFERENCE);
        if references.is_empty()
            || self.doc.children(manifest).into_iter().any(|node| {
                self.doc
                    .element(node)
                    .is_some_and(|e| !e.matches_name_ns(ns::DSIG, ns::node::REFERENCE))
            })
        {
            return Err(Error::XmlStructure(
                "Manifest must contain Reference children only".into(),
            ));
        }
        self.references = self
            .references
            .checked_add(references.len())
            .ok_or_else(|| limit_error("references"))?;
        if self.references > self.limits.max_references {
            return Err(limit_error("references"));
        }
        let mut height = 1;
        for reference in &references {
            height = height.max(1 + self.follow(*reference, depth + 1)?);
        }
        self.active.remove(&manifest);
        self.complete.insert(manifest, height);
        self.plans.push((manifest, references));
        Ok(height)
    }
}
