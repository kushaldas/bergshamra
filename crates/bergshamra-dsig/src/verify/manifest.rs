//! Explicit, bounded assessment of authenticated same-document Manifests.

use super::{
    account_retained_octets, build_verify_id_map, find_child_element, find_child_elements,
    find_element, validate_reference_position, verify_reference_with_limit,
    verify_signature_node_with_limit, VerifiedReference, VerifyResult,
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
    /// Maximum Manifest candidates inspected during graph discovery. The
    /// document is indexed once under `max_document_bytes`, not this budget.
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
/// containing subtree: implicit C14N or explicit C14N transforms. A preceding
/// enveloped-signature transform excludes only the current Signature subtree;
/// excluded Manifests need a separate authenticated reference. Other filtering
/// transforms on Manifest-containing targets are refused because source DOM
/// membership alone cannot prove that a Manifest survived the transform. Detached references
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
    check_document_bytes(doc, source_xml, limits.max_document_bytes)?;
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
        index: ManifestIndex::new(doc, &id_map, signature_node),
        signature_node,
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
        source_xml,
        signature_node,
        &id_map,
        Some(limits.max_reference_bytes),
        true,
    )?;
    if let VerifyResult::Invalid { reason } = &signature {
        return Err(Error::SignatureInvalid(reason.clone()));
    }
    if !signature.all_reference_digests_verified() {
        return Err(Error::SignatureInvalid(
            "Manifest verification requires every outer digest".into(),
        ));
    }
    // Outer references and Manifest members share one retained-octets budget.
    let mut retained_octets = 0usize;
    if let VerifyResult::Valid { references, .. } = &signature {
        for reference in references {
            account_retained_octets(&mut retained_octets, reference, ctx.retain_reference_octets)?;
        }
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
                source_xml,
                signature_node,
                &ctx.url_maps,
                ctx.debug,
                ctx.base_dir.as_deref(),
                Some(limits.max_reference_bytes),
                ctx.retain_reference_octets.is_some(),
            )
            .map_err(|error| reference_error(doc, manifest_node, uri, error))?;
            account_retained_octets(&mut retained_octets, &result, ctx.retain_reference_octets)?;
            if let Some(reason) = mismatch {
                return Err(Error::DigestMismatch(format!(
                    "Manifest reference URI={uri}: {reason}"
                )));
            }
            if !result.digest_verified {
                return Err(Error::DigestMismatch(format!(
                    "Manifest reference URI={uri}: digest was not verified"
                )));
            }
            if ctx.strict_verification {
                if let Some(target) = result.resolved_node {
                    validate_reference_position(doc, signature_node, target)
                        .map_err(|error| reference_error(doc, manifest_node, uri, error))?;
                }
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
    index: ManifestIndex,
    signature_node: NodeId,
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
        let coverage = subtree_coverage(self.doc, reference);
        let exclusion = coverage
            .filter(|excluded| *excluded)
            .map(|_| self.signature_node);
        let (start, end) = self.index.ranges[&target];
        let excluded_range = exclusion.map(|node| self.index.ranges[&node]);
        let mut position = self
            .index
            .manifests
            .partition_point(|(entry, _)| *entry < start);
        let mut manifests = Vec::new();
        while let Some(&(entry, manifest)) = self.index.manifests.get(position) {
            if entry >= end {
                break;
            }
            if let Some((excluded_start, excluded_end)) = excluded_range {
                if (excluded_start..excluded_end).contains(&entry) {
                    position = self
                        .index
                        .manifests
                        .partition_point(|(entry, _)| *entry < excluded_end);
                    continue;
                }
            }
            if self.inspected_nodes >= self.limits.max_nodes {
                return Err(limit_error("inspected nodes"));
            }
            self.inspected_nodes += 1;
            manifests.push(manifest);
            // Nested Manifests are not separate roots. visit() checks the full
            // indexed subtree before interpreting any member declarations.
            let manifest_end = self.index.ranges[&manifest].1;
            position = self
                .index
                .manifests
                .partition_point(|(entry, _)| *entry < manifest_end);
        }
        let mut height = 0;
        if manifests.is_empty()
            && element.get_attribute("Type") == Some("http://www.w3.org/2000/09/xmldsig#Manifest")
        {
            return Err(Error::UnsupportedAlgorithm(format!(
                "Manifest target excluded by transform URI={uri}"
            )));
        }
        if !manifests.is_empty() {
            if coverage.is_none() {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Manifest coverage through filtering transform URI={uri}"
                )));
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
                "Manifest cycle at Id={}",
                self.doc
                    .element(manifest)
                    .and_then(|e| e.get_attribute("Id"))
                    .unwrap_or("<anonymous>")
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
        let (start, end) = self.index.ranges[&manifest];
        let next = self
            .index
            .manifests
            .partition_point(|(entry, _)| *entry <= start);
        if self
            .index
            .manifests
            .get(next)
            .is_some_and(|(entry, _)| *entry < end)
        {
            return Err(Error::XmlStructure(
                "Manifest must not contain nested Manifest elements".into(),
            ));
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

/// Preorder intervals are computed once from the actual DOM, not inferred from
/// arena IDs or potentially stale source offsets. Ordinary payload nodes do not
/// consume the graph's Manifest-candidate budget.
struct ManifestIndex {
    ranges: HashMap<NodeId, (usize, usize)>,
    manifests: Vec<(usize, NodeId)>,
}
impl ManifestIndex {
    fn new(doc: &Document<'_>, ids: &HashMap<String, NodeId>, signature: NodeId) -> Self {
        // Same-document targets are IDs or the document root. Keep intervals
        // only for possible targets and Manifests, not ordinary payload nodes.
        let mut targets: HashSet<NodeId> = ids.values().copied().collect();
        targets.extend([doc.root(), signature]);
        let mut index = Self {
            ranges: HashMap::new(),
            manifests: Vec::new(),
        };
        let mut pending = vec![(doc.root(), false)];
        let mut next = 0;
        while let Some((node, exit)) = pending.pop() {
            if exit {
                if let Some(range) = index.ranges.get_mut(&node) {
                    range.1 = next;
                }
                continue;
            }
            let manifest = doc
                .element(node)
                .is_some_and(|e| e.matches_name_ns(ns::DSIG, ns::node::MANIFEST));
            if targets.contains(&node) || manifest {
                index.ranges.insert(node, (next, next));
            }
            if manifest {
                index.manifests.push((next, node));
            }
            next += 1;
            pending.push((node, true));
            pending.extend(
                doc.children(node)
                    .into_iter()
                    .rev()
                    .map(|child| (child, false)),
            );
        }
        index
    }
}

/// Return whether the current Signature subtree is excluded. `None` means an
/// unsupported filtering pipeline, for which source-DOM coverage is unknown.
fn subtree_coverage(doc: &Document<'_>, reference: NodeId) -> Option<bool> {
    let Some(transforms) = find_child_element(doc, reference, ns::DSIG, ns::node::TRANSFORMS)
    else {
        return Some(false);
    };
    let mut enveloped = false;
    let mut canonicalized = false;
    for node in doc.children(transforms) {
        let Some(element) = doc.element(node) else {
            continue;
        };
        if !element.matches_name_ns(ns::DSIG, ns::node::TRANSFORM) {
            return None;
        }
        let algorithm = element.get_attribute(ns::attr::ALGORITHM).unwrap_or("");
        if C14nMode::from_uri(algorithm).is_some() {
            canonicalized = true;
        } else if algorithm == bergshamra_core::algorithm::ENVELOPED_SIGNATURE
            && !canonicalized
            && !enveloped
            && doc
                .children(node)
                .into_iter()
                .all(|child| doc.element(child).is_none())
        {
            enveloped = true;
        } else {
            return None;
        }
    }
    Some(enveloped)
}

/// Count source-less DOM serialization without allocating a second full XML
/// String. Actual reference processing retains its existing lazy fallback.
fn check_document_bytes(
    doc: &Document<'_>,
    source: Option<&str>,
    limit: usize,
) -> Result<(), Error> {
    if let Some(source) = source {
        return if source.len() <= limit {
            Ok(())
        } else {
            Err(limit_error("document bytes"))
        };
    }
    let mut counter = DocumentByteLimit {
        remaining: limit,
        exceeded: false,
    };
    doc.write_to(&mut counter).map_err(|error| {
        if counter.exceeded {
            limit_error("document bytes")
        } else {
            Error::Io(error)
        }
    })
}
struct DocumentByteLimit {
    remaining: usize,
    exceeded: bool,
}
impl std::io::Write for DocumentByteLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(std::io::Error::other("document byte budget exceeded"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn reference_error(doc: &Document<'_>, manifest: NodeId, uri: &str, error: Error) -> Error {
    let id = doc
        .element(manifest)
        .and_then(|e| e.get_attribute("Id"))
        .unwrap_or("<anonymous>");
    let prefix = format!("Manifest Id={id} reference URI={uri}");
    match error {
        Error::XmlParse(message) => Error::XmlParse(format!("{prefix}: {message}")),
        Error::XmlStructure(message) => Error::XmlStructure(format!("{prefix}: {message}")),
        Error::UnsupportedAlgorithm(message) => {
            Error::UnsupportedAlgorithm(format!("{prefix}: {message}"))
        }
        Error::Crypto(message) => Error::Crypto(format!("{prefix}: {message}")),
        Error::Key(message) => Error::Key(format!("{prefix}: {message}")),
        Error::SignatureInvalid(message) => Error::SignatureInvalid(format!("{prefix}: {message}")),
        Error::DigestMismatch(message) => Error::DigestMismatch(format!("{prefix}: {message}")),
        Error::Canonicalization(message) => Error::Canonicalization(format!("{prefix}: {message}")),
        Error::Transform(message) => Error::Transform(format!("{prefix}: {message}")),
        Error::Encryption(message) => Error::Encryption(format!("{prefix}: {message}")),
        Error::Decryption(message) => Error::Decryption(format!("{prefix}: {message}")),
        Error::Base64(message) => Error::Base64(format!("{prefix}: {message}")),
        Error::KeyNotFound(message) => Error::KeyNotFound(format!("{prefix}: {message}")),
        Error::MissingElement(message) => Error::MissingElement(format!("{prefix}: {message}")),
        Error::MissingAttribute(message) => Error::MissingAttribute(format!("{prefix}: {message}")),
        Error::InvalidUri(message) => Error::InvalidUri(format!("{prefix}: {message}")),
        Error::Certificate(message) => Error::Certificate(format!("{prefix}: {message}")),
        Error::Other(message) => Error::Other(format!("{prefix}: {message}")),
        Error::Io(error) => Error::Io(std::io::Error::new(
            error.kind(),
            format!("{prefix}: {error}"),
        )),
    }
}

#[cfg(test)]
mod review_regressions {
    use super::*;
    #[test]
    fn source_less_document_size_is_checked_with_a_bounded_writer() {
        let xml = format!("<Root>{}</Root>", "payload".repeat(10_000));
        let doc = uppsala::parse(&xml).unwrap();
        let mut counter = DocumentByteLimit {
            remaining: 8,
            exceeded: false,
        };
        assert!(doc.write_to(&mut counter).is_err());
        assert!(counter.exceeded);
        assert!(
            matches!(check_document_bytes(&doc, None, 8), Err(Error::XmlStructure(message)) if message.contains("document bytes"))
        );
        let exact = doc.to_xml().len(); // Test-only expected serialized size.
        assert!(check_document_bytes(&doc, None, exact).is_ok());
        assert!(matches!(
            check_document_bytes(&doc, None, exact - 1),
            Err(Error::XmlStructure(_))
        ));
    }
}
