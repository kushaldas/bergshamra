# Explicit Manifest verification

The existing `verify` / `verify_all` APIs assess the References directly in
`SignedInfo`. A valid Reference to an Object authenticates that Object's XML,
including any declared Manifest digests, but does not check the detached bytes
named by those Manifest members. Those entry points retain their behavior.

Use `bergshamra::verify_with_manifests` when the application requires the first
Signature's reachable same-document Manifest members to be checked as well:

```rust,no_run
use bergshamra::{DsigContext, ManifestLimits, verify_with_manifests};

fn assess(ctx: &DsigContext, xml: &str) -> Result<(), bergshamra::Error> {
    let limits = ManifestLimits::default();
    let assessment = verify_with_manifests(ctx, xml, &limits)?;
    assert!(assessment.signature.is_valid());
    for manifest in assessment.manifests {
        for reference in manifest.references {
            assert!(reference.digest_verified);
            println!("checked {}", reference.uri);
        }
    }
    Ok(())
}
```

`verify_document_with_manifests(ctx, document, source_xml, limits)` is the
corresponding original-DOM entry point. It does not move/copy Reference nodes or
mutate the document. As with existing document APIs, optional source text must
represent the current document state. Node IDs in the result belong to that DOM.

Both APIs return `Err` for invalid outer signatures, any failed or unreadable
Manifest member, a skipped `cid:` digest, a cycle, or an exceeded limit. An `Ok`
result includes the valid outer signature and every distinct supported reachable
Manifest, in parent-before-child order. Parent binding digests are checked
before any child Manifest's resources are read. Shared acyclic subgraphs are
assessed once; their full height still counts on every reachable path.

## Authenticated scope

A Manifest is followed only when an actually checked Reference authenticates its
entire containing subtree. Implicit C14N and explicit C14N transforms preserve
that scope. Filtering transforms (XPath, XSLT, Base64, enveloped-signature, etc.)
on a Manifest-containing target are explicitly unsupported in this mode: a
source-DOM node alone does not prove that its content survived such a transform.
This prevents reporting an excluded Manifest as authenticated.

Nested same-document Manifest references are supported, including an ID target
outside the parent's physical subtree. An explicit
`Type="http://www.w3.org/2000/09/xmldsig#Manifest"` must identify a same-document
Manifest element; detached typed Manifests fail explicitly. Detached payloads
are hashed as the bytes/transforms specified by their Reference, not recursively
interpreted as new XML documents. Unreferenced Manifests are not assessed or
reported. These APIs do not claim to traverse arbitrary XML inside payloads.

The existing resolver and complete Reference transform dispatcher are reused.
OPC RelationshipTransform therefore uses the same implementation as ordinary
Reference verification; no second digest, canonicalization or transform engine
is introduced. For a ZIP/OPC caller, map complete URIs (including ContentType)
through `DsigContext::add_url_map`. ZIP safety, relationship/origin validation,
ContentType matching and coverage policy belong to the calling application.

## Limits and errors

Defaults are depth8 (roots count as1),32 distinct Manifests,128 total References
(including SignedInfo),16MiB input XML,16MiB per detached Reference resource, and
100,000 inspected graph-discovery nodes. Manifest depth has an additional hard
maximum64. Set fields on `ManifestLimits::default()` to select smaller budgets.
The reachable graph is planned and bounded before Reference resource I/O.

Bounded Reference reads share the existing URL-map/relative-path resolver and
reject oversized resources rather than digesting a truncated prefix. They use a
bounded read even when a file grows after its size was checked. The limits cover
Reference reads, not existing KeyInfo/RetrievalMethod key-resolution I/O, trust
policy, or arbitrary transform-computation cost. Callers must configure their
key/resolver/application policy accordingly.

Digest errors include the Manifest and member URI. Resource errors include that
same context and the underlying resolver/read error. Unsupported coverage is
reported through `UnsupportedAlgorithm`; malformed/cyclic/over-limit graphs
through `XmlStructure`. Success never means that only an outer signature passed
while a requested member failed.

## Genuine OOXML regression and partial coverage

`crates/bergshamra-dsig/tests/data/ooxml/partial.docx` is the unchanged LibreOffice
core fixture from tag `libreoffice-26.2.0.3`. Its original MPL-2.0 license and source
links are included alongside exact extracted resource bytes. It has3
SignedInfo References and8 Manifest members, including2 RelationshipTransform
references. The new mode verifies all8; changing `word/document.xml` or removing
its mapped file fails while the legacy outer-only API still passes.

The original deliberately has **partial package coverage**. Checking its8
Manifest declarations does not authenticate unsigned `docProps` streams or
establish full-package coverage, XAdES conformance, certificate trust, or an
Office/LibreOffice application's approval. Applications must inspect the member
results and apply their own complete-package and certificate policies.

An external `xmlsec1 1.3.9` reproduction with explicit URL mappings and `--verbose`
reports SignedInfo3/3 + Manifest8/8 on the original. On body tampering it reports
3/3 +7/8 but can still exit0: its outer signature status must not be substituted
for the separate Manifest result. The new Rust API returns an error for that
member mismatch. The tests also cover nested graphs, shared DAGs, cycles,
filtering exclusions, unsupported detached Manifests and all limits.
