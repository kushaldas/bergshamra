# Explicit Manifest verification

The existing `verify` / `verify_all` APIs assess the References directly in
`SignedInfo`. A valid Reference to an Object authenticates that Object's XML,
including any declared Manifest digests, but does not check the detached bytes
named by those Manifest members. Those entry points retain their behavior.

Use `bergshamra::verify_with_manifests` when the application requires the first
Signature's reachable same-document Manifest members to be checked as well.
For package validation, also require the expected Manifest and Signature identity;
`Ok` with no reachable Manifest is a valid generic XMLDSig result, not package
coverage. The parsed-DOM API lets the application bind its expected nodes. Its
example is compiled by `cargo test --doc -p bergshamra`.

See the [compiled facade example](https://docs.rs/bergshamra/latest/bergshamra/#binding-manifest-results-to-expected-nodes),
which binds both the expected Signature and Manifest NodeIds. The example lives
in the facade crate itself so it also ships in that crate's published package.

This API intentionally verifies only the **first** Signature, just like `verify`.
A later signature is neither a fallback for an invalid first signature nor an
implicit source of package coverage. Reported DOM IDs, direct reference targets
and each Manifest's member targets let the caller relate the authenticated
edges to its expected nodes. The result does not store a separate authentication
path or promise that a particular application Object was selected. Even with
zero reachable Manifests, every `Ok` result contains `VerifyResult::Valid`;
the existing enum is retained for compatibility and shared result handling.

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
that scope. An enveloped-signature transform before C14N excludes precisely the
current Signature subtree; Manifests in that excluded subtree are not followed
unless a separate reference authenticates them. Manifests elsewhere in the
covered document remain reachable. XPath, XSLT, Base64 and other filtering
pipelines on a Manifest-containing target are explicitly unsupported: the
source DOM alone cannot prove that its content survived those transformations.

Nested same-document Manifest references are supported, including an ID target
outside the parent's physical subtree. An explicit
`Type="http://www.w3.org/2000/09/xmldsig#Manifest"` must identify a same-document
Manifest element; detached typed Manifests fail explicitly. Detached payloads
are hashed as the bytes/transforms specified by their Reference, not recursively
interpreted as new XML documents. A Manifest containing another `ds:Manifest`
anywhere in its subtree is rejected as malformed, including one hidden deeper
inside a Reference/Transform. Unreferenced Manifests are not assessed or
reported. These APIs do not claim to traverse arbitrary XML inside payloads.

The existing resolver and complete Reference transform dispatcher are reused.
OPC RelationshipTransform therefore uses the same implementation as ordinary
Reference verification; no second digest, canonicalization or transform engine
is introduced. For a ZIP/OPC caller, map complete URIs (including ContentType)
through `DsigContext::add_url_map`. ZIP safety, relationship/origin validation,
ContentType matching and coverage policy belong to the calling application.

RelationshipTransform authenticates its selected relationships: changing a
selected Target fails its digest, while adding or changing an unselected
relationship can pass. The genuine fixture tests change the selected root
`_rels/.rels` rId1 and document-level rId1–rId5, modify the existing unselected
root rId2/rId3 Targets, and add an unselected document-level rId99. These checks
assert only the transform-selected relationship scope. This partial-coverage
contract does not authenticate new unselected package parts.

## Limits and errors

Defaults are depth 8 (roots count as 1), 32 distinct Manifests, 128 total
References (including SignedInfo), 16 MiB input XML, 16 MiB per detached Reference
resource, and 100,000 inspected Manifest candidates. Manifest depth has an
additional hard maximum of 64. The document is indexed once under the XML byte
budget; ordinary payload nodes do not consume the graph's candidate budget.
This is not a general parser node-count or transform-cost limit. Reachable
graph work, cycles, depth, shared-DAG height and counts remain bounded before
Reference resource I/O. Source-less DOM size is counted through the existing
streaming serializer without allocating a second full XML String; actual
reference processing retains its lazy fallback where needed.

These are explicit default budgets, not a claim that every Office package fits.
For a known larger package, raise the specific budget on `ManifestLimits` (for
example `limits.max_references = 512` or `limits.max_reference_bytes = 64 * 1024 *
1024`) after applying the application's resource policy. Tests cover more than
128 references and a resource larger than 16 MiB, both default refusal and
caller-selected success. The depth hard maximum remains 64.

Bounded Reference reads share the existing URL-map/relative-path resolver and
reject oversized resources rather than digesting a truncated prefix. They use a
bounded read even when a file grows after its size was checked. The limits cover
Reference reads, not existing KeyInfo/RetrievalMethod key-resolution I/O, trust
policy, or arbitrary transform-computation cost. Callers must configure their
key/resolver/application policy accordingly. In explicit Manifest mode, relative
resources need a configured `base_dir` or an exact URL map; a missing base file
never falls back to the process cwd. Legacy `verify` APIs retain their historical
cwd fallback. Traversal and lookalike URI maps remain refused. When
`ctx.strict_verification` is enabled, the existing XSW position rule applies to
same-document Manifest member targets as well as direct references; permissive
mode still returns the actual targets for application-specific checks.

Digest errors include the Manifest and member URI. Resource errors include that
same context and the underlying resolver/read error. Member processing preserves
the original error category (`UnsupportedAlgorithm`, `InvalidUri`, `Transform`,
etc.). In explicit Manifest mode, mapped-file I/O errors retain `Io` and its
underlying kind (`NotFound`, or `InvalidInput` for a non-regular resource); a
directory is not misreported as a byte-budget failure. Legacy mapped-read error
categories remain unchanged. Outer and member digest mismatches both use
`DigestMismatch`. Invalid SignatureValue uses `SignatureInvalid`. Malformed, cyclic and over-limit graphs
use `XmlStructure`. Bounded planning deliberately precedes outer authentication,
so a graph error can be reported before an invalid SignatureValue; both are
rejections and neither authenticates any node. Success never means that only an
outer signature passed while a requested member failed.

## Genuine OOXML regression and partial coverage

`crates/bergshamra-dsig/tests/data/ooxml/partial.docx` is the unchanged LibreOffice
core fixture from tag `libreoffice-26.2.0.3`. Its original MPL-2.0 license and source
links are included alongside exact extracted resource bytes. It has 3
SignedInfo References and 8 Manifest members, including 2 RelationshipTransform
references. The new mode verifies all 8; changing `word/document.xml` or removing
its mapped file fails while the legacy outer-only API still passes.

The original deliberately has **partial package coverage**. Checking its 8
Manifest declarations does not authenticate unsigned `docProps` streams or
establish full-package coverage, XAdES conformance, certificate trust, or an
Office/LibreOffice application's approval. Applications must inspect the member
results and apply their own complete-package and certificate policies.

An external `xmlsec1 1.3.9` reproduction with explicit URL mappings and `--verbose`
reports SignedInfo 3/3 + Manifest 8/8 on the original. On body tampering it reports
3/3 + 7/8 but can still exit 0: its outer signature status must not be substituted
for the separate Manifest result. The new Rust API returns an error for that
member mismatch. The tests also cover nested graphs, shared DAGs, cycles,
filtering exclusions, unsupported detached Manifests and all limits.
