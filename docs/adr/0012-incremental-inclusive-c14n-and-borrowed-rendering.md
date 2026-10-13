# ADR-0012: Incremental Inclusive C14N, Borrowed Attribute Rendering, and the Uppsala 0.12 Baseline

**Date:** 2026-10-13
**Status:** Accepted
**Context:** Porting the measured performance work from the `fix/perf`
experiment branch onto `main` while keeping bergshamra pure Rust

## Problem

ADR-0011 made exclusive C14N incremental and batched digest updates, but the
inclusive serializer and the shared rendering types kept three costs that
dominated profiles of SAML aggregate signing and verification:

1. Inclusive C14N rebuilt the complete in-scope namespace map by walking the
   ancestor chain for every element, the O(depth)-per-element pattern that
   ADR-0011 had already removed from the exclusive serializer.
2. Both serializers still allocated per node: a `format!` for every element
   name, a defensive clone of every text and processing-instruction value,
   and four owned `String`s for every attribute (namespace URI, local name,
   pre-formatted qualified name, value). An attribute-heavy canonicalization
   produced roughly 12,800 allocations from `Attr` alone.
3. `NodeSet` used the default SipHash `HashSet<usize>` for node indexes, and
   the output sink started empty and grew by doubling.

Two further issues were found while profiling:

- Serialization paths called `doc.element(id).unwrap()`. An inconsistent
  arena would abort the process, which a security library must not do.
- The release profile used the Cargo defaults, leaving cross-crate inlining
  between the workspace crates, `uppsala`, and `kryptering` to the linker.

Separately, `uppsala` 0.12.0 was published with direct DOM construction,
fused descendant XPath walks, and pre-sized serialization buffers, and the
Python bindings needed to serialize only the inserted `<ds:Signature>` rather
than the whole signed document.

The experiment branch also carried a C allocator crate. That part is
deliberately not ported; see "Alternatives Considered".

## Decision

### Maintain inclusive C14N namespace state incrementally

Inclusive C14N now carries the in-scope namespace map across its depth-first
traversal. Entering an element applies only that element's declarations and
records each previous binding in an undo log; leaving the subtree replays the
log in reverse. This is the same push/pop model ADR-0011 established for the
exclusive serializer, so both serializers now share one traversal discipline.

The incremental map preserves the exact semantics of the old ancestor walk:
`xmlns=""` stays an empty-string entry, prefixed undeclarations remove the
prefix, and the namespace node-set visibility scoping (`child_ns`) is
unchanged. Byte identity is therefore structural rather than incidental.

### Stream names and values from the arena

Element names, namespace declarations, and attributes are written straight to
the sink from the document arena. The per-element `format!`, the text and PI
clones, and the per-attribute rendered strings are gone from both serializers.

### Borrow attribute data through `Attr<'a>`

`bergshamra_c14n::render::Attr` becomes lifetime-generic with `Cow<'a, str>`
fields borrowed from the uppsala arena. It carries a separate `prefix` instead
of a pre-formatted `qualified_name`; the qualified name is written at
serialization time. Equality follows the canonical ordering key (namespace URI
and local name), which is what sorting and de-duplication actually compare.

One borrowed type serves both the whole-document and document-subset paths.
Where the subset path must synthesize an attribute that is not on the element
(`xml:*` inheritance, C14N 1.1 base handling), it stores an owned `Cow`. This
keeps a single rendering path and a single semantics-bearing implementation.

`NsDecl` stays owned. There are one to three declarations per element against
eight or more attributes on the hot documents, and the measured gain did not
justify a second lifetime parameter.

### Fast hashing and pre-sized sinks

`NodeSet` stores node indexes in an `FxHashSet` exposed as the `NodeIdSet`
alias; `from_ids` and `node_ids` use it, as do the ID sets in DSig
verification. `canonicalize_doc_to` pre-sizes buffering sinks to the input
text length.

### Fail with an error, never a panic

Element lookups inside the serializers go through `element_of()`, which
returns `Error::Canonicalization` for an inconsistent arena. Guarded
`Option::unwrap()` calls in the same paths were restructured away.

### Return the signature node from enveloped signing

`bergshamra_dsig::sign::sign_enveloped_document_with_node` signs exactly like
`sign_enveloped_document` and additionally returns the `NodeId` of the
inserted `<ds:Signature>`. `sign_enveloped_document` is now a thin wrapper.
Bindings use the node to serialize only the signature fragment and splice it
into their own document instead of re-serializing and re-parsing the whole
signed aggregate.

### Build profiles and benchmark infrastructure

The release profile uses fat LTO, a single codegen unit, and symbol stripping.
A `profiling` profile inherits from it but disables LTO, restores codegen
parallelism, and keeps full debug info so flamegraphs resolve symbols. The dev
profile keeps line tables only.

An end-to-end criterion benchmark (`cargo bench -p bergshamra-dsig --bench
dsig_e2e`) covers enveloped HMAC and RSA sign and verify at 40 and 400
entities. `scripts/` holds the fixture generator, a hyperfine CLI wall-time
harness, and a peak-RSS harness, each with a matching `just bench-*` recipe.

### Require uppsala 0.12.0

The workspace requires `uppsala` 0.12.0. Callers already on 0.10 document
types need no code changes; the bump is a baseline change for parse cost.

## Correctness Invariants

- Canonical output is byte-for-byte identical to the previous implementation
  for all six C14N variants, with and without a node set.
- Namespace declarations on invisible ancestors still reach visible
  descendants; rebinding and undeclaration apply only to their subtree.
- Undo logs are restored in reverse mutation order and on error return.
- `Attr` ordering and equality are unchanged: the sort key is still
  (namespace URI, local name).
- Synthesized attributes in the document-subset path are produced exactly as
  before; only their storage changed.
- No serialization path can panic on an inconsistent arena.

The xmlsec test suites run through the shim are the byte-identity gate:
DSig 447 OK, 0 failed, 3 skipped; Enc 700 OK, 0 failed, 1 skipped (the
deliberate DH-1024 composite-order rejection by kryptering). All workspace
unit tests pass with zero clippy warnings on both the default and the
`--no-default-features` feature sets.

## Alternatives Considered

### Ship a jemalloc or mimalloc global allocator

Rejected. The experiment branch measured a C allocator in the CLI. It was
dropped before porting because bergshamra ships no C code: a `cc`-built
allocator breaks the pure-Rust guarantee for every CLI user and
cross-compilation target, and library consumers must keep control of their
own allocator. The rejection is recorded in `README.md`. Allocator
experiments stay in scratch checkouts, and all numbers below use the system
allocator because that is what ships.

### Two rendering paths, borrowed whole-document and owned subset

This was the design proposed in ADR-0010. Not selected. A single `Cow`-based
type gives the borrowed fast path for the common case and an owned slot for
synthesized attributes without duplicating the sorting and escaping logic or
leaving two implementations to keep byte-identical.

### Cache a complete namespace map per element

Rejected for the same reason as in ADR-0011: document-proportional retained
memory and cache ownership complexity for a cost the undo log removes.

### Borrow `NsDecl` as well

Deferred. The per-element count is small and the `Cow` clone from uppsala is
a pointer copy in the common borrowed case; the measured benefit did not
clear the noise floor.

### Parse once per operation

Out of scope here. Verify and sign still re-parse for same-document
references, so each saved parse in uppsala is paid several times per
operation. That audit remains open and is the next item on the plan.

## Measured Consequences

Measurements come from two stages on the same developer machine with the
release profile above and the system allocator. The host showed large thermal
variance during the first stage (an untouched benchmark moved by up to 90%
between consecutive runs), so only deltas far outside that band are claimed;
the inclusive C14N wins cleared it in three independent comparisons and the
ambiguous cases were confirmed with thermally neutral stash A/B runs.

Stage 1 covers the C14N and rendering changes. The two tables use different
baselines and say so: the C14N rows were measured against the tree after the
release profile landed, so they isolate the code changes; the end-to-end rows
were saved against the earlier pre-profile baseline, so their first delta
includes the profile gain and the second delta, where a post-profile value
exists, isolates the C14N and rendering stage.

C14N, against the post-profile tree:

| Benchmark | Before | After | Change |
| --- | ---: | ---: | ---: |
| c14n_inclusive/saml | 807 us | 210 us | -74% |
| c14n_inclusive/attr_heavy | 1409 us | 449 us | -68% |
| c14n_inclusive/text_heavy | 75 us | 58 us | -22% |
| c14n_exclusive/saml | 232 us | 176 us | -24% |
| c14n_exclusive/attr_heavy | 490 us | 442 us | -11% |

End-to-end, against the pre-profile baseline, with the post-profile value
where one was recorded:

| Benchmark | Pre-profile | Post-profile | After | vs pre | vs post |
| --- | ---: | ---: | ---: | ---: | ---: |
| verify/enveloped_hmac_40 | 922 us | 778 us | 680 us | -28% | -13% |
| verify/enveloped_hmac_400 | 8.37 ms | 7.00 ms | 6.52 ms | -22% | -7% |
| sign/enveloped_hmac_40 | 966 us | n/a | 901 us | -12% | n/a |
| sign/enveloped_rsa_40 | 3.92 ms | 3.96 ms | 3.59 ms | -8% | -9% |

Stage 2, the uppsala 0.10.1 to 0.12.0 bump with bergshamra code identical in
both columns, so the C14N rows are the noise-floor control:

| Benchmark | uppsala 0.10.1 | uppsala 0.12.0 | Change |
| --- | ---: | ---: | ---: |
| parse/saml | 259 us | 180 us | -31% |
| parse/text_heavy | 248 us | 207 us | -16% |
| c14n_inclusive/saml | 184 us | 179 us | noise (control) |
| c14n_exclusive/saml | 185 us | 178 us | noise (control) |
| verify/enveloped_hmac_40 | 669 us | 524 us | -22% |
| verify/enveloped_hmac_400 | 6.43 ms | 5.09 ms | -21% |
| sign/enveloped_hmac_40 | 776 us | 655 us | -16% |
| sign/enveloped_hmac_400 | 7.40 ms | 6.54 ms | -12% |

The end-to-end HMAC gains exceed the parse gains because of the repeated
parsing noted above. RSA rows are within noise or confounded by a differing
kryptering build and are not claimed.

Through the Python bindings, with the GIL released on every hot entry point,
canonicalizing a 10.7 MB document went from 461 ms to about 210 ms and
four-thread verify wall time from 7.56 ms to about 3.1 ms. On the pyFF
benchmark host the SWAMID 720-entity MDQ job went from 30.2 s to 9.5 s and the
aggregate job from 69.8 s to 46.0 s with peak RSS down from 3.7 GB to 2.7 GB,
with all outputs independently verified. The full tables are in
`performance.md` and in the pybergshamra performance notes.

## Consequences

Positive consequences:

- Both C14N serializers now share one incremental, undo-logged traversal.
- Attribute-heavy canonicalization no longer allocates per attribute.
- Serialization paths return errors instead of aborting the process.
- Bindings can splice a signature fragment instead of round-tripping the
  whole signed document.
- Bergshamra remains pure Rust; the allocator experiment did not land.
- Benchmarks and build profiles are in the tree, so future changes can be
  measured the same way.

Negative consequences:

- `render::Attr` gained a lifetime parameter and lost `qualified_name`,
  which is a breaking change for any external user of the render types.
- Release builds are slower to link because of fat LTO and one codegen unit;
  the `profiling` profile exists for iteration and flamegraphs.
- The inclusive serializer now carries the same mutable traversal state and
  apply/restore pairing obligations as the exclusive one.

## Relationship to Earlier Decisions

This decision completes the work ADR-0011 started by applying the incremental
namespace model to inclusive C14N. It supersedes ADR-0010: the goal of
allocation-free attribute rendering is realized, but through one borrowed
`Cow` type rather than the two-path design that ADR proposed. It keeps the
document-native streaming architecture of ADR-0008 and adds no new signing
semantics; `sign_enveloped_document_with_node` only exposes a node the
existing path already created.
