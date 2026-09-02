# ADR-0008: Document-Native Signing and Verification

**Date:** 2026-07-10
**Status:** Accepted
**Context:** Removing the whole-document parse/serialize round trips from enveloped signing and verification of large documents (SAML metadata aggregates around 100 MB)

## Problem

The string API (`sign()`, `sign_enveloped()`, `verify()`) treats XML text as
the unit of exchange. Internally, `sign_owned()` parses the whole template and
then re-parses the entire document once per `<Reference>` so that
same-document references observe already-filled `DigestValue` elements, and
finally serializes the whole result back to a `String`. A Rust caller that
already holds a DOM additionally pays one serialization before the call and
one re-parse after it.

For an enveloped single-reference 100 MB aggregate that is two full parses
inside the signer plus a document-sized output string, around four whole-
document XML passes per signature, dwarfing the C14N and RSA work that
signing actually requires.

## Decision

Add document-native entry points that operate in place on a caller-provided
`uppsala::Document`:

- `sign_document(ctx, doc)` fills an existing `<Signature>` skeleton directly
  in the live DOM (`replace_element_text` swaps text nodes in place); nothing
  is serialized or re-parsed at document scale.
- `sign_enveloped_document(ctx, doc, options)` builds the standard enveloped
  template, parses only that small fragment, imports it as the document
  element's first child, and delegates to `sign_document`.
- `verify_document(ctx, doc)` / `verify_all_document(ctx, doc)` verify against
  the live DOM; the generic transform fallback serializes lazily only when a
  transform actually needs XML text.

Reference digests on the common shape (at most one enveloped-signature
transform followed by at most one C14N transform, same-document `#id`, empty,
or xpointer URIs) stream canonical bytes straight into the digest through
`ReferenceDigestSink` implementing `C14nSink`, so no document-sized buffer is
materialized. Uncommon transform chains fall back to the existing transform
pipeline, which serializes the current DOM for that pipeline only.

The string API stays: it is the stable, self-contained surface for callers
that genuinely hold text, and the reference implementation the document path
is tested against.

## Consequences

- Criterion benchmark (`benches/dsig.rs`, synthetic SAML-shaped aggregate,
  RSA-2048, exclusive C14N): sign 1 MB 84.7 ms to 38.3 ms (2.2x), sign 20 MB
  1.88 s to 717 ms (2.6x); verify 20 MB 652 ms to 453 ms.
- Signing mutates the caller's document (signature inserted, digest and
  signature values filled). Callers that need the pre-sign tree must copy it
  first.
- Same-document references resolve against the live DOM instead of re-parsed
  text, removing the per-reference re-parse loop entirely on the fast path.
- These document-native APIs are supported only within one linked Rust
  dependency graph. Python extension modules exchange owned serialized XML;
  sharing Uppsala DOM pointers or capsules across extension boundaries is not
  supported.
