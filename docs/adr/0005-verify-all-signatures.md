# ADR-0005: Verify Every `<Signature>` in a Document with `verify_all`

**Date:** 2026-06-29
**Status:** Accepted
**Context:** Verifying documents that carry more than one XML-DSig signature, in particular SAML Responses signed at both the Response and the Assertion level

## Problem

`bergshamra_dsig::verify::verify()` finds the **first** `<Signature>` element
in document order, verifies it, and returns a single `VerifyResult`. This is
correct for the common case of a singly-signed document, but it cannot serve a
caller that needs to confirm a *specific* object is covered by a valid
signature when that object's signature is not first in the document.

The motivating case is SAML. A SAML Response is frequently signed in two
places: the `Response` element **and** each `Assertion`. Per the SAML schema
the Response-level `<ds:Signature>` appears immediately after the Response
`<Issuer>`, i.e. *before* the Assertion and its signature:

```xml
<samlp:Response ID="_resp">
  <saml:Issuer>...</saml:Issuer>
  <ds:Signature> ... URI="#_resp" ... </ds:Signature>   <!-- first in doc order -->
  <samlp:Status>...</samlp:Status>
  <saml:Assertion ID="_assert">
    <saml:Issuer>...</saml:Issuer>
    <ds:Signature> ... URI="#_assert" ... </ds:Signature> <!-- second -->
    ...
  </saml:Assertion>
</samlp:Response>
```

A Service Provider that consumes identity/attributes from the Assertion must
bind cryptographic verification to that Assertion — its verified
`<Reference>` must target the Assertion's `ID` (this is the standard defence
against XML Signature Wrapping). With `verify()` the SP only ever sees the
Response signature's references (`#_resp`), never `#_assert`, so it cannot
confirm the Assertion is individually signed. SPID, for example, mandates that
the Assertion itself be signed; an SP enforcing that with `verify()` alone
rejects every legitimately signed Assertion.

The signatures must each be verified on the *unmodified* document: extracting
the Assertion to a standalone document and verifying that loses the ancestor
namespace context the signature was computed over (exclusive c14n re-derives
namespaces, but the extracted element must still parse, and inherited prefix
bindings would be undeclared). Verifying in place avoids that fragility.

## Options Considered

### Option A: Caller extracts the Assertion and calls `verify()` on it

The caller slices out the `<saml:Assertion>...</saml:Assertion>` substring and
verifies it as its own document, so its signature becomes the first one.

- **Pro:** No new API.
- **Con:** Pushes byte-exact extraction and namespace re-injection into every
  caller, in a security-critical path. The extracted element typically relies
  on prefix bindings (`saml:`, `ds:`) declared on ancestors and will not parse
  standalone without re-injecting them; getting this wrong silently breaks
  verification or, worse, weakens it. Re-serialization risks changing bytes the
  digest covers.

### Option B: `verify()` returns all signatures

Change `verify()` to return `Vec<VerifyResult>`.

- **Pro:** One entry point.
- **Con:** Breaking API change for every existing caller, the vast majority of
  which sign once and want a single verdict.

### Option C: Add `verify_all` alongside `verify` (chosen)

Add `verify_all(ctx, xml) -> Result<Vec<VerifyResult>, Error>` that finds every
`<Signature>` in the document and verifies each independently, in document
order. `verify()` is unchanged.

- **Pro:** Non-breaking. The single-signature fast path stays simple. Callers
  that need multi-signature documents opt in and decide which verified
  references they require. Each signature is verified against the original,
  unmodified document, so namespace context is exactly what was signed.
- **Con:** A second entry point with overlapping responsibility; callers must
  understand which to use.

## Decision

**Option C.** Add `verify_all`. It shares all per-signature logic with
`verify()` via an extracted `verify_signature_node(ctx, doc, xml, sig_node,
id_map)` helper, so the two paths cannot diverge in how a signature is checked.

`verify_all`:

- returns one `VerifyResult` per signature, in document order;
- returns `Err` **only** for document-level failures — a parse error, a
  duplicate-ID conflict while building the ID map, or no `<Signature>` element
  at all (`Error::MissingElement`, mirroring `verify()`) — rather than an empty
  `Vec`;
- maps a *per-signature* structural or processing failure (missing
  `SignedInfo`, unsupported algorithm, malformed base64, unresolvable key, XSW
  position violation, etc.) to a `VerifyResult::Invalid` entry for that
  signature instead of propagating it. A `?` inside the loop would let one
  malformed signature short-circuit the whole call and hide a valid signature
  elsewhere, defeating the purpose of "verify every signature." Because errors
  become `Invalid`, the result is fail-safe — a caller collecting references
  only from `Valid` entries treats an unprocessable signature as not-verified;
- reports a mix of `Valid` and `Invalid` entries when some signatures verify
  and others do not — the caller **must** inspect each entry rather than
  assume uniform success.

It does **not** itself decide which signatures are "enough." Binding policy —
e.g. "the consumed Assertion's ID must appear in the verified references of
some `Valid` signature" — is the caller's responsibility, because it is
domain-specific (SAML SP vs. metadata vs. WS-Security).

## Implementation

```rust
pub fn verify_all(ctx: &DsigContext, xml: &str) -> Result<Vec<VerifyResult>, Error> {
    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;
    let id_map = build_verify_id_map(ctx, &doc)?;

    let sig_nodes = find_all_elements(&doc, ns::DSIG, ns::node::SIGNATURE);
    if sig_nodes.is_empty() {
        return Err(Error::MissingElement("Signature".into()));
    }

    let mut results = Vec::with_capacity(sig_nodes.len());
    for sig_node in sig_nodes {
        results.push(verify_signature_node(ctx, &doc, xml, sig_node, &id_map)?);
    }
    Ok(results)
}
```

- `verify()` is refactored to `find_element(...)` + `verify_signature_node(...)`;
  the large per-signature body moved verbatim into the shared helper.
- `find_all_elements` collects matching elements in document order, alongside
  the existing `find_element`.
- `build_verify_id_map` factors out the id-attribute seeding shared by both
  entry points.
- Re-exported as `bergshamra::verify_all` from the umbrella crate.

Each signature is verified independently against the same parsed document.
This is sound for enveloped signatures: verifying the Response signature
canonicalizes the Response subtree (its enveloped-signature transform removes
only the Response's own `<Signature>`), and verifying the Assertion signature
canonicalizes the Assertion subtree (removing only the Assertion's
`<Signature>`); the two do not interfere.

## Consequences

- A caller can confirm that a specific nested object (e.g. a SAML Assertion) is
  covered by its own valid signature even when that signature is not first in
  the document, enabling correct XML Signature Wrapping defences and policies
  such as SPID's "the Assertion must be signed."
- `verify_all` is strictly additive: existing `verify()` / `verify_enveloped`
  callers are unaffected.
- Cost scales with the number of signatures (each is fully verified). Documents
  are expected to carry a small, bounded number of signatures.
- A document with one valid and one invalid signature yields a mixed result
  vector; a caller that ignores the per-entry status could wrongly treat such a
  document as fully verified. The doc comment makes the per-entry contract
  explicit.

## Location

- `crates/bergshamra-dsig/src/verify.rs` — `verify_all`,
  `verify_signature_node`, `build_verify_id_map`, `find_all_elements`
- `crates/bergshamra/src/lib.rs` — `pub use ... verify_all`
