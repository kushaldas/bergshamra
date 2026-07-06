# ADR-0006: Bind the validated X.509 leaf to the signature-verification key

**Date:** 2026-07-01
**Status:** Accepted
**Context:** Trust-anchor enforcement for certificates carried inline in
`<KeyInfo><X509Data>`, and the relationship between the certificate that is
validated against the trust anchors and the certificate whose public key
verifies the signature.

## Problem

When a signed document carries its signer certificate(s) inline in
`<ds:X509Data>`, bergshamra does two independent things:

1. **Signature verification** uses a public key. For an inline X.509 key,
   `extract_x509_certificate` (`bergshamra-keys/src/keyinfo.rs`) picks the
   end-entity certificate with `find_leaf_cert()` and loads *its* public key
   into `Key::data`. `find_leaf_cert` is a heuristic (BasicConstraints +
   issuer/subject graph) and, when several end-entity certificates are present,
   returns `*candidates.last()` — i.e. **not necessarily the first certificate
   in document order**.

2. **Trust-chain validation** (`bergshamra-dsig/src/verify.rs`, added in
   ADR-0004's spirit and extended to fire whenever trust anchors are
   configured) validates `key.x509_chain[0]` against the anchor pool via
   `validate_cert_chain`.

The original `extract_x509_certificate` built `x509_chain` in **document
order**, so `x509_chain[0]` was "whatever `<X509Certificate>` appeared first",
while `Key::data` was the *heuristically selected* leaf. Those two can be
**different certificates**, and `validate_cert_chain` never compared the
validated leaf against `Key::data`.

### The bypass

An attacker fully controls the signed document, including `<X509Data>`. With
trust anchors configured (a caller who set `--trusted <CA>`), the attacker:

1. Places a **legitimate** certificate `C_legit` that chains to the trusted CA
   **first** in `<X509Data>` (any certificate they can obtain under that CA).
2. Places their **own** certificate `C_attack` (self-issued, private key held
   by the attacker) **second**.
3. Signs the document with `C_attack`'s private key.

Then:

- `find_leaf_cert([C_legit, C_attack])` returns the last candidate → `C_attack`
  → the signature verifies (attacker holds the key).
- `x509_chain[0] == C_legit` → `validate_cert_chain` succeeds (it chains to the
  anchor and is time-valid).

Both checks pass, so the signature is reported valid/trusted even though it was
produced by `C_attack`, which chains to **no** configured anchor. This is a
key/leaf **confusion** trust bypass: the certificate that is *trusted* is not
the certificate that *signed*.

The single-certificate case (the overwhelmingly common one) was never affected,
because there `find_leaf_cert` and index 0 coincide. The xmlsec interop corpus
uses only honest, correctly ordered chains, so it did not exercise the gap.

## Decision

**`extract_x509_certificate` places the selected leaf at `x509_chain[0]`.** The
certificate whose public key becomes `Key::data` is guaranteed to be the same
certificate that downstream chain validation treats as the leaf:

```rust
let leaf_idx = find_leaf_cert(&parsed_certs);
let leaf = &parsed_certs[leaf_idx];
let mut key = crate::loader::load_x509_cert_der(&leaf.der).ok()?;

// Leaf first; the rest of the certs follow (order otherwise preserved).
let mut chain = Vec::with_capacity(parsed_certs.len());
chain.push(leaf.der.clone());
for (i, c) in parsed_certs.iter().enumerate() {
    if i != leaf_idx {
        chain.push(c.der.clone());
    }
}
key.x509_chain = chain;
```

This establishes the invariant that the rest of the system already assumed
(the comment "The first cert in x509_chain is the leaf" in `verify.rs`):

> **`x509_chain[0]` is the certificate whose public key is `Key::data`.**

With the invariant restored, the two decisions are bound to one certificate:

- `to_signing_key()` verifies the signature with the leaf's key.
- `validate_cert_chain(x509_chain[0], …)` validates that **same** leaf to an
  anchor.

The attack collapses: whichever certificate becomes the leaf, *both* the
signature check and the chain check apply to it. If the attacker makes their
own cert the leaf, chain validation fails (it does not chain to the anchor); if
they make the legit cert the leaf, signature verification fails (they do not
hold its key).

## Alternatives considered

- **Match by key in `verify.rs`:** choose `leaf_der` as the `x509_chain` entry
  whose SPKI equals `Key::data`. Equivalent security, but pushes the invariant
  into the consumer and must be repeated by every future consumer of
  `x509_chain`. Rejected in favour of fixing it once at the source.
- **Assert post-validation** that the validated leaf's key equals the signing
  key. A belt-and-braces check, but redundant once the ordering invariant
  holds. Could be added later as defence in depth.

## Consequences

- Inline multi-certificate `<X509Data>` is now safe against leaf/index-0
  confusion under trust-anchor enforcement.
- Honest chains are unaffected: single-cert `KeyInfo` is unchanged, and
  correctly ordered multi-cert chains still validate (the leaf simply moves to,
  or stays at, index 0). The xmlsec DSig suite remains at 447 OK / 0 failed.
- The rule is not limited to trust-anchor mode: any consumer that treats
  `x509_chain[0]` as the leaf (e.g. `enabled_key_data_x509`, `verify_keys`) now
  gets a leaf that matches the signature key.

## Scope note

This ADR concerns certificate-bearing `KeyInfo`. A document that embeds a raw
`<KeyValue>` (no certificate) has an empty `x509_chain` and is therefore not
subject to anchor chaining at all; callers who must reject inline keys entirely
should use the secure-by-default `DsigContext::new()` (`trusted_keys_only`),
which ignores inline key material and only trusts pre-configured keys.

## Testing

- `bergshamra-keys` unit tests
  (`keyinfo::tests::test_x509data_places_selected_leaf_first`,
  `test_x509data_single_cert_is_leaf`): with the end-entity leaf placed
  **second** in an adversarially ordered `<X509Data>`, `x509_chain[0]` is the
  leaf; the single-cert case is unchanged.
- xmlsec interop DSig suite: unchanged (447 OK / 0 failed), confirming honest
  multi-cert chains still validate.
