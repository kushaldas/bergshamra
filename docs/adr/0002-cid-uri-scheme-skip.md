# ADR-0002: Skip `cid:` URI References in XML-DSig Processing

**Date:** 2026-02-22
**Status:** Accepted
**Context:** Handling of `cid:` URI scheme references in XML Digital Signature verification and signing

## Problem

XML Digital Signatures may contain `<Reference>` elements with `cid:` URIs
(Content-ID), as defined in [RFC 2392](https://www.rfc-editor.org/rfc/rfc2392).
These references point to MIME body parts in multipart messages and are common
in WS-Security (OASIS WSS) where SOAP messages carry binary attachments
(e.g., `cid:attachment-1@example.com`).

Example from a WS-Security signed SOAP message:

```xml
<ds:SignedInfo>
  <ds:Reference URI="">
    <!-- references the SOAP Body (normal in-document ref) -->
  </ds:Reference>
  <ds:Reference URI="cid:attachment-1@example.com">
    <!-- references a MIME attachment outside the XML document -->
    <ds:Transforms>
      <ds:Transform Algorithm="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform"/>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>abc123...</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>
```

The `cid:` reference poses three problems for an XML-only library:

1. **The referenced content is not in the XML document.** It resides in a
   separate MIME part, so the library has no data to hash.
2. **WS-Security attachment transforms** (e.g.,
   `Attachment-Content-Signature-Transform`) are domain-specific and not
   part of the W3C XML-DSig specification.
3. **The digest is pre-computed by the signer.** The library cannot
   independently verify it without access to the raw MIME part bytes.

## Options Considered

### Option A: Fail on `cid:` URIs (strict)

Return an error when a `<Reference URI="cid:...">` is encountered, since
the library cannot resolve the content.

- **Pro:** No silent skipping; caller is forced to handle it.
- **Con:** Breaks verification of any signed document that includes `cid:`
  references alongside in-document references. The caller cannot remove the
  `cid:` references without invalidating the signature (they are covered by
  `<SignedInfo>`, which is itself signed). This makes the library unusable
  for WS-Security SOAP messages with attachments.

### Option B: Skip `cid:` URIs silently (chosen)

When iterating `<Reference>` elements during verification or signing, skip
any reference whose `URI` attribute starts with `cid:`. The library
verifies all in-document references normally. The caller is responsible for
verifying attachment digests out-of-band.

- **Pro:** Allows verification of the XML-internal portions of a signature
  without requiring access to MIME infrastructure. Matches the behavior of
  Go signedxml, which uses the same approach.
- **Con:** The caller must separately verify `cid:` reference digests if
  full signature coverage is required.

### Option C: Pluggable URI resolver

Allow callers to register a callback that resolves arbitrary URI schemes,
returning raw bytes for digest computation.

- **Pro:** Most flexible; could support `cid:`, `http:`, or any scheme.
- **Con:** Significant API complexity for a niche use case. The caller
  would still need to supply the MIME bytes, making this equivalent to
  Option B plus extra plumbing. Can be added later if needed.

## Decision

**Option B: Skip `cid:` references.** During both signature verification
and signing (digest computation), any `<Reference>` whose `URI` attribute
starts with `"cid:"` is skipped entirely — no transform processing, no
digest computation, no digest comparison. The reference is simply not
evaluated.

The `SignedInfo` canonicalization and signature verification still cover the
full `<SignedInfo>` element, including the skipped `<Reference>` elements.
This means the `cid:` reference's digest value, transforms, and URI are
still integrity-protected by the signature over `<SignedInfo>`. An attacker
cannot modify the expected digest of a `cid:` attachment without
invalidating the `<SignedInfo>` signature.

## Implementation

The skip is a prefix check at the top of the reference iteration loop:

```rust
// In verify_reference() / sign reference loop:
let uri = /* extract URI attribute */;
if uri.starts_with("cid:") {
    // MIME attachment reference — cannot resolve from XML document.
    // Caller must verify attachment digests separately.
    // See ADR-0002.
    continue;
}
```

Applied in two locations:
- `crates/bergshamra-dsig/src/verify.rs` — reference verification loop
- `crates/bergshamra-dsig/src/sign.rs` — reference digest computation loop

## Precedent

- **Go signedxml** (`validator.go:177-182`, `signer.go:112-117`): Skips
  `cid:` references with `if strings.HasPrefix(refUri, "cid:") { continue }`.
- **Apache Santuario** (Java): Supports `cid:` via a pluggable
  `ResourceResolverSpi`, but the default resolver does not handle `cid:`.
- **xmlsec1** (C): Does not handle `cid:` URIs; returns an error if
  encountered.

## Consequences

- Documents containing `cid:` references alongside in-document references
  can now be verified (the in-document references are checked, `cid:`
  references are skipped).
- Documents where **all** references are `cid:` will have their
  `<SignedInfo>` signature verified but no individual reference digests
  checked. This is a weaker guarantee — the caller should be aware.
- The skip is silent (no warning/error). This is intentional: the `cid:`
  references are expected in WS-Security, and logging on every occurrence
  would be noisy.
- Option C (pluggable resolver) remains available as a future enhancement
  if callers need full `cid:` digest verification within the library.

## Location

- Verification: `crates/bergshamra-dsig/src/verify.rs` — `verify()` reference loop
- Signing: `crates/bergshamra-dsig/src/sign.rs` — `sign()` reference loop
