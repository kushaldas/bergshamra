# ADR-0007: Reject Raw Inline KeyInfo Keys When Trust Anchors Are Configured

**Date:** 2026-07-06
**Status:** Accepted
**Context:** XML-DSig verification when a caller allows inline `KeyInfo` keys
and also configures trusted certificates as trust anchors.

## Problem

XML-DSig allows a signed document to carry signing-key material in
`<ds:KeyInfo>`. Bergshamra supports two very different inline key shapes:

- certificate-backed keys, such as `<ds:X509Data><ds:X509Certificate>...`;
- raw keys, such as `<ds:KeyValue>` and
  `<dsig11:DEREncodedKeyValue>`.

Certificate-backed keys can be chained to configured trust anchors. Raw inline
keys cannot: they are just document-controlled public-key bytes with no
certificate chain, issuer, expiry, name constraints, or revocation context.

Before this decision, a permissive library context could both:

1. load trusted CA certificates into `DsigContext::keys_manager`; and
2. accept a raw inline `<KeyValue>` from the document.

That meant a caller could believe the configured trust anchors constrained the
signing key while verification actually succeeded with an attacker-controlled
raw key from the XML document. The signature was cryptographically valid, but
it was valid for the wrong trust decision.

This is distinct from ADR-0006. ADR-0006 binds an inline X.509 leaf certificate
to the key used for signature verification. This ADR covers raw inline key
material, where there is no certificate leaf to bind or validate.

## Decision

When trust anchors are configured, Bergshamra rejects raw inline `KeyInfo`
signing keys by default.

Concretely, during verification:

1. If the selected key came from inline `<KeyValue>` or
   `<DEREncodedKeyValue>`, it has an empty `x509_chain`.
2. If `DsigContext::keys_manager` contains trusted certificates, that raw key
   is rejected before signature verification is reported as valid.
3. Inline `<X509Data>` remains supported. It is accepted only when its selected
   leaf certificate chains to one of the configured anchors.

The enforcement lives in `bergshamra-dsig`, not only in the CLI, because the
library is the primary API surface for most deployments.

## Library Usage

For protocols with pre-established signing keys, use the secure constructor and
preload the expected keys:

```rust
use bergshamra_dsig::{context::DsigContext, verify};
use bergshamra_keys::{loader, KeysManager};

let mut keys = KeysManager::new();
let idp_key = loader::load_x509_cert_pem(idp_cert_pem.as_bytes())?;
keys.add_key(idp_key);

let ctx = DsigContext::new(keys);
let result = verify::verify(&ctx, xml)?;
```

`DsigContext::new` sets `trusted_keys_only = true`, so document-supplied
`<KeyValue>`, `<DEREncodedKeyValue>`, and `<X509Data>` are ignored.

For deployments that intentionally trust a CA and accept signer certificates
from `<X509Data>`, use permissive mode with trusted anchors and leave
`allow_raw_inline_keyinfo_with_trust_anchors` disabled:

```rust
use bergshamra_dsig::{context::DsigContext, verify};
use bergshamra_keys::KeysManager;

let mut keys = KeysManager::new();
let ca_der = std::fs::read("ca.der")?;
keys.add_trusted_cert(ca_der);

let ctx = DsigContext::new_permissive(keys)
    .with_enabled_key_data_x509(true);

let result = verify::verify(&ctx, xml)?;
```

In this configuration:

- inline `<X509Data>` can verify only if the certificate chain validates to the
  configured anchor;
- raw inline `<KeyValue>` and `<DEREncodedKeyValue>` fail because they cannot
  validate to any CA.

## Compatibility Escape Hatch

Some xmlsec interop fixtures intentionally combine trusted CA options with raw
inline `KeyValue` test signatures. Those fixtures are useful for compatibility
testing, but they do not represent a trust-anchor security policy.

Library callers that need that compatibility behavior must opt in explicitly:

```rust
let ctx = DsigContext::new_permissive(keys)
    .with_enabled_key_data_x509(true)
    .with_allow_raw_inline_keyinfo_with_trust_anchors(true);
```

This flag means: "even though trust anchors are configured, allow a raw inline
document-controlled key to satisfy signature verification." Do not enable it
for normal verification of untrusted XML. Prefer one of these safer patterns:

- `DsigContext::new(keys)` with preloaded expected keys for SAML,
  WS-Security, and similar profiles;
- `DsigContext::new_permissive(keys).with_enabled_key_data_x509(true)` with
  configured trust anchors when inline signer certificates are expected.

The CLI exposes the same compatibility behavior as
`bergshamra verify --x509-skip-strict-checks`, primarily for xmlsec test-suite
compatibility. Library users should use
the chained builder call
`.with_allow_raw_inline_keyinfo_with_trust_anchors(true)` only when they
knowingly need the same compatibility profile.

## Alternatives Considered

### Option A: Allow raw inline keys when trust anchors are present

Rejected.

- Preserves maximum XML-DSig permissiveness.
- Leaves callers with a misleading trust policy: anchors are configured, but a
  raw document-controlled key can bypass them.
- Makes the safe behavior depend on every library consumer remembering to set
  `trusted_keys_only`.

### Option B: Reject all inline KeyInfo when trust anchors are present

Rejected.

- Secure, but too broad.
- Breaks legitimate workflows that trust a CA and expect signer certificates in
  inline `<X509Data>`.
- Duplicates `trusted_keys_only`, which already exists for deployments that
  want no document-supplied keys at all.

### Option C: Reject only raw inline keys, keep inline X.509 chain validation

Accepted.

- Enforces the trust-anchor invariant at the library boundary.
- Preserves standard certificate-backed XML-DSig workflows.
- Keeps compatibility available through an explicit, documented opt-in.

## Consequences

### Positive

- A configured trust anchor now constrains every accepted inline signing key by
  default.
- Library users get the same trust-anchor protection as CLI users for raw
  inline key material.
- Certificate-backed `<X509Data>` remains usable for CA-based deployments.

### Negative

- Some compatibility fixtures that intentionally mix trusted CA options with raw
  `KeyValue` signatures need the explicit compatibility flag.
- `DsigContext` gains a new public field. Code constructing `DsigContext` with
  a struct literal must set
  `allow_raw_inline_keyinfo_with_trust_anchors` or switch to the constructor and
  builder methods.

### Neutral

- `DsigContext::new` remains the recommended default for SAML,
  WS-Security, and other known-key protocols.
- `DsigContext::new_permissive` without trusted anchors still accepts raw
  inline `KeyValue` signatures for self-contained XML-DSig documents.
- `--x509-skip-strict-checks` and the matching library builder are
  compatibility switches, not security hardening switches.

## Validation

Regression coverage was added for:

- raw inline `KeyValue` verification without trust anchors;
- rejection of raw inline `KeyValue` when a trust anchor is configured;
- explicit compatibility opt-in via a context built with
  `.with_allow_raw_inline_keyinfo_with_trust_anchors(true)`.

The original security reproducer is:

```bash
cargo run -q -p bergshamra -- verify \
  --trusted test-data/keys/cacert.pem \
  raw_keyvalue_signed.xml
```

After this change, that command fails with:

```text
raw inline KeyInfo key is not trusted when trust anchors are configured
```

The compatibility profile remains explicit:

```bash
cargo run -q -p bergshamra -- verify \
  --x509-skip-strict-checks \
  --trusted test-data/keys/cacert.pem \
  raw_keyvalue_signed.xml
```

## Location

- Library policy field and builder:
  `crates/bergshamra-dsig/src/context.rs`
- Raw inline key rejection:
  `crates/bergshamra-dsig/src/verify.rs`
- CLI compatibility mapping:
  `crates/bergshamra/src/main.rs`
