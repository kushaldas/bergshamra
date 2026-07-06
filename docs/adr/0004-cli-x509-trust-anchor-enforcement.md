# ADR-0004: CLI-side X.509 Trust Anchor Enforcement for Inline KeyInfo Certificates

**Date:** 2026-06-06
**Status:** Accepted
**Context:** `bergshamra verify` handling of inline `<X509Certificate>` keys when callers also provide `--trusted` CA certificates

## Problem

The `bergshamra-dsig` library historically treated inline X.509 data and
preloaded trust anchors as separate concerns:

- Inline `<KeyInfo><X509Data><X509Certificate>` was accepted for signature
  verification when permissive DSig behavior was enabled.
- Certificate-chain validation only ran when the caller explicitly enabled
  `enabled_key_data_x509` or `verify_keys`.
- Supplying trusted roots alone did not force inline certificate validation.

For the CLI, this created a surprising and unsafe behavior:

```bash
bergshamra verify --trusted ca.pem signed.xml
```

The caller reasonably expects `ca.pem` to constrain trust for any inline
certificate used during verification. Before this change, that command loaded
the trust anchor but could still accept the inline public key without proving
that the embedded certificate chained to the trusted root.

The first attempted fix changed the DSig library itself so that the mere
presence of trusted roots triggered validation for any inline X.509 key.
That did address the CLI gap, but it also changed library-wide semantics and
broke the xmlsec interop harness. The failures fell into two categories:

1. xmlsec compatibility mode (`--X509-skip-strict-checks`) was parsed by the
   shim but not actually forwarded to the CLI, so tests that intentionally
   skip strict X.509 processing started failing.
2. Some legacy interop vectors rely on certificate chains and algorithms that
   the stricter library-wide path rejects, including DSA-signed certificate
   chains and inline chain-building cases that are out of scope for the CLI
   release blocker.

The release blocker was specifically the CLI behavior, not the public library
API.

## Decision

Implement trust-anchor enforcement in the CLI layer, not in the DSig library.

Concretely:

1. Keep `bergshamra-dsig` verification semantics unchanged.
2. In `bergshamra verify`, if the caller supplies `--trusted` and does not
   also request `--x509-skip-strict-checks`, force the existing inline X.509
   validation path on by setting `ctx.enabled_key_data_x509 = true`.
3. Expose a real CLI flag `--x509-skip-strict-checks` so xmlsec compatibility
   mode can explicitly opt out of that stricter behavior.
4. Forward the xmlsec shim's parsed `--X509-skip-strict-checks` flag to the
   CLI so interop tests preserve their previous behavior.

This means the CLI becomes safer by default for the common case of:

```bash
bergshamra verify --trusted ca.pem signed.xml
```

while embedders using `bergshamra-dsig` directly keep control over whether
inline X.509 trust validation should be enabled.

## Alternatives Considered

### Option A: Enforce trust anchors in the DSig library globally

Rejected.

- Fixes the CLI surprise.
- Changes semantics for all library users, including callers that use
  permissive mode intentionally.
- Regressed `just test-dsig` by enforcing validation in xmlsec interop paths
  that explicitly expect looser behavior.

### Option B: Require callers to pass `--enabled-key-data x509`

Rejected.

- Technically workable, but the CLI already has enough information to infer
  intent from `--trusted`.
- Leaves a footgun in the main verification workflow.
- Does not solve the mismatch between the shim's parsed
  `--X509-skip-strict-checks` flag and the actual CLI surface.

### Option C: CLI-side enforcement with explicit opt-out (chosen)

Accepted.

- Fixes the release blocker in the exact surface where it matters.
- Preserves existing library behavior.
- Keeps xmlsec compatibility through an explicit skip-strict flag.
- Minimizes blast radius while still making normal CLI verification safer.

## Consequences

### Positive

- `bergshamra verify --trusted ...` now behaves in line with operator
  expectations: trusted roots constrain inline X.509 verification.
- The change is scoped to the CLI and does not silently alter the public
  `bergshamra-dsig` API contract.
- xmlsec interop remains stable once `--x509-skip-strict-checks` is forwarded
  correctly.

### Negative

- CLI and library behavior are intentionally not identical in this area.
  Library embedders must still opt into inline X.509 validation themselves.
- The stricter CLI behavior can still be bypassed intentionally via
  `--x509-skip-strict-checks`, which exists for compatibility rather than
  security.

### Neutral

- Existing callers already passing `--enabled-key-data x509` see no behavior
  change.
- XML Encryption behavior is unaffected; this decision only concerns DSig
  verification.

## Validation

The CLI-scoped implementation was validated with:

- `cargo test -p bergshamra --bin bergshamra`
- `cargo test -p bergshamra-dsig --lib`
- `just test-dsig`

Result after the final CLI-only fix:

- `TOTAL OK: 447`
- `TOTAL FAILED: 0`
- `TOTAL SKIPPED: 3`

## Location

- CLI policy wiring: `crates/bergshamra/src/main.rs`
- xmlsec compatibility forwarding: `tests/xmlsec1-shim.py`
- DSig verification path left intentionally unchanged: `crates/bergshamra-dsig/src/verify.rs`