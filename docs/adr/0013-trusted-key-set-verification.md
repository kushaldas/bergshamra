# ADR-0013: Verify Against Every Trusted Key in the KeysManager

**Date:** 2026-10-28
**Status:** Accepted
**Context:** XML-DSig verification with `trusted_keys_only = true` when the
`KeysManager` holds more than one key for the same signer, most commonly
during certificate rollover.

## Problem

eIDAS national metadata, SAML federation metadata and similar signed feeds are
verified against signing certificates that the verifier configured in advance.
Publishers roll those certificates on their own schedule. For a rollover to be
seamless, the verifier loads both the current and the next certificate before
the publisher switches, and accepts a document signed with either one.

Before this decision, `trusted_keys_only` verification used exactly one key:

1. a manager key whose name matched `<KeyName>`;
2. otherwise a manager key whose certificate serial matched
   `<X509IssuerSerial>`;
3. otherwise `KeysManager::first_key()`.

eIDAS metadata usually carries the signer certificate as
`<X509Data>/<X509Certificate>`, which step 1 and step 2 do not inspect. Every
such document therefore fell through to the first key. With the old
certificate loaded first, a document signed with the new certificate failed to
verify, and the reverse after reordering. Aggregators such as pyFF had to work
around this by verifying repeatedly with one single-key context per
certificate.

## Decision

With `trusted_keys_only = true`, a signature is valid when **any** key in the
`KeysManager` that is compatible with the `SignatureMethod` verifies it.

Concretely, after the reference digests and `<SignedInfo>` canonicalization
succeed:

1. **Candidates.** Every key in the manager, each once
   (`bergshamra_keys::keyinfo::rank_trusted_keys`). Keys embedded in the
   document (`<KeyValue>`, `<DEREncodedKeyValue>`, `<X509Certificate>`,
   `<RetrievalMethod>`, `<EncryptedKey>`) are never candidates.
2. **Order.** `<KeyInfo>` hints only move trusted keys to the front: a
   `<KeyName>` match, then a key whose leaf certificate is byte-identical to an
   `<X509Certificate>` in the document, then an `<X509IssuerSerial>` serial
   match. All other keys follow in insertion order. A hint that matches
   nothing is ignored.
3. **Compatibility.** Keys whose type cannot verify the declared
   `SignatureMethod` are dropped
   (`bergshamra_crypto::sign::key_algorithm_matches_signature_uri`): RSA keys
   for RSA PKCS#1 v1.5 / PSS, EC keys for ECDSA, Ed25519 for EdDSA, HMAC
   secrets for HMAC, and the exact ML-DSA / SLH-DSA parameter set for
   post-quantum methods. EC curves are left to the provider. If no candidate
   remains, verification fails with `Error::Key("no trusted key in the manager
   is compatible with SignatureMethod …")`.
4. **Per-key policy.** Each candidate goes through the unchanged X.509 policy
   on its own: when trust anchors are configured or `verify_keys` is set, its
   certificate chain, validity period and CRLs are checked before its
   signature check. A candidate rejected by that policy is skipped, not fatal.
5. **Result.** The first candidate that verifies wins, and
   `VerifyResult::Valid.key_info` reports that key's name and certificate
   chain, so callers can log which certificate signed the document.
   Otherwise:
   - if every candidate was rejected by the X.509 policy, the first rejection
     is returned as `Err`, as the single-key path did;
   - with one candidate, the reason stays
     `"signature value verification failed"`;
   - with several, the reason states how many trusted keys were tried and how
     many were rejected before the signature check.

`KeysManager::add_keys` adds several keys in one call; it is a convenience over
`add_key` and has no extra semantics.

The permissive path (`trusted_keys_only = false`) and the HSM verifier path are
unchanged: they still select one key.

## Why This Is Safe

### Trust is not widened

The set of keys that can make a signature valid is still exactly the set the
caller put in the `KeysManager`. Before this change a document could already
select any of those keys by naming it in `<KeyName>`, or by an
`<X509IssuerSerial>` serial. A `KeysManager` used with `trusted_keys_only` has
therefore always meant "documents signed by any of these keys are accepted".
Trying all of them changes which trusted key gets checked, not which keys are
trusted.

The consequence callers must know, now stated in the documentation, is that a
`KeysManager` is one trust set. Keys for different signers that must not vouch
for each other (two IdPs, two countries) belong in separate managers and
separate `DsigContext`s. That was already true because of `<KeyName>`.

### Document-supplied keys stay out

`<KeyInfo>` is attacker-controlled. It may only reorder trusted keys. An
inline `<X509Certificate>` is compared byte-for-byte with trusted
certificates; it is never parsed into a verification key in this mode. A
regression test signs with a key that is not loaded, embeds its certificate,
and checks that verification fails.

### No algorithm confusion

Candidates are filtered by key family before any verification is attempted,
and the provider still rejects a key/algorithm mismatch. An HMAC
`SignatureMethod` can only be checked against HMAC secrets that the caller
loaded, never against public-key bytes.

### X.509 policy per key

Each candidate is validated independently. During a rollover the expired old
certificate fails its own chain check and the new certificate is tried next;
an expired certificate never verifies a document even though a valid one is
loaded alongside it.

### Bounded work

Reference digests and `<SignedInfo>` canonicalization are computed once,
before the candidate loop, so the size of the document does not multiply. The
extra cost is at most one public-key signature check, plus one chain
validation when anchors are configured, per compatible key in the manager.
That count is chosen by the operator, not by the document. A typical rollover
holds two keys.

### Failure reporting does not leak

All candidates are public keys or caller-owned secrets. The failure reason
reports counts only, not which key came closest, and verification of public
keys has no secret to leak through timing.

## Alternatives Considered

### Option A: Keep single-key selection, document "load the right key first"

Rejected. The verifier cannot know which certificate the publisher will use
next, which is the point of a rollover window. Callers would keep verifying
once per certificate, repeating digest and canonicalization work.

### Option B: Use `<X509Certificate>` from `<KeyInfo>` to pick one trusted key

Rejected as the only mechanism. It fixes documents that carry their
certificate, but not documents with no `<KeyInfo>`, a `<KeyName>` that does not
match the verifier's naming, or a certificate re-issued with the same key. It
is kept as an ordering hint so the usual case verifies on the first try.

### Option C: Make multi-key verification an opt-in flag

Rejected. The old behavior, "verify with whichever key happens to be first",
was not a security property anyone could rely on: `<KeyName>` already let a
document choose among the trusted keys. A flag would leave the surprising
failure in place by default and add another policy knob to `DsigContext`.

### Option D: Accept a list of keys in `add_key`

Rejected for the Rust API. `add_keys(impl IntoIterator<Item = Key>)` is
clearer and keeps `add_key` monomorphic. The Python bindings expose the same
name.

## Consequences

### Positive

- Certificate rollover works by loading the old and new certificates into one
  `KeysManager`.
- Managers that also hold non-signing keys (AES, 3DES, X25519) no longer fail
  when such a key happens to be first.
- `VerifyResult::Valid.key_info` identifies the certificate that verified.

### Negative

- A document that verifies with none of the keys costs one signature check per
  compatible key instead of one in total.
- The failure reason for several candidates differs from the single-key
  reason; code that matched the exact string sees a new message. The
  single-candidate message is unchanged.
- The CLI loads each `--trusted` CA certificate as a key as well as an anchor,
  so with `--trusted-keys-only` the CA key is a candidate too. A document
  could already reach it through an `<X509IssuerSerial>` hint; prefer `--cert`
  for signer certificates and keep CAs that should not sign documents
  directly out of the manager in library code.
- When the `SignatureMethod` is unsupported, `Error::UnsupportedAlgorithm` is
  now reported before key resolution errors such as an empty manager. Both
  are failures.

### Neutral

- With one key in the manager, the observable behavior is unchanged except
  that an incompatible key type now reports the compatibility error instead
  of a provider error.
- The permissive and HSM paths are unchanged.

## Validation

`crates/bergshamra-dsig/tests/trusted_key_set.rs` signs metadata-shaped
documents and covers:

- the signer loaded second, with no `<KeyInfo>`, with its certificate inline,
  and with a `<KeyName>` naming the other trusted key;
- an untrusted signer whose certificate is embedded in the document;
- EC and HMAC keys skipped for an RSA signature, and an ECDSA signature found
  after RSA keys;
- no compatible key, and an empty manager;
- rollover under a trust anchor: either certificate in either order during
  the overlap, the expired old certificate listed first with the document
  signed by the new one, a document signed with the expired certificate, and
  an expired sole key keeping its chain error;
- an anchor that issued none of the trusted keys;
- a tampered document failing before any key is tried.

Tests without certificate-chain validation use the xmlsec keys in
`test-data/keys`. Those chain through a SHA-1 intermediate with a 512-bit RSA
key, which AWS-LC and the non-legacy policy reject, so the anchored tests use
a dedicated RSA-2048 / SHA-256 chain in
`crates/bergshamra-dsig/tests/data/rollover/` (regenerate with its
`generate.sh`). They pin `DsigContext::verification_time` to a point inside
both certificates' validity, or after only the old one expired, so they do not
depend on the wall clock.

CI runs this test target for the default, RustCrypto and AWS-LC provider
sets. Nine of the original fifteen tests fail on the previous single-key
implementation. Unit tests cover `rank_trusted_keys` ordering and
deduplication, `KeysManager::add_keys`, and
`key_algorithm_matches_signature_uri`.

## Location

- Candidate loop and per-key check:
  `crates/bergshamra-dsig/src/verify.rs` (`verify_with_trusted_keys`,
  `check_signature_value`)
- Candidate ordering: `crates/bergshamra-keys/src/keyinfo.rs`
  (`rank_trusted_keys`)
- Key/algorithm compatibility: `crates/bergshamra-crypto/src/sign.rs`
  (`key_algorithm_matches_signature_uri`)
- Bulk insertion: `crates/bergshamra-keys/src/manager.rs` (`add_keys`)
