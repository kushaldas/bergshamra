# ADR 0003 — Choice of CSPRNG for signing paths

**Status:** Accepted
**Date:** 2026-04-23
**Deciders:** Kushal Das
**Supersedes:** —
**Related:** sibling ADR in `kryptering/docs/adr/0001-rng-choice.md`

---

## Update (2026-11-09)

Document signing now delegates to Kryptering. With Kryptering 0.7.1 and RSA
0.10, RSA uses rand_core 0.10, as does the ML-DSA provider path. Bergshamra's
RSA test and benchmark key generation uses `getrandom::SysRng` as well.
The historical split described below is no longer required for RSA;
rand 0.8 remains for the separate DSA/Ed25519/X25519 import/test stack.

## Context

`bergshamra-crypto` contains two randomized signing paths:

1. **ML-DSA** (`crates/bergshamra-crypto/src/sign.rs::pq_ml_dsa_sign`) — calls
   `ml_dsa::ExpandedSigningKey::sign_randomized(rng: &mut impl TryCryptoRng)`
   from `ml-dsa 0.1.0-rc.8`, built on **`rand_core 0.10`**.
2. **RSA-PSS** (`crates/bergshamra-crypto/src/sign.rs::RsaPss::sign`) — calls
   `rsa::pss::SigningKey::sign_with_rng(rng: &mut impl CryptoRngCore)` from
   `signature 2.2.0` (via `rsa 0.9`), built on **`rand_core 0.6`**.

Three CSPRNGs are available in our dependency graph:

| RNG | Crate | rand_core | Nature |
|---|---|---|---|
| `getrandom::SysRng` | `getrandom 0.4` (w/ `sys_rng`) | 0.10 (fallible `TryCryptoRng`) | zero-sized syscall wrapper |
| `rand::rngs::OsRng` | `rand 0.8` | 0.6 (infallible `CryptoRngCore`) | zero-sized syscall wrapper |
| `rand::thread_rng()` | `rand 0.8` | 0.6 (infallible `CryptoRngCore`) | ChaCha12 reseeded from OsRng, thread-local state |

`SysRng` and `OsRng` are **semantically identical** — both issue one OS
entropy syscall (`getrandom(2)` / `getentropy(2)` / `BCryptGenRandom` /
`SecRandomCopyBytes`) per draw, hold no user-space state, and are
fork-safe. They differ only in which `rand_core` major version their
traits come from.

Historically both signing paths used `rand::thread_rng()` (RSA-PSS) and
`sk.sign_deterministic(...)` (ML-DSA — no RNG at all). This ADR records the
switch, which landed together with the `ml-dsa 0.1.0-rc.7 → 0.1.0-rc.8`
bump.

---

## Decision

**Prefer `getrandom::SysRng` for new randomized-signing code. Where an
upstream API requires `rand_core 0.6` traits that `SysRng` does not
satisfy, use `rand::rngs::OsRng`. Never use `rand::thread_rng()` for
cryptographic signing paths.**

Concretely in this workspace:

| Call site | RNG | Reason |
|---|---|---|
| `pq_ml_dsa_sign` (`sign.rs:1092`) | `&mut getrandom::SysRng` | `sign_randomized` takes `TryCryptoRng` (rand_core 0.10) — direct fit |
| `RsaPss::sign` (`sign.rs:455`) | `let mut rng = rand::rngs::OsRng;` | `sign_with_rng` requires `CryptoRngCore` (rand_core 0.6); `SysRng` does not implement that trait |
| Key-agreement test fixtures (`keyagreement.rs`) | `rand::thread_rng()` | test-only; not security-sensitive, out of ADR scope |
| ECDSA / Ed25519 key generation (`sign.rs` tests) | `rand::rngs::OsRng` | test-only; already conformant |

---

## Rationale

Bergshamra is a library consumed by XML-signing and XML-encryption
callers, many of which embed us in long-lived server processes that
fork (CGI, Unicorn-style workers, systemd socket-activated daemons).
Our ranking of RNG properties:

1. **Correctness under fork.** `thread_rng()` keeps keyed ChaCha state in
   thread-local storage. After `fork(2)` both parent and child share that
   state until the next reseed — historically a recurring footgun
   (OpenSSL CVE-2010-4252; Wireguard-Go wg-fork bug). `SysRng` / `OsRng`
   hold no state, so fork cannot produce correlated output.

2. **Failure visibility.** `SysRng` implements the fallible
   `TryCryptoRng`: OS RNG exhaustion (seccomp filter blocking
   `getrandom(2)`, chroot without `/dev/urandom`, early-boot entropy
   starvation on embedded platforms) propagates as `Result<_, ml_dsa::Error>`
   and is converted to `bergshamra_crypto::Error::Crypto` by the
   existing `?` plumbing. Earlier drafts used `UnwrapErr(SysRng)` which
   collapsed RNG errors into a panic; that was rejected because it
   surprises callers running under `catch_unwind`, async runtimes, or
   structured logging.

   `rand_core 0.6`'s `CryptoRngCore` is infallible — `OsRng` panics on
   OS RNG failure. We accept this on the RSA-PSS path because we cannot
   bridge `rand_core` versions without code duplication, and
   fail-closed-by-panic is still correct for cryptographic signing
   (better than signing with predictable output).

3. **Memory hygiene.** `SysRng` and `OsRng` are unit structs — no secret
   material in process memory that could leak via core dump, swap,
   `ptrace(2)`, or `/proc/<pid>/mem`. `thread_rng()` carries a live
   ChaCha key not wrapped in `Zeroize`.

4. **Dependency minimality.** Both `getrandom` and `rand` are already in
   the workspace graph; no new crates.

5. **Performance.** The per-sign syscall cost (~μs) is noise next to
   ML-DSA / RSA-PSS arithmetic (~ms). `thread_rng()`'s speed advantage
   matters only in hot loops drawing thousands of random values per
   second — no such hot loop exists in bergshamra.

---

## Why ML-DSA moved from deterministic to randomized

FIPS 204 §3.4 permits both deterministic and "hedged" ML-DSA. The
deterministic mode is known to be vulnerable to fault-injection attacks
([Bruinderink & Pessl, 2018](https://eprint.iacr.org/2018/321);
[Ravi et al., 2019–2023](https://eprint.iacr.org/2023/1614)): an
attacker who can glitch the rejection-sampling loop on a deterministic
signer recovers bits of the secret `s1` / `s2` vectors by diffing
faulted and clean signatures on the same message.

Randomized signing absorbs a fresh 256-bit `rnd` into the challenge
hash, which defeats the "sign twice, diff outputs" fault strategy.
NIST's own FIPS 204 guidance (§3.4 note 2) recommends randomized
signing in any deployment that may run in a fault-capable environment —
which covers any library shipped as a cross-environment dependency.

Bergshamra is such a library: we have no control over whether a caller
runs on smartcards, mobile SoCs, or shared-tenant servers susceptible
to Rowhammer-class neighbours. Randomized ML-DSA is therefore the
correct default.

### Compatibility note

Signatures produced by the old deterministic code path continue to
verify — the on-wire signature format and the verify path are unchanged
between the two modes. Downstream callers will only notice that
`Signer::sign(data)` is no longer bit-for-bit reproducible across
calls. Any golden-file test that pinned ML-DSA output is now invalid
and must be rewritten to re-verify the signature rather than compare
bytes.

---

## Why the split across two concrete RNG types is acceptable

After this ADR, `sign.rs` contains both `getrandom::SysRng` (ML-DSA) and
`rand::rngs::OsRng` (RSA-PSS). This is a pragmatic response to the
current state of the RustCrypto trait ecosystem:

- `signature 2.2.0` (consumed by `rsa 0.9`, `dsa 0.6`, `ed25519-dalek 2.x`)
  defines `RandomizedSigner::sign_with_rng<R: CryptoRngCore>`, where
  `CryptoRngCore` comes from `rand_core 0.6`.
- `ml-dsa 0.1.0-rc.8` is published against the newer
  `rand_core 0.10 TryCryptoRng`.
- There is no automatic bridge between the two `rand_core` major
  versions.

We considered writing a shim that implements `rand_core 0.6`'s `RngCore`
on top of `getrandom` directly; we rejected that option because (a) it
duplicates code that already exists in `rand::rngs::OsRng`, (b) it
requires us to maintain a trait adapter, and (c) `OsRng`'s behaviour is
bit-for-bit equivalent to what the shim would implement.

When `signature` and its downstream crates migrate to `rand_core 0.10`
(tracked upstream — see
[RustCrypto/traits#1596](https://github.com/RustCrypto/traits/issues/1596)),
this ADR should be revisited and the RSA-PSS path moved to `SysRng` for
uniformity.

---

## Consequences

**Positive**
- OS RNG failures in ML-DSA surface as
  `Error::Crypto("ML-DSA sign failed: …")` — no panic — allowing callers
  to handle RNG exhaustion programmatically.
- Both signing paths now share the "syscall-per-draw, no user-space
  state" property; fork-safety is no longer hash-rate-dependent on
  `thread_rng()` reseeding.
- ML-DSA is fault-injection-resistant by default.
- No new crates in the workspace graph (the `ml-dsa 0.1.0-rc.8` bump
  pulls `getrandom 0.4`'s WASI transitive set regardless, so the
  incremental cost is zero).

**Negative**
- Per-sign latency on RSA-PSS grows by one `getrandom(2)` syscall
  relative to the old `thread_rng()` path — submicrosecond vs
  millisecond arithmetic, practically unmeasurable.
- Two concrete RNG types live in `sign.rs` until upstream trait
  alignment catches up. Each call site carries an inline comment
  pointing back to this ADR.
- Any downstream test fixture that pinned ML-DSA signature bytes will
  fail non-deterministically; those tests must re-verify instead of
  byte-comparing.

**Neutral**
- Tests continue to use `rand::rngs::OsRng` / `rand::thread_rng()`;
  test semantics unchanged.

---

## Alternatives considered

### A. Keep `rand::thread_rng()` on RSA-PSS
Rejected: user-space RNG state is a fork-safety footgun that we avoid
trivially; the speed advantage does not apply to signing.

### B. Keep ML-DSA deterministic
Rejected: FIPS 204 §3.4 guidance, plus the fault-injection literature
cited above. Defense-in-depth against an attack class we cannot
otherwise mitigate in a library context.

### C. Write a `rand_core 0.6` adapter over `getrandom` directly
Rejected: duplicates `OsRng`; no functional benefit.

### D. Use `rand_chacha::ChaCha20Rng::from_entropy()` per call
Rejected: creates ChaCha state whose zeroization story is upstream and
not under our control; no advantage over `OsRng` for a single 32-byte
draw.

### E. Accept `impl RngCore` in the public `SignatureAlgorithm::sign` API
Rejected: pushes the RNG-choice footgun to every caller. The crate is
already opinionated about cryptographic primitives (we reject SHA-1
MGF1 in OAEP, block finite-field DH outside `legacy-algorithms`, etc.);
RNG choice fits the same pattern.

---

## References

- FIPS 204 §3.4 — ML-DSA signing (hedged vs deterministic rationale)
- Bruinderink & Pessl, *Differential Fault Attacks on Deterministic Lattice Signatures*, CHES 2018
  — <https://eprint.iacr.org/2018/321>
- Ravi et al., *On the Masking-Friendly Designs for Post-Quantum Cryptography*, 2023
  — <https://eprint.iacr.org/2023/1614>
- `getrandom 0.4` — `SysRng`
- `rand_core 0.10` — `TryCryptoRng`, `UnwrapErr`
- `rand_core 0.6` — `CryptoRngCore`
- RustCrypto trait-migration tracking: <https://github.com/RustCrypto/traits/issues/1596>
- Sibling ADR in the `kryptering` crate: `kryptering/docs/adr/0001-rng-choice.md`
