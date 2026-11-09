# Dependency ecosystem status

Last reviewed: 2026-11-09. The workspace continues to require Rust 1.88.

## Updates applied

| Direct dependency | Previous locked version | Updated version |
| --- | --- | --- |
| uppsala | 0.12.0 | 0.12.1 |
| ml-dsa | 0.1.1 | 0.1.2 |
| tsp-ltv | 0.6.0 | 0.6.1 |
| base64 | 0.22.1 | 0.23.1 |
| yasna | 0.5.2 | 0.6.0 |
| num-bigint-dig | 0.8.6 | 0.9.1 |
| criterion | 0.5.1 | 0.8.2 |
| pem-rfc7468 | 0.7.0 | 1.0.0 |

The new major versions above do not exchange crypto traits with the retained
RSA/DSA stack. Bergshamra uses num-bigint-dig for its own finite-field DH
validation and derivation, exchanging byte arrays with the crypto provider.
DSA still brings num-bigint-dig 0.8 transitively; 0.9 adds its own rand 0.9
dependency. Upstream dependencies still use base64 0.22. These duplicates are
expected. Criterion's deprecated `black_box` re-export was replaced with
`std::hint::black_box` in all three benchmarks.
Criterion 0.8 also brings `alloca`, whose build script requires a C compiler
for tests and benchmarks. It is a development dependency; the default runtime
dependency graph remains Rust-only.

`cargo update` also rolled forward these existing lockfile entries:

```text
aws-lc-fips-sys     0.14.3 -> 0.14.4
aws-lc-rs          1.18.2 -> 1.19.0
aws-lc-sys         0.46.0 -> 0.47.0
cc                  1.8.0 -> 1.11.1
crypto-bigint      0.7.10 -> 0.7.11
ctutils             0.4.6 -> 0.4.8
der                 0.8.2 -> 0.8.3
elliptic-curve      0.14.1 -> 0.14.3
find-msvc-tools    0.1.14 -> 0.1.15
inout               0.2.5 -> 0.2.6
itoa               1.0.18 -> 1.0.19
js-sys             0.3.106 -> 0.3.107
libc               0.2.190 -> 0.2.191
log                0.4.34 -> 0.4.35
ml-kem              0.3.2 -> 0.3.4
module-lattice      0.2.3 -> 0.2.4
pkcs1           0.8.0-rc.5 -> 0.8.0
smallvec           1.16.3 -> 1.16.5
syn                 3.0.9 -> 3.0.10
wasm-bindgen       0.2.129 -> 0.2.130
web-sys            0.3.106 -> 0.3.107
```

The wasm-bindgen macro, macro-support, and shared crates moved to 0.2.130 too.
ML-DSA 0.1.2 now also brings sha3 0.12; Kryptering retains sha3 0.11 internally.

## RSA 0.10 migration

Kryptering 0.7.1 replaces its exact RSA prerelease pin with `rsa = "0.10"`.
The workspace now requires Kryptering >= 0.7.1, RSA 0.10 and PKCS#1 0.8.
`cargo update` moved Kryptering 0.7.0 -> 0.7.1 and RSA 0.10.0-rc.19 -> 0.10.0;
the direct upgrade also removed RSA 0.9.10 and PKCS#1 0.7.5 from Cargo.lock.
There is now one RSA implementation in the lockfile.

RSA imports and exports use PKCS#8 0.11 / SPKI 0.8 traits alongside the EC
curves. Encrypted PEM is decrypted once using the existing PKCS#8 0.10
legacy PBES2 support, then parsed using each algorithm's decoding traits.
RSA public components now use crypto-bigint's trimmed big-endian encoding to
preserve XML CryptoBinary's minimal unsigned encoding (including `AQAB` for
exponent 65537). A regression test covers this representation change.
RSA 0.10 also enforces a minimum 1024-bit RSA key on import, so the old
512-bit XMLSEC intermediate is rejected. Positive trust-chain unit tests now
use the existing RSA-2048/SHA-256 rollover fixtures with both providers; a
separate test checks rejection of the old chain.

RSA test/benchmark key generation now uses `getrandom::SysRng`, matching
RSA 0.10's rand_core 0.10 traits.

### Audit status

Both advisory exceptions were removed from `.cargo/audit.toml`:

- [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html):
  patched by RSA >= 0.10.0. No affected RSA version remains.
- [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html):
  fixed in rand >= 0.8.6 on the 0.8 line and >= 0.9.3 on the 0.9 line.
  The lockfile already contains patched rand 0.8.8 and 0.9.5; migrating all
  rand consumers to 0.10 is not necessary to resolve this advisory.

`cargo audit --deny warnings` passes without ignored advisories against
RustSec database commit `899077d9d471b9fd3dbf4b2faea8ef26e83692e8`
(2026-11-09; 1,429 advisories). This describes the resolved lockfile;
downstream applications should update and audit their own lockfiles too.

## Retained crypto versions

`cargo outdated --depth 1` still only reports PKCS#8 0.10.2 versus 0.11.0 and
misreports the `pkcs8-pq` alias. Registry manifests provide the coupling map:

| Consumer | Verified requirements | Reason retained |
| --- | --- | --- |
| rsa 0.10.0 | digest 0.11, rand_core 0.10, signature 3, pkcs1 0.8, pkcs8 0.11, spki 0.8 | Upgraded with its import/export and RNG call sites |
| kryptering 0.7.1 | rsa 0.10, digest 0.11, signature 3 | Accepts stable RSA |
| dsa 0.6.3 | digest 0.10, signature 2, pkcs8 0.10, num-bigint-dig 0.8 | Separate byte-serialized import stack; no shared RSA crypto traits |
| ed25519-dalek 2.2.0 | rand_core 0.6, signature 2, sha2 0.10 | Separate byte-serialized import stack |
| x25519-dalek 2.0.1 | rand_core 0.6 | Existing test RNGs remain compatible with rand 0.8 |
| tsp-ltv 0.6.1 | der 0.7, spki 0.7, x509-cert 0.2 | Exchanges certificate types directly with Bergshamra |
| pkcs8 0.10.2 | der 0.7, spki 0.7 | Legacy PBES2 decrypt support and DSA decoding |
| aes 0.9.2 (transitive) | Latest 0.9.4 requires Rust 1.89 | Preserve workspace Rust 1.88 MSRV |

The RSA trait migration is complete at all RSA call sites. Other algorithms
exchange byte arrays/DER with Kryptering and do not need to move together with
RSA. In particular, keeping DSA and Ed25519 on their existing stack avoids
unrelated source changes without retaining affected RSA or rand versions.
A future DSA/Ed25519 migration must move their signature, digest and RNG
consumers together. A tsp-ltv release adopting x509-cert 0.3 / der 0.8 /
spki 0.8 is still required before migrating shared certificate types.

The optional `pkcs8-pq` alias resolves to PKCS#8 0.11 and also supplies the PQ
import stack. Direct pem-rfc7468 1.0 exchanges only labels and byte vectors;
the older DER stack still brings pem-rfc7468 0.7 internally.
Unused historical primitive declarations in the root manifest do not determine
resolved primitive versions; Kryptering owns those dependencies.

## Verification of the RSA migration

Provider checks use separate feature sets: the workspace deliberately rejects
`--all-features`. Completed checks:

- `cargo test --locked --workspace --lib`: 218 passed.
- AWS-LC equivalent (`--no-default-features --features
  aws-lc,legacy-algorithms,pkcs11`): 188 passed.
- `cargo test --locked -p bergshamra-dsig --test trusted_key_set`: 17 passed
  with each provider.
- `cargo clippy --locked --workspace --all-targets -- -D warnings` passed
  for both the default and AWS-LC feature sets.
- `cargo +1.88.0 check --locked --workspace` passed.
- `cargo fmt --all -- --check` and `git diff --check` passed.
- `cargo audit --deny warnings --json`: zero vulnerabilities, zero warnings,
  empty ignore list, 303 resolved packages.

- `cargo build --locked --release` passed.
- XMLSEC encryption: 700 passed, zero failures, one existing DH fixture skip.

The initial XMLSEC DSig run reported 83 failures caused by the newly rejected
512-bit certificates (82 import failures and one RSA-MD5 fixture whose signer
is 512 bits). The runner now executes those verification commands and records
only the known rejections, with the exact legacy CA parameters, as skips.
Signature creation and negative verification phases remain active. The
RSA-MD5 existing-signature exception is restricted to that single fixture.
The completed DSig run reports 364 passed, zero failures, 86 skipped (83 RSA
and three existing GOST cases). README, justfile and the CI gate use these totals.
Positive chain-validation unit tests and rollover integration tests continue
to run against supported RSA-2048 fixtures with each provider.

FIPS and hardware-backed PKCS#11 execution were not exercised.

## Re-evaluation

Run `cargo update --dry-run --verbose` for in-range and MSRV constraints, then
`cargo outdated --workspace --depth 1`. Cross-check incompatible releases with
the crates.io API because of the tool limitations above. Inspect the updated
Kryptering and tsp-ltv manifests before probing further trait migrations.
