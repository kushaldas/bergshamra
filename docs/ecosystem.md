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
RSA/DSA still bring num-bigint-dig 0.8 transitively; 0.9 adds its own rand 0.9
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

## Retained crypto versions

Registry releases were checked directly through the crates.io API as well as
with `cargo outdated --workspace --depth 1`. The latter currently misses most
incompatible upgrades in this workspace, misreports the `pkcs8-pq` alias, and
panics with `--aggressive --features 'rustcrypto legacy-algorithms post-quantum pkcs11'`.
Its final ordinary report contains only pkcs8 0.10.2 versus 0.11.0 (and the
alias artefact); that does not mean the other versions below are current.

| Dependency | Current locked version | Latest stable | Reason retained |
| --- | --- | --- | --- |
| rsa | 0.9.10 | 0.10.0 | Kryptering's exact prerelease constraint blocks stable 0.10 |
| dsa | 0.6.3 | 0.7.0 | Keep the RSA/DSA import stack on matching PKCS#8 and signature traits |
| ed25519-dalek | 2.2.0 | 3.0.0 | Same signature/rand_core migration |
| x25519-dalek | 2.0.1 | 3.0.0 | Same rand_core migration |
| rand | 0.8.8 | 0.10.3 | RSA 0.9 and X25519 2 need rand_core 0.6 RNGs |
| signature | 2.2.0 | 3.0.0 | RSA 0.9 and DSA 0.6 require signature 2 |
| pkcs1 | 0.7.5 | 0.8.0 | RSA 0.9 implements the 0.7 decoding traits |
| pkcs8 | 0.10.2 | 0.11.0 | RSA/DSA key imports implement the 0.10 traits |
| der | 0.7.10 | 0.8.3 | Shared certificate types with tsp-ltv |
| spki | 0.7.3 | 0.8.1 | Shared certificate types and old RSA/DSA decoding traits |
| x509-cert | 0.2.5 | 0.3.0 | tsp-ltv exchanges x509-cert 0.2 certificates directly |
| aes (transitive) | 0.9.2 | 0.9.4 | Latest requires Rust 1.89 |

The workspace already uses the newer EC, cipher, and PQ stacks. Its `pkcs8-pq`
alias correctly resolves to pkcs8 0.11.0 and must not be downgraded to 0.10.
Separate old/new trait stacks are intentional at the byte-serialization boundary.
Direct PEM decoding can use pem-rfc7468 1.0 independently because it exchanges
only labels and byte vectors with the DER parsers; errors are mapped to
Bergshamra errors. Its `alloc` feature is enabled explicitly so standalone
AWS-LC builds also have `decode_vec`, without depending on RustCrypto feature
unification. The old DER stack still depends on pem-rfc7468 0.7 internally.

### Verified upstream constraints

These are version requirements read from the downloaded registry manifests:

| Consumer | Requirements |
| --- | --- |
| kryptering 0.7.0 | `rsa = "=0.10.0-rc.19"`, `digest = "0.11"`, `signature = "3"` |
| rsa 0.9.10 | `digest = "0.10.5"`, `rand_core = "0.6.4"`, `signature = ">2.0, <2.3"`, `pkcs1 = "0.7.5"`, `pkcs8 = "0.10.2"`, `spki = "0.7.3"` |
| dsa 0.6.3 | `digest = "0.10"`, `signature = "2.0, <2.3"`, `pkcs8 = "0.10"` |
| ed25519-dalek 2.2.0 | `rand_core = "0.6.4"`, `signature = ">=2.0, <2.3"`, `sha2 = "0.10"` |
| x25519-dalek 2.0.1 | `rand_core = "0.6"` |
| tsp-ltv 0.6.1 | `der = "0.7"`, `spki = "0.7"`, `pem-rfc7468 = "0.7"`, `x509-cert = "0.2"` |
| pkcs8 0.10.2 | `der = "0.7"`, `spki = "0.7.1"` |

A coordinated probe changed RSA to 0.10 along with DSA, Ed25519, X25519,
signature, rand, and PKCS#1. `cargo update` failed before compilation:

```text
failed to select a version for `rsa`
kryptering v0.7.0 requires =0.10.0-rc.19
previously selected package rsa v0.10.0
```

All probe manifest changes were reverted. A new Kryptering release accepting
stable RSA 0.10 is required before migrating the remaining import/RNG stack as
a group. A tsp-ltv release adopting x509-cert 0.3 / der 0.8 / spki 0.8 is
required before migrating the shared certificate stack. Neither migration
should be attempted by upgrading individual trait crates in isolation.

The root manifest also contains unused historical primitive declarations
(`sha1`, `sha2`, `sha3`, `md-5`, `ripemd`, `hmac`, `digest`, `hkdf`, `pkcs5`,
`pbkdf2`, and others). They are not inherited by workspace members and do not
determine the resolved primitive versions; Kryptering owns those dependencies.
They were left unchanged rather than presenting unused declaration edits as
runtime upgrades.

## Verification

Provider checks use separate feature sets: this workspace deliberately rejects
`--all-features`. Completed checks:

- `cargo build --locked --workspace` passed.
- `cargo +1.88.0 check --locked --workspace` passed.
- `cargo test --locked --workspace --lib`: 216 passed.
- `cargo test --locked -p bergshamra-dsig --test trusted_key_set`: 17 passed.
- The corresponding AWS-LC commands with
  `--no-default-features --features aws-lc,legacy-algorithms,pkcs11`:
  187 unit tests and 17 trusted-key tests passed.
- `cargo clippy --locked --workspace --all-targets -- -D warnings` passed
  for both the default and AWS-LC feature sets, including all benchmarks.
- `cargo fmt --all -- --check` and `git diff --check` passed.
- `cargo audit --deny warnings` passed using the existing `.cargo/audit.toml`
  exceptions. No advisory exceptions were added or broadened; their comments
  now reflect the current release constraints.

- `cargo build --locked --release` passed.
- The complete xmlsec signature suite: 447 passed, zero failures, three skips.
- The complete xmlsec encryption suite: 700 passed, zero failures, one skip.
  Its DH-1024 fixture is explicitly skipped by the existing runner because of
  its composite subgroup order, as documented in the README. The justfile's
  stale 701/0/0 expectation was corrected to 700/0/1 and both expected totals
  were checked against the complete run logs.

FIPS and hardware-backed PKCS#11 execution were not exercised in this update.

## Re-evaluation

Run `cargo update --dry-run --verbose` for in-range and MSRV constraints, then
`cargo outdated --workspace --depth 1`. Cross-check incompatible releases with
the crates.io API because of the tool limitations above. Inspect the updated
Kryptering and tsp-ltv manifests before probing either remaining migration.
