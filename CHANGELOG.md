# Changelog


## 0.6.0 [2026-06-27]

### Added

- `VerifyResult::all_reference_digests_verified()` — check whether any
  `<Reference>` digest was skipped, and whether all `<Reference>` digests were
  computed and verified locally. A `cid:` (WS-Security attachment) reference
  reports `digest_verified = false` because its bytes live outside the XML
  document and must be verified out-of-band.
- CLI `verify --require-reference-digests` — fail an otherwise-valid signature
  when any `<Reference>` digest was not verified locally (e.g. `cid:`
  attachments). Off by default to preserve the existing WS-Security workflow.

### Changed

- Updated shared dependencies to their latest releases: `kryptering` `0.3.0` →
  `0.4.0`, `tsp-ltv` `0.2.0` → `0.3.0`, and `uppsala` `0.4.0` → `0.5.0`.

## 0.5.1

### Changed

- Updates `uppsala` to latest 0.4.0 version.

## 0.5.0

### Breaking Changes

#### `DsigContext::new()` is now secure-by-default

`DsigContext::new()` now enables `trusted_keys_only = true`,
`strict_verification = true`, and `hmac_min_out_len = 160` out of the box,
hardened for federated identity (SAML, WS-Security). Callers that need the
previous permissive W3C XML-DSig behavior — inline `<KeyInfo>` keys, no
reference-position enforcement, no minimum HMAC output length — must switch to
the new `DsigContext::new_permissive()`.

#### `VerifiedReference` is now `#[non_exhaustive]` and gained `digest_verified`

The public `VerifiedReference` struct has a new `digest_verified: bool` field
(`false` for `cid:` WS-Security attachment references whose content lives
outside the XML document). The struct is now `#[non_exhaustive]`, so downstream
code must construct it via the verifier and match it with `..`; future fields
will no longer be a breaking change.

### Added

- `DsigContext::new_permissive()` — opt-in W3C-standard (permissive) context.
- Verifier-declared HMAC truncation (`HMACOutputLength`, W3C XML-DSig §6.3.1)
  via `SignatureAlgorithm::verify_truncated`, gated by the CVE-2009-0217 policy
  floor (`hmac_min_out_len`).

### Changed

- Updated `ml-dsa` to `0.1.1`, `slh-dsa` to `0.2.0-rc.5`, and the post-quantum
  `pkcs8` to the stable `0.11.0` (previously prerelease pins), tracking
  `kryptering 0.3`.
- `kryptering` (>=0.3) and `tsp-ltv` (>=0.2) are now resolved from crates.io
  instead of local `path` / `[patch]` dependencies.
- ML-DSA signing is now randomized (`sign_randomized`); RSA-PSS and ML-DSA
  draw from the OS CSPRNG (`OsRng` / `getrandom::SysRng`), and OS RNG failures
  surface as errors instead of panicking. See `docs/adr/0003-rng-choice.md`.
- `DsigContext` / `EncContext` `Debug` impls now redact the `KeysManager`
  (printing only a key count) to avoid leaking private/secret key material into
  logs and crash reports.

### Fixed

- XML-Enc: `<DerivedKey>` (ConcatKDF / PBKDF2) derivation failures now surface
  as errors instead of silently falling through to a `KeyName` lookup that used
  the wrong key bytes (which produced misleading downstream errors).

## 0.4.0

### Breaking Changes

#### `DsigContext` and `EncContext` no longer derive `Debug`

Both context types now contain trait-object fields (`Box<dyn Signer>`, etc.)
which do not implement `Debug`. Manual `Debug` impls are provided that print
placeholder strings for HSM fields. Code that relies on `#[derive(Debug)]`
behavior is unaffected, but generic bounds like `T: Debug` on a type containing
`DsigContext` may need adjustment.

### Added

#### HSM support via kryptering

`DsigContext` and `EncContext` now accept optional HSM-backed trait objects for
signing, verification, encryption, and key wrapping. When set, cryptographic
operations bypass the `KeysManager` and delegate to the HSM — key material
never leaves the hardware.

**`DsigContext` new fields and builders:**
- `hsm_signer: Option<Box<dyn kryptering::Signer>>` / `.with_hsm_signer()`
- `hsm_verifier: Option<Box<dyn kryptering::Verifier>>` / `.with_hsm_verifier()`

**`EncContext` new fields and builders:**
- `hsm_decryptor: Option<Box<dyn kryptering::Decryptor>>` / `.with_hsm_decryptor()`
- `hsm_key_unwrapper: Option<Box<dyn kryptering::KeyWrapper>>` / `.with_hsm_key_unwrapper()`
- `hsm_encryptor: Option<Box<dyn kryptering::Encryptor>>` / `.with_hsm_encryptor()`
- `hsm_key_wrapper: Option<Box<dyn kryptering::KeyWrapper>>` / `.with_hsm_key_wrapper()`

Example using SoftHSM2 via kryptering's PKCS#11 backend:

```rust
use kryptering::pkcs11::{Pkcs11Provider, Pkcs11Signer};

let provider = Pkcs11Provider::new(Path::new("/usr/lib/softhsm/libsofthsm2.so"))?;
let session = provider.open_session("1234")?;
let signer = Pkcs11Signer::new(&session, "my-rsa-key", SignatureAlgorithm::RsaSha256);

let ctx = DsigContext::new(KeysManager::new())
    .with_hsm_signer(Box::new(signer));

let signed_xml = sign(&ctx, template_xml)?;
```

#### Shared crypto backend (kryptering)

`bergshamra-crypto` now delegates cipher, digest, KDF, key agreement, key
transport, key wrap, and signing operations to the `kryptering` crate. This
eliminates code duplication across the e-signing family of crates while
preserving the same XML algorithm URI–based dispatch API. No behavioral changes
for existing callers.

#### Shared trust infrastructure (tsp-ltv)

X.509 certificate chain validation in `bergshamra-keys` now uses `tsp-ltv`
for trust store management and chain building. Re-exported as
`bergshamra_keys::trust` and `bergshamra_keys::tsp_crypto` /
`bergshamra_keys::tsp_error`.

#### Key introspection methods on `Key`

- `Key::algorithm_name()` — returns the algorithm name (delegates to `KeyData`)
- `Key::to_spki_der()` — returns SPKI DER encoding if available
- `Key::to_key_value_xml()` — returns KeyValue XML fragment if available
- `Key::has_private_key()` — returns whether the key contains private key material

#### HSM integration tests

New `hsm_sign_verify` integration test suite in `bergshamra-dsig` tests signing
and verification with SoftHSM2 via PKCS#11. Run with:

```bash
just hsm-setup    # Initialize SoftHSM2 token with test keys
just test-hsm     # Run HSM integration tests
```

### Changed

- Made `load_ed25519_private_pkcs8_der()` and `load_ed25519_public_spki_der()` public in `bergshamra-keys::loader`
- Made `try_load_pq_private_key()` and `try_load_pq_public_key()` public in `bergshamra-keys::loader`
- Pinned `ml-dsa` to exact version `=0.1.0-rc.7` to prevent breaking pre-release upgrades
- Added `kryptering` (shared crypto backend) and `tsp-ltv` (shared trust/validation) as workspace dependencies

## 0.3.1

### Added

- `Key::algorithm_name()` — returns the algorithm name (delegates to `KeyData`)
- `Key::to_spki_der()` — returns SPKI DER encoding if available
- `Key::to_key_value_xml()` — returns KeyValue XML fragment if available
- `Key::has_private_key()` — returns whether the key contains private key material

### Changed

- Made `load_ed25519_private_pkcs8_der()` and `load_ed25519_public_spki_der()` public in `bergshamra-keys::loader`
- Made `try_load_pq_private_key()` and `try_load_pq_public_key()` public in `bergshamra-keys::loader`

## 0.3.0

### Breaking Changes

#### `VerifyResult::Valid` now carries signing key metadata

The `Valid` variant has a new required field `key_info: VerifiedKeyInfo`.
Code that pattern-matches on this variant must be updated:

```rust
// Before:
match result {
    VerifyResult::Valid { signature_node, references } => { ... }
    VerifyResult::Invalid { reason } => { ... }
}

// After — use the new field:
match result {
    VerifyResult::Valid { signature_node, references, key_info } => {
        println!("Verified with {} key", key_info.algorithm);
        if let Some(name) = &key_info.key_name {
            println!("Key name: {name}");
        }
    }
    VerifyResult::Invalid { reason } => { ... }
}

// Or ignore it with `..`:
match result {
    VerifyResult::Valid { references, .. } => { ... }
    VerifyResult::Invalid { reason } => { ... }
}
```

`VerifiedKeyInfo` provides:

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | `String` | Algorithm name, e.g. `"RSA"`, `"EC-P256"`, `"HMAC"` |
| `key_name` | `Option<String>` | Key name if resolved from `KeysManager` by name |
| `x509_chain` | `Vec<Vec<u8>>` | DER-encoded X.509 certificate chain (leaf first) |

#### C14N `inclusive_prefixes` parameter generalized

`canonicalize()`, `canonicalize_doc()`, and `exclusive::canonicalize()` now
accept `&[S]` where `S: AsRef<str>` instead of `&[String]`. This lets you
pass `&["ns1", "ns2"]` directly without allocating `String`s.

Existing code passing `&Vec<String>` or `&[String]` compiles unchanged.
However, **empty slices `&[]` now require a type annotation** since Rust
cannot infer `S`:

```rust
// Before:
canonicalize(xml, mode, None, &[])

// After — pick one:
canonicalize(xml, mode, None, &[] as &[&str])
canonicalize(xml, mode, None, &[] as &[String])

// Or pass a typed empty vec:
let empty: Vec<&str> = vec![];
canonicalize(xml, mode, None, &empty)
```

### Added

#### Builder methods on context types

`DsigContext` and `EncContext` now support fluent builder-style configuration.
All fields remain `pub`, so direct assignment still works.

```rust
// Before:
let mut ctx = DsigContext::new(keys_manager);
ctx.trusted_keys_only = true;
ctx.strict_verification = true;
ctx.hmac_min_out_len = 128;

// After — either style works:
let ctx = DsigContext::new(keys_manager)
    .with_trusted_keys_only(true)
    .with_strict_verification(true)
    .with_hmac_min_out_len(128);
```

**`DsigContext` builder methods:**
`with_debug`, `with_insecure`, `with_verify_keys`, `with_verification_time`,
`with_skip_time_checks`, `with_enabled_key_data_x509`, `with_trusted_keys_only`,
`with_strict_verification`, `with_hmac_min_out_len`, `with_base_dir`

**`EncContext` builder methods:**
`with_disable_cipher_reference`

#### Top-level re-exports

The `bergshamra` crate now re-exports the most commonly used types and
functions at the top level. You no longer need to reach into sub-crate modules:

```rust
// Before:
use bergshamra_dsig::DsigContext;
use bergshamra_dsig::verify::verify;
use bergshamra_keys::KeysManager;
use bergshamra_core::Error;

// After:
use bergshamra::{DsigContext, verify, KeysManager, Error};
```

**Re-exported types:** `Error`, `DsigContext`, `EncContext`, `KeysManager`,
`Key`, `KeyData`, `KeyUsage`, `VerifyResult`, `VerifiedReference`,
`VerifiedKeyInfo`

**Re-exported functions:** `verify`, `sign`, `encrypt`, `decrypt`,
`decrypt_to_bytes`

The existing module re-exports (`bergshamra::dsig`, `bergshamra::enc`, etc.)
are unchanged.

#### New trait implementations

| Type | Added |
|------|-------|
| `DsigContext` | `Debug` |
| `EncContext` | `Debug` |
| `KeysManager` | `Debug` (already had `Clone`) |
| `VerifyResult` | `Clone` (already had `Debug`) |
| `C14nMode` | `Display` (prints the W3C algorithm URI) |

#### X.509 KeyInfo XML builders

Two new public functions in `bergshamra_keys` for generating `<ds:KeyInfo>`
fragments containing X.509 certificates:

```rust
// From base64-encoded DER strings:
let xml = bergshamra_keys::build_x509_key_info(&[cert_b64]);

// From raw DER bytes:
let xml = bergshamra_keys::build_x509_key_info_from_der(&[cert_der]);
```

### Changed

- Internal XML generation in `sign.rs`, `verify.rs`, `encrypt.rs`, and
  `keyinfo.rs` migrated from `format!()` string interpolation to Uppsala's
  `XmlWriter` API. No behavioral changes.

## 0.2.1

Initial public release with full XML-DSig, XML-Enc, and C14N support.
