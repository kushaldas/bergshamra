# Changelog

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
