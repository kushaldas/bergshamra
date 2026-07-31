# Migrating to Bergshamra 0.8.0

Bergshamra 0.8.0 was released on July 31, 2026. It is a coordinated breaking
release with Kryptering 0.5 and tsp-ltv 0.4. The minimum Rust version is 1.88.

## Choose a provider

Defaults preserve RustCrypto, legacy algorithms, post-quantum algorithms, and
PKCS#11. Alternate providers must disable defaults:

```toml
bergshamra = { version = "0.8.0", default-features = false, features = ["aws-lc", "legacy-algorithms", "pkcs11"] }
```

Do not use `all-features`: multiple document providers are rejected.

## Initialization and capability errors

Provider initialization and unsupported operations are now observable errors.
In FIPS builds initialization is mandatory:

```rust
let info = bergshamra::initialize_backend()?;
assert_eq!(info.fips, bergshamra::FipsStatus::Active);
```

Handle `BackendNotInitialized`, `BackendInitialization`, `FipsUnavailable`,
and parameterized `UnsupportedAlgorithm` errors instead of assuming every
compiled algorithm is available.

## Keys and digests

Signature operations use Kryptering's cloneable, opaque `SoftwareKey` rather
than exposing provider signing-key enums. Import private keys as PKCS#8,
public keys as SPKI, symmetric keys as raw bytes, and X25519 through its neutral
component constructor. Finite-field DH imports use
`KeyData::from_dh_parameters` with neutral big-endian integer components.
Use `Key::dh_parameters()` for public DH parameters and the opaque software
handle for agreement; the old private-exponent-bearing `dh_data()` accessor is
removed. Secret export is explicit and returns zeroizing data.

Digest one-shot calls and streaming hasher construction are fallible because
provider initialization and support checks can fail. Propagate their `Result`
values when migrating 0.7 code.

## HTTP clients

tsp-ltv network clients accept `AttestedHttpClient`, not an arbitrary
`reqwest::Client`. Construct it fallibly through the hardened builder. A named
unverified escape hatch exists only outside FIPS builds.
