# Bergshamra

Pure Rust XML Security library implementing the W3C XML Digital Signatures
(XML-DSig), XML Encryption (XML-Enc), and XML Canonicalization (C14N)
specifications. Built entirely on the RustCrypto ecosystem with
[Uppsala](https://crates.io/crates/uppsala) for XML parsing — no FFI, no
unsafe code, no libxml2.

## Features

- **XML Digital Signatures** — sign and verify (enveloped, enveloping, detached)
- **XML Encryption** — encrypt and decrypt (element, content, key wrapping, key transport, multi-recipient)
- **XML Canonicalization** — all 6 W3C C14N variants (inclusive/exclusive, with/without comments, 1.0/1.1) with document-subset filtering via XPath
- **X.509 certificate chain** — validation with expiry, trust anchors, CRL revocation, chain building
- **Post-quantum signatures** — ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) with context strings
- **EdDSA** — Ed25519 signatures (RFC 8032)
- **Key agreement** — ECDH-ES (P-256/P-384/P-521), X25519, DH-ES (X9.42 finite-field)
- **Key derivation** — ConcatKDF, HKDF (SHA-256/384/512), PBKDF2
- **RSA-OAEP** — configurable digest (SHA-1/224/256/384/512), MGF1, and OAEPparams
- **HMAC truncation** — HMACOutputLength with CVE-2009-0217 minimum length protection
- **SAML support** — SAML v1.1 `AssertionID` attribute as default ID, `cid:` URI scheme for WS-Security MIME references
- **CipherReference** — resolve encrypted content via URI with XPath and Base64 transforms
- **XPath** — XPath, XPath Filter 2.0, XPointer for reference processing
- **XSLT** — identity transform and minimal XSLT for document-subset operations
- **OPC Relationship Transform** — for Office Open XML signatures (ECMA-376 Part 2)
- **Key formats** — PEM, DER, PKCS#8 (plain and encrypted), PKCS#12, X.509 (PEM and DER), xmlsec keys.xml, raw symmetric keys
- **KeyInfo resolution** — KeyName, X509Certificate (multi-cert chain with leaf detection), X509IssuerSerial, RSA/EC/DSA KeyValue, DEREncodedKeyValue, RetrievalMethod, EncryptedKey, KeyInfoReference
- **`#![forbid(unsafe_code)]`** across every crate

### Supported algorithms

| Category | Algorithms |
|----------|-----------|
| Digest | SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512, MD5†, RIPEMD-160† |
| Signature (RSA) | RSA PKCS#1 v1.5 (SHA-1/224/256/384/512, MD5†, RIPEMD-160†), RSA-PSS (SHA-1/224/256/384/512, SHA3-224/256/384/512) |
| Signature (EC) | ECDSA (P-256/P-384/P-521 × SHA-1/224/256/384/512, SHA3-224/256/384/512, RIPEMD-160†) |
| Signature (other) | DSA (SHA-1, SHA-256), Ed25519, HMAC (SHA-1/224/256/384/512, MD5†, RIPEMD-160†) |
| Post-quantum | ML-DSA-44/65/87 (FIPS 204), SLH-DSA SHA2-128f/128s/192f/192s/256f/256s (FIPS 205) |
| Block cipher | AES-128/192/256-CBC, AES-128/192/256-GCM, 3DES-CBC |
| Key wrap | AES-KW-128/192/256 (RFC 3394), 3DES-KW (RFC 3217) |
| Key transport | RSA PKCS#1 v1.5, RSA-OAEP (SHA-1/224/256/384/512 digest, MGF1-SHA-1/224/256/384/512) |
| Key agreement | ECDH-ES (P-256/P-384/P-521), X25519, DH-ES (X9.42) |
| Key derivation | ConcatKDF, HKDF (SHA-256/384/512), PBKDF2 |
| C14N | Inclusive 1.0/1.1, Exclusive 1.0, each ± comments |
| Transforms | Enveloped signature, Base64, XPath, XPath Filter 2.0, XSLT (identity), OPC Relationship |
| Key formats | PEM, DER, PKCS#8, PKCS#12, X.509, xmlsec keys.xml, raw HMAC/AES/3DES |

† MD5 and RIPEMD-160 are behind the `legacy-algorithms` feature flag.

## xmlsec test suite compatibility

Bergshamra is tested against the full
[xmlsec](https://www.aleksey.com/xmlsec/) interoperability test suite
(1157 test steps across DSig and Enc). These are the same tests used by
the xmlsec1 C library, covering test vectors from the W3C, Merlin, Aleksey,
IAIK, NIST, and Phaos interop suites.

| Suite | Passed | Failed | Total | Pass Rate |
|-------|--------|--------|-------|-----------|
| Enc   | 701    | 0      | 701   | 100%      |
| DSig  | 447    | 9      | 456   | 98%       |
| **Total** | **1148** | **9** | **1157** | **99.2%** |

The 9 DSig failures are GOST algorithm tests (GOST R 34.10-2001,
GOST R 34.10-2012-256, GOST R 34.10-2012-512) which require special
OS cryptographic libraries not available in the RustCrypto ecosystem.

A Python shim (`tests/xmlsec1-shim.py`) translates xmlsec1 CLI flags to
bergshamra flags, so the unmodified xmlsec test scripts run directly against
bergshamra.

## Workspace crates

| Crate | Purpose |
|-------|---------|
| `bergshamra-core` | Error types, algorithm URIs, XML namespace/element constants |
| `bergshamra-xml` | DOM abstraction over Uppsala, NodeSet, XPath, XML writer |
| `bergshamra-c14n` | All 6 W3C C14N variants with document-subset filtering |
| `bergshamra-crypto` | Digest, signature, cipher, key wrap, key transport operations |
| `bergshamra-keys` | Key loading (PEM/DER/PKCS#8/PKCS#12), KeysManager, KeyInfo resolution |
| `bergshamra-transforms` | Transform pipeline (base64, enveloped, XPath, XSLT, URI handling) |
| `bergshamra-dsig` | XML Digital Signature verification and creation |
| `bergshamra-enc` | XML Encryption and decryption |
| `bergshamra` | CLI binary and re-exports |

Dependency flow: `core → xml → c14n → crypto → keys → transforms → dsig/enc → bergshamra`

## Build & test

```bash
cargo build                    # Debug build
cargo build --release          # Release build (needed for integration tests)
cargo test                     # Run all unit tests
cargo clippy --workspace       # Lint
cargo fmt --all -- --check     # Check formatting
```

### Integration tests (xmlsec test suite)

```bash
cd /path/to/bergshamra

# Enc tests
bash test-data/testrun.sh test-data/testEnc.sh openssl \
    "$(pwd)/test-data" "$(pwd)/tests/xmlsec1-shim.py" pem

# DSig tests
bash test-data/testrun.sh test-data/testDSig.sh openssl \
    "$(pwd)/test-data" "$(pwd)/tests/xmlsec1-shim.py" pem
```

## CLI usage

```bash
# Verify a signed document
bergshamra verify --trusted ca.pem signed.xml

# Sign a template
bergshamra sign -k private.pem --output signed.xml template.xml

# Decrypt
bergshamra decrypt -k private.pem encrypted.xml

# Encrypt
bergshamra encrypt --cert recipient.pem --output encrypted.xml template.xml data.xml
```

Key loading options: `-k` (auto-detect PEM/DER), `-K NAME:FILE` (named key),
`--pkcs12`, `--cert`, `--hmac-key`, `--aes-key`, `--keys-file` (xmlsec keys.xml),
`--trusted` (CA cert), `--pwd` (password).

## Security hardening

XML Digital Signatures are a frequent target of attack. Bergshamra provides
several layered protections — some always-on, some opt-in.

### Duplicate ID rejection (always on)

XML Signature Wrapping (XSW) attacks often rely on injecting a second element
with the same `Id` attribute so that the signature verifies against one element
while the application processes another. Bergshamra unconditionally rejects
documents that contain duplicate ID values across any registered ID attribute
(`Id`, `ID`, `id`, `AssertionID`, `xml:id`, and any names added via
`DsigContext::add_id_attr`). Both `verify` and `sign` return an error if a
duplicate is found.

### Inspecting what was signed (`VerifyResult` metadata)

A successful verification returns `VerifyResult::Valid` which carries:

- **`signature_node`** — the `NodeId` of the `<Signature>` element that was
  verified.
- **`references`** — a `Vec<VerifiedReference>`, one per `<Reference>` in
  `<SignedInfo>`. Each entry contains the URI string and the resolved target
  node.

You should always check that the signature covers the element you intend to
consume. For example, a SAML Service Provider should verify that one of the
references points to the `<Assertion>` it will process.

### Strict verification mode (opt-in)

Set `DsigContext::strict_verification = true` (or pass `--strict` on the CLI)
to enforce positional constraints on reference targets. In strict mode every
same-document reference must resolve to a node that is:

- the **document element** (root), or
- an **ancestor** of the `<Signature>` (the signed element wraps the signature
  — the common enveloped pattern), or
- a **sibling** of the `<Signature>` (both are children of the same parent).

Any other position causes verification to fail. This is the strongest defence
against XSW attacks and is recommended for SAML and WS-Security consumers
where the document structure is well-known.

### Trusted keys only (opt-in)

Set `DsigContext::trusted_keys_only = true` to ignore inline keys embedded in
`<KeyInfo>` (`<KeyValue>`, `<X509Certificate>`, etc.) and only use keys
pre-loaded into the `KeysManager`. Without this, an attacker who controls the
XML can embed their own key and sign with it — the signature will verify, but
against the wrong key. This is essential for SAML Service Providers and any
deployment where the signing key is known ahead of time.

### HMAC output truncation (CVE-2009-0217)

Set `DsigContext::hmac_min_out_len` to enforce a minimum `<HMACOutputLength>`
in bits. A zero-length or very short HMAC is trivially forgeable.

### Recommended configuration for SAML

```rust
let mut ctx = DsigContext::new(keys_manager);
ctx.trusted_keys_only = true;     // reject inline keys
ctx.strict_verification = true;   // reject unexpected reference positions
ctx.verify_keys = true;           // validate the IdP certificate chain
```

Or on the CLI:

```bash
bergshamra verify --strict --trusted-keys-only --trusted idp-ca.pem signed-assertion.xml
```

## License

BSD-2-Clause License. See [LICENSE](LICENSE) for details.
