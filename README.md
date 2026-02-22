# Bergshamra

Pure Rust XML Security library implementing the W3C XML Digital Signatures
(XML-DSig), XML Encryption (XML-Enc), and XML Canonicalization (C14N)
specifications. Built entirely on the RustCrypto ecosystem with
[Uppsala](https://crates.io/crates/uppsala) for XML parsing — no FFI, no
unsafe code, no libxml2.

## Features

- **XML Digital Signatures** — sign and verify (enveloped, enveloping, detached)
- **XML Encryption** — encrypt and decrypt (element, content, key wrapping, key transport)
- **XML Canonicalization** — all 6 W3C C14N variants (inclusive/exclusive, with/without comments, 1.0/1.1)
- **X.509 certificate chain** — validation with expiry, trust anchors, CRL revocation, chain building
- **Post-quantum signatures** — ML-DSA (FIPS 204) and SLH-DSA (FIPS 205)
- **Key agreement** — ECDH-ES with ConcatKDF (P-256/P-384/P-521)
- **XPath** — XPath, XPath Filter 2.0, XPointer for reference processing
- **XSLT** — identity transform and minimal XSLT for document-subset operations
- **OPC Relationship Transform** — for Office Open XML signatures
- **Key formats** — PEM, DER, PKCS#8, PKCS#12, X.509, xmlsec keys.xml
- **`#![forbid(unsafe_code)]`** across every crate

### Supported algorithms

| Category | Algorithms |
|----------|-----------|
| Digest | SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512, MD5, RIPEMD-160 |
| Signature | RSA PKCS#1 v1.5, RSA-PSS, DSA, ECDSA (P-256/P-384/P-521), HMAC |
| Post-quantum | ML-DSA-44/65/87 (FIPS 204), SLH-DSA SHA2-128f/128s/192f/192s/256f/256s (FIPS 205) |
| Block cipher | AES-128/192/256-CBC, AES-128/192/256-GCM, 3DES-CBC |
| Key wrap | AES-KW-128/192/256, 3DES-KW |
| Key transport | RSA PKCS#1 v1.5, RSA-OAEP (SHA-1/256/384/512, MGF1) |
| Key agreement | ECDH-ES (P-256/P-384/P-521) with ConcatKDF |
| C14N | Inclusive 1.0/1.1, Exclusive, each ± comments |
| Transforms | Enveloped signature, Base64, XPath, XPath Filter 2.0, XSLT (identity), OPC Relationship |
| Key formats | PEM, DER, PKCS#8, PKCS#12, X.509, xmlsec keys.xml |

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

## License

BSD-2-Clause License. See [LICENSE](LICENSE) for details.
