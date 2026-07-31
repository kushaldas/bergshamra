# Provider capabilities

Bergshamra 0.8.0 routes document cryptography through Kryptering 0.5. This
table is the expected-support manifest for the provider matrix; tests must
either exercise a row or assert the corresponding deterministic unsupported
error.

| Operation | RustCrypto | AWS-LC |
|---|---|---|
| SHA-2 and HMAC-SHA-2 | supported | supported |
| RSA PKCS#1/PSS | full existing Bergshamra mappings | stable SHA-2 mappings |
| ECDSA / Ed25519 | full existing mappings | stable AWS-LC mappings |
| AES-CBC/GCM | 128/192/256 | 128/192/256 |
| AES-KW | 128/192/256 | 128/256; 192 is expected-unsupported |
| RSA-OAEP | independent SHA-1/224/256/384/512 digest and MGF1; MD5/RIPEMD160 with `legacy-algorithms` | SHA-1/256/384/512 when digest and MGF1 match |
| ECDH | P-256/P-384/P-521 | P-256/P-384/P-521 |
| X25519 | supported | supported |
| finite-field X9.42 DH | supported through neutral hazmat parameters | expected-unsupported |
| PKCS#12 AES PBES2 | supported | supported |
| PKCS#12 SHA-1/3DES | `legacy-algorithms` | expected-unsupported |
| DSA | `legacy-algorithms` | expected-unsupported |
| ML-DSA / SLH-DSA | enabled by the existing PQ defaults | expected-unsupported |

No test is silently skipped because an algorithm is unavailable. The
parameterized `supports(Operation)` query is authoritative at runtime.

PKCS#11 is orthogonal: token operations remain on-token and any required
software preprocessing uses the selected document provider.

## FIPS deployment note

The `fips` feature changes initialization and capability policy; it is not a
claim that a consuming binary or deployment is certified. Call
`initialize_backend()` before use and verify the returned `BackendInfo`.
The `fips` feature selects AWS-LC. AWS-LC FIPS builds need its documented
native build toolchain, and every enabled provider must attest active FIPS
mode.
