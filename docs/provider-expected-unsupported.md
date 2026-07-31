# Provider-specific expected unsupported cases

The XMLSEC compatibility gate runs only against Bergshamra's default
RustCrypto configuration and requires the full established pass totals.
Alternate-provider limits listed here are covered by focused capability and
policy tests; they are not accepted as XMLSEC test failures.

| Provider | Fixture / operation | Reason |
|---|---|---|
| All providers | GOST 2001 signature transform fixtures (three DSig cases) | GOST is not part of Kryptering's algorithm contract. The upstream harness records these three cases as explicit skips. |
| AWS-LC | ML-DSA and SLH-DSA signature fixture families | The alternate adapter intentionally uses stable provider APIs and never falls back to RustCrypto. Stable AWS-LC APIs do not expose these signatures. |
| AWS-LC | X9.42 finite-field DH three-step encryption fixture | The modern alternate-provider baseline covers P-256/P-384/P-521 ECDH and X25519. The AWS-LC adapter does not import the X9.42 key OID; the operation fails before key use. |
| AWS-LC | Historical RSA keys and chains below 2048 bits, including 512- and 1024-bit signedxml/XMLSEC fixtures | Kryptering's AWS-LC adapter requires RSA keys to be at least 2048 bits. RustCrypto retains legacy-key interoperability, while the AWS-LC XML signature and trust-policy paths remain covered with supported RSA sizes. |
| AWS-LC | DSA signature and DSA `KeyValue` fixture families | Stable AWS-LC APIs do not expose DSA key import, signing, or verification. |
| AWS-LC | MD5, RIPEMD160, and SHA3-224 digest-dependent fixtures | These digests are absent from the stable AWS-LC digest surface used by the adapter. SHA-2 and the remaining tested stable digest mappings are covered independently. |
| AWS-LC | Non-stable RSA PKCS#1/PSS and ECDSA curve/hash combinations | Only the exact curve/hash and RSA/digest combinations exposed by stable aws-lc-rs are advertised. This includes rejecting legacy signing combinations, SHA-224/SHA-3 RSA variants, and non-exposed ECDSA pairs before key use. |
| AWS-LC | RSA-PSS signatures declaring a salt length different from the digest output length | Stable aws-lc-rs exposes digest-length RSA-PSS verification parameters. Other protocol-declared salt lengths fail deterministically when the verifier is constructed; RustCrypto retains broad X.509/CMS interoperability for these valid legacy signatures. |
| AWS-LC | RSA-OAEP with SHA-224, MD5, RIPEMD160, or independently selected OAEP/MGF1 hashes | Stable aws-lc-rs exposes SHA-1/256/384/512 OAEP only when the OAEP and MGF1 hashes match. |
| AWS-LC | AES-KW-192 fixtures | Stable AWS-LC APIs expose the required wrapping primitive for AES-128 and AES-256, not AES-192. |
| AWS-LC | 3DES-CBC/key-wrap fixtures and `test-data/keys/keys.xml` aggregate import | Stable AWS-LC APIs do not expose the legacy 3DES document operations. The aggregate file contains a 3DES entry, so all consumers of that heterogeneous file fail at import; HMAC, RSA, and AES imports are covered independently. |
| SoftHSM fixture | Ed25519 token test | SoftHSM 2.6 does not advertise EdDSA key generation. CI excludes this one token-capability test explicitly while running every other HSM operation with each document provider. Software Ed25519 remains part of every provider baseline. |

This manifest describes interoperability limits, not recommended security
policy. Applications should normally reject legacy SHA-1 chains as well;
Bergshamra enables them only with `legacy-algorithms`. FIPS builds use focused
provider tests and do not run the XMLSEC compatibility suite.
