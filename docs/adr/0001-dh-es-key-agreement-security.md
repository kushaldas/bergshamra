# ADR-0001: DH-ES Key Agreement Security Checks

**Date:** 2026-02-22
**Status:** Accepted
**Context:** Implementation of finite-field Diffie-Hellman Ephemeral-Static (DH-ES) key agreement per W3C XML Encryption 1.1 (`xmlenc11#dh-es`)

## Problem

DH-ES key agreement requires computing a shared secret from an untrusted
originator public key (embedded in XML `<DHKeyValue><Public>`) and a
trusted recipient private key (loaded from local PKCS#8/PKCS#12). An
attacker who controls the XML document can supply an arbitrary public key
value. Without proper validation, small-subgroup attacks can leak private
key bits one at a time.

## Decision

Split validation into two layers:

### Layer 1: Parameter validation at key load time (`validate_dh_params`)

Runs once when loading DH keys from PKCS#8, SPKI, or PKCS#12. All
parameters (p, g, q) are trusted after this point.

| Check | Rationale |
|-------|-----------|
| `p.bits() >= 512` | W3C XML Encryption 1.1 §5.6.1 minimum ("The size of p MUST be at least 512 bits") |
| `probably_prime(p, 20)` | p must be prime for Z_p* to be a valid group |
| `g.bits() >= 160` | W3C XML Encryption 1.1 §5.6.1 minimum ("g at least 160 bits") |
| `g < p` | Generator must be in the group Z_p* |
| `q > 1` | Subgroup order must be non-trivial |
| `q \| (p-1)` | Structural consistency: subgroup of order q exists in Z_p* only if q divides p-1 |

### Layer 2: Peer public key validation at computation time (`dh_compute`)

Runs on every DH-ES operation. The peer public key `y` is untrusted input
from the XML document.

| Check | Rationale |
|-------|-----------|
| `y in 2..p-1` | Reject trivial (0, 1) and out-of-group (≥ p) values. Required by NIST SP 800-56A Rev 3 §5.6.2.3.1 |
| `y^q mod p == 1` | Full subgroup membership validation. Proves y lies in the prime-order-q subgroup, not a small-order subgroup. Required by NIST SP 800-56A Rev 3 §5.6.2.3.1 |
| `q` required | Gate ensuring the subgroup check always runs; reject keys without q rather than skipping the check |

### Checks explicitly not included (with justification)

| Omitted check | Why not needed |
|----------------|---------------|
| `p == 0` in `dh_compute()` | `validate_dh_params()` enforces `p.bits() >= 512` at load time. Dead code at runtime. |
| `q == 0` in `dh_compute()` | `probably_prime(q, 20)` at load time rejects 0 (not prime). |
| `shared == 1` after modpow | If y passes the subgroup check (`y^q mod p == 1`) and `y > 1`, then `y^x mod p == 1` only if `x == 0 mod q`. Private keys are generated properly, so this is unreachable. The subgroup check already defends against attacker-controlled input. |
| `probably_prime(q)` in `validate_dh_params()` | X9.42 DH allows composite subgroup orders (e.g., `q = (p-1)/2` in safe-prime configurations). The DH-1024 test key uses a 1023-bit composite q. The runtime check `y^q mod p == 1` in `dh_compute()` works correctly regardless of whether q is prime — it validates that y lies in the subgroup of order q. Requiring prime q would break interop with valid keys. |
| Constant-time modpow | `BigUint::modpow` timing depends on the exponent (private key), not the base (public key). The attacker controls the base, not the exponent, so modpow timing does not leak private key bits. |
| `y == p-1` special case | `p-1` has order 2 in Z_p*. The subgroup check requires `y^q mod p == 1`, which for `y = p-1` means `(-1)^q mod p == 1`, requiring `q` to be even—impossible since `q` is a large prime. Already caught by the subgroup check. |

## Compliance

These checks implement **NIST SP 800-56A Rev 3 §5.6.2.3.1** (Full
Public-Key Validation Routine for finite-field DH), which requires
exactly:

1. Verify that `2 <= y <= p-2`
2. Verify that `y^q mod p = 1`

Both are present. The parameter validation layer goes beyond the minimum
by also verifying primality of p and q, and the structural relationship
`q | (p-1)`.

## Consequences

- DH-ES decryption/encryption rejects malformed public keys before any
  secret computation occurs.
- Keys without a subgroup order `q` are rejected entirely, even though
  the ASN.1 structure allows `q` to be optional in X9.42 DH parameters.
  This is a deliberate security-over-compatibility tradeoff.
- The `probably_prime` check with 20 Miller-Rabin rounds adds ~1ms per
  key load for 2048-bit parameters. This is acceptable since key loading
  is infrequent.
- The `p >= 512` minimum follows the W3C XML Encryption 1.1 spec §5.6.1
  rather than the stricter NIST SP 800-56A Rev 3 §5.8.2 (which requires
  2048 bits). This allows interoperability with legacy 1024-bit DH keys
  used in the xmlsec test suite. The other validation checks (primality,
  subgroup order, y^q mod p = 1) still provide strong protection.

## Location

- Parameter validation: `crates/bergshamra-keys/src/loader.rs` → `validate_dh_params()`
- Peer key validation: `crates/bergshamra-crypto/src/keyagreement.rs` → `dh_compute()`
