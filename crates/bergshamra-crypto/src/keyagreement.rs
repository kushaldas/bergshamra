#![forbid(unsafe_code)]

//! ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral-Static) key agreement.
//!
//! Computes a shared secret from an originator's public key and a recipient's
//! private key using ECDH, then derives a key-encryption key (KEK) using a
//! key derivation function (ConcatKDF or PBKDF2).

use bergshamra_core::Error;

/// Compute an ECDH shared secret for P-256.
///
/// Takes the originator's (ephemeral) public key as uncompressed SEC1 bytes
/// and the recipient's (static) private key.
pub fn ecdh_p256(
    originator_public: &[u8],
    recipient_private: &p256::SecretKey,
) -> Result<Vec<u8>, Error> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;

    let encoded_point = p256::EncodedPoint::from_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-256 public key: {e}")))?;

    let public_key: p256::PublicKey =
        Option::from(p256::PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| Error::Key("invalid P-256 public key point".into()))?;

    let shared_secret = p256::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an ECDH shared secret for P-384.
pub fn ecdh_p384(
    originator_public: &[u8],
    recipient_private: &p384::SecretKey,
) -> Result<Vec<u8>, Error> {
    use p384::elliptic_curve::sec1::FromEncodedPoint;

    let encoded_point = p384::EncodedPoint::from_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-384 public key: {e}")))?;

    let public_key: p384::PublicKey =
        Option::from(p384::PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| Error::Key("invalid P-384 public key point".into()))?;

    let shared_secret = p384::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an ECDH shared secret for P-521.
pub fn ecdh_p521(
    originator_public: &[u8],
    recipient_private: &p521::SecretKey,
) -> Result<Vec<u8>, Error> {
    use p521::elliptic_curve::sec1::FromEncodedPoint;

    let encoded_point = p521::EncodedPoint::from_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-521 public key: {e}")))?;

    let public_key: p521::PublicKey =
        Option::from(p521::PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| Error::Key("invalid P-521 public key point".into()))?;

    let shared_secret = p521::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an X25519 Diffie-Hellman shared secret (RFC 7748).
///
/// Takes the originator's (ephemeral) public key as raw 32 bytes
/// and the recipient's (static) private key as raw 32 bytes.
/// Returns the 32-byte shared secret.
pub fn ecdh_x25519(originator_public: &[u8], recipient_private: &[u8]) -> Result<Vec<u8>, Error> {
    if originator_public.len() != 32 {
        return Err(Error::Key(format!(
            "invalid X25519 public key length: {} (expected 32)",
            originator_public.len()
        )));
    }
    if recipient_private.len() != 32 {
        return Err(Error::Key(format!(
            "invalid X25519 private key length: {} (expected 32)",
            recipient_private.len()
        )));
    }

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(originator_public);
    let their_public = x25519_dalek::PublicKey::from(pub_bytes);

    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(recipient_private);
    let my_secret = x25519_dalek::StaticSecret::from(priv_bytes);

    let shared_secret = my_secret.diffie_hellman(&their_public);
    Ok(shared_secret.as_bytes().to_vec())
}

/// Compute a finite-field Diffie-Hellman shared secret (X9.42 DH).
///
/// shared_secret = other_public ^ my_private mod p
///
/// All values are big-endian byte arrays. The result is zero-padded on the left
/// to the byte-length of p (as required by the DH-ES specification). Requires
/// `q` for subgroup validation.
pub fn dh_compute(
    other_public: &[u8],
    my_private: &[u8],
    p: &[u8],
    q: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    use num_bigint_dig::BigUint;
    use num_traits::{One, Zero};

    let pub_uint = BigUint::from_bytes_be(other_public);
    let priv_uint = BigUint::from_bytes_be(my_private);
    let p_uint = BigUint::from_bytes_be(p);

    // Validate the (untrusted) peer public key: must be in range (1, p).
    // y=0 and y=1 are trivial, y>=p is out of the group.
    if pub_uint.is_zero() || pub_uint.is_one() || pub_uint >= p_uint {
        return Err(Error::Key(
            "DH public key out of range (must be in 2..p-1)".into(),
        ));
    }

    // Subgroup membership check: y^q mod p must equal 1.
    // This prevents small-subgroup attacks where an attacker sends a y
    // that lies in a small-order subgroup to leak private key bits.
    let q_bytes = q.ok_or_else(|| {
        Error::Key("DH subgroup order q is required for subgroup validation".into())
    })?;
    let q_uint = BigUint::from_bytes_be(q_bytes);
    let check = pub_uint.modpow(&q_uint, &p_uint);
    if !check.is_one() {
        return Err(Error::Key(
            "DH public key fails subgroup check (y^q mod p != 1)".into(),
        ));
    }

    let shared = pub_uint.modpow(&priv_uint, &p_uint);
    let mut result = shared.to_bytes_be();

    // Zero-pad to the byte-length of p
    let p_len = p.len();
    if result.len() < p_len {
        let mut padded = vec![0u8; p_len - result.len()];
        padded.extend_from_slice(&result);
        result = padded;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_roundtrip() {
        // Both parties generate key pairs; shared secret must match
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);

        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        // Alice computes shared secret with Bob's public key
        let shared_alice = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();

        // Bob computes shared secret with Alice's public key
        let shared_bob = ecdh_x25519(alice_public.as_bytes(), bob_secret.as_bytes()).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn x25519_invalid_public_key_length() {
        let secret = [0u8; 32];
        let short_pub = [0u8; 16];
        let err = ecdh_x25519(&short_pub, &secret).unwrap_err();
        assert!(
            err.to_string().contains("invalid X25519 public key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_invalid_private_key_length() {
        let pub_key = [0u8; 32];
        let short_priv = [0u8; 16];
        let err = ecdh_x25519(&pub_key, &short_priv).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid X25519 private key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_deterministic() {
        // Same inputs → same output
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        let shared1 = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();
        let shared2 = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();

        assert_eq!(shared1, shared2);
    }
}
