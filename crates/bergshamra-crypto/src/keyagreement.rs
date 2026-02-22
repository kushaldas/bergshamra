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

    let public_key: p256::PublicKey = Option::from(
        p256::PublicKey::from_encoded_point(&encoded_point),
    )
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

    let public_key: p384::PublicKey = Option::from(
        p384::PublicKey::from_encoded_point(&encoded_point),
    )
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

    let public_key: p521::PublicKey = Option::from(
        p521::PublicKey::from_encoded_point(&encoded_point),
    )
    .ok_or_else(|| Error::Key("invalid P-521 public key point".into()))?;

    let shared_secret = p521::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute a finite-field Diffie-Hellman shared secret (X9.42 DH).
///
/// shared_secret = other_public ^ my_private mod p
///
/// All values are big-endian byte arrays. The result is zero-padded on the left
/// to the byte-length of p (as required by the DH-ES specification).
pub fn dh_compute(
    other_public: &[u8],
    my_private: &[u8],
    p: &[u8],
) -> Result<Vec<u8>, Error> {
    use num_bigint_dig::BigUint;

    let pub_uint = BigUint::from_bytes_be(other_public);
    let priv_uint = BigUint::from_bytes_be(my_private);
    let p_uint = BigUint::from_bytes_be(p);

    if p_uint.bits() == 0 {
        return Err(Error::Key("DH prime p is zero".into()));
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
