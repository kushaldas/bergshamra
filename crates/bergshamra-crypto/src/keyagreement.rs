#![forbid(unsafe_code)]

//! ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral-Static) key agreement.
//!
//! Computes a shared secret from an originator's public key and a recipient's
//! private key using ECDH, then derives a key-encryption key (KEK) using a
//! key derivation function (ConcatKDF or PBKDF2).

use bergshamra_core::Error;

/// Compute an ECDH shared secret through the selected provider.
pub fn ecdh(
    curve: kryptering::EcCurve,
    peer_public: &[u8],
    private_key: &kryptering::SoftwareKey,
) -> Result<Vec<u8>, Error> {
    kryptering::keyagreement::agree(curve, peer_public, private_key)
        .map_err(crate::map_kryptering_err)
}

/// Compute an X25519 shared secret through the selected provider.
pub fn x25519(peer_public: &[u8], private_key: &kryptering::SoftwareKey) -> Result<Vec<u8>, Error> {
    kryptering::keyagreement::agree_x25519(peer_public, private_key)
        .map_err(crate::map_kryptering_err)
}

/// Compute finite-field Diffie-Hellman agreement through the selected
/// provider. The private exponent stays inside the opaque key handle.
pub fn dh_compute(
    other_public: &[u8],
    private_key: &kryptering::SoftwareKey,
) -> Result<Vec<u8>, Error> {
    kryptering::keyagreement::agree_dh(other_public, private_key).map_err(crate::map_kryptering_err)
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
        let alice_key = kryptering::SoftwareKey::from_x25519(
            Some(alice_secret.as_bytes()),
            alice_public.as_bytes(),
        )
        .unwrap();
        let shared_alice = x25519(bob_public.as_bytes(), &alice_key).unwrap();

        // Bob computes shared secret with Alice's public key
        let bob_key = kryptering::SoftwareKey::from_x25519(
            Some(bob_secret.as_bytes()),
            bob_public.as_bytes(),
        )
        .unwrap();
        let shared_bob = x25519(alice_public.as_bytes(), &bob_key).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn x25519_invalid_public_key_length() {
        let secret = [7u8; 32];
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        let key = kryptering::SoftwareKey::from_x25519(Some(&secret), public.as_bytes()).unwrap();
        let short_pub = [0u8; 16];
        let err = x25519(&short_pub, &key).unwrap_err();
        assert!(
            err.to_string().contains("X25519 public key") && err.to_string().contains("32"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_invalid_private_key_length() {
        let pub_key = [9u8; 32];
        let short_priv = [0u8; 16];
        let err = kryptering::SoftwareKey::from_x25519(Some(&short_priv), &pub_key).unwrap_err();
        assert!(
            err.to_string().contains("X25519") && err.to_string().contains("32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_deterministic() {
        // Same inputs → same output
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);
        let alice_key = kryptering::SoftwareKey::from_x25519(
            Some(alice_secret.as_bytes()),
            alice_public.as_bytes(),
        )
        .unwrap();
        let shared1 = x25519(bob_public.as_bytes(), &alice_key).unwrap();
        let shared2 = x25519(bob_public.as_bytes(), &alice_key).unwrap();

        assert_eq!(shared1, shared2);
    }
}
