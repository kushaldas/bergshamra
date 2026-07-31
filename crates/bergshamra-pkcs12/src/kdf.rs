#![forbid(unsafe_code)]

//! PKCS#12 KDF, MAC, and PBE operations delegated to kryptering.

use bergshamra_core::Error;

#[cfg(test)]
pub const ID_KEY: u8 = kryptering::pkcs12::ID_KEY;
pub const ID_MAC: u8 = kryptering::pkcs12::ID_MAC;

pub fn pkcs12_kdf_sha1(
    id: u8,
    password: &str,
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>, Error> {
    kryptering::pkcs12::derive(
        kryptering::HashAlgorithm::Sha1,
        id,
        password,
        salt,
        iterations,
        output_len,
    )
    .map_err(map_error)
}

pub fn pkcs12_kdf_sha256(
    id: u8,
    password: &str,
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>, Error> {
    kryptering::pkcs12::derive(
        kryptering::HashAlgorithm::Sha256,
        id,
        password,
        salt,
        iterations,
        output_len,
    )
    .map_err(map_error)
}

pub fn decrypt_pbe_sha1_3des(
    ciphertext: &[u8],
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "legacy-algorithms")]
    return kryptering::pkcs12::decrypt_pbe_sha1_3des(ciphertext, password, salt, iterations)
        .map_err(map_error);
    #[cfg(not(feature = "legacy-algorithms"))]
    {
        let _ = (ciphertext, password, salt, iterations);
        Err(Error::UnsupportedAlgorithm(
            "PKCS#12 SHA-1/3DES PBE requires legacy-algorithms".into(),
        ))
    }
}

pub fn decrypt_pbes2_aes256cbc(
    hash: kryptering::HashAlgorithm,
    ciphertext: &[u8],
    password: &str,
    salt: &[u8],
    iterations: u32,
    iv: &[u8],
) -> Result<Vec<u8>, Error> {
    kryptering::pkcs12::decrypt_pbes2_aes256cbc(hash, ciphertext, password, salt, iterations, iv)
        .map_err(map_error)
}

pub fn compute_hmac(
    hash: kryptering::HashAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    kryptering::digest::compute_hmac(hash, key, data).map_err(map_error)
}

fn map_error(error: kryptering::Error) -> Error {
    match error {
        kryptering::Error::Key(message) => Error::Key(message),
        kryptering::Error::Crypto(message) => Error::Crypto(message),
        error @ kryptering::Error::UnsupportedAlgorithm { .. } => {
            Error::UnsupportedAlgorithm(error.to_string())
        }
        kryptering::Error::Io(error) => Error::Io(error),
        #[allow(unreachable_patterns)]
        error => Error::Crypto(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs12_kdf_is_deterministic() {
        let first = pkcs12_kdf_sha1(ID_KEY, "test", b"saltsalt", 2048, 24).unwrap();
        let second = pkcs12_kdf_sha1(ID_KEY, "test", b"saltsalt", 2048, 24).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 24);
    }
}
