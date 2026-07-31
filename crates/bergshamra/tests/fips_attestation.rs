#![cfg(feature = "fips")]

#[test]
fn document_crypto_requires_initialization_then_attests() {
    let error = bergshamra::crypto::digest::digest(
        bergshamra::core::algorithm::SHA256,
        b"must fail before initialization",
    )
    .expect_err("FIPS document crypto must not initialize lazily");
    assert!(
        matches!(
            error,
            bergshamra::core::Error::Crypto(ref message)
                if message.contains("has not been explicitly initialized")
        ),
        "unexpected pre-initialization error: {error:?}"
    );

    let info = bergshamra::initialize_backend().expect("selected FIPS provider initialization");
    assert_eq!(info.fips, bergshamra::FipsStatus::Active);

    let digest = bergshamra::crypto::digest::digest(
        bergshamra::core::algorithm::SHA256,
        b"approved operation",
    )
    .expect("approved digest after initialization");
    assert_eq!(digest.len(), 32);
}
