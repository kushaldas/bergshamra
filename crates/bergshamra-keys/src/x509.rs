#![forbid(unsafe_code)]

//! X.509 certificate chain validation.
//!
//! Validates leaf certificates against trusted roots with optional intermediate
//! certificates. Supports time override, CRL checking, and chain building.

use bergshamra_core::Error;
use der::{Decode, Encode};
use x509_cert::Certificate;

/// Configuration for X.509 certificate chain validation.
pub struct CertValidationConfig<'a> {
    /// Trusted CA certificates (DER-encoded).
    pub trusted_certs: &'a [Vec<u8>],
    /// Untrusted intermediate certificates (DER-encoded).
    pub untrusted_certs: &'a [Vec<u8>],
    /// CRLs (DER-encoded).
    pub crls: &'a [Vec<u8>],
    /// Override verification time (format: "YYYY-MM-DD+HH:MM:SS").
    pub verification_time: Option<&'a str>,
    /// Skip time validity checks.
    pub skip_time_checks: bool,
}

/// Validate a certificate chain from a leaf cert to a trusted root.
///
/// `leaf_der` is the DER-encoded leaf certificate.
/// `additional_certs` are extra certs from the XML (the full x509_chain from KeyInfo).
/// Returns `Ok(())` if the chain is valid, `Err` otherwise.
pub fn validate_cert_chain(
    leaf_der: &[u8],
    additional_certs: &[Vec<u8>],
    config: &CertValidationConfig<'_>,
) -> Result<(), Error> {
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| Error::Certificate(format!("failed to parse leaf certificate: {e}")))?;

    // Collect all available certs for chain building (not trusted):
    // additional certs from XML + untrusted intermediates
    let mut available: Vec<(Certificate, Vec<u8>)> = Vec::new();
    for der in additional_certs {
        if der == leaf_der {
            continue; // skip the leaf itself
        }
        if let Ok(c) = Certificate::from_der(der) {
            available.push((c, der.clone()));
        }
    }
    for der in config.untrusted_certs {
        if let Ok(c) = Certificate::from_der(der) {
            available.push((c, der.clone()));
        }
    }

    // Parse trusted certs
    let mut trusted: Vec<(Certificate, Vec<u8>)> = Vec::new();
    for der in config.trusted_certs {
        if let Ok(c) = Certificate::from_der(der) {
            trusted.push((c, der.clone()));
        }
    }

    if trusted.is_empty() {
        return Err(Error::Certificate(
            "no trusted certificates available".into(),
        ));
    }

    // Check time validity of leaf cert
    if !config.skip_time_checks {
        let verif_time = resolve_verification_time(config.verification_time)?;
        check_cert_time_validity(&leaf, &verif_time)?;
    }

    // Build chain from leaf to a trusted root
    build_and_verify_chain(&leaf, leaf_der, &available, &trusted, config)?;

    // Check CRLs against the leaf cert
    if !config.crls.is_empty() {
        check_crls(&leaf, config.crls, config.verification_time)?;
    }

    Ok(())
}

/// Parse a verification time string into a `der::DateTime`.
/// Format: "YYYY-MM-DD+HH:MM:SS"
fn parse_verification_time(s: &str) -> Result<der::DateTime, Error> {
    // Format: "2025-12-10+00:00:00"
    let s = s.trim();
    if s.len() < 19 {
        return Err(Error::Certificate(format!(
            "invalid verification time format: {s}"
        )));
    }

    let year: u16 = s[0..4]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid year in time: {s}")))?;
    let month: u8 = s[5..7]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid month in time: {s}")))?;
    let day: u8 = s[8..10]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid day in time: {s}")))?;

    // Separator can be '+' or 'T'
    let rest = &s[11..];
    let hour: u8 = rest[0..2]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid hour in time: {s}")))?;
    let min: u8 = rest[3..5]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid minute in time: {s}")))?;
    let sec: u8 = rest[6..8]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid second in time: {s}")))?;

    der::DateTime::new(year, month, day, hour, min, sec)
        .map_err(|e| Error::Certificate(format!("invalid verification time: {e}")))
}

/// Get the current time as a `der::DateTime`, or use the override.
fn resolve_verification_time(
    override_time: Option<&str>,
) -> Result<der::DateTime, Error> {
    if let Some(time_str) = override_time {
        return parse_verification_time(time_str);
    }

    // Use current system time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Certificate(format!("system time error: {e}")))?;

    der::DateTime::from_unix_duration(now)
        .map_err(|e| Error::Certificate(format!("time conversion error: {e}")))
}

/// Convert an x509_cert Time to der::DateTime.
fn x509_time_to_datetime(t: &x509_cert::time::Time) -> Result<der::DateTime, Error> {
    Ok(t.to_date_time())
}

/// Check if a certificate is valid at the given time.
fn check_cert_time_validity(
    cert: &Certificate,
    verif_time: &der::DateTime,
) -> Result<(), Error> {
    let not_before = x509_time_to_datetime(&cert.tbs_certificate.validity.not_before)?;
    let not_after = x509_time_to_datetime(&cert.tbs_certificate.validity.not_after)?;

    if *verif_time < not_before {
        return Err(Error::Certificate(format!(
            "certificate is not yet valid (notBefore: {not_before:?})"
        )));
    }
    if *verif_time > not_after {
        return Err(Error::Certificate(format!(
            "certificate has expired (notAfter: {not_after:?})"
        )));
    }

    Ok(())
}

/// Build a chain from the leaf to a trusted root and verify signatures along the way.
fn build_and_verify_chain(
    leaf: &Certificate,
    leaf_der: &[u8],
    available: &[(Certificate, Vec<u8>)],
    trusted: &[(Certificate, Vec<u8>)],
    config: &CertValidationConfig<'_>,
) -> Result<(), Error> {
    // Check if the leaf itself is a trusted cert (self-signed trusted)
    for (tc, tc_der) in trusted {
        if tc_der == leaf_der {
            // Leaf is directly trusted — verify self-signature
            verify_cert_signature(leaf, &tc.tbs_certificate.subject_public_key_info)?;
            return Ok(());
        }
    }

    // Try to find an issuer for the leaf among trusted certs first
    let leaf_issuer_der = leaf.tbs_certificate.issuer.to_der().unwrap_or_default();
    let leaf_subject_der = leaf.tbs_certificate.subject.to_der().unwrap_or_default();

    // Self-signed but not trusted
    if leaf_issuer_der == leaf_subject_der {
        // Check if any trusted cert has the same public key
        for (tc, _) in trusted {
            let tc_subject_der = tc.tbs_certificate.subject.to_der().unwrap_or_default();
            if tc_subject_der == leaf_issuer_der {
                // Match by subject — now verify signature
                if verify_cert_signature(leaf, &tc.tbs_certificate.subject_public_key_info).is_ok()
                {
                    return Ok(());
                }
            }
        }
        return Err(Error::Certificate(
            "self-signed certificate not in trusted store".into(),
        ));
    }

    // Walk the chain: find issuer, verify, repeat until we reach a trusted root
    let mut current = leaf.clone();
    let mut visited: Vec<Vec<u8>> = vec![leaf_der.to_vec()];
    let max_depth = 10;

    for _ in 0..max_depth {
        let issuer_der = current
            .tbs_certificate
            .issuer
            .to_der()
            .unwrap_or_default();

        // Try to find issuer in trusted certs
        let mut found_trusted = false;
        for (tc, _tc_der) in trusted {
            let tc_subject_der = tc.tbs_certificate.subject.to_der().unwrap_or_default();
            if tc_subject_der == issuer_der {
                // Found a potential issuer — verify signature
                if verify_cert_signature(
                    &current,
                    &tc.tbs_certificate.subject_public_key_info,
                )
                .is_ok()
                {
                    // Check time validity of the trusted cert too
                    if !config.skip_time_checks {
                        if let Ok(verif_time) =
                            resolve_verification_time(config.verification_time)
                        {
                            check_cert_time_validity(tc, &verif_time)?;
                        }
                    }
                    found_trusted = true;
                    break;
                }
            }
        }

        if found_trusted {
            return Ok(());
        }

        // Try to find issuer in available (untrusted) certs
        let mut found_intermediate = false;
        for (ic, ic_der) in available {
            if visited.contains(ic_der) {
                continue; // avoid cycles
            }
            let ic_subject_der = ic.tbs_certificate.subject.to_der().unwrap_or_default();
            if ic_subject_der == issuer_der {
                // Verify signature
                if verify_cert_signature(
                    &current,
                    &ic.tbs_certificate.subject_public_key_info,
                )
                .is_ok()
                {
                    // Check time validity
                    if !config.skip_time_checks {
                        if let Ok(verif_time) =
                            resolve_verification_time(config.verification_time)
                        {
                            check_cert_time_validity(ic, &verif_time)?;
                        }
                    }
                    visited.push(ic_der.clone());
                    current = ic.clone();
                    found_intermediate = true;
                    break;
                }
            }
        }

        if !found_intermediate {
            return Err(Error::Certificate(format!(
                "cannot find issuer certificate (incomplete chain)"
            )));
        }
    }

    Err(Error::Certificate(
        "certificate chain too long".into(),
    ))
}

/// Verify a certificate's signature using the issuer's SPKI.
fn verify_cert_signature(
    cert: &Certificate,
    issuer_spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<(), Error> {
    // Get the TBS DER bytes for verification
    let tbs_der = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::Certificate(format!("failed to encode TBS: {e}")))?;

    // Get the signature bytes
    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Certificate("no signature bytes".into()))?;

    // Get the signature algorithm OID
    let sig_alg_oid = &cert.signature_algorithm.oid;

    // Encode the issuer's SPKI to DER for key parsing
    let spki_der = issuer_spki
        .to_der()
        .map_err(|e| Error::Certificate(format!("failed to encode issuer SPKI: {e}")))?;

    // RSA algorithms
    // sha1WithRSAEncryption: 1.2.840.113549.1.1.5
    // sha256WithRSAEncryption: 1.2.840.113549.1.1.11
    // RSA algorithms
    // md5WithRSAEncryption: 1.2.840.113549.1.1.4
    // sha1WithRSAEncryption: 1.2.840.113549.1.1.5
    // sha224WithRSAEncryption: 1.2.840.113549.1.1.14
    // sha256WithRSAEncryption: 1.2.840.113549.1.1.11
    // sha384WithRSAEncryption: 1.2.840.113549.1.1.12
    // sha512WithRSAEncryption: 1.2.840.113549.1.1.13
    const MD5_RSA: &str = "1.2.840.113549.1.1.4";
    const SHA1_RSA: &str = "1.2.840.113549.1.1.5";
    const SHA224_RSA: &str = "1.2.840.113549.1.1.14";
    const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
    const SHA384_RSA: &str = "1.2.840.113549.1.1.12";
    const SHA512_RSA: &str = "1.2.840.113549.1.1.13";

    // ECDSA algorithms
    // ecdsaWithSHA1: 1.2.840.10045.4.1
    // ecdsaWithSHA256: 1.2.840.10045.4.3.2
    // ecdsaWithSHA384: 1.2.840.10045.4.3.3
    // ecdsaWithSHA512: 1.2.840.10045.4.3.4
    const ECDSA_SHA1: &str = "1.2.840.10045.4.1";
    const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
    const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
    const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";

    let oid_str = sig_alg_oid.to_string();

    match oid_str.as_str() {
        MD5_RSA => verify_rsa_signature::<md5::Md5>(&spki_der, &tbs_der, sig_bytes),
        SHA1_RSA => verify_rsa_signature::<sha1::Sha1>(&spki_der, &tbs_der, sig_bytes),
        SHA224_RSA => verify_rsa_signature::<sha2::Sha224>(&spki_der, &tbs_der, sig_bytes),
        SHA256_RSA => verify_rsa_signature::<sha2::Sha256>(&spki_der, &tbs_der, sig_bytes),
        SHA384_RSA => verify_rsa_signature::<sha2::Sha384>(&spki_der, &tbs_der, sig_bytes),
        SHA512_RSA => verify_rsa_signature::<sha2::Sha512>(&spki_der, &tbs_der, sig_bytes),
        ECDSA_SHA1 | ECDSA_SHA256 | ECDSA_SHA384 | ECDSA_SHA512 => {
            verify_ecdsa_signature_auto_curve(&spki_der, &tbs_der, sig_bytes, issuer_spki)
        }
        _ => Err(Error::Certificate(format!(
            "unsupported signature algorithm: {oid_str}"
        ))),
    }
}

/// Verify an RSA PKCS#1 v1.5 signature.
fn verify_rsa_signature<D>(
    issuer_spki_der: &[u8],
    tbs_der: &[u8],
    signature: &[u8],
) -> Result<(), Error>
where
    D: digest::Digest + digest::const_oid::AssociatedOid,
    rsa::pkcs1v15::VerifyingKey<D>: signature::Verifier<rsa::pkcs1v15::Signature>,
{
    use spki::DecodePublicKey;

    let public_key = rsa::RsaPublicKey::from_public_key_der(issuer_spki_der)
        .map_err(|e| Error::Certificate(format!("invalid RSA public key: {e}")))?;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<D>::new(public_key);
    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|e| Error::Certificate(format!("invalid RSA signature: {e}")))?;

    use signature::Verifier;
    verifying_key
        .verify(tbs_der, &sig)
        .map_err(|e| Error::Certificate(format!("certificate signature verification failed: {e}")))
}

/// Auto-detect EC curve from SPKI and verify ECDSA signature.
fn verify_ecdsa_signature_auto_curve(
    issuer_spki_der: &[u8],
    tbs_der: &[u8],
    signature: &[u8],
    issuer_spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<(), Error> {
    // Detect curve from SPKI algorithm parameters
    // EC SPKI has algorithm = id-ecPublicKey (1.2.840.10045.2.1)
    // and parameters = curve OID
    let curve_oid = issuer_spki.algorithm.parameters.as_ref()
        .and_then(|p| der::asn1::ObjectIdentifier::from_der(p.value()).ok())
        .map(|oid| oid.to_string())
        .unwrap_or_default();

    // P-256: 1.2.840.10045.3.1.7
    // P-384: 1.3.132.0.34
    // P-521: 1.3.132.0.35
    match curve_oid.as_str() {
        "1.2.840.10045.3.1.7" => verify_ecdsa_p256_signature(issuer_spki_der, tbs_der, signature),
        "1.3.132.0.34" => verify_ecdsa_p384_signature(issuer_spki_der, tbs_der, signature),
        "1.3.132.0.35" => verify_ecdsa_p521_signature(issuer_spki_der, tbs_der, signature),
        _ => {
            // Try all curves as fallback
            verify_ecdsa_p256_signature(issuer_spki_der, tbs_der, signature)
                .or_else(|_| verify_ecdsa_p384_signature(issuer_spki_der, tbs_der, signature))
                .or_else(|_| verify_ecdsa_p521_signature(issuer_spki_der, tbs_der, signature))
        }
    }
}

/// Verify an ECDSA P-256 signature (DER-encoded).
fn verify_ecdsa_p256_signature(
    issuer_spki_der: &[u8],
    tbs_der: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    use spki::DecodePublicKey;

    let vk = p256::ecdsa::VerifyingKey::from_public_key_der(issuer_spki_der)
        .map_err(|e| Error::Certificate(format!("invalid EC P-256 key: {e}")))?;

    // Cert signatures are DER-encoded
    let sig = p256::ecdsa::DerSignature::from_bytes(signature)
        .map_err(|e| Error::Certificate(format!("invalid ECDSA signature: {e}")))?;

    use signature::Verifier;
    vk.verify(tbs_der, &sig)
        .map_err(|e| Error::Certificate(format!("certificate signature verification failed: {e}")))
}

/// Verify an ECDSA P-384 signature (DER-encoded).
fn verify_ecdsa_p384_signature(
    issuer_spki_der: &[u8],
    tbs_der: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    use spki::DecodePublicKey;

    let vk = p384::ecdsa::VerifyingKey::from_public_key_der(issuer_spki_der)
        .map_err(|e| Error::Certificate(format!("invalid EC P-384 key: {e}")))?;

    let sig = p384::ecdsa::DerSignature::from_bytes(signature)
        .map_err(|e| Error::Certificate(format!("invalid ECDSA signature: {e}")))?;

    use signature::Verifier;
    vk.verify(tbs_der, &sig)
        .map_err(|e| Error::Certificate(format!("certificate signature verification failed: {e}")))
}

/// Verify an ECDSA P-521 signature (DER-encoded).
fn verify_ecdsa_p521_signature(
    issuer_spki_der: &[u8],
    tbs_der: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    // Parse the SPKI to get the public key bitstring
    let spki = spki::SubjectPublicKeyInfoRef::try_from(issuer_spki_der)
        .map_err(|e| Error::Certificate(format!("invalid SPKI DER: {e}")))?;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| Error::Certificate(format!("invalid EC P-521 key: {e}")))?;

    let sig = p521::ecdsa::DerSignature::from_bytes(signature)
        .map_err(|e| Error::Certificate(format!("invalid ECDSA signature: {e}")))?;
    // Convert DER signature to normalized form for verification
    let sig: p521::ecdsa::Signature = sig.try_into()
        .map_err(|e: p521::ecdsa::Error| Error::Certificate(format!("ECDSA signature conversion: {e}")))?;

    use signature::Verifier;
    vk.verify(tbs_der, &sig)
        .map_err(|e| Error::Certificate(format!("certificate signature verification failed: {e}")))
}

/// Check leaf certificate against CRLs.
///
/// Always checks all CRLs regardless of CRL time validity (skip-time behavior).
/// When a cert serial is found in a CRL, it's considered revoked only if the
/// revocation date is at or before the verification time.
fn check_crls(
    leaf: &Certificate,
    crls: &[Vec<u8>],
    verification_time_str: Option<&str>,
) -> Result<(), Error> {
    use x509_cert::crl::CertificateList;

    let leaf_serial = &leaf.tbs_certificate.serial_number;
    let verif_time = resolve_verification_time(verification_time_str)?;

    for crl_der in crls {
        let crl = CertificateList::from_der(crl_der)
            .map_err(|e| Error::Certificate(format!("failed to parse CRL: {e}")))?;

        // Check if the leaf cert's serial is in the revoked list
        if let Some(ref revoked_certs) = crl.tbs_cert_list.revoked_certificates {
            for revoked in revoked_certs {
                if revoked.serial_number == *leaf_serial {
                    // Check revocation date against verification time
                    let revocation_time = x509_time_to_datetime(&revoked.revocation_date)?;
                    if verif_time >= revocation_time {
                        return Err(Error::Certificate(
                            "certificate has been revoked (found in CRL)".into(),
                        ));
                    }
                    // Revocation date is after verification time — cert wasn't revoked yet
                }
            }
        }
    }

    Ok(())
}
