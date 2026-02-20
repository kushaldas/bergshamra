#![forbid(unsafe_code)]

//! BER parsing of PKCS#12 (PFX) structures (RFC 7292).
//!
//! Uses `yasna::parse_ber` since PKCS#12 files use BER encoding, not strict DER.

use bergshamra_core::Error;
use yasna::models::ObjectIdentifier;
use yasna::{ASN1Error, ASN1ErrorKind, BERReader, Tag};

use crate::kdf;
use crate::Pkcs12Contents;

// ── OID constants ──────────────────────────────────────────────────────────

// Content types (PKCS#7)
const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];

// Bag types (PKCS#12)
const OID_PKCS8_SHROUDED_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
const OID_CERT_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];

// Certificate type
const OID_X509_CERTIFICATE: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];

// PBE algorithms
const OID_PBE_SHA1_3DES: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 3];
const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];

// Cipher
const OID_AES_256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];

// Hash / HMAC
const OID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];

fn oid(components: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(components)
}

// ── Algorithm types ────────────────────────────────────────────────────────

#[derive(Debug)]
enum EncryptionAlgorithm {
    PbeSha1And3Des {
        salt: Vec<u8>,
        iterations: u32,
    },
    Pbes2 {
        pbkdf2_salt: Vec<u8>,
        pbkdf2_iterations: u32,
        pbkdf2_prf: PrfAlgorithm,
        aes_iv: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy)]
enum PrfAlgorithm {
    HmacSha1,
    HmacSha256,
}

#[derive(Debug, Clone, Copy)]
enum MacHashAlgorithm {
    Sha1,
    Sha256,
}

// ── Parsed structures ──────────────────────────────────────────────────────

struct MacData {
    digest_algorithm: MacHashAlgorithm,
    digest_value: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
}

enum SafeBag {
    ShroudedKeyBag {
        algorithm: EncryptionAlgorithm,
        ciphertext: Vec<u8>,
    },
    CertBag {
        cert_der: Vec<u8>,
    },
    Other,
}

// ── Top-level parser ───────────────────────────────────────────────────────

pub fn parse_pfx(data: &[u8], password: &str) -> Result<Pkcs12Contents, Error> {
    let (auth_safe_data, mac_data) = yasna::parse_ber(data, |r| {
        r.read_sequence(|r| {
            // version
            let version = r.next().read_u32()?;
            if version != 3 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }

            // authSafe ContentInfo
            let auth_safe_data = parse_content_info_data(r.next())?;

            // optional macData
            let mac_data = r.read_optional(parse_mac_data)?;

            Ok((auth_safe_data, mac_data))
        })
    })
    .map_err(|e| Error::Key(format!("failed to parse PKCS#12 PFX: {e}")))?;

    // Verify MAC if present
    if let Some(ref mac) = mac_data {
        verify_mac(mac, &auth_safe_data, password)?;
    }

    // Parse the authSafe contents (SEQUENCE OF ContentInfo)
    let content_infos = yasna::parse_ber(&auth_safe_data, |r| {
        r.collect_sequence_of(parse_content_info_inner)
    })
    .map_err(|e| Error::Key(format!("failed to parse authSafe contents: {e}")))?;

    // Process each ContentInfo to extract bags
    let bmp_password = kdf::password_to_bmp(password);
    let mut private_keys = Vec::new();
    let mut certificates = Vec::new();

    for ci in content_infos {
        let bags_data = match ci {
            ContentInfoInner::Data(data) => data,
            ContentInfoInner::EncryptedData { algorithm, ciphertext } => {
                decrypt_data(&algorithm, &ciphertext, password, &bmp_password)?
            }
        };

        // Parse SafeBags from the decrypted data
        let bags = yasna::parse_ber(&bags_data, |r| r.collect_sequence_of(parse_safe_bag))
            .map_err(|e| Error::Key(format!("failed to parse SafeBags: {e}")))?;

        for bag in bags {
            match bag {
                SafeBag::ShroudedKeyBag { algorithm, ciphertext } => {
                    let pkcs8_der =
                        decrypt_data(&algorithm, &ciphertext, password, &bmp_password)?;
                    private_keys.push(pkcs8_der);
                }
                SafeBag::CertBag { cert_der } => {
                    certificates.push(cert_der);
                }
                SafeBag::Other => {}
            }
        }
    }

    Ok(Pkcs12Contents {
        private_keys,
        certificates,
    })
}

// ── ContentInfo parsing ────────────────────────────────────────────────────

/// Parse top-level ContentInfo that wraps the authSafe: expects OID = data,
/// extracts the OCTET STRING payload.
fn parse_content_info_data(r: BERReader) -> Result<Vec<u8>, ASN1Error> {
    r.read_sequence(|r| {
        let content_type = r.next().read_oid()?;
        if content_type != oid(OID_DATA) {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        // [0] EXPLICIT OCTET STRING
        let data = r
            .next()
            .read_tagged(Tag::context(0), |r| r.read_bytes())?;
        Ok(data)
    })
}

enum ContentInfoInner {
    Data(Vec<u8>),
    EncryptedData {
        algorithm: EncryptionAlgorithm,
        ciphertext: Vec<u8>,
    },
}

/// Parse a ContentInfo inside the authSafe SEQUENCE.
fn parse_content_info_inner(r: BERReader) -> Result<ContentInfoInner, ASN1Error> {
    r.read_sequence(|r| {
        let content_type = r.next().read_oid()?;

        if content_type == oid(OID_DATA) {
            let data = r
                .next()
                .read_tagged(Tag::context(0), |r| r.read_bytes())?;
            Ok(ContentInfoInner::Data(data))
        } else if content_type == oid(OID_ENCRYPTED_DATA) {
            // [0] EXPLICIT EncryptedData
            r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    // version
                    let _version = r.next().read_u32()?;
                    // EncryptedContentInfo
                    r.next().read_sequence(|r| {
                        // contentType (should be data)
                        let _ct = r.next().read_oid()?;
                        // contentEncryptionAlgorithm
                        let algorithm = parse_algorithm_identifier(r.next())?;
                        // [0] IMPLICIT encrypted content
                        let ciphertext = r
                            .next()
                            .read_tagged_implicit(Tag::context(0), |r| r.read_bytes())?;
                        Ok(ContentInfoInner::EncryptedData {
                            algorithm,
                            ciphertext,
                        })
                    })
                })
            })
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    })
}

// ── SafeBag parsing ────────────────────────────────────────────────────────

fn parse_safe_bag(r: BERReader) -> Result<SafeBag, ASN1Error> {
    r.read_sequence(|r| {
        let bag_type = r.next().read_oid()?;

        if bag_type == oid(OID_PKCS8_SHROUDED_KEY_BAG) {
            // [0] EXPLICIT EncryptedPrivateKeyInfo
            let (algorithm, ciphertext) = r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let algorithm = parse_algorithm_identifier(r.next())?;
                    let ciphertext = r.next().read_bytes()?;
                    Ok((algorithm, ciphertext))
                })
            })?;
            // Skip optional attributes
            let _attrs = r.read_optional(|r| {
                r.read_set_of(|r| {
                    // Read and discard each attribute SEQUENCE
                    r.read_sequence(|r| {
                        let _oid = r.next().read_oid()?;
                        r.next().read_set_of(|r| { let _ = r.read_der()?; Ok(()) })?;
                        Ok(())
                    })
                })
            })?;
            Ok(SafeBag::ShroudedKeyBag {
                algorithm,
                ciphertext,
            })
        } else if bag_type == oid(OID_CERT_BAG) {
            // [0] EXPLICIT CertBag
            let cert_der = r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let cert_type = r.next().read_oid()?;
                    if cert_type != oid(OID_X509_CERTIFICATE) {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    // [0] EXPLICIT OCTET STRING containing DER-encoded certificate
                    let cert_data = r
                        .next()
                        .read_tagged(Tag::context(0), |r| r.read_bytes())?;
                    Ok(cert_data)
                })
            })?;
            // Skip optional attributes
            let _attrs = r.read_optional(|r| {
                r.read_set_of(|r| {
                    r.read_sequence(|r| {
                        let _oid = r.next().read_oid()?;
                        r.next().read_set_of(|r| { let _ = r.read_der()?; Ok(()) })?;
                        Ok(())
                    })
                })
            })?;
            Ok(SafeBag::CertBag { cert_der })
        } else {
            // Skip unknown bag types: read and discard tag [0] value and optional attrs
            let _value = r.next().read_tagged(Tag::context(0), |r| r.read_der())?;
            let _attrs = r.read_optional(|r| {
                r.read_set_of(|r| {
                    r.read_sequence(|r| {
                        let _oid = r.next().read_oid()?;
                        r.next().read_set_of(|r| { let _ = r.read_der()?; Ok(()) })?;
                        Ok(())
                    })
                })
            })?;
            Ok(SafeBag::Other)
        }
    })
}

// ── AlgorithmIdentifier parsing ────────────────────────────────────────────

fn parse_algorithm_identifier(r: BERReader) -> Result<EncryptionAlgorithm, ASN1Error> {
    r.read_sequence(|r| {
        let alg_oid = r.next().read_oid()?;

        if alg_oid == oid(OID_PBE_SHA1_3DES) {
            // Legacy PBE params: SEQUENCE { salt OCTET STRING, iterations INTEGER }
            r.next().read_sequence(|r| {
                let salt = r.next().read_bytes()?;
                let iterations = r.next().read_u32()?;
                Ok(EncryptionAlgorithm::PbeSha1And3Des { salt, iterations })
            })
        } else if alg_oid == oid(OID_PBES2) {
            // PBES2-params: SEQUENCE { keyDerivationFunc AlgId, encryptionScheme AlgId }
            r.next().read_sequence(|r| {
                // keyDerivationFunc (must be PBKDF2)
                let (pbkdf2_salt, pbkdf2_iterations, pbkdf2_prf) =
                    r.next().read_sequence(|r| {
                        let kdf_oid = r.next().read_oid()?;
                        if kdf_oid != oid(OID_PBKDF2) {
                            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                        }
                        // PBKDF2-params: SEQUENCE { salt, iterationCount, keyLength?, prf? }
                        r.next().read_sequence(|r| {
                            let salt = r.next().read_bytes()?;
                            let iterations = r.next().read_u32()?;

                            // Optional keyLength (INTEGER) — skip if present
                            // Then optional PRF AlgorithmIdentifier
                            // We need to handle: [keyLength], [prf] — both optional
                            let mut prf = PrfAlgorithm::HmacSha1; // default per RFC

                            // Try to read remaining optional fields
                            // keyLength is an INTEGER, prf is a SEQUENCE
                            let remaining = r.read_optional(|r| {
                                // Could be keyLength (INTEGER) or prf (SEQUENCE)
                                r.read_der()
                            })?;

                            if let Some(der_bytes) = remaining {
                                // Check if this looks like an INTEGER (tag 0x02) or SEQUENCE (tag 0x30)
                                if !der_bytes.is_empty() && der_bytes[0] == 0x30 {
                                    // This is the PRF SEQUENCE
                                    prf = parse_prf_from_der(&der_bytes)?;
                                } else {
                                    // This was keyLength, try to read PRF next
                                    if let Some(prf_der) = r.read_optional(|r| r.read_der())? {
                                        prf = parse_prf_from_der(&prf_der)?;
                                    }
                                }
                            }

                            Ok((salt, iterations, prf))
                        })
                    })?;

                // encryptionScheme
                let aes_iv = r.next().read_sequence(|r| {
                    let enc_oid = r.next().read_oid()?;
                    if enc_oid != oid(OID_AES_256_CBC) {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    let iv = r.next().read_bytes()?;
                    Ok(iv)
                })?;

                Ok(EncryptionAlgorithm::Pbes2 {
                    pbkdf2_salt,
                    pbkdf2_iterations,
                    pbkdf2_prf,
                    aes_iv,
                })
            })
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    })
}

/// Parse a PRF AlgorithmIdentifier from raw DER bytes.
fn parse_prf_from_der(der: &[u8]) -> Result<PrfAlgorithm, ASN1Error> {
    yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            let prf_oid = r.next().read_oid()?;
            // Read optional NULL parameter
            let _null = r.read_optional(|r| r.read_null())?;
            if prf_oid == oid(OID_HMAC_SHA256) {
                Ok(PrfAlgorithm::HmacSha256)
            } else if prf_oid == oid(OID_HMAC_SHA1) {
                Ok(PrfAlgorithm::HmacSha1)
            } else {
                Err(ASN1Error::new(ASN1ErrorKind::Invalid))
            }
        })
    })
}

// ── MAC verification ───────────────────────────────────────────────────────

fn parse_mac_data(r: BERReader) -> Result<MacData, ASN1Error> {
    r.read_sequence(|r| {
        // DigestInfo: SEQUENCE { digestAlgorithm, digest }
        let (digest_algorithm, digest_value) = r.next().read_sequence(|r| {
            let alg = r.next().read_sequence(|r| {
                let hash_oid = r.next().read_oid()?;
                // optional NULL
                let _null = r.read_optional(|r| r.read_null())?;
                if hash_oid == oid(OID_SHA256) {
                    Ok(MacHashAlgorithm::Sha256)
                } else if hash_oid == oid(OID_SHA1) {
                    Ok(MacHashAlgorithm::Sha1)
                } else {
                    Err(ASN1Error::new(ASN1ErrorKind::Invalid))
                }
            })?;
            let digest = r.next().read_bytes()?;
            Ok((alg, digest))
        })?;

        let salt = r.next().read_bytes()?;
        let iterations = r.read_optional(|r| r.read_u32())?.unwrap_or(1);

        Ok(MacData {
            digest_algorithm,
            digest_value,
            salt,
            iterations,
        })
    })
}

fn verify_mac(mac: &MacData, auth_safe_data: &[u8], password: &str) -> Result<(), Error> {
    let bmp_password = kdf::password_to_bmp(password);

    let computed = match mac.digest_algorithm {
        MacHashAlgorithm::Sha1 => {
            let mac_key =
                kdf::pkcs12_kdf_sha1(kdf::ID_MAC, &bmp_password, &mac.salt, mac.iterations, 20);
            kdf::compute_hmac_sha1(&mac_key, auth_safe_data)
        }
        MacHashAlgorithm::Sha256 => {
            let mac_key =
                kdf::pkcs12_kdf_sha256(kdf::ID_MAC, &bmp_password, &mac.salt, mac.iterations, 32);
            kdf::compute_hmac_sha256(&mac_key, auth_safe_data)
        }
    };

    if computed != mac.digest_value {
        return Err(Error::Key(
            "PKCS#12 MAC verification failed (wrong password?)".into(),
        ));
    }

    Ok(())
}

// ── Decryption dispatch ────────────────────────────────────────────────────

fn decrypt_data(
    algorithm: &EncryptionAlgorithm,
    ciphertext: &[u8],
    password: &str,
    bmp_password: &[u8],
) -> Result<Vec<u8>, Error> {
    match algorithm {
        EncryptionAlgorithm::PbeSha1And3Des { salt, iterations } => {
            kdf::decrypt_pbe_sha1_3des(ciphertext, bmp_password, salt, *iterations)
        }
        EncryptionAlgorithm::Pbes2 {
            pbkdf2_salt,
            pbkdf2_iterations,
            pbkdf2_prf,
            aes_iv,
        } => match pbkdf2_prf {
            PrfAlgorithm::HmacSha256 => kdf::decrypt_pbes2_aes256cbc(
                ciphertext,
                password,
                pbkdf2_salt,
                *pbkdf2_iterations,
                aes_iv,
            ),
            PrfAlgorithm::HmacSha1 => kdf::decrypt_pbes2_aes256cbc_sha1(
                ciphertext,
                password,
                pbkdf2_salt,
                *pbkdf2_iterations,
                aes_iv,
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rsa_2048_p12() {
        let p12_path = std::path::Path::new("../../test-data/keys/rsa/rsa-2048-key.p12");
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let contents = parse_pfx(&data, "secret123").expect("parse_pfx should succeed");

        assert_eq!(
            contents.private_keys.len(),
            1,
            "expected 1 private key"
        );
        assert!(
            !contents.certificates.is_empty(),
            "expected at least 1 certificate"
        );

        // Verify the private key looks like valid PKCS#8 DER (starts with SEQUENCE tag 0x30)
        assert_eq!(contents.private_keys[0][0], 0x30);
    }

    #[test]
    fn test_parse_ec_p256_p12() {
        let p12_path = std::path::Path::new("../../test-data/keys/ec/ec-prime256v1-key.p12");
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let contents = parse_pfx(&data, "secret123").expect("parse_pfx should succeed");

        assert_eq!(contents.private_keys.len(), 1);
        assert!(!contents.certificates.is_empty());
        assert_eq!(contents.private_keys[0][0], 0x30);
    }

    #[test]
    fn test_parse_rsa_4096_p12() {
        let p12_path = std::path::Path::new("../../test-data/keys/rsa/rsa-4096-key.p12");
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let contents = parse_pfx(&data, "secret123").expect("parse_pfx should succeed");

        assert_eq!(contents.private_keys.len(), 1);
        assert!(!contents.certificates.is_empty());
    }

    #[test]
    fn test_wrong_password_fails_mac() {
        let p12_path = std::path::Path::new("../../test-data/keys/rsa/rsa-2048-key.p12");
        if !p12_path.exists() {
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let err = parse_pfx(&data, "wrong_password").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("MAC verification failed"),
            "expected MAC error, got: {msg}"
        );
    }
}
