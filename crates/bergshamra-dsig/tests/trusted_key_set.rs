//! Verification against a set of trusted keys (ADR-0013).
//!
//! With `trusted_keys_only`, every compatible key in the `KeysManager` is a
//! candidate and the signature is valid when any one of them verifies it.
//! This is what certificate rollover needs: a signer publishes metadata signed
//! with either its old or its new certificate while the verifier has both
//! loaded. `<KeyInfo>` may only change the order in which trusted keys are
//! tried; keys embedded in the document are never used.

use base64::Engine;
use bergshamra_core::{algorithm, Error};
use bergshamra_dsig::{context::DsigContext, verify, VerifyResult};
use bergshamra_keys::{loader, Key, KeysManager};

/// xmlsec test keys. Their certificates chain through `ca2cert.pem`, a
/// SHA-1 intermediate with a 512-bit RSA key, so they are only used by tests
/// that do not validate certificate chains.
const XMLSEC_KEYS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-data/keys/");

/// RSA-2048 / SHA-256 rollover chain accepted by every supported provider;
/// see `tests/data/rollover/generate.sh`.
const ROLLOVER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/rollover/");

/// A time inside both rollover certificates' validity periods.
const DURING_OVERLAP: &str = "2030-01-01T00:00:00";
/// A time after the old rollover certificate expired, while the root and the
/// new certificate are still valid.
const AFTER_OLD_EXPIRED: &str = "2046-01-01T00:00:00";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// DER of a PEM certificate file.
fn cert_der(path: &str) -> Vec<u8> {
    let key = loader::load_x509_cert_pem(&read(path)).expect("certificate");
    key.x509_chain[0].clone()
}

#[derive(Clone, Copy, Debug)]
enum Signer {
    Rsa2048,
    Rsa4096,
    RsaExpired,
    EcP256,
    /// Rollover fixture: the certificate being replaced.
    RolloverOld,
    /// Rollover fixture: the replacement certificate.
    RolloverNew,
}

impl Signer {
    fn cert_path(self) -> String {
        match self {
            Self::Rsa2048 => format!("{XMLSEC_KEYS}rsa/rsa-2048-cert.pem"),
            Self::Rsa4096 => format!("{XMLSEC_KEYS}rsa/rsa-4096-cert.pem"),
            Self::RsaExpired => format!("{XMLSEC_KEYS}rsa/rsa-expired-cert.pem"),
            Self::EcP256 => format!("{XMLSEC_KEYS}ec/ec-prime256v1-cert.pem"),
            Self::RolloverOld => format!("{ROLLOVER}old-cert.pem"),
            Self::RolloverNew => format!("{ROLLOVER}new-cert.pem"),
        }
    }

    fn key_path(self) -> String {
        match self {
            Self::Rsa2048 => format!("{XMLSEC_KEYS}rsa/rsa-2048-key.pem"),
            Self::Rsa4096 => format!("{XMLSEC_KEYS}rsa/rsa-4096-key.pem"),
            Self::RsaExpired => format!("{XMLSEC_KEYS}rsa/rsa-expired-key.pem"),
            Self::EcP256 => format!("{XMLSEC_KEYS}ec/ec-prime256v1-key.pem"),
            Self::RolloverOld => format!("{ROLLOVER}old-key.pem"),
            Self::RolloverNew => format!("{ROLLOVER}new-key.pem"),
        }
    }

    fn signature_method(self) -> &'static str {
        match self {
            Self::EcP256 => algorithm::ECDSA_SHA256,
            _ => algorithm::RSA_SHA256,
        }
    }

    /// The public certificate, as a verifier would load it.
    fn cert(self) -> Key {
        loader::load_x509_cert_pem(&read(&self.cert_path())).expect("certificate")
    }

    fn named_cert(self, name: &str) -> Key {
        self.cert().with_name(name)
    }

    fn cert_der(self) -> Vec<u8> {
        cert_der(&self.cert_path())
    }

    fn cert_b64(self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.cert_der())
    }
}

/// Sign an enveloped metadata-like document with `signer`, placing
/// `key_info` (raw XML, possibly empty) inside the `<ds:Signature>`.
fn sign_document(signer: Signer, key_info: &str) -> String {
    let template = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://eidas.example.eu/metadata">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="{c14n}"/>
      <ds:SignatureMethod Algorithm="{method}"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="{enveloped}"/>
          <ds:Transform Algorithm="{c14n}"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="{sha256}"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>{key_info}
  </ds:Signature>
  <md:Extensions>country metadata</md:Extensions>
</md:EntityDescriptor>"#,
        c14n = algorithm::EXC_C14N,
        method = signer.signature_method(),
        enveloped = algorithm::ENVELOPED_SIGNATURE,
        sha256 = algorithm::SHA256,
    );

    let mut keys = KeysManager::new();
    keys.add_key(loader::load_pem_auto(&read(&signer.key_path()), None).expect("private key"));
    let ctx = DsigContext::new_permissive(keys);
    bergshamra_dsig::sign::sign(&ctx, &template).expect("template should sign")
}

fn x509_key_info(signer: Signer) -> String {
    format!(
        "\n    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        signer.cert_b64()
    )
}

fn key_name_key_info(name: &str) -> String {
    format!("\n    <ds:KeyInfo><ds:KeyName>{name}</ds:KeyName></ds:KeyInfo>")
}

fn manager(keys: impl IntoIterator<Item = Key>) -> KeysManager {
    let mut manager = KeysManager::new();
    manager.add_keys(keys);
    manager
}

/// A secure context whose trusted keys must also chain to the rollover root,
/// validated at `time`, so certificate expiry is enforced per key.
fn anchored_ctx(keys: impl IntoIterator<Item = Key>, time: &str) -> DsigContext {
    let mut manager = manager(keys);
    manager.add_trusted_cert(cert_der(&format!("{ROLLOVER}root.pem")));
    DsigContext::new(manager).with_verification_time(time)
}

#[track_caller]
fn assert_valid_with(result: VerifyResult, signer: Signer) {
    match result {
        VerifyResult::Valid { key_info, .. } => assert_eq!(
            key_info.x509_chain.first(),
            Some(&signer.cert_der()),
            "verified with an unexpected key"
        ),
        VerifyResult::Invalid { reason } => panic!("expected valid, got invalid: {reason}"),
    }
}

#[track_caller]
fn assert_invalid(result: Result<VerifyResult, Error>) -> String {
    match result {
        Ok(VerifyResult::Invalid { reason }) => reason,
        Ok(VerifyResult::Valid { .. }) => panic!("expected the signature to be rejected"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn signer_second_in_manager_verifies_without_key_info() {
    let xml = sign_document(Signer::Rsa2048, "");
    let ctx = DsigContext::new(manager([Signer::Rsa4096.cert(), Signer::Rsa2048.cert()]));

    assert_valid_with(verify::verify(&ctx, &xml).unwrap(), Signer::Rsa2048);
}

#[test]
fn signer_first_in_manager_still_verifies() {
    let xml = sign_document(Signer::Rsa2048, "");
    let ctx = DsigContext::new(manager([Signer::Rsa2048.cert(), Signer::Rsa4096.cert()]));

    assert_valid_with(verify::verify(&ctx, &xml).unwrap(), Signer::Rsa2048);
}

#[test]
fn signer_second_in_manager_verifies_with_inline_signer_certificate() {
    // The eIDAS shape: the document carries its signer certificate. It is only
    // a hint that this trusted key should be tried first.
    let xml = sign_document(Signer::Rsa2048, &x509_key_info(Signer::Rsa2048));
    let ctx = DsigContext::new(manager([Signer::Rsa4096.cert(), Signer::Rsa2048.cert()]));

    assert_valid_with(verify::verify(&ctx, &xml).unwrap(), Signer::Rsa2048);
}

#[test]
fn misleading_key_name_does_not_prevent_verification() {
    // KeyName points at the other trusted key; the signer is still found.
    let xml = sign_document(Signer::Rsa2048, &key_name_key_info("old"));
    let ctx = DsigContext::new(manager([
        Signer::Rsa4096.named_cert("old"),
        Signer::Rsa2048.named_cert("new"),
    ]));

    match verify::verify(&ctx, &xml).unwrap() {
        VerifyResult::Valid { key_info, .. } => {
            assert_eq!(key_info.key_name.as_deref(), Some("new"))
        }
        VerifyResult::Invalid { reason } => panic!("expected valid: {reason}"),
    }
}

#[test]
fn inline_certificate_of_untrusted_signer_is_never_used() {
    // An attacker signs with their own key and embeds the matching certificate.
    let xml = sign_document(Signer::Rsa2048, &x509_key_info(Signer::Rsa2048));
    let ctx = DsigContext::new(manager([Signer::Rsa4096.cert(), Signer::EcP256.cert()]));

    let reason = assert_invalid(verify::verify(&ctx, &xml));
    // Only the one trusted RSA key is a candidate: the EC key is skipped and
    // the inline certificate is not added.
    assert_eq!(reason, "signature value verification failed");
}

#[test]
fn reports_how_many_trusted_keys_were_tried() {
    let xml = sign_document(Signer::Rsa2048, "");
    let ctx = DsigContext::new(manager([Signer::Rsa4096.cert(), Signer::RsaExpired.cert()]));

    let reason = assert_invalid(verify::verify(&ctx, &xml));
    assert_eq!(
        reason,
        "signature value verification failed with each of the 2 trusted keys"
    );
}

#[test]
fn keys_of_other_types_are_skipped() {
    let hmac = loader::load_hmac_key(b"an-unrelated-hmac-secret").unwrap();
    let xml = sign_document(Signer::Rsa2048, "");
    let ctx = DsigContext::new(manager([
        Signer::EcP256.cert(),
        hmac,
        Signer::Rsa2048.cert(),
    ]));

    assert_valid_with(verify::verify(&ctx, &xml).unwrap(), Signer::Rsa2048);
}

#[test]
fn ecdsa_signature_finds_ec_key_after_rsa_keys() {
    let xml = sign_document(Signer::EcP256, "");
    let ctx = DsigContext::new(manager([
        Signer::Rsa2048.cert(),
        Signer::Rsa4096.cert(),
        Signer::EcP256.cert(),
    ]));

    assert_valid_with(verify::verify(&ctx, &xml).unwrap(), Signer::EcP256);
}

#[test]
fn no_compatible_trusted_key_is_an_error() {
    let xml = sign_document(Signer::Rsa2048, "");
    let ctx = DsigContext::new(manager([Signer::EcP256.cert()]));

    match verify::verify(&ctx, &xml) {
        Err(Error::Key(msg)) => assert!(
            msg.contains("no trusted key in the manager is compatible"),
            "{msg}"
        ),
        other => panic!("expected a key error, got {other:?}"),
    }
}

#[test]
fn empty_manager_is_key_not_found() {
    let xml = sign_document(Signer::Rsa2048, "");
    let ctx = DsigContext::new(KeysManager::new());

    assert!(matches!(
        verify::verify(&ctx, &xml),
        Err(Error::KeyNotFound(_))
    ));
}

#[test]
fn rollover_overlap_accepts_either_certificate_in_either_order() {
    use Signer::{RolloverNew as New, RolloverOld as Old};
    for signer in [Old, New] {
        let xml = sign_document(signer, "");
        for order in [[Old, New], [New, Old]] {
            let ctx = anchored_ctx(order.map(Signer::cert), DURING_OVERLAP);
            match verify::verify(&ctx, &xml) {
                Ok(result) => assert_valid_with(result, signer),
                Err(e) => panic!("signer {signer:?}, order {order:?}: {e}"),
            }
        }
    }
}

#[test]
fn rollover_skips_expired_old_certificate() {
    // The old certificate has expired and is listed first; the document is
    // signed with the new one.
    let xml = sign_document(Signer::RolloverNew, "");
    let ctx = anchored_ctx(
        [Signer::RolloverOld.cert(), Signer::RolloverNew.cert()],
        AFTER_OLD_EXPIRED,
    );

    assert_valid_with(verify::verify(&ctx, &xml).unwrap(), Signer::RolloverNew);
}

#[test]
fn rollover_rejects_document_signed_with_expired_certificate() {
    let xml = sign_document(Signer::RolloverOld, "");
    let ctx = anchored_ctx(
        [Signer::RolloverOld.cert(), Signer::RolloverNew.cert()],
        AFTER_OLD_EXPIRED,
    );

    let reason = assert_invalid(verify::verify(&ctx, &xml));
    assert_eq!(
        reason,
        "signature value verification failed with each of the 2 trusted keys \
         (1 rejected before the signature check)"
    );
}

#[test]
fn single_expired_trusted_key_keeps_the_chain_error() {
    let xml = sign_document(Signer::RolloverOld, "");
    let ctx = anchored_ctx([Signer::RolloverOld.cert()], AFTER_OLD_EXPIRED);

    match verify::verify(&ctx, &xml) {
        Err(Error::Certificate(msg)) => assert!(msg.contains("expired"), "{msg}"),
        other => panic!("expected the expired certificate's chain error, got {other:?}"),
    }
}

#[test]
fn trusted_keys_must_chain_to_configured_anchor() {
    // With an anchor that issued none of the trusted keys, no candidate passes
    // the X.509 policy, even though the signer's key is loaded.
    let xml = sign_document(Signer::RolloverNew, "");
    let mut keys = manager([Signer::RolloverOld.cert(), Signer::RolloverNew.cert()]);
    keys.add_trusted_cert(Signer::Rsa2048.cert_der());
    let ctx = DsigContext::new(keys).with_verification_time(DURING_OVERLAP);

    match verify::verify(&ctx, &xml) {
        Err(Error::Certificate(_)) => {}
        other => panic!("expected a chain error, got {other:?}"),
    }
}

#[test]
fn tampered_document_fails_for_every_key() {
    let xml = sign_document(Signer::Rsa2048, "").replace("country metadata", "forged metadata");
    let ctx = DsigContext::new(manager([Signer::Rsa4096.cert(), Signer::Rsa2048.cert()]));

    let reason = assert_invalid(verify::verify(&ctx, &xml));
    assert!(reason.contains("Reference digest failed"), "{reason}");
}
