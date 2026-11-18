//! Opt-in, byte-bounded retention of each verified Reference's digested octets.
use base64::Engine;
use bergshamra_core::{algorithm, ns};
use bergshamra_dsig::{
    sign,
    verify::{verify, verify_all, verify_with_manifests, ManifestLimits},
    DsigContext, VerifiedReference, VerifyResult,
};
use bergshamra_keys::{loader, KeysManager};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const DETACHED: &[u8] = b"detached payload\x00with binary bytes";

fn context(retain: Option<usize>, resource: Option<&PathBuf>) -> DsigContext {
    let mut keys = KeysManager::new();
    keys.add_key(loader::load_hmac_key(b"reference-octets-tests-real-hmac-key").unwrap());
    let mut ctx = DsigContext::new_permissive(keys);
    ctx.retain_reference_octets = retain;
    if let Some(path) = resource {
        ctx.url_maps
            .push(("urn:payload".into(), path.display().to_string()));
    }
    ctx
}
fn reference(uri: &str, transforms: &str, digest: &str) -> String {
    format!(
        r#"<ds:Reference URI="{uri}">{transforms}<ds:DigestMethod Algorithm="{}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"#,
        algorithm::SHA256
    )
}
fn digest(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(bergshamra_crypto::digest::digest(algorithm::SHA256, bytes).unwrap())
}
const ENVELOPED: &str = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>"#;
const EXC: &str = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>"#;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bergshamra-reference-octets-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A signature with an enveloped whole-document reference, a same-document
/// ID reference (streaming fast-path shape) and a detached URL-mapped resource.
fn signed(resource: &PathBuf) -> String {
    let template = format!(
        r##"<Root xmlns:ds="{}"><Item Id="item" xmlns:x="urn:unused"><Value>42</Value></Item><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{}"/><ds:SignatureMethod Algorithm="{}"/>{}{}{}</ds:SignedInfo><ds:SignatureValue/></ds:Signature></Root>"##,
        ns::DSIG,
        algorithm::EXC_C14N,
        algorithm::HMAC_SHA256,
        reference("", ENVELOPED, ""),
        reference("#item", EXC, ""),
        reference("urn:payload", "", ""),
    );
    sign::sign(&context(None, Some(resource)), &template).unwrap()
}
fn references(result: VerifyResult) -> Vec<VerifiedReference> {
    match result {
        VerifyResult::Valid { references, .. } => references,
        VerifyResult::Invalid { reason } => panic!("expected a valid signature: {reason}"),
    }
}
fn declared_digests(xml: &str) -> Vec<String> {
    xml.split("<ds:DigestValue>")
        .skip(1)
        .map(|rest| rest[..rest.find("</ds:DigestValue>").unwrap()].to_owned())
        .collect()
}

#[test]
fn retention_is_off_by_default() {
    let temp = Temp::new();
    let resource = temp.0.join("payload.bin");
    fs::write(&resource, DETACHED).unwrap();
    let xml = signed(&resource);
    assert_eq!(context(None, None).retain_reference_octets, None);
    for reference in references(verify(&context(None, Some(&resource)), &xml).unwrap()) {
        assert!(reference.digest_verified);
        assert_eq!(reference.digested_octets, None, "{}", reference.uri);
    }
}

#[test]
fn retained_octets_are_exactly_the_digested_bytes() {
    let temp = Temp::new();
    let resource = temp.0.join("payload.bin");
    fs::write(&resource, DETACHED).unwrap();
    let xml = signed(&resource);
    let checked = references(verify(&context(Some(1 << 20), Some(&resource)), &xml).unwrap());
    let declared = declared_digests(&xml);
    assert_eq!(checked.len(), 3);
    for (reference, declared) in checked.iter().zip(&declared) {
        let octets = reference.digested_octets.as_ref().expect("retained");
        assert_eq!(&digest(octets), declared, "{}", reference.uri);
    }
    // Exact expected bytes: exclusive C14N drops the unused namespace and
    // the enveloped transform removes the Signature.
    assert_eq!(
        checked[1].digested_octets.as_deref(),
        Some(br#"<Item Id="item"><Value>42</Value></Item>"#.as_slice())
    );
    assert_eq!(
        checked[0].digested_octets.as_deref(),
        Some(br#"<Root><Item Id="item"><Value>42</Value></Item></Root>"#.as_slice())
    );
    assert_eq!(checked[2].digested_octets.as_deref(), Some(DETACHED));
}

#[test]
fn retention_does_not_change_the_verification_verdict() {
    let temp = Temp::new();
    let resource = temp.0.join("payload.bin");
    fs::write(&resource, DETACHED).unwrap();
    let xml = signed(&resource);
    let tampered = xml.replacen("<Value>42</Value>", "<Value>43</Value>", 1);
    for retain in [None, Some(1 << 20)] {
        let ctx = context(retain, Some(&resource));
        assert!(verify(&ctx, &xml).unwrap().is_valid(), "{retain:?}");
        assert!(!verify(&ctx, &tampered).unwrap().is_valid(), "{retain:?}");
    }
}

#[test]
fn exceeding_the_limit_is_an_error_never_a_truncation() {
    let temp = Temp::new();
    let resource = temp.0.join("payload.bin");
    fs::write(&resource, DETACHED).unwrap();
    let xml = signed(&resource);
    let total: usize = references(verify(&context(Some(1 << 20), Some(&resource)), &xml).unwrap())
        .iter()
        .map(|reference| reference.digested_octets.as_ref().unwrap().len())
        .sum();
    // Exactly at the limit is accepted.
    assert!(verify(&context(Some(total), Some(&resource)), &xml)
        .unwrap()
        .is_valid());
    // One byte less is refused for this signature.
    let error = verify(&context(Some(total - 1), Some(&resource)), &xml).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("retained reference octets exceed"),
        "{error}"
    );
    let all = verify_all(&context(Some(total - 1), Some(&resource)), &xml).unwrap();
    assert!(matches!(
        &all[0],
        VerifyResult::Invalid { reason } if reason.contains("retained reference octets exceed")
    ));
}

fn manifest_document(resource: &PathBuf) -> String {
    let member = reference("urn:payload", "", &digest(DETACHED));
    let template = format!(
        r##"<Root xmlns:ds="{}"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{}"/><ds:SignatureMethod Algorithm="{}"/>{}</ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="m">{member}</ds:Manifest></ds:Object></ds:Signature></Root>"##,
        ns::DSIG,
        algorithm::C14N,
        algorithm::HMAC_SHA256,
        reference("#m", "", ""),
    );
    sign::sign(&context(None, Some(resource)), &template).unwrap()
}

#[test]
fn manifest_members_retain_their_octets_within_the_shared_limit() {
    let temp = Temp::new();
    let resource = temp.0.join("payload.bin");
    fs::write(&resource, DETACHED).unwrap();
    let xml = manifest_document(&resource);
    let limits = ManifestLimits::default();
    let off = verify_with_manifests(&context(None, Some(&resource)), &xml, &limits).unwrap();
    assert_eq!(off.manifests[0].references[0].digested_octets, None);
    let on =
        verify_with_manifests(&context(Some(1 << 20), Some(&resource)), &xml, &limits).unwrap();
    let member = &on.manifests[0].references[0];
    assert_eq!(member.digested_octets.as_deref(), Some(DETACHED));
    let outer = references(on.signature);
    let outer_octets = outer[0].digested_octets.as_ref().unwrap();
    assert_eq!(&digest(outer_octets), &declared_digests(&xml)[0]);
    // Outer reference and member share one per-signature budget.
    let shared = outer_octets.len() + DETACHED.len();
    assert!(verify_with_manifests(&context(Some(shared), Some(&resource)), &xml, &limits).is_ok());
    let error = verify_with_manifests(&context(Some(shared - 1), Some(&resource)), &xml, &limits)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("retained reference octets exceed"),
        "{error}"
    );
}

/// Pre-digest buffers that xmlsec1 prints, byte-exact, in processing order.
fn xmlsec_pre_digest_buffers(stdout: &[u8]) -> Vec<Vec<u8>> {
    const START: &[u8] = b"== PreDigest data - start buffer:\n";
    const END: &[u8] = b"\n== PreDigest data - end buffer";
    let mut out = Vec::new();
    let mut rest = stdout;
    while let Some(start) = rest.windows(START.len()).position(|w| w == START) {
        let body = &rest[start + START.len()..];
        let end = body
            .windows(END.len())
            .position(|w| w == END)
            .expect("unterminated xmlsec1 buffer");
        out.push(body[..end].to_vec());
        rest = &body[end..];
    }
    out
}

/// xmlsec1 stdout (debug dump with buffers) and stderr (status and counts).
fn run_xmlsec(dir: &std::path::Path, xml: &str, resource: &PathBuf) -> (Vec<u8>, String) {
    let document = dir.join("signed.xml");
    let key = dir.join("hmac.bin");
    fs::write(&document, xml).unwrap();
    fs::write(&key, b"reference-octets-tests-real-hmac-key").unwrap();
    let output = std::process::Command::new("xmlsec1")
        .args([
            "--verify",
            "--verbose",
            "--store-references",
            "--print-debug",
        ])
        .args([
            "--lax-key-search",
            "--id-attr:Id",
            "Item",
            "--id-attr:Id",
            "Manifest",
        ])
        .arg("--hmackey")
        .arg(&key)
        .arg("--url-map:urn:payload")
        .arg(resource)
        .arg(&document)
        .output()
        .expect("xmlsec1 is required for this differential (run with --ignored)");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    eprintln!("xmlsec1: {stderr}");
    (output.stdout, stderr)
}

#[test]
#[ignore] // Requires xmlsec1 (1.3.x): run with `cargo test --test reference_octets -- --ignored`
fn retained_octets_match_xmlsec1_pre_digest_buffers() {
    let temp = Temp::new();
    let resource = temp.0.join("payload.bin");
    fs::write(&resource, DETACHED).unwrap();

    let xml = signed(&resource);
    let (stdout, stderr) = run_xmlsec(&temp.0, &xml, &resource);
    assert!(
        stderr.contains("SignedInfo References (ok/all): 3/3"),
        "{stderr}"
    );
    let native: Vec<Vec<u8>> =
        references(verify(&context(Some(1 << 20), Some(&resource)), &xml).unwrap())
            .into_iter()
            .map(|reference| reference.digested_octets.unwrap())
            .collect();
    assert_eq!(native, xmlsec_pre_digest_buffers(&stdout));

    let xml = manifest_document(&resource);
    let (stdout, stderr) = run_xmlsec(&temp.0, &xml, &resource);
    assert!(
        stderr.contains("SignedInfo References (ok/all): 1/1"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Manifests References (ok/all): 1/1"),
        "{stderr}"
    );
    let on = verify_with_manifests(
        &context(Some(1 << 20), Some(&resource)),
        &xml,
        &ManifestLimits::default(),
    )
    .unwrap();
    let mut native: Vec<Vec<u8>> = references(on.signature)
        .into_iter()
        .map(|reference| reference.digested_octets.unwrap())
        .collect();
    native.extend(
        on.manifests[0]
            .references
            .iter()
            .map(|reference| reference.digested_octets.clone().unwrap()),
    );
    assert_eq!(native, xmlsec_pre_digest_buffers(&stdout));
}
