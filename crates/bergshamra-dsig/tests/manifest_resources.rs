//! Relative-resource compatibility is tested in a child process so no test
//! changes the working directory of another concurrent test.
use base64::Engine;
use bergshamra_core::{algorithm, ns, Error};
use bergshamra_dsig::{
    sign,
    verify::{verify, verify_document_with_manifests, verify_with_manifests, ManifestLimits},
    DsigContext,
};
use bergshamra_keys::{loader, KeysManager};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

fn context() -> DsigContext {
    let mut keys = KeysManager::new();
    keys.add_key(loader::load_hmac_key(b"manifest-resource-tests-real-hmac-key").unwrap());
    DsigContext::new_permissive(keys)
}
fn reference(uri: &str, digest: &str) -> String {
    format!(
        r#"<ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="{}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"#,
        algorithm::SHA256
    )
}
fn digest(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(bergshamra_crypto::digest::digest(algorithm::SHA256, bytes).unwrap())
}
fn template(outer: &str, object: &str) -> String {
    format!(
        r##"<Root xmlns:ds="{}"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{}"/><ds:SignatureMethod Algorithm="{}"/>{outer}</ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="a">{object}</ds:Manifest></ds:Object></ds:Signature></Root>"##,
        ns::DSIG,
        algorithm::C14N,
        algorithm::HMAC_SHA256
    )
}
fn signed_member(uri: &str, bytes: &[u8]) -> String {
    sign::sign(
        &context(),
        &template(&reference("#a", ""), &reference(uri, &digest(bytes))),
    )
    .unwrap()
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "bergshamra-review-resources-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn explicit_manifest_mode_requires_a_base_or_exact_map_instead_of_cwd_fallback() {
    const CHILD: &str = "BERGSHAMRA_MANIFEST_CWD_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let bytes = b"actual cwd fixture";
        let inner = signed_member("member.bin", bytes);
        let mut signing = context();
        signing.base_dir = Some(std::env::current_dir().unwrap().display().to_string());
        let outer = sign::sign(&signing, &template(&reference("member.bin", ""), "")).unwrap();
        let cwd_only = context();
        assert!(
            verify(&cwd_only, &outer).unwrap().is_valid(),
            "legacy cwd fallback is retained"
        );
        for xml in [&inner, &outer] {
            let error =
                verify_with_manifests(&cwd_only, xml, &ManifestLimits::default()).unwrap_err();
            assert!(matches!(error, Error::InvalidUri(_)), "{error}");
            assert!(error.to_string().contains("member.bin"), "{error}");
            let mut mapped = context();
            mapped.add_url_map(
                "member.bin",
                std::env::current_dir()
                    .unwrap()
                    .join("member.bin")
                    .to_str()
                    .unwrap(),
            );
            assert!(verify_with_manifests(&mapped, xml, &ManifestLimits::default()).is_ok());
            let mut based = context();
            based.base_dir = Some(std::env::current_dir().unwrap().display().to_string());
            assert!(verify_with_manifests(&based, xml, &ManifestLimits::default()).is_ok());
            based.base_dir = Some(
                std::env::current_dir()
                    .unwrap()
                    .join("empty-base")
                    .display()
                    .to_string(),
            );
            assert!(
                verify(&based, &outer).unwrap().is_valid(),
                "legacy still falls back from missing base file"
            );
            let error = verify_with_manifests(&based, xml, &ManifestLimits::default()).unwrap_err();
            assert!(matches!(error, Error::InvalidUri(_)), "{error}");
        }
        return;
    }
    let t = Temp::new();
    fs::write(t.0.join("member.bin"), b"actual cwd fixture").unwrap();
    fs::create_dir(t.0.join("empty-base")).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "explicit_manifest_mode_requires_a_base_or_exact_map_instead_of_cwd_fallback",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .current_dir(&t.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn relative_traversal_and_lookalike_maps_never_gain_manifest_authority() {
    let t = Temp::new();
    fs::write(t.0.join("payload.bin"), b"body").unwrap();
    for uri in ["../payload.bin", "urn:payload.evil"] {
        let signed = signed_member(uri, b"body");
        let mut ctx = context();
        ctx.add_url_map("urn:payload", t.0.join("payload.bin").to_str().unwrap());
        let error = verify_with_manifests(&ctx, &signed, &ManifestLimits::default()).unwrap_err();
        assert!(matches!(error, Error::InvalidUri(_)), "{error}");
        assert!(error.to_string().contains(uri), "{error}");
    }
}

#[test]
fn caller_can_raise_resource_budget_and_special_files_remain_refused() {
    let t = Temp::new();
    let bytes = vec![b'x'; 16 * 1024 * 1024 + 1];
    let path = t.0.join("large.bin");
    fs::write(&path, &bytes).unwrap();
    let signed = signed_member("urn:large", &bytes);
    let mut ctx = context();
    ctx.add_url_map("urn:large", path.to_str().unwrap());
    let error = verify_with_manifests(&ctx, &signed, &ManifestLimits::default()).unwrap_err();
    assert!(matches!(error, Error::Other(_)), "{error}");
    assert!(error.to_string().contains("byte limit"), "{error}");
    let mut limits = ManifestLimits::default();
    limits.max_reference_bytes = bytes.len();
    assert_eq!(
        verify_with_manifests(&ctx, &signed, &limits)
            .unwrap()
            .manifests[0]
            .references
            .len(),
        1
    );
    let signed = signed_member("urn:directory", b"");
    let mut ctx = context();
    ctx.add_url_map("urn:directory", t.0.to_str().unwrap());
    let error = verify_with_manifests(&ctx, &signed, &ManifestLimits::default()).unwrap_err();
    assert!(matches!(&error, Error::Io(io) if io.kind() == std::io::ErrorKind::InvalidInput), "{error}");
    assert!(error.to_string().contains("not a regular file"), "{error}");
    assert!(!error.to_string().contains("byte limit"), "{error}");
}


#[test]
fn mapped_read_errors_are_typed_only_in_explicit_manifest_mode() {
    let t = Temp::new();
    let path = t.0.join("mapped.bin");
    fs::write(&path, b"body").unwrap();
    let mut ctx = context();
    ctx.add_url_map("urn:mapped", path.to_str().unwrap());
    let outer = sign::sign(&ctx, &template(&reference("urn:mapped", ""), "")).unwrap();
    fs::remove_file(&path).unwrap();
    for directory in [false, true] {
        if directory { fs::create_dir(&path).unwrap(); }
        let legacy = verify(&ctx, &outer).unwrap_err();
        assert!(matches!(legacy, Error::Other(_)), "legacy category: {legacy}");
        let error = verify_with_manifests(&ctx, &outer, &ManifestLimits::default()).unwrap_err();
        let kind = if directory { std::io::ErrorKind::InvalidInput } else { std::io::ErrorKind::NotFound };
        assert!(matches!(&error, Error::Io(io) if io.kind() == kind), "{error}");
        assert!(error.to_string().contains("url-map URI=urn:mapped"), "{error}");
    }
}

#[test]
fn source_less_detached_reference_uses_only_mapped_bytes_and_transforms() {
    let t = Temp::new();
    let bytes = b"actual detached binary, not XML source";
    let path = t.0.join("payload.b64");
    fs::write(&path, base64::engine::general_purpose::STANDARD.encode(bytes)).unwrap();
    let member = reference("urn:payload", &digest(bytes)).replace(
        "<ds:DigestMethod", &format!(r#"<ds:Transforms><ds:Transform Algorithm="{}"/></ds:Transforms><ds:DigestMethod"#, algorithm::BASE64),
    );
    let signed = sign::sign(&context(), &template(&reference("#a", ""), &member)).unwrap();
    let doc = uppsala::parse(&signed).unwrap();
    let mut ctx = context();
    ctx.add_url_map("urn:payload", path.to_str().unwrap());
    let result = verify_document_with_manifests(&ctx, &doc, None, &ManifestLimits::default()).unwrap();
    assert!(result.manifests[0].references[0].digest_verified);
    assert!(result.manifests[0].references[0].resolved_node.is_none());
    fs::remove_file(path).unwrap();
    let error = verify_document_with_manifests(&ctx, &doc, None, &ManifestLimits::default()).unwrap_err();
    assert!(error.to_string().contains("urn:payload"), "{error}");
}
