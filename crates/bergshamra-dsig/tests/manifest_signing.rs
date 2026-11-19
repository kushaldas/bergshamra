//! Opt-in signing of authenticated same-document Manifest members.
//!
//! With `DsigContext::sign_manifest_members` set, `sign` and `sign_document*`
//! fill each empty member `<DigestValue>` of the Signature's own Manifests
//! before the SignedInfo references are digested. The default leaves members
//! exactly as before.
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
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const HMAC_KEY: &[u8] = b"manifest-signing-tests-real-hmac-key";
const CONTENT: &[u8] = b"<office:document-content>body</office:document-content>\n";
const PICTURE: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00binary\xff\x00tail";
const MANIFEST_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#Manifest";

fn context(maps: &[(&str, &Path)], sign_members: bool) -> DsigContext {
    let mut keys = KeysManager::new();
    keys.add_key(loader::load_hmac_key(HMAC_KEY).unwrap());
    let mut ctx = DsigContext::new_permissive(keys);
    ctx.sign_manifest_members = sign_members;
    for (uri, path) in maps {
        ctx.add_url_map(uri, path.to_str().unwrap());
    }
    ctx
}
fn reference(uri: &str, kind: Option<&str>, transforms: &str, digest: &str) -> String {
    let kind = kind.map(|k| format!(r#" Type="{k}""#)).unwrap_or_default();
    format!(
        r#"<ds:Reference URI="{uri}"{kind}>{transforms}<ds:DigestMethod Algorithm="{}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"#,
        algorithm::SHA256
    )
}
fn manifest(id: &str, members: &str) -> String {
    format!(r#"<ds:Object><ds:Manifest Id="{id}">{members}</ds:Manifest></ds:Object>"#)
}
fn template(outer: &str, objects: &str) -> String {
    format!(
        r##"<Root xmlns:ds="{}"><Item Id="item" xmlns:x="urn:unused"><Value>42</Value></Item><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{}"/><ds:SignatureMethod Algorithm="{}"/>{outer}</ds:SignedInfo><ds:SignatureValue/>{objects}</ds:Signature></Root>"##,
        ns::DSIG,
        algorithm::C14N,
        algorithm::HMAC_SHA256
    )
}
fn digest(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(bergshamra_crypto::digest::digest(algorithm::SHA256, bytes).unwrap())
}
/// Text of every `<ds:DigestValue>` (prefixed) or `<DigestValue>` element.
fn digest_values(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    for open in ["<ds:DigestValue>", "<DigestValue>"] {
        let close = open.replace('<', "</");
        for (start, _) in xml.match_indices(open) {
            let body = &xml[start + open.len()..];
            out.push((start, body[..body.find(&close).unwrap()].to_owned()));
        }
    }
    out.sort_by_key(|(start, _)| *start);
    out.into_iter().map(|(_, value)| value).collect()
}
fn sign_dom(ctx: &DsigContext, template: &str) -> Result<String, Error> {
    let mut doc = uppsala::parse(template).unwrap();
    sign::sign_document(ctx, &mut doc)?;
    Ok(doc.to_xml())
}
fn sha256_hex(bytes: &[u8]) -> String {
    bergshamra_crypto::digest::digest(algorithm::SHA256, bytes)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bergshamra-manifest-signing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// ODF-style: raw external members (one with NUL bytes) plus a same-document
/// member with an exclusive C14N transform.
fn odf_template() -> String {
    let exc = format!(
        r#"<ds:Transforms><ds:Transform Algorithm="{}"/></ds:Transforms>"#,
        algorithm::EXC_C14N
    );
    template(
        &reference("#m", Some(MANIFEST_TYPE), "", ""),
        &manifest(
            "m",
            &[
                reference("content.xml", None, "", ""),
                reference("Pictures/blob.bin", None, "", ""),
                reference("#item", None, &exc, ""),
            ]
            .concat(),
        ),
    )
}
fn odf_maps(temp: &Temp) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("content.xml", temp.file("content.xml", CONTENT)),
        ("Pictures/blob.bin", temp.file("blob.bin", PICTURE)),
    ]
}
fn borrow<'a>(maps: &'a [(&'static str, PathBuf)]) -> Vec<(&'static str, &'a Path)> {
    maps.iter().map(|(u, p)| (*u, p.as_path())).collect()
}

/// Nested: Manifest `a` authenticates Manifest `b` through a member.
fn nested_template() -> String {
    template(
        &reference("#a", Some(MANIFEST_TYPE), "", ""),
        &[
            manifest(
                "a",
                &[
                    reference("content.xml", None, "", ""),
                    reference("#b", Some(MANIFEST_TYPE), "", ""),
                ]
                .concat(),
            ),
            manifest("b", &reference("Pictures/blob.bin", None, "", "")),
        ]
        .concat(),
    )
}

#[test]
fn signing_members_is_off_by_default_and_output_is_unchanged() {
    let temp = Temp::new();
    let maps = odf_maps(&temp);
    let ctx = context(&borrow(&maps), false);
    assert!(!DsigContext::new_permissive(KeysManager::new()).sign_manifest_members);
    assert!(!DsigContext::new(KeysManager::new()).sign_manifest_members);
    let template = odf_template();
    let signed = sign::sign(&ctx, &template).unwrap();
    // Members stay empty; only the outer reference and SignatureValue fill.
    let values = digest_values(&signed);
    assert_eq!(values.len(), 4);
    assert!(!values[0].is_empty());
    assert!(values[1..].iter().all(String::is_empty), "{values:?}");
    assert!(verify(&ctx, &signed).unwrap().is_valid());
    assert!(verify_with_manifests(&ctx, &signed, &ManifestLimits::default()).is_err());
    // Byte-identical to the pre-feature engine (pinned at e945ffae).
    assert_eq!(
        sha256_hex(signed.as_bytes()),
        "d0e8ea2781b297fade991f0dcb510086f1f0609f4c13bd78ca61c53ed5093fc2",
        "string path output changed"
    );
    let dom = sign_dom(&ctx, &template).unwrap();
    assert_eq!(
        sha256_hex(dom.as_bytes()),
        "aad73bab42370a51957ef44c8314b027f04e9d0410023f8ecd842b59e22dea1c",
        "document path output changed"
    );
}

#[test]
fn odf_style_raw_external_members_are_filled_and_verify() {
    let temp = Temp::new();
    let maps = odf_maps(&temp);
    let ctx = context(&borrow(&maps), true);
    for signed in [
        sign::sign(&ctx, &odf_template()).unwrap(),
        sign_dom(&ctx, &odf_template()).unwrap(),
    ] {
        let values = digest_values(&signed);
        assert_eq!(values[1], digest(CONTENT));
        assert_eq!(values[2], digest(PICTURE));
        assert_eq!(
            values[3],
            digest(br#"<Item Id="item"><Value>42</Value></Item>"#)
        );
        let checked = verify_with_manifests(&ctx, &signed, &ManifestLimits::default()).unwrap();
        assert!(checked.signature.is_valid());
        assert_eq!(checked.manifests.len(), 1);
        assert_eq!(checked.manifests[0].references.len(), 3);
        assert!(checked.manifests[0]
            .references
            .iter()
            .all(|r| r.digest_verified));
    }
}

const OOXML_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ooxml/");
const OOXML_SIGNATURE: &str = include_str!("data/ooxml/_xmlsignatures/sig1.xml");
const OOXML_PARTS: [(&str, &str); 8] = [
    ("/_rels/.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml", "_rels/.rels"),
    ("/word/_rels/document.xml.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml", "word/_rels/document.xml.rels"),
    ("/word/document.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml", "word/document.xml"),
    ("/word/fontTable.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml", "word/fontTable.xml"),
    ("/word/settings.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml", "word/settings.xml"),
    ("/word/styles.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml", "word/styles.xml"),
    ("/word/theme/theme1.xml?ContentType=application/vnd.openxmlformats-officedocument.theme+xml", "word/theme/theme1.xml"),
    ("/word/webSettings.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml", "word/webSettings.xml"),
];
fn blank_digests(segment: &str) -> String {
    let mut out = String::new();
    let mut rest = segment;
    while let Some(start) = rest.find("<DigestValue>") {
        out.push_str(&rest[..start + "<DigestValue>".len()]);
        rest = &rest[start..];
        rest = &rest[rest.find("</DigestValue>").unwrap()..];
    }
    out + rest
}
/// The genuine Office signature turned back into a template: HMAC instead of
/// RSA, no KeyInfo, empty SignatureValue and empty SignedInfo/Manifest digests.
fn ooxml_template() -> String {
    let s = OOXML_SIGNATURE.replace(
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        algorithm::HMAC_SHA256,
    );
    let cut = |s: &str, open: &str, close: &str| {
        let a = s.find(open).unwrap();
        let b = s.find(close).unwrap() + close.len();
        (a, b)
    };
    let (a, b) = cut(&s, "<SignatureValue>", "</KeyInfo>");
    let s = format!("{}<SignatureValue></SignatureValue>{}", &s[..a], &s[b..]);
    let (a, b) = cut(&s, "<SignedInfo>", "</SignedInfo>");
    let s = format!("{}{}{}", &s[..a], blank_digests(&s[a..b]), &s[b..]);
    let (a, b) = cut(&s, "<Manifest>", "</Manifest>");
    format!("{}{}{}", &s[..a], blank_digests(&s[a..b]), &s[b..])
}
fn ooxml_context(root: &Path, sign_members: bool) -> DsigContext {
    let maps: Vec<(&str, PathBuf)> = OOXML_PARTS
        .iter()
        .map(|(uri, part)| (*uri, root.join(part)))
        .collect();
    context(&borrow(&maps), sign_members)
}

#[test]
fn ooxml_members_with_relationship_transforms_reproduce_office_digests() {
    let ctx = ooxml_context(Path::new(OOXML_FIXTURE), true);
    let template = ooxml_template();
    let original = digest_values(OOXML_SIGNATURE);
    let blanked = digest_values(&template);
    assert_eq!(blanked.iter().filter(|v| v.is_empty()).count(), 11);
    for signed in [
        sign::sign(&ctx, &template).unwrap(),
        sign_dom(&ctx, &template).unwrap(),
    ] {
        // Every SignedInfo and Manifest digest equals the one Office produced:
        // the member digests (RelationshipTransform + C14N on .rels parts) and
        // the outer digest over the filled package Object.
        assert_eq!(digest_values(&signed), original);
        let doc = uppsala::parse(&signed).unwrap();
        let checked =
            verify_document_with_manifests(&ctx, &doc, Some(&signed), &ManifestLimits::default())
                .unwrap();
        assert!(checked.signature.is_valid());
        assert_eq!(checked.manifests.len(), 1);
        assert_eq!(checked.manifests[0].references.len(), 8);
    }
}

#[test]
fn nested_manifests_fill_children_before_parents() {
    let temp = Temp::new();
    let maps = odf_maps(&temp);
    let ctx = context(&borrow(&maps), true);
    for signed in [
        sign::sign(&ctx, &nested_template()).unwrap(),
        sign_dom(&ctx, &nested_template()).unwrap(),
    ] {
        let values = digest_values(&signed);
        assert!(values.iter().all(|v| !v.is_empty()), "{values:?}");
        assert_eq!(values[1], digest(CONTENT));
        assert_eq!(values[3], digest(PICTURE));
        // The parent member over Manifest b covers b's filled digest.
        let doc = uppsala::parse(&signed).unwrap();
        let b = doc
            .descendants(doc.root())
            .into_iter()
            .find(|&n| doc.element(n).and_then(|e| e.get_attribute("Id")) == Some("b"))
            .unwrap();
        let set = bergshamra_xml::nodeset::NodeSet::tree_without_comments(b, &doc);
        let c14n = bergshamra_c14n::canonicalize_doc(
            &doc,
            bergshamra_c14n::C14nMode::Inclusive,
            Some(&set),
            &[] as &[&str],
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&c14n).contains(&digest(PICTURE)));
        assert_eq!(values[2], digest(&c14n));
        let checked = verify_with_manifests(&ctx, &signed, &ManifestLimits::default()).unwrap();
        assert_eq!(checked.manifests.len(), 2);
    }
}

#[test]
fn already_filled_member_digest_is_left_byte_identical() {
    let temp = Temp::new();
    let maps = odf_maps(&temp);
    let ctx = context(&borrow(&maps), true);
    let preset = reference("content.xml", None, "", "\n  AAAA/preset+digest=\n");
    let template = template(
        &reference("#m", None, "", ""),
        &manifest(
            "m",
            &[preset.clone(), reference("Pictures/blob.bin", None, "", "")].concat(),
        ),
    );
    let signed = sign::sign(&ctx, &template).unwrap();
    assert!(signed.contains(&preset), "{signed}");
    assert_eq!(digest_values(&signed)[2], digest(PICTURE));
    assert!(verify(&ctx, &signed).unwrap().is_valid());
    let dom = sign_dom(&ctx, &template).unwrap();
    assert!(dom.contains(&preset), "{dom}");
    assert_eq!(digest_values(&dom)[2], digest(PICTURE));
}

fn assert_limit(ctx: &DsigContext, template: &str, category: &str) {
    let error = sign::sign(ctx, template).expect_err(category);
    assert!(error.to_string().contains(category), "{category}: {error}");
    let mut doc = uppsala::parse(template).unwrap();
    let before = doc.to_xml();
    let error = sign::sign_document(ctx, &mut doc).expect_err(category);
    assert!(error.to_string().contains(category), "{category}: {error}");
    assert_eq!(doc.to_xml(), before, "{category}: no partial output");
}

#[test]
fn exceeding_manifest_limits_fails_without_output() {
    let temp = Temp::new();
    let maps = odf_maps(&temp);
    let limits = ManifestLimits::default();
    let ctx = context(&borrow(&maps), true);
    let member = || reference("content.xml", None, "", "");

    // Depth: a chain one Manifest deeper than the default bound.
    let chain: String = (1..=limits.max_depth + 1)
        .map(|i| {
            let next = if i == limits.max_depth + 1 {
                member()
            } else {
                reference(&format!("#m{}", i + 1), Some(MANIFEST_TYPE), "", "")
            };
            manifest(&format!("m{i}"), &next)
        })
        .collect();
    assert_limit(
        &ctx,
        &template(&reference("#m1", None, "", ""), &chain),
        "limit exceeded: depth",
    );
    // Within the bound, the same shape signs and verifies.
    let ok_chain: String = (1..=limits.max_depth)
        .map(|i| {
            let next = if i == limits.max_depth {
                member()
            } else {
                reference(&format!("#m{}", i + 1), Some(MANIFEST_TYPE), "", "")
            };
            manifest(&format!("m{i}"), &next)
        })
        .collect();
    let signed = sign::sign(&ctx, &template(&reference("#m1", None, "", ""), &ok_chain)).unwrap();
    assert_eq!(
        verify_with_manifests(&ctx, &signed, &limits)
            .unwrap()
            .manifests
            .len(),
        limits.max_depth
    );

    // Manifest count: one Object holding one Manifest too many.
    let many: String = (0..=limits.max_manifests)
        .map(|i| format!(r#"<ds:Manifest Id="n{i}">{}</ds:Manifest>"#, member()))
        .collect();
    assert_limit(
        &ctx,
        &template(
            &reference("#all", None, "", ""),
            &format!(r#"<ds:Object Id="all">{many}</ds:Object>"#),
        ),
        "limit exceeded: Manifests",
    );

    // References: outer plus members exceed the shared budget by one.
    let members: String = (0..limits.max_references).map(|_| member()).collect();
    assert_limit(
        &ctx,
        &template(&reference("#m", None, "", ""), &manifest("m", &members)),
        "limit exceeded: references",
    );

    // Detached bytes: one member resource over the per-reference bound.
    let big = temp.file("big.bin", &vec![0u8; limits.max_reference_bytes + 1]);
    let big_ctx = context(&[("big.bin", big.as_path())], true);
    assert_limit(
        &big_ctx,
        &template(
            &reference("#m", None, "", ""),
            &manifest("m", &reference("big.bin", None, "", "")),
        ),
        "byte limit exceeded",
    );

    // A cycle between two Manifests is refused.
    let cycle = [
        manifest("p", &reference("#q", Some(MANIFEST_TYPE), "", "")),
        manifest("q", &reference("#p", Some(MANIFEST_TYPE), "", "")),
    ]
    .concat();
    assert_limit(
        &ctx,
        &template(&reference("#p", None, "", ""), &cycle),
        "Manifest cycle",
    );
}

#[test]
fn a_late_member_failure_leaves_no_partial_output() {
    let temp = Temp::new();
    let maps = odf_maps(&temp);
    let ctx = context(&borrow(&maps), true);
    let template = nested_template().replace(
        r#"<ds:Reference URI="content.xml">"#,
        r#"<ds:Reference URI="missing.bin">"#,
    );
    // Manifest b's member is filled first; a's unreadable member then fails.
    assert_limit(&ctx, &template, "missing.bin");
}

#[test]
fn tampered_member_resource_fails_manifest_verification() {
    let temp = Temp::new();
    let maps = odf_maps(&temp);
    let ctx = context(&borrow(&maps), true);
    let signed = sign::sign(&ctx, &odf_template()).unwrap();
    assert!(verify_with_manifests(&ctx, &signed, &ManifestLimits::default()).is_ok());
    let mut changed = PICTURE.to_vec();
    changed[9] = 1; // The NUL byte inside the binary member.
    fs::write(&maps[1].1, changed).unwrap();
    assert!(verify(&ctx, &signed).unwrap().is_valid(), "outer is intact");
    let error = verify_with_manifests(&ctx, &signed, &ManifestLimits::default()).unwrap_err();
    assert!(matches!(error, Error::DigestMismatch(_)), "{error}");
    assert!(error.to_string().contains("Pictures/blob.bin"), "{error}");
}

/// xmlsec1 `--verify --verbose` stderr for a signed document.
fn run_xmlsec(temp: &Temp, xml: &str, maps: &[(&'static str, PathBuf)]) -> String {
    let document = temp.file("signed.xml", xml.as_bytes());
    let key = temp.file("hmac.bin", HMAC_KEY);
    let mut command = std::process::Command::new("xmlsec1");
    command
        .args(["--verify", "--verbose", "--lax-key-search"])
        .args(["--id-attr:Id", "Item", "--id-attr:Id", "Manifest"])
        .arg("--hmackey")
        .arg(&key);
    for (uri, path) in maps {
        command.arg(format!("--url-map:{uri}")).arg(path);
    }
    let output = command
        .arg(&document)
        .output()
        .expect("xmlsec1 is required for this differential (run with --ignored)");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    eprintln!("xmlsec1: {stderr}");
    stderr
}

#[test]
#[ignore] // Requires xmlsec1 (1.3.x): run with `cargo test --test manifest_signing -- --ignored`
fn signed_manifests_verify_with_xmlsec1() {
    let temp = Temp::new();
    let maps = odf_maps(&temp);
    let ctx = context(&borrow(&maps), true);
    for (template, members) in [(odf_template(), 3), (nested_template(), 3)] {
        for signed in [
            sign::sign(&ctx, &template).unwrap(),
            sign_dom(&ctx, &template).unwrap(),
        ] {
            let stderr = run_xmlsec(&temp, &signed, &maps);
            assert!(
                stderr.contains("SignedInfo References (ok/all): 1/1"),
                "{stderr}"
            );
            assert!(
                stderr.contains(&format!(
                    "Manifests References (ok/all): {members}/{members}"
                )),
                "{stderr}"
            );
        }
    }
    // Off by default, xmlsec1 rejects the empty member digests.
    let unsigned = sign::sign(&context(&borrow(&maps), false), &odf_template()).unwrap();
    let document = temp.file("unsigned.xml", unsigned.as_bytes());
    let status = std::process::Command::new("xmlsec1")
        .args(["--verify", "--lax-key-search", "--id-attr:Id", "Item"])
        .args(["--id-attr:Id", "Manifest", "--hmackey"])
        .arg(temp.file("hmac.bin", HMAC_KEY))
        .args(["--url-map:content.xml"])
        .arg(&maps[0].1)
        .args(["--url-map:Pictures/blob.bin"])
        .arg(&maps[1].1)
        .arg(&document)
        .output()
        .unwrap();
    assert!(!status.status.success());
}
