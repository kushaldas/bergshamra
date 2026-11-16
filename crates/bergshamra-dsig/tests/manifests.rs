//! A genuine OPC signature must not become outer-only Valid when Manifest
//! member validation is requested. The fixture intentionally has partial
//! package coverage; these tests do not turn that into a full-package claim.

use bergshamra_core::Error;
use bergshamra_dsig::verify::{
    verify, verify_document_with_manifests, verify_with_manifests, ManifestLimits,
};
use bergshamra_dsig::{DsigContext, VerifyResult};
use bergshamra_keys::KeysManager;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ooxml/");
const SIGNATURE: &str = include_str!("data/ooxml/_xmlsignatures/sig1.xml");
const RESOURCES: [(&str, &str); 8] = [
    (
        "/_rels/.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml",
        "_rels/.rels",
    ),
    (
        "/word/_rels/document.xml.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml",
        "word/_rels/document.xml.rels",
    ),
    (
        "/word/document.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        "word/document.xml",
    ),
    (
        "/word/fontTable.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml",
        "word/fontTable.xml",
    ),
    (
        "/word/settings.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
        "word/settings.xml",
    ),
    (
        "/word/styles.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
        "word/styles.xml",
    ),
    (
        "/word/theme/theme1.xml?ContentType=application/vnd.openxmlformats-officedocument.theme+xml",
        "word/theme/theme1.xml",
    ),
    (
        "/word/webSettings.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml",
        "word/webSettings.xml",
    ),
];

fn context(resources: &Path) -> DsigContext {
    let mut context = DsigContext::new_permissive(KeysManager::new());
    // These are cryptographic fixture checks, not certificate trust decisions.
    context.insecure = true;
    context.require_reference_digests = true;
    for (uri, member) in RESOURCES {
        context.add_url_map(uri, resources.join(member).to_str().unwrap());
    }
    context
}

struct TemporaryResources(PathBuf);

impl TemporaryResources {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bergshamra-manifest-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("fresh temporary resource directory");
        for (_, member) in RESOURCES {
            let target = path.join(member);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(Path::new(FIXTURE).join(member), target).unwrap();
        }
        Self(path)
    }
}

impl Drop for TemporaryResources {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn genuine_ooxml_manifest_validates_all_eight_declared_members() {
    let context = context(Path::new(FIXTURE));
    let legacy = verify(&context, SIGNATURE).expect("outer signature");
    match legacy {
        VerifyResult::Valid { references, .. } => assert_eq!(references.len(), 3),
        result => panic!("genuine outer signature must verify: {result:?}"),
    }

    let result = verify_with_manifests(&context, SIGNATURE, &ManifestLimits::default())
        .expect("genuine OOXML outer signature and all Manifest members");
    assert!(result.signature.is_valid());
    assert!(result.signature.all_reference_digests_verified());
    assert_eq!(result.manifests.len(), 1);
    assert_eq!(result.manifests[0].references.len(), 8);
    for (actual, (uri, _)) in result.manifests[0].references.iter().zip(RESOURCES) {
        assert_eq!(actual.uri, uri);
        assert!(actual.digest_verified);
    }

    let document = uppsala::parse(SIGNATURE).unwrap();
    let in_place = verify_document_with_manifests(
        &context,
        &document,
        Some(SIGNATURE),
        &ManifestLimits::default(),
    )
    .expect("already-parsed original-location assessment");
    assert_eq!(in_place.manifests.len(), 1);
    assert_eq!(in_place.manifests[0].references.len(), 8);
    assert_eq!(
        in_place.manifests[0].manifest_node,
        result.manifests[0].manifest_node
    );
}

#[test]
fn changed_ooxml_body_cannot_return_outer_only_valid() {
    let temporary = TemporaryResources::new();
    let body = temporary.0.join("word/document.xml");
    let original = fs::read_to_string(&body).unwrap();
    assert!(original.contains("Hello world!"));
    fs::write(&body, original.replacen("Hello world!", "Altered text", 1)).unwrap();
    let context = context(&temporary.0);
    assert!(verify(&context, SIGNATURE).unwrap().is_valid());
    let error = verify_with_manifests(&context, SIGNATURE, &ManifestLimits::default())
        .expect_err("body tampering must fail Manifest verification");
    assert!(matches!(error, Error::DigestMismatch(_)), "{error}");
    assert!(error.to_string().contains("Manifest"), "{error}");
    assert!(error.to_string().contains(RESOURCES[2].0), "{error}");
}

#[test]
fn missing_ooxml_resource_cannot_return_outer_only_valid() {
    let temporary = TemporaryResources::new();
    fs::remove_file(temporary.0.join("word/document.xml")).unwrap();
    let context = context(&temporary.0);
    assert!(verify(&context, SIGNATURE).unwrap().is_valid());
    let error = verify_with_manifests(&context, SIGNATURE, &ManifestLimits::default())
        .expect_err("an unreadable declared member must fail Manifest verification");
    assert!(matches!(error, Error::Other(_)), "{error}");
    assert!(error.to_string().contains("Manifest"), "{error}");
    assert!(error.to_string().contains(RESOURCES[2].0), "{error}");
}

#[test]
fn ooxml_manifest_assessment_obeys_reference_and_input_limits() {
    let context = context(Path::new(FIXTURE));
    let restrictions: [(fn(&mut ManifestLimits), &str); 5] = [
        (|limits| limits.max_references = 10, "references"), // Three outer plus eight members.
        (|limits| limits.max_manifests = 0, "Manifests"),
        (|limits| limits.max_depth = 0, "depth"),
        (
            |limits| limits.max_document_bytes = SIGNATURE.len() - 1,
            "document bytes",
        ),
        (|limits| limits.max_nodes = 1, "inspected nodes"),
    ];
    for (restrict, category) in restrictions {
        let mut limits = ManifestLimits::default();
        restrict(&mut limits);
        let error = verify_with_manifests(&context, SIGNATURE, &limits)
            .expect_err("the selected budget must reject this genuine input");
        assert!(matches!(error, Error::XmlStructure(_)), "{error}");
        assert!(
            error
                .to_string()
                .contains("Manifest verification limit exceeded"),
            "{error}"
        );
        assert!(error.to_string().contains(category), "{error}");
    }

    let mut limits = ManifestLimits::default();
    limits.max_reference_bytes = 1;
    let error = verify_with_manifests(&context, SIGNATURE, &limits)
        .expect_err("a detached member exceeding its byte budget must reject");
    assert!(matches!(error, Error::Other(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains("Manifest"), "{message}");
    assert!(message.contains(RESOURCES[0].0), "{message}");
    assert!(
        message.contains("Reference resource byte limit exceeded (1 bytes)"),
        "{message}"
    );
}

#[test]
fn selected_ooxml_relationship_targets_are_authenticated() {
    let selected_targets = [
        ("rId1", "styles.xml", "settings.xml"),
        ("rId2", "settings.xml", "webSettings.xml"),
        ("rId3", "webSettings.xml", "styles.xml"),
        ("rId4", "fontTable.xml", "settings.xml"),
        ("rId5", "theme/theme1.xml", "webSettings.xml"),
    ];
    for (id, original_target, changed_target) in selected_targets {
        assert!(SIGNATURE.contains(&format!("SourceId=\"{id}\"")));
        let temporary = TemporaryResources::new();
        let relationships = temporary.0.join("word/_rels/document.xml.rels");
        let original = fs::read_to_string(&relationships).unwrap();
        let selected = format!("Id=\"{id}\"");
        assert!(original.contains(&selected));
        let target = format!("Target=\"{original_target}\"");
        assert_eq!(original.matches(&target).count(), 1);
        let changed = original.replacen(&target, &format!("Target=\"{changed_target}\""), 1);
        fs::write(relationships, changed).unwrap();
        let context = context(&temporary.0);
        assert!(verify(&context, SIGNATURE).unwrap().is_valid());
        let error = verify_with_manifests(&context, SIGNATURE, &ManifestLimits::default())
            .expect_err("changing a selected relationship must fail its member digest");
        assert!(matches!(error, Error::DigestMismatch(_)), "{id}: {error}");
        assert!(error.to_string().contains("Manifest"), "{id}: {error}");
        assert!(error.to_string().contains(RESOURCES[1].0), "{id}: {error}");
    }
}

#[test]
fn unselected_ooxml_relationship_changes_preserve_partial_coverage() {
    const ID: &str = "rId99";
    assert!(!SIGNATURE.contains(&format!("SourceId=\"{ID}\"")));
    let temporary = TemporaryResources::new();
    let relationships = temporary.0.join("word/_rels/document.xml.rels");
    let original = fs::read_to_string(&relationships).unwrap();
    // Both targets already exist in the real package. This is only a statement
    // about the transform-selected relationship set, not complete OPC approval.
    for target in ["webSettings.xml", "settings.xml"] {
        let added = format!(
            "<Relationship Id=\"{ID}\" Type=\"urn:example:unselected\" Target=\"{target}\"/></Relationships>"
        );
        fs::write(
            &relationships,
            original.replacen("</Relationships>", &added, 1),
        )
        .unwrap();
        let context = context(&temporary.0);
        let result = verify_with_manifests(&context, SIGNATURE, &ManifestLimits::default())
            .expect("an unselected relationship does not change signed transform output");
        assert!(result.signature.is_valid());
        assert_eq!(result.manifests.len(), 1);
        assert_eq!(result.manifests[0].references.len(), 8);
        assert!(result.manifests[0]
            .references
            .iter()
            .all(|reference| reference.digest_verified));
    }
}

#[test]
fn source_less_original_dom_assesses_all_declared_ooxml_members() {
    let context = context(Path::new(FIXTURE));
    let document = uppsala::parse(SIGNATURE).unwrap();
    let result =
        verify_document_with_manifests(&context, &document, None, &ManifestLimits::default())
            .expect(
                "the source-less DOM entry point preserves real signature and member assessment",
            );
    assert!(result.signature.is_valid());
    assert_eq!(result.manifests.len(), 1);
    assert_eq!(result.manifests[0].references.len(), RESOURCES.len());
    for (actual, (expected_uri, _)) in result.manifests[0].references.iter().zip(RESOURCES) {
        assert_eq!(actual.uri, expected_uri);
        assert!(actual.digest_verified);
    }
}

#[test]
fn caller_selected_larger_budgets_preserve_genuine_ooxml_assessment() {
    let context = context(Path::new(FIXTURE));
    let mut limits = ManifestLimits::default();
    limits.max_depth = 16;
    limits.max_manifests = 64;
    limits.max_references = 512;
    limits.max_document_bytes = 32 * 1024 * 1024;
    limits.max_reference_bytes = 64 * 1024 * 1024;
    limits.max_nodes = 200_000;
    let result = verify_with_manifests(&context, SIGNATURE, &limits)
        .expect("applications may select larger package/reference budgets");
    assert!(result.signature.is_valid());
    assert_eq!(result.manifests.len(), 1);
    assert_eq!(result.manifests[0].references.len(), 8);
    assert!(result.manifests[0]
        .references
        .iter()
        .all(|reference| reference.digest_verified));
}
