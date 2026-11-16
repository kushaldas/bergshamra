//! Authenticated same-document Manifest graphs. All signatures and reference
//! digests are produced by the engine's existing signing/C14N/digest code.

use base64::Engine;
use bergshamra_c14n::{canonicalize_doc, C14nMode};
use bergshamra_core::{algorithm, ns};
use bergshamra_crypto::digest;
use bergshamra_dsig::verify::{verify, verify_with_manifests, ManifestLimits};
use bergshamra_dsig::{sign, DsigContext, VerifyResult};
use bergshamra_keys::{loader, KeysManager};
use bergshamra_xml::NodeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const SECRET: &[u8] = b"manifest-graph-tests-use-a-real-hmac-key";
const MANIFEST_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#Manifest";
const PLACEHOLDER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn context() -> DsigContext {
    let mut keys = KeysManager::new();
    keys.add_key(loader::load_hmac_key(SECRET).unwrap());
    DsigContext::new_permissive(keys)
}

fn limits_with(configure: fn(&mut ManifestLimits)) -> ManifestLimits {
    let mut limits = ManifestLimits::default();
    configure(&mut limits);
    limits
}

fn reference(uri: &str, reference_type: Option<&str>, transforms: &str, value: &str) -> String {
    let reference_type = reference_type
        .map(|value| format!(" Type=\"{value}\""))
        .unwrap_or_default();
    let transforms = if transforms.is_empty() {
        String::new()
    } else {
        format!("<ds:Transforms>{transforms}</ds:Transforms>")
    };
    format!(
        r#"<ds:Reference URI="{uri}"{reference_type}>{transforms}<ds:DigestMethod Algorithm="{sha256}"/><ds:DigestValue>{value}</ds:DigestValue></ds:Reference>"#,
        sha256 = algorithm::SHA256
    )
}

fn manifest(id: &str, references: &str) -> String {
    format!(r#"<ds:Manifest Id="{id}">{references}</ds:Manifest>"#)
}

fn template(outer_references: &str, objects: &str) -> String {
    format!(
        r#"<Root xmlns:ds="{ds}"><Payload Id="payload">original body</Payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{c14n}"/><ds:SignatureMethod Algorithm="{hmac}"/>{outer_references}</ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:Object Id="object">{objects}</ds:Object></ds:Signature></Root>"#,
        ds = ns::DSIG,
        c14n = algorithm::C14N,
        hmac = algorithm::HMAC_SHA256,
    )
}

/// Compute a fixture digest using precisely the engine's ordinary subtree C14N
/// and hash primitives; this helper is not part of product verification.
fn node_digest(xml: &str, target: &str) -> String {
    let doc = uppsala::parse(xml).unwrap();
    let id = doc
        .descendants(doc.root())
        .into_iter()
        .find(|id| {
            doc.element(*id)
                .and_then(|element| element.get_attribute("Id"))
                == Some(target)
        })
        .expect("fixture reference target");
    let nodes = NodeSet::tree_without_comments(id, &doc);
    let bytes = canonicalize_doc(&doc, C14nMode::Inclusive, Some(&nodes), &[] as &[String])
        .expect("fixture subtree C14N");
    base64::engine::general_purpose::STANDARD
        .encode(digest::digest(algorithm::SHA256, &bytes).unwrap())
}

fn fill_digest(mut xml: String, placeholder: &str, target: &str) -> String {
    let digest = node_digest(&xml, target);
    assert!(xml.contains(placeholder));
    xml = xml.replace(placeholder, &digest);
    xml
}

fn sign_template(xml: &str) -> String {
    sign::sign(&context(), xml).expect("real HMAC fixture signing")
}

/// A -> B -> payload, with B intentionally outside A's subtree. A signed digest
/// authenticates B's full subtree; the next digest authenticates the payload.
fn nested_template(shared_target: bool) -> String {
    let to_b = reference("#b", Some(MANIFEST_TYPE), "", "DIGEST_B");
    let a = manifest("a", &to_b.repeat(if shared_target { 2 } else { 1 }));
    let b = manifest("b", &reference("#payload", None, "", "DIGEST_PAYLOAD"));
    let xml = template(&reference("#a", Some(MANIFEST_TYPE), "", ""), &(a + &b));
    let xml = fill_digest(xml, "DIGEST_PAYLOAD", "payload");
    fill_digest(xml, "DIGEST_B", "b")
}

#[test]
fn authenticated_nested_manifests_validate_every_reference() {
    let signed = sign_template(&nested_template(false));
    assert!(verify(&context(), &signed).unwrap().is_valid());
    let result = verify_with_manifests(&context(), &signed, &ManifestLimits::default())
        .expect("A -> B -> payload must be fully checked");
    assert!(result.signature.is_valid());
    assert_eq!(result.manifests.len(), 2);
    assert_eq!(
        result
            .manifests
            .iter()
            .map(|manifest| manifest.references.len())
            .sum::<usize>(),
        2
    );
    assert!(result.manifests.iter().all(|manifest| manifest
        .references
        .iter()
        .all(|reference| reference.digest_verified)));
}

#[test]
fn nested_payload_tamper_cannot_be_hidden_by_valid_outer_signature() {
    let signed = sign_template(&nested_template(false));
    let changed = signed.replacen("original body", "changed body", 1);
    assert_ne!(signed, changed);
    assert!(verify(&context(), &changed).unwrap().is_valid());
    let error = verify_with_manifests(&context(), &changed, &ManifestLimits::default())
        .expect_err("nested B payload digest must be checked")
        .to_string();
    assert!(error.contains("Manifest"), "{error}");
    assert!(error.contains("#payload"), "{error}");
}

#[test]
fn nested_manifest_depth_and_total_reference_limits_are_enforced() {
    let signed = sign_template(&nested_template(false));
    let restrictions: [fn(&mut ManifestLimits); 4] = [
        |limits| limits.max_depth = 1,
        |limits| limits.max_depth = 65, // The explicit recursion hard cap is 64.
        |limits| limits.max_manifests = 1,
        |limits| limits.max_references = 2, // Outer + A + B require three.
    ];
    for restrict in restrictions {
        let mut limits = ManifestLimits::default();
        restrict(&mut limits);
        assert!(verify_with_manifests(&context(), &signed, &limits).is_err());
    }
}

#[test]
fn repeated_acyclic_manifest_target_is_assessed_once() {
    let signed = sign_template(&nested_template(true));
    let limits = limits_with(|limits| {
        limits.max_manifests = 2;
        limits.max_references = 4; // Outer + A's two edges + B's one edge.
    });
    let result = verify_with_manifests(&context(), &signed, &limits)
        .expect("a repeated DAG target is not a cycle");
    assert_eq!(result.manifests.len(), 2);
    let mut counts = result
        .manifests
        .iter()
        .map(|manifest| manifest.references.len())
        .collect::<Vec<_>>();
    counts.sort_unstable();
    assert_eq!(counts, vec![1, 2]);
}

#[test]
fn cached_dag_target_still_obeys_the_depth_of_each_reachable_path() {
    let a = manifest(
        "a",
        &(reference("#b", Some(MANIFEST_TYPE), "", "DIGEST_B")
            + &reference("#c", Some(MANIFEST_TYPE), "", "DIGEST_C")),
    );
    let b = manifest("b", &reference("#d", Some(MANIFEST_TYPE), "", "DIGEST_D"));
    let c = manifest("c", &reference("#b", Some(MANIFEST_TYPE), "", "DIGEST_B"));
    let d = manifest("d", &reference("#payload", None, "", "DIGEST_PAYLOAD"));
    let xml = template(
        &reference("#a", Some(MANIFEST_TYPE), "", ""),
        &(a + &b + &c + &d),
    );
    let xml = fill_digest(xml, "DIGEST_PAYLOAD", "payload");
    let xml = fill_digest(xml, "DIGEST_D", "d");
    let xml = fill_digest(xml, "DIGEST_B", "b");
    let xml = fill_digest(xml, "DIGEST_C", "c");
    let signed = sign_template(&xml);
    let result = verify_with_manifests(&context(), &signed, &ManifestLimits::default())
        .expect("A -> B -> D and A -> C -> B -> D is an acyclic shared graph");
    assert_eq!(result.manifests.len(), 4);

    // B is cached at depth two with descendant D at depth three. Reaching B
    // through C is itself legal at depth three, but its cached descendant D
    // would be at depth four. Checking B's entry depth alone is insufficient.
    let limits = limits_with(|limits| limits.max_depth = 3);
    let error = verify_with_manifests(&context(), &signed, &limits)
        .expect_err("a cached subtree cannot hide descendants beyond max_depth")
        .to_string();
    assert!(error.to_ascii_lowercase().contains("depth"), "{error}");
}

#[test]
fn manifest_cycles_are_reported_before_invalid_member_digests() {
    let a = manifest("a", &reference("#b", Some(MANIFEST_TYPE), "", PLACEHOLDER));
    let b = manifest("b", &reference("#a", Some(MANIFEST_TYPE), "", PLACEHOLDER));
    let self_cycle = manifest("a", &reference("#a", Some(MANIFEST_TYPE), "", PLACEHOLDER));
    for objects in [a + &b, self_cycle] {
        let signed = sign_template(&template(
            &reference("#a", Some(MANIFEST_TYPE), "", ""),
            &objects,
        ));
        // The containing outer signature is authentic. Cyclic internal digest
        // placeholders cannot satisfy cryptographic fixed points and must not
        // hide that the graph itself is cyclic.
        assert!(verify(&context(), &signed).unwrap().is_valid());
        let error = verify_with_manifests(&context(), &signed, &ManifestLimits::default())
            .expect_err("a reachable Manifest cycle must be explicit")
            .to_string();
        assert!(error.to_ascii_lowercase().contains("cycle"), "{error}");
    }
}

#[test]
fn unrelated_unsigned_manifest_is_not_reported_as_authenticated() {
    let unsigned = manifest(
        "unsigned",
        &reference("urn:missing:unsigned-member", None, "", PLACEHOLDER),
    );
    let signed = sign_template(&template(&reference("#payload", None, "", ""), &unsigned));
    let result = verify_with_manifests(&context(), &signed, &ManifestLimits::default())
        .expect("the unrelated Manifest is outside the authenticated reference");
    assert!(result.signature.is_valid());
    assert!(result.manifests.is_empty());
}

#[test]
fn filtering_transforms_do_not_authenticate_excluded_manifest_claims() {
    let unsigned = manifest(
        "unsigned",
        &reference("urn:missing:unsigned-member", None, "", ""),
    );
    let xpath = format!(
        r#"<ds:Transform Algorithm="{}"><ds:XPath>not(ancestor-or-self::ds:Manifest)</ds:XPath></ds:Transform>"#,
        algorithm::XPATH
    );
    let base64 = format!(r#"<ds:Transform Algorithm="{}"/>"#, algorithm::BASE64);
    for (transform, objects) in [
        (xpath, unsigned.clone()),
        (base64, format!("QUJD{unsigned}")),
    ] {
        let signed = sign_template(&template(
            &reference("#object", None, &transform, ""),
            &objects,
        ));
        assert!(verify(&context(), &signed).unwrap().is_valid());
        let error = verify_with_manifests(&context(), &signed, &ManifestLimits::default())
            .expect_err("filtered unsigned Manifest cannot be treated as covered")
            .to_string();
        assert!(error.contains("Manifest"), "{error}");
        assert!(error.to_ascii_lowercase().contains("transform"), "{error}");
    }
}

struct TemporaryFile(PathBuf);

impl TemporaryFile {
    fn new(contents: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bergshamra-external-manifest-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, contents).unwrap();
        Self(path)
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn explicitly_typed_external_manifest_is_not_silently_skipped() {
    let external = format!(
        r#"<ds:Manifest xmlns:ds="{}"><ds:Reference URI="urn:missing:nested"><ds:DigestMethod Algorithm="{}"/><ds:DigestValue>{PLACEHOLDER}</ds:DigestValue></ds:Reference></ds:Manifest>"#,
        ns::DSIG,
        algorithm::SHA256
    );
    let file = TemporaryFile::new(external.as_bytes());
    let expected = base64::engine::general_purpose::STANDARD
        .encode(digest::digest(algorithm::SHA256, external.as_bytes()).unwrap());
    let uri = "urn:manifest:external";
    let a = manifest("a", &reference(uri, Some(MANIFEST_TYPE), "", &expected));
    let signed = sign_template(&template(&reference("#a", Some(MANIFEST_TYPE), "", ""), &a));
    let mut context = context();
    context.add_url_map(uri, file.0.to_str().unwrap());
    assert!(verify(&context, &signed).unwrap().is_valid());
    let error = verify_with_manifests(&context, &signed, &ManifestLimits::default())
        .expect_err("external Manifest recursion is unsupported, not outer-only Valid")
        .to_string();
    assert!(error.contains("Manifest"), "{error}");
    assert!(error.contains(uri), "{error}");
}

#[test]
fn requested_manifest_mode_never_skips_cid_digests() {
    let nested = manifest("a", &reference("cid:body", None, "", PLACEHOLDER));
    let signed_nested = sign_template(&template(
        &reference("#a", Some(MANIFEST_TYPE), "", ""),
        &nested,
    ));
    let signed_outer = sign_template(&template(
        &reference("cid:outer", None, "", PLACEHOLDER),
        "",
    ));
    for (signed, uri) in [(signed_nested, "cid:body"), (signed_outer, "cid:outer")] {
        let mut context = context();
        context.require_reference_digests = false;
        assert!(verify(&context, &signed).unwrap().is_valid());
        let error = verify_with_manifests(&context, &signed, &ManifestLimits::default())
            .expect_err("opt-in Manifest mode requires actual digest checks")
            .to_string();
        assert!(error.contains(uri), "{error}");
    }
}

#[test]
fn parent_binding_is_checked_before_untrusted_child_resources() {
    let signed = sign_template(&nested_template(false));
    let tampered_child = signed.replacen(
        "URI=\"#payload\"",
        "URI=\"urn:untrusted:child-resource\"",
        1,
    );
    assert_ne!(signed, tampered_child);
    assert!(verify(&context(), &tampered_child).unwrap().is_valid());
    let error = verify_with_manifests(&context(), &tampered_child, &ManifestLimits::default())
        .expect_err("A's binding to changed B must fail before B's resource is resolved");
    assert!(
        matches!(error, bergshamra_core::Error::DigestMismatch(_)),
        "{error}"
    );
    assert!(error.to_string().contains("#b"), "{error}");
}

#[test]
fn explicit_manifest_type_cannot_relabel_an_ordinary_payload() {
    let xml = template(&reference("#payload", Some(MANIFEST_TYPE), "", ""), "");
    let signed = sign_template(&xml);
    assert!(verify(&context(), &signed).unwrap().is_valid());
    let error = verify_with_manifests(&context(), &signed, &ManifestLimits::default())
        .expect_err("Manifest Type must identify a Manifest element");
    assert!(error.to_string().contains("#payload"), "{error}");
}

fn assert_structure(error: bergshamra_core::Error, fragment: &str) {
    assert!(
        matches!(error, bergshamra_core::Error::XmlStructure(_)),
        "{error}"
    );
    assert!(error.to_string().contains(fragment), "{error}");
}

#[test]
fn enveloped_document_reference_excludes_signature_but_object_reference_covers_manifest() {
    let env = format!(
        r#"<ds:Transform Algorithm="{}"/>"#,
        algorithm::ENVELOPED_SIGNATURE
    );
    for root_uri in ["", "#xpointer(/)"] {
        let m = manifest("a", &reference("#payload", None, "", "DIGEST_PAYLOAD"));
        let xml = template(
            &(reference(root_uri, None, &env, "") + &reference("#object", None, "", "")),
            &m,
        );
        let xml = fill_digest(xml, "DIGEST_PAYLOAD", "payload");
        let signed = sign_template(&xml);
        assert!(verify(&context(), &signed).unwrap().is_valid());
        let report = verify_with_manifests(&context(), &signed, &ManifestLimits::default())
            .expect("enveloped exclusion must not hide the separately authenticated Object");
        assert_eq!(report.manifests.len(), 1);
        assert_eq!(report.manifests[0].references[0].uri, "#payload");
    }
}

#[test]
fn large_ordinary_enveloped_document_does_not_consume_manifest_node_budget() {
    let env = format!(
        r#"<ds:Transform Algorithm="{}"/>"#,
        algorithm::ENVELOPED_SIGNATURE
    );
    let xml = template(&reference("", None, &env, ""), "")
        .replace("original body", &"<Item/>".repeat(100_100));
    let signed = sign_template(&xml);
    assert!(verify(&context(), &signed).unwrap().is_valid());
    assert!(
        verify_with_manifests(&context(), &signed, &ManifestLimits::default())
            .expect("a >100k-node ordinary document needs no Manifest traversal")
            .manifests
            .is_empty()
    );
    let mut limits = ManifestLimits::default();
    limits.max_nodes = 0; // No reachable Manifest candidates need graph inspection.
    let report = verify_with_manifests(&context(), &signed, &limits)
        .expect("ordinary payload nodes are not Manifest graph work");
    assert!(matches!(report.signature, VerifyResult::Valid { .. }));
    assert!(report.manifests.is_empty());
}

#[test]
fn enveloped_exclusion_preserves_manifests_outside_the_signature() {
    let env = format!(
        r#"<ds:Transform Algorithm="{}"/>"#,
        algorithm::ENVELOPED_SIGNATURE
    );
    let m = manifest("a", &reference("#payload", None, "", "DIGEST_PAYLOAD"));
    let xml = template(&reference("", None, &env, ""), "")
        .replace("<ds:Signature>", &(m + "<ds:Signature>"));
    let xml = fill_digest(xml, "DIGEST_PAYLOAD", "payload");
    let signed = sign_template(&xml);
    let report = verify_with_manifests(&context(), &signed, &ManifestLimits::default())
        .expect("enveloped data outside Signature remains authenticated");
    assert_eq!(report.manifests.len(), 1);
}

fn strict_template(wrapped: bool) -> String {
    let m = manifest("a", &reference("#payload", None, "", "DIGEST_PAYLOAD"));
    let mut xml = template(&reference("#a", Some(MANIFEST_TYPE), "", ""), "")
        .replace("<ds:Signature>", &(m + "<ds:Signature>"));
    if wrapped {
        xml = xml.replace(
            "<Payload Id=\"payload\">original body</Payload>",
            "<Wrapper><Payload Id=\"payload\">original body</Payload></Wrapper>",
        );
    }
    fill_digest(xml, "DIGEST_PAYLOAD", "payload")
}

#[test]
fn strict_position_policy_applies_to_manifest_members_and_permissive_mode_reports_targets() {
    for wrapped in [false, true] {
        let signed = sign_template(&strict_template(wrapped));
        let permissive =
            verify_with_manifests(&context(), &signed, &ManifestLimits::default()).unwrap();
        assert!(permissive.manifests[0].references[0]
            .resolved_node
            .is_some());
        let mut strict = context();
        strict.strict_verification = true;
        assert!(verify(&strict, &signed).unwrap().is_valid()); // Manifest is a Signature sibling.
        let result = verify_with_manifests(&strict, &signed, &ManifestLimits::default());
        if wrapped {
            assert_structure(
                result.expect_err("wrapped member violates caller XSW position policy"),
                "strict mode",
            );
        } else {
            assert!(result.is_ok(), "sibling member is eligible: {result:?}");
        }
    }
}

fn signature_part(xml: &str) -> String {
    let start = xml.find("<ds:Signature>").unwrap();
    let end = xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    xml[start..end].to_owned()
}

#[test]
fn first_signature_and_original_dom_provenance_are_explicit() {
    let plain = signature_part(&sign_template(&template(
        &reference("#payload", None, "", ""),
        "",
    )))
    .replace("Id=\"object\"", "Id=\"plain-object\"");
    let nested = signature_part(&sign_template(&nested_template(false)));
    for (signatures, expected_count) in [(plain.clone() + &nested, 0), (nested + &plain, 2)] {
        let xml = format!(
            r#"<Root xmlns:ds="{}"><Payload Id="payload">original body</Payload>{signatures}</Root>"#,
            ns::DSIG
        );
        let all = bergshamra_dsig::verify::verify_all(&context(), &xml).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(VerifyResult::is_valid));
        let doc = uppsala::parse(&xml).unwrap();
        let signatures = doc
            .descendants(doc.root())
            .into_iter()
            .filter(|id| {
                doc.element(*id)
                    .is_some_and(|e| e.matches_name_ns(ns::DSIG, "Signature"))
            })
            .collect::<Vec<_>>();
        let report = bergshamra_dsig::verify::verify_document_with_manifests(
            &context(),
            &doc,
            Some(&xml),
            &ManifestLimits::default(),
        )
        .unwrap();
        let VerifyResult::Valid {
            signature_node,
            references,
            ..
        } = &report.signature
        else {
            panic!("Ok must carry Valid")
        };
        assert_eq!(*signature_node, signatures[0]);
        assert_eq!(report.manifests.len(), expected_count);
        if expected_count != 0 {
            assert_eq!(references[0].uri, "#a");
            for manifest in &report.manifests {
                assert!(doc
                    .element(manifest.manifest_node)
                    .unwrap()
                    .matches_name_ns(ns::DSIG, "Manifest"));
                for member in &manifest.references {
                    let target = doc.element(member.resolved_node.unwrap()).unwrap();
                    assert_eq!(
                        Some(member.uri.trim_start_matches('#')),
                        target.get_attribute("Id")
                    );
                }
            }
        }
    }
}

#[test]
fn digest_mismatches_have_the_same_category_in_outer_and_manifest_references() {
    let outer = sign_template(&template(&reference("#payload", None, "", ""), ""));
    let nested = sign_template(&nested_template(false));
    for signed in [outer, nested] {
        let changed = signed.replacen("original body", "changed body", 1);
        let error =
            verify_with_manifests(&context(), &changed, &ManifestLimits::default()).unwrap_err();
        assert!(
            matches!(error, bergshamra_core::Error::DigestMismatch(_)),
            "{error}"
        );
        assert!(error.to_string().contains("#payload"), "{error}");
    }
}

#[test]
fn unsupported_member_digest_and_unresolved_uri_retain_their_error_categories() {
    for (member, unsupported) in [
        (
            reference("#payload", None, "", PLACEHOLDER)
                .replace(algorithm::SHA256, "urn:unsupported:digest"),
            true,
        ),
        (
            reference("urn:unmapped:member", None, "", PLACEHOLDER),
            false,
        ),
    ] {
        let signed = sign_template(&template(
            &reference("#a", Some(MANIFEST_TYPE), "", ""),
            &manifest("a", &member),
        ));
        let error =
            verify_with_manifests(&context(), &signed, &ManifestLimits::default()).unwrap_err();
        if unsupported {
            assert!(
                matches!(error, bergshamra_core::Error::UnsupportedAlgorithm(_)),
                "{error}"
            );
        } else {
            assert!(
                matches!(error, bergshamra_core::Error::InvalidUri(_)),
                "{error}"
            );
        }
        assert!(error.to_string().contains("Manifest"), "{error}");
        assert!(
            error.to_string().contains(if unsupported {
                "#payload"
            } else {
                "urn:unmapped:member"
            }),
            "{error}"
        );
    }
}

#[test]
fn graph_error_precedence_and_invalid_outer_result_are_explicit() {
    let ordinary = sign_template(&template(&reference("#payload", None, "", ""), ""));
    let a = manifest("a", &reference("#a", Some(MANIFEST_TYPE), "", PLACEHOLDER));
    let cyclic = sign_template(&template(&reference("#a", Some(MANIFEST_TYPE), "", ""), &a));
    for (signed, cycle) in [(ordinary, false), (cyclic, true)] {
        let begin = signed.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
        let mut invalid = signed.clone();
        invalid.replace_range(
            begin..begin + 1,
            if &signed[begin..begin + 1] == "A" {
                "B"
            } else {
                "A"
            },
        );
        assert!(!verify(&context(), &invalid).unwrap().is_valid());
        let error =
            verify_with_manifests(&context(), &invalid, &ManifestLimits::default()).unwrap_err();
        if cycle {
            assert_structure(error, "cycle");
        } else {
            assert!(
                matches!(error, bergshamra_core::Error::SignatureInvalid(_)),
                "{error}"
            );
        }
    }
}

#[test]
fn callers_can_raise_reference_budget_without_changing_default_policy() {
    let member = reference("#payload", None, "", "DIGEST_PAYLOAD");
    let xml = template(
        &reference("#a", Some(MANIFEST_TYPE), "", ""),
        &manifest("a", &member.repeat(129)),
    );
    let signed = sign_template(&fill_digest(xml, "DIGEST_PAYLOAD", "payload"));
    assert_structure(
        verify_with_manifests(&context(), &signed, &ManifestLimits::default()).unwrap_err(),
        "references",
    );
    let mut limits = ManifestLimits::default();
    limits.max_references = 130;
    let report = verify_with_manifests(&context(), &signed, &limits).unwrap();
    assert_eq!(report.manifests[0].references.len(), 129);
}
