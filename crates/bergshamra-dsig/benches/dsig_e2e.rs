//! End-to-end XML-DSig performance harness.
//!
//! Measures the shipped operations — enveloped signing and full verification —
//! over the same deterministic SAML-shaped fixture family as the C14N harness
//! (`bergshamra-c14n/benches/c14n.rs`). Each operation includes XML parsing,
//! the transform pipeline, canonicalization, digesting, and the RSA/HMAC
//! primitive, so the totals are the numbers users experience.
//!
//! Two signature methods are measured deliberately:
//! - `rsa` — the realistic production case (asymmetric crypto dominates).
//! - `hmac` — isolates the XML pipeline (parse + transforms + C14N + digest)
//!   from the asymmetric primitive, so regressions in XML code stay visible
//!   even when RSA dominates the total.
//!
//! Run:    cargo bench -p bergshamra-dsig --bench dsig_e2e
//! Save:   cargo bench -p bergshamra-dsig --bench dsig_e2e -- --save-baseline main
//! Compare cargo bench -p bergshamra-dsig --bench dsig_e2e -- --baseline main

use bergshamra_dsig::context::DsigContext;
use bergshamra_dsig::sign::{sign_enveloped_document, EnvelopedSignatureOptions};
use bergshamra_dsig::verify;
use bergshamra_keys::{Key, KeyData, KeyUsage, KeysManager};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

/// SAML-shaped, namespace-heavy document with nested signed-assertion
/// structure: the realistic production case for this library.
fn saml_shaped(assertions: usize) -> String {
    let mut s = String::with_capacity(16 * 1024 * (1 + assertions / 40));
    s.push_str(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response" Version="2.0" IssueInstant="2026-06-29T12:00:00Z">"#,
    );
    s.push_str(r#"<saml:Issuer>https://idp.example.org/metadata</saml:Issuer>"#);
    for i in 0..assertions {
        s.push_str(&format!(
            r#"<saml:Assertion ID="_assertion{i}" Version="2.0" IssueInstant="2026-06-29T12:00:00Z"><saml:Issuer>https://idp.example.org/metadata</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">user-{i}@example.org</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2026-06-29T12:05:00Z" Recipient="https://sp.example.org/acs"/></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="urn:oid:1.2.3.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>value &amp; {i} &lt; threshold</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#,
        ));
    }
    s.push_str("</samlp:Response>");
    s
}

/// Build a key manager holding one RSA-2048 key usable for sign and verify.
///
/// Key generation happens once per benchmark process and is excluded from all
/// measurements.
fn rsa_keys_manager() -> KeysManager {
    use rsa::pkcs8::EncodePrivateKey;

    let mut rng = rand::rngs::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .expect("RSA-2048 key generation must succeed for the benchmark");
    let der = private
        .to_pkcs8_der()
        .expect("PKCS#8 export must succeed for the benchmark");
    let data = KeyData::from_pkcs8_der(kryptering::KeyAlgorithm::Rsa, der.as_bytes())
        .expect("PKCS#8 import through kryptering must succeed");
    let mut keys = KeysManager::new();
    keys.add_key(Key::new(data, KeyUsage::Any));
    keys
}

/// Build a key manager holding one HMAC-SHA256 key.
fn hmac_keys_manager() -> KeysManager {
    let mut keys = KeysManager::new();
    keys.add_key(Key::new(
        KeyData::from_symmetric_bytes(kryptering::KeyAlgorithm::Hmac, b"dsig-e2e-benchmark-key")
            .expect("symmetric key import must succeed"),
        KeyUsage::Any,
    ));
    keys
}

/// Per-method benchmark context: signing context plus a pre-signed document.
struct MethodFixture {
    signing_ctx: DsigContext,
    verify_ctx: DsigContext,
    /// SAML-shaped input, signed once (excluded from measurement).
    signed_xml: String,
}

fn signature_method(method: &str) -> &'static str {
    match method {
        "rsa" => bergshamra_core::algorithm::RSA_SHA256,
        "hmac" => bergshamra_core::algorithm::HMAC_SHA256,
        other => panic!("unknown signature method {other}"),
    }
}

fn prepare(method: &'static str, assertions: usize) -> MethodFixture {
    let keys = match method {
        "rsa" => rsa_keys_manager(),
        "hmac" => hmac_keys_manager(),
        other => panic!("unknown signature method {other}"),
    };
    let signing_ctx = DsigContext::new_permissive(keys.clone());
    let verify_ctx = DsigContext::new_permissive(keys);

    let xml = saml_shaped(assertions);
    let mut doc = uppsala::parse(&xml)
        .expect("benchmark fixture must parse")
        .into_static();
    let options = EnvelopedSignatureOptions::new(
        None,
        signature_method(method),
        bergshamra_core::algorithm::SHA256,
        bergshamra_core::algorithm::EXC_C14N,
        None,
    );
    sign_enveloped_document(&signing_ctx, &mut doc, options)
        .expect("benchmark fixture signing must succeed");
    let signed_xml = doc.to_xml();

    // Prove the harness produces verifiable signatures before measuring.
    let result =
        verify::verify(&verify_ctx, &signed_xml).expect("benchmark verification must not error");
    assert!(
        result.is_valid(),
        "pre-signed benchmark fixture must verify: {result:?}"
    );

    MethodFixture {
        signing_ctx,
        verify_ctx,
        signed_xml,
    }
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");

    for (method, assertions) in [("rsa", 40), ("hmac", 40), ("hmac", 400)] {
        let fixture = prepare(method, assertions);
        // Generated once per benchmark; the timed closure measures only
        // parse + sign + serialize, as the module docs promise.
        let xml = saml_shaped(assertions);
        group.throughput(Throughput::Bytes(xml.len() as u64));
        group.bench_function(format!("enveloped_{method}_{assertions}"), |b| {
            let options = EnvelopedSignatureOptions::new(
                None,
                signature_method(method),
                bergshamra_core::algorithm::SHA256,
                bergshamra_core::algorithm::EXC_C14N,
                None,
            );
            b.iter(|| {
                let mut doc = uppsala::parse(black_box(&xml)).unwrap();
                sign_enveloped_document(&fixture.signing_ctx, &mut doc, options.clone()).unwrap();
                black_box(doc.to_xml());
            });
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    for (method, assertions) in [("rsa", 40), ("hmac", 40), ("hmac", 400)] {
        let fixture = prepare(method, assertions);
        group.throughput(Throughput::Bytes(fixture.signed_xml.len() as u64));
        group.bench_function(format!("enveloped_{method}_{assertions}"), |b| {
            b.iter(|| {
                let result = verify::verify(
                    black_box(&fixture.verify_ctx),
                    black_box(&fixture.signed_xml),
                )
                .unwrap();
                black_box(result.is_valid());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
