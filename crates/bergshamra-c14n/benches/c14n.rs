//! Performance harness for bergshamra-c14n.
//!
//! Measures the hot paths exercised by every XML-DSig / XML-Enc operation:
//! XML parsing, inclusive/exclusive canonicalization, and entity escaping.
//!
//! Inputs are generated deterministically in-code so the harness is fully
//! reproducible and self-contained (no dependency on the `test-data/` symlink).
//!
//! Run:    cargo bench -p bergshamra-c14n
//! Save:   cargo bench -p bergshamra-c14n -- --save-baseline main
//! Compare cargo bench -p bergshamra-c14n -- --baseline main

use bergshamra_c14n::{escape, exclusive, inclusive};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

const NO_PREFIXES: &[&str] = &[];

/// A SAML-shaped, namespace-heavy document with nested signed-assertion
/// structure: the realistic production case for this library.
fn saml_shaped() -> String {
    let mut s = String::with_capacity(16 * 1024);
    s.push_str(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response" Version="2.0" IssueInstant="2026-06-29T12:00:00Z">"#,
    );
    s.push_str(r#"<saml:Issuer>https://idp.example.org/metadata</saml:Issuer>"#);
    for i in 0..40 {
        s.push_str(&format!(
            r#"<saml:Assertion ID="_assertion{i}" Version="2.0" IssueInstant="2026-06-29T12:00:00Z"><saml:Issuer>https://idp.example.org/metadata</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">user-{i}@example.org</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2026-06-29T12:05:00Z" Recipient="https://sp.example.org/acs"/></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="urn:oid:1.2.3.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>value &amp; {i} &lt; threshold</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#,
        ));
    }
    s.push_str("</samlp:Response>");
    s
}

/// Text-heavy document: large text nodes peppered with escapable bytes
/// (`&`, `<`, `>`). Stresses `escape_text`.
fn text_heavy() -> String {
    let mut s = String::with_capacity(64 * 1024);
    s.push_str("<doc>");
    for i in 0..200 {
        s.push_str("<p>");
        // ~300 bytes of mostly-clean text with a few escapable chars sprinkled in.
        for _ in 0..10 {
            s.push_str("the quick brown fox jumps over the lazy dog ");
        }
        s.push_str(&format!("item {i} a &amp; b &lt; c &gt; d end."));
        s.push_str("</p>");
    }
    s.push_str("</doc>");
    s
}

/// Attribute-heavy document: many elements each with many attributes.
/// Stresses attribute collection/sorting and `escape_attr`.
fn attr_heavy() -> String {
    let mut s = String::with_capacity(64 * 1024);
    s.push_str("<root>");
    for i in 0..400 {
        s.push_str(&format!(
            r#"<cell id="c{i}" class="data-cell highlighted" data-row="{i}" data-col="3" title="value &amp; label &lt; {i}&gt;" style="color:red" lang="en" role="gridcell"/>"#,
        ));
    }
    s.push_str("</root>");
    s
}

fn bench_parse(c: &mut Criterion) {
    let inputs = [
        ("saml", saml_shaped()),
        ("text_heavy", text_heavy()),
        ("attr_heavy", attr_heavy()),
    ];
    let mut group = c.benchmark_group("parse");
    for (name, xml) in &inputs {
        group.throughput(Throughput::Bytes(xml.len() as u64));
        group.bench_function(*name, |b| {
            b.iter(|| {
                let doc = uppsala::parse(black_box(xml)).unwrap();
                black_box(doc.root());
            });
        });
    }
    group.finish();
}

fn bench_c14n_inclusive(c: &mut Criterion) {
    let inputs = [
        ("saml", saml_shaped()),
        ("text_heavy", text_heavy()),
        ("attr_heavy", attr_heavy()),
    ];
    let mut group = c.benchmark_group("c14n_inclusive");
    for (name, xml) in &inputs {
        let doc = uppsala::parse(xml).unwrap();
        group.throughput(Throughput::Bytes(xml.len() as u64));
        group.bench_function(*name, |b| {
            b.iter(|| {
                let out = inclusive::canonicalize(black_box(&doc), false, None).unwrap();
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_c14n_exclusive(c: &mut Criterion) {
    let inputs = [
        ("saml", saml_shaped()),
        ("text_heavy", text_heavy()),
        ("attr_heavy", attr_heavy()),
    ];
    let mut group = c.benchmark_group("c14n_exclusive");
    for (name, xml) in &inputs {
        let doc = uppsala::parse(xml).unwrap();
        group.throughput(Throughput::Bytes(xml.len() as u64));
        group.bench_function(*name, |b| {
            b.iter(|| {
                let out =
                    exclusive::canonicalize(black_box(&doc), false, None, NO_PREFIXES).unwrap();
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_escape(c: &mut Criterion) {
    // Common case: large mostly-clean text with sparse escapable bytes.
    let mut clean = String::with_capacity(8192);
    for _ in 0..180 {
        clean.push_str("the quick brown fox jumps over the lazy dog ");
    }
    let mut sparse = clean.clone();
    sparse.push_str(" a & b < c > d \" e");

    // Worst case: escapable byte every few characters.
    let dense: String = "a&b<c>d\"e\t".repeat(800);

    let mut group = c.benchmark_group("escape");

    group.throughput(Throughput::Bytes(sparse.len() as u64));
    group.bench_function("text_sparse", |b| {
        b.iter(|| black_box(escape::escape_text(black_box(&sparse))));
    });
    group.bench_function("attr_sparse", |b| {
        b.iter(|| black_box(escape::escape_attr(black_box(&sparse))));
    });

    group.throughput(Throughput::Bytes(dense.len() as u64));
    group.bench_function("text_dense", |b| {
        b.iter(|| black_box(escape::escape_text(black_box(&dense))));
    });
    group.bench_function("attr_dense", |b| {
        b.iter(|| black_box(escape::escape_attr(black_box(&dense))));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse,
    bench_c14n_inclusive,
    bench_c14n_exclusive,
    bench_escape
);
criterion_main!(benches);
