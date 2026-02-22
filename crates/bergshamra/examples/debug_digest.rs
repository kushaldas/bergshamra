#![forbid(unsafe_code)]

use bergshamra::xml as bergshamra_xml;
use bergshamra::c14n as bergshamra_c14n;
use bergshamra::crypto as bergshamra_crypto;
use uppsala::{NodeKind, NodeId};

fn main() {
    let path = std::env::args().nth(1).expect("usage: debug_digest <xml_file>");
    let xml = std::fs::read_to_string(&path).unwrap();
    let xdoc = bergshamra_xml::XmlDocument::parse(xml.clone()).unwrap();
    let doc = xdoc.parse_doc().unwrap();

    // Build ID map
    let mut id_map = std::collections::HashMap::new();
    for id in doc.descendants(doc.root()) {
        if let Some(elem) = doc.element(id) {
            for attr_name in &["Id", "ID", "id"] {
                if let Some(val) = elem.get_attribute(attr_name) {
                    id_map.insert(val.to_string(), id);
                }
            }
        }
    }

    // Find Signature -> SignedInfo -> Reference elements
    let sig_node = doc.descendants(doc.root())
        .into_iter()
        .find(|&id| {
            doc.element(id).map_or(false, |e| e.name.local_name == "Signature")
        })
        .expect("no Signature");
    let signed_info = doc.children(sig_node)
        .into_iter()
        .find(|&id| {
            doc.element(id).map_or(false, |e| e.name.local_name == "SignedInfo")
        })
        .expect("no SignedInfo");

    let references: Vec<NodeId> = doc.children(signed_info)
        .into_iter()
        .filter(|&id| {
            doc.element(id).map_or(false, |e| e.name.local_name == "Reference")
        })
        .collect();

    for reference in references {
        let uri = doc.element(reference)
            .and_then(|e| e.get_attribute("URI"))
            .unwrap_or("");
        eprintln!("=== Reference URI: {}", uri);

        // Resolve URI
        if let Some(id_val) = uri.strip_prefix('#') {
            if let Some(&node_id) = id_map.get(id_val) {
                let ns = bergshamra_xml::nodeset::NodeSet::tree_without_comments(node_id, &doc);

                let result = bergshamra_c14n::canonicalize(
                    &xml,
                    bergshamra_c14n::C14nMode::Inclusive,
                    Some(&ns),
                    &[],
                ).unwrap();

                eprintln!("PreDigest data ({} bytes):", result.len());
                eprintln!("{}", String::from_utf8_lossy(&result));
                eprintln!("--- END PreDigest ---");

                // Compute digest
                let digest_uri = doc.children(reference)
                    .into_iter()
                    .find(|&id| {
                        doc.element(id).map_or(false, |e| e.name.local_name == "DigestMethod")
                    })
                    .and_then(|id| doc.element(id).and_then(|e| e.get_attribute("Algorithm")))
                    .unwrap_or("http://www.w3.org/2000/09/xmldsig#sha1");

                let digest = bergshamra_crypto::digest::digest(digest_uri, &result).unwrap();
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&digest);
                eprintln!("Computed digest: {}", b64);

                let expected_text: String = doc.children(reference)
                    .into_iter()
                    .find(|&id| {
                        doc.element(id).map_or(false, |e| e.name.local_name == "DigestValue")
                    })
                    .map(|id| {
                        doc.children(id).into_iter().filter_map(|c| {
                            match doc.node_kind(c) {
                                Some(NodeKind::Text(t)) => Some(t.as_ref().to_owned()),
                                _ => None,
                            }
                        }).collect::<String>()
                    })
                    .unwrap_or_default();
                eprintln!("Expected digest: {}", expected_text.trim());
                eprintln!("Match: {}", b64 == expected_text.trim());
            } else {
                eprintln!("ID '{}' not found in id_map", id_val);
            }
        }
    }
}
