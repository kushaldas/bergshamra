use bergshamra::xml as bergshamra_xml;
use bergshamra::c14n as bergshamra_c14n;
use bergshamra::crypto as bergshamra_crypto;

fn main() {
    let path = std::env::args().nth(1).expect("usage: debug_digest <xml_file>");
    let xml = std::fs::read_to_string(&path).unwrap();
    let xdoc = bergshamra_xml::XmlDocument::parse(xml.clone()).unwrap();
    let inner = xdoc.parse_doc().unwrap();

    // Build ID map
    let mut id_map = std::collections::HashMap::new();
    for node in inner.descendants() {
        if node.is_element() {
            for attr in &["Id", "ID", "id"] {
                if let Some(val) = node.attribute(*attr) {
                    id_map.insert(val.to_string(), node.id());
                }
            }
        }
    }

    // Find Signature -> SignedInfo -> Reference elements
    let sig_node = inner.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .expect("no Signature");
    let signed_info = sig_node.children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .expect("no SignedInfo");

    for reference in signed_info.children().filter(|n| n.is_element() && n.tag_name().name() == "Reference") {
        let uri = reference.attribute("URI").unwrap_or("");
        eprintln!("=== Reference URI: {}", uri);

        // Resolve URI
        if let Some(id) = uri.strip_prefix('#') {
            if let Some(&node_id) = id_map.get(id) {
                let node = inner.get_node(node_id).unwrap();
                let ns = bergshamra_xml::nodeset::NodeSet::tree_without_comments(node);

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
                let digest_uri = reference.children()
                    .find(|n| n.is_element() && n.tag_name().name() == "DigestMethod")
                    .and_then(|n| n.attribute("Algorithm"))
                    .unwrap_or("http://www.w3.org/2000/09/xmldsig#sha1");

                let digest = bergshamra_crypto::digest::digest(digest_uri, &result).unwrap();
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&digest);
                eprintln!("Computed digest: {}", b64);

                let expected = reference.children()
                    .find(|n| n.is_element() && n.tag_name().name() == "DigestValue")
                    .and_then(|n| n.text())
                    .unwrap_or("");
                eprintln!("Expected digest: {}", expected.trim());
                eprintln!("Match: {}", b64 == expected.trim());
            } else {
                eprintln!("ID '{}' not found in id_map", id);
            }
        }
    }
}
