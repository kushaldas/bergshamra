#![forbid(unsafe_code)]

//! XML Canonicalization (C14N) for the Bergshamra XML Security library.
//!
//! Implements all six W3C canonicalization variants:
//! - Canonical XML 1.0 (with and without comments)
//! - Canonical XML 1.1 (with and without comments)
//! - Exclusive Canonical XML 1.0 (with and without comments)
//!
//! Most callers should use [`canonicalize`] when they have raw XML text or
//! [`canonicalize_doc`] when they already parsed the document with `uppsala`.
//! Both return the complete canonical byte stream. Digest-heavy callers, such
//! as XML-DSig verification, can use [`canonicalize_doc_to`] to write the same
//! canonical bytes into a custom sink and avoid a temporary `Vec<u8>`.

pub mod escape;
pub mod exclusive;
pub mod inclusive;
pub mod inclusive11;
pub mod render;

use bergshamra_core::{algorithm, Error};
use bergshamra_xml::NodeSet;
use uppsala::Document;

/// Destination for canonicalized bytes.
///
/// `Vec<u8>` implements this for the existing buffered API. DSig verification
/// implements it for a digest stream to avoid allocating the full canonical
/// byte vector when the caller only needs a hash.
///
/// Implementations must preserve byte order exactly and must not transform the
/// bytes. C14N output is usually signature or digest input, so any altered byte
/// changes the security result.
pub trait C14nSink {
    /// Reserve capacity if the sink buffers bytes.
    ///
    /// Non-buffering sinks can ignore this hint. The default implementation is
    /// intentionally a no-op so stream-like sinks do not need a fake capacity.
    fn reserve(&mut self, _additional: usize) {}

    /// Write canonicalized bytes to the sink.
    fn write(&mut self, bytes: &[u8]);

    /// Write one canonicalized byte to the sink.
    ///
    /// The default implementation forwards to [`Self::write`]. Buffering sinks
    /// may override this to avoid constructing a one-byte slice repeatedly.
    fn write_byte(&mut self, byte: u8) {
        self.write(&[byte]);
    }
}

impl C14nSink for Vec<u8> {
    /// Reserve output buffer capacity before appending more canonical bytes.
    fn reserve(&mut self, additional: usize) {
        Vec::reserve(self, additional);
    }

    /// Append canonical bytes to the output buffer.
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    /// Append one canonical byte to the output buffer.
    fn write_byte(&mut self, byte: u8) {
        self.push(byte);
    }
}

/// A supported XML canonicalization algorithm.
///
/// The enum is intentionally URI-oriented: XML-DSig templates and transforms
/// identify canonicalization algorithms by URI, and [`C14nMode::from_uri`] and
/// [`C14nMode::uri`] keep that mapping in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C14nMode {
    /// Canonical XML 1.0
    Inclusive,
    /// Canonical XML 1.0 with comments
    InclusiveWithComments,
    /// Canonical XML 1.1
    Inclusive11,
    /// Canonical XML 1.1 with comments
    Inclusive11WithComments,
    /// Exclusive Canonical XML 1.0
    Exclusive,
    /// Exclusive Canonical XML 1.0 with comments
    ExclusiveWithComments,
}

impl C14nMode {
    /// Return the XML Security algorithm URI for this canonicalization mode.
    pub fn uri(&self) -> &'static str {
        match self {
            Self::Inclusive => algorithm::C14N,
            Self::InclusiveWithComments => algorithm::C14N_WITH_COMMENTS,
            Self::Inclusive11 => algorithm::C14N11,
            Self::Inclusive11WithComments => algorithm::C14N11_WITH_COMMENTS,
            Self::Exclusive => algorithm::EXC_C14N,
            Self::ExclusiveWithComments => algorithm::EXC_C14N_WITH_COMMENTS,
        }
    }

    /// Parse a C14N mode from an XML Security algorithm URI.
    ///
    /// Returns `None` when the URI is not one of Bergshamra's supported C14N
    /// variants. Callers that need a user-facing error usually map this to
    /// [`Error::UnsupportedAlgorithm`].
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            algorithm::C14N => Some(Self::Inclusive),
            algorithm::C14N_WITH_COMMENTS => Some(Self::InclusiveWithComments),
            algorithm::C14N11 => Some(Self::Inclusive11),
            algorithm::C14N11_WITH_COMMENTS => Some(Self::Inclusive11WithComments),
            algorithm::EXC_C14N => Some(Self::Exclusive),
            algorithm::EXC_C14N_WITH_COMMENTS => Some(Self::ExclusiveWithComments),
            _ => None,
        }
    }

    /// Return whether this mode serializes comment nodes that are visible in
    /// the selected node set.
    pub fn with_comments(&self) -> bool {
        matches!(
            self,
            Self::InclusiveWithComments
                | Self::Inclusive11WithComments
                | Self::ExclusiveWithComments
        )
    }

    /// Return whether this mode uses Exclusive XML Canonicalization.
    ///
    /// Exclusive C14N applies the InclusiveNamespaces PrefixList; inclusive
    /// C14N modes ignore that list.
    pub fn is_exclusive(&self) -> bool {
        matches!(self, Self::Exclusive | Self::ExclusiveWithComments)
    }
}

impl std::fmt::Display for C14nMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.uri())
    }
}

/// Parse and canonicalize an XML document.
///
/// `node_set` selects a document subset. Pass `None` to canonicalize the whole
/// parsed document. `inclusive_prefixes` is used only for Exclusive C14N modes;
/// callers can pass an empty slice for inclusive modes.
///
/// # Errors
///
/// Returns [`Error::XmlParse`] if `xml` is not well-formed XML. Other errors
/// are returned by the selected canonicalization implementation.
pub fn canonicalize<S: AsRef<str>>(
    xml: &str,
    mode: C14nMode,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[S],
) -> Result<Vec<u8>, Error> {
    let doc = uppsala::parse(xml).map_err(|e| Error::XmlParse(e.to_string()))?;
    canonicalize_doc(&doc, mode, node_set, inclusive_prefixes)
}

/// Canonicalize an already parsed document into a new byte vector.
///
/// This avoids reparsing when the caller already holds an `uppsala` document.
/// It is otherwise equivalent to [`canonicalize`].
///
/// # Errors
///
/// Returns errors from the selected canonicalization implementation.
pub fn canonicalize_doc<S: AsRef<str>>(
    doc: &Document<'_>,
    mode: C14nMode,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[S],
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    canonicalize_doc_to(doc, mode, node_set, inclusive_prefixes, &mut output)?;
    Ok(output)
}

/// Capacity hint for buffering sinks before canonicalization starts.
///
/// Canonical output of a whole document is on the order of the input length,
/// and growing a `Vec<u8>` through realloc-copies on a 10 MB document is pure
/// waste, so whole-document and compact inverted selections (the enveloped
/// `URI=""` reference, the document element) reserve the input length up
/// front. Only [`NodeSetType::Invert`] stores exclusions; every other
/// variant, `TreeInvert` included, materializes its visible node IDs (see
/// `NodeSet::contains_id`). Materialized selections such as a `<SignedInfo>`
/// subtree are usually tiny relative to the document; pre-sizing them to the
/// input would turn a few hundred bytes of output into an input-sized
/// allocation on every sign and verify, so they return no hint and grow from
/// their actual output.
fn output_size_hint(doc: &Document<'_>, node_set: Option<&NodeSet>) -> Option<usize> {
    use bergshamra_xml::nodeset::NodeSetType;

    match node_set.map(NodeSet::set_type) {
        None | Some(NodeSetType::Invert) => Some(doc.input_text().len()),
        Some(NodeSetType::Normal)
        | Some(NodeSetType::Tree)
        | Some(NodeSetType::TreeWithoutComments)
        | Some(NodeSetType::TreeInvert) => None,
    }
}

/// Canonicalize an already parsed document into a byte sink.
///
/// This is the streaming form of [`canonicalize_doc`]. It is useful when the
/// caller wants to hash, write, or otherwise consume canonical bytes without
/// retaining the entire canonical stream in memory.
///
/// `output` receives exactly the same bytes that [`canonicalize_doc`] would
/// return. The function does not clear or reset the sink before writing.
///
/// # Errors
///
/// Returns errors from the selected canonicalization implementation.
pub fn canonicalize_doc_to<S: AsRef<str>, W: C14nSink>(
    doc: &Document<'_>,
    mode: C14nMode,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[S],
    output: &mut W,
) -> Result<(), Error> {
    if let Some(hint) = output_size_hint(doc, node_set) {
        output.reserve(hint);
    }
    match mode {
        C14nMode::Inclusive | C14nMode::InclusiveWithComments => {
            inclusive::canonicalize_to(doc, mode.with_comments(), node_set, output)
        }
        C14nMode::Inclusive11 | C14nMode::Inclusive11WithComments => {
            inclusive11::canonicalize_to(doc, mode.with_comments(), node_set, output)
        }
        C14nMode::Exclusive | C14nMode::ExclusiveWithComments => exclusive::canonicalize_to(
            doc,
            mode.with_comments(),
            node_set,
            inclusive_prefixes,
            output,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bergshamra_xml::nodeset::{NodeIdSet, NodeSetType};

    /// Sink that records every capacity hint it receives.
    #[derive(Default)]
    struct RecordingSink {
        reserved: Vec<usize>,
        bytes: Vec<u8>,
    }

    impl C14nSink for RecordingSink {
        fn reserve(&mut self, additional: usize) {
            self.reserved.push(additional);
        }

        fn write(&mut self, bytes: &[u8]) {
            self.bytes.extend_from_slice(bytes);
        }
    }

    const XML: &str = r#"<Root xmlns="urn:x"><A><B>text</B></A><C>more</C></Root>"#;

    fn canonicalize_recording(node_set: Option<&NodeSet>) -> RecordingSink {
        let doc = uppsala::parse(XML).expect("fixture must parse");
        let mut sink = RecordingSink::default();
        canonicalize_doc_to::<&str, _>(&doc, C14nMode::Exclusive, node_set, &[], &mut sink)
            .expect("canonicalization must succeed");
        sink
    }

    /// The serializers issue small per-node hints of their own; only the
    /// leading, input-sized hint from `canonicalize_doc_to` is under test.
    fn input_sized_hints(sink: &RecordingSink) -> Vec<usize> {
        sink.reserved
            .iter()
            .copied()
            .filter(|&n| n >= XML.len())
            .collect()
    }

    #[test]
    fn whole_document_reserves_input_length() {
        let sink = canonicalize_recording(None);
        assert_eq!(sink.reserved.first(), Some(&XML.len()));
        assert_eq!(input_sized_hints(&sink), vec![XML.len()]);
        assert!(!sink.bytes.is_empty());
    }

    #[test]
    fn compact_inverted_set_reserves_input_length() {
        let doc = uppsala::parse(XML).expect("fixture must parse");
        let all = NodeSet::all_without_comments(&doc);
        assert_eq!(all.set_type(), NodeSetType::Invert);
        let sink = canonicalize_recording(Some(&all));
        assert_eq!(sink.reserved.first(), Some(&XML.len()));
        assert_eq!(input_sized_hints(&sink), vec![XML.len()]);
    }

    #[test]
    fn sparse_normal_set_gets_no_capacity_hint() {
        let doc = uppsala::parse(XML).expect("fixture must parse");
        let root = doc.document_element().expect("document element");
        let a = doc
            .first_child(root)
            .expect("Root must have a first child element");
        let subtree = NodeSet::tree_without_comments(a, &doc);
        assert_eq!(subtree.set_type(), NodeSetType::Normal);
        let sink = canonicalize_recording(Some(&subtree));
        assert!(
            input_sized_hints(&sink).is_empty(),
            "a materialized subtree must not reserve input-sized capacity: {:?}",
            sink.reserved
        );
        assert_eq!(sink.bytes, b"<A xmlns=\"urn:x\"><B>text</B></A>");

        for set_type in [
            NodeSetType::Normal,
            NodeSetType::Tree,
            NodeSetType::TreeWithoutComments,
            NodeSetType::TreeInvert,
        ] {
            // Every materialized variant, TreeInvert included, stores visible
            // IDs directly and must not reserve input-sized capacity.
            let explicit = NodeSet::from_ids(NodeIdSet::default(), set_type);
            let sink = canonicalize_recording(Some(&explicit));
            assert!(
                sink.reserved.is_empty(),
                "{set_type:?} must not reserve: {:?}",
                sink.reserved
            );
            assert!(sink.bytes.is_empty());
        }
    }
}
