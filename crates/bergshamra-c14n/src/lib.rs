#![forbid(unsafe_code)]

//! XML Canonicalization (C14N) for the Bergshamra XML Security library.
//!
//! Implements all six W3C canonicalization variants:
//! - Canonical XML 1.0 (with and without comments)
//! - Canonical XML 1.1 (with and without comments)
//! - Exclusive Canonical XML 1.0 (with and without comments)

pub mod escape;
pub mod inclusive;
pub mod inclusive11;
pub mod exclusive;
pub mod render;

use bergshamra_core::{algorithm, Error};
use bergshamra_xml::NodeSet;

/// The canonicalization mode.
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
    /// Get the algorithm URI for this mode.
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

    /// Parse a C14N mode from an algorithm URI.
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

    pub fn with_comments(&self) -> bool {
        matches!(
            self,
            Self::InclusiveWithComments
                | Self::Inclusive11WithComments
                | Self::ExclusiveWithComments
        )
    }

    pub fn is_exclusive(&self) -> bool {
        matches!(self, Self::Exclusive | Self::ExclusiveWithComments)
    }
}

/// Canonicalize an XML document.
///
/// - `xml`: the raw XML text
/// - `mode`: which C14N variant to use
/// - `node_set`: optional node set (for document-subset canonicalization)
/// - `inclusive_prefixes`: for exclusive C14N, the InclusiveNamespaces PrefixList
pub fn canonicalize(
    xml: &str,
    mode: C14nMode,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>, Error> {
    let doc = roxmltree::Document::parse_with_options(xml, roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() }).map_err(|e| Error::XmlParse(e.to_string()))?;

    match mode {
        C14nMode::Inclusive | C14nMode::InclusiveWithComments => {
            inclusive::canonicalize(&doc, mode.with_comments(), node_set)
        }
        C14nMode::Inclusive11 | C14nMode::Inclusive11WithComments => {
            inclusive11::canonicalize(&doc, mode.with_comments(), node_set)
        }
        C14nMode::Exclusive | C14nMode::ExclusiveWithComments => {
            exclusive::canonicalize(&doc, mode.with_comments(), node_set, inclusive_prefixes)
        }
    }
}

/// Convenience: canonicalize with a pre-parsed document.
pub fn canonicalize_doc(
    doc: &roxmltree::Document<'_>,
    mode: C14nMode,
    node_set: Option<&NodeSet>,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>, Error> {
    match mode {
        C14nMode::Inclusive | C14nMode::InclusiveWithComments => {
            inclusive::canonicalize(doc, mode.with_comments(), node_set)
        }
        C14nMode::Inclusive11 | C14nMode::Inclusive11WithComments => {
            inclusive11::canonicalize(doc, mode.with_comments(), node_set)
        }
        C14nMode::Exclusive | C14nMode::ExclusiveWithComments => {
            exclusive::canonicalize(doc, mode.with_comments(), node_set, inclusive_prefixes)
        }
    }
}
