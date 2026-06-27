#![forbid(unsafe_code)]

//! XML Digital Signature (XML-DSig) implementation.
//!
//! Provides signature verification and creation per the W3C XML-DSig spec.
//!
//! # Security Hardening
//!
//! XML Digital Signatures are a frequent target of attack. Bergshamra provides
//! several layered protections that you should understand and enable as
//! appropriate for your application.
//!
//! ## Duplicate ID Rejection (always on)
//!
//! XML Signature Wrapping (XSW) attacks often rely on injecting a second
//! element with the same `Id` attribute so that the signature verifies against
//! one element while the application processes another.
//!
//! Bergshamra **always** rejects documents that contain duplicate ID values
//! across any registered ID attribute (`Id`, `ID`, `id`, `AssertionID`,
//! `xml:id`, and any names added via [`DsigContext::add_id_attr`]). Both
//! [`verify::verify`] and [`sign::sign`] return
//! `Err(Error::XmlStructure("duplicate ID: …"))` if a duplicate is found.
//!
//! No opt-in is required — this protection is unconditional.
//!
//! ## Inspecting What Was Signed (`VerifyResult` metadata)
//!
//! A successful verification returns [`VerifyResult::Valid`] which carries:
//!
//! - **`signature_node`** — the [`NodeId`](uppsala::NodeId) of the
//!   `<Signature>` element that was verified.
//! - **`references`** — a `Vec<`[`VerifiedReference`]`>`, one per
//!   `<Reference>` in `<SignedInfo>`. Each entry contains the `uri` string and
//!   the `resolved_node` (an `Option<NodeId>`) that the URI resolved to, plus
//!   `digest_verified` to report whether Bergshamra locally computed and
//!   checked that reference digest.
//!
//! If `digest_verified` is `false`, the reference is currently a `cid:`
//! attachment reference: its URI, transforms, and declared digest are
//! integrity-protected by the signed `<SignedInfo>`, but the external
//! attachment bytes were not hashed by Bergshamra. Use
//! [`VerifyResult::all_reference_digests_verified`] or
//! [`VerifyResult::has_unverified_references`] when your application requires
//! complete local digest coverage.
//!
//! **You should always check that the signature covers the element you intend
//! to consume.** For example, a SAML Service Provider should verify that one
//! of the references points to the `<Assertion>` it will process:
//!
//! ```rust,ignore
//! use bergshamra_dsig::VerifyResult;
//!
//! let result = bergshamra_dsig::verify::verify(&ctx, &xml)?;
//! match result {
//!     VerifyResult::Valid { references, .. } => {
//!         let covers_assertion = references.iter().any(|r| {
//!             r.resolved_node.is_some_and(|n| {
//!                 doc.element(n).is_some_and(|e| {
//!                     &*e.name.local_name == "Assertion"
//!                 })
//!             })
//!         });
//!         assert!(covers_assertion, "signature must cover the Assertion");
//!     }
//!     VerifyResult::Invalid { reason } => panic!("invalid: {reason}"),
//! }
//! ```
//!
//! ## Strict Verification Mode (opt-in)
//!
//! Set [`DsigContext::strict_verification`] to `true` to enforce positional
//! constraints on reference targets. In strict mode every same-document
//! reference must resolve to a node that is:
//!
//! - the **document element** (root), or
//! - an **ancestor** of the `<Signature>` (the signed element wraps the
//!   signature — the common enveloped pattern), or
//! - a **sibling** of the `<Signature>` (both are children of the same parent).
//!
//! Any other position causes verification to fail with
//! `Err(Error::XmlStructure("strict mode: …"))`.
//!
//! This is the strongest defence against XSW attacks and is recommended for
//! SAML and WS-Security consumers where the document structure is well-known.
//!
//! ```rust,ignore
//! let ctx = DsigContext::new(keys_manager);  // secure defaults: strict + trusted_keys_only
//! let result = bergshamra_dsig::verify::verify(&ctx, &xml)?;
//! ```
//!
//! The CLI exposes this as `bergshamra verify --strict --trusted-keys-only`.
//!
//! ## Secure Defaults (`DsigContext::new`)
//!
//! [`DsigContext::new()`] enables secure defaults out of the box:
//! - **`trusted_keys_only = true`** — ignores inline keys in `<KeyInfo>`
//!   (`<KeyValue>`, `<X509Certificate>`, etc.) and only uses keys from the
//!   [`KeysManager`](bergshamra_keys::KeysManager). Without this, an attacker
//!   who controls the XML can embed their own key and forge a valid signature.
//! - **`strict_verification = true`** — rejects references to nodes that are not
//!   ancestors, siblings, or the document element (XSW protection).
//! - **`hmac_min_out_len = 160`** — enforces a minimum HMAC output length of
//!   160 bits to prevent truncation attacks (CVE-2009-0217).
//!
//! Use [`DsigContext::new_permissive()`] for W3C XML-DSig standard behavior
//! (e.g., self-contained signatures with inline keys).
//!
//! ## Recommended Configuration for SAML
//!
//! ```rust,ignore
//! // DsigContext::new() already has secure defaults — just add cert validation:
//! let mut ctx = DsigContext::new(keys_manager);
//! ctx.verify_keys = true;
//! ```

pub mod context;
pub mod sign;
pub mod verify;

pub use context::DsigContext;
pub use verify::{VerifiedKeyInfo, VerifiedReference, VerifyResult};

/// Convert a [`kryptering::Error`] into a [`bergshamra_core::Error`].
fn map_kryptering_err(e: kryptering::Error) -> bergshamra_core::Error {
    match e {
        kryptering::Error::Crypto(s) => bergshamra_core::Error::Crypto(s),
        kryptering::Error::UnsupportedAlgorithm(s) => {
            bergshamra_core::Error::UnsupportedAlgorithm(s)
        }
        kryptering::Error::Key(s) => bergshamra_core::Error::Key(s),
        kryptering::Error::Io(e) => bergshamra_core::Error::Io(e),
        // Handle additional error variants (e.g., Pkcs11) when the kryptering
        // crate is compiled with optional features.
        #[allow(unreachable_patterns)]
        other => bergshamra_core::Error::Crypto(other.to_string()),
    }
}
