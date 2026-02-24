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
//!   the `resolved_node` (an `Option<NodeId>`) that the URI resolved to.
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
//! let mut ctx = DsigContext::new(keys_manager);
//! ctx.strict_verification = true;   // enable XSW protection
//! ctx.trusted_keys_only = true;     // only trust pre-configured keys
//! let result = bergshamra_dsig::verify::verify(&ctx, &xml)?;
//! ```
//!
//! The CLI exposes this as `bergshamra verify --strict`.
//! Combined with `--trusted-keys-only`, this provides robust XSW protection.
//!
//! ## Trusted Keys Only (opt-in)
//!
//! Set [`DsigContext::trusted_keys_only`] to `true` to ignore inline keys
//! embedded in `<KeyInfo>` (`<KeyValue>`, `<X509Certificate>`, etc.) and only
//! use keys pre-loaded into the [`KeysManager`](bergshamra_keys::KeysManager).
//! Without this, an attacker who controls the XML can embed their own key and
//! sign with it — the signature will verify, but against the wrong key.
//!
//! This is essential for SAML Service Providers and any deployment where the
//! signing key is known ahead of time.
//!
//! ## HMAC Output Truncation (CVE-2009-0217)
//!
//! Set [`DsigContext::hmac_min_out_len`] to enforce a minimum
//! `<HMACOutputLength>` in bits. A zero-length or very short HMAC is trivially
//! forgeable. The W3C recommendation is at least 80 bits; xmlsec1 defaults to
//! half the hash output length.
//!
//! ## Recommended Configuration for SAML
//!
//! ```rust,ignore
//! let mut ctx = DsigContext::new(keys_manager);
//! ctx.trusted_keys_only = true;     // reject inline keys
//! ctx.strict_verification = true;   // reject unexpected reference positions
//! // Optionally validate the IdP certificate chain:
//! ctx.verify_keys = true;
//! ```

pub mod context;
pub mod verify;
pub mod sign;

pub use context::DsigContext;
pub use verify::{VerifiedReference, VerifyResult};
