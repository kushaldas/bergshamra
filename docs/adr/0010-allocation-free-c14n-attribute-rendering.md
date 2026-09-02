# ADR-0010: Allocation-Free C14N Attribute and Namespace Rendering

**Date:** 2026-07-10
**Status:** Proposed
**Context:** Investigating per-element allocation in C14N attribute and
namespace rendering

## Problem

The current implementation renders an element's attributes through an owned
`Attr` representation. It clones the namespace URI, local name, qualified name,
and value, then sorts and serializes those owned copies for every element and
every canonicalization. Attribute-heavy documents therefore create avoidable
short-lived allocations.

## Proposed Decision

Render attributes and namespace declarations directly from the borrowed DOM
into the output sink, with no intermediate owned representation, wherever the
canonicalization semantics permit:

- `render.rs` would gain `NsDecl::render_into` / `Attr::render_into` (escape
  directly into the sink) and a shared `render_sorted_attrs` that sorts a
  small index vector over the element's borrowed attributes and writes each
  qualified name and escaped value directly from the DOM.
- `exclusive.rs` would use the borrowed path: exclusive C14N never
  synthesizes or suppresses attributes, so borrowed rendering is
  unconditionally correct.
- `inclusive.rs` would use the borrowed path for the whole-document case (no
  node set). The document-subset path keeps the owned `Attr` logic byte-for-byte:
  attribute exclusion, `xml:*` inheritance from excluded ancestors, and the
  C14N 1.1 base handling genuinely materialize attributes that are not on the
  element, and correctness there outranks allocation savings.

Output byte-identity would be the hard gate: the C14N specification and golden
test suite must pass unchanged, and signed documents must keep verifying.

## Expected Consequences

- The proposed borrowed path should reduce temporary allocations during
  whole-document canonicalization. Its throughput and memory effects must be
  measured after implementation; this ADR makes no performance claim for
  version 0.9.0.
- Inclusive C14N would have two rendering paths: borrowed whole-document and
  owned document-subset. The subset path would remain the semantics-bearing
  reference, and any future optimization must reproduce its attribute
  synthesis exactly.
