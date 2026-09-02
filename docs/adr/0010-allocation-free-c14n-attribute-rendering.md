# ADR-0010: Allocation-Free C14N Attribute and Namespace Rendering

**Date:** 2026-07-10
**Status:** Accepted
**Context:** C14N throughput (36 to 43 MiB/s) sat far below uppsala's parse throughput (about 190 MiB/s) and dominates signing time, since every reference digest and the SignedInfo digest canonicalize XML

## Problem

Profiling the c14n benchmarks showed that escaping was NOT the bottleneck: the
escape routines were already run-based over `memchr` and move about 5 GiB/s.
The real cost was per-element allocation in attribute handling. Rendering an
element's attributes went through an owned `Attr` representation that cloned
four `String`s per attribute (prefix, local name, value, plus the qualified
name assembly), then sorted and serialized those owned copies, for every
element, on every canonicalization. Attribute-heavy documents (SAML metadata
is attribute-heavy) paid this as the dominant cost.

## Decision

Render attributes and namespace declarations straight from the borrowed DOM
into the output sink, with no intermediate owned representation, wherever the
canonicalization semantics permit:

- `render.rs` gains `NsDecl::render_into` / `Attr::render_into` (escape
  directly into the sink) and a shared `render_sorted_attrs` that sorts a
  small index vector over the element's borrowed attributes and writes each
  qualified name and escaped value directly from the DOM.
- `exclusive.rs` always uses the borrowed path: exclusive C14N never
  synthesizes or suppresses attributes, so borrowed rendering is
  unconditionally correct.
- `inclusive.rs` uses the borrowed path for the whole-document case (no node
  set). The document-subset path keeps the owned `Attr` logic byte-for-byte:
  attribute exclusion, `xml:*` inheritance from excluded ancestors, and the
  C14N 1.1 base handling genuinely materialize attributes that are not on the
  element, and correctness there outranks allocation savings.

Output byte-identity is the hard gate: the c14n spec/golden test suite must
pass unchanged, and signed documents must keep verifying.

## Consequences

- Controlled back-to-back benchmark comparison (old versus new under identical
  load, p < 0.01): attr_heavy inclusive -83.8 percent (about 6x), attr_heavy
  exclusive -80.2 percent, saml exclusive -39.1 percent, saml inclusive -31.0
  percent, text_heavy neutral to slightly better.
- End-to-end effect on the dsig benchmarks from the c14n change alone: verify
  -24 to -39 percent, sign -7 to -22 percent.
- Two rendering paths now exist in inclusive C14N (borrowed whole-document,
  owned document-subset). The subset path is the semantics-bearing one and
  stays the reference; any future optimization of it must reproduce its
  attribute synthesis exactly.
