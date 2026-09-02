# ADR-0009: Generic Document Lifetimes in the dsig Document APIs

**Date:** 2026-07-10
**Status:** Accepted
**Context:** pyuppsala moved to zero-copy documents that borrow from their retained input, so its documents are no longer `Document<'static>`

## Problem

The document-native signing functions were declared over
`&mut Document<'static>`:

```rust
pub fn sign_document(ctx: &DsigContext, doc: &mut Document<'static>) -> Result<(), Error>
```

`'static` was an accident of history: the first caller (pyuppsala) happened to
own fully `'static` documents because it copied every string out of the parse
input via `into_static()`. When pyuppsala adopted the zero-copy model
(pyuppsala ADR 0003), its documents became `Document<'a>` borrowing from the
retained input string, and the `'static` bound stopped compiling for the very
caller the API was built for.

## Decision

Relax the document-native signatures to a generic lifetime:

- `sign_document(ctx, doc: &mut Document<'_>)`
- `sign_enveloped_document(ctx, doc: &mut Document<'_>, options)`
- internal helpers `replace_element_text(doc: &mut Document<'_>, ..)` and
  `populate_x509_data_document(doc: &mut Document<'_>, ..)`

The verify-side functions were already lifetime-generic. The implementations
only ever insert owned data (`Cow::Owned` strings, freshly imported subtrees),
and owned values coerce into any document lifetime, so no behavior changes.
A `Document<'static>` still coerces into `Document<'_>`, so existing callers
compile unchanged.

## Consequences

- bergshamra signs both owned documents and borrowed zero-copy documents; the
  pyuppsala capsule handoff works without a document copy.
- The relaxed bound is also the honest one: nothing in signing requires the
  document to own its strings, only to be mutable for the duration of the
  call.
- Future document-native APIs in this workspace should default to generic
  document lifetimes; requiring `'static` should need a justification.
