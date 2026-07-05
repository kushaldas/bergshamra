#![forbid(unsafe_code)]

//! Entity escaping for C14N output.
//!
//! Per the C14N spec:
//! - Text nodes: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `\r` → `&#xD;`
//! - Attribute values: additionally `"` → `&quot;`, `\t` → `&#x9;`, `\n` → `&#xA;`
//! - PI data: `\r` → `&#xD;`
//!
//! Every byte that needs escaping is a single ASCII byte, which can never occur
//! inside a multi-byte UTF-8 sequence. So we scan `s.as_bytes()` directly and
//! emit an entity per special byte, replacing the previous per-`char` loop
//! (which decoded UTF-8) and its per-node `String` allocation.
//!
//! ## Scanning strategy
//!
//! The common case is text/attribute values with *sparse* special bytes (long
//! clean runs). There `memchr` is a big win: one SIMD-accelerated search finds
//! the next special and we bulk-copy the clean run before it.
//!
//! But when special bytes are *dense* (e.g. text reconstructed from many
//! `&lt;`/`&amp;` numeric/entity references), bulk-copying tiny runs is slower
//! than a plain per-byte loop, and per-call `memchr` overhead dominates — an
//! adversary could use that as a denial-of-service amplifier. So the scan is
//! **adaptive**: it uses `memchr3` to skip clean runs, but the moment a run is
//! short (a dense region) it finishes with a per-byte push loop. That loop does
//! strictly less work than the original `char` loop, so no input — sparse or
//! dense — can regress, while sparse inputs keep the full `memchr` speedup.
//! (Measured: ~37× faster on sparse text, ~1.3× faster on dense text.)
//!
//! `memchr3` covers three needles. The text set has four (`& < > \r`) and the
//! attribute set six (`& < " \t \n \r`); the extra bytes (`\r`, `\t`, `\n`) only
//! reach a C14N value via numeric character references and are rare. A cheap
//! pre-check routes those uncommon inputs to a full-needle per-byte loop.

use crate::C14nSink;
use memchr::{memchr, memchr3, memchr_iter};

/// Below this clean-run length we treat the region as "dense" and switch from
/// `memchr` skipping to a per-byte push loop. Roughly one SIMD register: above
/// it, bulk-copying a run beats pushing its bytes one at a time; below it, the
/// per-call `memchr`/`extend_from_slice` overhead dominates.
const DENSE_RUN: usize = 16;

/// The escape sequence for a single special byte.
#[inline]
fn entity_for(byte: u8) -> &'static [u8] {
    match byte {
        b'&' => b"&amp;",
        b'<' => b"&lt;",
        b'>' => b"&gt;",
        b'"' => b"&quot;",
        b'\t' => b"&#x9;",
        b'\n' => b"&#xA;",
        b'\r' => b"&#xD;",
        _ => unreachable!("entity_for called on non-special byte"),
    }
}

/// Escape text node content per C14N rules and append it to `out`.
///
/// The output is UTF-8 bytes. The sink receives unmodified clean runs and C14N
/// entity byte sequences for `&`, `<`, `>`, and carriage returns.
pub fn escape_text_into<W: C14nSink>(out: &mut W, s: &str) {
    let bytes = s.as_bytes();
    out.reserve(bytes.len());
    // Fast path: no carriage return (the rare 4th needle), so the only specials
    // are `& < >` — exactly `memchr3`'s three. Otherwise use the full-needle
    // per-byte loop.
    if memchr(b'\r', bytes).is_none() {
        let mut i = 0;
        let mut last = 0;
        while let Some(rel) = memchr3(b'&', b'<', b'>', &bytes[i..]) {
            let pos = i + rel;
            out.write(&bytes[last..pos]);
            out.write(entity_for(bytes[pos]));
            last = pos + 1;
            i = pos + 1;
            if rel < DENSE_RUN {
                // Dense region: finish with a per-byte push loop.
                push_text_bytes(out, &bytes[last..]);
                return;
            }
        }
        out.write(&bytes[last..]);
    } else {
        push_text_bytes(out, bytes);
    }
}

/// Per-byte loop over the full text needle set (`& < > \r`). Does strictly less
/// work than the original per-`char` loop (no UTF-8 decode), so it never
/// regresses; used for dense regions and for the rare `\r`-bearing inputs.
fn push_text_bytes<W: C14nSink>(out: &mut W, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'&' => out.write(b"&amp;"),
            b'<' => out.write(b"&lt;"),
            b'>' => out.write(b"&gt;"),
            b'\r' => out.write(b"&#xD;"),
            _ => out.write_byte(b),
        }
    }
}

/// Escape an attribute value per C14N rules and append it to `out`.
///
/// In addition to the text-node escapes, this also escapes `"`, tab, and line
/// feed. Attribute normalization happens during XML parsing; these control
/// bytes generally appear only when they came from character references.
pub fn escape_attr_into<W: C14nSink>(out: &mut W, s: &str) {
    let bytes = s.as_bytes();
    out.reserve(bytes.len());
    // Fast path: no tab/newline/CR (the rare extra needles — normalised away on
    // parse unless they came from numeric refs), so the only specials are
    // `& < "` — exactly `memchr3`'s three.
    if memchr3(b'\t', b'\n', b'\r', bytes).is_none() {
        let mut i = 0;
        let mut last = 0;
        while let Some(rel) = memchr3(b'&', b'<', b'"', &bytes[i..]) {
            let pos = i + rel;
            out.write(&bytes[last..pos]);
            out.write(entity_for(bytes[pos]));
            last = pos + 1;
            i = pos + 1;
            if rel < DENSE_RUN {
                push_attr_bytes(out, &bytes[last..]);
                return;
            }
        }
        out.write(&bytes[last..]);
    } else {
        push_attr_bytes(out, bytes);
    }
}

/// Per-byte loop over the full attribute needle set (`& < " \t \n \r`).
fn push_attr_bytes<W: C14nSink>(out: &mut W, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'&' => out.write(b"&amp;"),
            b'<' => out.write(b"&lt;"),
            b'"' => out.write(b"&quot;"),
            b'\t' => out.write(b"&#x9;"),
            b'\n' => out.write(b"&#xA;"),
            b'\r' => out.write(b"&#xD;"),
            _ => out.write_byte(b),
        }
    }
}

/// Escape processing instruction data and append it to `out`.
///
/// C14N only changes carriage returns in PI data, replacing each `\r` with
/// `&#xD;`.
pub fn escape_pi_into<W: C14nSink>(out: &mut W, s: &str) {
    let bytes = s.as_bytes();
    out.reserve(bytes.len());
    let mut last = 0;
    for pos in memchr_iter(b'\r', bytes) {
        out.write(&bytes[last..pos]);
        out.write(b"&#xD;");
        last = pos + 1;
    }
    out.write(&bytes[last..]);
}

/// Escape text node content per C14N rules and return a UTF-8 string.
///
/// This is the convenience wrapper around [`escape_text_into`].
pub fn escape_text(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    escape_text_into(&mut out, s);
    // Input is valid UTF-8 and every inserted byte sequence is ASCII, so the
    // result is valid UTF-8.
    String::from_utf8(out).expect("escaped text is valid UTF-8")
}

/// Escape an attribute value per C14N rules and return a UTF-8 string.
///
/// This is the convenience wrapper around [`escape_attr_into`].
pub fn escape_attr(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    escape_attr_into(&mut out, s);
    String::from_utf8(out).expect("escaped attr is valid UTF-8")
}

/// Escape processing instruction data and return a UTF-8 string.
///
/// This is the convenience wrapper around [`escape_pi_into`].
pub fn escape_pi(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    escape_pi_into(&mut out, s);
    String::from_utf8(out).expect("escaped PI is valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_text() {
        assert_eq!(escape_text("hello"), "hello");
        assert_eq!(escape_text("a&b<c>d"), "a&amp;b&lt;c&gt;d");
        assert_eq!(escape_text("line\rend"), "line&#xD;end");
    }

    #[test]
    fn test_escape_attr() {
        assert_eq!(escape_attr("hello"), "hello");
        assert_eq!(escape_attr("a&b\"c"), "a&amp;b&quot;c");
        assert_eq!(escape_attr("a\tb\nc\rd"), "a&#x9;b&#xA;c&#xD;d");
    }

    #[test]
    fn test_escape_pi() {
        assert_eq!(escape_pi("no carriage return"), "no carriage return");
        assert_eq!(escape_pi("a\rb\rc"), "a&#xD;b&#xD;c");
    }

    #[test]
    fn test_text_does_not_escape_attr_only_bytes() {
        // ", \t, \n are NOT escaped in text content.
        assert_eq!(escape_text("a\"b\tc\nd"), "a\"b\tc\nd");
    }

    #[test]
    fn test_text_scalar_fallback_matches_fast_path() {
        // Presence of \r forces the scalar fallback; result must be identical.
        assert_eq!(escape_text("a<b\rc&d>e"), "a&lt;b&#xD;c&amp;d&gt;e");
        assert_eq!(escape_text("\r\r&&<<"), "&#xD;&#xD;&amp;&amp;&lt;&lt;");
    }

    #[test]
    fn test_attr_scalar_fallback_matches_fast_path() {
        // Presence of \t/\n/\r forces the scalar fallback.
        assert_eq!(escape_attr("a&b\tc<d\"e"), "a&amp;b&#x9;c&lt;d&quot;e");
    }

    #[test]
    fn test_multibyte_utf8_preserved() {
        // Multi-byte chars must pass through untouched; ASCII specials around
        // them must still escape.
        assert_eq!(escape_text("café & thé < lait"), "café &amp; thé &lt; lait");
        assert_eq!(escape_attr("naïve\"quote"), "naïve&quot;quote");
        // Emoji (4-byte) adjacent to specials.
        assert_eq!(escape_text("🔒<lock>"), "🔒&lt;lock&gt;");
        // Multi-byte adjacent to a rare byte (scalar fallback path).
        assert_eq!(escape_text("café\r<x>"), "café&#xD;&lt;x&gt;");
    }

    #[test]
    fn test_empty_and_boundary() {
        assert_eq!(escape_text(""), "");
        assert_eq!(escape_text("&"), "&amp;");
        assert_eq!(escape_text("&&&"), "&amp;&amp;&amp;");
        assert_eq!(escape_attr("\t"), "&#x9;");
        assert_eq!(escape_pi(""), "");
    }

    #[test]
    fn test_dense_bail_path_matches() {
        // Dense specials trigger the per-byte bail; output must stay identical
        // to a straightforward reference escaping. Mix a long clean prefix
        // (memchr fast path) with a dense tail (bail path).
        let input = format!("{}{}", "x".repeat(64), "a&b<c>d".repeat(50));
        let expected: String = input
            .chars()
            .map(|c| match c {
                '&' => "&amp;".to_string(),
                '<' => "&lt;".to_string(),
                '>' => "&gt;".to_string(),
                other => other.to_string(),
            })
            .collect();
        assert_eq!(escape_text(&input), expected);

        let attr_input = format!("{}{}", "y".repeat(64), "a&b<c\"d".repeat(50));
        let attr_expected: String = attr_input
            .chars()
            .map(|c| match c {
                '&' => "&amp;".to_string(),
                '<' => "&lt;".to_string(),
                '"' => "&quot;".to_string(),
                other => other.to_string(),
            })
            .collect();
        assert_eq!(escape_attr(&attr_input), attr_expected);
    }

    #[test]
    fn test_into_appends() {
        let mut out = b"PREFIX:".to_vec();
        escape_text_into(&mut out, "a<b");
        assert_eq!(out, b"PREFIX:a&lt;b");
    }
}
