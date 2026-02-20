#![forbid(unsafe_code)]

//! Entity escaping for C14N output.
//!
//! Per the C14N spec:
//! - Text nodes: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `\r` → `&#xD;`
//! - Attribute values: additionally `"` → `&quot;`, `\t` → `&#x9;`, `\n` → `&#xA;`
//! - PI data: `\r` → `&#xD;`

/// Escape text node content per C14N rules.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escape attribute value per C14N rules.
pub fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escape processing instruction data.
pub fn escape_pi(s: &str) -> String {
    s.replace('\r', "&#xD;")
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
}
