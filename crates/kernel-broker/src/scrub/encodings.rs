//! The encoders behind the variant closure: hex, base32, percent-encoding,
//! HTML entities and JSON/JS unicode escapes, in both hex cases.

/// Hex pairs joined by `separator` (`73:62:36`), both hex cases.
pub(super) fn hex_separated(value: &str, separator: &str, upper: bool) -> String {
    let pairs: Vec<String> = value
        .bytes()
        .map(|byte| {
            if upper {
                format!("{byte:02X}")
            } else {
                format!("{byte:02x}")
            }
        })
        .collect();
    pairs.join(separator)
}

/// `0x73 0x62 …` (one prefix per byte, space-separated), both hex cases.
pub(super) fn hex_zero_x(value: &str, upper: bool) -> String {
    let pairs: Vec<String> = value
        .bytes()
        .map(|byte| {
            if upper {
                format!("0x{byte:02X}")
            } else {
                format!("0x{byte:02x}")
            }
        })
        .collect();
    pairs.join(" ")
}

/// `&#x43;&#x4e;…` (hex) or `&#67;&#78;…` (decimal) HTML entities, one per
/// character.
pub(super) fn html_entities(value: &str, hex: bool) -> String {
    let mut out = String::with_capacity(value.len() * 6);
    for c in value.chars() {
        if hex {
            out.push_str(&format!("&#x{:X};", c as u32));
        } else {
            out.push_str(&format!("&#{};", c as u32));
        }
    }
    out
}

/// `%73%62…`: every byte percent-escaped, uppercase hex (the R6 spelling the
/// decoded scan accepts).
pub(super) fn percent_encode_all(value: &str) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len() * 3);
    for &byte in value.as_bytes() {
        out.push('%');
        out.push(UPPER[(byte >> 4) as usize] as char);
        out.push(UPPER[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Percent-encode only the characters that break URL/query parsing (`%`,
/// `+`, `&`, `=`, `?`, `#`, `;`, space, quotes, angle brackets, backtick);
/// everything else is left as-is. This is the "minimal" complement of
/// [`percent_encode`], which escapes everything outside RFC 3986 unreserved.
pub(super) fn percent_encode_minimal(value: &str, upper: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        let must_escape = c.is_ascii()
            && matches!(
                c,
                '%' | '+' | '&' | '=' | '?' | '#' | ';' | ' ' | '"' | '\'' | '<' | '>' | '`'
            );
        if must_escape {
            let byte = c as u8;
            out.push('%');
            out.push(digits[(byte >> 4) as usize] as char);
            out.push(digits[(byte & 0x0F) as usize] as char);
        } else {
            out.push(c);
        }
    }
    out
}

/// Lower- or upper-case hex of `value`.
pub(super) fn hex_encode(value: &str, upper: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(value.len() * 2);
    for &byte in value.as_bytes() {
        out.push(digits[(byte >> 4) as usize] as char);
        out.push(digits[(byte & 0x0F) as usize] as char);
    }
    out
}

/// `\x73\x62…` (the prefix and the digits each in the requested case).
pub(super) fn escaped_hex(value: &str, prefix: &str, upper: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(value.len() * (prefix.len() + 2));
    for &byte in value.as_bytes() {
        out.push_str(prefix);
        out.push(digits[(byte >> 4) as usize] as char);
        out.push(digits[(byte & 0x0F) as usize] as char);
    }
    out
}

/// `\u0043\U00000043`-style escapes, one per **character**: `\u` uses four
/// hex digits for the BMP and a surrogate pair (`\uD83D\uDE00`) beyond it,
/// `\U` uses eight hex digits. Both hex cases (R7-4/R8).
pub(super) fn unicode_escaped(value: &str, prefix: &str, upper: bool) -> String {
    let mut out = String::with_capacity(value.len() * (prefix.len() + 8));
    for c in value.chars() {
        let code = c as u32;
        if prefix == "\\U" {
            push_hex_escape(&mut out, prefix, code, 8, upper);
        } else if code > 0xFFFF {
            let (high, low) = surrogate_pair(code);
            push_hex_escape(&mut out, prefix, high, 4, upper);
            push_hex_escape(&mut out, prefix, low, 4, upper);
        } else {
            push_hex_escape(&mut out, prefix, code, 4, upper);
        }
    }
    out
}

/// `\u{43}` / `\u{0043}` / `\u{1F600}`-style escapes, one per character,
/// zero-padded to at least `digits` hex digits, both hex cases.
pub(super) fn braced_unicode_escaped(value: &str, digits: usize, upper: bool) -> String {
    let mut out = String::with_capacity(value.len() * (digits + 5));
    for c in value.chars() {
        push_hex_escape(&mut out, "\\u{", c as u32, digits, upper);
        out.push('}');
    }
    out
}

/// Push `prefix` followed by `value` as zero-padded hex (`width` digits).
fn push_hex_escape(out: &mut String, prefix: &str, value: u32, width: usize, upper: bool) {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digits = if upper { UPPER } else { LOWER };
    out.push_str(prefix);
    for position in (0..width).rev() {
        out.push(digits[((value >> (4 * position)) & 0x0F) as usize] as char);
    }
}

/// The UTF-16 surrogate pair of a non-BMP code point.
pub(super) fn surrogate_pair(code: u32) -> (u32, u32) {
    let offset = code - 0x1_0000;
    (0xD800 + (offset >> 10), 0xDC00 + (offset & 0x3FF))
}

/// RFC 4648 base32; `pad` appends `=` to a multiple of eight symbols.
pub(super) fn base32_encode(bytes: &[u8], pad: bool, lower: bool) -> String {
    const UPPER: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let alphabet = if lower { LOWER } else { UPPER };
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5) + 6);
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for &byte in bytes {
        acc = ((acc << 8) | u64::from(byte)) & 0xFF_FFFF_FFFF;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet[((acc >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(alphabet[((acc << (5 - bits)) & 0x1F) as usize] as char);
    }
    if pad {
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
    }
    out
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
pub(super) fn percent_encode(value: &str, upper: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let hex = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(value.len() * 3);
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex[(byte >> 4) as usize] as char);
            out.push(hex[(byte & 0x0F) as usize] as char);
        }
    }
    out
}

/// `\u00ab` → `\u00AB` for a JSON-escaped body (both cases are legal).
pub(super) fn uppercase_unicode_escapes(escaped: &str) -> String {
    let bytes = escaped.as_bytes();
    let mut out = String::with_capacity(escaped.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 6 <= bytes.len()
            && bytes.get(i + 1) == Some(&b'u')
            && bytes[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit)
        {
            out.push_str(&escaped[i..i + 2]);
            out.push_str(&escaped[i + 2..i + 6].to_ascii_uppercase());
            i += 6;
        } else {
            let ch = escaped[i..].chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}
