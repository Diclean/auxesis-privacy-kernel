//! Unicode folding for split-value matching: invisible-character condensing
//! and NFKC / escape folding, each with byte maps back to the original span.

use unicode_normalization::char::{canonical_combining_class, compose, decompose_compatible};

use super::hex::unicode_unit_at;

/// Whitespace, control and invisible characters that may be inserted between
/// a value's bytes. Mirrors `kernel_core::text::sanitize_text`'s dropped set
/// (private there) plus all whitespace.
pub(super) fn is_scrub_noise(c: char) -> bool {
    if c.is_whitespace() || c.is_control() {
        return true;
    }
    is_noncharacter(c)
        || matches!(
            c,
            '\u{00A0}'
                | '\u{00AD}'
                | '\u{034F}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}'
                | '\u{1680}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{2000}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{2060}'..='\u{206F}'
                | '\u{2800}'
                | '\u{3000}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF0}'..='\u{FFF8}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

fn is_noncharacter(c: char) -> bool {
    let cp = c as u32;
    matches!(c, '\u{FDD0}'..='\u{FDEF}') || (cp >= 0xFFFE && (cp & 0xFFFE) == 0xFFFE)
}

/// Condense `text` for split-value matching: drop every
/// [`is_scrub_noise`] character, keeping per-condensed-byte maps back to the
/// original byte span of the character.
#[allow(clippy::type_complexity)]
pub(super) fn condense(text: &str) -> (String, Vec<u32>, Vec<u32>) {
    let mut condensed = String::with_capacity(text.len());
    let mut starts: Vec<u32> = Vec::with_capacity(text.len());
    let mut ends: Vec<u32> = Vec::with_capacity(text.len());
    for (offset, c) in text.char_indices() {
        if is_scrub_noise(c) {
            continue;
        }
        condensed.push(c);
        let start = offset as u32;
        let end = (offset + c.len_utf8()) as u32;
        for _ in 0..c.len_utf8() {
            starts.push(start);
            ends.push(end);
        }
    }
    (condensed, starts, ends)
}

/// Fold `text` to NFKC, keeping per-folded-byte maps back to the original
/// character span: compatibility decomposition per character,
/// canonical ordering of combining marks, then the standard canonical
/// recomposition (Hangul L/V/T included). Ligatures, fullwidth forms,
/// superscripts, decomposed combining sequences in any order and conjoining
/// Hangul Jamo all match the same registered value. A hit in the folded copy
/// masks the whole original span of the character(s) it came from.
#[allow(clippy::type_complexity)]
pub(super) fn fold_nfkc(text: &str) -> (String, Vec<u32>, Vec<u32>) {
    // 1. Compatibility decomposition per character, with its original span.
    let mut parts: Vec<(char, u32, u32)> = Vec::with_capacity(text.len());
    for (offset, c) in text.char_indices() {
        let start = offset as u32;
        let end = (offset + c.len_utf8()) as u32;
        decompose_compatible(c, |part| parts.push((part, start, end)));
    }
    // 2. Canonical ordering: each run of non-starters is stably sorted by
    // canonical combining class (the same rule the `Decompositions` iterator
    // applies).
    canonical_order(&mut parts);
    // 3. Canonical recomposition (the standard last-starter algorithm, which
    // `compose` extends with Hangul L+V+T).
    let mut out: Vec<(char, u32, u32)> = Vec::with_capacity(parts.len());
    let mut composee: Option<(char, u32, u32)> = None;
    let mut last_ccc: Option<u8> = None;
    let mut buffer: Vec<(char, u32, u32)> = Vec::new();
    for (ch, start, end) in parts {
        let ch_class = canonical_combining_class(ch);
        let (k, k_start, k_end) = match composee {
            None => {
                if ch_class != 0 {
                    out.push((ch, start, end));
                    continue;
                }
                composee = Some((ch, start, end));
                continue;
            }
            Some(k) => k,
        };
        match last_ccc {
            None => match compose(k, ch) {
                Some(composed) => composee = Some((composed, k_start, end)),
                None => {
                    if ch_class == 0 {
                        out.push((k, k_start, k_end));
                        composee = Some((ch, start, end));
                    } else {
                        buffer.push((ch, start, end));
                        last_ccc = Some(ch_class);
                    }
                }
            },
            Some(blocked_class) => {
                if blocked_class >= ch_class {
                    if ch_class == 0 {
                        out.push((k, k_start, k_end));
                        out.append(&mut buffer);
                        composee = Some((ch, start, end));
                        last_ccc = None;
                    } else {
                        buffer.push((ch, start, end));
                        last_ccc = Some(ch_class);
                    }
                } else {
                    match compose(k, ch) {
                        Some(composed) => composee = Some((composed, k_start, end)),
                        None => {
                            buffer.push((ch, start, end));
                            last_ccc = Some(ch_class);
                        }
                    }
                }
            }
        }
    }
    if let Some((k, start, end)) = composee {
        out.push((k, start, end));
    }
    out.append(&mut buffer);
    // 4. Build the folded string and the per-byte maps.
    let mut folded = String::with_capacity(text.len());
    let mut starts: Vec<u32> = Vec::with_capacity(text.len());
    let mut ends: Vec<u32> = Vec::with_capacity(text.len());
    for (c, start, end) in out {
        folded.push(c);
        for _ in 0..c.len_utf8() {
            starts.push(start);
            ends.push(end);
        }
    }
    (folded, starts, ends)
}

/// Canonical ordering: stably sort every maximal run of non-starters by
/// canonical combining class. The runs are delimited by starters (ccc 0) and
/// the tail.
fn canonical_order(parts: &mut [(char, u32, u32)]) {
    let mut ready = 0usize;
    for index in 0..parts.len() {
        if canonical_combining_class(parts[index].0) == 0 {
            parts[ready..index].sort_by_key(|(c, _, _)| canonical_combining_class(*c));
            ready = index + 1;
        }
    }
    parts[ready..].sort_by_key(|(c, _, _)| canonical_combining_class(*c));
}

/// Fold `\uXXXX`, `\UXXXXXXXX` and `\u{…}` escapes (surrogate pairs
/// included) to their characters, keeping per-folded-byte maps back to the
/// original escape span. This catches mixed spellings — a raw value
/// with one escaped character — that no contiguous needle covers.
#[allow(clippy::type_complexity)]
pub(super) fn fold_unicode_escapes(text: &str) -> (String, Vec<u32>, Vec<u32>) {
    let bytes = text.as_bytes();
    let mut folded = String::with_capacity(text.len());
    let mut starts: Vec<u32> = Vec::with_capacity(text.len());
    let mut ends: Vec<u32> = Vec::with_capacity(text.len());
    let mut i = 0usize;
    while i < text.len() {
        if bytes.get(i) == Some(&b'\\') && matches!(bytes.get(i + 1), Some(b'u' | b'U')) {
            if let Some((code, start, next)) = unicode_unit_at(bytes, i) {
                if let Some(c) = char::from_u32(code) {
                    folded.push(c);
                    let start = start as u32;
                    let end = next as u32;
                    for _ in 0..c.len_utf8() {
                        starts.push(start);
                        ends.push(end);
                    }
                    i = next;
                    continue;
                }
            }
        }
        let c = text[i..].chars().next().unwrap_or('\u{FFFD}');
        folded.push(c);
        let start = i as u32;
        let end = (i + c.len_utf8()) as u32;
        for _ in 0..c.len_utf8() {
            starts.push(start);
            ends.push(end);
        }
        i += c.len_utf8();
    }
    (folded, starts, ends)
}
