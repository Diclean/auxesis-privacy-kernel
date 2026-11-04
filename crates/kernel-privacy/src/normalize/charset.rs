//! Character-level normalisation: Unicode spaces, dashes, line breaks and the
//! invisible characters stripped before scanning.

use super::unicode_digit_value;

/// Map one original char, or `None` when it is stripped.
pub(super) fn normalize_char(ch: char) -> Option<char> {
    if is_zero_width(ch) {
        return None;
    }
    if let Some(digit) = unicode_digit_value(ch) {
        return Some((b'0' + digit as u8) as char);
    }
    if is_unicode_space(ch) {
        return Some(' ');
    }
    if is_dash(ch) {
        return Some('-');
    }
    if let Some(ascii) = fullwidth_ascii(ch) {
        return Some(ascii);
    }
    Some(ch)
}

/// Fold the fullwidth ASCII block U+FF01–U+FF5E to ASCII `!`–`~`.
///
/// This covers the fullwidth letters, the commercial `＠`, and the fullwidth
/// punctuation this layer folds to ASCII (`．` U+FF0E, `＋` U+FF0B, `－` U+FF0D,
/// `／` U+FF0F, `：` U+FF1A, `（`/`）` U+FF08/U+FF09). Fullwidth digits are
/// already handled by [`unicode_digit_value`], which runs first.
fn fullwidth_ascii(ch: char) -> Option<char> {
    let code = ch as u32;
    if (0xFF01..=0xFF5E).contains(&code) {
        Some((b'!' as u32 + (code - 0xFF01)) as u8 as char)
    } else {
        None
    }
}

/// Fold the ideographic full stop `。` (U+3002) to `.` only when it sits
/// between two digits.
///
/// A CJK sentence often ends `…。`, and a bare number followed by that mark
/// must not gain a date separator; when the mark is genuinely a thousands
/// separator inside a number it is folded (P2).
pub(super) fn fold_ideographic_stop(chars: &mut [char]) {
    let count = chars.len();
    for index in 1..count.saturating_sub(1) {
        if chars[index] == '\u{3002}'
            && chars[index - 1].is_ascii_digit()
            && chars[index + 1].is_ascii_digit()
        {
            chars[index] = '.';
        }
    }
}

/// Zero-width and otherwise invisible characters, stripped before scanning.
/// The ranges live once, in [`kernel_core::text::is_invisible`]; the folder's
/// narrower subset is [`crate::contacts::fold::is_default_ignorable`].
pub(super) fn is_zero_width(ch: char) -> bool {
    crate::contacts::fold::is_default_ignorable(ch)
}

/// Unicode space separators folded to ASCII space.
pub(crate) fn is_unicode_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// Dashes folded to ASCII `-`.
pub(super) fn is_dash(ch: char) -> bool {
    matches!(ch, '\u{2010}'..='\u{2015}' | '\u{2212}')
}

/// Line breaks: the ASCII newlines, the vertical tab, form feed, NEL and the
/// Unicode line and paragraph separators.
pub(super) fn is_line_break(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\u{000B}' | '\u{000C}' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}'
    )
}

/// Line breaks and tabs. Inside an identifier they are separators, not content.
pub(super) fn is_line_break_or_tab(ch: char) -> bool {
    ch == '\t' || is_line_break(ch)
}

/// Whether `text` holds a line break: `\n`, `\r`, the vertical tab, the form
/// feed, NEL or a Unicode line or paragraph separator. Shared with the
/// National Insurance recogniser, whose suffix letter may not cross one
/// (NINO-NEWLINE-SUFFIX); a tab is no line break and still folds.
pub(crate) fn holds_line_break(text: &str) -> bool {
    text.chars().any(is_line_break)
}
