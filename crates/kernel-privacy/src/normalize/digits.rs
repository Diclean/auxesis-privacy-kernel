//! Unicode digit values and the OCR confusable fold behind the normalised view.

/// Zero code points of the Unicode decimal-digit blocks, so every `Nd`
/// character maps to its value. Each entry starts a block of ten consecutive
/// `Nd` digits with values 0 to 9; the list covers every such block up to
/// Unicode 17 (U+11DE0, Tolong Siki, is the one Unicode 17 block), so it does
/// not depend on the Unicode tables of the toolchain.
///
/// This is the one table of the workspace: the broker's phone folding uses it
/// through [`unicode_digit_value`] too.
pub(super) const DIGIT_ZEROS: &[u32] = &[
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
    0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80,
    0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0,
    0xFF10, 0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450,
    0x114D0, 0x11650, 0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0, 0x11950, 0x11BF0, 0x11C50,
    0x11D50, 0x11DA0, 0x11DE0, 0x11F50, 0x16130, 0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0,
    0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E5F1, 0x1E950,
    0x1FBF0,
];

/// The numeric value of any Unicode decimal digit, ASCII included.
pub fn unicode_digit_value(ch: char) -> Option<u32> {
    let code = ch as u32;
    DIGIT_ZEROS
        .iter()
        .find(|zero| code >= **zero && code < **zero + 10)
        .map(|zero| code - *zero)
}

/// Whether a char can sit inside a digit-ish OCR run.
fn run_material(ch: char) -> bool {
    ch.is_ascii_digit() || is_confusable(ch) || is_number_separator(ch)
}

/// The separators a printed number may use between digit groups.
fn is_number_separator(ch: char) -> bool {
    matches!(ch, ' ' | '-' | '.' | '/' | '(' | ')')
}

/// The OCR confusables the fold rewrites.
fn is_confusable(ch: char) -> bool {
    matches!(ch, 'O' | 'o' | 'l' | 'I')
}

/// Fold `O`/`o` → `0` and `l`/`I` → `1`, but only a single confusable that sits
/// between two digit groups or touches a digit directly.
///
/// A whole letter word is never rewritten: `Ilo` after a number, `om` and
/// `IBAN-ra` stay intact because no confusable in them has a digit on both
/// sides (across separators) or immediately beside it. The leading confusable
/// of `O6 l2` is folded because it touches the `6` directly.
pub(super) fn fold_ocr_confusables(chars: &mut [char]) {
    let count = chars.len();
    let mut index = 0;
    while index < count {
        if is_confusable(chars[index]) {
            let touches_digit = index
                .checked_sub(1)
                .and_then(|left| chars.get(left))
                .is_some_and(|ch| ch.is_ascii_digit())
                || chars.get(index + 1).is_some_and(|ch| ch.is_ascii_digit());
            let between_digits =
                digit_across(chars, index, false) && digit_across(chars, index, true);
            if touches_digit || between_digits {
                chars[index] = match chars[index] {
                    'O' | 'o' => '0',
                    'l' | 'I' => '1',
                    other => other,
                };
            }
        }
        index += 1;
    }
}

/// Whether a digit lies across from `index` once separators and other
/// confusables are skipped; any other character stops the scan, so the fold
/// cannot reach into a following word.
fn digit_across(chars: &[char], index: usize, forward: bool) -> bool {
    let count = chars.len();
    let mut cursor = index;
    loop {
        if forward {
            cursor += 1;
            if cursor >= count {
                return false;
            }
        } else {
            if cursor == 0 {
                return false;
            }
            cursor -= 1;
        }
        let ch = chars[cursor];
        if ch.is_ascii_digit() {
            return true;
        }
        if !run_material(ch) {
            return false;
        }
    }
}

/// Whether [`fold_ocr_confusables`] would rewrite a confusable in `bytes`.
pub(super) fn ocr_would_fold(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .enumerate()
        .any(|(at, &byte)| matches!(byte, b'O' | b'o' | b'l' | b'I') && ocr_folds_at(bytes, at))
}

/// [`fold_ocr_confusables`] for one confusable at `at`.
pub(super) fn ocr_folds_at(bytes: &[u8], at: usize) -> bool {
    let touches_digit = at
        .checked_sub(1)
        .is_some_and(|left| bytes[left].is_ascii_digit())
        || bytes.get(at + 1).is_some_and(u8::is_ascii_digit);
    touches_digit || (digit_across_bytes(bytes, at, false) && digit_across_bytes(bytes, at, true))
}

fn digit_across_bytes(bytes: &[u8], at: usize, forward: bool) -> bool {
    let mut cursor = at;
    loop {
        if forward {
            cursor += 1;
            if cursor >= bytes.len() {
                return false;
            }
        } else {
            if cursor == 0 {
                return false;
            }
            cursor -= 1;
        }
        let byte = bytes[cursor];
        if byte.is_ascii_digit() {
            return true;
        }
        if !run_material_byte(byte) {
            return false;
        }
    }
}

/// [`run_material`] over bytes.
fn run_material_byte(byte: u8) -> bool {
    byte.is_ascii_digit()
        || matches!(byte, b'O' | b'o' | b'l' | b'I')
        || matches!(byte, b' ' | b'-' | b'.' | b'/' | b'(' | b')')
}
