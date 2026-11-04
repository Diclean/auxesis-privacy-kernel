//! Escape parsing: percent runs, backslash escapes and UTF-8 widths.

use kernel_core::text::hex_value;

use super::html_entities::decode_entity;

pub(super) type EscapeParser<'a> = dyn Fn(&str, usize) -> Option<(char, usize)> + 'a;

/// The additional escapes read by both the privacy and known-secret views.
pub(super) fn common_escape(source: &str, at: usize) -> Option<(char, usize)> {
    let bytes = source.as_bytes();
    match (*bytes.get(at)?, *bytes.get(at + 1)?) {
        (b'\\', b'/') => Some(('/', at + 2)),
        (b'\\', b'0'..=b'7') => {
            let mut end = at + 1;
            let mut value = 0u32;
            while end < (at + 4).min(bytes.len()) && (b'0'..=b'7').contains(&bytes[end]) {
                value = value * 8 + u32::from(bytes[end] - b'0');
                end += 1;
            }
            (value <= 0o377).then_some((char::from_u32(value)?, end))
        }
        (b'%', b'u' | b'U') => {
            let unit = |start: usize| -> Option<u32> {
                bytes
                    .get(start..start + 4)?
                    .iter()
                    .try_fold(0, |n, b| Some(n * 16 + u32::from(hex_value(*b)?)))
            };
            let mut value = unit(at + 2)?;
            let mut end = at + 6;
            if (0xD800..=0xDBFF).contains(&value) {
                if !matches!(bytes.get(end..end + 2), Some([b'%', b'u' | b'U'])) {
                    return None;
                }
                let low = unit(end + 2).filter(|n| (0xDC00..=0xDFFF).contains(n))?;
                value = 0x10000 + ((value - 0xD800) << 10) + low - 0xDC00;
                end += 6;
            }
            Some((char::from_u32(value)?, end))
        }
        _ => None,
    }
}

/// Whether the known-secret view can decode an escape starting at `at`.
pub fn known_escape_at(source: &str, at: usize, escape: &EscapeParser<'_>) -> bool {
    let Some(rest) = source.get(at..) else {
        return false;
    };
    if common_escape(rest, 0).is_some() || (rest.starts_with('\\') && escape(rest, 0).is_some()) {
        return true;
    }
    if rest.starts_with('&') {
        return decode_entity(rest, 0).is_some();
    }
    if rest.starts_with('%') {
        let probe = rest.get(..12).unwrap_or(rest);
        let end = percent_run_end(probe, 0);
        return decode_percent_run(&probe[..end]).1;
    }
    false
}

/// The byte range of the percent-escape run that starts at `index` (a `%`).
///
/// A run is the maximal sequence of `%` units, each followed by zero, one or two
/// hex digits, so a truncated escape such as `%8` stays inside the run it
/// follows instead of splitting it.
pub(super) fn percent_run_end(source: &str, index: usize) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = index;
    while cursor < bytes.len() && bytes[cursor] == b'%' {
        cursor += 1;
        let mut taken = 0;
        while taken < 2 && cursor < bytes.len() && hex_value(bytes[cursor]).is_some() {
            cursor += 1;
            taken += 1;
        }
    }
    cursor
}

/// Decode the percent-escape run `run` (which starts with `%`).
///
/// Every escape that yields a printable ASCII byte or a valid multi-byte UTF-8
/// sequence decodes; anything else — a truncated `%8`, a `%ZZ`, a lone
/// continuation byte — is kept exactly as written. Returns the decoded text and
/// whether at least one escape decoded.
///
/// This is the privacy detector's decoder. It refuses bytes that would not form
/// valid, printable text so a decoded view can still be scanned with exact
/// source offsets. The broker and MCP decoders are separate on purpose: they
/// keep every raw byte because they compare against secret bytes, where a broken
/// sequence can still be part of the secret.
pub(super) fn decode_percent_run(run: &str) -> (String, bool) {
    let bytes = run.as_bytes();
    let mut out = String::with_capacity(run.len());
    let mut changed = false;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            let ch = run[index..]
                .chars()
                .next()
                .expect("index is on a char boundary");
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        let first = bytes
            .get(index + 1)
            .copied()
            .and_then(hex_value)
            .zip(bytes.get(index + 2).copied().and_then(hex_value));
        let Some((high, low)) = first else {
            // `%` with no hex digit after it: literal.
            out.push('%');
            index += 1;
            continue;
        };
        let byte = high * 16 + low;
        if byte < 0x80 {
            if (0x20..=0x7E).contains(&byte) {
                out.push(byte as char);
                changed = true;
            } else {
                out.push_str(&run[index..index + 3]);
            }
            index += 3;
            continue;
        }
        let Some(width) = utf8_width(byte) else {
            out.push_str(&run[index..index + 3]);
            index += 3;
            continue;
        };
        // Collect the continuation escapes of a multi-byte sequence.
        let mut sequence = vec![byte];
        let mut cursor = index + 3;
        let mut complete = true;
        while sequence.len() < width {
            let Some(continuation) =
                bytes
                    .get(cursor)
                    .filter(|byte| **byte == b'%')
                    .and_then(|_| {
                        bytes
                            .get(cursor + 1)
                            .copied()
                            .and_then(hex_value)
                            .zip(bytes.get(cursor + 2).copied().and_then(hex_value))
                    })
            else {
                complete = false;
                break;
            };
            let value = continuation.0 * 16 + continuation.1;
            if !(0x80..=0xBF).contains(&value) {
                complete = false;
                break;
            }
            sequence.push(value);
            cursor += 3;
        }
        match (complete, std::str::from_utf8(&sequence)) {
            (true, Ok(decoded)) => {
                out.push_str(decoded);
                changed = true;
                index = cursor;
            }
            _ => {
                out.push_str(&run[index..index + 3]);
                index += 3;
            }
        }
    }
    (out, changed)
}

/// The UTF-8 sequence width a leading byte announces, when it is a valid one.
fn utf8_width(byte: u8) -> Option<usize> {
    match byte {
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}
