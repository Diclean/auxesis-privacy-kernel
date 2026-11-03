//! The decoders behind a leaf's views: percent escapes, JSON `\uXXXX`, and whole-leaf
//! hex or base64.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;

use super::encoded::looks_encoded;
use super::{Unscreened, MAX_DECODED_PER_LEAF, MAX_DECODE_ROUNDS, MIN_ENCODED_LEN};

/// Push every decoded view of `text` and of those views, up to
/// [`MAX_DECODE_ROUNDS`] rounds deep, charging each view's bytes to `budget`.
///
/// Returns whether the end of a decoding chain still looks encoded: a view at the
/// depth cap that looks encoded or that a decoder would still change (fail
/// closed: the layer the cap leaves is never read), or one that nothing decodes
/// any further and that looks encoded.
pub(super) fn collect_views(
    text: &str,
    round: usize,
    budget: &mut usize,
    views: &mut Vec<String>,
) -> Result<bool, Unscreened> {
    if round == MAX_DECODE_ROUNDS {
        return Ok(looks_encoded(text) || !decode_once(text)?.is_empty());
    }
    let decoded = decode_once(text)?;
    if decoded.is_empty() {
        return Ok(looks_encoded(text));
    }
    let mut still_encoded = false;
    for view in decoded {
        *budget = budget.checked_sub(view.len()).ok_or(Unscreened)?;
        still_encoded |= collect_views(&view, round + 1, budget, views)?;
        views.push(view);
    }
    Ok(still_encoded)
}

/// The views `text` decodes to in one round: each decoder that changes it.
fn decode_once(text: &str) -> Result<Vec<String>, Unscreened> {
    let mut views = Vec::new();
    if text.contains('%') {
        views.push(percent_decode(text));
    }
    if text.contains("\\u") {
        views.push(json_unicode(text));
    }
    views.extend(whole_leaf_views(text)?);
    views.retain(|view| view != text);
    Ok(views)
}

/// The UTF-8 text `text` reads as when the whole leaf is hex or base64.
///
/// A leaf whose shape fits but whose decoded size is over
/// [`MAX_DECODED_PER_LEAF`] is `Err`: its bytes cannot be read in full. A
/// malformed encoding yields nothing.
fn whole_leaf_views(text: &str) -> Result<Vec<String>, Unscreened> {
    let mut views = Vec::new();
    if text.len() < MIN_ENCODED_LEN {
        return Ok(views);
    }
    let bytes = text.as_bytes();
    if bytes.len().is_multiple_of(2) && bytes.iter().all(u8::is_ascii_hexdigit) {
        if bytes.len() / 2 > MAX_DECODED_PER_LEAF {
            return Err(Unscreened);
        }
        if let Some(view) = hex_decode(bytes).and_then(utf8) {
            views.push(view);
        }
    }
    let body = text.trim_end_matches('=');
    if body.len() % 4 != 1 && body.bytes().all(is_base64_byte) {
        if body.len() * 3 / 4 > MAX_DECODED_PER_LEAF {
            return Err(Unscreened);
        }
        if let Some(view) = decode_base64(body).and_then(utf8) {
            views.push(view);
        }
    }
    Ok(views)
}

/// The bytes of an unpadded base64 run. The alphabet is picked by the characters
/// present; the other one fails to decode, so a mixed run is ignored rather than
/// guessed.
fn decode_base64(body: &str) -> Option<Vec<u8>> {
    if body.contains(['-', '_']) {
        URL_SAFE_NO_PAD.decode(body).ok()
    } else {
        STANDARD_NO_PAD.decode(body).ok()
    }
}

/// Whether an unpadded base64 run decodes to plain text.
pub(super) fn decodes_to_text(body: &str) -> bool {
    decode_base64(body).is_some_and(|bytes| is_text(&bytes))
}

/// Whether `bytes` read as plain text: valid UTF-8 with no control character other
/// than whitespace.
fn is_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|ch| !ch.is_control() || ch.is_whitespace())
    })
}

/// Whether a byte belongs to either base64 alphabet.
pub(super) fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

/// The bytes of an even-length hex string, or `None` on any other byte.
fn hex_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some((hex_value(pair[0])? << 4) | hex_value(pair[1])?))
        .collect()
}

/// The value of one hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

/// The text of `bytes` when they are valid UTF-8.
fn utf8(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes).ok()
}

/// `%XX` escapes decoded. A malformed escape is kept as written.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = bytes
            .get(index + 1..index + 3)
            .filter(|_| byte == b'%')
            .and_then(hex_pair);
        match escaped {
            Some(value) => {
                decoded.push(value);
                index += 3;
            }
            None => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// The byte of two hex digits.
pub(super) fn hex_pair(pair: &[u8]) -> Option<u8> {
    match pair {
        [high, low] => Some((hex_value(*high)? << 4) | hex_value(*low)?),
        _ => None,
    }
}

/// `\uXXXX` escapes decoded, a surrogate pair combined. A lone surrogate becomes
/// U+FFFD, and a malformed escape is kept as written.
fn json_unicode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("\\u") {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(unit) = unicode_escape(rest) else {
            out.push_str("\\u");
            rest = &rest[2..];
            continue;
        };
        rest = &rest[6..];
        let code = match unit {
            0xD800..=0xDBFF => match unicode_escape(rest) {
                Some(low @ 0xDC00..=0xDFFF) => {
                    rest = &rest[6..];
                    0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                }
                _ => 0xFFFD,
            },
            0xDC00..=0xDFFF => 0xFFFD,
            other => other,
        };
        out.push(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    out.push_str(rest);
    out
}

/// The code unit of a `\uXXXX` escape at the start of `text`.
fn unicode_escape(text: &str) -> Option<u32> {
    let digits = text.strip_prefix("\\u")?.as_bytes().get(..4)?;
    digits.iter().try_fold(0u32, |code, &byte| {
        Some((code << 4) | u32::from(hex_value(byte)?))
    })
}
