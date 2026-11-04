//! Hex-spelling decoding: contiguous and separated pairs, `\x`/`%`/`0x` unit
//! escapes, and `xxd`/`od`/`hexdump` dumps matched through the same automaton.

use aho_corasick::AhoCorasick;

use super::MIN_KNOWN_SECRET_LEN;

/// Decoded bytes of a hex spelling in progress, with the source span of every
/// byte so a match on the decoded buffer maps back onto the text.
#[derive(Default)]
struct HexDecode {
    bytes: Vec<u8>,
    starts: Vec<u32>,
    ends: Vec<u32>,
}

impl HexDecode {
    fn push(&mut self, byte: u8, start: usize, end: usize) {
        self.bytes.push(byte);
        self.starts.push(start as u32);
        self.ends.push(end as u32);
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Match the decoded bytes through the same automaton and record the
    /// original spans; then start a new run. Flushing at `limit` decoded
    /// bytes can never split a match (a match is shorter than the limit).
    fn flush(&mut self, matcher: &AhoCorasick, ranges: &mut Vec<(usize, usize)>) {
        if self.bytes.len() >= MIN_KNOWN_SECRET_LEN {
            for hit in matcher.find_overlapping_iter(self.bytes.as_slice()) {
                ranges.push((
                    self.starts[hit.start()] as usize,
                    self.ends[hit.end() - 1] as usize,
                ));
            }
        }
        self.bytes.clear();
        self.starts.clear();
        self.ends.clear();
    }
}

/// Cheap pre-check so ordinary text (no two adjacent hex digits) skips the
/// two decode passes entirely.
pub(super) fn text_may_hold_hex(bytes: &[u8]) -> bool {
    bytes
        .windows(2)
        .any(|pair| hex_digit(pair[0]).is_some() && hex_digit(pair[1]).is_some())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Every span of `text` that is a hex spelling of a registered needle: the
/// contiguous spelling, pairs separated by arbitrary whitespace or
/// `:`, `\xNN`/`\XNN`/`0xNN`/`%NN` escapes, and `xxd`/`od`/`hexdump -C`
/// output (offset column and ASCII column included). The text is decoded in
/// one pass per shape and the decoded bytes are matched through the same
/// automaton, so the cost stays linear in the text and the needle set is
/// never compiled into a backtracking pattern.
pub(super) fn hex_spelling_ranges(
    bytes: &[u8],
    matcher: &AhoCorasick,
    limit: usize,
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    flex_hex_ranges(bytes, matcher, limit, &mut ranges);
    dump_hex_ranges(bytes, matcher, limit, &mut ranges);
    ranges
}

/// Pairs that are separated rather than contiguous: `73 62:36\n6b`,
/// `73-62-36`, `73.62.36`, `73_62_36`, `\x73\x62`, `%73%62`, `0x73 0x62`.
fn flex_hex_ranges(
    bytes: &[u8],
    matcher: &AhoCorasick,
    limit: usize,
    ranges: &mut Vec<(usize, usize)>,
) {
    let mut run = HexDecode::default();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some((code, start, next)) = hex_unit_at(bytes, i) {
            // One unit can encode up to four UTF-8 bytes (a surrogate pair or
            // a non-BMP `\U`/`\u{…}` escape); every byte maps back to the
            // unit's span.
            let mut encoded = [0u8; 4];
            if let Some(c) = char::from_u32(code) {
                for &byte in c.encode_utf8(&mut encoded).as_bytes() {
                    run.push(byte, start, next);
                }
            }
            if run.len() >= limit {
                run.flush(matcher, ranges);
            }
            i = next;
            continue;
        }
        if is_hex_separator(bytes[i]) {
            i += 1;
            continue;
        }
        run.flush(matcher, ranges);
        i += 1;
    }
    run.flush(matcher, ranges);
}

/// One encoded unit at `p` decoded to a Unicode code point: `73`, `\x73`,
/// `\X73`, `0x73`, `%73`, or the unicode escapes `\u0073`, `\U00000073`,
/// `\u{73}`, `\u{0073}` — including surrogate pairs (`\uD83D\uDE00`) for
/// non-BMP characters.
pub(super) fn hex_unit_at(bytes: &[u8], p: usize) -> Option<(u32, usize, usize)> {
    if bytes.get(p) == Some(&b'\\') && matches!(bytes.get(p + 1), Some(b'u' | b'U')) {
        return unicode_unit_at(bytes, p);
    }
    let mut q = p;
    match bytes.get(p) {
        Some(b'\\') if matches!(bytes.get(p + 1), Some(b'x' | b'X')) => q = p + 2,
        Some(b'%') => q = p + 1,
        Some(b'0') if matches!(bytes.get(p + 1), Some(b'x' | b'X')) => q = p + 2,
        _ => {}
    }
    let hi = hex_digit(*bytes.get(q)?)?;
    let lo = hex_digit(*bytes.get(q + 1)?)?;
    Some((u32::from((hi << 4) | lo), p, q + 2))
}

/// `\u0073` / `\U00000073` (fixed width) and `\u{73}` / `\u{0073}` (braced),
/// with `\uD83D\uDE00` surrogate pairs composed into one code point.
pub(super) fn unicode_unit_at(bytes: &[u8], p: usize) -> Option<(u32, usize, usize)> {
    let fixed = bytes.get(p + 1) == Some(&b'U');
    let width = if fixed { 8 } else { 4 };
    let mut q = p + 2;
    let mut braced = false;
    let mut value = 0u32;
    if bytes.get(q) == Some(&b'{') {
        braced = true;
        q += 1;
        let mut digits = 0usize;
        while let Some(digit) = hex_digit(*bytes.get(q)?) {
            value = value.checked_mul(16)?.checked_add(u32::from(digit))?;
            digits += 1;
            q += 1;
            if digits > 6 {
                return None;
            }
        }
        if digits == 0 || bytes.get(q) != Some(&b'}') {
            return None;
        }
        q += 1;
    } else {
        for _ in 0..width {
            let digit = hex_digit(*bytes.get(q)?)?;
            value = value.checked_mul(16)?.checked_add(u32::from(digit))?;
            q += 1;
        }
    }
    // A `\uXXXX` high surrogate must be followed by its `\uXXXX` low
    // surrogate: the pair decodes to one non-BMP code point.
    if !fixed && !braced && (0xD800..=0xDBFF).contains(&value) {
        let mut low_q = q;
        if bytes.get(low_q) == Some(&b'\\') && bytes.get(low_q + 1) == Some(&b'u') {
            low_q += 2;
            let mut low = 0u32;
            for _ in 0..4 {
                let digit = hex_digit(*bytes.get(low_q)?)?;
                low = low.checked_mul(16)?.checked_add(u32::from(digit))?;
                low_q += 1;
            }
            if (0xDC00..=0xDFFF).contains(&low) {
                let code = 0x1_0000 + ((value - 0xD800) << 10) + (low - 0xDC00);
                return Some((code, p, low_q));
            }
        }
        return None;
    }
    if (0xD800..=0xDFFF).contains(&value) {
        return None;
    }
    char::from_u32(value)?;
    Some((value, p, q))
}

/// Separators the hex decoders accept between two encoded bytes: a dump may
/// join its pairs with `:`, `-`, `,`, `.`, `_` or `|`, or with whitespace.
fn is_hex_separator(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b':' | b'-' | b',' | b'.' | b'_' | b'|')
}

/// Line-oriented pass for dump output: `xxd`, `od` and `hexdump -C` print an
/// offset column and (except `od`) an ASCII column between the byte pairs.
/// The offset is dropped and the hex column is decoded up to the ASCII
/// column; anything else on the line ends it.
fn dump_hex_ranges(
    bytes: &[u8],
    matcher: &AhoCorasick,
    limit: usize,
    ranges: &mut Vec<(usize, usize)>,
) {
    let mut run = HexDecode::default();
    let mut start = 0usize;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset);
        if !dump_line_into(&mut run, matcher, ranges, limit, bytes, start, end) {
            run.flush(matcher, ranges);
        }
        start = end + 1;
    }
    run.flush(matcher, ranges);
}

/// Decode the hex column of one line. Returns `true` when the line looks like
/// dump output; `false` ends the current run.
fn dump_line_into(
    run: &mut HexDecode,
    matcher: &AhoCorasick,
    ranges: &mut Vec<(usize, usize)>,
    limit: usize,
    bytes: &[u8],
    start: usize,
    end: usize,
) -> bool {
    let mut line_end = end;
    while line_end > start && matches!(bytes[line_end - 1], b' ' | b'\t' | b'\r') {
        line_end -= 1;
    }
    if start >= line_end {
        return false;
    }
    // First token and the start of the second (if any), to recognise the
    // offset column of a tool that always prints one.
    let mut first_end = start;
    while first_end < line_end && !matches!(bytes[first_end], b' ' | b'\t') {
        first_end += 1;
    }
    let mut second_start = first_end;
    while second_start < line_end && matches!(bytes[second_start], b' ' | b'\t') {
        second_start += 1;
    }
    let mut cursor = if hex_digit(bytes[start]).is_some()
        && second_start < line_end
        && is_offset_token(&bytes[start..first_end])
    {
        second_start
    } else {
        start
    };
    let mut any = false;
    while cursor < line_end {
        if matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
            continue;
        }
        let token_start = cursor;
        while cursor < line_end && !matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
        }
        if bytes[token_start] == b'|' {
            // `hexdump -C`'s ASCII column.
            break;
        }
        // Colon-separated pairs inside one token (`73:62:36`).
        let mut seg_start = token_start;
        let mut broken = false;
        loop {
            let seg_end = bytes[seg_start..cursor]
                .iter()
                .position(|byte| *byte == b':')
                .map_or(cursor, |offset| seg_start + offset);
            if seg_end > seg_start {
                let segment = &bytes[seg_start..seg_end];
                if !segment.len().is_multiple_of(2)
                    || !segment.iter().all(|byte| hex_digit(*byte).is_some())
                {
                    broken = true;
                    break;
                }
                let mut k = 0usize;
                while k < segment.len() {
                    let hi = hex_digit(segment[k]).unwrap_or(0);
                    let lo = hex_digit(segment[k + 1]).unwrap_or(0);
                    run.push((hi << 4) | lo, seg_start + k, seg_start + k + 2);
                    any = true;
                    k += 2;
                    if run.len() >= limit {
                        run.flush(matcher, ranges);
                    }
                }
            }
            if seg_end >= cursor {
                break;
            }
            seg_start = seg_end + 1;
            if seg_start >= cursor {
                break;
            }
        }
        if broken {
            // The ASCII column (or an alien token) starts here; the rest of
            // the line belongs to it.
            break;
        }
    }
    any
}

/// An offset column token: all hex digits, optionally closed by `:`, at most
/// 16 digits (a 64-bit offset).
fn is_offset_token(token: &[u8]) -> bool {
    let token = if token.last() == Some(&b':') {
        &token[..token.len() - 1]
    } else {
        token
    };
    !token.is_empty() && token.len() <= 16 && token.iter().all(|byte| hex_digit(*byte).is_some())
}
