//! Identity redaction for logs: WhatsApp JIDs, grouped phone numbers and
//! long digit runs, keeping dates and endpoints readable.

/// Mask the identity material the secret scrubber deliberately leaves alone:
/// WhatsApp JIDs and long digit runs.
///
/// Rules:
/// - a JID local part (`<digits>@s.whatsapp.net`, `@lid`, `@g.us`, with an
///   optional `:device` suffix) carrying at least seven digits is replaced by
///   `<jid>`; the server name stays (it carries no identity). This mirrors the
///   vetted rule in `the app's voice::error`; the log path cannot call it directly
///   (`the app's voice crate` sits above `kernel-broker`), so the same boundary logic lives
///   here without the voice-specific extras;
/// - every maximal run of eight or more ASCII digits is replaced by
///   `<number>` (E.164/national phone numbers and any stray long numeric
///   identifier), except the readable shapes: dates, clock times with their
///   fraction and zone, and IPv4 endpoints (`:port`, loopback, or right after
///   a context word such as `host:`). A bare dotted quad such as `41.23.45.67`
///   is masked, since it can be a phone number;
///
/// This is the layer the daemon log writer applies after [`redact_secrets`](super::redact_secrets)
/// (see [`redact_log_line`](super::redact_log_line)): the library crates (`whatsapp-rust`, `wacore*`)
/// log peer identities at `INFO`, and a number or JID must never reach
/// `~/.auxesis/logs/auxd.log`.
pub fn redact_identifiers(text: &str) -> String {
    redact_digit_runs(&redact_grouped_phone_numbers(&redact_jid_identifiers(text)))
}

/// JID servers whose `@`-suffixed local part is an identity. Kept in sync
/// with the voice scrubber (`the app's voice::error`).
const IDENTITY_JID_SERVERS: [&str; 3] = ["s.whatsapp.net", "lid", "g.us"];

/// Characters allowed in a JID local part (digits, group dash, device `:`).
fn is_jid_local_char(ch: char) -> bool {
    ch.is_ascii_digit() || matches!(ch, '-' | ':' | '.')
}

/// Can `ch` continue a JID server name? A `.` is handled by
/// [`jid_server_ends`]: it only continues the name when an identifier
/// character follows it.
fn is_jid_tail_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')
}

/// Does the JID server name end where `rest` starts? An identifier character
/// after the name (`1@s.whatsapp.netX`), or a `.` followed by one
/// (`1@lid.example`), makes it a longer name. A sentence full stop after the
/// server (`1@lid.`) ends the JID.
fn jid_server_ends(rest: &str) -> bool {
    let mut chars = rest.chars();
    match chars.next() {
        None => true,
        Some('.') => !chars.next().is_some_and(is_jid_tail_char),
        Some(ch) => !is_jid_tail_char(ch),
    }
}

/// Replace the local part of every WhatsApp JID with `<jid>`.
pub(super) fn redact_jid_identifiers(text: &str) -> String {
    if !text.contains('@') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('@') {
        let after = &rest[at + 1..];
        let is_jid = IDENTITY_JID_SERVERS
            .iter()
            .any(|server| after.starts_with(*server) && jid_server_ends(&after[server.len()..]));
        if !is_jid {
            out.push_str(&rest[..at + 1]);
            rest = after;
            continue;
        }
        let local_start = rest[..at]
            .char_indices()
            .rev()
            .find(|(_, ch)| !is_jid_local_char(*ch))
            .map(|(index, ch)| index + ch.len_utf8())
            .unwrap_or(0);
        let digits = rest[local_start..at]
            .chars()
            .filter(char::is_ascii_digit)
            .count();
        if digits >= 7 {
            out.push_str(&rest[..local_start]);
            out.push_str("<jid>");
        } else {
            out.push_str(&rest[..at + 1]);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Most separator characters the digit scanner bridges between two digits.
/// Four covers a grouping with a doubled separator (`06..12`).
const MAX_DIGIT_GAP: usize = 4;

/// Replace digit candidates with `<number>`, preserving only whole-candidate
/// dates/times and IPv4 addresses. The scan alphabet folds Unicode decimal
/// digits (the mathematical digit sets included) and decodes `\uXXXX` and
/// `\u{X...}` escapes to the character they name, for any code point. Offsets
/// point into the original text, so a masked span is always the raw span.
/// Ambiguous long numeric content such as durations or lists, UUID/hash digit
/// runs, and IPv6 parts may be masked: in logs, a false positive is cheaper
/// than a leaked identity.
///
/// A candidate is a run of digits joined by at most [`MAX_DIGIT_GAP`]
/// separators, where a separator is neither a digit, alphanumeric nor a line
/// break. A candidate of eight or more digits is kept only when its whole
/// normalised text is a date or a clock time (with an optional fraction and
/// zone), or an IPv4 address that is an endpoint: followed by `:port` (at most
/// 65535), loopback (`127.x.x.x`, `0.0.0.0`), or introduced right before it
/// by a context word such as `host:` or `peer=` (see `ipv4_context`). Every
/// field is range-checked. A bare dotted quad such as `12.34.56.78` is a phone
/// number in several countries, so it is masked. Semantic versions are never
/// kept at eight digits or more: `415.555.1234` has the shape of one. Real versions
/// (`1.2.3`, `rustc 1.90.0`) have fewer than eight digits and are never masked.
pub(super) fn redact_grouped_phone_numbers(text: &str) -> String {
    grouped_phone::redact(text)
}

/// The grouped-phone scan: fold the text into units, drop the combining marks
/// a digit owns, then mask the digit candidates.
mod grouped_phone {
    use super::MAX_DIGIT_GAP;

    #[derive(Clone, Copy)]
    struct Unit {
        ch: char,
        start: usize,
        end: usize,
    }

    fn decimal_digit(c: char) -> Option<char> {
        // Each entry starts a block of ten Nd digits. The table is exact, so it
        // needs no `is_numeric` guard, and it does not depend on the Unicode
        // tables of the toolchain knowing the newest blocks. The last rows add
        // the mathematical sets (U+1D7D8, U+1D7E2, U+1D7EC, U+1D7F6; U+1D7CE is
        // the bold set) and the Unicode 16 blocks.
        //
        // This table is not the same as the privacy table in
        // `kernel_privacy::normalize::digits`: it has ten more block starts
        // (U+10D40, U+11950, U+11BF0, U+11F50, U+16130, U+16AC0, U+16D70,
        // U+1CCF0, U+1E4F0, U+1E5F1). Keeping the difference is deliberate in
        // this cleanup: using the union on the privacy side would mask more,
        // which is a detection change that needs a privacy seal. Do not merge
        // the two tables here.
        const ZEROES: &[u32] = &[
            0x0030, 0x0660, 0x06f0, 0x07c0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0be6, 0x0c66,
            0x0ce6, 0x0d66, 0x0de6, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946,
            0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0,
            0xa9f0, 0xaa50, 0xabf0, 0xff10, 0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0,
            0x112f0, 0x11450, 0x114d0, 0x11650, 0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50,
            0x11d50, 0x11da0, 0x11f50, 0x16a60, 0x16ac0, 0x16b50, 0x1d7ce, 0x1e140, 0x1e2f0,
            0x1e4f0, 0x1e950, 0x1fbf0, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x10d40, 0x11bf0,
            0x16130, 0x16d70, 0x1ccf0, 0x1e5f1,
        ];
        let cp = c as u32;
        ZEROES.iter().find_map(|zero| {
            (cp >= *zero && cp < *zero + 10)
                .then(|| char::from_digit(cp - *zero, 10))
                .flatten()
        })
    }

    /// The character named by a `\uXXXX` or `\u{X...}` escape that starts at
    /// byte `i`, and the byte just past it. Surrogates and values beyond
    /// U+10FFFF name no character, so they stay literal text.
    fn escaped_char(text: &str, i: usize) -> Option<(char, usize)> {
        let bytes = text.as_bytes();
        if bytes.get(i) != Some(&b'\\') || bytes.get(i + 1) != Some(&b'u') {
            return None;
        }
        let (hex, end) = if bytes.get(i + 2) == Some(&b'{') {
            let body = bytes.get(i + 3..)?;
            let close = body.iter().take(7).position(|byte| *byte == b'}')?;
            (&body[..close], i + 3 + close + 1)
        } else {
            (bytes.get(i + 2..i + 6)?, i + 6)
        };
        if hex.is_empty() || hex.len() > 6 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let code = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
        char::from_u32(code).map(|ch| (ch, end))
    }

    fn is_format_or_zero_width(c: char) -> bool {
        matches!(
            c as u32,
            0x00ad
                | 0x0600..=0x0605
                | 0x061c
                | 0x06dd
                | 0x070f
                | 0x0890..=0x0891
                | 0x08e2
                | 0x180e
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x206f
                | 0xfeff
                | 0xfff9..=0xfffb
                | 0x110bd
                | 0x110cd
                | 0x13430..=0x1343f
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0001
                | 0xe0020..=0xe007f
        )
    }
    fn is_combining(c: char) -> bool {
        matches!(c as u32, 0x0300..=0x036f)
            || unicode_normalization::char::canonical_combining_class(c) != 0
    }

    /// The value of one to nine ASCII digits (nine cannot overflow `u32`).
    fn digits(bytes: &[u8]) -> Option<u32> {
        if bytes.is_empty() || bytes.len() > 9 || !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            bytes
                .iter()
                .fold(0, |n, byte| n * 10 + u32::from(*byte - b'0')),
        )
    }

    /// The value of exactly `width` ASCII digits.
    fn digits_of_width(bytes: &[u8], width: usize) -> Option<u32> {
        if bytes.len() == width {
            digits(bytes)
        } else {
            None
        }
    }

    /// `HH:MM`, optionally `:SS` with a fraction of up to nine digits (after
    /// `.` or `,`), then an optional `Z` or zone. Every field is range-checked.
    fn clock(bytes: &[u8]) -> bool {
        let (time, zone) = match bytes.split_last() {
            Some((&b'Z', time)) => (time, None),
            _ => match bytes.iter().position(|byte| matches!(*byte, b'+' | b'-')) {
                Some(at) => (&bytes[..at], Some(&bytes[at..])),
                None => (bytes, None),
            },
        };
        let time = match zone {
            // A zone may follow one space: `22:28:46 +0000`.
            Some(zone) if zone_ok(zone) => time.strip_suffix(b" ").unwrap_or(time),
            Some(_) => return false,
            None => time,
        };
        let mut fields = time.split(|byte| *byte == b':');
        let hour = fields.next().and_then(|field| digits_of_width(field, 2));
        let minute = fields.next().and_then(|field| digits_of_width(field, 2));
        let (Some(hour), Some(minute)) = (hour, minute) else {
            return false;
        };
        if hour > 23 || minute > 59 {
            return false;
        }
        if let Some(seconds) = fields.next() {
            if fields.next().is_some() {
                return false;
            }
            let mark = seconds.iter().position(|byte| matches!(*byte, b'.' | b','));
            let (second, fraction) = match mark {
                Some(mark) => (&seconds[..mark], Some(&seconds[mark + 1..])),
                None => (seconds, None),
            };
            if digits_of_width(second, 2).is_none_or(|second| second > 59) {
                return false;
            }
            let fraction_ok = fraction.is_none_or(|digits| {
                (1..=9).contains(&digits.len()) && digits.iter().all(u8::is_ascii_digit)
            });
            if !fraction_ok {
                return false;
            }
        }
        true
    }

    /// A zone: `+HH:MM`, `-HH:MM`, `+HHMM` or `-HHMM`.
    fn zone_ok(zone: &[u8]) -> bool {
        let Some((sign, digits)) = zone.split_first() else {
            return false;
        };
        let (hours, minutes) = match digits {
            [h1, h2, b':', m1, m2] => ([*h1, *h2], [*m1, *m2]),
            [h1, h2, m1, m2] => ([*h1, *h2], [*m1, *m2]),
            _ => return false,
        };
        matches!(*sign, b'+' | b'-')
            && digits_of_width(&hours, 2).is_some_and(|hour| hour <= 23)
            && digits_of_width(&minutes, 2).is_some_and(|minute| minute <= 59)
    }

    /// `YYYY-MM-DD` with a year in 1900..=2100, optionally followed by `T` or
    /// a space and a clock time (with its fraction and zone).
    fn date(bytes: &[u8]) -> bool {
        if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return false;
        }
        let year = digits_of_width(&bytes[..4], 4);
        let month = digits_of_width(&bytes[5..7], 2);
        let day = digits_of_width(&bytes[8..10], 2);
        let (Some(year), Some(month), Some(day)) = (year, month, day) else {
            return false;
        };
        if !(1900..=2100).contains(&year) {
            return false;
        }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return false,
        };
        if day == 0 || day > days {
            return false;
        }
        match &bytes[10..] {
            [] => true,
            [b'T' | b' ', time @ ..] => clock(time),
            _ => false,
        }
    }

    /// `a.b.c.d`: four octets 0..=255, no leading zero unless the octet is a
    /// lone `0`, and an optional `:port` of at most 65535.
    fn ipv4(candidate: &str) -> bool {
        let (address, port) = match candidate.split_once(':') {
            Some((address, port)) => (address, Some(port)),
            None => (candidate, None),
        };
        let octets: Vec<&str> = address.split('.').collect();
        let octet_ok = |octet: &str| {
            let bytes = octet.as_bytes();
            (1..=3).contains(&bytes.len())
                && (bytes.len() == 1 || bytes[0] != b'0')
                && digits(bytes).is_some_and(|value| value <= 255)
        };
        let port_ok = |port: &str| {
            let bytes = port.as_bytes();
            (1..=5).contains(&bytes.len()) && digits(bytes).is_some_and(|value| value <= 65_535)
        };
        octets.len() == 4 && octets.into_iter().all(octet_ok) && port.is_none_or(port_ok)
    }

    /// The words that introduce an endpoint address (`host: 10.0.0.5`). `from`
    /// and `to` are not among them: `call me from 12.34.56.78` is a phone number.
    fn is_context_word(word: &str) -> bool {
        matches!(
            word,
            "ip" | "addr"
                | "address"
                | "host"
                | "peer"
                | "remote"
                | "client"
                | "server"
                | "bind"
                | "listen"
                | "connect"
                | "src"
                | "dst"
        )
    }

    /// Is one of those words right before the address? Only `=`, `:`, a space or
    /// `"` may sit between them, at most two characters (`host: 10.0.0.5`,
    /// `peer=10.0.0.5`). The word must be whole and ASCII case-insensitive, so
    /// `ship` is not `ip`.
    fn ipv4_context(before: &str) -> bool {
        let word_end = before.trim_end_matches(['=', ':', ' ', '"']);
        let separator = &before[word_end.len()..];
        separator.len() <= 2
            && word_end
                .rsplit(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .is_some_and(|word| is_context_word(&word.to_ascii_lowercase()))
    }

    /// An IPv4-shaped candidate is readable only as an endpoint: followed by a
    /// valid `:port`, loopback (`127.x.x.x`, `0.0.0.0`), or introduced by a
    /// context word (see `ipv4_context`). A bare dotted quad of eight digits is
    /// masked.
    fn ipv4_readable(candidate: &str, before: &str) -> bool {
        if !ipv4(candidate) {
            return false;
        }
        let address = candidate
            .split_once(':')
            .map_or(candidate, |(address, _)| address);
        candidate.contains(':')
            || address.starts_with("127.")
            || address == "0.0.0.0"
            || ipv4_context(before)
    }

    /// The whole-candidate shapes that are readable rather than phones. The
    /// candidate is normalised text, so any non-ASCII character (an en dash, a
    /// euro sign, a combining mark) makes it a number. `before` is the raw text
    /// ahead of the candidate, for the IPv4 context rule.
    fn allowed(candidate: &str, before: &str) -> bool {
        let bytes = candidate.as_bytes();
        candidate.is_ascii() && (clock(bytes) || date(bytes) || ipv4_readable(candidate, before))
    }

    pub(super) fn redact(text: &str) -> String {
        let units = phone_units(text);
        let units = drop_combining_units(units);
        mask_grouped_numbers(text, &units)
    }

    /// Fold `text` into units: digits normalised, escapes decoded, zero-width
    /// format characters dropped.
    fn phone_units(text: &str) -> Vec<Unit> {
        let mut units: Vec<Unit> = Vec::with_capacity(text.len());
        let mut i = 0;
        while i < text.len() {
            let (ch, end) = escaped_char(text, i).unwrap_or_else(|| {
                let ch = text[i..].chars().next().unwrap_or('\0');
                (ch, i + ch.len_utf8())
            });
            if let Some(digit) = decimal_digit(ch) {
                units.push(Unit {
                    ch: digit,
                    start: i,
                    end,
                });
            } else if !is_format_or_zero_width(ch) {
                units.push(Unit { ch, start: i, end });
            }
            i = end;
        }
        units
    }

    /// Drop every combining mark a digit neighbours, so an accent cannot split
    /// a number.
    fn drop_combining_units(units: Vec<Unit>) -> Vec<Unit> {
        // A combining mark is dropped when the nearest non-mark character on
        // either side is a digit, so an accent cannot split a number.
        let marks: Vec<bool> = units.iter().map(|unit| is_combining(unit.ch)).collect();
        let mut dropped = vec![false; units.len()];
        let mut after_digit = false;
        for (index, unit) in units.iter().enumerate() {
            if marks[index] {
                dropped[index] = after_digit;
            } else {
                after_digit = unit.ch.is_ascii_digit();
            }
        }
        let mut before_digit = false;
        for (index, unit) in units.iter().enumerate().rev() {
            if marks[index] {
                dropped[index] |= before_digit;
            } else {
                before_digit = unit.ch.is_ascii_digit();
            }
        }
        let units: Vec<Unit> = units
            .into_iter()
            .zip(dropped)
            .filter_map(|(unit, gone)| (!gone).then_some(unit))
            .collect();
        units
    }

    /// Mask every candidate of eight or more digits that is not a readable
    /// date, clock time or IPv4 endpoint.
    fn mask_grouped_numbers(text: &str, units: &[Unit]) -> String {
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        let mut u = 0;
        while u < units.len() {
            if !units[u].ch.is_ascii_digit() {
                u += 1;
                continue;
            }
            let start_u = u;
            let mut end_u = u + 1;
            let mut digit_count = 1;
            while end_u < units.len() {
                if units[end_u].ch.is_ascii_digit() {
                    digit_count += 1;
                    end_u += 1;
                    continue;
                }
                let sep_start = end_u;
                while end_u < units.len()
                    && end_u - sep_start < MAX_DIGIT_GAP
                    && !units[end_u].ch.is_ascii_digit()
                    && !units[end_u].ch.is_alphanumeric()
                    && !matches!(units[end_u].ch, '\n' | '\r')
                {
                    end_u += 1;
                }
                if end_u == sep_start || end_u == units.len() || !units[end_u].ch.is_ascii_digit() {
                    end_u = sep_start;
                    break;
                }
                digit_count += 1;
                end_u += 1;
            }
            let first = units[start_u].start;
            let last = units[end_u - 1].end;
            if digit_count >= 8 {
                let normalized: String = units[start_u..end_u].iter().map(|unit| unit.ch).collect();
                if !allowed(&normalized, &text[..first]) {
                    out.push_str(&text[cursor..first]);
                    out.push_str("<number>");
                    cursor = last;
                }
            }
            u = end_u;
        }
        out.push_str(&text[cursor..]);
        out
    }
}

/// Is `bytes[start..end]` the fraction of a clock time (`22:28:46.123456789`,
/// `22:28:46,123`)? The candidate scanner has already vetted the whole time,
/// and a clock fraction is at most nine digits.
fn is_clock_fraction(bytes: &[u8], start: usize, end: usize) -> bool {
    if start < 9 || end - start > 9 || !matches!(bytes[start - 1], b'.' | b',') {
        return false;
    }
    let seconds = &bytes[start - 9..start - 1];
    seconds.iter().enumerate().all(|(index, byte)| {
        if index == 2 || index == 5 {
            *byte == b':'
        } else {
            byte.is_ascii_digit()
        }
    })
}

/// Replace every maximal run of eight or more ASCII digits with `<number>`.
fn redact_digit_runs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            // Not a digit byte: it starts a full UTF-8 character.
            let ch = text[index..].chars().next().unwrap_or('\0');
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index - start >= 8 && !is_clock_fraction(bytes, start, index) {
            out.push_str("<number>");
        } else {
            out.push_str(&text[start..index]);
        }
    }
    out
}
