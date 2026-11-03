//! HTML entity references: numeric values and named lookup over the tables.

use super::entities;

/// The longest entity body we decode, in bytes.
pub(crate) const MAX_ENTITY_BODY: usize = 34;

/// Windows-1252 characters HTML5 substitutes for numeric references
/// `&#128;` to `&#159;`, in order; a C1 control reads U+FFFD.
const C1_REPLACEMENTS: &str = "€\u{FFFD}‚ƒ„…†‡ˆ‰Š‹Œ\u{FFFD}Ž\u{FFFD}\u{FFFD}‘’“”•–—˜™š›œ\u{FFFD}žŸ";

/// Decode the entity that starts at `index` (which holds `&`).
///
/// Returns the decoded string and the source bytes consumed. A numeric reference
/// follows HTML5: any digits (leading zeros too), `;` optional, an invalid value
/// reads U+FFFD. A named entity is any HTML5 name in any case; without `;` only a
/// legacy name decodes, the longest one at the start of the run. Anything else
/// returns `None`, so its bytes stay in place.
pub(super) fn decode_entity(source: &str, index: usize) -> Option<(String, usize)> {
    let bytes = &source.as_bytes()[index + 1..];
    if bytes.first() == Some(&b'#') {
        let hex = matches!(bytes.get(1), Some(b'x' | b'X'));
        let digits_at = if hex { 2 } else { 1 };
        let radix = if hex { 16 } else { 10 };
        // Every digit is consumed, so a long run is read once, not per `&`.
        let (count, code) = bytes[digits_at..]
            .iter()
            .map_while(|b| (*b as char).to_digit(radix))
            .fold((0, 0u32), |(n, code), digit| {
                (
                    n + 1,
                    code.saturating_mul(radix)
                        .saturating_add(digit)
                        .min(0x11_0000),
                )
            });
        if count == 0 {
            return None;
        }
        let used = digits_at + count;
        let used = used + usize::from(bytes.get(used) == Some(&b';'));
        let ch = match code {
            0x80..=0x9F => C1_REPLACEMENTS
                .chars()
                .nth((code - 0x80) as usize)
                .unwrap_or('\u{FFFD}'),
            _ => char::from_u32(code)
                .filter(|ch| *ch != '\0')
                .unwrap_or('\u{FFFD}'),
        };
        return Some((ch.to_string(), used + 1));
    }
    // A longer run is read for its longest known prefix, as HTML5 does.
    let name_len = bytes
        .iter()
        .take(MAX_ENTITY_BODY)
        .take_while(|b| b.is_ascii_alphanumeric())
        .count();
    let name = &source[index + 1..index + 1 + name_len];
    let lower = name.to_ascii_lowercase();
    if bytes.get(name_len) == Some(&b';') {
        if let Some(value) = named_entity(name, &lower, true) {
            return Some((value.to_string(), name_len + 2));
        }
    }
    // No `;`: the longest legacy name at the start of the run.
    (1..=name_len).rev().find_map(|len| {
        named_entity(&name[..len], &lower[..len], false).map(|value| (value.to_string(), len + 1))
    })
}

/// Names the kernel decoded without `;` before the full table, though HTML5
/// reads them only with it: they stay decoded, so no view loses a character.
const NO_SEMICOLON_EXTRA: &[&str] = &[
    "applyfunction",
    "apos",
    "bull",
    "emsp",
    "ensp",
    "euro",
    "hellip",
    "invisiblecomma",
    "invisibletimes",
    "ldquo",
    "lrm",
    "lsquo",
    "mdash",
    "ndash",
    "negativemediumspace",
    "negativethickspace",
    "negativethinspace",
    "negativeverythinspace",
    "nobreak",
    "nonbreakingspace",
    "rdquo",
    "rlm",
    "rsquo",
    "thinsp",
    "trade",
    "zerowidthspace",
    "zwj",
    "zwnj",
];

/// The HTML5 named character reference `name` (without `;`, `lower` is its
/// ASCII lowercase): an exact match first, then any case (`&EACUTE;` reads
/// `é`). Without its `;` (`semicolon` false) a name decodes only when HTML5
/// allows it (`&eacute`, `&amp`) or the kernel always has. Two binary searches over the generated table: linear
/// decoding stays linear.
fn named_entity(name: &str, lower: &str, semicolon: bool) -> Option<&'static str> {
    let find = |table: &'static [(&str, &str, bool)], key: &str| {
        table
            .binary_search_by(|(entry, _, _)| entry.cmp(&key))
            .ok()
            .map(|at| table[at])
    };
    let (_, value, legacy) =
        find(entities::ENTITIES, name).or_else(|| find(entities::FOLDED, lower))?;
    (semicolon || legacy || NO_SEMICOLON_EXTRA.contains(&lower)).then_some(value)
}
