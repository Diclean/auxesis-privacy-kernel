//! A letters-only Wi-Fi key right after its cue.

use super::keys::is_prose_word;
use super::value::{bounded, core, next_word};

/// A letters-only Wi-Fi key right after its [`WIFI_KEY_RE`](super::keys::WIFI_KEY_RE)
/// key and a `:`, `=`, `is` or `est` (`Wi-Fi key: blueotterriver`), on the
/// key's line or the next: 8 to 63 letters, the length of a WPA passphrase, not
/// a [`PROSE_WORDS`](super::keys::PROSE_WORDS) status nor `ask…`/`see…`, and after `is` no `-ed` or `-ing`
/// verb (`is changing`). The value position is the cue, so no digit is needed.
pub(super) fn wifi_word(text: &str, from: usize) -> Option<(usize, usize)> {
    let rest = bounded(text, from);
    let trimmed = rest.trim_start_matches([' ', '\t']);
    let word = ["is ", "est "].iter().find_map(|w| trimmed.strip_prefix(w));
    let linked = word.or_else(|| trimmed.strip_prefix([':', '=', '：']))?;
    let linked = linked.trim_start_matches([' ', '\t']);
    let next = linked.strip_prefix("\r\n").or(linked.strip_prefix('\n'));
    let (start, word_end) = next_word(text, from + rest.len() - next.unwrap_or(linked).len())?;
    let (start, end) = core(text, start, word_end);
    let value = &text[start..end];
    let verb = word.is_some() && (value.ends_with("ed") || value.ends_with("ing"));
    let lower = value.to_lowercase();
    let prose = is_prose_word(value) || lower.starts_with("ask") || lower.starts_with("see");
    let letters = value.chars().all(char::is_alphabetic) && !prose && !verb;
    ((8..=63).contains(&value.chars().count()) && letters).then_some((start, end))
}
