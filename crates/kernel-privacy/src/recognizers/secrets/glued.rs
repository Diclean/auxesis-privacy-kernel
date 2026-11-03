//! K-SKPROJ-GLUE: `sk-` and `sl.` keys glued after a letter or digit, and the
//! wrapped continuation lines they are joined across.

use std::sync::LazyLock;

use regex::Regex;

use super::key_view::{is_key_char, join_wrapped, KeyView};

/// K-SKPROJ-GLUE: an `sk-` key (`sk-proj-`, `sk-ant-`) or an `sl.` token glued
/// after a letter or a digit (`notesk-proj-…`). The two shapes in [`SHAPES`](super::SHAPES) need
/// a character other than a letter or digit before the prefix. Here the
/// boundary is dropped: exact-length OpenAI bodies are accepted by length,
/// except when the entire run after `sk-` reads as identifier words. Longer
/// issuer formats retain the random-tail shape checks. The accepted span ends
/// at the key body, so a following identifier suffix stays clear. Keys after a
/// non-alphanumeric character are the main scan's; this view only adds.
static GLUED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:sk-|sl\.(?:[a-z]\.)?)[A-Za-z0-9_\-]*").expect("glued key compiles")
});

/// Key characters the long tails of `sk-proj-`, `sk-svcacct-`, `sk-admin-`,
/// `sk-ant-…` and `sl.` tokens need after their sub-prefix. Real tails run about
/// 95 to 200 characters. Such a tail also needs both cases and a digit, and a
/// change between lower case, upper case and digits for at least every
/// [`GLUED_LONG_TURN_EVERY`] characters (a random tail has one every 1.6):
/// slugs, words and repeated filler have far fewer.
const GLUED_MIN_LONG_TAIL: usize = 80;
const GLUED_LONG_TURN_EVERY: usize = 4;

/// Whether `run`, the whole run of key characters of a glued `sk-` or `sl.`
/// match (prefix included, ended by a non-key character or the end of the
/// text), is one of the issuers' exact formats:
///
/// * OpenAI legacy: `sk-` + exactly 48 `[A-Za-z0-9]`;
/// * OpenAI project: `sk-proj-` + exactly 48 or 64 `[A-Za-z0-9]` without the
///   optional marker;
/// * DeepSeek: `sk-` + exactly 32 lower-case hex;
/// * OpenRouter: `sk-or-v1-` + exactly 64 lower-case hex;
/// * any `sk-` tail of [`GLUED_MIN_TAIL`]+ key characters with the OpenAI
///   marker `T3BlbkFJ`;
/// * `sk-proj-`, `sk-svcacct-`, `sk-admin-`, `sk-ant-api0…`, `sk-ant-admin0…`,
///   Dropbox `sl.` and `sl.u.`: [`GLUED_MIN_LONG_TAIL`]+ key characters after
///   the sub-prefix that read as random (see [`GLUED_LONG_TURN_EVERY`]).
///
/// A random 32-hex or 48-character ID after `task-` or `disk-` is masked too:
/// an accepted over-mask, a key may not leak.
pub(super) fn known_glued_format(run: &str) -> bool {
    let all =
        |tail: &str, n: usize, ok: fn(&u8) -> bool| tail.len() == n && tail.bytes().all(|b| ok(&b));
    let hex = |b: &u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    let has = |tail: &str, ok: fn(&u8) -> bool| tail.bytes().any(|b| ok(&b));
    let class = |b: &u8| match b {
        b'a'..=b'z' => 1,
        b'A'..=b'Z' => 2,
        b'0'..=b'9' => 3,
        _ => 0,
    };
    let long = |tail: &str| {
        let turns = tail
            .as_bytes()
            .windows(2)
            .filter(|w| class(&w[0]) * class(&w[1]) != 0 && class(&w[0]) != class(&w[1]))
            .count();
        tail.len() >= GLUED_MIN_LONG_TAIL
            && turns * GLUED_LONG_TURN_EVERY >= tail.len()
            && has(tail, u8::is_ascii_lowercase)
            && has(tail, u8::is_ascii_uppercase)
            && has(tail, u8::is_ascii_digit)
    };
    if let Some(rest) = run.strip_prefix("sl.") {
        let rest = match rest.as_bytes() {
            [b'a'..=b'z', b'.', ..] => &rest[2..],
            _ => rest,
        };
        return long(rest);
    }
    let Some(tail) = run.strip_prefix("sk-") else {
        return false;
    };
    all(tail, 48, u8::is_ascii_alphanumeric)
        || tail.strip_prefix("proj-").is_some_and(|rest| {
            all(rest, 48, u8::is_ascii_alphanumeric) || all(rest, 64, u8::is_ascii_alphanumeric)
        })
        || all(tail, 32, hex)
        || tail
            .strip_prefix("or-v1-")
            .is_some_and(|rest| all(rest, 64, hex))
        || (tail.len() >= GLUED_MIN_TAIL && tail.contains("T3BlbkFJ"))
        || ["proj-", "svcacct-", "admin-", "ant-api0", "ant-admin0"]
            .into_iter()
            .any(|sub| tail.strip_prefix(sub).is_some_and(long))
}

/// A whole glued run is exempt only when it reads as identifier words. Split
/// camelCase and explicit separators, then reject mixed-case/digit segments
/// before the inexpensive pronounceability check.
pub(super) fn plainly_words(run: &str) -> bool {
    let Some(tail) = run.strip_prefix("sk-") else {
        return false;
    };
    let mut words = Vec::new();
    let mut start = 0;
    let b = tail.as_bytes();
    for i in 1..=b.len() {
        let separator = i < b.len() && matches!(b[i], b'_' | b'-' | b'.');
        let boundary = i == b.len()
            || separator
            || (i < b.len()
                && ((b[i].is_ascii_uppercase() && b[i - 1].is_ascii_lowercase())
                    || (b[i].is_ascii_digit() != b[i - 1].is_ascii_digit())));
        if boundary {
            if i > start {
                words.push(&tail[start..i]);
            }
            start = i + usize::from(separator);
        }
    }
    // A clear run must visibly read as a segmented identifier. A single
    // unsegmented word (including repeated-word filler) is never enough.
    let alpha_words = words
        .iter()
        .filter(|word| word.bytes().all(|b| b.is_ascii_alphabetic()))
        .count();
    alpha_words >= 3
        && words.iter().enumerate().all(|(index, word)| {
            let bytes = word.as_bytes();
            if bytes.iter().all(u8::is_ascii_digit) {
                // Keep the #231 identifiers with a trailing year clear, but
                // don't exempt short numeric suffixes or mixed tokens.
                return index + 1 == words.len() && bytes.len() == 4;
            }
            if !bytes.iter().all(u8::is_ascii_alphabetic) {
                return false;
            }
            if bytes.len() < 3 {
                // Preserve the pre-existing #231 camel-case examples, whose
                // two-letter function-word segments are part of longer clear
                // identifiers. The three substantial alphabetic segments
                // required above still prevent a short label from opening an
                // otherwise unsegmented key.
                return ["in", "of", "to", "by", "de", "du", "et", "la", "le", "on"]
                    .iter()
                    .any(|short| word.eq_ignore_ascii_case(short));
            }
            if bytes.first().is_some_and(u8::is_ascii_uppercase) {
                if !bytes[1..].iter().all(u8::is_ascii_lowercase) {
                    return false;
                }
            } else if !bytes.iter().all(u8::is_ascii_lowercase) {
                return false;
            }
            let mut consonants = 0;
            let mut max_consonants = 0;
            for ch in word.chars() {
                if "aeiouyAEIOUY".contains(ch) {
                    consonants = 0;
                } else {
                    consonants += 1;
                    max_consonants = max_consonants.max(consonants);
                }
            }
            max_consonants <= 3 && word.chars().any(|ch| "aeiouyAEIOUY".contains(ch))
        })
}

/// Key characters a glued key needs after its prefix.
const GLUED_MIN_TAIL: usize = 32;

/// Case and digit changes a glued key needs after its prefix.
const GLUED_MIN_TURNS: usize = 16;

/// Lower-case and upper-case letters a glued key needs after its prefix, and
/// upper-case letters not followed by a lower-case one (camelCase has none).
const GLUED_MIN_CASE: usize = 4;
const GLUED_MIN_BARE_UPPER: usize = 1;

/// Whether `tail` reads as random key characters (see [`GLUED_RE`]).
fn key_like_tail(tail: &str) -> bool {
    let class = |ch: char| match ch {
        'a'..='z' => 1,
        'A'..='Z' => 2,
        '0'..='9' => 3,
        _ => 0,
    };
    let (mut len, mut turns, mut last) = (0, 0, 0);
    let (mut lower, mut upper, mut bare_upper) = (0, 0, 0);
    for ch in tail.chars() {
        let now = class(ch);
        len += usize::from(is_key_char(ch));
        turns += usize::from(now != 0 && last != 0 && now != last);
        lower += usize::from(now == 1);
        upper += usize::from(now == 2);
        bare_upper += usize::from(last == 2 && now != 1);
        last = now;
    }
    bare_upper += usize::from(last == 2);
    len >= GLUED_MIN_TAIL
        && turns >= GLUED_MIN_TURNS
        && lower >= GLUED_MIN_CASE
        && upper >= GLUED_MIN_CASE
        // A random base62 key can have every uppercase letter followed by a
        // lowercase byte by chance. In that rare case require stronger class
        // turnover; ordinary camelCase identifiers remain below this floor.
        && (bare_upper >= GLUED_MIN_BARE_UPPER || turns >= 24)
}

/// The byte ranges of the `sk-` and `sl.` keys glued after a letter or a digit.
pub(super) fn glued_keys(text: &str) -> Vec<(usize, usize)> {
    let view = KeyView::for_text(text);
    let haystack = view.as_ref().map_or(text, |view| view.text.as_str());
    let bytes = haystack.as_bytes();
    let mut out = Vec::new();
    let mut consumed = 0;
    let mut consumed_joined = JoinedKeyView::default();
    // K-SKPROJ-GLUE round 2: an exact format also counts when the run goes on
    // with `-` or `_` right after it (`<key>-prod`, `<key>_old`). The lengths
    // are `sk-` + 32, `sk-` + 48 and `sk-or-v1-` + 64; the run is ASCII.
    // An ambiguous glued prefix must first satisfy a key shape. Return the
    // issuer body only; separator tails and following identifiers stay clear.
    let key_end = |run: &str| -> Option<usize> {
        if known_glued_format(run) && !plainly_words(run) {
            return Some(run.len());
        }
        let mut best = None;
        for n in [35, 51, 56, 72, 73] {
            if run.len() >= n && known_glued_format(&run[..n]) && !plainly_words(run) {
                best = Some(best.map_or(n, |previous: usize| previous.max(n)));
            }
        }
        best
    };
    for key in GLUED_RE.find_iter(haystack) {
        let whole_run = key.as_str();
        // Prefer the first issuer-shaped prefix. A random body can itself
        // contain `sk-`; selecting its last occurrence drops real key bytes.
        let mut offset = 0;
        let mut candidate = None;
        let mut seek = 0;
        let mut checked = 0;
        while checked < 2 {
            let Some(found) = whole_run[seek..].find("sk-") else {
                break;
            };
            let at = seek + found;
            checked += 1;
            if let Some(end) = key_end(&whole_run[at..]) {
                offset = at;
                candidate = Some(end);
                break;
            }
            seek = at + 3;
        }
        let run = &whole_run[offset..];
        let start = key.start() + offset;
        let glued = start > 0 && bytes[start - 1].is_ascii_alphanumeric();
        let own_end = candidate.or_else(|| key_end(run));
        if !glued && own_end.is_none() {
            continue;
        }
        // An earlier run joined this line: an exact key is still its own key.
        if key.end() <= consumed {
            if let Some(suffix) = consumed_joined.suffix(start) {
                if let Some(suffix_end) = key_end(suffix) {
                    let end = consumed_joined.original_end();
                    let end = end - (suffix.len() - suffix_end);
                    out.push(view.as_ref().map_or((start, end), |view| {
                        let (mapped_start, _) = view.original(start, key.end());
                        let (_, end) = view.original(start, end);
                        (mapped_start, end)
                    }));
                    continue;
                }
            }
            if let Some(end) = own_end {
                out.push(view.as_ref().map_or((start, start + end), |view| {
                    view.original(start, start + end)
                }));
            }
            continue;
        }
        let end = join_wrapped(haystack, key.end(), is_key_char);
        consumed = end;
        consumed_joined = JoinedKeyView::new(haystack, start, end);
        // The run on its own line, or joined over its wrapped lines (key
        // characters only): either one may hold the exact format.
        let joined: String = haystack[start..end]
            .chars()
            .filter(|ch| is_key_char(*ch) || *ch == '.')
            .collect();
        // Prefer the complete wrapped view: a 64-byte project key can have an
        // exact 48-byte prefix on its first line, which must not truncate it.
        let accepted_end = key_end(&joined)
            .or(own_end)
            .or_else(|| key_like_tail(&haystack[start + 3..end]).then_some(end - start));
        if let Some(accepted_end) = accepted_end {
            // `accepted_end` counts key characters with wrapped line breaks
            // removed. Map its final character through the joined view so the
            // original LF/CRLF bytes are included in the masked span.
            let original_end = consumed_joined
                .ends
                .get(accepted_end.saturating_sub(1))
                .copied()
                .filter(|_| accepted_end > 0)
                .unwrap_or(start + accepted_end);
            out.push(view.as_ref().map_or((start, original_end), |view| {
                view.original(start, original_end)
            }));
        }
    }
    out
}

/// The key characters of one consumed run, with their offsets in the view that
/// `GLUED_RE` scans. Later matches inside that run can read their joined suffix
/// without walking the continuation lines again.
#[derive(Default)]
struct JoinedKeyView {
    text: String,
    starts: Vec<usize>,
    ends: Vec<usize>,
}

impl JoinedKeyView {
    fn new(source: &str, start: usize, end: usize) -> Self {
        let mut view = Self::default();
        for (offset, ch) in source[start..end].char_indices() {
            if is_key_char(ch) || ch == '.' {
                view.text.push(ch);
                view.starts.push(start + offset);
                view.ends.push(start + offset + ch.len_utf8());
            }
        }
        view
    }

    fn suffix(&self, source_start: usize) -> Option<&str> {
        let index = self.starts.binary_search(&source_start).ok()?;
        self.text.get(index..)
    }

    fn original_end(&self) -> usize {
        self.ends.last().copied().unwrap_or(0)
    }
}
