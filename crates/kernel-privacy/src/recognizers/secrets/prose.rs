//! The prose rule (K13): a key followed by its value on the same line.

use std::sync::LazyLock;

use regex::Regex;

use super::key_names::{name_class, SecretValue, MAX_VALUE_BYTES, MIN_PASSWORD_LENGTH};
use super::key_values::Breaks;
use super::phrase::phrase_scan;
use super::tail::key_tail_scan;

/// The key of a prose secret (K13): a password, a passcode, or a key or token, with
/// the closed key set and a whole-word match, in any case. The link is an optional
/// `is`, `was`, `of`, `=`, `:` or `->`, after up to three Markdown or quote marks
/// closing the key (`**password**:`, `` `password` is ``), and the value is the next word on the line,
/// after an optional quote. A key and its value stay on one line.
static PROSE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:\b|_)(?:passwd|password|pwd|passcode|passphrase|api[ -]key|apikey|secret key|access key|access token|auth token|private key)(?:\b[*_`"'”’»]{0,3}|_{1,3}[*`"'”’»]{0,2})(?:[ \t]+(?:is|was|of)[ \t]+|[ \t]*(?:=|:|->)[*_`]{0,3}[ \t]*|[ \t]+)["'“‘«]?([^\s]+)"#,
    )
    .expect("prose secret shape compiles")
});

/// A key name wrapped in marks (`` `token` is X ``, `“clientSecret” was X`,
/// `__api_key__ is X`), K15: the marks show it is a name, so any name that the
/// name-assigned rule classes as a secret key takes an `is` or `was` link. Group 1
/// is the name, group 2 the value.
static DECORATED_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"[*_`"'“‘«]{1,3}([A-Za-z][A-Za-z0-9_.\- ]{0,62}[A-Za-z0-9])[*_`"'”’»]{1,3}[ \t]+(?i:is|was)[ \t]+["'“‘«]?([^\s]+)"#,
    )
    .expect("decorated key shape compiles")
});

/// Words that follow a prose key and are not its value (K13): a status, a function
/// word, or the head of a noun phrase such as `password manager`.
pub(super) const PROSE_STOPWORDS: &[&str] = &[
    "is",
    "was",
    "are",
    "required",
    "incorrect",
    "invalid",
    "expired",
    "wrong",
    "missing",
    "reset",
    "changed",
    "updated",
    "manager",
    "field",
    "policy",
    "protected",
    "here",
    "below",
    "above",
    "for",
    "to",
    "and",
    "or",
    "the",
    "a",
    "an",
    "not",
    "will",
    "must",
    "should",
    "can",
];

/// A value word without the punctuation and closing quote that follow it.
pub(super) fn value_word(word: &str) -> &str {
    word.trim_end_matches(['.', ',', ';', ')', ']', '"', '\''])
}

/// A value word without any closing mark, only to compare it with a stopword: the
/// masked span keeps the marks, which may be part of the secret.
pub(super) fn bare_word(word: &str) -> &str {
    value_word(word).trim_end_matches(['`', '*', '_', '}', '\u{201d}', '\u{2019}', '\u{bb}'])
}

/// Whether a value word is long enough to be a secret (K13).
pub(super) fn is_value_word(word: &str) -> bool {
    word.chars().count() >= MIN_PASSWORD_LENGTH
}

/// The values of the prose rule (K13): the word after a prose key, unless it is a
/// stopword or too short.
pub(super) fn prose_values(text: &str) -> (Vec<SecretValue>, Vec<SecretValue>) {
    let breaks = Breaks::new(text);
    let (phrase, mut tails) = phrase_scan(text, &breaks);
    let extra = key_tail_scan(text, &breaks);
    let named = DECORATED_KEY_RE.captures_iter(text).filter_map(|captures| {
        let name = captures.get(1)?.as_str().replace(' ', "_");
        name_class(&name).and(captures.get(2))
    });
    let mut values: Vec<SecretValue> = PROSE_KEY_RE
        .captures_iter(text)
        .filter_map(|captures| captures.get(1))
        .chain(named)
        .filter_map(|value| {
            let word = value_word(value.as_str());
            let stopword = PROSE_STOPWORDS
                .iter()
                .any(|stop| stop.eq_ignore_ascii_case(bare_word(word)));
            // The key rule masks exactly what the main scan masked (an exclusion
            // list would let real values through); the phrase rule below only adds.
            if stopword || !is_value_word(word) {
                return None;
            }
            Some(SecretValue {
                start: value.start(),
                end: value.start() + word.len(),
                long: word.len() > MAX_VALUE_BYTES,
            })
        })
        .chain(phrase)
        .collect();
    // Both shapes may find the same value: keep it once.
    values.sort_by_key(|value| (value.start, value.end));
    values.dedup_by_key(|value| (value.start, value.end));
    // A clause-tail span equal to a value is that value: kept once.
    let key = |value: &SecretValue| (value.start, value.end);
    tails.extend(
        extra
            .into_iter()
            .filter(|span| values.binary_search_by_key(&key(span), key).is_err()),
    );
    (values, tails)
}

/// Whether a value with no link before it looks like a secret rather than a word: it
/// has a digit, a character that is not a letter, or a capital after its first letter.
pub(super) fn is_secret_shaped(word: &str) -> bool {
    word.chars()
        .enumerate()
        .any(|(index, ch)| !ch.is_alphabetic() || (index > 0 && ch.is_uppercase()))
}
