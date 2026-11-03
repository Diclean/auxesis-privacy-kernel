//! The phrase scan (K-SECRET-PHRASE): a cue, its qualifier, its link and its
//! value, plus the clause tails that only add masks.

use std::sync::LazyLock;

use regex::Regex;

use super::key_names::{
    skip_blanks, SecretValue, MAX_TERMINATOR_WORD, MAX_VALUE_BYTES, MIN_PASSWORD_LENGTH,
};
use super::key_values::Breaks;
use super::prose::{bare_word, is_secret_shaped, value_word, PROSE_STOPWORDS};

/// The cue of a secret in a sentence (K-SECRET-PHRASE): a password word, a key or token
/// name, a passcode, a PIN, a door or alarm code, `pw`, `pass` or `code`, as a whole word
/// in any case. Group 1 is set for `passwords`, which also links with `are`; group 2 for
/// a passphrase, whose value runs to the clause end; group 3 for a weak cue, whose value
/// needs a digit; group 4 for `code`, which counts only with a qualifier (`the code to
/// the shared drive: …`); group 5 for `token`, whose value must look like one.
static PHRASE_CUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:(passwords)|password|passwd|(passphrase|seed phrase|recovery phrase)|pwd|api[ -]?key|secret key|access key|access token|auth token|private key|(passcode|pass|pw|pin(?: number| code)?|(?:door|alarm|gate|access) code|(code)|(token)))\b",
    )
    .expect("phrase cue shape compiles")
});

/// Most words, and bytes after the cue, of the qualifier between a cue and its link
/// (`for the client portal`). The same caps bound the filler between `is` and a later
/// colon (`the same as before:`). Nothing further is read.
pub(super) const MAX_QUALIFIER_WORDS: usize = 8;
pub(super) const MAX_QUALIFIER_BYTES: usize = 80;

/// Most values read in a list after `passwords` (`are A and B`).
const MAX_LIST_VALUES: usize = 4;

/// Words that may stand between a link and its value (`is now …`); one is skipped.
pub(super) const FILLERS: &str = "now still just also actually currently simply";

/// Words that make `password <word>:` a label, not a value (`password strength: Strong`).
const LABELS: &str = "strength policy requirements rules hint reset manager length";

/// Whether `word` is one of the space-separated `words`, in any case.
pub(crate) fn one_of(words: &str, word: &str) -> bool {
    words.split(' ').any(|one| one.eq_ignore_ascii_case(word))
}

fn is_label(word: &str) -> bool {
    one_of(LABELS, word.trim_end_matches([':', '=', '：']))
}

/// Longest quoted value read up to its closing quote on the same line, in bytes.
const MAX_PHRASE_QUOTE_BYTES: usize = 128;

/// The words that open a qualifier.
pub(super) const QUALIFIER_HEADS: &[&str] = &["for", "to", "of", "on", "at", "in", "with", "from"];

/// The next word at or after `at` and before `stop`, blanks skipped: it runs to the
/// next whitespace, and reads at most `cap` bytes plus one character.
pub(super) fn next_word(text: &str, at: usize, stop: usize, cap: usize) -> Option<(usize, usize)> {
    let start = skip_blanks(text.as_bytes(), at);
    let mut end = start;
    for ch in text.get(start..stop)?.chars() {
        if ch.is_whitespace() || end - start > cap {
            break;
        }
        end += ch.len_utf8();
    }
    (end > start).then_some((start, end))
}

/// How a word links a cue to its value: `is` or `was`, or a separator (`:`, `=`, `->`,
/// or a word that ends with `:` or `=`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    Is,
    Separator,
}

fn link_of(word: &str, plural: bool) -> Option<Link> {
    let plural_link = word.eq_ignore_ascii_case("are") || word.eq_ignore_ascii_case("were");
    if word.eq_ignore_ascii_case("is") || word.eq_ignore_ascii_case("was") || plural && plural_link
    {
        Some(Link::Is)
    } else if matches!(word, "->" | "=>") || word.ends_with([':', '=', '：']) {
        Some(Link::Separator)
    } else {
        None
    }
}

/// What a value needs besides its length: nothing, a digit, or a token's shape (a digit,
/// a letter and eight characters).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Need {
    Any,
    Digit,
    Token,
}

/// The value that opens at `at`, before `stop`: a quoted run up to its closing quote on
/// the line (within [`MAX_PHRASE_QUOTE_BYTES`]), without the quotes, or else the next
/// word without its closing punctuation. Kept when it is no stopword, has
/// [`MIN_PASSWORD_LENGTH`] characters, what `need` asks, and a secret's shape when
/// `shaped`. The second item is where the read stopped.
pub(super) fn phrase_value(
    text: &str,
    at: usize,
    stop: usize,
    need: Need,
    shaped: bool,
) -> (Option<SecretValue>, usize) {
    let Some((start, end)) = next_word(text, at, stop, MAX_VALUE_BYTES) else {
        return (None, at);
    };
    let open = text[start..]
        .chars()
        .next()
        .filter(|ch| "\"'“‘«".contains(*ch));
    let quoted = open.and_then(|open| {
        let inner = start + open.len_utf8();
        let close = match open {
            '“' => '”',
            '‘' => '’',
            '«' => '»',
            other => other,
        };
        let mut limit = stop.min(inner + MAX_PHRASE_QUOTE_BYTES);
        while !text.is_char_boundary(limit) {
            limit -= 1;
        }
        let found = text[inner..limit].find(close)?;
        Some((inner, inner + found))
    });
    let (start, value_end, read) = match quoted {
        Some((inner, close)) => (inner, close, close),
        None => {
            let skip = open.map_or(0, char::len_utf8);
            let word = value_word(&text[start + skip..end]);
            (start + skip, start + skip + word.len(), end)
        }
    };
    let value = &text[start..value_end];
    let stopword = PROSE_STOPWORDS
        .iter()
        .any(|stop| stop.eq_ignore_ascii_case(bare_word(value)));
    let kept = !stopword
        && value.chars().filter(|ch| !ch.is_whitespace()).count() >= MIN_PASSWORD_LENGTH
        && (need == Need::Any || value.chars().any(|ch| ch.is_ascii_digit()))
        && (need != Need::Token || value.len() >= 8 && value.chars().any(char::is_alphabetic))
        && (!shaped || is_secret_shaped(value));
    let value = kept.then_some(SecretValue {
        start,
        end: value_end,
        long: value_end - start > MAX_VALUE_BYTES,
    });
    (value, read)
}

/// The values of secrets written in a sentence (K-SECRET-PHRASE). After a cue comes
/// either a value that looks like a secret (`pass Gx7#qq91`), or an optional qualifier
/// that opens with a [`QUALIFIER_HEADS`] word (at most [`MAX_QUALIFIER_WORDS`] words
/// ending within [`MAX_QUALIFIER_BYTES`] bytes of the cue), a link, and the value. When
/// the word after `is` is not a value, a word ending in `:` within the same caps may
/// still bring one that looks like a secret (`is the same as before: Sunflower#88`).
/// Cue, link and value stay on one line. A cue inside a value already read is skipped,
/// so the scan stays linear.
/// Adds the clause tail of `value`: from its end to its clause end (`. , ; ! ?` or the
/// line break `stop`), with no byte cap; past [`MAX_VALUE_BYTES`] from the value it is
/// long and the gate refuses the text (fail closed). A value ending inside the last
/// tail shares its clause end and adds nothing, so the scan stays linear.
pub(super) fn push_tail(
    text: &str,
    value: Option<&SecretValue>,
    stop: usize,
    tails: &mut Vec<SecretValue>,
    tail_reach: &mut usize,
) {
    let Some(value) = value.filter(|value| value.end > *tail_reach) else {
        return;
    };
    let clause = text[value.start..stop]
        .split(['.', ',', ';', '!', '?'])
        .next()
        .unwrap_or("")
        .trim_end();
    let end = value.start + clause.len();
    // From the value's end, so value and tail are one contiguous masked run.
    let start = value.end.min(end);
    if end > start {
        tails.push(SecretValue {
            start,
            end,
            long: end - value.start > MAX_VALUE_BYTES,
        });
    }
    *tail_reach = (*tail_reach).max(end);
}

/// The phrase scan: its values, and the clause tails that only add to them
/// (K-SECRET-TAIL): after a password, key or code value, the rest of its clause
/// (`is correct horse battery staple`). The scan, its values and every cue it reads
/// stay exactly main's, so a tail can only add a mask (strict superset by
/// construction).
pub(super) fn phrase_scan(text: &str, breaks: &Breaks) -> (Vec<SecretValue>, Vec<SecretValue>) {
    let mut values = Vec::new();
    let mut tails = Vec::new();
    // Where the last tail ended: a cue inside it shares its clause end, so its tail
    // adds nothing and is not read again (the scan stays linear).
    let mut tail_reach = 0;
    let mut resume = 0;
    for cue in PHRASE_CUE_RE.captures_iter(text) {
        let Some(whole) = cue.get(0) else {
            continue;
        };
        if whole.start() < resume {
            continue;
        }
        let (plural, phrase, code) = (cue.get(1).is_some(), cue.get(2).is_some(), cue.get(4));
        let need = match (cue.get(3), cue.get(5)) {
            (_, Some(_)) => Need::Token,
            (Some(_), None) => Need::Digit,
            (None, None) => Need::Any,
        };
        let stop = breaks.break_from(whole.end());
        let mut at = whole.end();
        let mut link = None;
        // The link may follow the full qualifier, so it is read as one word more.
        for index in 0..=MAX_QUALIFIER_WORDS {
            let Some((start, end)) = next_word(text, at, stop, MAX_TERMINATOR_WORD) else {
                break;
            };
            let word = &text[start..end];
            at = end;
            if index == 0 && is_label(word) {
                break;
            }
            if let Some(found) = link_of(word, plural) {
                link = (code.is_none() || index > 0).then_some(found);
                break;
            }
            // A qualifier is one clause: a word with sentence punctuation ends it.
            if index > 0 && word.contains(['.', ',', ';', '!', '?']) {
                break;
            }
            if index == 0
                && !QUALIFIER_HEADS
                    .iter()
                    .any(|head| head.eq_ignore_ascii_case(word))
            {
                // A value glued to a separator (`pwd=abc`) is the key-value rule's.
                if code.is_none() && word.starts_with(|ch: char| ch.is_alphanumeric()) {
                    let (value, read) = phrase_value(text, start, stop, need, true);
                    resume = resume.max(read);
                    values.extend(value);
                }
                break;
            }
            if end - whole.end() > MAX_QUALIFIER_BYTES {
                break;
            }
        }
        let Some(link) = link else {
            continue;
        };
        let adverb = next_word(text, at, stop, MAX_TERMINATOR_WORD)
            .filter(|&(start, end)| one_of(FILLERS, &text[start..end]));
        at = adverb.map_or(at, |(_, end)| end);
        let (mut value, mut read) = phrase_value(text, at, stop, need, false);
        // A passphrase runs to the end of its clause (`is correct horse battery staple`).
        let quoted = |start: usize| text[..start].ends_with(['"', '\'', '“', '‘', '«']);
        if let Some(value) = value
            .as_mut()
            .filter(|value| phrase && !quoted(value.start))
        {
            let mut limit = stop.min(value.start + MAX_PHRASE_QUOTE_BYTES);
            while !text.is_char_boundary(limit) {
                limit -= 1;
            }
            let clause = text[value.start..limit]
                .split(['.', ',', ';', '!', '?'])
                .next();
            value.end = value
                .end
                .max(value.start + clause.unwrap_or("").trim_end().len());
            read = read.max(value.end);
        }
        let tail_cue = !phrase && need == Need::Any && !plural;
        if tail_cue && !value.as_ref().is_some_and(|value| quoted(value.start)) {
            push_tail(text, value.as_ref(), stop, &mut tails, &mut tail_reach);
        }
        resume = resume.max(read);
        if value.is_some() || link == Link::Separator {
            let listed = plural && value.is_some();
            values.extend(value);
            // A list after `passwords`: each next value that looks like a secret, after
            // `and` or a comma.
            let and_at = |from: usize| {
                next_word(text, from, stop, MAX_TERMINATOR_WORD)
                    .filter(|&(start, end)| text[start..end].eq_ignore_ascii_case("and"))
            };
            // Set once the list went on past a closing quote, which main did not read:
            // those items never move `resume`, so every cue main read is still read.
            let mut past_quote = false;
            for _ in 1..if listed { MAX_LIST_VALUES } else { 1 } {
                let mut and = and_at(read);
                if and.is_none() && !text[..read].ends_with(',') {
                    // A quoted item ends at its closing quote; the list goes on after
                    // it (`are "A1xx" and "B2yy"`, K-PUBLIC-MISSES).
                    let close = text[read..]
                        .chars()
                        .next()
                        .filter(|ch| "\"'”’»".contains(*ch));
                    let Some(close) = close else {
                        break;
                    };
                    read += close.len_utf8();
                    past_quote = true;
                    // A comma after the closing quote separates the items too
                    // (`are 'A1xx', 'B2yy'`, pre-review of #129).
                    if text[read..].starts_with(',') {
                        read += 1;
                    }
                    and = and_at(read);
                    if and.is_none() && !text[..read].ends_with(',') {
                        break;
                    }
                }
                let next = and.map_or(read, |(_, end)| end);
                let (Some(item), after) = phrase_value(text, next, stop, need, true) else {
                    break;
                };
                values.push(item);
                read = after;
                if !past_quote {
                    resume = resume.max(after);
                }
            }
            continue;
        }
        // `is set to 4521`, `was changed to 4521` (K-PUBLIC-MISSES): read on its own,
        // so the scan below runs as on main.
        values.extend(set_to_value(text, at, stop, need));
        let filler = at;
        for _ in 0..MAX_QUALIFIER_WORDS {
            let Some((_, end)) = next_word(text, at, stop, MAX_TERMINATOR_WORD) else {
                break;
            };
            at = end;
            if end - filler > MAX_QUALIFIER_BYTES {
                break;
            }
            if text[..end].ends_with(':') {
                let (value, read) = phrase_value(text, at, stop, need, true);
                resume = resume.max(read);
                // `is the same as before: Sunflower#88 horse battery staple` (seal r1
                // of #143): the clause tail follows this value too.
                if !phrase && need == Need::Any && !plural {
                    push_tail(text, value.as_ref(), stop, &mut tails, &mut tail_reach);
                }
                values.extend(value);
                break;
            }
        }
    }
    (values, tails)
}

/// The value after `set to` or `changed to` (also `reset`, `updated`, `switched`), from
/// `at`: it must look like a secret and meet `need`.
pub(super) fn set_to_value(text: &str, at: usize, stop: usize, need: Need) -> Option<SecretValue> {
    let (start, end) = next_word(text, at, stop, MAX_TERMINATOR_WORD)?;
    if !one_of("set changed reset updated switched", &text[start..end]) {
        return None;
    }
    let (start, end) = next_word(text, end, stop, MAX_TERMINATOR_WORD)?;
    if !text[start..end].eq_ignore_ascii_case("to") {
        return None;
    }
    phrase_value(text, end, stop, need, true).0
}
