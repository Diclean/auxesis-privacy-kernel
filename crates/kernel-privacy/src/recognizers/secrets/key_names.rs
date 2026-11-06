//! Key names and their class, and the secret value every scan returns.

use std::sync::LazyLock;

use regex::Regex;

/// An AWS secret access key or session token, matched by its key name in env,
/// ini, JSON and YAML (`SecretAccessKey`, `secret_access_key = "…"`,
/// `AWS_SECRET_KEY=`, a YAML folded value). Only the value is the secret.
pub(super) static AWS_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:(?:aws_?)?secret_?access_?key|aws_?secret_?key|aws_session_token)["']?\s*[:=]\s*[>|]?\s*["']?([A-Za-z0-9/+=_\-]{20,})"#,
    )
    .expect("aws secret key shape compiles")
});

/// Longest key token read before a separator, in bytes. A key name is found within
/// this many bytes of its separator; nothing further back is read.
const MAX_KEY_BYTES: usize = 64;

/// Longest value read up to its own end, in bytes. A longer one is the whole remainder
/// of its line, masked as one secret: over-masked, never refused, never masked in part.
pub(super) const MAX_VALUE_BYTES: usize = 1024;

/// Longest YAML block scalar the gate reads, in bytes. A longer one is refused too.
pub(super) const MAX_BLOCK_BYTES: usize = 8192;

/// Longest quoted value read up to its closing quote, in bytes. The quote may close
/// on a later line.
pub(super) const MAX_QUOTED_BYTES: usize = 8192;

/// Longest word read when a blank is tested for starting another assignment, in bytes.
pub(super) const MAX_TERMINATOR_WORD: usize = 128;

/// Bytes before a separator read for a spaced or non-ASCII key name.
const KEY_TAIL_BYTES: usize = 40;

/// Most key segments joined when testing a key name.
const MAX_NAME_SEGMENTS: usize = 4;

/// Shortest value (blanks not counted) of a password key. Other secret keys take any
/// non-empty value.
pub(super) const MIN_PASSWORD_LENGTH: usize = 4;

/// The class of a key: a password, or another secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyClass {
    Password,
    Other,
}

/// Key names that match a segment of a key, or a run of segments joined by `_`:
/// `SECRET_KEY` has the segment `secret`, `APP_KEY` the run `app_key`.
const KEY_NAMES: &[(&str, KeyClass)] = &[
    ("password", KeyClass::Password),
    ("passwd", KeyClass::Password),
    ("pwd", KeyClass::Password),
    ("pass", KeyClass::Password),
    ("passphrase", KeyClass::Password),
    ("mdp", KeyClass::Password),
    ("mot_de_passe", KeyClass::Password),
    ("motdepasse", KeyClass::Password),
    ("jelszo", KeyClass::Password),
    ("geslo", KeyClass::Password),
    ("wagwoord", KeyClass::Password),
    ("secret", KeyClass::Other),
    ("token", KeyClass::Other),
    ("api_key", KeyClass::Other),
    ("apikey", KeyClass::Other),
    ("access_key", KeyClass::Other),
    ("private_key", KeyClass::Other),
    ("client_secret", KeyClass::Other),
    ("encryption_key", KeyClass::Other),
    ("master_key", KeyClass::Other),
    ("app_key", KeyClass::Other),
    ("auth_token", KeyClass::Other),
    ("credential", KeyClass::Other),
    ("credentials", KeyClass::Other),
    ("dsn", KeyClass::Other),
    ("creds", KeyClass::Other),
    ("identifiants", KeyClass::Other),
    ("account_key", KeyClass::Other),
    ("subscription_key", KeyClass::Other),
    ("preshared_key", KeyClass::Other),
    ("psk", KeyClass::Password),
    ("mnemonic", KeyClass::Password),
];

/// Name endings that make a one-word key a secret's (`PGPASSWORD`, `dbpassword`,
/// `clientsecret`): a segment that is two or more ASCII letters, then one.
const KEY_SUFFIXES: &[(&str, KeyClass)] = &[
    ("password", KeyClass::Password),
    ("passwd", KeyClass::Password),
    ("passphrase", KeyClass::Password),
    ("secret", KeyClass::Other),
    ("token", KeyClass::Other),
    ("apikey", KeyClass::Other),
];

/// Key names that match the text before the separator: spaced and non-ASCII names.
const KEY_PHRASES: &[(&str, KeyClass)] = &[
    ("mot de passe", KeyClass::Password),
    ("jelszó", KeyClass::Password),
    ("密码", KeyClass::Password),
    ("密碼", KeyClass::Password),
    ("口令", KeyClass::Password),
    ("助记词", KeyClass::Password),
    ("phrase de récupération", KeyClass::Password),
    ("phrase de recuperation", KeyClass::Password),
];

/// A secret-class value: its byte span in the scanned text, and whether it is past
/// the length the gate reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SecretValue {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) long: bool,
}

/// The segments of a key token, split at `_`, `.`, `-` and at camelCase boundaries
/// (`secretKey` and `APIKey` split too). Slices of the token: a key costs one
/// allocation.
fn key_segments(token: &str) -> Vec<&str> {
    let bytes = token.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if matches!(byte, b'_' | b'.' | b'-') {
            if index > start {
                segments.push(&token[start..index]);
            }
            start = index + 1;
        } else if byte.is_ascii_uppercase() && index > start {
            let before = bytes[index - 1];
            let acronym_end = before.is_ascii_uppercase()
                && bytes.get(index + 1).is_some_and(u8::is_ascii_lowercase);
            if before.is_ascii_lowercase() || before.is_ascii_digit() || acronym_end {
                segments.push(&token[start..index]);
                start = index;
            }
        }
    }
    if start < bytes.len() {
        segments.push(&token[start..]);
    }
    segments
}

/// Whether a run of up to [`MAX_NAME_SEGMENTS`] segments, joined by `_`, is `name`
/// (ASCII case ignored).
fn segments_contain(segments: &[&str], name: &str) -> bool {
    (0..segments.len()).any(|first| {
        let mut rest = name;
        for (offset, segment) in segments[first..].iter().take(MAX_NAME_SEGMENTS).enumerate() {
            if offset > 0 {
                let Some(next) = rest.strip_prefix('_') else {
                    return false;
                };
                rest = next;
            }
            let Some(head) = rest.get(..segment.len()) else {
                return false;
            };
            if !head.eq_ignore_ascii_case(segment) {
                return false;
            }
            rest = &rest[segment.len()..];
            if rest.is_empty() {
                return true;
            }
        }
        false
    })
}

/// The class of a key token by the key names it carries. A password name wins. A
/// token with no key name is read by its [`KEY_SUFFIXES`] only, so no class an
/// older name gave changes.
pub(super) fn name_class(token: &str) -> Option<KeyClass> {
    let segments = key_segments(token);
    let mut found = None;
    for &(name, class) in KEY_NAMES {
        if segments_contain(&segments, name) {
            if class == KeyClass::Password {
                return Some(KeyClass::Password);
            }
            found = Some(class);
        }
    }
    found.or_else(|| {
        segments.iter().find_map(|segment| {
            KEY_SUFFIXES.iter().find_map(|&(suffix, class)| {
                let cut = segment.len().checked_sub(suffix.len())?;
                let (head, end) = (segment.get(..cut)?, segment.get(cut..)?);
                let letters = head.len() > 1 && head.bytes().all(|b| b.is_ascii_alphabetic());
                (letters && end.eq_ignore_ascii_case(suffix)).then_some(class)
            })
        })
    })
}

/// The class of the text before a separator, by a spaced or non-ASCII key name. The
/// window is `text[window..end]`; an ASCII window is compared without a copy.
fn phrase_class(text: &str, window: usize, end: usize) -> Option<KeyClass> {
    let tail = &text[window..end];
    if tail.is_ascii() {
        KEY_PHRASES
            .iter()
            .find(|entry| {
                let phrase = entry.0;
                phrase.is_ascii()
                    && tail.len() >= phrase.len()
                    && tail[tail.len() - phrase.len()..].eq_ignore_ascii_case(phrase)
            })
            .map(|entry| entry.1)
    } else {
        let lower = tail.to_lowercase();
        KEY_PHRASES
            .iter()
            .find(|entry| lower.ends_with(entry.0))
            .map(|entry| entry.1)
    }
}

/// The key before the separator at `sep`: blanks and up to [`MAX_KEY_MARKS`] closing
/// marks (a JSON or curly quote, a backtick, Markdown `*` or `_`) are skipped, then
/// the ASCII key characters (at most [`MAX_KEY_BYTES`]) are read and matched.
pub(super) fn key_before(text: &str, sep: usize) -> Option<KeyClass> {
    let bytes = text.as_bytes();
    let mut end = skip_back_blanks(bytes, sep);
    let mut marks = 0;
    while marks < MAX_KEY_MARKS {
        let Some(mark) = text[..end]
            .chars()
            .next_back()
            .filter(|ch| is_key_mark(*ch))
        else {
            break;
        };
        end -= mark.len_utf8();
        marks += 1;
    }
    if marks > 0 {
        end = skip_back_blanks(bytes, end);
    }
    let mut start = end;
    while start > 0 && end - start < MAX_KEY_BYTES && is_key_byte(bytes[start - 1]) {
        start -= 1;
    }
    let token = &text[start..end];
    let mut class = name_class(token);
    // A spaced or non-ASCII name ends the text before the separator. Only a word that
    // ends the phrase (`passe` of `mot de passe`), or no word at all, can end one;
    // a token with no class is read too (`ration` of `phrase de récupération`).
    if token.is_empty() || token.eq_ignore_ascii_case("passe") || class.is_none() {
        let mut window = end.saturating_sub(KEY_TAIL_BYTES);
        while !text.is_char_boundary(window) {
            window += 1;
        }
        if class != Some(KeyClass::Password) {
            class = phrase_class(text, window, end).or(class);
        }
    }
    class
}

/// Whether a label line ends with a separator after a key the gate reads as a
/// secret's (`myapikey:`, `psk =`, `mot de passe :`), as [`key_before`] reads it,
/// a YAML block-scalar header after it too (`password: |-`, `apikey: >2`).
pub(crate) fn names_a_key(label: &str) -> bool {
    let label = label.trim_end();
    let names = |label: &str| {
        let sep = label.char_indices().next_back().map(|(at, _)| at);
        sep.is_some_and(|at| separator_len(label, at).is_some() && key_before(label, at).is_some())
    };
    names(label) || without_block_header(label).is_some_and(names)
}

/// A label line without the block-scalar header that ends it (`password: >`),
/// trailing blanks taken out; `None` when no header ends it.
pub(crate) fn without_block_header(label: &str) -> Option<&str> {
    let label = label.trim_end();
    let at = label.rfind([' ', '\t', ':', '=', '：'])?;
    let at = at + label[at..].chars().next().map_or(0, char::len_utf8);
    is_block_header(&label[at..]).then(|| label[..at].trim_end())
}

/// The most closing marks read between a key and its separator (`**password**:`).
const MAX_KEY_MARKS: usize = 3;

/// A mark that may close a key: a straight or curly quote, a guillemet, a backtick,
/// or Markdown emphasis.
pub(super) fn is_key_mark(ch: char) -> bool {
    matches!(
        ch,
        '"' | '\''
            | '`'
            | '*'
            | '_'
            | '\u{201c}'
            | '\u{201d}'
            | '\u{2018}'
            | '\u{2019}'
            | '\u{ab}'
            | '\u{bb}'
    )
}

pub(super) fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

pub(super) fn is_blank(ch: char) -> bool {
    ch == ' ' || ch == '\t'
}

/// The index after the blanks (spaces and tabs) that start at `at`.
pub(super) fn skip_blanks(bytes: &[u8], mut at: usize) -> usize {
    while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
        at += 1;
    }
    at
}

/// The index before the blanks that end at `at`.
fn skip_back_blanks(bytes: &[u8], mut at: usize) -> usize {
    while at > 0 && matches!(bytes[at - 1], b' ' | b'\t') {
        at -= 1;
    }
    at
}

/// The length of the separator at `at`: `:=` (Go) and `=>` (PHP, Ruby) are two
/// bytes; `:`, `=` and `：` are one.
pub(super) fn separator_len(text: &str, at: usize) -> Option<usize> {
    let rest = &text[at..];
    if rest.starts_with(":=") || rest.starts_with("=>") {
        Some(2)
    } else if rest.starts_with([':', '=', '：']) {
        rest.chars().next().map(char::len_utf8)
    } else {
        None
    }
}

/// Whether a value is a YAML block-scalar header: `|` or `>`, then `-`, `+` or digits.
pub(super) fn is_block_header(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= 4
        && matches!(chars.next(), Some('|' | '>'))
        && chars.all(|ch| matches!(ch, '-' | '+' | '0'..='9'))
}
