//! The keys of prose links, the words that join them to a value, and the
//! limits of a key's read.

use std::sync::LazyLock;

use regex::Regex;

/// Words a key reads past to find its value.
pub(super) const MAX_WORDS: usize = 10;
/// A longer word ends the search: no value is that long.
///
/// [`strong`](super::value::strong) caps a value at 256 characters, and a key reads at most
/// [`MAX_WORDS`] words, so a 1,024-byte window let every key of a text dense
/// with long hyphenated words walk ten whole words of it: 255 keys per KiB, and
/// a 1 MiB gate run cost 11.8 s against main's 2.2 s. A word past the cap is
/// not a value — the gate splits a secret span at
/// [`MAX_KEY_SPAN_BYTES`](kernel_privacy::recognizer::MAX_KEY_SPAN_BYTES) and
/// reads prose words, not blobs — so the window is 257 bytes and the scan is
/// linear with a small constant.
pub(super) const MAX_WORD: usize = 257;
/// Cookie attributes (`; Path=/`) joined to a cookie value.
pub(super) const MAX_ATTRS: usize = 16;

/// A key in prose, longest alternatives first. `\_` is a Markdown escape.
pub(super) static KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:\b|_)(set-cookies?|(?:http |browser |session )?cookies?|passwords?|passwd|pwd|",
        r"passphrases?|passcodes?|api(?:\\?[_ -])?keys?|(?:access|secret|private)\\?[_ ]keys?|",
        r"(?:access|auth|bearer)\\?[_ ]tokens?|pins?(?: codes?| numbers?)?|codes? pin|",
        r"mots? de passe|mdp|codes? secrets?|cl[ée]s? api|tokens?|jetons?)\b"
    ))
    .expect("prose key list compiles")
});

/// SECRET-RECALL-1 keys, scanned on their own so they never shadow a
/// [`KEY_RE`] key: recovery and backup codes, a named app's secret
/// (`AWS secret`), and a Wi-Fi key or `clé` up to 40 bytes after `Wi-Fi` on its
/// line (`Wi-Fi: CafeNet / key: …`).
pub(super) static EXTRA_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:(?:recovery|backup)[ \t]+codes?|",
        r"codes?[ \t]+de[ \t]+(?:r[ée]cup[ée]ration|secours)|",
        r"(?:aws|client|app|webhook|signing|consumer)\\?[_ ]secrets?|",
        r"(?:wi-?fi|wlan|wpa2?)\b[^\n]{0,40}?\b(?:key|cl[ée]|pass)|cl[ée]s?[ \t]+(?:wi-?fi|wpa2?))\b"
    ))
    .expect("extra prose keys compile")
});

/// SECRET-RECALL-2 Wi-Fi keys, scanned on their own like [`EXTRA_KEY_RE`]: a
/// key, `clé`, password or passphrase up to 40 bytes after `Wi-Fi` on its line,
/// or `clé Wi-Fi`, `mot de passe Wi-Fi`.
pub(super) static WIFI_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:(?:wi-?fi|wlan|wpa2?)\b[^\n]{0,40}?\b(?:key|cl[ée]|pass(?:word|phrase)?|",
        r"mot[ \t]+de[ \t]+passe|mdp)|(?:cl[ée]s?|mot[ \t]+de[ \t]+passe)[ \t]+(?:wi-?fi|wpa2?))\b"
    ))
    .expect("Wi-Fi keys compile")
});

/// Words that end a code run or are no Wi-Fi key, though they read as a group:
/// a sentence start or a polite close (`R6T3 Thanks`), or a status
/// (`Wi-Fi password: required`). Lowercase.
const PROSE_WORDS: &str = concat!(
    "thanks thank then please regards cheers hello sorry note also keep store merci bonjour ",
    "cordialement salut voici ensuite required optional unknown unchanged available attached ",
    "provided missing pending requis obligatoire facultatif inconnu disponible identique"
);

pub(super) fn is_prose_word(word: &str) -> bool {
    PROSE_WORDS.split(' ').any(|w| w.eq_ignore_ascii_case(word))
}

/// `use VALUE as the password`: the value before its key.
pub(super) static REVERSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\buse[ \t]+(\S{6,256}?)[ \t]+as[ \t]+(?:(?:the|your|my|our|their|a|an)[ \t]+)?",
        r"(?:new[ \t]+)?(?:password|passcode|passphrase|pin|api key)\b"
    ))
    .expect("reverse link compiles")
});

/// A cookie attribute after a `name=value` pair: the cue of a bare cookie.
pub(super) static ATTR_CUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i);[ \t]?(?:path|domain|expires|max-age|samesite|httponly|secure)\b")
        .expect("cookie attribute cue compiles")
});

/// One cookie attribute or further pair, at the start of the rest of a value.
pub(super) static ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)^;[ \t]?(?:expires=[a-z]{3},?[ \t][^;\n]{0,32}?gmt|",
        r"[a-z_][a-z0-9_.-]{0,63}(?:=[^;\s]{0,512})?)"
    ))
    .expect("cookie attribute compiles")
});

/// Words that link a key to its value.
pub(super) const LINKS: &[&str] = &[
    "is",
    "was",
    "are",
    "were",
    "be",
    "as",
    "to",
    "use",
    "using",
    "with",
    "of",
    "like",
    "including",
    "value",
    "now",
    "equals",
    "en",
    "est",
    "etait",
    "était",
    "sera",
    "vaut",
];
