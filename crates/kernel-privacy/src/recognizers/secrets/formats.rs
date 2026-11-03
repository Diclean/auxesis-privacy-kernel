//! Other secret formats: DSN userinfo, AWS pairs, authorization headers,
//! PEM/PuTTY keys and MySQL flags, and the scan that gathers every value.

use std::sync::LazyLock;

use regex::Regex;

use super::key_names::{SecretValue, MAX_VALUE_BYTES};
use super::key_values::{cli_values, k8s_values, key_values, line_spans, xml_values};
use super::key_view::KeyView;
use super::prose::{is_value_word, prose_values, value_word};

/// A MySQL command word, or a `-u` or `--user` flag, which makes a glued `-p` a
/// password on the same line (K13). The command word is case-insensitive; the
/// flags are not.
static MYSQL_COMMAND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:\bmysql(?:dump)?\b|\bmariadb\b)|(?:^|\s)(?:-u|--user)")
        .expect("mysql command shape compiles")
});

/// A `-p` flag glued to its value, with no space, as `mysql -pSECRET` takes it.
static MYSQL_FLAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)-p(\S+)").expect("mysql flag shape compiles"));

/// The MySQL-style values (K13): a glued `-p` value on a line that names a MySQL or
/// MariaDB command or a `-u` or `--user` flag. Each line is read on its own.
fn mysql_values(text: &str) -> Vec<SecretValue> {
    let mut values = Vec::new();
    for (line_start, line_stop) in line_spans(text) {
        let line = &text[line_start..line_stop];
        if !line.contains("-p") || !MYSQL_COMMAND_RE.is_match(line) {
            continue;
        }
        for captures in MYSQL_FLAG_RE.captures_iter(line) {
            let Some(value) = captures.get(1) else {
                continue;
            };
            let word = value_word(value.as_str());
            if is_value_word(word) {
                let start = line_start + value.start();
                values.push(SecretValue {
                    start,
                    end: start + word.len(),
                    long: word.len() > MAX_VALUE_BYTES,
                });
            }
        }
    }
    values
}

/// Every secret-class value in `text`: the key-value pairs, the k8s pairs, the XML
/// elements and the command-line flags. The prose rule and the MySQL flag add the
/// values that do not overlap a name-assigned value, which wins on overlap (K10).
pub(super) fn secret_values(text: &str) -> Vec<SecretValue> {
    let mut values = key_values(text);
    values.extend(k8s_values(text));
    values.extend(xml_values(text));
    values.extend(cli_values(text));
    let mut assigned = values.clone();
    assigned.sort_unstable_by_key(|value| value.start);
    // The furthest end of the values up to each index: a value overlaps one of
    // them exactly when the furthest end before its own end passes its start.
    let mut reach = Vec::with_capacity(assigned.len());
    let mut furthest = 0;
    for value in &assigned {
        furthest = furthest.max(value.end);
        reach.push(furthest);
    }
    let (prose, tails) = prose_values(text);
    for value in prose.into_iter().chain(mysql_values(text)) {
        let before = assigned.partition_point(|kept| kept.start < value.end);
        let overlaps = before > 0 && reach[before - 1] > value.start;
        if !overlaps {
            values.push(value);
        }
    }
    // Clause tails are added after the K10 overlap rule, never filtered by it: a tail
    // only widens what is masked (K-SECRET-TAIL).
    values.extend(tails);
    values
}

/// Whether a secret-class value in `text` is longer than the gate reads. The gate
/// refuses such text (fail closed): a value is never masked in part.
pub fn value_too_long(text: &str) -> bool {
    let view = KeyView::for_text(text);
    let haystack = view.as_ref().map_or(text, |view| view.text.as_str());
    secret_values(haystack).iter().any(|value| value.long)
}

/// The userinfo of a URL, `scheme://user:password@`, for any host. The user may be
/// empty (`redis://:password@host`). The password is the secret; the user is one
/// too when it is not empty.
pub(super) static DSN_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.\-]*://([^\s/@:"'<>]*):([^\s/@"'<>]+)@"#)
        .expect("DSN userinfo shape compiles")
});

/// A `user:password@host/path` without its scheme (`DATABASE_URL=ada:pass@db/x`).
/// The host needs a path or port, so `mailto:alice@example.com` stays clear.
pub(super) static DSN_NO_SCHEME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:^|[\s"'=,;(])([A-Za-z0-9._~%+\-]{1,64}):([^\s/@"'<>]{6,})@[A-Za-z0-9.\-]+[:/]"#,
    )
    .expect("scheme-less DSN shape compiles")
});

/// An AWS access key ID and the 40-character secret beside it, on the same line
/// or the next. Only the secret is the span; the ID has its own shape.
pub(super) static AWS_PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:AKIA|ASIA)[0-9A-Z]{16}[^A-Za-z0-9+/=]{0,8}([A-Za-z0-9/+=]{40})")
        .expect("AWS pair shape compiles")
});

/// The value of an `Authorization:` header with a Bearer or Basic credential.
pub(super) static AUTHORIZATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)Authorization:\s*(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=\-]{8,})")
        .expect("authorization shape compiles")
});

/// A PEM private-key block (OPENSSH, RSA, EC, PGP and generic), from its header to
/// its footer. Without a footer the block runs to the end of the text: a header
/// with no footer is still a key, so it fails toward masking.
pub(super) static PEM_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----|\z)",
    )
    .expect("PEM block shape compiles")
});

/// A PuTTY private key file (`.ppk`), from its header to its MAC line.
pub(super) static PUTTY_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"PuTTY-User-Key-File-\d: [^\n]*\n[\s\S]*?(?:Private-MAC: [0-9a-f]+|\z)")
        .expect("PuTTY key shape compiles")
});

/// A PEM body with no header: a line of 64 characters that opens with `MII`, and
/// two or more lines of 64 characters after it (the base64 of a DER key).
pub(super) static HEADERLESS_PEM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^MII[A-Za-z0-9+/]{61}(?:\r?\n[A-Za-z0-9+/]{64}){2,}(?:\r?\n[A-Za-z0-9+/]{1,64}={0,2})?")
        .expect("headerless PEM shape compiles")
});

/// Whether a character belongs to a secret value (an AWS key or a token).
pub(super) fn is_value_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '/' | '+' | '=' | '_' | '-')
}
