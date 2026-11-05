//! Other secret formats: DSN userinfo, AWS pairs, authorization headers,
//! PEM/PuTTY keys and MySQL flags, the value shapes (command-line passwords,
//! Wi-Fi QR codes, presigned URLs, webhooks, password hashes), and the scan that
//! gathers every value.

use std::sync::LazyLock;

use regex::{Match, Regex};

use super::key_names::{SecretValue, MAX_VALUE_BYTES};
use super::key_values::{cli_values, k8s_values, key_values, line_spans, xml_values};
use super::key_view::KeyView;
use super::prose::{is_secret_shaped, is_value_word, prose_values, value_word};
use super::MAX_WRAP_BYTES;

/// A MySQL command word, or a `-u` or `--user` flag, which makes a glued `-p` a
/// password on the same line (K13). The command word is case-insensitive; the
/// flags are not.
static MYSQL_COMMAND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:\bmysql(?:dump)?\b|\bmariadb\b)|(?:^|\s)(?:-u|--user)")
        .expect("mysql command shape compiles")
});

/// A MySQL or MariaDB command word alone: only it makes a spaced `-p` value a
/// password.
static MYSQL_WORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bmysql(?:dump)?\b|\bmariadb\b").expect("mysql word shape compiles")
});

/// A `-p` flag glued to its value, with no space, as `mysql -pSECRET` takes it.
static MYSQL_FLAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)-p(\S+)").expect("mysql flag shape compiles"));

/// A `-p` flag, blanks, then a value (`mysql -u root -p Hunter22 appdb`). MySQL
/// reads a database name there, so only a value shaped like a secret counts.
static MYSQL_SPACED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)-p[ \t]+([^\s\-]\S*)").expect("mysql spaced flag shape compiles")
});

/// The MySQL-style values (K13): a glued `-p` value on a line that names a MySQL or
/// MariaDB command or a `-u` or `--user` flag, and a spaced one shaped like a
/// secret on a line that names the command. Each line is read on its own.
fn mysql_values(text: &str) -> Vec<SecretValue> {
    let mut values = Vec::new();
    for (line_start, line_stop) in line_spans(text) {
        let line = &text[line_start..line_stop];
        if !line.contains("-p") || !MYSQL_COMMAND_RE.is_match(line) {
            continue;
        }
        let spaced = MYSQL_WORD_RE
            .is_match(line)
            .then(|| MYSQL_SPACED_RE.captures_iter(line))
            .into_iter()
            .flatten()
            .map(|captures| (captures, true));
        let glued = MYSQL_FLAG_RE
            .captures_iter(line)
            .map(|captures| (captures, false));
        for (captures, spaced) in glued.chain(spaced) {
            let Some(value) = captures.get(1) else {
                continue;
            };
            let word = value_word(value.as_str());
            if is_value_word(word) && (!spaced || is_secret_shaped(word)) {
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
/// values that do not overlap a name-assigned value, which wins on overlap.
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
    // Clause tails are added after the overlap rule, never filtered by it: a tail
    // only widens what is masked.
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

/// Secrets found by the text around them, and key blocks the shapes above miss:
/// group 1 is the secret (the whole match for a shape without a group), kept when
/// it is at least as long as given. Nothing joins a wrapped line here.
#[rustfmt::skip]
const VALUE_SHAPES: &[(&str, usize)] = &[
    // Command lines: `sshpass -p`, `redis-cli -a`, `htpasswd -b file user password`
    // (`curl`, `docker login` and `htpasswd -n` are in `CHECKED_SHAPES`).
    (r#"\bsshpass\s+(?:-[a-zA-Z]\s+)*-p\s*["']?([^\s"']+)"#, 4),
    (r#"\bredis-cli\b[^\n]*?\s(?:-a|--pass)\s+["']?([^\s"']+)"#, 4),
    (r"\bhtpasswd\s+(?:-[a-zA-Z]+\s+)*?-[a-zA-Z]*b[a-zA-Z]*\s+(?:-[a-zA-Z]+\s+)*\S+\s+\S+\s+(\S+)", 4),
    // The password field of a Wi-Fi QR code (`WIFI:T:WPA;S:net;P:…;;`).
    (r"WIFI:(?:[A-Z]:(?:\\.|[^;\\\n])*;)*?P:((?:\\.|[^;\\\n])+)", 4),
    // Slack and Discord webhook paths.
    (r"hooks\.slack\.com/(?:services|workflows|triggers)/([A-Za-z0-9/_\-]+)", 20),
    (r"discord(?:app)?\.com/api/webhooks/([0-9]+/[A-Za-z0-9_\-]+)", 30),
    // Password hashes: bcrypt, Apache MD5, crypt(3) MD5/SHA, yescrypt, argon2, scrypt.
    (r"\$(?:2[abxy]?|apr1|1|5|6|7|y|argon2(?:id|i|d)|scrypt)\$[A-Za-z0-9./+=,$]+", 20),
    // A private-key block with four or five dashes, or the SSH2 ` ---- ` frame.
    (r"-{4,5} ?BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-{4,5}[\s\S]*?(?:-{4,5} ?END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-{4,5}|\z)", 1),
    // A headerless DER (`MII`) or OpenSSH (`openssh-key-v1`) body wrapped at 60 to
    // 76 columns.
    (r"(?m)^(?:MII|b3BlbnNzaC1rZXktdjE)[A-Za-z0-9+/]{40,73}(?:\r?\n[A-Za-z0-9+/]{60,76}){2,}(?:\r?\n[A-Za-z0-9+/]{1,76}={0,2})?", 1),
    // The response of a Digest credential, and a Discord webhook with an API version.
    (r#"(?i)Authorization["']?\s*[:=]\s*["']?Digest\s[^\n]*?\bresponse\s*=\s*["']?([0-9a-f]+)"#, 16),
    (r"discord(?:app)?\.com/api/v[0-9]+/webhooks/([0-9]+/[A-Za-z0-9_\-]+)", 30),
    // URL userinfo whose password holds `@`, or `/` (not a port before a path,
    // `localhost:5173/@vite`), and a scheme-less one in a `…_URL=` value with no
    // path (`DATABASE_URL=alice:pw@db.example.com`).
    (r#"(?i)\b[a-z][a-z0-9+.\-]*://([^\s/@:"'<>]*:[^\s/"'<>]*@[^\s/"'<>]*)@[a-z0-9\[]"#, 1),
    (r#"(?i)\b[a-z][a-z0-9+.\-]*://([^\s/@:"'<>]*:[^\s/@:"'<>]*[^\s/@:"'<>0-9][^\s/@:"'<>]*/[^\s@"'<>]*)@[a-z0-9\[]"#, 1),
    (r#"(?i)\b[a-z0-9_]*(?:url|uri|dsn)\s*=\s*["']?([^\s/@:"'<>]+:[^\s/@"'<>]+)@[a-z0-9]"#, 1),
];

/// What a value of a [`CHECKED_SHAPES`] shape must also be to count.
#[derive(Clone, Copy)]
enum Keep {
    Any,
    /// A header credential: after a scheme other than Bearer or Basic, no plain
    /// word that a sentence goes on from (`Token refreshes happen…`). It joins the
    /// lines that continue it.
    Credential,
    /// A `user:password`, not a URL (`curl -u https://…`).
    UserInfo,
    /// Not a registry host of plain words that ends a `docker login` line
    /// (`-p registry.example.com`; `-p s3cret.pass` stays a password).
    NotRegistry,
    /// Not a slug of plain words and numbers (`?sig=publish-2026-11-05-final`).
    NotSlug,
    /// An `htpasswd` line with `-n` and `-b`: no file, the password comes second.
    NoFile,
}

use Keep::{Any, Credential, NoFile, NotRegistry, NotSlug, UserInfo};

/// The value shapes whose value must also pass its [`Keep`].
#[rustfmt::skip]
const CHECKED_SHAPES: &[(&str, usize, Keep)] = &[
    // `Authorization` quoted (JSON, Python) or with another scheme, and the
    // credential quoted after the scheme.
    (r#"(?i)Authorization["']?\s*[:=]\s*["']?(?:Bearer|Basic|Token|ApiKey|Bot|SSWS|DeepL-Auth-Key)\s+([A-Za-z0-9._~+/=:\-]+)"#, 8, Credential),
    (r#"(?i)Authorization["']?\s*[:=]\s*["']?(?:Bearer|Basic|Token|ApiKey|Bot|SSWS|DeepL-Auth-Key)\s+["']([A-Za-z0-9._~+/=:\-]+)"#, 8, Credential),
    // `curl -u user:password`, `docker login -p`, `htpasswd -nb user password`.
    (r#"\bcurl\b[^\n]*?\s(?:-u|--user)(?:\s+|=)["']?([^\s"':]*:[^\s"']+)"#, 4, UserInfo),
    (r#"\bdocker\s+login\b[^\n]*?\s(?:-p|--password)(?:\s+|=)["']?([^\s"']+)"#, 4, NotRegistry),
    (r"\bhtpasswd(?:[ \t]+-[a-zA-Z]+(?:[ \t]+[0-9]{1,2})?)+[ \t]+[^\s\-]\S*[ \t]+(\S+)", 4, NoFile),
    // The signature of a presigned URL (Azure SAS, S3, Google Cloud Storage), and
    // the V2 `Signature` (S3, Google Cloud Storage, CloudFront, Alibaba OSS).
    (r"(?i)[?&](?:sig|x-amz-signature|x-goog-signature)=([^&\s#]+)", 16, NotSlug),
    (r"(?i)[?&]signature=([^&\s#]+)", 16, NotSlug),
];

static VALUE_SHAPES_RE: LazyLock<Vec<(Regex, usize, Keep)>> = LazyLock::new(|| {
    let unchecked = VALUE_SHAPES
        .iter()
        .map(|&(shape, min_len)| (shape, min_len, Any));
    unchecked
        .chain(CHECKED_SHAPES.iter().copied())
        .map(|(shape, min_len, keep)| {
            (
                Regex::new(shape).expect("value shape compiles"),
                min_len,
                keep,
            )
        })
        .collect()
});

/// A registry host, with an optional port (`registry.example.com`, `localhost:5000`).
static HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:localhost|(?:[a-z0-9\-]+\.)+[a-z]{2,})(?::[0-9]+)?$")
        .expect("host shape compiles")
});

/// The spans of the value shapes in `text`: each value long enough and kept by
/// its [`Keep`]; a header credential joins the lines that continue it.
pub(super) fn shape_values(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for (shape, min_len, keep) in VALUE_SHAPES_RE.iter() {
        for captures in shape.captures_iter(text) {
            let Some(whole) = captures.get(0) else {
                continue;
            };
            let value = captures.get(1).unwrap_or(whole);
            if value.len() >= *min_len && keeps(*keep, text, whole.start(), value) {
                let joined = matches!(keep, Credential).then(|| join_lines(text, value.end()));
                spans.push((value.start(), joined.unwrap_or(value.end())));
            }
        }
    }
    spans
}

/// Whether `value`, matched from `start`, passes `keep`.
fn keeps(keep: Keep, text: &str, start: usize, value: Match) -> bool {
    let (head, found) = (&text[start..value.start()], value.as_str());
    match keep {
        Any => true,
        // The scheme is the last word before the value.
        Credential => {
            let mut words = head.split(|ch: char| ch.is_whitespace() || "\"':=".contains(ch));
            let scheme = words.rfind(|word| !word.is_empty()).unwrap_or("");
            let line = text[value.end()..].split('\n').next().unwrap_or_default();
            let next = line
                .strip_prefix([' ', '\t'])
                .and_then(|rest| rest.split_whitespace().next());
            let sentence = next.is_some_and(is_word);
            ["bearer", "basic"]
                .iter()
                .any(|name| scheme.eq_ignore_ascii_case(name))
                || !is_word(found)
                || !sentence
        }
        UserInfo => !found
            .split_once(':')
            .is_some_and(|(_, rest)| rest.starts_with("//")),
        NotRegistry => {
            let rest = text[value.end()..].split('\n').next().unwrap_or_default();
            let host = found.split(':').next().unwrap_or_default();
            !(HOST_RE.is_match(found) && is_slug(host))
                || !rest.trim_start_matches(['"', '\'']).trim().is_empty()
        }
        NotSlug => !is_slug(found),
        NoFile => {
            let flags: String = head
                .split_whitespace()
                .filter(|word| word.starts_with('-'))
                .collect();
            flags.contains('n') && flags.contains('b')
        }
    }
}

/// Whether a value is a plain word, or plain words joined by `-` (`re-issued`):
/// letters only (at most 16 a part), no capital after the first, its closing
/// punctuation aside.
fn is_word(value: &str) -> bool {
    let word = value.trim_end_matches(['.', ',', ';', ':', '!', '?']);
    word.split('-')
        .all(|part| (1..=16).contains(&part.chars().count()) && !is_secret_shaped(part))
}

/// Whether a value is plain words and numbers of at most 16 joined by `-`, `_`
/// or `.` (`your-signature-here`, `publish-2026-11-05`, `registry.example.com`).
fn is_slug(value: &str) -> bool {
    value.split(['-', '_', '.']).all(|part| {
        is_word(part)
            || ((1..=16).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// The end of a header credential with the lines that continue it: a next line
/// that holds only credential characters and is no plain word joins, so a token
/// cut by a fixed-width wrap is read whole, and `Thanks`, a sentence or a
/// `Name: value` header line is not. Bounded by [`MAX_WRAP_BYTES`].
fn join_lines(text: &str, from: usize) -> usize {
    let mut limit = text.len().min(from + MAX_WRAP_BYTES);
    while !text.is_char_boundary(limit) {
        limit -= 1;
    }
    let window = &text[..limit];
    let mut end = from;
    loop {
        let rest = window[end..].trim_start_matches([' ', '\t', '\r']);
        let Some(line) = rest.strip_prefix('\n') else {
            return end;
        };
        let body = line.trim_start_matches([' ', '\t']);
        let run = body
            .find(|ch: char| !is_credential_char(ch))
            .unwrap_or(body.len());
        let tail = body[run..].trim_start_matches([' ', '\t', '\r']);
        if run == 0 || !(tail.is_empty() || tail.starts_with('\n')) || is_word(&body[..run]) {
            return end;
        }
        end = limit - body.len() + run;
    }
}

/// Whether a character belongs to a header credential (base64, base64url, hex).
fn is_credential_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || "._~+/=-".contains(ch)
}

/// Whether a character belongs to a secret value (an AWS key or a token).
pub(super) fn is_value_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '/' | '+' | '=' | '_' | '-')
}
