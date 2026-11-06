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
    // Command lines (`curl -u` is in `CHECKED_SHAPES`): `docker login -p`, `sshpass -p`,
    // `redis-cli -a`, `htpasswd -b file user password`.
    (r#"\bdocker\s+login\b[^\n]*?\s(?:-p|--password)(?:\s+|=)["']?([^\s"']+)"#, 4),
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
    // An Okta token after `SSWS` and words that name it (`SSWS header: <token>`,
    // `SSWS token` then the token on the next line).
    (r#"\bSSWS(?:[ \t]+(?i:authentication|authorization|credentials?|headers?|prefix|scheme|tokens?|auth)\b)+[ \t]*[:=]?[ \t]*(?:\r?\n[ \t]*)?["']?([A-Za-z0-9._~+/=\-]+)"#, 20),
    // URL userinfo whose password holds `@`, or `/` (not a port before a path,
    // `localhost:5173/@vite`), and a scheme-less one in a `…_URL=` value with no
    // path (`DATABASE_URL=alice:pw@db.example.com`).
    (r#"(?i)\b[a-z][a-z0-9+.\-]*://([^\s/@:"'<>]*:[^\s/"'<>]*@[^\s/"'<>]*)@[a-z0-9\[]"#, 1),
    (r#"(?i)\b[a-z][a-z0-9+.\-]*://([^\s/@:"'<>]*:[^\s/@:"'<>]*[^\s/@:"'<>0-9][^\s/@:"'<>]*/[^\s@"'<>]*)@[a-z0-9\[]"#, 1),
    (r#"(?i)\b[a-z0-9_]*(?:url|uri|dsn)\s*=\s*["']?([^\s/@:"'<>]+:[^\s/@"'<>]+)@[a-z0-9]"#, 1),    // `curl -u user:password`, a link-shaped value too: the whole value is hidden,
    // as before #95 (the #95 r2 seals found credentials inside such links).
    (r#"\bcurl\b[^\n]*?\s(?:-u|--user)(?:\s+|=)["']?([^\s"':]*:[^\s"']+)"#, 4),
];

/// What a value of a [`CHECKED_SHAPES`] shape must also be to count.
#[derive(Clone, Copy)]
enum Keep {
    /// A header credential, not a status word that a plain word follows (`Token
    /// refreshes happen…`). It joins the lines that continue it.
    Credential,
    /// Not a placeholder the docs write for a signature.
    NotPlaceholder,
    /// An `htpasswd` line with `-n` and `-b` or `-B`: no file, the
    /// password is second.
    NoFile,
    /// An `htpasswd` line with `-b` or `-B` and no `-n` or `-i`: the password follows
    /// a file and a user.
    WithFile,
    /// A [`Credential`](Keep::Credential) that, after a scheme not written `SSWS`
    /// in capitals (`ssws`, `Ssws`), is also shaped like a secret: `ssws
    /// implementation` is prose.
    CaseFreeCredential,
    /// An Okta token, which holds a digit (`00…`): a long identifier is not one.
    OktaToken,
    /// As [`NoFile`](Keep::NoFile), and a quoted user takes only a quoted or
    /// secret-shaped password (`"alice smith" then` is prose).
    NoFileQuoting,
    /// As [`WithFile`](Keep::WithFile), with the quoted-user rule of
    /// [`NoFileQuoting`](Keep::NoFileQuoting).
    WithFileQuoting,
    /// A value after `SSWS:` in any case: an [`OktaToken`](Keep::OktaToken), or a
    /// value with no dot that is not a listed word.
    ColonToken,
}

use Keep::{
    CaseFreeCredential, ColonToken, Credential, NoFile, NoFileQuoting, NotPlaceholder, OktaToken,
    WithFile, WithFileQuoting,
};

/// The value shapes whose value must also pass its [`Keep`].
#[rustfmt::skip]
const CHECKED_SHAPES: &[(&str, usize, Keep)] = &[
    // `Authorization` quoted (JSON, Python) or with another scheme, the credential
    // quoted after the scheme, and an Okta `SSWS` credential on its own.
    (r#"(?i)Authorization["']?\s*[:=]\s*["']?(?:Bearer|Basic|Token|ApiKey|Bot|SSWS|DeepL-Auth-Key)\s+([A-Za-z0-9._~+/=:\-]+)"#, 8, Credential),
    (r#"(?i)Authorization["']?\s*[:=]\s*["']?(?:Bearer|Basic|Token|ApiKey|Bot|SSWS|DeepL-Auth-Key)\s+["']([A-Za-z0-9._~+/=:\-]+)"#, 8, Credential),
    (r#"\bSSWS[ \t]+["']?([A-Za-z0-9._~+/=:\-]+)"#, 8, Credential),
    // KV02-SECRETS-4, beside the shapes above: `ssws` in any case and a no-break,
    // narrow no-break or thin space for a blank; after the words that name the
    // token, up to three line breaks (blank lines) before it; and `SSWS: <token>`.
    (r#"(?i:\bSSWS)[ \t\u{A0}\u{2009}\u{202F}]+["']?([A-Za-z0-9._~+/=:\-]+)"#, 8, CaseFreeCredential),
    (r#"(?i:\bSSWS)(?:[ \t\u{A0}\u{2009}\u{202F}]+(?i:authentication|authorization|credentials?|headers?|prefix|scheme|tokens?|auth)\b)+[ \t\u{A0}\u{2009}\u{202F}]*[:=]?(?:[ \t\u{A0}\u{2009}\u{202F}]*\r?\n){0,3}[ \t\u{A0}\u{2009}\u{202F}]*["']?([A-Za-z0-9._~+/=\-]+)"#, 20, OktaToken),
    (r#"(?i:\bSSWS)[ \t\u{A0}\u{2009}\u{202F}]*:(?:[ \t\u{A0}\u{2009}\u{202F}]*\r?\n){0,3}[ \t\u{A0}\u{2009}\u{202F}]*["']?([A-Za-z0-9._~+/=\-]+)"#, 20, OktaToken),
    // KV02-SECRETS-5, beside the two above: up to seven line breaks, and an `SSWS:`
    // value of 8 characters or more, the bare rule's minimum.
    (r#"(?i:\bSSWS)(?:[ \t\u{A0}\u{2009}\u{202F}]+(?i:authentication|authorization|credentials?|headers?|prefix|scheme|tokens?|auth)\b)+[ \t\u{A0}\u{2009}\u{202F}]*[:=]?(?:[ \t\u{A0}\u{2009}\u{202F}]*\r?\n){0,7}[ \t\u{A0}\u{2009}\u{202F}]*["']?([A-Za-z0-9._~+/=\-]+)"#, 20, OktaToken),
    (r#"(?i:\bSSWS)[ \t\u{A0}\u{2009}\u{202F}]*:(?:[ \t\u{A0}\u{2009}\u{202F}]*\r?\n){0,7}[ \t\u{A0}\u{2009}\u{202F}]*["']?([A-Za-z0-9._~+/=\-]+)"#, 8, ColonToken),
    // `htpasswd -nb user password`.
    (r"\bhtpasswd(?:[ \t]+-[a-zA-Z]+(?:[ \t]+[0-9]{1,2})?)+[ \t]+[^\s\-]\S*[ \t]+(\S+)", 4, NoFile),
    // `htpasswd -nb user password` and `htpasswd -b file user password`: flags
    // with digits (`-2`, `-nb5`) in any order, `--`, a numeric value (`-C 10`,
    // `-r 5000`), a quoted password whole.
    (r#"\bhtpasswd(?:[ \t]+(?:-[A-Za-z0-9]+|--)(?:[ \t]+[0-9]{1,6})?)+[ \t]+[^\s\-]\S*[ \t]+("[^"\n]*"\S*|'[^'\n]*'\S*|\S+)"#, 4, NoFile),
    (r#"\bhtpasswd(?:[ \t]+(?:-[A-Za-z0-9]+|--)(?:[ \t]+[0-9]{1,6})?)+[ \t]+[^\s\-]\S*[ \t]+[^\s\-]\S*[ \t]+("[^"\n]*"\S*|'[^'\n]*'\S*|\S+)"#, 4, WithFile),
    // KV02-SECRETS-4, beside the two above: a numeric value of up to nine digits
    // (`-r 1000000`), a quoted file or user (`"/srv/my site/.htpasswd"`), and a
    // quoted password with an escaped quote inside (`"pa\" ss"`, `'it'\''s'`). A
    // quoted user takes only a quoted or secret-shaped password.
    (r#"\bhtpasswd(?:[ \t]+(?:-[A-Za-z0-9]+|--)(?:[ \t]+[0-9]{1,9})?)+[ \t]+(?:"[^"\n]*"\S*|'[^'\n]*'\S*|[^\s\-]\S*)[ \t]+("(?:\\.|[^"\\\n])*"\S*|'[^'\n]*'(?:\\''[^'\n]*')*\S*|"[^"\n]*"\S*|'[^'\n]*'\S*|\S+)"#, 4, NoFileQuoting),
    (r#"\bhtpasswd(?:[ \t]+(?:-[A-Za-z0-9]+|--)(?:[ \t]+[0-9]{1,9})?)+[ \t]+(?:"[^"\n]*"\S*|'[^'\n]*'\S*|[^\s\-]\S*)[ \t]+(?:"[^"\n]*"\S*|'[^'\n]*'\S*|[^\s\-]\S*)[ \t]+("(?:\\.|[^"\\\n])*"\S*|'[^'\n]*'(?:\\''[^'\n]*')*\S*|"[^"\n]*"\S*|'[^'\n]*'\S*|\S+)"#, 4, WithFileQuoting),
    // KV02-SECRETS-6, beside the two above: the password on the line after a `\`
    // line continuation.
    (r#"\bhtpasswd(?:[ \t]+(?:-[A-Za-z0-9]+|--)(?:[ \t]+[0-9]{1,9})?)+[ \t]+(?:"[^"\n]*"\S*|'[^'\n]*'\S*|[^\s\-]\S*)[ \t]*\\\r?\n[ \t]*("(?:\\.|[^"\\\n])*"\S*|'[^'\n]*'(?:\\''[^'\n]*')*\S*|"[^"\n]*"\S*|'[^'\n]*'\S*|\S+)"#, 4, NoFileQuoting),
    (r#"\bhtpasswd(?:[ \t]+(?:-[A-Za-z0-9]+|--)(?:[ \t]+[0-9]{1,9})?)+[ \t]+(?:"[^"\n]*"\S*|'[^'\n]*'\S*|[^\s\-]\S*)[ \t]+(?:"[^"\n]*"\S*|'[^'\n]*'\S*|[^\s\-]\S*)[ \t]*\\\r?\n[ \t]*("(?:\\.|[^"\\\n])*"\S*|'[^'\n]*'(?:\\''[^'\n]*')*\S*|"[^"\n]*"\S*|'[^'\n]*'\S*|\S+)"#, 4, WithFileQuoting),
    // The signature of a presigned URL (Azure SAS, S3, Google Cloud Storage), and
    // the V2 `Signature` (S3, Google Cloud Storage, CloudFront, Alibaba OSS).
    (r"(?i)[?&](?:sig|x-amz-signature|x-goog-signature)=([^&\s#]+)", 16, NotPlaceholder),
    (r"(?i)[?&]signature=([^&\s#]+)", 16, NotPlaceholder),
];

pub(super) static VALUE_SHAPES_RE: LazyLock<Vec<(Regex, usize)>> = LazyLock::new(|| {
    VALUE_SHAPES
        .iter()
        .map(|(shape, min_len)| (Regex::new(shape).expect("value shape compiles"), *min_len))
        .collect()
});

static CHECKED_SHAPES_RE: LazyLock<Vec<(Regex, usize, Keep)>> = LazyLock::new(|| {
    let compile =
        |&(shape, min_len, keep)| (Regex::new(shape).expect("shape compiles"), min_len, keep);
    CHECKED_SHAPES.iter().map(compile).collect()
});

/// The spans of the [`CHECKED_SHAPES`] in `text`: each value long enough and kept
/// by its [`Keep`]; a header credential joins the lines that continue it.
pub(super) fn shape_values(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for (shape, min_len, keep) in CHECKED_SHAPES_RE.iter() {
        for captures in shape.captures_iter(text) {
            let Some(value) = captures.get(1) else {
                continue;
            };
            let start = captures.get(0).map_or(0, |whole| whole.start());
            if value.len() >= *min_len && keeps(*keep, text, start, value) {
                let joined = matches!(keep, Credential | CaseFreeCredential)
                    .then(|| join_lines(text, value.end()));
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
        Credential => {
            let line = text[value.end()..].split('\n').next().unwrap_or_default();
            let next = line
                .strip_prefix([' ', '\t'])
                .and_then(|rest| rest.split_whitespace().next());
            // After `SSWS`, a listed word with no token after it is prose (`the
            // SSWS authentication header`), not an Okta token.
            let ssws_word =
                after_ssws(head) && is_ssws_word(found) && !token_follows(text, value.end(), next);
            !ssws_word
                && (!is_status_word(found) || !next.is_some_and(|word| !is_secret_shaped(word)))
        }
        CaseFreeCredential => {
            let blank = |ch: char| ch.is_whitespace() || ch == '"' || ch == '\'';
            let capitals = head.trim_end_matches(blank).ends_with("SSWS");
            keeps(Credential, text, start, value)
                && (capitals || is_secret_shaped(found) || found.len() == OKTA_TOKEN_LEN)
        }
        OktaToken => {
            // A sentence's full stop after the token is not part of it; a value of
            // the token's length with the stop counts too, as before the stop was
            // dropped.
            let bare = found.strip_suffix('.').unwrap_or(found);
            bare.bytes().any(|b| b.is_ascii_digit())
                || bare.len() == OKTA_TOKEN_LEN
                || found.len() == OKTA_TOKEN_LEN
        }
        ColonToken => {
            // The colon makes the value an assignment in any case; a host name
            // (`login.example.com`) holds a dot, which no Okta token does.
            let found = found.strip_suffix('.').unwrap_or(found);
            keeps(OktaToken, text, start, value) || (!is_ssws_word(found) && !found.contains('.'))
        }
        NotPlaceholder => !is_placeholder(found),
        NoFile => {
            let flags = htpasswd_flags(head);
            flags.contains('n') && flags.contains(['b', 'B'])
        }
        WithFile => {
            let flags = htpasswd_flags(head);
            !flags.contains(['n', 'i']) && flags.contains(['b', 'B'])
        }
        NoFileQuoting => {
            keeps(NoFile, text, start, value) && fits_user(head, found, rest(text, value))
        }
        WithFileQuoting => {
            keeps(WithFile, text, start, value) && fits_user(head, found, rest(text, value))
        }
    }
}

/// The length of an Okta API token: one of 42 characters is a token even with no
/// digit in it.
const OKTA_TOKEN_LEN: usize = 42;

/// The rest of the line after `value`.
fn rest<'t>(text: &'t str, value: Match) -> &'t str {
    text[value.end()..].split('\n').next().unwrap_or_default()
}

/// Whether an `htpasswd` password fits its user: a quoted user (`"alice smith"`)
/// takes a quoted or secret-shaped password, or the last word of the command (the
/// line ends, or a shell operator, a redirect, a `#` comment or a `\` follows),
/// so `"alice smith" then restart` is prose.
fn fits_user(head: &str, found: &str, rest: &str) -> bool {
    let quote = ['"', '\''];
    let after = rest.trim_start();
    // A redirect with a file descriptor, a blank before `>` too (`2 >file`).
    let fd = after.trim_start_matches(|ch: char| ch.is_ascii_digit());
    let redirect = fd.len() < after.len() && fd.trim_start().starts_with(['<', '>']);
    let last = after.is_empty()
        || redirect
        || after.starts_with(['&', '|', ';', '>', '<', ')', '`', '#', '\\']);
    // A `\` line continuation before the password is a blank between the two.
    let head = head.trim_end_matches([' ', '\t']);
    let head = head.strip_suffix('\n').map_or(head, |line| {
        let line = line.strip_suffix('\r').unwrap_or(line);
        line.strip_suffix('\\').unwrap_or(line)
    });
    !head.trim_end().ends_with(quote) || found.starts_with(quote) || is_secret_shaped(found) || last
}

/// Whether a token follows a header value that ends at `end`: the next word on
/// its line, or the first word of the next line, is shaped like a secret, or the
/// next line would join the value as a wrapped credential.
fn token_follows(text: &str, end: usize, next: Option<&str>) -> bool {
    let shaped = |word: &str| is_secret_shaped(word.trim_end_matches(CLOSING));
    let below = text[end..]
        .split('\n')
        .nth(1)
        .and_then(|line| line.split_whitespace().next());
    next.is_some_and(shaped) || below.is_some_and(shaped) || join_lines(text, end) > end
}

/// The flag words of an `htpasswd` line before its value, joined.
fn htpasswd_flags(head: &str) -> String {
    head.split_whitespace()
        .filter(|word| word.starts_with('-'))
        .collect()
}

/// The punctuation that may close a word in prose.
const CLOSING: [char; 7] = ['.', ',', ';', ':', '!', '?', ')'];

/// Whether `head`, the match up to a header credential, ends with the Okta `SSWS`
/// scheme (an opening quote and blanks aside), case aside.
fn after_ssws(head: &str) -> bool {
    let scheme = head.trim_end_matches(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'');
    scheme
        .get(scheme.len().saturating_sub(4)..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case("SSWS"))
}

/// Ordinary words that follow `SSWS` in prose and are never an Okta token (`the
/// SSWS authentication header`); a [`STATUS_WORDS`] word is one too.
const SSWS_WORDS: &[&str] = &[
    "auth",
    "authentication",
    "authorization",
    "credential",
    "credentials",
    "header",
    "headers",
    "prefix",
    "scheme",
    "token",
    "tokens",
];

/// Whether a word, its closing punctuation aside, is one of [`SSWS_WORDS`] or of
/// [`STATUS_WORDS`].
fn is_ssws_word(word: &str) -> bool {
    let bare = word.trim_end_matches(CLOSING);
    is_status_word(word)
        || SSWS_WORDS
            .iter()
            .any(|ordinary| ordinary.eq_ignore_ascii_case(bare))
}

/// Ordinary verbs and adjectives that say what happens to a credential and are never
/// one (`Authorization: Token refreshes happen every hour`).
const STATUS_WORDS: &[&str] = &[
    "cleared",
    "expired",
    "missing",
    "needed",
    "refresh",
    "refreshes",
    "required",
    "revoked",
    "rotated",
];

/// Whether a word, its closing punctuation aside, is one of [`STATUS_WORDS`].
fn is_status_word(word: &str) -> bool {
    let word = word.trim_end_matches(['.', ',', ';', ':', '!', '?']);
    STATUS_WORDS
        .iter()
        .any(|status| status.eq_ignore_ascii_case(word))
}

/// Whether a value is a literal the docs write in place of a signature, case aside,
/// or a run of `x`, `*` or `.` alone (`xxxxxxxxxxxxxxxx`).
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "your-signature-here" | "signature-goes-here" | "<your-signature>"
    ) || value.bytes().all(|b| b"xX*.".contains(&b))
}

/// The end of a header credential with the lines that continue it: a next line
/// that holds only credential characters joins, so a token cut by a fixed-width
/// wrap is read whole, and a sentence or a `Name: value` header line is not.
/// Bounded by [`MAX_WRAP_BYTES`].
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
        if run == 0 || !(tail.is_empty() || tail.starts_with('\n')) {
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
