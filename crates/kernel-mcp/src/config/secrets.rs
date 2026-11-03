//! Secret detection in values, keys and command-line arguments.

use super::echo::percent_decoded;
use super::policy::long_flag;

/// Whether a value looks like a credential: a known token prefix, a
/// `token=`/`api-key`/`password` style flag or query parameter, a JWT, an AWS
/// key id, or userinfo embedded in a URL. Such values belong in
/// `~/.auxesis/.env`, never in an argument, URL or config file.
///
/// The value is percent-decoded first (item 5): `token%3Dabc` is the same
/// request as `token=abc`, so it must be refused too.
pub fn looks_like_secret(value: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "--api-key",
        "--api_key",
        "--apikey",
        "--access-token",
        "--access_token",
        "--auth-token",
        "--auth_token",
        "--token",
        "--private-key",
        "--private_key",
        "--password",
        "--passwd",
        "--client-secret",
        "--client_secret",
        "--secret",
        "?token=",
        "&token=",
        "token=",
        "api_key=",
        "api-key=",
        "apikey=",
        "?secret=",
        "&secret=",
        "secret=",
        "?access_key=",
        "&access_key=",
        "access_key=",
        "x-api-key",
        "authorization: bearer",
        "authorization:bearer",
        "access_token=",
        "password=",
        "passwd=",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "sk_live_",
        "sk_test_",
        "bearer ",
    ];
    let value = &percent_decoded(value);
    let lower = value.to_ascii_lowercase();
    if NEEDLES.iter().any(|needle| lower.contains(needle)) {
        return true;
    }
    // `?key=` / `&key=` / a leading `key=`, so `monkey=` is not a false hit.
    let key_needle = lower.starts_with("key=")
        || lower.contains("?key=")
        || lower.contains("&key=")
        || lower.contains("?apikey=")
        || lower.contains("&apikey=");
    if key_needle {
        return true;
    }
    // `sk-…` keys: a word-initial `sk-` followed by a plausible key body, so
    // ordinary words such as `task-list` or `desk-top` do not trip the check.
    let sk = lower.match_indices("sk-").any(|(index, _)| {
        let word_start = index == 0 || !lower.as_bytes()[index - 1].is_ascii_alphanumeric();
        let body = lower.as_bytes()[index + 3..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_' || **b == b'-')
            .count();
        word_start && body >= 8
    });
    if sk {
        return true;
    }
    // AWS access-key id: `AKIA` + 16 uppercase alphanumerics. Every occurrence
    // is checked, so a decoy prefix cannot hide a real key later in the string.
    if value.match_indices("AKIA").any(|(index, _)| {
        value[index + 4..]
            .bytes()
            .take_while(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            .count()
            >= 16
    }) {
        return true;
    }
    // JWT: a word-initial `eyJ` header, two `.`-separated segments, long enough.
    if lower.match_indices("eyj").any(|(index, _)| {
        let word_start = index == 0 || !lower.as_bytes()[index - 1].is_ascii_alphanumeric();
        word_start && value[index..].len() >= 24 && value[index..].matches('.').count() >= 2
    }) {
        return true;
    }
    has_userinfo(value) || structured_secret_pair(value)
}

/// Whether `key` names a secret: the key is normalised (`-`/`.` folded to `_`,
/// case ignored) and then matched **part by part** (item 5), so `API-KEY`,
/// `api_key` and `X-Api-Key` all count while `monkey`, `--author=` and
/// `tokenizer` do not.
///
/// A needle matches only when it is one whole `_`-separated part of the key,
/// or the entire key. That is what keeps `author` from tripping `auth` and
/// `tokenizer` from tripping `token`; `api_key`/`access_key`/`private_key`
/// still match through their `key` part.
fn key_looks_like_secret(key: &str) -> bool {
    const KEY_NEEDLES: &[&str] = &[
        "token", "apikey", "password", "passwd", "secret", "auth", "key", "bearer",
    ];
    let normalized = key
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase()
        .replace(['-', '.'], "_");
    normalized
        .split('_')
        .any(|part| !part.is_empty() && KEY_NEEDLES.contains(&part))
}

/// Whether `value` carries a structured `key<sep>value` pair whose key names a
/// secret (item 5): JSON `"key":"value"`, `key: value`, `key=value` and
/// `key:value`. A non-empty value is enough to refuse.
fn structured_secret_pair(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b':' && *byte != b'=' {
            continue;
        }
        // Walk back over the key, skipping spaces and a closing quote.
        let mut end = index;
        while end > 0 && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        if end > 0 && matches!(bytes[end - 1], b'"' | b'\'') {
            end -= 1;
        }
        let mut start = end;
        while start > 0
            && (bytes[start - 1].is_ascii_alphanumeric()
                || matches!(bytes[start - 1], b'_' | b'-' | b'.'))
        {
            start -= 1;
        }
        if start == end || !key_looks_like_secret(&value[start..end]) {
            continue;
        }
        // Walk forward over the value, skipping spaces and an opening quote.
        let mut value_start = index + 1;
        while value_start < bytes.len() && matches!(bytes[value_start], b' ' | b'\t') {
            value_start += 1;
        }
        if value_start < bytes.len() && matches!(bytes[value_start], b'"' | b'\'') {
            value_start += 1;
        }
        if value_start < bytes.len()
            && !matches!(bytes[value_start], b'"' | b'\'' | b']' | b'}' | b',')
        {
            return true;
        }
    }
    false
}

/// Whether a value embeds `user:password@host` userinfo.
fn has_userinfo(value: &str) -> bool {
    let authority = match value.find("://") {
        Some(scheme) => &value[scheme + 3..],
        None => {
            // A bare `user:pass@host` argument.
            let Some(at) = value.find('@') else {
                return false;
            };
            let before = &value[..at];
            return !before.contains('/') && before.contains(':') && !before.contains(' ');
        }
    };
    let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    let userinfo_host = &authority[..end];
    let Some(at) = userinfo_host.find('@') else {
        return false;
    };
    userinfo_host[..at].contains(':')
}

/// Whether a value looks like a secret for the split flag forms: a known token
/// prefix, or at least 12 characters mixing letters and digits.
fn value_is_secret_like(value: &str) -> bool {
    if looks_like_secret(value) {
        return true;
    }
    let has_letter = value.bytes().any(|byte| byte.is_ascii_alphabetic());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    value.len() >= 12 && has_letter && has_digit
}

/// Whether the value of a `--key`/`-k` flag is secret-looking.
///
/// Item 6: an all-letters value of 12 characters or more is a plausible
/// passphrase even without a digit, so it is refused alongside the mixed
/// letter/digit form.
fn key_value_refused(value: &str) -> bool {
    if value_is_secret_like(value) {
        return true;
    }
    value.len() >= 12 && value.bytes().all(|byte| byte.is_ascii_alphabetic())
}

/// Whether the flag at `args[index]` takes a **secret value** in the next token
/// or inline, including the split spellings (items 5/10): `--access-token`,
/// `--auth-token`, `--api_key`/`--api-key`, `--private-key`, `--token`,
/// `--password`, `--client-secret`, `--secret`, `--key`/`-k`, `-u user:pass`,
/// `X-API-Key:` and `Authorization: Bearer` across two tokens, plus the
/// attached `-k<value>` form.
pub(super) fn secret_pair_refused(args: &[String], index: usize) -> bool {
    let arg = args[index].as_str();
    // Attached short form: `-k0123456789ab` / `-k=0123456789ab`.
    if let Some(rest) = arg.strip_prefix("-k") {
        if !arg.starts_with("--") {
            let value = rest.strip_prefix('=').unwrap_or(rest);
            if !value.is_empty() && key_value_refused(value) {
                return true;
            }
        }
    }
    let (name, inline) = long_flag(arg)
        .map(|(name, value)| (name.to_ascii_lowercase(), value.map(str::to_owned)))
        .unwrap_or_else(|| (arg.to_ascii_lowercase(), None));
    let next = args.get(index + 1).map(String::as_str);
    let next_lower = next.map(str::to_ascii_lowercase);
    let value = inline.as_deref().or(next);
    match name.as_str() {
        // `-K` lowercases to `-k`, so one arm covers both.
        "-k" | "--key" => value.is_some_and(key_value_refused),
        "--client-secret" | "--secret" => value.is_some_and(|value| !value.is_empty()),
        "--access-token" | "--auth-token" | "--api-key" | "--api_key" | "--apikey"
        | "--private-key" | "--token" | "--password" | "--passwd" => {
            value.is_some_and(value_is_secret_like)
        }
        "-u" | "--user" => value.is_some_and(|value| value.contains(':')),
        "-h" | "--header" => value.is_some_and(|value| {
            let lower = value.to_ascii_lowercase();
            (lower.contains("authorization:") || lower.contains("x-api-key"))
                && (lower.contains("bearer") || lower.contains("x-api-key"))
        }),
        _ => {
            let next_is_value = next_lower
                .as_deref()
                .is_some_and(|value| !value.is_empty() && !value.starts_with('-'));
            let auth_then_bearer = (name.ends_with("authorization:") || name == "authorization:")
                && next_lower
                    .as_deref()
                    .is_some_and(|value| value.starts_with("bearer"));
            let api_key_then_value =
                (name.ends_with("x-api-key:") || name == "x-api-key:") && next_is_value;
            auth_then_bearer || api_key_then_value
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_util::shared::args;
    use crate::config::{evaluate_stdio_policy, McpConfig};

    #[test]
    fn secret_looking_arguments_and_urls_are_refused() {
        for value in [
            "--api-key",
            "--api_key",
            "--access-token",
            "--auth-token",
            "--private-key",
            "--token=abc",
            "--apikey=abc",
            "--password=hunter2",
            "--access-token=abcdefgh1234",
            "--auth-token=abcdefgh1234",
            "--api_key=abcdefgh1234",
            "--private-key=abcdefgh1234",
            "https://example.test/mcp?token=abc",
            "https://example.test/mcp?apikey=abc",
            "https://example.test/mcp?key=abc",
            "sk-abcdefgh1234",
            "sk_live_abcdefgh1234",
            "AKIAIOSFODNN7EXAMPLE",
            // Item 6: a decoy `AKIA` prefix must not hide a later real key.
            "AKIANOTENOUGH AKIAIOSFODNN7EXAMPLE",
            "xoxb-short",
            "xoxp-short",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "https://user:password@example.test/mcp",
            "user:password@example.test",
            // Item 5: structured key/value pairs, all four spellings.
            r#"{"token":"abc"}"#,
            r#"{"api_key": "abc"}"#,
            "api_key: abc",
            "api_key:abc",
            "client_secret=abc",
            "--flag=token:abc",
            "auth=1",
            "X-Bearer:abc",
        ] {
            assert!(looks_like_secret(value), "{value} must look secret");
        }
        for value in [
            "task-list",
            "desk-top",
            "https://example.test/mcp",
            "monkey=banana",
            "AKIANOTENOUGH",
            // An ordinary structured pair whose key is not secret-looking.
            r#"{"note":"hello"}"#,
            "name: value",
            // Item 5: `auth`/`token`/`key` match whole `_`/`-`-separated parts
            // only, so these are not false positives.
            "--author=Jane Doe",
            "tokenizer=gpt2",
            "keynote=1",
            "hockey-stick=1",
        ] {
            assert!(!looks_like_secret(value), "{value} must not look secret");
        }
        // Item 5: an encoded separator is decoded before the check, so
        // `token%3Dabc` is the same request as `token=abc`.
        for value in [
            "token%3Dabc",
            "api_key%3Aabc",
            "%22token%22%3A%22abc%22",
            "https://example.test/mcp%3Ftoken%3Dabc",
        ] {
            assert!(
                looks_like_secret(value),
                "{value} must look secret after percent-decoding"
            );
        }
        assert!(!looks_like_secret("percent%2Fonly"));
        assert!(
            evaluate_stdio_policy("s", "/usr/local/bin/tool", &args(&["--token=abc"]), false)
                .is_err()
        );
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["-k", "0123456789abcdef"]),
            false
        )
        .is_err());
        let parsed = McpConfig::parse(
            "t",
            "[[server]]\nid = \"a\"\ntransport = \"http\"\nurl = \"https://example.test/mcp?token=abc\"\n",
        )
        .unwrap();
        assert!(parsed.server[0].check().is_err());
    }

    #[test]
    fn secret_parameter_names_cover_split_args_and_the_lowered_key_threshold() {
        for value in [
            "--client-secret",
            "--client-secret=abc",
            "--secret=abc",
            "--access-token=abcdefgh1234",
            "--auth-token=abcdefgh1234",
            "--api_key=abcdefgh1234",
            "--private-key=abcdefgh1234",
            "https://example.test/mcp?secret=abc",
            "https://example.test/mcp?access_key=abc",
            "X-API-Key: abc",
            "Authorization: Bearer abc",
            "authorization:bearer abc",
        ] {
            assert!(looks_like_secret(value), "{value} must look secret");
        }
        for argv in [
            vec!["--client-secret="],
            vec!["--client-secret", "abc"],
            vec!["--secret", "abc"],
            vec!["-u", "user:pass"],
            vec!["--user", "user:pass"],
            vec!["-H", "X-API-Key: abc"],
            vec!["Authorization:", "Bearer", "abc"],
            // Item 10: the `--key` value threshold is lowered to 12 characters.
            vec!["--key", "0123456789ab"],
            vec!["-k", "0123456789ab"],
            // Item 6: a letters-only value of 12+ characters is a plausible
            // passphrase even without a digit.
            vec!["--key", "abcdefghijkl"],
            vec!["-k", "abcdefghijkl"],
            // Item 5: a structured JSON/colon pair inside one argument.
            vec![r#"{"token":"abc"}"#],
            vec!["api_key:abc"],
            // Item 5: the split spellings all take a secret value.
            vec!["--access-token", "abcdefgh1234"],
            vec!["--auth-token", "abcdefgh1234"],
            vec!["--api_key", "abcdefgh1234"],
            vec!["--api-key", "abcdefgh1234"],
            vec!["--private-key", "abcdefgh1234"],
            vec!["--password", "abcdefgh1234"],
            vec!["--token", "abcdefgh1234"],
            vec!["--access-token", "ghp_abcdefghijklmnop"],
            // Attached `-k<value>` / `-k=<value>`, letters-only included.
            vec!["-kabcdefgh1234"],
            vec!["-k=abcdefgh1234"],
            vec!["-kghp_abcdefghijklmnop"],
            vec!["-kabcdefghijkl"],
            vec!["-k=abcdefghijkl"],
        ] {
            assert!(
                evaluate_stdio_policy("s", "/usr/local/bin/tool", &args(&argv), false).is_err(),
                "{argv:?} must be refused"
            );
        }
        // A short, non-secret value is still allowed.
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["--key", "0123456789"]),
            false
        )
        .is_ok());
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["-k", "0123456789"]),
            false
        )
        .is_ok());
        // A short letters-only value and a long digits-only value stay allowed.
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["--key", "abcdef"]),
            false
        )
        .is_ok());
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["--key", "0123456789012"]),
            false
        )
        .is_ok());
        assert!(evaluate_stdio_policy("s", "/usr/local/bin/tool", &args(&["-u"]), false).is_ok());
    }
}
