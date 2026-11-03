//! Cookie values: the pairs of a `Cookie:` header and a named session cookie.

use std::sync::LazyLock;

use regex::Regex;

use super::scan::trimmed;

/// The shortest cookie value.
const MIN_COOKIE: usize = 8;
/// Bytes of a `Cookie:` line read for its pairs.
const MAX_COOKIE_LINE: usize = 4096;

/// A session or auth cookie name, then `=` and its value (closed list).
static COOKIE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:^|[^A-Za-z0-9_.\-])(?:sessionid|session_id|session|sid|user_session|",
        r"auth|auth_token|token|csrftoken|csrf_token|remember_token|remember_me|",
        r"phpsessid|jsessionid|aspsessionid|asp\.net_sessionid|connect\.sid|",
        r"laravel_session|ci_session|_session_id)=([^\s;,]+)"
    ))
    .expect("cookie name list compiles")
});

/// A cookie header: its pairs run to the line end.
static COOKIE_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[^A-Za-z0-9-])(?:set-)?cookie[ \t]*:").expect("cookie header compiles")
});

/// Cookie attributes: a `Set-Cookie` pair that is no value.
const ATTRIBUTES: &[&str] = &[
    "path",
    "domain",
    "expires",
    "max-age",
    "samesite",
    "httponly",
    "secure",
    "priority",
    "partitioned",
];

/// A cookie value: [`MIN_COOKIE`] bytes or more, hidden whole however long.
fn cookie_value(value: &str) -> bool {
    value.len() >= MIN_COOKIE
}

pub(super) fn cookies(text: &str, spans: &mut Vec<(usize, usize)>) {
    for found in COOKIE_RE.captures_iter(text) {
        if let Some(value) = found.get(1) {
            let (start, end) = trimmed(text, value.start(), value.end());
            if cookie_value(&text[start..end]) {
                spans.push((start, end));
            }
        }
    }
    let mut reach = 0;
    for cue in COOKIE_HEADER_RE.find_iter(text) {
        if cue.end() <= reach {
            continue;
        }
        // Cap before searching: a long line is read once, not once per cue.
        let mut cap = text.len().min(cue.end() + MAX_COOKIE_LINE);
        while !text.is_char_boundary(cap) {
            cap -= 1;
        }
        let end = text[cue.end()..cap]
            .find(['\n', '\r'])
            .map_or(cap, |at| cue.end() + at);
        reach = end;
        let mut at = cue.end();
        for pair in text[cue.end()..end].split(';') {
            let pair_start = at;
            at += pair.len() + 1;
            let Some((name, _)) = pair.split_once('=') else {
                continue;
            };
            if ATTRIBUTES.contains(&name.trim().to_ascii_lowercase().as_str()) {
                continue;
            }
            let value_start = pair_start + name.len() + 1;
            let (start, stop) = trimmed(text, value_start, pair_start + pair.len());
            if cookie_value(&text[start..stop]) && !text[start..stop].contains(char::is_whitespace)
            {
                spans.push((start, stop));
            }
        }
    }
}
