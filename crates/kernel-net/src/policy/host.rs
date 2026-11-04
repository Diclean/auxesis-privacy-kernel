//! URL host helpers: the bare host, the seen-origin key and domain matching.

/// The seen-origin key of `url`: `scheme://host:effective-port`, host bare and
/// lowercased. Used for the conversation's already-seen set and for redirect
/// destinations, so both sides key on the same tuple.
pub(crate) fn url_origin_key(url: &reqwest::Url) -> String {
    let host = bare_host(url).unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    format!("{}://{host}:{port}", url.scheme())
}

/// The origin key of `url` (see [`url_origin_key`]), or `None` when it does
/// not parse.
pub(crate) fn origin_of(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .map(|parsed| url_origin_key(&parsed))
}

/// True when `pattern` covers `host` (case-insensitive).
///
/// A bare `example.com` matches the domain and every subdomain;
/// `*.example.com` and `.example.com` mean the same. There is no implicit
/// suffix at the TLD boundary here (that is `ask_once_per_site`, W6): a
/// `deny_domains` entry is matched literally as written, so no entry is ever
/// widened by the PSL.
pub fn domain_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    let suffix = pattern
        .strip_prefix("*.")
        .or_else(|| pattern.strip_prefix('.'))
        .unwrap_or(pattern.as_str());
    if suffix.is_empty() {
        return false;
    }
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Host (or `None`) of `url`, brackets stripped for IPv6 literals.
pub(crate) fn bare_host(url: &reqwest::Url) -> Option<String> {
    url.host_str().map(|host| {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    })
}

/// True for a numeric spelling that is *not* a valid IP literal but is an
/// attempt to smuggle one: a single all-digit number (`2130706433`,
/// `017700000001`), a dotted numeric form (`0177.0.0.1`, `127.1`) or a
/// `0x`-prefixed form (`0x7f.1`, `0x7f000001`).
pub(super) fn is_obfuscated_numeric_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if host.starts_with("0x") || host.split('.').any(|label| label.starts_with("0x")) {
        return true;
    }
    let all_digits = host.chars().all(|c| c.is_ascii_digit());
    let dotted_numeric = host.chars().all(|c| c.is_ascii_digit() || c == '.') && host.contains('.');
    all_digits || dotted_numeric
}
