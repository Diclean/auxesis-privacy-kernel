//! Credential-name classification: which assignment names, header names
//! and vendor prefixes mark the value next to them as secret.

/// Vendor prefixes whose following run is key material. Order only matters
/// for overlapping prefixes within one family; matching is ASCII
/// case-insensitive and the original spelling is re-emitted.
const TOKEN_PREFIXES: &[&str] = &[
    "github_pat_",
    "glpat-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "xapp-",
    "xoxa-",
    "xoxb-",
    "xoxc-",
    "xoxd-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
    "sk_",
    "sk-",
    "xi-",
    "npm_",
    "AIza",
];

/// Name components whose value is treated as a secret (looser value gate).
const STRONG_NAME_COMPONENTS: &[&str] = &[
    "password",
    "passwd",
    // `DB_PASS`, `PASS`, `PW` are the same credential; the
    // exact-component match keeps `bypass`/`compass`/`passenger` readable
    // (the all-caps suffix rule is the only way these can appear glued).
    "pass",
    "pw",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "credential",
    "credentials",
    "apikey",
    "authtoken",
    "authorization",
    // Cookie-jar names carry session credentials without a
    // `Cookie:` header in front of them.
    "session",
    "sessionid",
    "jsessionid",
    "sid",
    "csrftoken",
    "csrf",
];

/// Name components that mark an assignment as secret-bearing but use the
/// strict shape gate (`key =`, `*_URL`, `*_URI`, `*_WEBHOOK_URL`, `auth`).
const WEAK_NAME_COMPONENTS: &[&str] = &["key", "url", "uri", "webhook", "auth"];

/// Components that name a digest, not a credential: `public_key_sha256` is a
/// hash of public material and must stay readable.
const HASH_NAME_COMPONENTS: &[&str] = &[
    "sha1",
    "sha256",
    "sha512",
    "md5",
    "hash",
    "checksum",
    "digest",
    "fingerprint",
];

/// Adjacent name components that together mean a credential (`api_key`,
/// `access_key`, `private_key`, `auth_token`).
const STRONG_NAME_BIGRAMS: &[(&str, &str)] = &[
    ("api", "key"),
    ("access", "key"),
    ("private", "key"),
    ("auth", "token"),
];

/// How strongly an assignment name marks its value as a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Strength {
    /// Not a secret name.
    #[default]
    None,
    /// Secret-bearing, strict value shape (`key`, `*_URL`).
    Weak,
    /// Secret-bearing, loose value shape (`password`, `token`, …).
    Strong,
}

/// What a name means for redaction.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NameInfo {
    pub(crate) strength: Strength,
    /// The name contains `url`/`uri`/`webhook`.
    pub(super) url_like: bool,
    /// The name contains `webhook`.
    pub(super) webhook: bool,
    /// The daemon's own `AUX_KEY_…` env shape: every non-empty value redacts.
    pub(super) aux_key: bool,
}

/// Classify one assignment name. No allocation: names can be long and there
/// can be many of them on an adversarial input.
///
/// Leading/trailing padding is ignored — `{" api_key " : …}` names the
/// same credential as `{"api_key": …}`.
pub(crate) fn classify_name(name: &str) -> NameInfo {
    let name = name.trim();
    let mut info = NameInfo::default();
    let mut hash_hint = false;
    let mut previous: Option<&str> = None;
    let mut last: Option<&str> = None;
    for part in name.split(['_', '-', '.']).filter(|part| !part.is_empty()) {
        last = Some(part);
        if STRONG_NAME_COMPONENTS
            .iter()
            .any(|term| part.eq_ignore_ascii_case(term))
        {
            info.strength = Strength::Strong;
        } else if WEAK_NAME_COMPONENTS
            .iter()
            .any(|term| part.eq_ignore_ascii_case(term))
            && info.strength == Strength::None
        {
            info.strength = Strength::Weak;
        }
        if part.eq_ignore_ascii_case("url") || part.eq_ignore_ascii_case("uri") {
            info.url_like = true;
        }
        if part.eq_ignore_ascii_case("webhook") {
            info.url_like = true;
            info.webhook = true;
        }
        if HASH_NAME_COMPONENTS
            .iter()
            .any(|term| part.eq_ignore_ascii_case(term))
        {
            hash_hint = true;
        }
        if let Some(previous) = previous {
            if STRONG_NAME_BIGRAMS.iter().any(|(left, right)| {
                previous.eq_ignore_ascii_case(left) && part.eq_ignore_ascii_case(right)
            }) {
                info.strength = Strength::Strong;
            }
        }
        // CamelCase words inside one part (`secretAccessKey`, `dbPassword`)
        // expose the same terms as the app's case-transition split.
        if part.bytes().any(|byte| byte.is_ascii_uppercase()) {
            let bytes = part.as_bytes();
            let mut word_start = 0usize;
            let mut previous_word: Option<&str> = None;
            for index in 1..=bytes.len() {
                let boundary = index == bytes.len()
                    || (bytes[index].is_ascii_uppercase()
                        && (bytes[index - 1].is_ascii_lowercase()
                            || bytes[index - 1].is_ascii_digit()));
                if !boundary {
                    continue;
                }
                let word = &part[word_start..index];
                if STRONG_NAME_COMPONENTS
                    .iter()
                    .any(|term| word.eq_ignore_ascii_case(term))
                {
                    info.strength = Strength::Strong;
                }
                if let Some(previous_word) = previous_word {
                    if STRONG_NAME_BIGRAMS.iter().any(|(left, right)| {
                        previous_word.eq_ignore_ascii_case(left) && word.eq_ignore_ascii_case(right)
                    }) {
                        info.strength = Strength::Strong;
                    }
                }
                previous_word = Some(word);
                word_start = index;
            }
        }
        // All-caps/digit glued compounds expose a strong term as a suffix
        // (`PGPASSWORD`, `MYSQLPWD`, `SECRETACCESSKEY`); a mixed-case or
        // lowercase part is never suffix-matched, so `monkey`/`keyboard`
        // stay readable.
        if part.len() > 4 && part.bytes().all(|byte| !byte.is_ascii_lowercase()) {
            for term in STRONG_NAME_COMPONENTS {
                if part.len() <= term.len() {
                    continue;
                }
                let tail = part.len() - term.len();
                if part.is_char_boundary(tail) && part[tail..].eq_ignore_ascii_case(term) {
                    info.strength = Strength::Strong;
                }
            }
        }
        previous = Some(part);
    }
    if name.len() >= 8 && name.as_bytes()[..8].eq_ignore_ascii_case(b"aux_key_") {
        info.aux_key = true;
        info.strength = Strength::Strong;
    }
    // A name that ends in `id`/`uuid` names an identifier, not the
    // credential itself (`token_id`, `session_id`, `access_key_id`). The
    // `AUX_KEY_` env shape keeps its own rule.
    if !info.aux_key
        && last.is_some_and(|part| {
            part.eq_ignore_ascii_case("id") || part.eq_ignore_ascii_case("uuid")
        })
    {
        return NameInfo::default();
    }
    if info.strength != Strength::Strong && hash_hint {
        // A digest of public material is not key material.
        info.strength = Strength::None;
    }
    info
}

/// How one HTTP header value is gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderGate {
    /// Redact when the value looks like an opaque secret (`Authorization:
    /// none` must survive.
    Shaped,
    /// Redact the whole value: the header is a credential by definition.
    Whole,
}

/// Credential headers as a name → gate map; names are matched whole and
/// case-insensitively.
pub(crate) fn header_gate(name: &str) -> Option<HeaderGate> {
    const SHAPED: &[&str] = &["authorization", "proxy-authorization"];
    const WHOLE: &[&str] = &[
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-goog-api-key",
        "x-access-token",
    ];
    if SHAPED
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
    {
        return Some(HeaderGate::Shaped);
    }
    if WHOLE.iter().any(|header| name.eq_ignore_ascii_case(header)) {
        return Some(HeaderGate::Whole);
    }
    const HUB: &[u8] = b"x-hub-signature";
    if name.len() > HUB.len() && name.as_bytes()[..HUB.len()].eq_ignore_ascii_case(HUB) {
        return Some(HeaderGate::Whole);
    }
    None
}

/// Bytes that make up a token/name run: identifiers, base64url, JWT dots and
/// scheme `+` (so `mongodb+srv://` is one run). Kept apart from punctuation
/// so a prefix only matches at a run start (`task-sk-1234` is safe).
pub(crate) fn is_run_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+')
}

/// Case-insensitive vendor-prefix match at a run start; returns its length.
pub(crate) fn vendor_prefix(run: &str) -> Option<usize> {
    TOKEN_PREFIXES.iter().find_map(|prefix| {
        (run.len() >= prefix.len()
            && run.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes()))
        .then_some(prefix.len())
    })
}
