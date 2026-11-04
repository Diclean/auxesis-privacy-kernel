//! The secret-redaction entry point. Composes known-value redaction,
//! separator normalisation, structured JSON and the token scanner.

use super::json::{scrub_embedded_json, scrub_json_document};
use super::redactor::Redactor;
use super::*;

/// Redact every documented secret shape from `text`.
///
/// This is **composed layers** behind a single entry point: every caller (API
/// previews, error details, the WS frame sanitizer, the run-summary scrub and
/// the daemon log writer) gets all of them without knowing about them.
///
/// - **L-1 known values.** Exact-value redaction of the secrets this process
///   has resolved (`AUX_KEY_*` from `.env`/environment, the API token, every
///   provider key the engine loads), plus their common transforms
///   (base64, percent-encoded, JSON-escaped, whitespace/zero-width-split).
///   `crate::scrub` owns the registry; the scan is linear and off — zero
///   allocation — when nothing is registered. This is the layer that catches
///   a key with no name in front of it; the shape layers remain the fallback
///   for unknown secrets.
/// - **L0 normalise.** Secret-adjacent separator lookalikes (`＝`, `：` and
///   the small forms) are folded to their ASCII separators, and every
///   control/invisible/format character (U+200B–U+200F, U+2060, U+FEFF,
///   soft hyphen, bidi controls, …) is stripped. `token\u{200b}=…`,
///   `api_key＝…` and `api_key：…` are therefore the same pair as their ASCII
///   spelling *before* any scan runs. The fold is
///   context-sensitive: only a lookalike separator directly after a
///   credential-looking name is rewritten, so ordinary prose, curly quotes,
///   CJK punctuation and fullwidth letters come out byte-identical
/// - **L1 structured.** When the text — or a balanced JSON substring inside
///   it — parses with `serde_json`, the value tree is walked: the value of
///   any key whose normalised name names a credential is replaced, values
///   that are themselves JSON strings are scrubbed recursively, and the
///   region is re-serialised. Pretty-printed JSON, escaped quotes, nesting
///   and JSON-inside-JSON cannot hide a key from a parser.
///   [`scrub_json_value`] exposes the same walk to callers that hold a
///   `serde_json::Value` *before* it is re-serialised (activity/WS summaries).
///   A region with nothing to redact is returned **byte for byte**:
///   whitespace, escape spelling, duplicate keys, key order and every number
///   lexeme survive untouched. Only a region in which something *was*
///   redacted is re-serialised (compactly, keys in input order via
///   `preserve_order`, numbers exact via `arbitrary_precision`).
/// - **L2 tokenizer.** The single-pass, linear-time tokenizer, extended with
///   multi-line pair values (bounded window), `\"` escapes,
///   `;`-separated cookie jars, percent-encoded URL schemes and the stricter
///   `plausible_token` gates.
///
/// The layer order matters: normalising first means L1 can parse JSON that
/// carries invisible or fullwidth punctuation, and the parser runs before
/// the tokenizer so escapes (`{\"api_key\":…}`) are resolved on real keys.
///
/// The tokenizer recognises, in any position:
///
/// - PEM blocks (`-----BEGIN <label>-----`, label case-insensitive) whose
///   label contains `PRIVATE KEY`, through the matching `-----END` marker (or
///   to the end of the text when it is missing), and PuTTY/OpenSSH new-format
///   keys (`PuTTY-User-Key-File-…`, no `BEGIN` marker);
/// - URL/URI userinfo credentials (`scheme://user:pass@host`, any scheme,
///   `redis://:pass@`, `mongodb+srv://…`, and the percent-encoded
///   `scheme%3A%2F%2Fuser:pass@host` spelling): the credential part is
///   replaced, the scheme and host stay readable;
/// - HTTP header lines: `authorization`/`proxy-authorization` values that
///   look like opaque secrets, and the whole value of `cookie`, `set-cookie`,
///   `x-api-key`, `x-auth-token`, `x-hub-signature*`, `x-amz-security-token`,
///   `x-goog-api-key` and `x-access-token` — short, low-entropy cookie values
///   included;
/// - key/value pairs separated by `=`, `:`, `:=` or their percent-encoded
///   forms `%3D`/`%3A`, quoted (`{"api_key":"…"}`, `"k": "v"`) or unquoted,
///   with an optional line break and indentation between the separator and
///   the value, with vendor-style names split on `_`/`-`/`.` (`DB_PASSWORD`,
///   `client_secret`, `GPG_PASSPHRASE`, `X-Api-Key`, …), the daemon's own
///   `AUX_KEY_…` env shape, cookie-jar names (`session`, `sid`, `jsessionid`,
///   `csrftoken`, …) and URL-shaped names (`*_URL`, `*_URI`,
///   `*_WEBHOOK_URL`);
/// - vendor-prefixed tokens (`sk-`, `ghp_`, `github_pat_`, `glpat-`, `AIza`,
///   `AKIA…`, `xox…-`, `npm_`, …), matched only at the start of a token run so
///   `task-sk-1234` and `disk-sk-usage` stay readable;
/// - `Bearer`/`Basic` scheme values and `curl -u`/`--user`/`--password`
///   values that look like opaque credentials;
/// - `eyJ…` JWTs (three dot-separated segments).
///
/// Value shape gates keep ordinary text intact: a secret-named assignment is
/// redacted when its value is token-shaped (digits, mixed case, a long opaque
/// run or a quoted passphrase) — so `public_key_sha256 = 9f2a1b3c`,
/// `key = "abcdefghijkl"` and `let token = parse(input);` survive — and the
/// strongest components (`password`, `token`, `secret`, …) use a looser gate
/// than the weak `key` component. Hash/checksum/fingerprint names without a
/// strong component (`public_key_sha256`) are never treated as credentials, a
/// `*_id`/`*_uuid` name is an identifier, and an all-digit epoch, a UUID or a
/// CamelCase type name is not a secret by shape alone. A match is
/// re-emitted with its original spelling, never rewritten to a constant name.
///
/// This is a *pattern* redactor: values that are base64-, hex- or
/// newline-encoded before they reach the text are out of scope, and no
/// caller may claim more than that. The API response body is the contract.
///
/// A text with nothing to redact is returned **byte for byte**
/// (whitespace, escape spelling, duplicate keys, key order and number
/// lexemes included). Only a JSON region in which something was redacted is
/// re-serialised, and then it keeps key order and exact number lexemes.
pub fn redact_secrets(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    // L-1: exact-value redaction of the secrets this process knows. This is
    // the precise layer: it needs no name or shape next to the value, so a
    // key the daemon itself resolved can never survive in prose, a tool
    // argument or an encoded copy. `None` (empty registry or no match) keeps
    // the original bytes with no allocation; the heuristic layers below stay
    // the fallback for values this process has never seen.
    let known = crate::scrub::redact_known_secrets(text);
    let had_known = known.is_some();
    let original: &str = known.as_deref().unwrap_or(text);
    // L0: one normalised alphabet for every layer below.
    let normalised = normalise_for_scrub(original);
    if normalised.is_empty() {
        // Only invisible/space characters: keep the isolates, drop the rest.
        return kernel_core::text::sanitize_text_keep_bidi_isolates(&strip_ansi(original));
    }
    // L1: structured JSON, whole document first, then balanced substrings.
    let structured = scrub_json_document(&normalised).or_else(|| scrub_embedded_json(&normalised));
    let structured_changed = structured
        .as_deref()
        .is_some_and(|structured| structured != normalised);
    let base = structured.as_deref().unwrap_or(&normalised);
    // L2: the linear tokenizer, on the structured result.
    let out = Redactor {
        text: base,
        bytes: base.as_bytes(),
        out: String::with_capacity(base.len()),
        copied: 0,
        cursor: 0,
    }
    .run();
    if had_known || structured_changed || out != base {
        out
    } else {
        // Nothing needed redaction: keep the bytes, including the bidi
        // isolate controls the L0 scan strips (dh-1 fidelity note). ANSI and
        // the other control/invisible characters still go; only the four
        // isolates are content rather than spoofing scaffolding.
        kernel_core::text::sanitize_text_keep_bidi_isolates(&strip_ansi(original))
    }
}

/// L0: fold the separator lookalikes that sit directly after a
/// credential-looking name onto the ASCII separators the tokenizer
/// understands, drop ANSI escape sequences whole (so an SGR reset between a
/// name and its separator cannot break the pair), then strip
/// control/invisible/format characters (keeping `\n`/`\t`, like
/// [`sanitize_text`]).
///
/// The fold is deliberately *not* a whole-text NFKC pass: only
/// `＝`/`﹦` (→ `=`) and `：`/`﹕` (→ `:`), and only when the run immediately
/// before them classifies as a credential name. Every other character —
/// curly quotes, fullwidth letters and digits, CJK punctuation, emoji — is
/// left exactly as it was, so text with nothing to redact stays byte-identical.
pub(super) fn normalise_for_scrub(text: &str) -> String {
    let stripped = strip_ansi(text);
    let folded = fold_separator_lookalikes(&stripped);
    sanitize_text(&folded)
}

/// Fold `＝`/`﹦`/`：`/`﹕` to `=`/`:` when the name directly before them is
/// credential-shaped; keep the original character otherwise.
fn fold_separator_lookalikes(text: &str) -> String {
    if !text.chars().any(is_separator_lookalike) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for (i, c) in text.char_indices() {
        if let Some(ascii) = separator_lookalike(c) {
            out.push(if credential_name_before(text, i) {
                ascii
            } else {
                c
            });
        } else {
            out.push(c);
        }
    }
    out
}

/// Is the text directly before the separator at byte `at` a credential
/// name — unquoted (`api_key＝…`) or quoted (`{"api_key"：…}`)?
fn credential_name_before(text: &str, at: usize) -> bool {
    const WINDOW: usize = 128;
    let before = &text[..at];
    let trimmed = before.trim_end_matches([' ', '\t']);
    let name = if let Some(quote) = trimmed
        .chars()
        .next_back()
        .filter(|c| *c == '"' || *c == '\'')
    {
        // Quoted key: `"api_key"：`, `" api_key "：`, `'token'：`.
        let quote_len = quote.len_utf8();
        if trimmed.len() < quote_len * 2 {
            return false;
        }
        // The window is a byte count: round its start up to a character
        // boundary. The closing quote is ASCII, so `end` always is one.
        let end = trimmed.len() - quote_len;
        let mut start = trimmed.len().saturating_sub(WINDOW).min(end);
        while !trimmed.is_char_boundary(start) {
            start += 1;
        }
        let content = &trimmed[start..end];
        let Some(open) = content.rfind(quote) else {
            return false;
        };
        content[open + quote_len..].trim()
    } else {
        // Unquoted run immediately before the separator.
        let end = trimmed.len();
        let mut start = end;
        let bytes = trimmed.as_bytes();
        while start > 0 && end - start < WINDOW && is_run_byte(bytes[start - 1]) {
            start -= 1;
        }
        if start == end {
            return false;
        }
        trimmed[start..end].trim()
    };
    !name.is_empty()
        && (header_gate(name).is_some() || classify_name(name).strength != Strength::None)
}

/// The four separator lookalikes the tokenizer aliases: fullwidth equals and
/// colon and their small-form variants.
fn separator_lookalike(c: char) -> Option<char> {
    match c {
        '\u{FF1D}' | '\u{FE66}' => Some('='),
        '\u{FF1A}' | '\u{FE55}' => Some(':'),
        _ => None,
    }
}

fn is_separator_lookalike(c: char) -> bool {
    separator_lookalike(c).is_some()
}
