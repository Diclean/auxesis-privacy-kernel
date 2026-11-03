//! Structured-JSON redaction: walks a `serde_json::Value` and masks
//! credential-named entries without rewriting clean documents.

use super::shapes::{numeric_secret, value_is_secret};
use super::*;

/// L1a: scrub `text` when it is one JSON document (object, array or string).
///
/// Returns `Some(text)` when the document parsed and was already clean (the
/// original bytes are kept: no formatting is invented), `Some(compact)` when
/// the walk changed it, and `None` when the text is not a JSON document.
///
/// B4-01: "clean" is decided by the *walk*, never by comparing
/// re-serialisations. Re-serialising a clean document would normalise
/// whitespace, escape spelling and (before `arbitrary_precision`) every
/// number through `f64`; a document with nothing to redact is returned
/// byte for byte.
pub(super) fn scrub_json_document(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"')) {
        return None;
    }
    let mut value: serde_json::Value = serde_json::from_str(text).ok()?;
    // Only containers and strings can carry content; a bare number/bool has
    // nothing to walk.
    if scrub_json_value(&mut value) {
        serde_json::to_string(&value).ok()
    } else {
        Some(text.to_string())
    }
}

/// L1b: scrub every balanced JSON object/array substring of `text`.
///
/// The extractor is a byte state machine (string/escape aware, depth-capped)
/// charged against a global byte budget, so an adversarial text full of
/// `{`/`[` can never turn the structured pass quadratic; once the budget is
/// gone the L2 tokenizer still covers the remaining text.
pub(super) fn scrub_embedded_json(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut budget = text.len().saturating_mul(2).saturating_add(1024);
    let mut out: Option<String> = None;
    let mut copied = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if (bytes[i] == b'{' || bytes[i] == b'[') && budget > 0 {
            let start = i;
            if let Some(end) = json_region_end(bytes, start, &mut budget) {
                if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&text[start..end])
                {
                    // B4-01: replace the region only when the walk redacted
                    // something; a clean region stays byte-identical.
                    if scrub_json_value(&mut value) {
                        let serialised = serde_json::to_string(&value).unwrap_or_default();
                        let buffer = out.get_or_insert_with(|| String::with_capacity(text.len()));
                        buffer.push_str(&text[copied..start]);
                        buffer.push_str(&serialised);
                        copied = end;
                    }
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.map(|mut buffer| {
        buffer.push_str(&text[copied..]);
        buffer
    })
}

/// Depth cap for the balanced-brace extractor (serde_json's own recursion
/// limit is lower, so a deeper region could never parse anyway).
const JSON_REGION_MAX_DEPTH: usize = 64;

/// End (exclusive) of the balanced `{…}`/`[…]` region starting at `start`,
/// or `None` when it does not close inside the remaining budget. Scans
/// string/escape state so a `}` inside a JSON string cannot end the region.
fn json_region_end(bytes: &[u8], start: usize, budget: &mut usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = start;
    while i < bytes.len() {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let byte = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > JSON_REGION_MAX_DEPTH {
                        return None;
                    }
                }
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Maximum JSON nesting the tree walker descends into before it redacts the
/// whole subtree; a payload deeper than this is treated as opaque.
const JSON_WALK_MAX_DEPTH: usize = 64;

/// Scrub a `serde_json::Value` tree in place: the value of every key whose
/// normalised name names a credential is replaced with the mask, and every
/// string value is passed through [`redact_secrets`] (so a JSON document
/// hidden inside a string is scrubbed before the tree is re-serialised).
///
/// Returns `true` when anything was redacted. Callers that re-serialise a
/// payload — activity digests, WS journal frames — run this *before* turning
/// the value into a string, so a key can never be hidden behind an escape
/// produced by `serde_json` (B3-02). The text entry points keep the original
/// bytes when the result is `false` (B4-01); digest callers may still render
/// the tree, but with `arbitrary_precision`/`preserve_order` enabled (see
/// `Cargo.toml`) its numbers keep their exact original lexemes and its keys
/// keep their input order.
pub fn scrub_json_value(value: &mut serde_json::Value) -> bool {
    scrub_json_inner(value, 0)
}

fn scrub_json_inner(value: &mut serde_json::Value, depth: usize) -> bool {
    use serde_json::Value;
    if depth > JSON_WALK_MAX_DEPTH {
        if !matches!(value, Value::Null) {
            *value = Value::String(MASK.to_string());
            return true;
        }
        return false;
    }
    match value {
        Value::Object(map) => {
            let mut changed = false;
            // E6-02: a secret used as a JSON *key* (`{"<secret>":"owner"}`)
            // must not survive the tree walk either. The raw-text path sees
            // it through the exact layer; the tree path holds values only, so
            // scrub the keys here before anything else reads them.
            let original_keys: Vec<String> = map.keys().cloned().collect();
            for key in &original_keys {
                let scrubbed = redact_secrets(key);
                if scrubbed != *key {
                    if let Some(entry) = map.remove(key.as_str()) {
                        map.insert(scrubbed, entry);
                        changed = true;
                    }
                }
            }
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in &keys {
                let info = classify_name(key);
                let Some(entry) = map.get_mut(key) else {
                    continue;
                };
                if (info.strength != Strength::None || info.aux_key) && mask_json_entry(info, entry)
                {
                    changed = true;
                    continue;
                }
                changed |= scrub_json_inner(entry, depth + 1);
            }
            // E5-01: a credential *name* in one entry and its *value* in a
            // sibling entry (`{"name":"api_key","value":"…"}` — tool-call
            // argument dumps, MCP envelopes, credential managers) defeats
            // the per-key classifier because neither entry is secret-shaped
            // on its own. When an entry names a credential, the sibling
            // value carriers are masked whole.
            let names_credential = keys
                .iter()
                .any(|key| is_name_carrier(key) && map.get(key).is_some_and(credential_name));
            if names_credential {
                for key in &keys {
                    if !is_value_carrier(key) {
                        continue;
                    }
                    if let Some(entry) = map.get_mut(key) {
                        if mask_sibling_value(entry) {
                            changed = true;
                        }
                    }
                }
            }
            changed
        }
        Value::Array(items) => {
            let mut changed = false;
            // E5-01: a two-element tuple whose first item names a credential
            // (`["api_key","…"]`, `["Authorization","Bearer …"]`).
            if items.len() == 2 && credential_name(&items[0]) && mask_sibling_value(&mut items[1]) {
                changed = true;
            }
            for item in items {
                changed |= scrub_json_inner(item, depth + 1);
            }
            changed
        }
        Value::String(text) => {
            let scrubbed = redact_secrets(text);
            if scrubbed != *text {
                *text = scrubbed;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Replace one JSON entry whose key names a credential, when the entry's
/// shape (or, for containers, its content) justifies it. Returns `true` when
/// the entry was replaced.
fn mask_json_entry(info: NameInfo, entry: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    match entry {
        Value::String(text) => {
            if value_is_secret(info, text, true) {
                *entry = Value::String(MASK.to_string());
                return true;
            }
        }
        Value::Number(number) => {
            let text = number.to_string();
            if numeric_secret(info, &text) || value_is_secret(info, &text, false) {
                *entry = Value::String(MASK.to_string());
                return true;
            }
        }
        Value::Array(items) => {
            if !items.is_empty() {
                *entry = Value::String(MASK.to_string());
                return true;
            }
        }
        Value::Object(map) => {
            if !map.is_empty() {
                *entry = Value::String(MASK.to_string());
                return true;
            }
        }
        Value::Bool(_) | Value::Null => {}
    }
    false
}

/// Keys that *carry* a credential name in an envelope object
/// (`{"name":"api_key","value":"…"}`): the value of one of these names the
/// credential whose value sits under a value carrier. E6-01: tool-call
/// dumps use `env`, `var`, `setting`, `option` and `param` for the same
/// carrier role.
fn is_name_carrier(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "name"
            | "key"
            | "header"
            | "field"
            | "variable"
            | "env"
            | "var"
            | "setting"
            | "option"
            | "param"
    )
}

/// Keys that *carry* the credential value next to a name carrier.
fn is_value_carrier(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "value" | "val" | "content" | "data"
    )
}

/// Does this scalar name a credential (`"api_key"`, `"Authorization"`)?
fn credential_name(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            let text = text.trim();
            header_gate(text).is_some() || classify_name(text).strength == Strength::Strong
        }
        _ => false,
    }
}

/// Mask the value that sits next to a credential name; returns `true` when
/// the entry changed. Empty strings/containers and booleans/null carry
/// nothing and stay as they are.
fn mask_sibling_value(entry: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    let replace = match entry {
        Value::String(text) => !text.is_empty(),
        Value::Number(_) => true,
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        Value::Bool(_) | Value::Null => false,
    };
    if replace {
        *entry = Value::String(MASK.to_string());
    }
    replace
}
