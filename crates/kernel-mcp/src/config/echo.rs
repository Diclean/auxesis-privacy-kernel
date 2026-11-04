//! Secret-safe rendering of server ids and agent names in refusals.

use kernel_core::text::hex_value;

use super::secrets::looks_like_secret;

/// A server id or agent name as a refusal may show it: debug-quoted, or
/// `placeholder` when [`looks_like_secret`] reads it as a credential (a key
/// pasted as the id is still a valid slug).
///
/// A percent-encoded key is the same key, so a decoded copy is read too:
/// `%73k-…` and `%2573k-…` are hidden just like `sk-…` is, and so is every
/// deeper layer (`%25252573k-…`).
pub(super) fn shown(value: &str, placeholder: &str) -> String {
    if looks_like_secret(value) || looks_like_secret_decoded(value) {
        placeholder.to_string()
    } else {
        format!("{value:?}")
    }
}

/// Whether `value` reads as a credential in a percent-decoded copy of it.
/// Bytes that are not valid UTF-8 cannot be shown safely, so they count as a
/// credential too.
fn looks_like_secret_decoded(value: &str) -> bool {
    // The detector has read the value once already: that read is charged to
    // the budget too.
    decoded_copy_is_secret_shaped(value, value.len(), looks_like_secret)
}

/// How many percent-escape layers are peeled before a value is taken at face
/// value: `%73k-…`, `%2573k-…` and `%252573k-…` are one key.
const MAX_DECODE_ROUNDS: usize = 16;

/// The work budget of one value: every byte the detector or the decoder
/// reads is charged, so the whole check stays within 16 × the length of the
/// input and never exceeds 4 MiB.
const MAX_REDACT_WORK: usize = 4 * 1024 * 1024;

/// Whether a percent-decoded copy of `value` reads as a credential.
///
/// The decoder peels one escape layer per round and `secret_shaped` is called
/// with every copy as it is produced: only the current copy is ever kept, so
/// a value that nests its escapes deeply cannot pile up into a pile of
/// copies.
///
/// The work is bounded twice over: at most [`MAX_DECODE_ROUNDS`] rounds, and
/// at most [`MAX_REDACT_WORK`] bytes of work across the whole check — every
/// byte the detector and the decoder read is charged, so the bytes decoded
/// stay within 16 × the length of the input and the total never exceeds
/// 4 MiB. A value that is still changing when the budget or the round cap
/// runs out cannot be shown safely: it counts as secret-shaped.
fn decoded_copy_is_secret_shaped(
    value: &str,
    mut spent: usize,
    secret_shaped: impl Fn(&str) -> bool,
) -> bool {
    let budget = value.len().saturating_mul(16).min(MAX_REDACT_WORK);
    let mut current = value.to_string();
    for _ in 0..MAX_DECODE_ROUNDS {
        // A round that does not fit the budget is never started.
        if spent.saturating_add(current.len()) > budget {
            return true;
        }
        spent = spent.saturating_add(current.len());
        let next = match String::from_utf8(percent_decode_bytes(&current)) {
            Ok(next) => next,
            // Bytes that are not valid UTF-8 cannot be shown safely.
            Err(_) => return true,
        };
        if next == current {
            // The text stopped changing: there is no deeper copy to read.
            return false;
        }
        // The detector reads the copy too: its bytes are charged as well.
        if spent.saturating_add(next.len()) > budget {
            return true;
        }
        spent = spent.saturating_add(next.len());
        if secret_shaped(&next) {
            return true;
        }
        current = next;
    }
    // The round cap ran out while the text was still changing.
    true
}

/// Percent-decode `value` before the secret checks (item 5), so an encoded
/// separator cannot hide a `token%3Dabc` / `key%3Avalue` pair. An invalid or
/// truncated escape is left exactly as written; the bytes are decoded raw, so
/// a valid UTF-8 sequence round-trips and anything else is lossily replaced.
pub(super) fn percent_decoded(value: &str) -> String {
    String::from_utf8_lossy(&percent_decode_bytes(value)).into_owned()
}

/// The bytes of `value` after one percent-decoding round: every valid `%XX`
/// escape replaced by its byte. An invalid or truncated escape is left
/// exactly as written.
///
/// This is the MCP refusal path: it checks whether a server id or agent name
/// reads as a credential once decoded. It decodes raw bytes and converts them
/// lossily, because a key may not be valid UTF-8. The privacy crate's decoder is
/// separate on purpose: it only yields printable ASCII or valid UTF-8, so a
/// detector never sees a broken byte sequence.
fn percent_decode_bytes(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpConfig;

    #[test]
    fn a_refusal_never_quotes_a_secret_shaped_id_or_agent() {
        // CONFIG-ERR-ECHO-2: a slug-valid key as the server id or agent name,
        // and an id that fails the slug check.
        let (id, stdio) = ("sk-proj-canary-7f3k9q", "transport = \"stdio\"\ncommand");
        let agents = |agent: &str| {
            format!("id = \"x\"\n{stdio} = \"/bin/x\"\nagents = {{ {agent} = [\"a b\"] }}")
        };
        for (body, kept) in [
            (
                format!("id = \"{id}\"\ntransport = \"http\""),
                "server <id> is http",
            ),
            (
                format!("id = \"{id}\"\ntransport = \"http\"\nurl = \"http://h.test\""),
                "server <id> must use https",
            ),
            (
                format!("id = \"{id}\"\n{stdio} = \"relative\""),
                "server <id> stdio command",
            ),
            (
                "id = \"Sk-CANARY-7f3k9q\"\ntransport = \"http\"".into(),
                "server id must match",
            ),
            (
                agents(id),
                "server \"x\" lists an unusable tool name for agent <agent>",
            ),
            (
                agents("\"sk CANARY\""),
                "server \"x\" names an invalid agent",
            ),
        ] {
            let text = format!("[[server]]\n{body}\n");
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let refusal = config.server[0].check().unwrap_err();
            let err = config.validate().unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}{refusal:?}"));
            assert!(!debug.to_lowercase().contains("canary"), "{debug}");
            assert!(shown.contains(kept), "{shown}");
        }
        let text = format!("[[server]]\nid = \"{id}\"\ntransport = \"http\"\n");
        let mut twins = McpConfig::parse("mcp.toml", &text).unwrap();
        twins.server.push(twins.server[0].clone());
        let err = twins.validate_structural().unwrap_err().to_string();
        assert!(err.contains("duplicate server id <id>"), "{err}");
    }

    #[test]
    fn a_refusal_never_quotes_a_percent_encoded_id_or_agent() {
        // CONFIG-ERR-ECHO-2 (review): `%73k-…` is the same key as `sk-…`, and
        // so are `%2573k-…` (encoded twice) and `%53K-…` (the same bytes,
        // another case). None of them may reach a refusal.
        for id in [
            "sk-proj-canary-7f3k9q",
            "%73k-proj-canary-7f3k9q",
            "%2573k-proj-canary-7f3k9q",
            "%53K-PROJ-canary-7f3k9q",
        ] {
            let text = format!("[[server]]\nid = \"{id}\"\ntransport = \"http\"\n");
            let mut twins = McpConfig::parse("mcp.toml", &text).unwrap();
            twins.server.push(twins.server[0].clone());
            let err = twins.validate_structural().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            assert!(err.contains("duplicate server id <id>"), "{err}");
            // The same id in a refusal that names the server.
            let text = format!(
                "[[server]]\nid = \"{id}\"\ntransport = \"http\"\nurl = \"http://h.test\"\n"
            );
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let err = config.validate().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            // The agent name is the same key.
            let text = format!(
                "[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = \"/bin/x\"\nagents = {{ \"{id}\" = [\"a b\"] }}\n"
            );
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let err = config.validate().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
        }
    }

    #[test]
    fn a_refusal_never_quotes_a_key_hidden_however_many_times_it_is_encoded() {
        // CONFIG-ECHO-DECODE-LOOP: `%25252573k-…` is the same key as `sk-…`,
        // four escape layers deep, and `%252525252573k-…` six layers deep. The
        // decoder peels every layer, so neither reaches a refusal.
        for id in [
            "%25252573k-proj-canary-7f3k9q",
            "%252525252573k-proj-canary-7f3k9q",
        ] {
            let text = format!("[[server]]\nid = \"{id}\"\ntransport = \"http\"\n");
            let mut twins = McpConfig::parse("mcp.toml", &text).unwrap();
            twins.server.push(twins.server[0].clone());
            let err = twins.validate_structural().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            assert!(err.contains("duplicate server id <id>"), "{err}");
            // The same id in a refusal that names the server.
            let text = format!(
                "[[server]]\nid = \"{id}\"\ntransport = \"http\"\nurl = \"http://h.test\"\n"
            );
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let err = config.validate().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            // The agent name is the same key.
            let text = format!(
                "[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = \"/bin/x\"\nagents = {{ \"{id}\" = [\"a b\"] }}\n"
            );
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let err = config.validate().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
        }
    }

    #[test]
    fn a_megabyte_of_nested_escapes_is_hidden_and_the_work_stays_bounded() {
        // CONFIG-ECHO-DECODE-LOOP (review): a value that nests its escapes
        // deeply must not make the decoder work without bound. The decoder
        // stops at its budget while the text is still changing, so the value
        // is hidden — and it stops fast.
        let canary = format!("%25{}73k-proj-canary-7f3k9q", "25".repeat(98));
        let value = format!("{canary}{}", "x".repeat(1_000_000 - canary.len()));
        let started = std::time::Instant::now();
        let shown = shown(&value, "<id>");
        let elapsed = started.elapsed();
        assert_eq!(shown, "<id>", "{shown}");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the decoder took {elapsed:?} on a megabyte"
        );
    }
}
