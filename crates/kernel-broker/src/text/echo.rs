//! Classifies whether a value is secret-shaped, including through repeated
//! percent-decoding, so callers can refuse to echo it.

use kernel_core::text::hex_value;

use super::*;

/// What an echo of a value may show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchoState {
    /// The value is not secret-shaped.
    Clean,
    /// The value is secret-shaped, raw or through a decoded copy.
    Secret,
    /// The decoder cannot settle the value inside its work budget.
    Unstable,
}

/// The raw value and every percent-decoded copy of it, classified.
///
/// The caller decides what to render: [`EchoState::Secret`] as
/// `<redacted>`/`<id>`, [`EchoState::Unstable`] as `[hidden]`. A provider id
/// is a name and a lookup handle, so a key-shaped name is refused rather than
/// stored or echoed.
pub fn classify_echo(text: &str) -> EchoState {
    if redact_secrets(text) != text {
        return EchoState::Secret;
    }
    // The scrubber has read the value once already: that read is charged to
    // the budget too.
    decoded_copy_state(text, text.len(), |copy| redact_secrets(copy) != copy)
}

/// True when `text` is secret-shaped, raw or through any decoded copy.
///
/// This is the one detector the provider layer and the store migrations use.
pub fn is_secret_shaped(text: &str) -> bool {
    !matches!(classify_echo(text), EchoState::Clean)
}

/// 32 escape layers: `%73k-…`, `%2573k-…` and `%25252573k-…` are one key.
const MAX_DECODE_ROUNDS: usize = 32;

/// The work budget of one value: every byte the scrubber or the decoder
/// reads is charged, at most 66 × the input and never over 4 MiB.
const MAX_REDACT_WORK: usize = 4 * 1024 * 1024;

/// How a percent-decoded copy of `text` reads. One escape layer per round,
/// only the current copy kept, every byte read charged to the budget. A value
/// still changing when the budget or [`MAX_DECODE_ROUNDS`] runs out is
/// [`EchoState::Unstable`], because it cannot be shown safely.
fn decoded_copy_state(
    text: &str,
    mut spent: usize,
    secret_shaped: impl Fn(&str) -> bool,
) -> EchoState {
    let budget = text.len().saturating_mul(66).min(MAX_REDACT_WORK);
    let mut current = text.to_string();
    for _ in 0..MAX_DECODE_ROUNDS {
        // A round that does not fit the budget is never started.
        if spent.saturating_add(current.len()) > budget {
            return EchoState::Unstable;
        }
        spent = spent.saturating_add(current.len());
        let next = match String::from_utf8(decode_once(&current)) {
            Ok(next) => next,
            // Bytes that are not valid UTF-8 cannot be shown safely.
            Err(_) => return EchoState::Unstable,
        };
        if next == current {
            // The text stopped changing: there is no deeper copy to read.
            return EchoState::Clean;
        }
        // The scrubber reads the copy too: its bytes are charged as well.
        if spent.saturating_add(next.len()) > budget {
            return EchoState::Unstable;
        }
        spent = spent.saturating_add(next.len());
        if secret_shaped(&next) {
            return EchoState::Secret;
        }
        current = next;
    }
    // The round cap ran out while the text was still changing.
    EchoState::Unstable
}

/// One percent-decoding round: the bytes of `text` with every valid `%XX`
/// escape replaced by its byte. A malformed escape is kept as written.
///
/// This is the broker's echo decoder. It keeps raw bytes because it compares a
/// decoded value against secret bytes, where any byte can matter. The privacy
/// crate has its own decoder that only yields printable ASCII or valid UTF-8,
/// so a detector never sees a broken byte sequence. The two are separate on
/// purpose; do not merge them.
fn decode_once(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(byte) = bytes.get(index + 1..index + 3).and_then(hex_pair) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// The byte of two hex digits.
fn hex_pair(pair: &[u8]) -> Option<u8> {
    match pair {
        [high, low] => Some((hex_value(*high)? << 4) | hex_value(*low)?),
        _ => None,
    }
}
