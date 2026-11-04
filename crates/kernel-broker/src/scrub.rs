//! Exact-value redaction of the secrets this process *knows*.
//!
//! The heuristic layers in `crate::text` are shape-based: they recognise
//! credential *names* and vendor prefixes, but a value with no name in front
//! of it (a sentence, a tool argument, an encoded copy) is invisible to
//! them. Shape-driven patching is open-ended — a value can hide in any
//! number of spellings — so this module adds a precise first layer instead:
//! every secret
//! Auxesis itself resolves — provider keys (`AUX_KEY_*` from `.env` or the
//! process environment), the API bearer token, and any key the engine loads
//! at runtime — is registered here, and every scrub surface replaces those
//! exact values (and their common transforms) by substring before the
//! heuristic layers run.
//!
//! Guarantees:
//!
//! - **Exact.** Only registered values and their derived encodings match;
//!   the layer is off (zero cost) when the registry is empty.
//! - **Minimum length 8.** A shorter value would make false positives likely
//!   for a substring search, so it is left to the heuristic layers.
//! - **Linear.** One Aho-Corasick automaton over all needles, plus a second
//!   scan over a whitespace/zero-width-condensed copy of the text (so a
//!   value split across lines or stuffed with invisible characters still
//!   matches); both scans and the range merge are linear in the text.
//! - **Never logged, never formatted.** `KnownSecret` has a custom `Debug`
//!   impl that prints `<redacted>` and zeroes its buffer on drop; nothing in
//!   this module ever writes a value into a log line or an error message.
//! - **Withheld from streaming output.** [`streaming_hold_bytes`] returns the
//!   fixed trailing window a streaming writer must hold back so a value (or
//!   a heuristic match in progress) cannot leave half-formed; the writer then
//!   emits a prefix of the *whole-buffer* scrub, which never splits a match.
//!
//! The heuristic layers stay as the fallback for secrets this process has
//! never seen; their documented residuals are unchanged.
//!
//! # Scrubber limits (frozen)
//!
//! The exact-value layer covers a registered value's **raw form plus a closed
//! composition closure of encodings to depth 2**: base64 (standard and
//! URL-safe, padded and unpadded), base32, hex (contiguous, `: - space`
//! separated, `\x`/`0x`), percent-encoding (full, minimal, all-byte), JSON
//! `\u` escapes, HTML entities and NFKC forms, composed in every pair
//! (base64-of-hex, hex-of-base64, percent-of-base64, …). Every registered
//! value's raw form is always a needle; a value longer than
//! [`MAX_KNOWN_SECRET_LEN`] is refused, and a value whose closure exceeds its
//! byte budget — always the case from 410 value bytes, where the `0x`-of-hex
//! composition passes the needle cap — is flagged [`registry_oversized`], so
//! live streams fail closed (whole-message placeholder) instead of silently
//! missing a spelling; registration logs one warning with the source label
//! from 400 bytes up (never the value).
//!
//! No finite closure can be complete: an attacker who can inject instructions
//! can always ask the model for an encoding outside it (ROT13, reversed,
//! letter-spaced, translated, a one-time pad). The **real defences** are that
//! secrets are never placed in model context, untrusted content is tainted,
//! egress is approval-gated, and tool outputs are redacted per turn. This
//! scrubber is defence in depth and is **frozen after this round**: no
//! further spelling families without an explicit owner request.

mod encodings;
mod fold;
mod hex;
mod redact;
mod registry;
mod stream;
mod variants;

pub use redact::redact_known_secrets;
pub use registry::{
    clear_known_secrets, pin_known_secrets, register_known_secret,
    register_known_secrets_from_home, registry_generation, registry_oversized, registry_saturated,
    unpin_known_secrets,
};
pub use stream::{stream_prefix_cut, streaming_hold_bytes};

/// Values shorter than this are never registered: a substring search on a
/// short value would redact ordinary text. The heuristic layers still cover
/// short credentials in a recognisable shape.
pub const MIN_KNOWN_SECRET_LEN: usize = 8;

/// Longest registered value. Keys are far shorter; a file that claims
/// otherwise is not a credential and would only make the automaton huge.
pub const MAX_KNOWN_SECRET_LEN: usize = 4096;

/// Upper bound on registered values, so a hostile `.env` cannot turn every
/// later scrub into a multi-thousand-pattern search. When full, the oldest
/// *unpinned* registration is evicted (a rotated key must still be picked
/// up). Values pinned by live streams are never evicted.
pub const MAX_KNOWN_SECRETS: usize = 128;

/// Hard ceiling for the pinned case: a registry may grow past
/// [`MAX_KNOWN_SECRETS`] while every value is pinned by a live stream, but
/// never past this. At the ceiling, a new value is refused and the registry
/// reports [`registry_saturated`], so live streams fail closed with a
/// visible placeholder instead of leaking unscrubbed text.
pub const MAX_KNOWN_SECRETS_HARD: usize = MAX_KNOWN_SECRETS * 2;

// The tests drive the private helpers and registry internals directly, as
// they did when this was one file; keep those names on the test-only path,
// not the crate one.
#[cfg(test)]
use crate::text::MASK;

#[cfg(test)]
use encodings::{hex_encode, hex_separated, percent_encode, surrogate_pair};

#[cfg(test)]
use fold::fold_nfkc;

#[cfg(test)]
use registry::{
    is_known_secret_name, read_registry, KnownSecret, Registry, API_TOKEN_FILE, ENV_FILE,
};

#[cfg(test)]
use stream::{MAX_STREAM_WINDOW, MIN_STREAM_WINDOW, SPELLING_EXPANSION, STREAM_WINDOW_SLACK};

#[cfg(test)]
use variants::{apply_transform, MAX_VARIANT_LEN, TRANSFORMS};

#[cfg(test)]
mod tests;
