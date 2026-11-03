//! The streaming contract: the trailing window a writer must hold back and
//! the largest prefix it may publish without splitting a mask.

use super::registry::read_registry;
use crate::text::{PAIR_SKIP_LIMIT, QUOTED_SCAN_LIMIT};

/// Slack above the longest registered spelling: a value can only be held for
/// its own length, so a larger hold means an open construct.
pub(super) const STREAM_WINDOW_SLACK: usize = 64;

/// Bytes per value byte of the widest registered spelling: `\xNN`/`0xNN` cost
/// four, `%NN` three, and a separator (or an invisible character the
/// condensed scan drops) may sit between units; six covers every documented
/// family with margin.
pub(super) const SPELLING_EXPANSION: usize = 6;

/// Lower/upper bounds on [`streaming_hold_bytes`]: never less than a small
/// tail, never more than a few KiB, so streaming latency and memory stay
/// bounded even for a hostile registry.
pub(super) const MIN_STREAM_WINDOW: usize = 256;

pub(super) const MAX_STREAM_WINDOW: usize = 4096;

/// How far back a name run is scanned before a separator. Mirrors the
/// tokenizer's bounded scans; a construct cannot start further back than
/// this plus its separator and value windows.
const HEURISTIC_NAME_SCAN: usize = 96;

/// Fixed trailing window (bytes) a streaming writer must withhold from a
/// text buffer before emitting a prefix of it.
///
/// The window is derived from the registry, not from the text: the longest
/// registered value may still be spelled out (hex, `\xNN`, `0xNN`, `%NN`,
/// base64, base32, JSON-escaped, case-folded) with separators or invisible
/// characters between its bytes, and a heuristic construct in progress (a
/// pair's value, a `Bearer` keyword, a quoted or unquoted name) may span the
/// tokenizer's bounded scan windows. Holding back this many trailing bytes
/// means a future chunk cannot complete any of those constructs *before* the
/// hold: the whole-buffer scrub of the next state still starts with the same
/// bytes, so a streaming emitter can release the prefix and later match the
/// whole-buffer result exactly.
///
/// The result is clamped to `MIN_STREAM_WINDOW`..=`MAX_STREAM_WINDOW`;
/// a registered value longer than the cap is outside the streaming window
/// contract, but the whole-buffer pass (and therefore the final output) is
/// unaffected.
pub fn streaming_hold_bytes() -> usize {
    let registry = read_registry();
    let longest = registry
        .values
        .iter()
        .map(|secret| secret.value().len())
        .max()
        .unwrap_or(0);
    // An in-progress heuristic construct spans the pair-skip window, a quoted
    // value's scan window and the name before its separator.
    let heuristic = PAIR_SKIP_LIMIT + QUOTED_SCAN_LIMIT + HEURISTIC_NAME_SCAN;
    let expanded = longest
        .saturating_mul(SPELLING_EXPANSION)
        .max(heuristic)
        .saturating_add(STREAM_WINDOW_SLACK);
    expanded.clamp(MIN_STREAM_WINDOW, MAX_STREAM_WINDOW)
}

/// How many times the streaming cut moves back before giving up for this
/// call; the next call happens after more text arrives.
const MAX_STREAM_BACKOFF_ATTEMPTS: usize = 6;

/// Largest raw-prefix length of `raw` a streaming writer may publish now,
/// using the fixed trailing window ([`streaming_hold_bytes`]).
///
/// Contract: the returned prefix
/// * ends on a char boundary and outside a token run,
/// * lies at least one window away from the end of `raw`,
/// * and `crate::text::redact_secrets(&raw[..cut])` is a byte-prefix of the
///   whole-buffer scrub of `raw`.
///
/// A writer that emits `redact_secrets(&raw[..cut])` now and later emits the
/// remainder of `redact_secrets(raw)` therefore streams byte-identical text
/// to the whole-buffer scrub: no mask ever straddles a frame boundary and
/// the final flush equals `redact_secrets(whole)`. Returns `0` while nothing
/// is stable (the window covers the buffer, or a construct cannot be
/// resolved yet).
pub fn stream_prefix_cut(raw: &str) -> usize {
    if raw.is_empty() {
        return 0;
    }
    let window = streaming_hold_bytes();
    let mut cut = run_start(
        raw,
        floor_char_boundary(raw, raw.len().saturating_sub(window)),
    );
    if cut == 0 {
        return 0;
    }
    let whole = crate::text::redact_secrets(raw);
    let mut attempts = 0usize;
    loop {
        let prefix = crate::text::redact_secrets(&raw[..cut]);
        if whole.starts_with(prefix.as_str()) {
            return cut;
        }
        // A mask straddles the cut: move it back before that region.
        let divergence = common_prefix_len(whole.as_bytes(), prefix.as_bytes());
        let back = prefix.len().saturating_sub(divergence).max(1);
        let next = run_start(raw, floor_char_boundary(raw, cut.saturating_sub(back)));
        attempts += 1;
        if next >= cut || next == 0 || attempts >= MAX_STREAM_BACKOFF_ATTEMPTS {
            return 0;
        }
        cut = next;
    }
}

/// If `cut` splits a run, move it to the run's first byte: a token, a vendor
/// key or a JWT is only recognisable whole (or from its own start), so no
/// frame boundary may fall inside one.
fn run_start(text: &str, cut: usize) -> usize {
    if cut == 0 || cut >= text.len() {
        return cut;
    }
    text[..cut]
        .char_indices()
        .rev()
        .take_while(|(at, _)| cut - *at <= MAX_STREAM_WINDOW)
        .find(|(_, ch)| ch.is_whitespace())
        .map_or(0, |(at, ch)| at + ch.len_utf8())
}

/// Floor `at` onto a UTF-8 char boundary of `text`.
pub(super) fn floor_char_boundary(text: &str, at: usize) -> usize {
    let bytes = text.as_bytes();
    let mut at = at.min(bytes.len());
    while at > 0 && at < bytes.len() && (bytes[at] & 0xC0) == 0x80 {
        at -= 1;
    }
    at
}

/// Longest common byte prefix of two slices.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .take_while(|(left, right)| left == right)
        .count()
}
