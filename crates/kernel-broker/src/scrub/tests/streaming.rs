//! The streaming hold window and the prefix-cut contract that keeps a
//! streamed scrub byte-identical to the whole-buffer one.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_hold_window_stays_within_its_bounds() {
        // The window is always in [MIN, MAX], whatever the registry holds,
        // and a registered value widens the spelling budget. (Values longer
        // than the cap are outside the streaming window contract; the whole
        // buffer pass still covers them.)
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_known_secrets();
        let window = streaming_hold_bytes();
        assert!(
            (MIN_STREAM_WINDOW..=MAX_STREAM_WINDOW).contains(&window),
            "window out of bounds: {window}"
        );
        let secret = format!("{}{}", "WINDOW", "W".repeat(64));
        assert!(register_known_secret(&secret));
        let window = streaming_hold_bytes();
        assert!(
            (MIN_STREAM_WINDOW..=MAX_STREAM_WINDOW).contains(&window),
            "window out of bounds after registration: {window}"
        );
        let expanded =
            (secret.len() * SPELLING_EXPANSION + STREAM_WINDOW_SLACK).min(MAX_STREAM_WINDOW);
        assert!(
            window >= expanded,
            "the registered value must widen the window: {window} < {expanded}"
        );
        clear_known_secrets();
    }

    /// The streaming cut contract: for every split of a pattern-shaped
    /// secret, `redact_secrets(raw[..cut])` is a byte-prefix of
    /// `redact_secrets(raw)`, so a writer that emits the prefix now and the
    /// remainder later streams exactly the whole-buffer scrub — and never a
    /// half-published token.
    #[test]
    fn stream_prefix_cut_contract_holds_at_every_split() {
        // Pattern-based (no registry mutation): a vendor token split at every
        // byte boundary inside two windows of filler.
        let token = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let filler = "The quick brown fox jumps over the lazy dog. ".repeat(24);
        for split in 1..token.len() {
            let mut raw = String::new();
            raw.push_str(&filler);
            raw.push_str(&token[..split]);
            let cut = stream_prefix_cut(&raw);
            let whole_prefix = crate::text::redact_secrets(&raw[..cut]);
            raw.push_str(&token[split..]);
            raw.push_str(&filler);
            let whole = crate::text::redact_secrets(&raw);
            assert!(
                whole.starts_with(whole_prefix.as_str()),
                "split {split}: the early cut is not a prefix of the whole scrub"
            );
            assert!(
                !whole_prefix.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
                "split {split}: a half token was published"
            );
            assert!(
                !whole.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
                "split {split}: the token survived the whole-buffer scrub"
            );
        }
    }

    /// A streaming writer that re-cuts as text arrives and finishes with the
    /// whole-buffer remainder produces exactly the whole-buffer scrub.
    #[test]
    fn stream_prefix_cut_streaming_matches_the_whole_buffer_scrub() {
        let token = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let raw = format!("{}token={}{}", "x".repeat(600), token, "y".repeat(600));
        let mut emitted = String::new();
        let mut cut = 0usize;
        for end in 1..=raw.len() {
            if !raw.is_char_boundary(end) {
                continue;
            }
            let next = stream_prefix_cut(&raw[..end]);
            if next > cut {
                emitted.push_str(&crate::text::redact_secrets(&raw[cut..next]));
                cut = next;
            }
        }
        // Final flush: the remainder of the whole-buffer scrub.
        let whole = crate::text::redact_secrets(&raw);
        assert!(whole.starts_with(emitted.as_str()));
        emitted.push_str(&whole[emitted.len()..]);
        assert_eq!(emitted, whole);
        assert!(!emitted.contains(token), "{emitted}");
    }
}
