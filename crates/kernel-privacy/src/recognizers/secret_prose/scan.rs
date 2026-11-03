//! The prose scan, its keys run in order and merged into one span set.

use super::keys::{ATTR_CUE_RE, EXTRA_KEY_RE, KEY_RE, MAX_WORD, REVERSE_RE, WIFI_KEY_RE};
use super::rows::row_runs;
use super::runs::{group_runs, RecoveryRun};
use super::value::{attrs_end, class_of, core, is_value, strong, value_after, Class};
use super::wifi::wifi_word;

/// The secret spans of prose links, escaped keys and cookies in `text`.
pub(crate) fn prose_scan(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut reach = 0;
    for found in KEY_RE.captures_iter(text) {
        let Some(key) = found.get(1) else { continue };
        if key.start() < reach {
            continue;
        }
        let class = class_of(key.as_str());
        reach = key.end();
        if let Some((start, mut end)) = value_after(text, key.end(), class) {
            if class == Class::Cookie || text[start..end].contains('=') {
                end = attrs_end(text, end);
            }
            spans.push((start, end));
            reach = end;
        }
    }
    let mut reach = 0;
    for key in EXTRA_KEY_RE.find_iter(text) {
        if let Some(span) = value_after(text, key.end(), Class::Strong) {
            spans.push(span);
        }
        if key.start() >= reach {
            let recovery_codes = key.as_str().to_ascii_lowercase().contains("code");
            let mut recovery = RecoveryRun::default();
            reach = group_runs(text, key.end(), recovery_codes, &mut recovery, &mut spans);
            if recovery_codes {
                reach = reach.max(row_runs(text, key.end(), &mut recovery, &mut spans));
            }
        }
    }
    for key in WIFI_KEY_RE.find_iter(text) {
        spans.extend(wifi_word(text, key.end()));
    }
    for found in REVERSE_RE.captures_iter(text) {
        if let Some(value) = found.get(1) {
            let (start, end) = core(text, value.start(), value.end());
            if strong(&text[start..end]) {
                spans.push((start, end));
            }
        }
    }
    let mut reach = 0;
    for cue in ATTR_CUE_RE.find_iter(text) {
        if cue.start() < reach {
            continue;
        }
        let mut low = cue.start().saturating_sub(MAX_WORD);
        while !text.is_char_boundary(low) {
            low += 1;
        }
        let before = &text[low..cue.start()];
        let space = before
            .char_indices()
            .rev()
            .find(|(_, ch)| ch.is_whitespace());
        let from = match space {
            Some((at, ch)) => low + at + ch.len_utf8(),
            None if low == 0 => 0,
            None => continue,
        };
        let (start, _) = core(text, from, cue.start());
        if start < cue.start() && is_value(&text[start..cue.start()], Class::Cookie) {
            let end = attrs_end(text, cue.start());
            spans.push((start, end));
            reach = end;
        }
    }
    // The key scan and the cookie cue may find the same value: keep it once.
    spans.sort_unstable();
    spans.dedup();
    spans
}
