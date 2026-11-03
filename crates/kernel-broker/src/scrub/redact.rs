//! The scrub pass: find every registered spelling in a text — raw, escaped,
//! condensed or folded — and mask the original spans with [`MASK`].

use super::fold::{condense, fold_nfkc, fold_unicode_escapes, is_scrub_noise};
use super::hex::{hex_spelling_ranges, hex_unit_at, text_may_hold_hex};
use super::registry::{ensure_matcher, read_registry, write_registry, Registry};
use super::stream::floor_char_boundary;
use super::MIN_KNOWN_SECRET_LEN;
use crate::text::MASK;

/// Replace every known value (or derived encoding) found in `text`.
///
/// Returns `None` when the registry is empty or nothing matched, so callers
/// can keep the original bytes without cloning. Matching is linear: one
/// automaton pass over the raw text and one over a condensed copy that drops
/// whitespace and invisible characters, so values split across lines or
/// stuffed with zero-width characters are still found.
pub fn redact_known_secrets(text: &str) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    {
        let registry = read_registry();
        if !registry.matcher_dirty {
            return redact_with_registry(&registry, text);
        }
    }
    let mut registry = write_registry();
    ensure_matcher(&mut registry);
    redact_with_registry(&registry, text)
}

/// [`redact_known_secrets`] against a registry whose automaton is current.
fn redact_with_registry(registry: &Registry, text: &str) -> Option<String> {
    let matcher = registry.matcher.as_ref()?;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for hit in matcher.find_overlapping_iter(text.as_bytes()) {
        ranges.push((hit.start(), hit.end()));
    }
    // SB6-01: a dump or an escaped copy is still the same secret. Scan the
    // text a second time as hex spellings (contiguous or separated by
    // whitespace/colons, `\xNN`/`%NN` escaped, `xxd`/`od`/`hexdump -C`
    // scaffolding) and match the decoded bytes through the same automaton.
    if text.len() <= u32::MAX as usize && text_may_hold_hex(text.as_bytes()) {
        let limit = registry.max_needle_len.saturating_add(1024).max(4096);
        ranges.extend(hex_spelling_ranges(text.as_bytes(), matcher, limit));
    }
    // The condensed copy catches inserted whitespace/newlines and
    // zero-width/invisible characters between a value's bytes. For plain
    // ASCII without whitespace it would be identical, so skip building it.
    let needs_condense = text.bytes().any(|byte| byte.is_ascii_whitespace()) || !text.is_ascii();
    if needs_condense && text.len() <= u32::MAX as usize {
        let (condensed, starts, ends) = condense(text);
        if condensed.len() >= MIN_KNOWN_SECRET_LEN && condensed != text {
            for hit in matcher.find_overlapping_iter(condensed.as_bytes()) {
                let start = starts[hit.start()] as usize;
                let end = ends[hit.end() - 1] as usize;
                ranges.push((start, end));
            }
        }
    }
    // R8: an NFKC-equivalent spelling (`ofﬁce` with a ligature, fullwidth or
    // superscript compatibility forms, a decomposed combining sequence) is
    // the same value to a human and to any NFKC normaliser. Fold the text
    // with real NFKC and match through the same automaton, mapping every hit
    // back to the original span; hex spellings written in compatibility
    // forms are decoded from the folded copy too.
    if text.len() <= u32::MAX as usize && !text.is_ascii() {
        let (folded, starts, ends) = fold_nfkc(text);
        if folded != text {
            for hit in matcher.find_overlapping_iter(folded.as_bytes()) {
                ranges.push((starts[hit.start()] as usize, ends[hit.end() - 1] as usize));
            }
            if text_may_hold_hex(folded.as_bytes()) {
                let limit = registry.max_needle_len.saturating_add(1024).max(4096);
                for (start, end) in hex_spelling_ranges(folded.as_bytes(), matcher, limit) {
                    ranges.push((starts[start] as usize, ends[end - 1] as usize));
                }
            }
        }
    }
    // R8: JSON/JS `\u` escapes — surrogate pairs included — are the same
    // characters; fold them and match, so a mixed spelling (raw text with
    // one escaped character) is caught too. Separated and hex-dump spellings
    // are handled by the decoded-run scanner.
    if text.len() <= u32::MAX as usize && (text.contains("\\u") || text.contains("\\U")) {
        let (unescaped, starts, ends) = fold_unicode_escapes(text);
        if unescaped != text {
            for hit in matcher.find_overlapping_iter(unescaped.as_bytes()) {
                ranges.push((starts[hit.start()] as usize, ends[hit.end() - 1] as usize));
            }
            if text_may_hold_hex(unescaped.as_bytes()) {
                let limit = registry.max_needle_len.saturating_add(1024).max(4096);
                for (start, end) in hex_spelling_ranges(unescaped.as_bytes(), matcher, limit) {
                    ranges.push((starts[start] as usize, ends[end - 1] as usize));
                }
            }
        }
    }
    // Keep the original scans; add matches from each decoded run.
    let mut offset = 0;
    for part in text.split_inclusive(char::is_whitespace) {
        let run = part.trim_end_matches(char::is_whitespace);
        if run.contains(['\\', '%', '&']) {
            let parse = |source: &str, at: usize| {
                let bytes = source.as_bytes();
                match bytes.get(at + 1) {
                    Some(b'\\') => Some(('\\', at + 2)),
                    Some(b'u' | b'U' | b'x' | b'X') => {
                        let (code, _, end) = hex_unit_at(bytes, at)?;
                        Some((char::from_u32(code)?, end))
                    }
                    _ => None,
                }
            };
            // One escape can only create a new match within a needle's reach.
            let mut scan_start = 0;
            let mut scan = run;
            if run.len() > kernel_privacy::decode::MAX_SECRET_DECODE_WORK / 3
                && (run.is_ascii()
                    || run
                        .chars()
                        .all(|c| !is_scrub_noise(c) && !matches!(c, '⟦' | '⟧')))
            {
                let mut markers = run
                    .match_indices(['\\', '%', '&'])
                    .filter(|(at, _)| kernel_privacy::decode::known_escape_at(run, *at, &parse));
                let first = markers.next();
                if first.is_none() {
                    offset += part.len();
                    continue;
                }
                if let (Some((at, _)), None) = (first, markers.next()) {
                    let margin = registry.max_needle_len.saturating_add(1024);
                    scan_start = floor_char_boundary(run, at.saturating_sub(margin));
                    let end = floor_char_boundary(run, at.saturating_add(margin).min(run.len()));
                    scan = &run[scan_start..end];
                }
            }
            let settled = kernel_privacy::DecodedText::scan_known_secret(
                scan,
                &parse,
                &mut |view, starts, bounds| {
                    for hit in matcher.find_overlapping_iter(view.as_bytes()) {
                        let first = starts.partition_point(|at| *at < hit.start());
                        let after = starts.partition_point(|at| *at < hit.end());
                        if first < after {
                            ranges.push((
                                offset + scan_start + bounds[first].0,
                                offset + scan_start + bounds[after - 1].1,
                            ));
                        }
                    }
                },
            );
            if !settled {
                ranges.push((offset, offset + run.len()));
            }
        }
        offset += part.len();
    }
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut copied = 0usize;
    for (start, end) in merged {
        if start > copied {
            out.push_str(&text[copied..start]);
        }
        out.push_str(MASK);
        copied = end;
    }
    out.push_str(&text[copied..]);
    Some(out)
}
