//! The normalised view: its shared scan cache, builders and exact offset map.
//!
//! A scan builds one view per OCR flag and shares it with every recogniser, so
//! the text is normalised once; every span maps back to the original bytes.

use std::cell::RefCell;
use std::sync::Arc;

use super::charset::{
    fold_ideographic_stop, is_line_break, is_line_break_or_tab, is_unicode_space, is_zero_width,
    normalize_char,
};
use super::digits::{fold_ocr_confusables, ocr_folds_at, ocr_would_fold};
use super::{NormalizedText, MAX_FOLDED_BREAKS, MAX_FOLDED_RUN, RUN_BOUNDARY};

/// One scan: its text (shared with an identity view, reusable) and two views.
struct Scan {
    source: Arc<String>,
    views: [Option<NormalizedText>; 2],
}

/// The scans on this thread; `depth` counts live ones, the rest are spare slots.
pub(super) struct Shared {
    scans: Vec<Scan>,
    pub(super) depth: usize,
}

thread_local! {
    pub(super) static SHARED: RefCell<Shared> = const {
        RefCell::new(Shared { scans: Vec::new(), depth: 0 })
    };
}

/// While alive, every [`NormalizedText::new`] of exactly this text shares one
/// view per `ocr` flag, so the recognisers of a scan normalise the text twice,
/// not once each (K-REGISTRY-PERF: two dozen whole-text passes were most of a
/// megabyte's scan). A view is a pure function of the text and the flag, so a
/// shared one is the value a fresh build returns. Dropping the guard (or a
/// panic unwinding past it) forgets the text and its views.
///
/// A scan that runs while a non-main thread is tearing down its thread-locals
/// — for example, another thread-local's `Drop` invoking the registry — calls
/// into `SHARED` after the storage is gone. `try_with` returns an `AccessError`
/// in that window, so the guard silently stays unregistered and its `Drop`
/// stays a no-op; every call falls back to a fresh build whose output is
/// byte-identical to the cached one (K-REGISTRY-PERF r1 fix for NO SEAL P2).
pub(crate) struct SharedViews(bool);

impl SharedViews {
    pub(crate) fn new(text: &str) -> Self {
        let registered = SHARED
            .try_with(|shared| {
                let mut shared = shared.borrow_mut();
                let depth = shared.depth;
                if depth < shared.scans.len() {
                    // Reuse the slot and its source allocation; a caller still
                    // holding a view keeps the old source alive, so replace it.
                    let scan = &mut shared.scans[depth];
                    scan.views = [None, None];
                    match Arc::get_mut(&mut scan.source) {
                        Some(source) => {
                            source.clear();
                            source.push_str(text);
                        }
                        None => scan.source = Arc::new(text.to_owned()),
                    }
                } else {
                    shared.scans.push(Scan {
                        source: Arc::new(text.to_owned()),
                        views: [None, None],
                    });
                }
                shared.depth += 1;
            })
            .is_ok();
        Self(registered)
    }
}

impl Drop for SharedViews {
    fn drop(&mut self) {
        if !self.0 {
            // Thread-local storage was already gone when the guard was built,
            // so nothing was pushed. Touching SHARED now would panic, and a
            // drop is the one place a panic is silently unobservable.
            return;
        }
        let _ = SHARED.try_with(|shared| {
            let mut shared = shared.borrow_mut();
            if shared.depth > 0 {
                let depth = shared.depth - 1;
                shared.depth = depth;
                // Release the views; the slot's source stays for reuse.
                shared.scans[depth].views = [None, None];
            }
        });
    }
}

impl NormalizedText {
    /// Build the normalised view. `ocr` enables the digit-run confusable fold.
    pub fn new(text: &str, ocr: bool) -> Self {
        let slot = usize::from(ocr);
        // The cache lives in a thread-local. While the current thread's
        // thread-locals are being torn down (for example inside another
        // thread-local's `Drop`) `try_with` fails with `AccessError`; fall
        // back to a fresh build whose output is byte-identical to the cached
        // view, so the recognition result never depends on the cache.
        let found = SHARED.try_with(|shared| {
            let shared = shared.borrow();
            let depth = shared.depth;
            if depth == 0 {
                return None;
            }
            let scan = shared.scans.get(depth - 1)?;
            if scan.source.as_str() != text {
                return None;
            }
            Some((scan.views[slot].clone(), Arc::clone(&scan.source)))
        });
        match found {
            Err(_) | Ok(None) => Self::build(text, ocr),
            Ok(Some((Some(view), _))) => view,
            Ok(Some((None, source))) => {
                let view = Self::build_shared(&source, ocr);
                let _ = SHARED.try_with(|shared| {
                    let mut shared = shared.borrow_mut();
                    let depth = shared.depth;
                    if let Some(scan) = shared.scans.get_mut(depth.wrapping_sub(1)) {
                        if Arc::ptr_eq(&scan.source, &source) {
                            scan.views[slot] = Some(view.clone());
                        }
                    }
                });
                view
            }
        }
    }

    /// The view of `text`: identity, else the ASCII or general builder.
    pub(super) fn build(text: &str, ocr: bool) -> Self {
        if is_identity(text, ocr) {
            return Self::identity(Arc::new(text.to_owned()));
        }
        if text.is_ascii() {
            return Self::build_ascii(text, ocr);
        }
        Self::build_slow(text, ocr)
    }

    /// [`NormalizedText::build`] sharing the scan's source for an identity view.
    fn build_shared(source: &Arc<String>, ocr: bool) -> Self {
        if is_identity(source, ocr) {
            return Self::identity(Arc::clone(source));
        }
        if source.is_ascii() {
            return Self::build_ascii(source, ocr);
        }
        Self::build_slow(source, ocr)
    }

    fn identity(text: Arc<String>) -> Self {
        Self {
            text,
            char_starts: Arc::from(Vec::new()),
            orig_bounds: Arc::from(Vec::new()),
            identity: true,
            compact: true,
        }
    }

    /// The ASCII view: one byte per char, so `char_starts` is implicit.
    fn build_ascii(text: &str, ocr: bool) -> Self {
        let bytes = text.as_bytes();
        if has_soft_break(bytes) {
            return Self::build_slow(text, ocr);
        }
        let mut normalized: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut orig_bounds: Vec<(usize, usize)> = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if !is_ascii_separator(bytes[index]) {
                normalized.push(bytes[index]);
                orig_bounds.push((index, index + 1));
                index += 1;
                continue;
            }
            let start = index;
            while index < bytes.len() && is_ascii_separator(bytes[index]) {
                index += 1;
            }
            let group = &bytes[start..index];
            if group.iter().copied().any(is_ascii_break_or_tab) {
                normalized.push(if ascii_run_folds(group) { b' ' } else { 0 });
                orig_bounds.push((start, index));
            } else {
                for (at, &byte) in bytes[start..index].iter().enumerate() {
                    normalized.push(byte);
                    orig_bounds.push((start + at, start + at + 1));
                }
            }
        }
        if ocr {
            for at in 0..normalized.len() {
                if matches!(normalized[at], b'O' | b'o' | b'l' | b'I')
                    && ocr_folds_at(&normalized, at)
                {
                    normalized[at] = match normalized[at] {
                        b'O' | b'o' => b'0',
                        _ => b'1',
                    };
                }
            }
        }
        Self {
            text: Arc::new(String::from_utf8(normalized).expect("ASCII view")),
            char_starts: Arc::from(Vec::new()),
            orig_bounds: orig_bounds.into(),
            identity: false,
            compact: true,
        }
    }

    pub(super) fn build_slow(text: &str, ocr: bool) -> Self {
        let source = without_soft_breaks(text);
        let mut chars: Vec<char> = Vec::with_capacity(source.len());
        let mut orig_bounds: Vec<(usize, usize)> = Vec::with_capacity(source.len());
        let mut index = 0;
        while index < source.len() {
            // A run of separator characters is scanned once, so a long run of
            // plain spaces costs linear time (one pass per run, not per char).
            let run = separator_run_len(&source[index..]);
            let span = run.max(1);
            let group = &source[index..index + span];
            let breaks = group.iter().any(|&(_, ch)| is_line_break_or_tab(ch));
            // A zero-width character counts toward the cap too, so an invisible
            // run longer than the cap is a boundary even without a line break.
            let invisible = span > MAX_FOLDED_RUN && group.iter().any(|&(_, ch)| is_zero_width(ch));
            if run > 0 && (breaks || invisible) {
                // A line break, a tab or an over-long invisible run is one
                // separator: a run within the caps becomes a single space, a
                // longer one a hard boundary. Either way its original bytes
                // (every `\r`, `\n`, tab, space and invisible character in it)
                // stay in the span.
                let (first, _) = group[0];
                let (last, last_ch) = group[span - 1];
                chars.push(if run_folds(group) { ' ' } else { RUN_BOUNDARY });
                orig_bounds.push((first, last + last_ch.len_utf8()));
            } else {
                for &(offset, ch) in group {
                    if let Some(mapped) = normalize_char(ch) {
                        chars.push(mapped);
                        orig_bounds.push((offset, offset + ch.len_utf8()));
                    }
                }
            }
            index += span;
        }
        fold_ideographic_stop(&mut chars);
        if ocr {
            fold_ocr_confusables(&mut chars);
        }
        let mut normalized = String::with_capacity(chars.len());
        let mut char_starts = Vec::with_capacity(chars.len());
        for ch in &chars {
            char_starts.push(normalized.len());
            normalized.push(*ch);
        }
        Self {
            text: Arc::new(normalized),
            char_starts: char_starts.into(),
            orig_bounds: orig_bounds.into(),
            identity: false,
            compact: false,
        }
    }

    /// The normalised text to scan.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Map a byte range in the normalised text back to original byte offsets.
    ///
    /// Returns `None` when the range is empty, out of bounds or not on a char
    /// boundary. Zero-width characters stripped inside the range are included
    /// in the original bounds, so masking covers them too.
    pub fn to_original(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        if start >= end || end > self.text.len() {
            return None;
        }
        if !self.text.is_char_boundary(start) || !self.text.is_char_boundary(end) {
            return None;
        }
        if self.identity {
            return Some((start, end));
        }
        let (first, after) = if self.compact {
            (start, end)
        } else {
            (
                self.char_starts.partition_point(|offset| *offset < start),
                self.char_starts.partition_point(|offset| *offset < end),
            )
        };
        if first >= after {
            return None;
        }
        let (orig_start, _) = self.orig_bounds[first];
        let (_, orig_end) = self.orig_bounds[after - 1];
        if orig_start >= orig_end {
            return None;
        }
        Some((orig_start, orig_end))
    }
}

/// Whether normalisation returns `text` unchanged: every character maps to
/// itself, none is dropped, no run folds, and the OCR fold does nothing.
fn is_identity(text: &str, ocr: bool) -> bool {
    if text.is_ascii() {
        if text
            .bytes()
            .any(|byte| matches!(byte, b'\n' | b'\r' | b'\t' | 0x0b | 0x0c))
        {
            return false;
        }
        return !ocr || !ocr_would_fold(text.as_bytes());
    }
    for ch in text.chars() {
        if is_line_break_or_tab(ch)
            || matches!(ch, '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{3002}')
            || normalize_char(ch) != Some(ch)
        {
            return false;
        }
    }
    !ocr || !ocr_would_fold(text.as_bytes())
}

/// The separator bytes of an ASCII text: space, tab and the ASCII line breaks.
fn is_ascii_separator(byte: u8) -> bool {
    byte == b' ' || is_ascii_break_or_tab(byte)
}

fn is_ascii_break_or_tab(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

/// Whether a quoted-printable soft break starts in `bytes`.
fn has_soft_break(bytes: &[u8]) -> bool {
    let mut at = 0;
    while let Some(found) = bytes[at..].iter().position(|&byte| byte == b'=') {
        let mut cursor = at + found + 1;
        while matches!(bytes.get(cursor), Some(b' ' | b'\t')) {
            cursor += 1;
        }
        if matches!(bytes.get(cursor), Some(b'\r' | b'\n')) {
            return true;
        }
        at += found + 1;
    }
    false
}

/// [`run_folds`] for one ASCII separator run.
fn ascii_run_folds(group: &[u8]) -> bool {
    let (mut breaks, mut previous) = (0usize, None);
    for &byte in group {
        // A tab is no line break here: it makes the run fold, but it does not
        // count toward the break cap (as `run_folds` counts them).
        if matches!(byte, b'\n' | b'\r' | 0x0b | 0x0c)
            && !(byte == b'\n' && previous == Some(b'\r'))
        {
            breaks += 1;
        }
        previous = Some(byte);
    }
    breaks <= MAX_FOLDED_BREAKS && group.len() <= MAX_FOLDED_RUN
}

/// Whether a separator run folds to one space: at most
/// [`MAX_FOLDED_BREAKS`] line breaks (a CRLF counts once) and at most
/// [`MAX_FOLDED_RUN`] separator characters in all. Zero-width characters count
/// too, so an invisible run cannot stretch a masked region either.
fn run_folds(group: &[(usize, char)]) -> bool {
    let mut breaks = 0;
    let mut previous = None;
    for &(_, ch) in group {
        if is_line_break(ch) && !(ch == '\n' && previous == Some('\r')) {
            breaks += 1;
        }
        previous = Some(ch);
    }
    breaks <= MAX_FOLDED_BREAKS && group.len() <= MAX_FOLDED_RUN
}

/// Characters that can sit inside a run of separators: spaces, line breaks,
/// tabs and zero-width characters.
fn is_separator_run(ch: char) -> bool {
    ch == ' ' || is_line_break_or_tab(ch) || is_unicode_space(ch) || is_zero_width(ch)
}

/// Length of the run of separator characters at the start of `source` (0 when
/// its first character is not one).
fn separator_run_len(source: &[(usize, char)]) -> usize {
    source
        .iter()
        .take_while(|&&(_, ch)| is_separator_run(ch))
        .count()
}

/// The chars of `text` with every quoted-printable soft break removed, each kept
/// char paired with its original byte offset.
///
/// A soft break is what a mail client writes when it wraps a long line. Removing
/// it before the folds means the two sides join with nothing between them, so
/// `name=\r\n@example.invalid` scans as `name@example.invalid`. The removed bytes
/// still lie inside the offsets of the chars on either side, so a span that
/// straddles the wrap covers them.
fn without_soft_breaks(text: &str) -> Vec<(usize, char)> {
    // No `=` means no soft break: one pass, one buffer.
    if !text.contains('=') {
        return text.char_indices().collect();
    }
    let all: Vec<(usize, char)> = text.char_indices().collect();
    let mut kept = Vec::with_capacity(all.len());
    let mut index = 0;
    while index < all.len() {
        let skipped = soft_break_len(&all[index..]);
        if skipped > 0 {
            index += skipped;
        } else {
            kept.push(all[index]);
            index += 1;
        }
    }
    kept
}

/// The number of chars of the soft break at the start of `source`, or 0 when no
/// soft break starts there. The break is an `=`, any blanks (spaces, tabs and
/// the other blanks [`is_separator_run`] takes), then `\r\n`, `\r` or `\n`. A
/// plain `=` (`id=123`, `x = 1`, a trailing `=`) is not one.
fn soft_break_len(source: &[(usize, char)]) -> usize {
    if source.first().map(|&(_, ch)| ch) != Some('=') {
        return 0;
    }
    let blanks = source[1..]
        .iter()
        .take_while(|&&(_, ch)| is_separator_run(ch) && !is_line_break(ch))
        .count();
    let line_break = match source.get(1 + blanks).map(|&(_, ch)| ch) {
        Some('\r') if source.get(2 + blanks).map(|&(_, ch)| ch) == Some('\n') => 2,
        Some('\r' | '\n') => 1,
        _ => return 0,
    };
    1 + blanks + line_break
}
