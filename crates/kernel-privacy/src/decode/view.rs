//! The decoded view and the map from decoded characters back to source bytes.

use super::escapes::{common_escape, EscapeParser};
use super::limits::{MAX_PASSES, MAX_SECRET_DECODE_WORK};
use super::pass::{decode_once, url_ranges, Markers};

type ViewVisitor<'a> = dyn FnMut(&str, &[usize], &[(usize, usize)]) + 'a;

/// A decoded view of a text plus the map from decoded characters back to the
/// original byte ranges.
pub struct DecodedText {
    text: String,
    /// Decoded byte offset of each decoded character.
    char_starts: Vec<usize>,
    /// Original byte range of each decoded character.
    char_bounds: Vec<(usize, usize)>,
    /// Source tokens still encoded after [`MAX_PASSES`]: masked whole.
    unresolved: Vec<(usize, usize)>,
    /// Whether a `⟦…⟧` pair was dropped with its content.
    dropped_marker_body: bool,
    /// Source range of every dropped marker: a lone bracket, or a pair with its
    /// content, written plainly or as entities.
    markers: Vec<(usize, usize)>,
    /// What this view did with the markers.
    mode: Markers,
}

impl DecodedText {
    /// Build the decoded view of `source`.
    ///
    /// HTML entities are decoded everywhere; percent escapes only inside a URL
    /// token. Decoding repeats to a fixed point, at most [`MAX_PASSES`] times,
    /// so a nested value (`%2540` → `%40` → `@`, `&AMP;eacute;` → `é`) folds to
    /// its final character. Each pass is linear, so the whole is linear. Every valid escape
    /// decodes on its own and each invalid one stays literal; the whole percent
    /// run is attributed to every character it produced, so a detection that
    /// covers only part of a partially decoded run still maps back to all of its
    /// source bytes.
    pub fn new(source: &str) -> Self {
        Self::build(source, Markers::Drop)
    }

    /// The same view, but a `⟦…⟧` pair loses only its brackets: a value written
    /// inside one (`⟦sk-…⟧`) is still read.
    pub fn brackets_only(source: &str) -> Self {
        Self::build(source, Markers::Brackets)
    }

    /// The same view, but each bracket reads as a space: a value it touches
    /// keeps its word boundary (`texte⟦sk-…⟧` reads `texte sk-… `).
    pub fn brackets_as_spaces(source: &str) -> Self {
        Self::build(source, Markers::Space)
    }

    /// Decode extra escapes; `brackets_only` retains marker bodies.
    pub fn escaped(source: &str, brackets_only: bool) -> Option<Self> {
        let mode = [Markers::Drop, Markers::Brackets][usize::from(brackets_only)];
        let has_common = |text: &str| {
            text.match_indices(['\\', '%'])
                .any(|(at, _)| common_escape(text, at).is_some())
        };
        let mut seen = has_common(source);
        let (mut view, settled) =
            Self::build_inner(source, mode, Some(&|_, _| None), &mut |text, _, _| {
                seen |= has_common(text);
            });
        if !settled && !source.is_empty() {
            view.unresolved.push((0, source.len()));
        }
        (seen || !settled).then_some(view)
    }

    fn build(source: &str, mode: Markers) -> Self {
        Self::build_inner(source, mode, None, &mut |_, _, _| {}).0
    }

    /// Whether decoding leaves `source` alone: only an ASCII text with no
    /// entity (`&`) and no percent escape decodes to itself.
    pub(crate) fn is_unchanged(source: &str) -> bool {
        source.is_ascii() && !source.bytes().any(|byte| matches!(byte, b'&' | b'%'))
    }

    /// Visit each decoded view of a known-secret run, mapped back to `source`.
    /// Returns false if decoding cannot settle within the shared limits.
    pub fn scan_known_secret(
        source: &str,
        escape: &EscapeParser<'_>,
        visit: &mut ViewVisitor<'_>,
    ) -> bool {
        if source.len() > MAX_SECRET_DECODE_WORK {
            return false;
        }
        Self::build_inner(source, Markers::Drop, Some(escape), visit).1
    }

    fn build_inner(
        source: &str,
        mode: Markers,
        escape: Option<&EscapeParser<'_>>,
        visit: &mut ViewVisitor<'_>,
    ) -> (Self, bool) {
        let mut dropped_marker_body = false;
        let mut text = source.to_string();
        let mut char_starts: Vec<usize> = Vec::with_capacity(source.len());
        let mut char_bounds: Vec<(usize, usize)> = Vec::with_capacity(source.len());
        for (index, ch) in source.char_indices() {
            char_starts.push(index);
            char_bounds.push((index, index + ch.len_utf8()));
        }
        let mut converged = false;
        let mut spent = 0usize;
        let budget = source
            .len()
            .saturating_mul(MAX_PASSES)
            .min(MAX_SECRET_DECODE_WORK);
        let mut markers: Vec<(usize, usize)> = Vec::new();
        for _ in 0..MAX_PASSES {
            if escape.is_some() && spent.saturating_add(text.len().saturating_mul(2)) > budget {
                break;
            }
            spent = spent.saturating_add(text.len());
            let (decoded, local_bounds, dropped, local_markers) = decode_once(&text, mode, escape);
            if decoded == text {
                converged = true;
                break;
            }
            if escape.is_some() && spent.saturating_add(decoded.len().saturating_mul(2)) > budget {
                break;
            }
            spent = spent.saturating_add(decoded.len());
            dropped_marker_body |= dropped;
            for (start, end) in local_markers {
                let first = char_starts.partition_point(|offset| *offset < start);
                let after = char_starts.partition_point(|offset| *offset < end);
                markers.push((char_bounds[first].0, char_bounds[after - 1].1));
            }
            let mut next_starts: Vec<usize> = Vec::with_capacity(decoded.len());
            let mut next_bounds: Vec<(usize, usize)> = Vec::with_capacity(decoded.len());
            // Local bounds only move forward, so two cursors replace a binary
            // search per character.
            let (mut first, mut after) = (0usize, 0usize);
            for ((offset, _), (start, end)) in
                decoded.char_indices().zip(local_bounds.iter().copied())
            {
                while first < char_starts.len() && char_starts[first] < start {
                    first += 1;
                }
                after = after.max(first);
                while after < char_starts.len() && char_starts[after] < end {
                    after += 1;
                }
                debug_assert!(
                    first < after,
                    "a decoded char maps to at least one source char"
                );
                next_starts.push(offset);
                next_bounds.push((char_bounds[first].0, char_bounds[after - 1].1));
            }
            text = decoded;
            char_starts = next_starts;
            char_bounds = next_bounds;
            if escape.is_some() {
                visit(&text, &char_starts, &char_bounds);
            }
        }
        if !converged && escape.is_some() && spent.saturating_add(text.len()) <= budget {
            converged = decode_once(&text, mode, escape).0 == text;
        }
        let mut view = Self {
            text,
            char_starts,
            char_bounds,
            unresolved: Vec::new(),
            dropped_marker_body,
            markers,
            mode,
        };
        view.markers.sort_unstable();
        if !converged && escape.is_none() {
            view.unresolved = view.unresolved_tokens(source, mode);
        }
        (view, converged)
    }

    /// Fail closed at the pass cap: every whitespace-delimited source token a
    /// further pass would still change.
    fn unresolved_tokens(&self, source: &str, mode: Markers) -> Vec<(usize, usize)> {
        let (decoded, local_bounds, _, _) = decode_once(&self.text, mode, None);
        let mut tokens: Vec<(usize, usize)> = Vec::new();
        for (ch, (start, end)) in decoded.chars().zip(local_bounds) {
            let same = self.text[start..end] == *ch.encode_utf8(&mut [0; 4]);
            let Some((from, to)) = self.source_bounds(start, end).filter(|_| !same) else {
                continue;
            };
            if tokens.last().is_some_and(|last| from < last.1) {
                continue;
            }
            let from = source[..from]
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_whitespace())
                .map_or(0, |(at, c)| at + c.len_utf8());
            let to = source[to..]
                .find(char::is_whitespace)
                .map_or(source.len(), |at| to + at);
            tokens.push((from, to));
        }
        tokens
    }

    /// Source ranges still encoded when decoding stopped at [`MAX_PASSES`].
    pub fn unresolved(&self) -> &[(usize, usize)] {
        &self.unresolved
    }

    /// Whether a `⟦…⟧` pair was dropped with its content.
    pub fn dropped_marker_body(&self) -> bool {
        self.dropped_marker_body
    }

    /// Source range of every dropped token marker (a lone `⟦` or `⟧`, or a
    /// `⟦…⟧` pair with its content), sorted by start.
    pub fn markers(&self) -> &[(usize, usize)] {
        &self.markers
    }

    /// Whether this view deletes the markers (dropped, or brackets only),
    /// rather than reading them as spaces.
    pub fn mode_drops_brackets(&self) -> bool {
        self.mode != Markers::Space
    }

    /// Whether the dropped marker at source range `marker` sits between two
    /// letters of this view (`chimioth⟦X⟧érapie`, `sk-abc⟦X def⟧` read with only
    /// the brackets gone): dropping it splices one word out of two.
    pub fn marker_joins_letters(&self, marker: (usize, usize)) -> bool {
        let letter = |index: usize| {
            self.char_starts
                .get(index)
                .and_then(|&at| self.text[at..].chars().next())
                .is_some_and(char::is_alphabetic)
        };
        // A dropped marker's bytes go to the next kept character.
        let after = self.char_bounds.partition_point(|b| b.1 <= marker.1);
        let before = self.char_bounds.partition_point(|b| b.1 <= marker.0);
        before > 0 && letter(before - 1) && letter(after)
    }

    /// The decoded text to scan.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Map a byte range in the decoded view back to the original bytes.
    ///
    /// Returns `None` when the range is empty, out of bounds or not on a char
    /// boundary. A range that spans a decoded entity returns the full original
    /// range of that entity, so masking covers every source byte of the value.
    pub fn source_bounds(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        if start >= end || end > self.text.len() {
            return None;
        }
        if !self.text.is_char_boundary(start) || !self.text.is_char_boundary(end) {
            return None;
        }
        let first = self.char_starts.partition_point(|offset| *offset < start);
        let after = self.char_starts.partition_point(|offset| *offset < end);
        if first >= after {
            return None;
        }
        let (orig_start, _) = self.char_bounds[first];
        let (_, orig_end) = self.char_bounds[after - 1];
        if orig_start >= orig_end {
            return None;
        }
        Some((orig_start, orig_end))
    }

    /// The path and query segments of every URL in `source`, with their
    /// original byte offsets.
    ///
    /// A segment is a maximal run of word characters; `-`, `_`, `.`, `+`, `/`,
    /// `?`, `&` and `=` all separate segments, so `linkedin.example.invalid/in/
    /// jules-ferrand` yields `linkedin`, `example`, `invalid`, `in`, `jules`
    /// and `ferrand`. Values that decode to nothing are skipped.
    pub fn url_segments(source: &str) -> Vec<(String, usize, usize)> {
        let mut segments = Vec::new();
        for (start, end) in url_ranges(source) {
            let decoded = DecodedText::new(&source[start..end]);
            let mut cursor = 0usize;
            let mut segment_start: Option<usize> = None;
            for (offset, ch) in decoded.text().char_indices() {
                if ch.is_alphanumeric() {
                    if segment_start.is_none() {
                        segment_start = Some(offset);
                    }
                } else if let Some(begin) = segment_start.take() {
                    if let Some((orig_start, orig_end)) = decoded.source_bounds(begin, offset) {
                        segments.push((
                            source[start + orig_start..start + orig_end].to_string(),
                            start + orig_start,
                            start + orig_end,
                        ));
                    }
                }
                cursor = offset + ch.len_utf8();
            }
            if let Some(begin) = segment_start {
                if let Some((orig_start, orig_end)) = decoded.source_bounds(begin, cursor) {
                    segments.push((
                        source[start + orig_start..start + orig_end].to_string(),
                        start + orig_start,
                        start + orig_end,
                    ));
                }
            }
        }
        segments
    }
}
