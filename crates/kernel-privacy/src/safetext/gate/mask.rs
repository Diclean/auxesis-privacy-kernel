//! Masking: the tokenising and passthrough paths, the residue rounds, and the
//! per-session token views they detect on.

use std::collections::BTreeSet;

use kernel_core::privacy::GrantPolicy;

use crate::recognizer::MARKER_RUN;
use crate::span::{EntityKind, Span};

use super::Gate;
use crate::safetext::prohibited::{
    consolidate_mask_spans, export_spans, remove_prohibited, report_of, take_widened,
};
use crate::safetext::report::{DetectError, DetectionReport, GateError};
use crate::safetext::residue::{
    clear_parts, is_stand_in_only, residue_in_text, url_tails, RESIDUE_ROUNDS,
};
use crate::safetext::tokens::{blank_minted, strip_tokens, token_ranges, TokenRange};

/// A person's `span` without a trailing `'s`: a token is keyed by its surface, so
/// `Mira Fictive's` would be a second person.
fn without_possessive(text: &str, span: Span) -> Span {
    if span.kind != EntityKind::Person {
        return span;
    }
    let name = text
        .get(span.start..span.end)
        .unwrap_or_default()
        .strip_suffix(['s', 'S'])
        .and_then(|head| head.strip_suffix(['\'', '’', 'ʼ']));
    match name {
        Some(name) if name.ends_with(char::is_alphabetic) => Span {
            end: span.start + name.len(),
            ..span
        },
        _ => span,
    }
}

impl Gate {
    /// Detection runs on the input. A passthrough gate returns the text
    /// unchanged; a tokenising gate masks each span, then scans the clear parts
    /// of the masked output once more: they must hold no detectable value.
    pub(super) fn mask(&mut self, text: &str) -> Result<(String, DetectionReport), GateError> {
        match self.session_tokens.clone() {
            Some(minted) => self.mask_keeping(text, &minted),
            // A tokenising gate reads a foreign token's text both ways too, so
            // a value it splits is still masked.
            None if self.policy == GrantPolicy::Tokenised => {
                self.mask_keeping(text, &BTreeSet::new())
            }
            None => self.mask_clear(text),
        }
    }

    /// [`Gate::mask`] for a gate that keeps the session's tokens. Detection
    /// reads the **whole** text, in two views of it: with each minted token
    /// replaced by blanks of the same length (a token separates the values
    /// around it; any other token-shaped string is plain text, read as it is);
    /// and with every token-shaped string (minted or not) deleted, so a value a
    /// token splits (`mara@⟦…⟧example.test`) is read the way a server that
    /// deletes the token reads it. Every span found in either view is masked; a span
    /// that touches a token masks it too. Only a minted token no span touches
    /// stays, whole, and the text between kept tokens is masked.
    fn mask_keeping(
        &mut self,
        text: &str,
        minted: &BTreeSet<String>,
    ) -> Result<(String, DetectionReport), GateError> {
        let tokens = token_ranges(text, minted);
        if tokens.is_empty() {
            return self.mask_clear(text);
        }
        let blanked = blank_minted(text, &tokens);
        let (stripped, segments) = strip_tokens(text, &tokens);
        for view in [blanked.as_ref(), stripped.as_str()] {
            if crate::recognizers::secrets::value_too_long(view) {
                return Err(GateError::Detect(DetectError::TooLong));
            }
        }
        let ((mut spans, blanked_covered), (stripped_spans, stripped_covered)) =
            self.detector.detect_pair_covered(&blanked, &stripped)?;
        self.names_run =
            Some(self.names_run.unwrap_or(true) && blanked_covered && stripped_covered);
        let mut extra = export_spans(&blanked);
        spans.extend(stripped_spans.into_iter().filter_map(|span| {
            let start = segments.original(span.start, false)?;
            let end = segments.original(span.end, true)?;
            Some(Span { start, end, ..span })
        }));
        extra.extend(take_widened(&mut spans));
        // A span that touches a token takes all of it. Tokens and (after the
        // merge) spans are sorted and disjoint: binary searches and one
        // cursor keep this linear-log in their number.
        for span in &mut spans {
            let mut at = tokens.partition_point(|t| t.end <= span.start);
            while at < tokens.len() && tokens[at].start < span.end {
                span.start = span.start.min(tokens[at].start);
                span.end = span.end.max(tokens[at].end);
                at += 1;
            }
        }
        for span in &mut extra {
            let mut at = tokens.partition_point(|t| t.end <= span.start);
            while at < tokens.len() && tokens[at].start < span.end {
                span.start = span.start.min(tokens[at].start);
                span.end = span.end.max(tokens[at].end);
                at += 1;
            }
        }
        let spans = consolidate_mask_spans(spans);
        let report = report_of(self.policy, &spans, &extra);
        let mut out = String::with_capacity(text.len());
        let mut from = 0;
        let kept = tokens.iter().filter(|t| {
            let at = spans.partition_point(|s| s.end <= t.start);
            spans.get(at).is_none_or(|s| t.end <= s.start)
        });
        let mut next = 0;
        for token in kept.chain(std::iter::once(&TokenRange {
            start: text.len(),
            end: text.len(),
        })) {
            let first = next;
            while next < spans.len() && spans[next].end <= token.start {
                next += 1;
            }
            let piece: Vec<Span> = spans[first..next]
                .iter()
                .filter(|s| from <= s.start)
                .map(|s| Span {
                    start: s.start - from,
                    end: s.end - from,
                    ..*s
                })
                .collect();
            // An export span keeps to the piece: the tokens kept are main's.
            let added: Vec<Span> = extra
                .iter()
                .filter(|s| s.start < token.start && from < s.end)
                .map(|s| Span {
                    start: s.start.max(from) - from,
                    end: s.end.min(token.start) - from,
                    ..*s
                })
                .collect();
            out.push_str(&self.apply_spans(&text[from..token.start], &piece, &added)?);
            out.push_str(&text[token.start..token.end]);
            from = token.end;
        }
        Ok((out, report))
    }

    fn mask_clear(&mut self, text: &str) -> Result<(String, DetectionReport), GateError> {
        if text.is_empty() {
            return Ok((String::new(), DetectionReport::empty(self.policy)));
        }
        // This path has no issued-token context, so every marker is detector input.
        let view = blank_minted(text, &token_ranges(text, &BTreeSet::new()));
        let (mut spans, covered) = self.detector.detect_covered(&view)?;
        let mut extra = export_spans(&view);
        extra.extend(take_widened(&mut spans));
        if self.policy == GrantPolicy::Passthrough && view.as_ref() != text {
            // The blanked view holds no token, so it never sees one that splices
            // a word: that run fails closed on the text itself, as the registry
            // and the tokenising gate read it.
            let raw = self.detector.residue(text)?;
            extra.extend(raw.into_iter().filter(|span| span.recognizer == MARKER_RUN));
        }
        self.names_run = Some(self.names_run.unwrap_or(true) && covered);
        let report = report_of(self.policy, &spans, &extra);
        if self.policy == GrantPolicy::Passthrough {
            // Open mode returns ordinary text unchanged, but a prohibited
            // class (IBAN, card, ID, health, secret, address) is replaced, never
            // returned. Each maximal merged range is written once; every
            // other span is left exactly as it was.
            spans.extend(extra);
            return Ok((remove_prohibited(text, &spans), report));
        }
        Ok((self.apply_spans(text, &spans, &extra)?, report))
    }

    /// Mask `spans` of `text` and scan what is left in clear, then mask
    /// `extra` on top of that.
    ///
    /// The residue rounds re-read the masked view, and what
    /// they find depends on what was masked first, so a span added up front
    /// can make them hide less. `extra` is added only once main's rounds have
    /// settled: the rounds run again from main's final spans plus `extra`, and
    /// spans only grow, so every byte main hides stays hidden. Those rounds
    /// never refuse on residue: a hit they leave is in bytes main's own output
    /// left in clear, and their last masking is returned. A detector error in
    /// them fails closed, as it does in main's rounds: main's output is never
    /// returned in its place.
    fn apply_spans(
        &mut self,
        text: &str,
        spans: &[Span],
        extra: &[Span],
    ) -> Result<String, GateError> {
        if text.is_empty() {
            return Ok(String::new());
        }
        // Fail closed: a secret-class value past the read cap is refused before
        // anything is masked, never masked in part.
        if crate::recognizers::secrets::value_too_long(text) {
            return Err(GateError::Detect(DetectError::TooLong));
        }
        let mut spans: Vec<Span> = spans
            .iter()
            .map(|span| without_possessive(text, *span))
            .collect();
        let (masked, settled) = self.residue_rounds(text, &mut spans)?;
        if !settled {
            return Err(GateError::Residue);
        }
        if extra.is_empty() {
            return Ok(masked);
        }
        spans.extend_from_slice(extra);
        let (more, _) = self.residue_rounds(text, &mut spans)?;
        Ok(more)
    }

    /// Mask `spans` of `text`, then add what the residue view still reads in
    /// clear, at most [`RESIDUE_ROUNDS`] times: the last masking, and whether
    /// its residue view read nothing.
    fn residue_rounds(
        &mut self,
        text: &str,
        spans: &mut Vec<Span>,
    ) -> Result<(String, bool), GateError> {
        let anonymizer = self.anonymizer.as_mut().ok_or(GateError::Key)?;
        let mut round = 0;
        loop {
            let (masked, tokens) = anonymizer.anonymize(text, spans);
            // The values this call newly masked are kept until the caller takes
            // them, so the local screen can resolve the tokens. Nothing else keeps them.
            self.minted.extend(tokens.iter().cloned());
            let clear = clear_parts(&masked);
            let clear = blank_minted(&clear, &token_ranges(&clear, &BTreeSet::new()));
            if crate::recognizers::secrets::value_too_long(&clear) {
                return Err(GateError::Detect(DetectError::TooLong));
            }
            // A residue hit is a value left in clear, unless every character of it is a
            // masked token's stand-in: then it is that token's own place. An address
            // reads its line, and a stand-in starts a new line, so the residue view
            // can read one the text never held: it never refuses.
            let residue = self.detector.residue(&clear)?;
            let hits: Vec<&Span> = residue
                .iter()
                .filter(|span| {
                    span.kind != EntityKind::Address
                        && !is_stand_in_only(&clear[span.start..span.end])
                })
                .collect();
            if hits.is_empty() {
                return Ok((masked, true));
            }
            // A value the residue view reads in clear is masked, never
            // refused (private = tokenise). Masking changes what a clear quote next
            // to a stand-in pairs with, so the view can own more than the text did;
            // and a stand-in's line break starts a line, so a number glued to a
            // masked value reads as a phone or an MRZ line there (bank
            // files). A hit still there after the last round refuses.
            if round == RESIDUE_ROUNDS {
                return Ok((masked, false));
            }
            let mut more = residue_in_text(text, &masked, tokens.occurrences(), &hits);
            let tails = url_tails(text, spans, &more);
            more.extend(tails);
            if more.is_empty() {
                return Ok((masked, false));
            }
            spans.extend(more);
            round += 1;
        }
    }
}
