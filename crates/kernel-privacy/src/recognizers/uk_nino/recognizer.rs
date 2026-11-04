//! The recogniser, its three passes joined by one union of overlapping spans.

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

use super::compact::{nino_at, opens_another, reads_table};
use super::loose::loose_ninos;
use super::separated::separated_nino_at;
use super::NAME;

/// The National Insurance number recogniser.
#[derive(Clone, Copy, Debug)]
pub struct UkNinoRecognizer;

impl UkNinoRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Default for UkNinoRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for UkNinoRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::UkNino]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, false);
        let bytes = normalized.text().as_bytes();
        let mut spans = Vec::new();
        // The separated shapes, then one union of both passes. Neither
        // pass is allowed to lose to the other: the compact
        // pass eats the suffix letter that opens a line, the separated pass
        // stops at the break, so on the same range they read differently and
        // overlap. Dropping the separated span then left a whole number in clear
        // (`AB 12 34 56 AB123456\ncDog`, whose `AB 12 34 56 ` only the separated
        // pass reads). A union adds masks and drops none, and it keeps the spans
        // sorted and disjoint as the `overlaps` scan that guarded this needed.
        //
        // NINO-CHAIN: after each number, both passes go on from the offset
        // [`opens_another`] gives — the shared suffix letter itself when the
        // next number starts there, so the scan steps back one byte at most and
        // still always advances. The separated pass records those offsets too: a
        // slashed or dotted head is only its own, and the compact number behind
        // its glued suffix letter is only the other pass's, whose start rule
        // would never look there. The list is sorted, both passes advance, and
        // one cursor walks it: a linear scan still.
        let reads = reads_table(bytes, text, &normalized);
        let mut opens: Vec<usize> = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            let Some(end) = separated_nino_at(bytes, index, text, &normalized, &reads) else {
                index += 1;
                continue;
            };
            if let Some((start, end)) = normalized.to_original(index, end) {
                spans.push(Span::new(EntityKind::UkNino, start, end, 1.0, NAME));
            }
            let next = opens_another(bytes, end, &reads);
            opens.extend(next);
            index = next.map_or(end, |at| at.min(end));
        }
        let (mut index, mut at, mut resume) = (0, 0, 0);
        while index < bytes.len() {
            while at < opens.len() && opens[at] < index {
                at += 1;
            }
            let starts = index == 0
                || index == resume
                || opens.get(at) == Some(&index)
                || !bytes[index - 1].is_ascii_alphanumeric();
            match starts
                .then(|| nino_at(bytes, index, text, &normalized, &reads))
                .flatten()
            {
                Some(end) => {
                    if let Some((start, end)) = normalized.to_original(index, end) {
                        spans.push(Span::new(EntityKind::UkNino, start, end, 1.0, NAME));
                    }
                    let next = opens_another(bytes, end, &reads);
                    // `usize::MAX` is a resume that no offset reaches.
                    resume = next.unwrap_or(usize::MAX);
                    index = next.map_or(end, |at| at.min(end));
                }
                None => index += 1,
            }
        }
        spans.extend(loose_ninos(text));
        union(spans)
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

/// The union of spans that overlap, in start order. Every
/// span this module makes is a `uk_nino` of the same score and name, so the
/// union of two of them is one of them, ended at the later end.
///
/// Only *overlapping* spans merge, never two that merely touch: two numbers side
/// by side, or a number and the next one on the next line, keep their own spans
/// and their own tokens, exactly as before.
fn union(spans: Vec<Span>) -> Vec<Span> {
    let mut spans = spans;
    spans.sort_unstable_by_key(|span| span.start);
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        let joined = out.last_mut().is_some_and(|last| {
            if span.start < last.end {
                last.end = last.end.max(span.end);
                true
            } else {
                false
            }
        });
        if !joined {
            out.push(span);
        }
    }
    out
}
