//! The recogniser: its candidate scans and span assembly.

use std::sync::LazyLock;

use regex::Regex;

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::recognizers::iban::{uuid_tokens, IbanRecognizer};
use crate::span::{EntityKind, Span};

use super::checks::check_score;
use super::cues::{near_cue, spaced_without_cue_is_passport};
use super::rows::{data_rows, MRZ_LINE_MIN, MRZ_LINE_RE};
use super::{BROAD_SCORE, MRZ_LINE_SCORE, STRICT_SCORE};

static MRZ_CHECK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z0-9<]{9}[0-9]\b").expect("mrz regex compiles"));
static STRICT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z]{1,3}[0-9]{6,9}\b").expect("passport regex compiles"));
static STRICT_SEPARATED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[A-Z]{1,3}[ .\-][0-9]{6,9}\b").expect("separated passport regex compiles")
});
static BROAD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z0-9]{8,10}\b").expect("broad passport regex compiles"));

/// A passport number shaped like `1–3 letters + 6–9 digits`, with or without a
/// valid ICAO check digit.
#[derive(Clone, Copy, Debug)]
pub struct PassportMrzRecognizer {
    verified: bool,
}

impl PassportMrzRecognizer {
    /// Build the recogniser (unverified, mounted by default).
    pub fn new() -> Self {
        Self { verified: false }
    }
}

impl Default for PassportMrzRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for PassportMrzRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::PassportMrz]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let identity = |start: usize, end: usize| {
            (start < end && text.is_char_boundary(start) && text.is_char_boundary(end))
                .then_some((start, end))
        };
        self.analyze_with_source(text, text, &identity)
    }

    fn analyze_with_source(
        &self,
        text: &str,
        original: &str,
        source_bounds: &dyn Fn(usize, usize) -> Option<(usize, usize)>,
    ) -> Vec<Span> {
        // The normalised view makes Unicode digits and fullwidth letters part
        // of the shape; the OCR confusable fold stays off because a passport
        // number carries meaningful letters (P1).
        let normalized = NormalizedText::new(text, false);
        let body = normalized.text();
        let mut spans: Vec<Span> = Vec::new();
        // A whole MRZ line masks on its shape: a long run with a `<<` filler,
        // or a data row (`data_rows`).
        for found in MRZ_LINE_RE.find_iter(body) {
            if found.len() >= MRZ_LINE_MIN && found.as_str().contains("<<") {
                push(
                    &mut spans,
                    &normalized,
                    found.start(),
                    found.end(),
                    MRZ_LINE_SCORE,
                );
            }
        }
        for (start, end) in data_rows(body) {
            push(&mut spans, &normalized, start, end, MRZ_LINE_SCORE);
        }
        // A valid 7-3-1 check digit raises the score and is masked on its own.
        for found in MRZ_CHECK_RE.find_iter(body) {
            if let Some(score) = check_score(found.as_str()) {
                push(&mut spans, &normalized, found.start(), found.end(), score);
            }
        }
        // UUID delimiters and candidate ranges both map to the original text:
        // a folded view can erase a non-ASCII neighbour that is not an ASCII
        // delimiter. A cue or valid check digit remains a passport signal
        // even when the candidate lies inside a whole UUID token.
        let ids = uuid_tokens(original);
        // The strict shape masks by default. Without a cue or a valid check
        // digit, a candidate wholly inside a whole ASCII-delimited UUID is one
        // of the id's fields and can be left in clear (MRZ-UUID-OVERMASK).
        let mut ibans = None;
        for found in STRICT_RE.find_iter(body) {
            let checked = check_score(found.as_str());
            let source = normalized
                .to_original(found.start(), found.end())
                .and_then(|(start, end)| source_bounds(start, end));
            if checked.is_none() && !near_cue(body, found.start(), found.end()) {
                if let Some((start, end)) =
                    source.filter(|&(start, end)| inside_uuid(&ids, start, end))
                {
                    // Keep main's overlap result if another recognizer also
                    // reads this UUID field. This avoids exposing a previously
                    // suppressed IBAN candidate when the passport guess drops.
                    let overlaps_iban = ibans
                        .get_or_insert_with(|| IbanRecognizer::new().analyze(text))
                        .iter()
                        .any(|iban| iban.start < end && start < iban.end);
                    if !overlaps_iban {
                        continue;
                    }
                }
            }
            let score = checked.unwrap_or(STRICT_SCORE);
            push(&mut spans, &normalized, found.start(), found.end(), score);
        }
        // A separated strict shape masks too. A *space* between the prefix and
        // the digits is too weak on its own (a cued TAJ, `TAJ 123456788`, looks
        // the same), so without a passport cue that form needs a strong passport
        // signal; a hyphen or dot is unambiguous attachment and masks on sight.
        for found in STRICT_SEPARATED_RE.find_iter(body) {
            let value = found.as_str();
            if value.contains(' ')
                && !near_cue(body, found.start(), found.end())
                && !spaced_without_cue_is_passport(value)
            {
                continue;
            }
            push(
                &mut spans,
                &normalized,
                found.start(),
                found.end(),
                STRICT_SCORE,
            );
        }
        // The broad shape masks near a cue, before or after the value.
        for found in BROAD_RE.find_iter(body) {
            let value = found.as_str();
            let digits = value.chars().filter(|ch| ch.is_ascii_digit()).count();
            if digits < 5 || !near_cue(body, found.start(), found.end()) {
                continue;
            }
            let score = check_score(value).unwrap_or(BROAD_SCORE);
            push(&mut spans, &normalized, found.start(), found.end(), score);
        }
        spans.sort_by_key(|span| (span.start, span.end));
        spans.dedup_by_key(|span| (span.start, span.end));
        spans
    }

    fn name(&self) -> &'static str {
        "passport_mrz"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// Whether a byte range lies wholly inside one of the sorted, non-overlapping
/// UUID tokens returned by `iban::uuid_tokens`.
fn inside_uuid(ids: &[(usize, usize)], start: usize, end: usize) -> bool {
    let index = ids.partition_point(|&(_, uuid_end)| uuid_end <= start);
    ids.get(index)
        .is_some_and(|&(uuid_start, uuid_end)| uuid_start <= start && end <= uuid_end)
}

fn push(spans: &mut Vec<Span>, normalized: &NormalizedText, start: usize, end: usize, score: f32) {
    if let Some((start, end)) = normalized.to_original(start, end) {
        spans.push(Span::new(
            EntityKind::PassportMrz,
            start,
            end,
            score,
            "passport_mrz",
        ));
    }
}
