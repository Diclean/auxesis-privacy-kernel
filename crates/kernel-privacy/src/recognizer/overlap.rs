//! The overlap resolution: overlapping spans become one masked region.

use crate::span::{EntityKind, Span};

/// Resolve overlaps into the union of every overlapping span (P1-1, P2-5).
///
/// Two spans become one region only when they overlap. Adjacent spans of
/// different kinds stay separate, so a display name and the e-mail address
/// beside it keep their own tokens (the hero path fills `attendee_name` and
/// `attendee_email` separately). The region's kind is the highest-priority kind
/// among the members ([`EntityKind::mask_priority`]) and its score is the
/// highest member score.
///
/// A `PERSON` span that overlaps a deterministic span becomes one region with
/// that span's kind, so a name inside an e-mail address is masked as the address
/// and leaves no fragment in clear. A `PERSON` span that does not overlap a
/// deterministic span is its own region, so a name alone in clear text keeps its
/// `PERSON` label. The result is non-overlapping, ordered by start offset, and
/// its byte coverage is exactly `masked_regions` on the same input.
pub fn resolve_overlaps(spans: Vec<Span>) -> Vec<Span> {
    merge_regions(spans.into_iter().filter(|span| !span.is_empty()).collect())
}

/// Give each region of `regions` (ordered, disjoint: [`resolve_overlaps`]) the
/// kind of the prohibited span of `spans` overlapping it with the lowest
/// `(mask_priority, kind)`, the first in `spans` order on a tie, and drop its
/// person; returns which regions hold one. A labelled date of birth also lends
/// its origin, the only one that is prohibited. `spans` may be in any order and
/// overlap. One sorted sweep: each span visits only the regions it overlaps,
/// found by binary search, so a text dense with prohibited values stays
/// linear-log instead of regions x spans.
pub(crate) fn label_prohibited(regions: &mut [Span], spans: &[Span]) -> Vec<bool> {
    let key = |span: &Span| (span.kind.mask_priority(), span.kind);
    let mut best: Vec<Option<&Span>> = vec![None; regions.len()];
    for span in spans.iter().filter(|span| span.is_prohibited()) {
        let first = regions.partition_point(|region| region.end <= span.start);
        for (region, slot) in regions[first..].iter().zip(&mut best[first..]) {
            if region.start >= span.end {
                break;
            }
            if slot.is_none_or(|old| key(span) < key(old)) {
                *slot = Some(span);
            }
        }
    }
    for (region, best) in regions.iter_mut().zip(&best) {
        if let Some(best) = best {
            region.kind = best.kind;
            if best.kind == EntityKind::DateOfBirth {
                region.recognizer = best.recognizer;
            }
            region.person_id = None;
        }
    }
    best.iter().map(Option::is_some).collect()
}

/// The non-overlapping regions to mask: union of every overlapping span of
/// every kind.
///
/// [`crate::Anonymizer`] uses this view so each byte is masked exactly once with
/// the highest-priority kind. Since [`resolve_overlaps`] already merges every
/// overlap into the exact union, this is the same region set; it is kept as the
/// explicit masking view the anonymizer reads.
pub(crate) fn masked_regions(spans: Vec<Span>) -> Vec<Span> {
    merge_regions(spans.into_iter().filter(|span| !span.is_empty()).collect())
}

/// Merge spans: overlapping members become one region. Touching spans of
/// different kinds stay separate.
fn merge_regions(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by_key(|span| (span.start, span.end));
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(last) = merged.last_mut() {
            if span.start < last.end {
                last.end = last.end.max(span.end);
                if wins_over(&span, last) {
                    last.kind = span.kind;
                    last.recognizer = span.recognizer;
                }
                last.score = last.score.max(span.score);
                // A region keeps a person only when every member names that person.
                if last.person_id != span.person_id {
                    last.person_id = None;
                }
                continue;
            }
        }
        merged.push(span);
    }
    merged
}

/// Whether `candidate` should take the label of a span it overlaps.
///
/// A passport-origin span outranks an IBAN candidate (P3, kind labels), even
/// though the registry relabels it `NATIONAL_ID`. It does *not* steal the label
/// from a more specific national-id rule (a cued TAJ or NIR), and the kind
/// priority decides every other pair; on an equal priority the specific label
/// beats the generic passport fallback, otherwise the span that already won
/// keeps the label.
///
/// A prohibited span ([`Span::is_prohibited`]) outranks every kind Open
/// mode leaves in clear before any of this, so a region that holds a health
/// term, an IBAN, an ID or a secret is removed in every mode, whatever e-mail,
/// phone, URL or address it overlaps (K-SPAN-PRIORITY).
fn wins_over(candidate: &Span, current: &Span) -> bool {
    if candidate.is_prohibited() != current.is_prohibited() {
        return candidate.is_prohibited();
    }
    let candidate_passport = candidate.recognizer == "passport_mrz";
    let current_passport = current.recognizer == "passport_mrz";
    if candidate_passport && current.kind == EntityKind::Iban {
        return true;
    }
    if current_passport && candidate.kind == EntityKind::Iban {
        return false;
    }
    let candidate_priority = candidate.kind.mask_priority();
    let current_priority = current.kind.mask_priority();
    if candidate_priority != current_priority {
        return candidate_priority < current_priority;
    }
    current_passport && !candidate_passport
}
