//! Prohibited classes never leave the Mac in any mode: their fixed removal
//! markers, and the span bookkeeping that keeps a prohibited range whole.

use kernel_core::privacy::GrantPolicy;

use crate::recognizer::{resolve_overlaps, span_is_well_formed, NAME_WIDENED};
use crate::recognizers::dob_label::trim_invisible;
use crate::span::{EntityKind, Span};

use super::report::DetectionReport;

/// The fixed text a passthrough gate writes in place of a detected secret. Open
/// mode leaves ordinary kinds in clear and only reports; a prohibited class is
/// never returned, only counted.
pub(super) const SECRET_REMOVED: &str = "[secret removed]";

/// The fixed text a passthrough gate writes in place of a detected value of a
/// class that never leaves the Mac in any mode (IBAN, payment card, national
/// ID or passport, health, secret, postal address), or `None` for an ordinary
/// kind that open mode leaves in clear.
pub(super) fn removal_text(kind: EntityKind) -> Option<&'static str> {
    match kind {
        EntityKind::Secret => Some(SECRET_REMOVED),
        EntityKind::Iban => Some("[iban removed]"),
        EntityKind::CreditCard => Some("[card removed]"),
        EntityKind::Health => Some("[health removed]"),
        EntityKind::Address => Some("[address removed]"),
        EntityKind::DateOfBirth => Some("[date of birth removed]"),
        EntityKind::FrNir
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino
        | EntityKind::PassportMrz
        | EntityKind::NationalId => Some("[id removed]"),
        _ => None,
    }
}

/// Whether `span` is an IBAN-shaped guess (not a checksum-valid IBAN of a known
/// country) inside a hex token of 32 or more characters, which is a digest. The
/// recogniser fails toward masking, so private mode tokenises such a guess and
/// restores it locally; open mode cannot restore, and would hand the model a
/// corrupted hash it must cite. A real IBAN starts with letters outside `a`-`f`
/// (or is checksum-valid), so it never qualifies.
pub(super) fn is_hash_fragment(text: &str, span: &Span) -> bool {
    if span.kind != EntityKind::Iban || span.score >= crate::recognizers::iban::SCORE {
        return false;
    }
    // A low-confidence IBAN span can occur at every offset in an unbroken
    // alphanumeric run. Scanning the full run for each span made Open mode
    // quadratic on glued identifiers. Only exempt bounded digest-like runs;
    // when the boundary is beyond this window, fail closed and mask the span.
    const MAX_HASH_FRAGMENT_BYTES: usize = 256;
    let bytes = text.as_bytes();
    let alnum = |index: usize| bytes[index].is_ascii_alphanumeric();
    let mut start = span.start;
    let mut scanned = 0;
    while start > 0 && alnum(start - 1) && scanned < MAX_HASH_FRAGMENT_BYTES {
        start -= 1;
        scanned += 1;
    }
    if start > 0 && alnum(start - 1) {
        return false;
    }
    let mut end = span.end;
    scanned = 0;
    while end < bytes.len() && alnum(end) && scanned < MAX_HASH_FRAGMENT_BYTES {
        end += 1;
        scanned += 1;
    }
    if end < bytes.len() && alnum(end) {
        return false;
    }
    end - start >= 32 && bytes[start..end].iter().all(u8::is_ascii_hexdigit)
}

/// Keep each full overlap union and its best prohibited label, so masking or
/// removal cannot leave the tail of a prohibited-containing region clear.
/// The ranges the gate hides as secrets on top of its detector's spans, in
/// both modes: the export columns of a table. Public for the
/// tests' exact reader of an Open output.
#[doc(hidden)]
pub fn export_column_ranges(text: &str) -> Vec<(usize, usize)> {
    crate::recognizers::export_scan(text)
}

/// [`export_column_ranges`] as secret spans.
pub(super) fn export_spans(text: &str) -> Vec<Span> {
    export_column_ranges(text)
        .into_iter()
        .map(|(start, end)| Span::new(EntityKind::Secret, start, end, 1.0, "secret-export"))
        .collect()
}

/// Remove and return the [`NAME_WIDENED`] regions of `spans`: the gate masks
/// them once its main rounds have settled, as `extra`, so they never change
/// what those rounds hide.
pub(super) fn take_widened(spans: &mut Vec<Span>) -> Vec<Span> {
    let (widened, rest) = std::mem::take(spans)
        .into_iter()
        .partition(|span| span.recognizer == NAME_WIDENED);
    *spans = rest;
    widened
}

/// The report of `spans`, plus each `extra` region no span of `spans` holds.
pub(super) fn report_of(policy: GrantPolicy, spans: &[Span], extra: &[Span]) -> DetectionReport {
    if extra.is_empty() {
        return DetectionReport::of(policy, spans);
    }
    let all: Vec<Span> = spans.iter().chain(extra).copied().collect();
    DetectionReport::of(policy, &consolidate_mask_spans(all))
}

pub(super) fn consolidate_mask_spans(spans: Vec<Span>) -> Vec<Span> {
    let mut resolved = resolve_overlaps(spans.clone());
    crate::recognizer::label_prohibited(&mut resolved, &spans);
    resolved
}

/// Replace every well-formed prohibited-class span of `text` (see
/// [`removal_text`]) with its fixed marker, for the passthrough policy.
///
/// Overlapping and adjacent prohibited spans merge into one maximal range and
/// are replaced once, so no byte of a prohibited value survives and no range is
/// written twice; a merged range takes the marker of its highest-priority kind
/// (a secret over an ID over a health term). Every other span, and every byte
/// no prohibited span covers, is returned exactly as it was.
pub(super) fn remove_prohibited(text: &str, spans: &[Span]) -> String {
    let mut ranges: Vec<(usize, usize, EntityKind)> = spans
        .iter()
        .filter(|span| {
            span.is_prohibited() && span_is_well_formed(text, span) && !is_hash_fragment(text, span)
        })
        .map(|span| match span.kind {
            // Not the invisible characters the fold read in front of the date.
            EntityKind::DateOfBirth => {
                let (start, end) = trim_invisible(text, span.start, span.end);
                (start, end, span.kind)
            }
            _ => (span.start, span.end, span.kind),
        })
        .filter(|&(start, end, _)| start < end)
        .collect();
    if ranges.is_empty() {
        return text.to_string();
    }
    ranges.sort_by_key(|&(start, end, kind)| (start, end, kind.mask_priority()));
    let mut merged: Vec<(usize, usize, EntityKind)> = Vec::with_capacity(ranges.len());
    for (start, end, kind) in ranges {
        match merged.last_mut() {
            Some((_, last_end, last_kind)) if start <= *last_end => {
                *last_end = (*last_end).max(end);
                if kind.mask_priority() < last_kind.mask_priority() {
                    *last_kind = kind;
                }
            }
            _ => merged.push((start, end, kind)),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end, kind) in merged {
        out.push_str(&text[cursor..start]);
        out.push_str(removal_text(kind).unwrap_or(SECRET_REMOVED));
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}
