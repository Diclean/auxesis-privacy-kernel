//! The prohibited-label sweep: the region kinds match a full scan.

use crate::span::{EntityKind, Span};

use super::super::{label_prohibited, resolve_overlaps};

/// The sorted sweep labels every region exactly as main's full scan did
/// (same kind, same tie, same person drop) on unsorted, overlapping,
/// empty and reversed spans, and every byte of a prohibited span lies in a
/// region that holds a prohibited kind (OCR-KERNEL-3a).
#[test]
fn label_prohibited_matches_a_full_scan() {
    let kinds = [
        EntityKind::Person,
        EntityKind::Email,
        EntityKind::Iban,
        EntityKind::CreditCard,
        EntityKind::Health,
        EntityKind::Secret,
        EntityKind::NationalId,
        EntityKind::Address,
    ];
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % bound as u64) as usize
    };
    for round in 0..2_000 {
        let spans: Vec<Span> = (0..1 + round % 24)
            .map(|_| {
                let start = next(80);
                let end = if next(10) == 0 {
                    start.saturating_sub(next(3))
                } else {
                    start + next(12)
                };
                let mut span = Span::new(kinds[next(kinds.len())], start, end, 0.9, "t");
                span.person_id = Some(next(4) as u32);
                span
            })
            .collect();
        let mut swept = resolve_overlaps(spans.clone());
        let mut scanned = swept.clone();
        let held = label_prohibited(&mut swept, &spans);
        for region in &mut scanned {
            if let Some(best) = spans
                .iter()
                .filter(|s| s.kind.is_prohibited() && s.start < region.end && region.start < s.end)
                .min_by_key(|s| (s.kind.mask_priority(), s.kind))
            {
                region.kind = best.kind;
                region.person_id = None;
            }
        }
        assert_eq!(swept, scanned, "round {round}: {spans:?}");
        for span in spans
            .iter()
            .filter(|s| s.kind.is_prohibited() && !s.is_empty())
        {
            for byte in span.start..span.end {
                let at = swept.iter().position(|r| r.start <= byte && byte < r.end);
                assert!(
                    at.is_some_and(|at| held[at] && swept[at].kind.is_prohibited()),
                    "round {round}: byte {byte} of {span:?} in clear"
                );
            }
        }
    }
}
