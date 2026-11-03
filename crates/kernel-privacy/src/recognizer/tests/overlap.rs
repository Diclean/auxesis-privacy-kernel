//! Overlap resolution: which kind wins, and where a region ends.

use crate::span::{EntityKind, Span};

use super::super::{masked_regions, resolve_overlaps};
use super::span;

#[test]
fn overlapping_spans_merge_and_priority_picks_the_kind() {
    let spans = vec![
        span(EntityKind::Email, 0, 5, 0.9),
        span(EntityKind::Url, 0, 9, 0.4),
        span(EntityKind::Phone, 20, 25, 0.3),
        span(EntityKind::Iban, 20, 25, 0.8),
    ];
    let kept = resolve_overlaps(spans);
    assert_eq!(kept.len(), 2);
    // Email outranks Url, Iban outranks Phone.
    assert_eq!(kept[0].kind, EntityKind::Email);
    assert_eq!((kept[0].start, kept[0].end), (0, 9));
    assert_eq!(kept[1].kind, EntityKind::Iban);
}

#[test]
fn touching_spans_of_different_kinds_stay_separate() {
    let spans = vec![
        span(EntityKind::Email, 10, 20, 1.0),
        span(EntityKind::Phone, 0, 10, 1.0),
    ];
    let kept = resolve_overlaps(spans);
    assert_eq!(kept.len(), 2);
    assert_eq!(
        (kept[0].kind, kept[0].start, kept[0].end),
        (EntityKind::Phone, 0, 10)
    );
    assert_eq!(
        (kept[1].kind, kept[1].start, kept[1].end),
        (EntityKind::Email, 10, 20)
    );
}

#[test]
fn a_person_inside_a_deterministic_span_takes_its_kind_without_a_gap() {
    let spans = vec![
        span(EntityKind::Email, 0, 12, 1.0),
        span(EntityKind::Person, 3, 8, 0.7),
    ];
    let kept = resolve_overlaps(spans);
    // One exact union region: no separate PERSON edge to fall short of a
    // gold span that straddles the boundary.
    assert_eq!(kept.len(), 1);
    assert_eq!((kept[0].start, kept[0].end), (0, 12));
    assert_eq!(kept[0].kind, EntityKind::Email);
}

#[test]
fn a_name_right_after_a_phone_stays_its_own_region() {
    let spans = vec![
        span(EntityKind::Phone, 0, 10, 1.0),
        span(EntityKind::Person, 10, 15, 0.7),
    ];
    let kept = resolve_overlaps(spans);
    assert_eq!(kept.len(), 2);
    assert_eq!(
        (kept[0].kind, kept[0].start, kept[0].end),
        (EntityKind::Phone, 0, 10)
    );
    assert_eq!(
        (kept[1].kind, kept[1].start, kept[1].end),
        (EntityKind::Person, 10, 15)
    );
}

#[test]
fn a_person_on_its_own_keeps_its_kind() {
    let spans = vec![
        span(EntityKind::Phone, 0, 10, 1.0),
        span(EntityKind::Person, 12, 17, 0.7),
    ];
    let kept = resolve_overlaps(spans);
    assert_eq!(kept.len(), 2);
    assert_eq!(
        (kept[1].kind, kept[1].start, kept[1].end),
        (EntityKind::Person, 12, 17)
    );
}

#[test]
fn contained_span_widens_the_union_instead_of_being_dropped() {
    let spans = vec![
        span(EntityKind::Url, 0, 30, 0.9),
        span(EntityKind::Email, 5, 35, 1.0),
    ];
    let kept = resolve_overlaps(spans);
    assert_eq!(kept.len(), 1);
    assert_eq!((kept[0].start, kept[0].end), (0, 35));
    assert_eq!(kept[0].kind, EntityKind::Email);
}

#[test]
fn partial_overlap_masks_the_whole_union() {
    let spans = vec![
        span(EntityKind::Phone, 0, 10, 1.0),
        span(EntityKind::Email, 8, 20, 1.0),
    ];
    let kept = resolve_overlaps(spans);
    assert_eq!(kept.len(), 1);
    assert_eq!((kept[0].start, kept[0].end), (0, 20));
}

#[test]
fn passport_origin_outranks_iban_and_keeps_its_end() {
    // The registry relabels the passport hit `NATIONAL_ID`, so only the
    // originating recogniser can carry `passport > iban` (P3).
    let spans = vec![
        span(EntityKind::Iban, 10, 21, 0.55),
        span(EntityKind::NationalId, 10, 21, 0.6),
    ]
    .into_iter()
    .map(|mut span| {
        if span.kind == EntityKind::NationalId {
            span.recognizer = "passport_mrz";
        } else {
            span.recognizer = "iban";
        }
        span
    })
    .collect();
    let kept = resolve_overlaps(spans);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].kind, EntityKind::NationalId);
    assert_eq!(kept[0].recognizer, "passport_mrz");
    // The end is the passport end.
    assert_eq!((kept[0].start, kept[0].end), (10, 21));
}

#[test]
fn specific_national_id_keeps_its_label_over_the_passport_fallback() {
    let mut passport = span(EntityKind::NationalId, 0, 13, 0.6);
    passport.recognizer = "passport_mrz";
    let taj = span(EntityKind::HuTaj, 4, 13, 1.0);
    let kept = resolve_overlaps(vec![passport, taj]);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].kind, EntityKind::HuTaj);
    assert_eq!(kept[0].recognizer, "test");
    assert_eq!((kept[0].start, kept[0].end), (0, 13));
}

#[test]
fn generic_national_id_outranks_company_ids_and_phones() {
    let spans = vec![
        span(EntityKind::FrVat, 0, 13, 1.0),
        span(EntityKind::Phone, 2, 11, 0.5),
        span(EntityKind::NationalId, 0, 11, 0.6),
    ];
    let kept = resolve_overlaps(spans);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].kind, EntityKind::NationalId);
    assert_eq!((kept[0].start, kept[0].end), (0, 13));
}

/// Random overlapping spans over multi-byte text: the masked bytes are
/// exactly the union of the spans, with no off-by-one at a char boundary.
#[test]
fn random_overlapping_spans_mask_the_exact_union() {
    let text = "aé—•Ωz bonjour Élise Ünïcode 漢字 end";
    let boundaries: Vec<usize> = text
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(text.len()))
        .collect();
    // A small deterministic LCG: no dependency, reproducible.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = |bound: usize| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((state >> 33) as usize) % bound
    };
    for _ in 0..500 {
        let count = 1 + next(6);
        let mut spans = Vec::new();
        for _ in 0..count {
            let a = boundaries[next(boundaries.len())];
            let b = boundaries[next(boundaries.len())];
            let (start, end) = if a <= b { (a, b) } else { (b, a) };
            if start == end {
                continue;
            }
            let kind = [
                EntityKind::Person,
                EntityKind::Email,
                EntityKind::Address,
                EntityKind::Phone,
            ][next(4)];
            spans.push(Span::new(kind, start, end, 0.9, "test"));
        }
        let regions = resolve_overlaps(spans.clone());
        // Build the expected union byte set from the raw spans.
        let mut expected = vec![false; text.len()];
        for span in &spans {
            for slot in expected.iter_mut().take(span.end).skip(span.start) {
                *slot = true;
            }
        }
        let mut covered = vec![false; text.len()];
        for region in &regions {
            assert!(
                text.is_char_boundary(region.start) && text.is_char_boundary(region.end),
                "a region must stay on char boundaries: {region:?}"
            );
            for slot in covered.iter_mut().take(region.end).skip(region.start) {
                *slot = true;
            }
        }
        assert_eq!(covered, expected, "union mismatch for {spans:?}");
        // The regions never overlap each other.
        for pair in regions.windows(2) {
            assert!(pair[0].end <= pair[1].start, "regions overlap: {pair:?}");
        }
        // The masking view is byte-for-byte the same union.
        assert_eq!(
            masked_regions(spans.clone()),
            regions,
            "resolve_overlaps and the masker must agree"
        );
    }
}
