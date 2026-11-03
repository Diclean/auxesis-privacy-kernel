//! Span consolidation: score, order and prohibited unions.

use crate::span::{EntityKind, Span};

use super::super::consolidate::{consolidate, consolidate_flat};

#[test]
fn consolidate_flat_matches_the_quadratic_scan() {
    fn naive(mut spans: Vec<Span>) -> Vec<Span> {
        spans.retain(|span| !span.is_empty());
        spans.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.start.cmp(&right.start))
                .then_with(|| left.end.cmp(&right.end))
        });
        let mut kept: Vec<Span> = Vec::new();
        for span in spans {
            if !kept.iter().any(|kept| kept.overlaps(&span)) {
                kept.push(span);
            }
        }
        kept.sort_by_key(|span| (span.start, span.end));
        kept
    }
    let kinds = [
        EntityKind::Person,
        EntityKind::Organization,
        EntityKind::Health,
        EntityKind::Email,
    ];
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move |bound: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % bound
    };
    for _ in 0..2_000 {
        let count = next(24) as usize;
        let spans: Vec<Span> = (0..count)
            .map(|_| {
                let start = next(60) as usize;
                let end = start + next(12) as usize;
                let score = next(5) as f32 / 4.0;
                Span::new(kinds[next(4) as usize], start, end, score, "gliner")
            })
            .collect();
        assert_eq!(consolidate_flat(spans.clone()), naive(spans));
    }
}

#[test]
fn consolidate_keeps_the_higher_score_and_orders_by_start() {
    let spans = vec![
        Span::new(EntityKind::Person, 0, 12, 0.9, "gliner"),
        Span::new(EntityKind::Person, 5, 12, 0.5, "gliner"),
        Span::new(EntityKind::Organization, 20, 30, 0.7, "gliner"),
    ];
    let kept = consolidate(spans);
    assert_eq!(kept.len(), 2);
    assert_eq!((kept[0].start, kept[0].end), (0, 12));
    assert_eq!(kept[0].score, 0.9);
    assert_eq!((kept[1].start, kept[1].end), (20, 30));
}

#[test]
fn consolidate_keeps_adjacent_spans_apart() {
    let spans = vec![
        Span::new(EntityKind::Person, 0, 4, 0.9, "gliner"),
        Span::new(EntityKind::Person, 4, 8, 0.9, "gliner"),
    ];
    let kept = consolidate(spans);
    assert_eq!(kept.len(), 2);
}

fn pre_250_consolidate(mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|span| !span.is_empty());
    spans.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.end.cmp(&right.end))
    });
    let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        if kept.iter().any(|kept| kept.overlaps(&span)) {
            continue;
        }
        kept.push(span);
    }
    kept.sort_by_key(|span| (span.start, span.end));
    kept
}

#[test]
fn non_prohibited_spans_match_pre_250_for_overlaps_and_2000_fake_deep_cases() {
    let cases = [
        vec![
            Span::new(EntityKind::Person, 0, 12, 0.9, "fake-deep"),
            Span::new(EntityKind::Health, 5, 12, 0.95, "fake-deep"),
        ],
        vec![
            Span::new(EntityKind::Person, 0, 12, 0.9, "fake-deep"),
            Span::new(EntityKind::Organization, 5, 14, 0.9, "fake-deep"),
        ],
        vec![
            Span::new(EntityKind::Person, 0, 20, 0.8, "fake-deep"),
            Span::new(EntityKind::Address, 4, 16, 0.9, "fake-deep"),
            Span::new(EntityKind::Organization, 7, 12, 0.7, "fake-deep"),
        ],
        vec![
            Span::new(EntityKind::Person, 0, 8, 0.9, "fake-deep"),
            Span::new(EntityKind::Organization, 0, 8, 0.9, "fake-deep"),
        ],
    ];
    for spans in cases {
        let expected: Vec<_> = pre_250_consolidate(spans.clone())
            .into_iter()
            .filter(|span| !span.kind.is_prohibited())
            .collect();
        let actual: Vec<_> = consolidate(spans)
            .into_iter()
            .filter(|span| !span.kind.is_prohibited())
            .collect();
        assert_eq!(actual, expected);
    }

    // Deterministic, invented fake-Deep output: ties, nested names, and
    // Tier C overlaps vary across inputs while ordinary selections must
    // remain byte-for-byte equal to the pre-#250 flat pass.
    for input in 0..2_000 {
        let shift = input % 7;
        let score = [0.6, 0.7, 0.8, 0.9][input % 4];
        let spans = vec![
            Span::new(EntityKind::Person, shift, shift + 12, score, "fake-deep"),
            Span::new(
                EntityKind::Organization,
                shift + input % 3,
                shift + 10,
                score,
                "fake-deep",
            ),
            Span::new(
                EntityKind::Address,
                shift + 4,
                shift + 15,
                0.85,
                "fake-deep",
            ),
            Span::new(EntityKind::Health, shift + 2, shift + 13, 0.95, "fake-deep"),
            Span::new(
                EntityKind::NationalId,
                shift + 8,
                shift + 11,
                0.95,
                "fake-deep",
            ),
        ];
        let expected: Vec<_> = pre_250_consolidate(spans.clone())
            .into_iter()
            .filter(|span| !span.kind.is_prohibited())
            .collect();
        let actual: Vec<_> = consolidate(spans)
            .into_iter()
            .filter(|span| !span.kind.is_prohibited())
            .collect();
        assert_eq!(actual, expected, "fake-Deep input {input}");
    }
}

#[test]
fn consolidate_unions_prohibited_overlap_chains_and_ignores_other_labels() {
    let kept = consolidate(vec![
        Span::new(EntityKind::Health, 0, 27, 0.9, "fake"),
        Span::new(EntityKind::NationalId, 0, 3, 0.9, "fake"),
        Span::new(EntityKind::Secret, 5, 40, 0.8, "fake"),
        Span::new(EntityKind::Health, 10, 15, 0.8, "fake"),
        Span::new(EntityKind::Iban, 38, 50, 0.7, "fake"),
        Span::new(EntityKind::Person, 0, 50, 1.0, "fake"),
    ]);
    let sensitive: Vec<_> = kept
        .iter()
        .filter(|span| span.kind.is_prohibited())
        .collect();
    assert_eq!(sensitive.len(), 1);
    assert_eq!(
        (sensitive[0].start, sensitive[0].end, sensitive[0].kind),
        (0, 50, EntityKind::Secret)
    );
    assert!(kept.iter().any(|span| span.kind == EntityKind::Person));
}

#[test]
fn consolidate_keeps_touching_prohibited_ranges_separate_and_ties_are_stable() {
    let kept = consolidate(vec![
        Span::new(EntityKind::Health, 0, 27, 0.9, "fake"),
        Span::new(EntityKind::NationalId, 0, 3, 0.9, "fake"),
        Span::new(EntityKind::Secret, 27, 40, 0.9, "fake"),
    ]);
    assert_eq!(kept.len(), 2);
    assert_eq!(
        (kept[0].start, kept[0].end, kept[0].kind),
        (0, 27, EntityKind::NationalId)
    );
    assert_eq!(
        (kept[1].start, kept[1].end, kept[1].kind),
        (27, 40, EntityKind::Secret)
    );
}
