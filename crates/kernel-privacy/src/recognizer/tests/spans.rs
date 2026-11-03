//! Span hygiene: the byte bounds and the length caps.

use crate::span::{EntityKind, Span};

use super::super::{span_is_well_formed, split_long_spans, MAX_SPAN_BYTES};
use super::span;

#[test]
fn well_formed_checks_boundaries() {
    let text = "héllo";
    assert!(span_is_well_formed(
        text,
        &span(EntityKind::Email, 0, 6, 1.0)
    ));
    assert!(!span_is_well_formed(
        text,
        &span(EntityKind::Email, 2, 3, 1.0)
    ));
    assert!(!span_is_well_formed(
        text,
        &span(EntityKind::Email, 0, 0, 1.0)
    ));
    assert!(!span_is_well_formed(
        text,
        &span(EntityKind::Email, 0, 99, 1.0)
    ));
}

#[test]
fn long_spans_split_on_char_boundaries() {
    let text = "x".repeat(300);
    let span = Span::new(EntityKind::NationalId, 0, 300, 1.0, "test");
    let split = split_long_spans(&text, vec![span]);
    assert!(split.iter().all(|span| span.len() <= MAX_SPAN_BYTES));
    assert_eq!(split.first().map(|span| span.start), Some(0));
    assert_eq!(split.last().map(|span| span.end), Some(300));
    assert!(split
        .iter()
        .all(|span| text.is_char_boundary(span.start) && text.is_char_boundary(span.end)));
}
