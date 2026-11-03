//! Shared fixtures for the recogniser tests, split by topic.

mod overlap;
mod person;
mod prohibited;
mod registry;
mod spans;

use crate::span::{EntityKind, Span};

fn span(kind: EntityKind, start: usize, end: usize, score: f32) -> Span {
    Span::new(kind, start, end, score, "test")
}
