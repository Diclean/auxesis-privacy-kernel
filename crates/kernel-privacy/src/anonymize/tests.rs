//! Unit tests for the anonymiser, split by topic.

use crate::span::{EntityKind, Span};

use super::*;

fn span(kind: EntityKind, start: usize, end: usize) -> Span {
    Span::new(kind, start, end, 1.0, "test")
}

fn restore_keep(text: &str, pairs: &TokenMap) -> String {
    Anonymizer::restore(text, pairs, UnknownPolicy::Keep).text
}

mod debug;
mod masking;
mod normalize;
mod restore;
