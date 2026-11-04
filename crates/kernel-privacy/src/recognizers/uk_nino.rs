//! UK National Insurance number recogniser (`AB 12 34 56 C` or `AB123456C`).
//!
//! Three passes — compact, separated and loose — joined by one span union.

mod compact;
mod labels;
mod loose;
mod recognizer;
mod separated;
mod shape;

pub use recognizer::UkNinoRecognizer;

/// The name echoed in [`Span::recognizer`](crate::span::Span::recognizer).
const NAME: &str = "uk_nino";

#[cfg(test)]
mod tests;
