//! Windowed-scan test: a long text loses and doubles no name.

use crate::recognizer::Recognizer;
use crate::span::EntityKind;

use super::super::{ContactIndex, WINDOW_BYTES};
use super::draft;

#[test]
fn a_long_text_is_scanned_in_windows_without_losing_or_doubling_a_name() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Marie", "Dupont", &[]));
    // The name's space is the last break before the window edge, so the
    // first window ends inside the name.
    let start = WINDOW_BYTES - 8;
    let words = (start - 2) / 3;
    let text = format!(
        "{}{}Marie Dupont fin.",
        "ab ".repeat(words),
        " ".repeat(start - 3 * words)
    );
    assert_eq!(text.as_bytes()[start], b'M');
    let spans = index.recognizer().expect("build").analyze(&text);
    let people: Vec<(usize, usize)> = spans
        .iter()
        .filter(|span| span.kind == EntityKind::Person)
        .map(|span| (span.start, span.end))
        .collect();
    assert_eq!(people, [(start, start + "Marie Dupont".len())]);
}
