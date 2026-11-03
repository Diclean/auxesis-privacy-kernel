//! `Debug` output must not leak values or keys.

use super::*;

#[test]
fn debug_never_prints_a_value_or_key() {
    let mut anonymizer = Anonymizer::new([9u8; 32]);
    let (_, pairs) = anonymizer.anonymize(
        "secret@example.com",
        &[Span::new(EntityKind::Email, 0, 18, 1.0, "test")],
    );
    let rendered = format!("{anonymizer:?}");
    assert!(rendered.contains("redacted"));
    assert!(rendered.contains("entries: 1"));
    assert!(!rendered.contains("secret@example.com"));
    assert!(!rendered.contains("9, 9"));

    let map = format!("{pairs:?}");
    assert!(map.contains("tokens"));
    assert!(!map.contains("secret@example.com"));
    assert!(!format!("{pairs:?}").contains("secret"));
}
