//! Unknown, cross-session, and malformed placeholders.

use super::*;

#[test]
fn unknown_delimited_token_is_reported_and_kept() {
    let mut anonymizer = Anonymizer::new([0x79u8; 32]);
    let (_, pairs) = anonymizer.anonymize("0612345678", &[span(EntityKind::Phone, 0, 10)]);
    let text = "masked ⟦PHONE_zzzzzz⟧ tail";
    let report = Anonymizer::restore(text, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.unknown, vec!["PHONE_zzzzzz".to_string()]);
    assert_eq!(report.text, text);
    assert!(!report.is_clean());

    let report = Anonymizer::restore(text, &pairs, UnknownPolicy::Redact);
    assert_eq!(report.text, "masked [unknown reference] tail");
    assert_eq!(report.unknown, vec!["PHONE_zzzzzz".to_string()]);
}
#[test]
fn cross_session_token_is_unknown() {
    let mut session = Anonymizer::new([0x7Au8; 32]);
    let (_, pairs) = session.anonymize("0612345678", &[span(EntityKind::Phone, 0, 10)]);
    let mut other = Anonymizer::new([0x7Bu8; 32]);
    let (forged, _) = other.token_for(EntityKind::Phone, "0612345678");
    let text = format!("⟦{forged}⟧");
    let report = Anonymizer::restore(&text, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.unknown, vec![forged]);
}
#[test]
fn missing_close_delimiter_stays_literal() {
    let pairs = TokenMap::default();
    let text = "no close ⟦ here";
    let report = Anonymizer::restore(text, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.text, text);
    assert!(report.is_clean());
}
