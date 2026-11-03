use super::hits;
use crate::recognizer::Recognizer;
use crate::recognizers::mrz::PassportMrzRecognizer;
use crate::span::EntityKind;

#[test]
fn valid_and_invalid_vectors() {
    let recognizer = PassportMrzRecognizer::new();
    assert_eq!(hits("passport L898902C36"), vec!["L898902C36"]);
    // No cue and no strict shape: only a valid check digit would mask it.
    assert!(hits("L898902C35").is_empty());
    assert!(!recognizer.verified());
    assert!(recognizer.enabled_by_default());
}

#[test]
fn declared_kind_and_name() {
    let recognizer = PassportMrzRecognizer::new();
    assert_eq!(recognizer.kinds(), &[EntityKind::PassportMrz]);
    assert_eq!(recognizer.name(), "passport_mrz");
}
