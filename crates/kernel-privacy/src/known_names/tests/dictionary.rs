//! Compiling the dictionary: short entries, build errors, empty input.

use crate::recognizer::Recognizer;

use super::super::rule::{NameCheck, PatternRule};
use super::super::{NameDictionary, NameDictionaryError};

#[test]
fn short_entries_compile_with_the_right_check() {
    assert!(NameDictionary::new(["A"]).expect("dictionary").is_empty());
    assert!(NameDictionary::new([""]).expect("dictionary").is_empty());
    let bo = NameDictionary::new(["Bo"]).expect("dictionary");
    assert!(!bo.is_empty());
    assert!(bo.analyze("bo").is_empty());
    assert!(!bo.analyze("Bo").is_empty());
    let le = NameDictionary::new(["Le"]).expect("dictionary");
    assert!(!le.is_empty());
    assert!(le.analyze("le dossier").is_empty());
    assert!(!le.analyze("Le dossier").is_empty());
    let gall = NameDictionary::new(["Camille Le Gall"]).expect("dictionary");
    assert!(gall.analyze("Le dossier").is_empty());
    assert!(!gall.analyze("Mme Le Gall").is_empty());
}

#[test]
fn a_build_failure_is_an_error_not_an_empty_dictionary() {
    assert!(matches!(
        NameDictionary::compile(
            vec![String::new()],
            vec![PatternRule::for_pattern("", NameCheck::Any)]
        ),
        Err(NameDictionaryError::Build)
    ));
}

#[test]
fn an_empty_dictionary_matches_nothing() {
    let dictionary = NameDictionary::new(std::iter::empty::<&str>()).expect("dictionary");
    assert!(dictionary.is_empty());
    assert!(dictionary.analyze("camille exemple").is_empty());
}
