//! Word folding and whole-word matching.

use super::hits;

#[test]
fn case_and_accents_fold_to_one_word() {
    assert_eq!(hits("CHIMIOTHÉRAPIE"), vec!["CHIMIOTHÉRAPIE"]);
    assert_eq!(hits("chimiotherapie"), vec!["chimiotherapie"]);
    assert_eq!(hits("Cancers"), vec!["Cancers"]);
}

#[test]
fn a_term_is_a_whole_word() {
    assert!(hits("The cancelled flight").is_empty());
    assert!(hits("Rakete").is_empty());
}

#[test]
fn a_stem_matches_every_inflection() {
    assert_eq!(hits("cukorbetegségben"), vec!["cukorbetegségben"]);
    assert_eq!(hits("sladkorna"), vec!["sladkorna"]);
}

#[test]
fn an_english_final_word_takes_the_y_ies_and_verb_forms() {
    assert_eq!(hits("pregnancies"), vec!["pregnancies"]);
    assert_eq!(hits("disabilities"), vec!["disabilities"]);
    assert_eq!(hits("chemotherapies"), vec!["chemotherapies"]);
    assert_eq!(hits("miscarried"), vec!["miscarried"]);
    assert_eq!(hits("hospitalized"), vec!["hospitalized"]);
    assert_eq!(hits("hospitalised"), vec!["hospitalised"]);
    assert_eq!(hits("hospitalization"), vec!["hospitalization"]);
    assert_eq!(hits("two hospitalizations"), vec!["hospitalizations"]);
    assert_eq!(hits("a kidney stone"), vec!["kidney stone"]);
    assert_eq!(hits("one gallstone"), vec!["gallstone"]);
    assert_eq!(hits("a varicose vein"), vec!["varicose vein"]);
    assert_eq!(hits("kidney stones"), vec!["kidney stones"]);
    assert_eq!(hits("disabled"), vec!["disabled"]);
    assert_eq!(hits("addicted"), vec!["addicted"]);
    assert_eq!(hits("overdosed"), vec!["overdosed"]);
    assert_eq!(hits("overdoses"), vec!["overdoses"]);
    assert_eq!(hits("seizures"), vec!["seizures"]);
    assert_eq!(hits("heroin"), vec!["heroin"]);
    assert_eq!(hits("methadone"), vec!["methadone"]);
}

#[test]
fn a_multi_word_term_joins_across_hyphens_and_spaces() {
    assert_eq!(hits("self-harm"), vec!["self-harm"]);
    assert_eq!(hits("sick  leave"), vec!["sick  leave"]);
    assert!(hits("sick, leave").is_empty());
}

#[test]
fn an_apostrophe_ends_a_word() {
    assert_eq!(hits("l'insomnie"), vec!["insomnie"]);
}

#[test]
fn a_combining_mark_and_an_invisible_character_stay_inside_the_word() {
    // `e` plus U+0301 is the same word as the precomposed `é`.
    assert_eq!(
        hits("chimiothe\u{0301}rapie"),
        vec!["chimiothe\u{0301}rapie"]
    );
    assert_eq!(hits("can\u{200B}cer"), vec!["can\u{200B}cer"]);
}
