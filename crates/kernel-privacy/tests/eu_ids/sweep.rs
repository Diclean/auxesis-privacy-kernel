//! The whole corpus at once: every spelling hidden, a failing check left
//! in clear, and a label hiding it.

use kernel_privacy::recognizers::eu_ids::ItCodiceFiscaleRecognizer;
use kernel_privacy::EntityKind;
use kernel_privacy::Recognizer;

use super::corpus::{FAILURES, LABELLED, SPELLINGS};
use super::helpers::{covered, issue, masked, spans_of, MODES};

/// Every spelling is hidden in both modes: the value never reaches the cloud.
#[test]
fn every_spelling_is_hidden_in_both_modes() {
    let mut missed = Vec::new();
    for (class, input, value) in SPELLINGS.iter().chain(LABELLED) {
        let start = input.find(value).expect("the value is in the text");
        let end = start + value.len();
        for mode in MODES {
            let (output, _) = issue(mode, input).expect("the gate issues the text");
            if output.contains(value) {
                missed.push(format!("{class} {mode:?} {input:?} kept {value:?}"));
                continue;
            }
            let ranges = masked(mode, input).expect("the gate issues the text");
            if !covered(&ranges, start, end) {
                missed.push(format!(
                    "{class} {mode:?} {input:?} did not cover {value:?}"
                ));
            }
        }
    }
    assert!(
        missed.is_empty(),
        "{} missed:\n{}",
        missed.len(),
        missed.join("\n")
    );
}

/// A value whose check digit fails stays in clear while no label names it.
#[test]
fn a_check_that_fails_stays_in_clear_without_a_label() {
    let mut missed = Vec::new();
    for (class, value, _) in FAILURES {
        let (output, _) = issue(MODES[1], value).expect("the gate issues the text");
        if !output.contains(value) {
            missed.push(format!("{class} {value:?} was removed in open mode"));
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}

/// A label names the value, so a typo in a real document is still hidden.
#[test]
fn a_label_hides_a_value_whose_check_fails() {
    let mut missed = Vec::new();
    for (class, value, labelled) in FAILURES {
        for mode in MODES {
            let (output, _) = issue(mode, labelled).expect("the gate issues the text");
            if output.contains(value) {
                missed.push(format!("{class} {mode:?} {labelled:?} kept {value:?}"));
            }
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}

/// Every rule finds its own value and names itself, so the span says which
/// rule read it.
#[test]
fn every_rule_finds_its_own_value() {
    for (class, input, value) in SPELLINGS {
        let spans = spans_of(class, input);
        let start = input.find(value).expect("the value is in the text");
        let end = start + value.len();
        assert!(
            spans
                .iter()
                .any(|span| span.start <= start && span.end >= end),
            "{class} {input:?} -> {spans:?}"
        );
        assert!(spans.iter().all(|span| span.kind == EntityKind::NationalId));
    }
}

/// A rule reads nothing in a value whose check digit fails.
#[test]
fn a_rule_reads_nothing_in_a_value_whose_check_fails() {
    for (class, value, _) in FAILURES {
        assert!(
            spans_of(class, value).is_empty(),
            "{class} masked {value:?} without a label"
        );
    }
    // The upper-case codice fiscale is not read either: the bank rule's IBAN
    // guess over its last twelve characters is main's business.
    assert!(ItCodiceFiscaleRecognizer::new()
        .analyze("ZMRPKC73R12H780Y")
        .is_empty());
}
