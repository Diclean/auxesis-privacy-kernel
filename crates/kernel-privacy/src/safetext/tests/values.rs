//! Gate behaviour: JSON values, name coverage, joining, and minted pairs.

use super::*;
use crate::anonymize::{PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use crate::recognizer::Registry;
use crate::safetext::detector::standard_builder;
use crate::safetext::prohibited::{removal_text, remove_prohibited, SECRET_REMOVED};
use crate::safetext::KernelMarker;
use std::sync::Arc;

#[test]
fn values_mask_every_string_leaf_and_keep_scalars() {
    let mut gate = masking_gate();
    let input = serde_json::json!({
        "to": "elise.vautrin@example.invalid",
        "count": 3,
        "tags": ["plain", true, null]
    });
    let (safe, _) = gate.value(&input).unwrap();
    let wire = serde_json::to_string(&safe).unwrap();
    assert!(!wire.contains("elise.vautrin"));
    assert!(wire.contains("\"count\":3"));
    assert!(wire.contains("\"plain\""));
    assert!(wire.contains("true"));
}

#[test]
fn overlapping_and_adjacent_secret_spans_merge_into_one_removal() {
    let text = "abcdefghij";
    let spans = [
        Span::new(EntityKind::Secret, 0, 4, 1.0, "t"),
        Span::new(EntityKind::Secret, 4, 7, 1.0, "t"),
        Span::new(EntityKind::Secret, 6, 10, 1.0, "t"),
    ];
    assert_eq!(remove_prohibited(text, &spans), SECRET_REMOVED);
    // Only a prohibited class is replaced: another kind's span leaves the
    // text alone.
    let email = [Span::new(EntityKind::Email, 0, 4, 1.0, "t")];
    assert_eq!(remove_prohibited(text, &email), text);
    // Overlapping spans of two classes become one range, marked by the
    // higher-priority kind.
    let mixed = [
        Span::new(EntityKind::Health, 0, 6, 1.0, "t"),
        Span::new(EntityKind::Secret, 4, 10, 1.0, "t"),
    ];
    assert_eq!(remove_prohibited(text, &mixed), SECRET_REMOVED);
    let ids = [
        Span::new(EntityKind::Iban, 0, 3, 1.0, "t"),
        Span::new(EntityKind::Person, 3, 6, 1.0, "t"),
    ];
    assert_eq!(remove_prohibited(text, &ids), "[iban removed]defghij");
    // An IBAN-shaped guess inside a 64-hex digest stays; a checksum-valid
    // IBAN score or a short token does not.
    let digest = "sha 16e07db253f23a282d673668bd4b4656bf1f410962612fa4c7b4ddd87d893d77";
    let at = digest.find("db25").unwrap();
    let guess = [Span::new(EntityKind::Iban, at, at + 28, 0.55, "t")];
    assert_eq!(remove_prohibited(digest, &guess), digest);
    let valid = [Span::new(EntityKind::Iban, at, at + 28, 1.0, "t")];
    assert_ne!(remove_prohibited(digest, &valid), digest);
    let short = "ref ab12cd34ef56";
    let guess = [Span::new(EntityKind::Iban, 4, 16, 0.55, "t")];
    assert_ne!(remove_prohibited(short, &guess), short);
}

#[test]
fn a_removal_marker_exists_for_exactly_the_prohibited_kinds() {
    for kind in EntityKind::ALL {
        // A date of birth is prohibited only as a labelled span.
        let labelled = kind == EntityKind::DateOfBirth;
        assert_eq!(
            removal_text(kind).is_some(),
            kind.is_prohibited() || labelled
        );
    }
}

#[test]
fn a_typed_placeholder_look_alike_is_masked_as_clear_text() {
    let mut gate = masking_gate();
    let (safe, _) = gate.text("tel ⟦EMAIL_abcdef⟧ fin").unwrap();
    assert_eq!(safe.as_str(), "tel ⟦⟦EMAIL_abcdef⟧ fin");
}

#[test]
fn safe_text_serializes_as_a_plain_string() {
    let mut gate = passthrough_gate();
    let (safe, _) = gate.text("salut").unwrap();
    assert_eq!(serde_json::to_string(&safe).unwrap(), "\"salut\"");
}

/// The full name every name test uses. The deterministic recognisers do not
/// find it in running prose.
const NAME: &str = "Mara Ellison";

/// Stands in for a name detector (GLiNER): it finds the full name and says
/// so through `checks_names`.
struct NameAware;

impl Detector for NameAware {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(text
            .find(NAME)
            .map(|start| {
                vec![Span::new(
                    EntityKind::Person,
                    start,
                    start + NAME.len(),
                    0.9,
                    "name",
                )]
            })
            .unwrap_or_default())
    }

    fn checks_names(&self) -> bool {
        true
    }
}

#[test]
fn a_full_name_is_masked_when_a_name_detector_runs() {
    let mut gate = tokenising_gate(KEY, Arc::new(NameAware));
    let (safe, report) = gate.text("Le dossier de Mara Ellison est prêt.").unwrap();
    assert!(!safe.as_str().contains(NAME));
    assert!(safe.as_str().contains("⟦PERSON_"));
    assert!(safe.names_checked());
    assert_eq!(report.count(EntityKind::Person), 1);
    assert!(!report.to_string().contains(NAME));
}

#[test]
fn an_open_gate_without_a_name_detector_marks_names_unchecked() {
    let (safe, _) = passthrough_gate_without_names()
        .text("Le dossier est prêt.")
        .unwrap();
    assert!(!safe.names_checked());
}

#[test]
fn a_private_gate_with_no_name_coverage_still_masks_pattern_values() {
    // A detector that does not check names: the private gate tokenises
    // what it finds and issues the text marked names-not-checked; it does
    // not refuse (owner, 2026-10-14).
    let mut gate = Gate::for_tests(&grant(PrivacyMode::Private), KEY, Arc::new(Registry::new()));
    let text = "Écris à camille@exemple.fr, IBAN FR7630006000011234567890189.";
    let (safe, _) = gate.text(text).unwrap();
    assert!(!safe.names_checked());
    assert!(
        !safe.as_str().contains("camille@exemple.fr"),
        "{}",
        safe.as_str()
    );
    assert!(
        !safe.as_str().contains("FR7630006000011234567890189"),
        "{}",
        safe.as_str()
    );
    let (value, _) = gate.value(&serde_json::json!({ "to": text })).unwrap();
    assert!(!value.names_checked());
    assert!(!value.as_value().to_string().contains("camille@exemple.fr"));
}

#[test]
fn the_deep_stack_deterministic_half_includes_the_dictionary() {
    // `NameStack` (Deep) builds its deterministic half with
    // `standard_builder`; this pins that the dictionary is in it, so Deep
    // never detects less than Standard.
    let registry = standard_builder(["Mara Ellison"])
        .expect("dictionary")
        .0
        .without_email_layer()
        .build();
    let text = "Le dossier de Mara Ellison est prêt.";
    let found = registry.analyze(text);
    assert!(found
        .iter()
        .any(|span| span.kind == EntityKind::Person && &text[span.start..span.end] == NAME));
}

#[test]
fn a_private_default_gate_without_a_dictionary_issues_and_masks_patterns() {
    // The default Standard detector mounts no dictionary: names are not
    // checked, but a phone number is still tokenised and the text issued.
    let mut gate = Gate::for_grant(&grant(PrivacyMode::Private), KEY);
    let text = "Le dossier de Mara Ellison est prêt, rappelle au +33612345678.";
    let (safe, _) = gate.text(text).unwrap();
    assert!(!safe.names_checked());
    assert!(!safe.as_str().contains("+33612345678"), "{}", safe.as_str());
    assert!(safe.as_str().contains('⟦'), "{}", safe.as_str());
}

/// NAMES-OFF (owner, 2026-10-19): a known name passes; the phone does not.
#[test]
fn a_private_standard_gate_keeps_a_known_name_and_masks_a_phone() {
    let mut gate = Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Mara Ellison"])
        .expect("dictionary");
    let text = "Le dossier de Mara Ellison est prêt, rappelle au +33612345678.";
    let (safe, _) = gate.text(text).unwrap();
    assert!(safe.as_str().contains(NAME), "{}", safe.as_str());
    assert!(!safe.as_str().contains("⟦PERSON_"), "{}", safe.as_str());
    assert!(!safe.as_str().contains("+33612345678"), "{}", safe.as_str());
}

/// TOK-CONSISTENT-1 F3: never `Mira Fictive's's` on screen.
#[test]
fn a_possessive_keeps_the_token_of_the_bare_name() {
    let names = ["Mira Fictive"];
    let mut gate = Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, names).unwrap();
    let bare = gate.text("Mira Fictive").unwrap().0.as_str().to_string();
    for apostrophe in ['\'', '’'] {
        let (safe, _) = gate
            .text(&format!("Show Mira Fictive{apostrophe}s card."))
            .unwrap();
        assert_eq!(safe.as_str(), format!("Show {bare}{apostrophe}s card."));
    }
}

#[test]
fn a_private_gate_keeps_a_hyphenated_name_whole() {
    let mut gate = Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Vosloo"])
        .expect("dictionary");
    let text = "Hi Smit-Vosloo, thanks for the file.";
    assert_eq!(gate.text(text).unwrap().0.as_str(), text);
}

#[test]
fn a_private_gate_with_a_name_detector_masks_the_name() {
    let mut gate = tokenising_gate(KEY, Arc::new(NameAware));
    let (safe, _) = gate.text("Le dossier de Mara Ellison est prêt.").unwrap();
    assert!(!safe.as_str().contains(NAME));
    assert!(safe.names_checked());
}

#[test]
fn a_value_is_marked_like_its_gate() {
    let mut gate = tokenising_gate(KEY, Arc::new(NameAware));
    let (safe, _) = gate
        .value(&serde_json::json!({ "to": "Mara Ellison" }))
        .unwrap();
    assert!(safe.names_checked());
    let wire = serde_json::to_string(&safe).unwrap();
    assert!(!wire.contains(NAME));
}

#[test]
fn a_name_that_only_the_context_suggests_does_not_refuse_the_text() {
    // The e-mail layer reads "a name" after a comma as a person, but that
    // cue depends on the words around it, which masking changes. The residue
    // scan reads values only, so the text is issued, not withheld.
    let text = "- `read_file` (risk: low): Find places matching a name, from Open-Meteo.";
    assert!(masking_gate().text(text).is_ok());
    assert!(Registry::new()
        .analyze_values(text)
        .iter()
        .all(|span| span.kind != EntityKind::Person));
}

#[test]
fn a_joined_text_is_as_covered_as_its_least_covered_part() {
    // The former literal path is the closed `KernelMarker` enum now: the
    // app-authored part is a fixed kernel constant, not a token a caller
    // writes.
    let app = SafeText::from_marker(KernelMarker::RefusalPlaceholder);
    assert_eq!(app.as_str(), "[auxesis: withheld]");
    assert!(app.names_checked());
    let open = passthrough_gate_without_names().text("Bonjour").unwrap().0;
    assert!(SafeText::join([app.clone(), app.clone()]).names_checked());
    assert!(!SafeText::join([app.clone(), open]).names_checked());
    assert_eq!(
        SafeText::join([app.clone(), app]).as_str(),
        "[auxesis: withheld][auxesis: withheld]"
    );
}

#[test]
fn a_gated_text_and_a_fixed_marker_join_without_a_literal_path() {
    // The former `safe_text_literal!("# Tools\n\n")` caller takes the
    // grant-bound path; a fixed marker comes from the closed enum.
    let (head, _) = passthrough_gate().text("# Tools\n\n").unwrap();
    let marker = SafeText::from_marker(KernelMarker::RefusalPlaceholder);
    assert_eq!(
        SafeText::join([head, marker]).as_str(),
        "# Tools\n\n[auxesis: withheld]"
    );
}

#[test]
fn minted_pairs_are_handed_out_once_and_match_the_masked_text() {
    let mut gate = masking_gate();
    let (safe, _) = gate
        .text("écrire à anne.dupont@example.org demain")
        .unwrap();
    let minted = gate.take_minted();
    assert_eq!(minted.len(), 1, "one distinct value, one pair");
    let (token, value) = &minted[0];
    assert_eq!(value, "anne.dupont@example.org");
    assert!(token.starts_with("EMAIL_"));
    assert!(safe
        .as_str()
        .contains(&format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}")));
    assert!(gate.take_minted().is_empty(), "taking forgets the pairs");
}
