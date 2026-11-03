//! The registry: what it mounts by default, and what the e-mail layer adds.

use crate::span::EntityKind;

use super::super::Registry;

#[test]
fn default_registry_runs_every_recognizer() {
    let registry = Registry::new();
    assert!(!registry.recognizers().is_empty());
    assert!(registry
        .recognizers()
        .iter()
        .all(|recognizer| recognizer.enabled_by_default()));
}

#[test]
fn builder_mounts_all_recognizers() {
    let registry = Registry::builder().with_all().build();
    assert_eq!(
        registry.recognizers().len(),
        Registry::new().recognizers().len()
    );
    assert!(registry
        .recognizers()
        .iter()
        .any(|recognizer| !recognizer.verified()));
}

#[test]
fn email_layer_is_mounted_by_default_and_masks_a_header_name() {
    assert!(Registry::new().email_layer().is_some());
    assert!(!Registry::new()
        .email_layer()
        .expect("email layer")
        .masks_first_names());
    // Wiring check: the default path runs the email layer, so a sender
    // display name with no deterministic recogniser is still masked.
    let text = "De : Océane Mabille <oceane.mabille@example.invalid>";
    let spans = Registry::new().analyze(text);
    assert!(
        spans.iter().any(|span| {
            span.kind == EntityKind::Person && &text[span.start..span.end] == "Océane Mabille"
        }),
        "{spans:?}"
    );
    let without = Registry::builder().with_all().without_email_layer().build();
    assert!(without.email_layer().is_none());
    assert!(without
        .analyze(text)
        .iter()
        .all(|span| span.kind != EntityKind::Person));
}

#[test]
fn bare_first_names_are_off_by_default_and_the_switch_restores_them() {
    // A lone given name in a greeting is not a person by default. A
    // signature singleton is a different case: that context always keeps
    // the span (see `signature_and_header_singletons_always_stay`).
    let text = "Bonjour Théo,\n\nThéo";
    assert!(Registry::new()
        .analyze(text)
        .iter()
        .all(|span| span.kind != EntityKind::Person));
    let strict = Registry::builder()
        .with_all()
        .mask_first_names(true)
        .build();
    assert!(strict
        .analyze(text)
        .iter()
        .any(|span| span.kind == EntityKind::Person));
    // A full name is always masked, whatever the switch.
    let full = "Cordialement,\nThéo Lambrecht";
    assert!(Registry::new()
        .analyze(full)
        .iter()
        .any(|span| span.kind == EntityKind::Person));
}
