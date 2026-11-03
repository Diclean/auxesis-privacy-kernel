//! Erasure: forgetting a session, a person or a value across sessions.

use std::fs;

use super::*;

#[test]
fn forget_session_removes_only_that_session() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    vault.record("session-b", &mask_text([8; 32]).1).unwrap();

    assert!(vault.forget_session("session-a").unwrap());
    assert!(vault.lookup("session-a").unwrap().is_empty());
    assert!(!vault.lookup("session-b").unwrap().is_empty());
    assert!(!vault.forget_session("session-a").unwrap());
}

#[test]
fn forget_value_erases_one_person_across_sessions() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    vault.record("session-a", &marie.1).unwrap();
    vault.record("session-b", &mask_text([8; 32]).1).unwrap();

    assert_eq!(vault.forget_value(EMAIL).unwrap(), 2);

    let a = vault.lookup("session-a").unwrap();
    assert_eq!(a.len(), 2, "phone and the other person remain");
    assert!(a.iter().all(|(_, original)| original != EMAIL));
    assert!(a
        .occurrences()
        .iter()
        .all(|(_, original)| original != EMAIL));
    assert_eq!(vault.lookup("session-b").unwrap().len(), 1);
    assert_eq!(vault.forget_value(EMAIL).unwrap(), 0);
}

#[test]
fn forget_value_matches_after_nfkc_folding() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
    vault.record("session-a", &marie.1).unwrap();

    // Fullwidth Latin folds to ASCII under NFKC.
    assert_eq!(vault.forget_value("ｍａｒｉｅ@example.test").unwrap(), 1);
    assert!(vault.lookup("session-a").unwrap().is_empty());
}

#[test]
fn forget_value_erases_a_person_in_any_case_and_padding() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    // The token keys on the exact spelling, so each surface is its own token.
    let lower = mask(
        KEY,
        "Bonjour Camille Exemple.",
        &[("Camille Exemple", EntityKind::Person)],
    );
    let upper = mask(
        KEY,
        "Bonjour CAMILLE EXEMPLE.",
        &[("CAMILLE EXEMPLE", EntityKind::Person)],
    );
    vault.record("session-a", &lower.1).unwrap();
    vault.record("session-a", &upper.1).unwrap();

    assert_eq!(vault.forget_value("camille exemple").unwrap(), 2);
    assert!(vault.lookup("session-a").unwrap().is_empty());

    vault.record("session-a", &lower.1).unwrap();
    vault.record("session-a", &upper.1).unwrap();
    assert_eq!(vault.forget_value(" CAMILLE EXEMPLE ").unwrap(), 2);
    assert!(vault.lookup("session-a").unwrap().is_empty());
}

#[test]
fn forget_value_matches_an_email_in_any_case() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
    vault.record("session-a", &marie.1).unwrap();

    assert_eq!(vault.forget_value("MARIE@Example.TEST").unwrap(), 1);
    assert!(vault.lookup("session-a").unwrap().is_empty());
}

#[test]
fn forget_value_erases_every_surface_of_a_shared_token() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    // Spaced surface first, compact surface second: one token, two surfaces.
    let text = "Appelez 06 12 34 56 78 ou 0612345678.";
    let (_, map) = mask(
        KEY,
        text,
        &[
            ("06 12 34 56 78", EntityKind::Phone),
            ("0612345678", EntityKind::Phone),
        ],
    );
    assert_eq!(map.len(), 1, "both surfaces share one token");
    vault.record("session-a", &map).unwrap();

    assert_eq!(vault.forget_value("0612345678").unwrap(), 1);
    let left = vault.lookup("session-a").unwrap();
    assert!(left.is_empty());
    assert!(left.occurrences().is_empty());
}

#[test]
fn forgetting_one_address_keeps_the_one_that_differs_by_an_accent() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let text = "Écrivez à José@example.test et à Jos@example.test.";
    let (_, map) = mask(
        KEY,
        text,
        &[
            ("José@example.test", EntityKind::Email),
            ("Jos@example.test", EntityKind::Email),
        ],
    );
    assert_eq!(map.len(), 2, "two addresses, two tokens");
    vault.record("session-a", &map).unwrap();

    assert_eq!(vault.forget_value("José@example.test").unwrap(), 1);
    let left = vault.lookup("session-a").unwrap();
    assert_eq!(left.len(), 1);
    assert!(left
        .iter()
        .all(|(_, original)| original == "Jos@example.test"));
}

#[test]
fn erasure_reaches_a_record_the_manifest_has_fallen_behind() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
    vault.record("session-a", &marie.1).unwrap();
    // A manifest restored from an older copy names generation 0.
    let mut manifest = vault.load_manifest().unwrap();
    vault
        .set_generation(&mut manifest, &slot_for("session-a"), 0)
        .unwrap();
    assert!(matches!(
        vault.lookup("session-a"),
        Err(VaultError::Corrupt(_))
    ));

    // The erasure still reaches the record, and the erased copy is newer.
    assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);
    let left = vault.lookup("session-a").unwrap();
    assert_eq!(left.len(), 2, "phone and the other person remain");
    assert!(left.iter().all(|(_, original)| original != EMAIL));
}

#[test]
fn erasure_removes_a_leftover_temp_file_of_an_interrupted_write() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    // The temp file `write_atomic` names for this record, left by a crash
    // before the rename. It holds the ciphertext of the email.
    let slot = slot_for("session-a");
    let leftover = dir
        .path()
        .join(SESSIONS_DIR)
        .join(format!(".{slot}.{RECORD_EXT}.tmp.4242.1"));
    fs::copy(vault.record_path(&slot), &leftover).unwrap();

    assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);
    assert!(
        !leftover.exists(),
        "the erased value must not survive in a temp file"
    );
}
