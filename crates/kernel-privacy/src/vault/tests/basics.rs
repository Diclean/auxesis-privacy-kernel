//! Records, key files and session isolation: the vault's public surface.

use std::fs;

use super::*;

#[test]
fn round_trip_restores_the_exact_text() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let (masked, map) = mask_text(KEY);
    vault.record("session-a", &map).unwrap();

    let loaded = vault.lookup("session-a").unwrap();
    assert_eq!(loaded, map);
    let report = Anonymizer::restore(&masked, &loaded, UnknownPolicy::Redact);
    assert!(report.is_clean());
    assert_eq!(report.text, TEXT);
}

#[test]
fn wrong_key_is_rejected_not_read_as_empty() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();

    fs::write(dir.path().join(KEY_FILE), [9u8; KEY_LEN]).unwrap();
    let reopened = Vault::open(dir.path()).unwrap();
    assert!(matches!(
        reopened.lookup("session-a"),
        Err(VaultError::Corrupt(_))
    ));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    let path = vault.record_path(&slot_for("session-a"));
    let original = fs::read(&path).unwrap();

    for index in [
        MAGIC.len() + NONCE_LEN,
        MAGIC.len() + NONCE_LEN + 1,
        original.len() - 1,
    ] {
        let mut bytes = original.clone();
        bytes[index] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        assert!(
            matches!(vault.lookup("session-a"), Err(VaultError::Corrupt(_))),
            "a flipped byte at {index} was accepted"
        );
    }
    fs::write(&path, &original).unwrap();
    assert!(!vault.lookup("session-a").unwrap().is_empty());
}

#[test]
fn key_and_directories_are_private() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("privacy");
    let vault = Vault::open(&root).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();

    assert_eq!(mode(&root.join(KEY_FILE)), 0o600);
    assert_eq!(mode(&root.join(MANIFEST_FILE)), 0o600);
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&root.join(SESSIONS_DIR)), 0o700);
    assert_eq!(mode(&vault.record_path(&slot_for("session-a"))), 0o600);
}

#[test]
fn key_readable_by_others_is_refused() {
    let dir = TempDir::new().unwrap();
    Vault::open(dir.path()).unwrap();
    fs::set_permissions(dir.path().join(KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Vault::open(dir.path()),
        Err(VaultError::KeyUnavailable(_))
    ));
}

#[test]
fn missing_key_beside_records_fails_closed() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    fs::remove_file(dir.path().join(KEY_FILE)).unwrap();
    assert!(matches!(
        Vault::open(dir.path()),
        Err(VaultError::KeyUnavailable(_))
    ));
}

#[test]
fn one_sessions_tokens_do_not_resolve_in_another_session() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let (masked, map) = mask_text(KEY);
    vault.record("session-a", &map).unwrap();

    let other = vault.lookup("session-b").unwrap();
    assert!(other.is_empty());
    let report = Anonymizer::restore(&masked, &other, UnknownPolicy::Redact);
    assert_eq!(report.unknown.len(), 2);
    assert!(!report.text.contains(EMAIL));
    assert!(!report.text.contains(PHONE));
}

#[test]
fn record_moved_to_another_session_slot_is_rejected() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    fs::copy(
        vault.record_path(&slot_for("session-a")),
        vault.record_path(&slot_for("session-b")),
    )
    .unwrap();

    assert!(matches!(
        vault.lookup("session-b"),
        Err(VaultError::Corrupt(_))
    ));
    assert!(!vault.lookup("session-a").unwrap().is_empty());
}

#[test]
fn a_token_mapped_to_another_value_is_refused() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let token = "PHONE_0A1B2C3D4E5F";
    vault
        .record("session-a", &single(token, "0612345678"))
        .unwrap();
    let before = vault.lookup("session-a").unwrap();

    // A second value that minted the same token, as two anonymizers can.
    let clash = single(token, "0712345678");
    assert!(matches!(
        vault.record("session-a", &clash),
        Err(VaultError::TokenConflict)
    ));
    assert_eq!(vault.lookup("session-a").unwrap(), before);
}

#[test]
fn the_same_value_under_another_surface_is_not_a_conflict() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let token = "PHONE_0A1B2C3D4E5F";
    vault
        .record("session-a", &single(token, "06 12 34 56 78"))
        .unwrap();
    vault
        .record("session-a", &single(token, "0612345678"))
        .unwrap();

    let loaded = vault.lookup("session-a").unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.occurrences().len(), 2);
}

#[test]
fn two_handles_recording_in_parallel_keep_every_update() {
    let dir = TempDir::new().unwrap();
    Vault::open(dir.path()).unwrap();
    std::thread::scope(|scope| {
        for worker in 0..2 {
            let root = dir.path();
            scope.spawn(move || {
                let vault = Vault::open(root).unwrap();
                for index in 0..25 {
                    let needle = format!("worker{worker}-{index}@example.test");
                    let text = format!("Écrivez à {needle}.");
                    let (_, map) = mask(KEY, &text, &[(needle.as_str(), EntityKind::Email)]);
                    vault.record("session-shared", &map).unwrap();
                }
            });
        }
    });

    let vault = Vault::open(dir.path()).unwrap();
    assert_eq!(vault.lookup("session-shared").unwrap().len(), 50);
}

#[test]
fn recording_the_same_map_twice_keeps_one_entry_per_token() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let (masked, map) = mask_text(KEY);
    vault.record("session-a", &map).unwrap();
    vault.record("session-a", &map).unwrap();

    let loaded = vault.lookup("session-a").unwrap();
    assert_eq!(loaded.len(), 2);
    let report = Anonymizer::restore(&masked, &loaded, UnknownPolicy::Redact);
    assert_eq!(report.text, TEXT);
}
