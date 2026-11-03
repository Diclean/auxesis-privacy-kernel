//! Rollback refusal, crash recovery, manifest checks and stale records.

use std::fs;

use super::*;

#[test]
fn a_copy_of_a_record_from_before_an_erasure_is_refused() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    let path = vault.record_path(&slot_for("session-a"));
    let before = fs::read(&path).unwrap();

    assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);
    fs::write(&path, &before).unwrap();

    assert!(matches!(
        vault.lookup("session-a"),
        Err(VaultError::Rollback)
    ));
    assert!(matches!(
        vault.record("session-a", &mask_text(KEY).1),
        Err(VaultError::Rollback)
    ));
}

#[test]
fn a_forgotten_session_cannot_be_restored_from_a_copy() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    let path = vault.record_path(&slot_for("session-a"));
    let before = fs::read(&path).unwrap();

    assert!(vault.forget_session("session-a").unwrap());
    fs::write(&path, &before).unwrap();

    assert!(matches!(
        vault.lookup("session-a"),
        Err(VaultError::Rollback)
    ));
}

#[test]
fn a_stale_record_is_still_erased_by_forget_value() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    let path = vault.record_path(&slot_for("session-a"));
    let before = fs::read(&path).unwrap();
    assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);

    // The old copy is back, as after a write interrupted before its record.
    fs::write(&path, &before).unwrap();
    assert_eq!(vault.forget_value(EMAIL).unwrap(), 1);

    let left = vault.lookup("session-a").unwrap();
    assert_eq!(left.len(), 1, "the phone remains");
    assert!(left.iter().all(|(_, original)| original != EMAIL));
}

#[test]
fn a_missing_or_tampered_manifest_fails_closed() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    let manifest = dir.path().join(MANIFEST_FILE);
    let sealed = fs::read(&manifest).unwrap();

    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    fs::write(&manifest, &tampered).unwrap();
    assert!(matches!(
        vault.lookup("session-a"),
        Err(VaultError::Corrupt(_))
    ));

    fs::remove_file(&manifest).unwrap();
    assert!(matches!(
        vault.lookup("session-a"),
        Err(VaultError::Corrupt(_))
    ));

    fs::write(&manifest, &sealed).unwrap();
    assert!(!vault.lookup("session-a").unwrap().is_empty());
}

#[test]
fn crash_between_a_record_and_its_manifest_commits_the_record() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
    vault.record("session-a", &marie.1).unwrap();
    let path = vault.record_path(&slot_for("session-a"));
    let before = fs::read(&path).unwrap();

    let (masked, map) = mask_text(KEY);
    arm_crash(CrashPoint::AfterRecordWrite);
    assert!(matches!(
        vault.record("session-a", &map),
        Err(VaultError::Io(_))
    ));
    drop(vault);

    let reopened = Vault::open(dir.path()).unwrap();
    assert_eq!(generations(&reopened, "session-a"), (Some(2), 1));
    // The record was replaced first, so the write is committed. The read
    // raises the manifest to match it.
    let loaded = reopened.lookup("session-a").unwrap();
    assert_eq!(loaded.len(), 3, "marie plus the two masked values");
    let report = Anonymizer::restore(&masked, &loaded, UnknownPolicy::Redact);
    assert_eq!(report.text, TEXT);
    assert_eq!(generations(&reopened, "session-a"), (Some(2), 2));

    // Once repaired, a copy from before the crashed write is refused.
    fs::write(&path, &before).unwrap();
    assert!(matches!(
        reopened.lookup("session-a"),
        Err(VaultError::Rollback)
    ));
}

#[test]
fn crash_in_the_first_write_leaves_a_usable_vault() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let (masked, map) = mask_text(KEY);
    arm_crash(CrashPoint::AfterRecordWrite);
    assert!(matches!(
        vault.record("session-a", &map),
        Err(VaultError::Io(_))
    ));
    drop(vault);

    // The manifest already existed, so the lone record is not a corrupt vault.
    let reopened = Vault::open(dir.path()).unwrap();
    let loaded = reopened.lookup("session-a").unwrap();
    let report = Anonymizer::restore(&masked, &loaded, UnknownPolicy::Redact);
    assert_eq!(report.text, TEXT);
    reopened.record("session-b", &mask_text([8; 32]).1).unwrap();
    assert_eq!(generations(&reopened, "session-a"), (Some(1), 1));
}

#[test]
fn crash_before_an_erasure_unlinks_refuses_the_record_until_a_retry() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();
    let path = vault.record_path(&slot_for("session-a"));
    let before = fs::read(&path).unwrap();

    arm_crash(CrashPoint::AfterGenerationBump);
    assert!(matches!(
        vault.forget_session("session-a"),
        Err(VaultError::Io(_))
    ));
    drop(vault);

    // The erasure is never undone: the leftover record is refused, not read.
    let reopened = Vault::open(dir.path()).unwrap();
    assert!(matches!(
        reopened.lookup("session-a"),
        Err(VaultError::Rollback)
    ));
    // A retry clears the leftover file and leaves the session empty.
    assert!(reopened.forget_session("session-a").unwrap());
    assert!(reopened.lookup("session-a").unwrap().is_empty());
    // A copy of the pre-erasure record stays refused.
    fs::write(&path, &before).unwrap();
    assert!(matches!(
        reopened.lookup("session-a"),
        Err(VaultError::Rollback)
    ));
}

#[test]
fn crash_in_an_erasure_that_empties_a_session_is_finished_by_a_retry() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]);
    vault.record("session-a", &marie.1).unwrap();

    arm_crash(CrashPoint::AfterGenerationBump);
    assert!(matches!(
        vault.forget_value("marie@example.test"),
        Err(VaultError::Io(_))
    ));
    drop(vault);

    let reopened = Vault::open(dir.path()).unwrap();
    assert!(matches!(
        reopened.lookup("session-a"),
        Err(VaultError::Rollback)
    ));
    assert_eq!(reopened.forget_value("marie@example.test").unwrap(), 1);
    assert!(reopened.lookup("session-a").unwrap().is_empty());
}

#[test]
fn crash_after_an_erasure_rewrite_keeps_the_erasure() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-a", &mask_text(KEY).1).unwrap();

    arm_crash(CrashPoint::AfterRecordWrite);
    assert!(matches!(vault.forget_value(EMAIL), Err(VaultError::Io(_))));
    drop(vault);

    let reopened = Vault::open(dir.path()).unwrap();
    let left = reopened.lookup("session-a").unwrap();
    assert_eq!(left.len(), 1, "the phone remains");
    assert!(left.iter().all(|(_, original)| original != EMAIL));
    assert!(left
        .occurrences()
        .iter()
        .all(|(_, original)| original != EMAIL));
}

#[test]
fn crash_one_below_max_commits_the_last_generation_on_read() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let (_, map) = mask_text(KEY);
    set_manifest(&vault, "session-a", u64::MAX - 1);
    arm_crash(CrashPoint::AfterRecordWrite);
    assert!(matches!(
        vault.record("session-a", &map),
        Err(VaultError::Io(_))
    ));
    drop(vault);

    // The record sits at `u64::MAX`, one ahead of the manifest: the read commits it.
    let reopened = Vault::open(dir.path()).unwrap();
    assert_eq!(
        generations(&reopened, "session-a"),
        (Some(u64::MAX), u64::MAX - 1)
    );
    assert_eq!(reopened.lookup("session-a").unwrap(), map);
    assert_eq!(
        generations(&reopened, "session-a"),
        (Some(u64::MAX), u64::MAX)
    );
    assert!(matches!(
        reopened.lookup("session-a"),
        Err(VaultError::GenerationExhausted)
    ));
}
