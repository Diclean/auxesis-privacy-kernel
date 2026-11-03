//! What is on disk, what Debug shows, and the generation limit.

use std::fs;

use super::*;

#[test]
fn no_value_appears_in_the_bytes_on_disk() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    vault.record("session-canary", &mask_text(KEY).1).unwrap();
    let bytes = fs::read(vault.record_path(&slot_for("session-canary"))).unwrap();

    for needle in [EMAIL, PHONE, "session-canary"] {
        assert!(
            !contains(&bytes, needle.as_bytes()),
            "a plaintext value or session id appears in the record file"
        );
    }
}

#[test]
fn debug_output_shows_neither_the_key_nor_a_value() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let key_hex = hex(&fs::read(dir.path().join(KEY_FILE)).unwrap());
    let shown = format!("{vault:?} {:?}", mask_text(KEY).1);
    assert!(!shown.contains(EMAIL));
    assert!(!shown.contains(&key_hex));
}

#[test]
fn generation_at_max_refuses_every_operation_and_writes_nothing() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let (_, map) = mask_text(KEY);
    record_at(&vault, "session-a", &map, u64::MAX);
    let path = vault.record_path(&slot_for("session-a"));
    let before = fs::read(&path).unwrap();

    for (name, result) in run_each(&vault, &map) {
        assert!(
            matches!(result, Err(VaultError::GenerationExhausted)),
            "{name} at u64::MAX: {result:?}"
        );
    }
    assert_eq!(fs::read(&path).unwrap(), before, "the record is untouched");
    assert_eq!(
        generations(&vault, "session-a"),
        (Some(u64::MAX), u64::MAX),
        "the generation does not wrap"
    );

    // A session with no record but a generation at the limit: a write is refused
    // before its record is created.
    set_manifest(&vault, "session-c", u64::MAX);
    let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]).1;
    assert!(matches!(
        vault.record("session-c", &marie),
        Err(VaultError::GenerationExhausted)
    ));
    assert!(!vault.record_path(&slot_for("session-c")).exists());

    // Another session is unaffected.
    vault.record("session-b", &marie).unwrap();
    assert_eq!(generations(&vault, "session-b"), (Some(1), 1));
}

#[test]
fn generation_one_below_max_takes_one_last_step_then_refuses() {
    let (_, map) = mask_text(KEY);
    let marie = mask(KEY, OTHER, &[("marie@example.test", EntityKind::Email)]).1;
    for step in ["record", "forget_session", "forget_value"] {
        let dir = TempDir::new().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        record_at(&vault, "session-a", &map, u64::MAX - 1);
        assert_eq!(
            vault.lookup("session-a").unwrap(),
            map,
            "{step}: a read below u64::MAX is unchanged"
        );

        let result = match step {
            "record" => vault.record("session-a", &marie),
            "forget_session" => vault.forget_session("session-a").map(|_| ()),
            _ => vault.forget_value(EMAIL).map(|_| ()),
        };
        assert!(result.is_ok(), "{step} at u64::MAX - 1: {result:?}");
        assert_eq!(
            generations(&vault, "session-a").1,
            u64::MAX,
            "{step} takes the last generation"
        );
        assert!(
            matches!(
                vault.record("session-a", &marie),
                Err(VaultError::GenerationExhausted)
            ),
            "{step}: a write past u64::MAX is refused"
        );
        assert!(
            matches!(
                vault.forget_session("session-a"),
                Err(VaultError::GenerationExhausted)
            ),
            "{step}: an erasure past u64::MAX is refused"
        );
    }
}
