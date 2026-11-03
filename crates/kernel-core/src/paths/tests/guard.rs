//! Guard tests: environment, identity, symlink spellings and the port.

use super::*;
use crate::paths::guard::FORCED_REAL_HOME;
use crate::paths::*;
use std::path::{Path, PathBuf};

#[test]
fn env_override_wins() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let custom = dir.path().join("custom-auxesis");
    std::env::set_var("AUXESIS_HOME", &custom);
    assert_eq!(auxesis_home(), custom);
    std::env::remove_var("AUXESIS_HOME");
}

#[test]
fn env_override_is_trimmed() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let trimmed = dir.path().join("trimmed-auxesis");
    std::env::set_var("AUXESIS_HOME", format!("  {}  ", trimmed.display()));
    assert_eq!(auxesis_home(), trimmed);
    std::env::remove_var("AUXESIS_HOME");
}

#[test]
fn blank_override_falls_back_to_home() {
    let _guard = ENV_LOCK.lock().unwrap();
    let previous = std::env::var("HOME").ok();
    std::env::set_var("AUXESIS_HOME", "   ");
    std::env::set_var("HOME", "/home/tester");
    assert_eq!(auxesis_home(), PathBuf::from("/home/tester/.auxesis"));
    std::env::remove_var("AUXESIS_HOME");
    restore_home(previous);
}

#[test]
fn paths_live_under_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    assert_eq!(config_path(&home), home.join("config.toml"));
    assert_eq!(store_path(&home), home.join("store.db"));
    assert_eq!(log_dir(&home), home.join("logs"));
}

/// The combinations of (sandbox flag, real vs overridden `$HOME`) crossed
/// with (real vs sandbox Auxesis home), plus the incident mode.
#[test]
fn sandbox_guard_covers_the_combinations() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    let real_aux = real_home.join(DEFAULT_DIR_NAME);
    std::fs::create_dir_all(real_aux.join("nested")).unwrap();
    let sandbox_home = dir.path().join("sandbox-home");
    let sandbox_aux = sandbox_home.join(DEFAULT_DIR_NAME);
    std::fs::create_dir_all(&sandbox_aux).unwrap();

    let cases: &[(bool, Option<&Path>, &Path, bool, &str)] = &[
        (
            true,
            Some(&real_home),
            &real_aux,
            true,
            "sandbox flag + real HOME",
        ),
        (
            true,
            Some(&sandbox_home),
            &sandbox_aux,
            false,
            "recommended command",
        ),
        (
            true,
            Some(&sandbox_home),
            &real_aux,
            true,
            "incident: HOME overridden, home real",
        ),
        (false, Some(&real_home), &real_aux, false, "production"),
        (
            false,
            Some(&sandbox_home),
            &real_aux,
            true,
            "HOME override alone",
        ),
        (
            false,
            Some(&sandbox_home),
            &sandbox_aux,
            false,
            "sandbox home, no flag",
        ),
        // Item 2: empty and relative `$HOME` are violations too.
        (false, Some(Path::new("")), &real_aux, true, "empty HOME"),
        (
            false,
            Some(Path::new("relative/home")),
            &real_aux,
            true,
            "relative HOME",
        ),
        (false, None, &real_aux, true, "unset HOME"),
    ];
    for (sandbox, env_home, home, refused, label) in cases {
        let outcome = check_sandbox_home(home, &real_home, *env_home, *sandbox);
        assert_eq!(outcome.is_err(), *refused, "case {label}: {outcome:?}");
        if *refused {
            assert!(outcome.unwrap_err().contains("refus de sandbox"));
        }
    }

    // "Or under" the real home, not just equal to it.
    assert!(check_sandbox_home(
        &real_aux.join("nested"),
        &real_home,
        Some(&sandbox_home),
        true
    )
    .is_err());
}

/// Item (e): `AUXESIS_HOME` equal to the real home root is refused.
#[test]
fn sandbox_guard_refuses_the_real_home_root() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(&real_home).unwrap();
    let sandbox_home = dir.path().join("sandbox-home");
    let err = check_sandbox_home(&real_home, &real_home, Some(&sandbox_home), true).unwrap_err();
    assert!(err.contains("foyer réel"), "{err}");
}

/// Item (a): identity defeats a firmlink spelling of the real `.auxesis`
/// (`/System/Volumes/Data/…` on macOS) even though no symlink is
/// involved and the textual path is different.
#[test]
#[cfg(target_os = "macos")]
fn sandbox_guard_refuses_a_firmlink_spelling() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    let real_aux = real_home.join(DEFAULT_DIR_NAME);
    std::fs::create_dir_all(&real_aux).unwrap();
    let sandbox_home = dir.path().join("sandbox-home");
    let canonical = std::fs::canonicalize(&real_aux).unwrap();
    let firmlink = PathBuf::from("/System/Volumes/Data").join(
        canonical
            .strip_prefix("/")
            .expect("canonical path is absolute"),
    );
    assert!(
        std::fs::metadata(&firmlink).is_ok(),
        "the firmlink spelling must resolve: {}",
        firmlink.display()
    );
    assert!(
        check_sandbox_home(&firmlink, &real_home, Some(&sandbox_home), true).is_err(),
        "the firmlink spelling must be refused"
    );
    // …and the same spelling must not be usable as AUXESIS_HOME.
    assert!(check_sandbox_home(
        &firmlink.join("future"),
        &real_home,
        Some(&sandbox_home),
        true
    )
    .is_err());
}

/// Item (a): case- and normalisation-insensitive variants of the real
/// `.auxesis` (APFS/HFS+) must be refused.
#[test]
fn sandbox_guard_refuses_case_and_normalisation_variants() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox_home = dir.path().join("sandbox-home");

    // The real `.auxesis` may not exist yet (e.g. on CI): the tail must
    // still compare case-insensitively.
    let absent_real = dir.path().join("absent-real");
    std::fs::create_dir_all(&absent_real).unwrap();
    assert!(
        check_sandbox_home(
            &absent_real.join(".AUXESIS"),
            &absent_real,
            Some(&sandbox_home),
            true
        )
        .is_err(),
        ".AUXESIS must be refused even when the real home does not exist"
    );

    // An NFD/NFC pair must compare equal. Rust source strings are NFC
    // ("é" = U+00E9); the decomposed spelling is "e" + U+0301. The home
    // does not exist, so the comparison itself has to normalise.
    let composed = dir.path().join("Caf\u{00e9}");
    let decomposed = dir.path().join("Cafe\u{0301}");
    assert!(
        check_sandbox_home(
            &decomposed.join(DEFAULT_DIR_NAME),
            &composed,
            Some(&sandbox_home),
            true
        )
        .is_err(),
        "NFC/NFD variants must compare equal"
    );
    assert!(
        check_sandbox_home(
            &composed.join(DEFAULT_DIR_NAME),
            &decomposed,
            Some(&sandbox_home),
            true
        )
        .is_err(),
        "NFC/NFD variants must compare equal (other direction)"
    );

    // When it exists, identity resolves the spelling as well.
    let real_home = dir.path().join("real-home");
    std::fs::create_dir_all(real_home.join(DEFAULT_DIR_NAME)).unwrap();
    assert!(
        check_sandbox_home(
            &real_home.join(".AUXESIS"),
            &real_home,
            Some(&sandbox_home),
            true
        )
        .is_err(),
        ".AUXESIS must be refused when the real home exists"
    );
}

/// Item 2: a missing `AUXESIS_HOME` with an unusable `$HOME` must never
/// fall back to the CWD or the real home.
#[test]
fn sandbox_guard_refuses_a_missing_home_without_a_usable_home_env() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    for env_home in [None, Some(Path::new("")), Some(Path::new("relative"))] {
        let ctx = SandboxContext::new(
            Some(real_home.clone()),
            env_home.map(Path::to_path_buf),
            false,
        );
        assert!(ctx.active, "invalid HOME must arm the guard: {env_home:?}");
        let err = ctx.resolve_home_from(None).unwrap_err();
        assert!(err.contains("refus de sandbox"), "{err}");
    }
    // A valid HOME still resolves the documented fallback.
    let ctx = SandboxContext::new(Some(real_home.clone()), Some(real_home.clone()), false);
    assert_eq!(
        ctx.resolve_home_from(None).unwrap(),
        real_home.join(DEFAULT_DIR_NAME)
    );
}

/// A relative `AUXESIS_HOME` is refused while the guard is active.
#[test]
fn sandbox_guard_refuses_a_relative_auxesis_home() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    let sandbox_home = dir.path().join("sandbox-home");
    let ctx = SandboxContext::new(Some(real_home.clone()), Some(sandbox_home.clone()), true);
    assert!(ctx.resolve_home_from(Some("./.auxesis")).is_err());
    // Production (HOME == real home, no flag) keeps the historical
    // tolerance.
    let ctx = SandboxContext::new(Some(real_home.clone()), Some(real_home), false);
    assert!(ctx.resolve_home_from(Some("./.auxesis")).is_ok());
}

/// Symlinked spellings, including ancestors of a home not created yet.
#[test]
#[cfg(unix)]
fn sandbox_guard_refuses_symlinked_spellings() {
    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    let real_aux = real_home.join(DEFAULT_DIR_NAME);
    std::fs::create_dir_all(real_aux.join("nested")).unwrap();
    let sandbox_home = dir.path().join("sandbox-home");
    std::fs::create_dir_all(&sandbox_home).unwrap();

    // A symlink straight to the real Auxesis home.
    let alias = sandbox_home.join("alias");
    std::os::unix::fs::symlink(&real_aux, &alias).unwrap();
    assert!(check_sandbox_home(&alias, &real_home, Some(&sandbox_home), true).is_err());
    // … even when the leaf does not exist yet (the ancestor is resolved).
    assert!(check_sandbox_home(
        &alias.join("nested").join("future"),
        &real_home,
        Some(&sandbox_home),
        true
    )
    .is_err());
    // A symlinked spelling of the real home itself.
    let home_alias = sandbox_home.join("home-alias");
    std::os::unix::fs::symlink(&real_home, &home_alias).unwrap();
    assert!(check_sandbox_home(
        &home_alias.join(DEFAULT_DIR_NAME),
        &real_home,
        Some(&sandbox_home),
        true
    )
    .is_err());
    // A shared *string* prefix is not a shared path prefix.
    assert!(check_sandbox_home(
        &real_home.join(".auxesis-evil"),
        &real_home,
        Some(&sandbox_home),
        true
    )
    .is_ok());
    // A symlink that leaves the real tree stays allowed.
    let away = sandbox_home.join("away");
    std::os::unix::fs::symlink(&sandbox_home, &away).unwrap();
    assert!(check_sandbox_home(
        &away.join(DEFAULT_DIR_NAME),
        &real_home,
        Some(&sandbox_home),
        true
    )
    .is_ok());

    // A *dangling* symlink to the real home (the real `.auxesis` may not
    // exist yet, e.g. on CI) is still refused, leaf included.
    let absent_real = dir.path().join("absent-real");
    std::fs::create_dir_all(&absent_real).unwrap();
    let dangling = sandbox_home.join("dangling");
    std::os::unix::fs::symlink(absent_real.join(DEFAULT_DIR_NAME), &dangling).unwrap();
    assert!(check_sandbox_home(&dangling, &absent_real, Some(&sandbox_home), true).is_err());
    assert!(check_sandbox_home(
        &dangling.join("future"),
        &absent_real,
        Some(&sandbox_home),
        true
    )
    .is_err());
}

/// The OS user database, not `$HOME`, decides what "real" means.
#[test]
#[cfg(unix)]
fn real_user_home_ignores_a_sandboxed_home_override() {
    let _guard = ENV_LOCK.lock().unwrap();
    let Some(from_db) = real_user_home() else {
        return;
    };
    let previous_home = std::env::var("HOME").ok();
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    assert_eq!(real_user_home(), Some(from_db));
    restore_home(previous_home);
}

/// J02-2-BI2-03: a failed passwd lookup fails closed while the guard is
/// active, whatever `$HOME` says.
#[test]
fn guard_fails_closed_when_the_passwd_lookup_fails() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let sandbox_home = dir.path().join("sandbox-home");
    let previous_home = std::env::var("HOME").ok();
    let previous_aux = std::env::var("AUXESIS_HOME").ok();
    let previous_forced = FORCED_REAL_HOME.with(|slot| slot.borrow().clone());

    FORCED_REAL_HOME.with(|slot| *slot.borrow_mut() = Some(None));
    std::env::set_var(SANDBOX_ENV, "1");
    std::env::set_var("HOME", dir.path());
    std::env::set_var("AUXESIS_HOME", &sandbox_home);
    let err = ensure_sandbox_guard(Some(0)).unwrap_err();
    assert!(
        err.contains("introuvable") || err.contains("lookup"),
        "{err}"
    );

    // Restore everything before asserting the happy path.
    std::env::remove_var(SANDBOX_ENV);
    FORCED_REAL_HOME.with(|slot| *slot.borrow_mut() = previous_forced);
    match previous_aux {
        Some(value) => std::env::set_var("AUXESIS_HOME", value),
        None => std::env::remove_var("AUXESIS_HOME"),
    }
    restore_home(previous_home);
}

/// End-to-end guard: the incident's own spelling is refused, the
/// recommended literal invocation is accepted.
#[test]
fn guard_refuses_the_incident_and_allows_the_recommended() {
    let _guard = ENV_LOCK.lock().unwrap();
    let Some(os_home) = real_user_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let previous_home = std::env::var("HOME").ok();
    let previous_aux = std::env::var("AUXESIS_HOME").ok();
    std::env::set_var("HOME", dir.path());
    std::env::set_var(SANDBOX_ENV, "1");

    // The incident: HOME=<tmp> but AUXESIS_HOME expanded to the real home.
    std::env::set_var("AUXESIS_HOME", os_home.join(DEFAULT_DIR_NAME));
    let refused = ensure_sandbox_guard(Some(0)).unwrap_err();
    assert!(refused.contains("refus de sandbox"), "{refused}");
    // Its own recommendation must work now.
    let sandbox = dir.path().join(DEFAULT_DIR_NAME);
    std::fs::create_dir_all(&sandbox).unwrap();
    std::env::set_var("AUXESIS_HOME", &sandbox);
    // The guard exports the canonical path (macOS temp dirs are behind
    // /private/var).
    let exported = ensure_sandbox_guard(Some(0)).unwrap();
    assert_eq!(exported, std::fs::canonicalize(&sandbox).unwrap());
    // …but the real daemon port stays refused while the guard is active.
    let port_refused = ensure_sandbox_guard(Some(REAL_DAEMON_PORT)).unwrap_err();
    assert!(port_refused.contains("2893"), "{port_refused}");

    std::env::remove_var(SANDBOX_ENV);
    match previous_aux {
        Some(value) => std::env::set_var("AUXESIS_HOME", value),
        None => std::env::remove_var("AUXESIS_HOME"),
    }
    restore_home(previous_home);
}

/// An overridden `HOME` alone activates the guard; `AUXESIS_SANDBOX`
/// values other than `1` do not.
#[test]
fn guard_activates_on_home_override_and_only_literal_one() {
    let _guard = ENV_LOCK.lock().unwrap();
    let Some(os_home) = real_user_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let previous_home = std::env::var("HOME").ok();
    let real_aux = os_home.join(DEFAULT_DIR_NAME);

    std::env::remove_var(SANDBOX_ENV);
    std::env::set_var("HOME", dir.path());
    assert!(ensure_sandbox_home(&real_aux).is_err());
    std::env::set_var(SANDBOX_ENV, "0");
    assert!(ensure_sandbox_home(&real_aux).is_err());

    // Inert only when neither signal is present.
    restore_home(Some(os_home.to_string_lossy().into_owned()));
    assert!(ensure_sandbox_home(&real_aux).is_ok());

    std::env::remove_var(SANDBOX_ENV);
    restore_home(previous_home);
}

/// Item 5: the port guard follows the guard's active condition, not just
/// the flag, and only refuses the real daemon port.
#[test]
fn sandbox_port_guard_refuses_2893() {
    let _guard = ENV_LOCK.lock().unwrap();
    let previous_flag = std::env::var(SANDBOX_ENV).ok();
    let previous_home = std::env::var("HOME").ok();
    let Some(os_home) = real_user_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();

    std::env::set_var(SANDBOX_ENV, "1");
    let refused = ensure_sandbox_port(REAL_DAEMON_PORT).unwrap_err();
    assert!(refused.contains("refus de sandbox"), "{refused}");
    assert!(refused.contains("2893"), "{refused}");
    assert!(ensure_sandbox_port(0).is_ok());
    assert!(ensure_sandbox_port(2894).is_ok());

    // A HOME override alone arms the port guard too (no flag).
    std::env::remove_var(SANDBOX_ENV);
    std::env::set_var("HOME", dir.path());
    assert!(ensure_sandbox_port(REAL_DAEMON_PORT).is_err());
    assert!(ensure_sandbox_port(0).is_ok());

    // Inert in production.
    restore_home(Some(os_home.to_string_lossy().into_owned()));
    assert!(ensure_sandbox_port(REAL_DAEMON_PORT).is_ok());
    std::env::set_var(SANDBOX_ENV, "0");
    assert!(ensure_sandbox_port(REAL_DAEMON_PORT).is_ok());

    match previous_flag {
        Some(value) => std::env::set_var(SANDBOX_ENV, value),
        None => std::env::remove_var(SANDBOX_ENV),
    }
    restore_home(previous_home);
}
