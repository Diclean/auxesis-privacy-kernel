//! The developer-directory checks: the bundle identity, the ownership, the
//! lookup and the grant they earn.

use super::super::developer_dir::{
    active_developer_dir, cached_developer_dir, developer_dir_rules, resolve_developer_dir,
    DeveloperDirCache, DeveloperDirGrant, PathFacts, CLT_DEVELOPER_DIR, DEVELOPER_DIR,
    XCODE_BUNDLE_ID,
};
use super::super::profile::seatbelt_profile_with_developer_dir;
use std::path::{Path, PathBuf};

fn profile_with_developer_dir(developer_dir: Option<&Path>) -> String {
    seatbelt_profile_with_developer_dir(
        Path::new("/tmp/ws"),
        Path::new("/tmp/tmp"),
        Some(Path::new("/Users/tester")),
        false,
        developer_dir,
        DeveloperDirGrant::Allow,
    )
    .unwrap()
}

fn fake_facts(uid: u32, mode: u32) -> impl Fn(&Path) -> Option<PathFacts> {
    move |path| {
        let meta = std::fs::symlink_metadata(path).ok()?;
        Some(PathFacts {
            uid,
            mode,
            is_dir: meta.is_dir(),
            is_symlink: meta.file_type().is_symlink(),
        })
    }
}

fn resolve(root: &Path, path: &Path, uid: u32, mode: u32, id: &'static str) -> Option<PathBuf> {
    resolve_developer_dir(path, root, &fake_facts(uid, mode), &|_| {
        Some(id.to_string())
    })
}

/// A temp directory standing in for `/Applications`, canonicalised so the
/// selected paths compare equal after canonicalisation.
fn fake_applications_root(sandbox: &tempfile::TempDir) -> PathBuf {
    let root = sandbox.path().canonicalize().unwrap().join("Applications");
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn fake_xcode_bundle(root: &Path, name: &str) -> PathBuf {
    let developer = root.join(name).join("Contents/Developer");
    std::fs::create_dir_all(&developer).unwrap();
    developer
}

#[test]
fn wrong_bundle_id_adds_no_rule() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = fake_applications_root(&sandbox);
    let developer = fake_xcode_bundle(&root, "Evil.app");
    assert_eq!(
        resolve(&root, &developer, 0, 0o755, "com.example.evil"),
        None
    );
}

#[test]
#[cfg(unix)]
fn non_root_owned_or_group_writable_bundle_adds_no_rule() {
    use std::os::unix::fs::MetadataExt;
    let sandbox = tempfile::tempdir().unwrap();
    let root = fake_applications_root(&sandbox);
    let developer = fake_xcode_bundle(&root, "Xcode.app");
    let test_uid = std::fs::symlink_metadata(&developer).unwrap().uid();
    if test_uid != 0 {
        assert_eq!(
            resolve(&root, &developer, test_uid, 0o755, XCODE_BUNDLE_ID),
            None
        );
    }
    assert_eq!(resolve(&root, &developer, 0, 0o775, XCODE_BUNDLE_ID), None);
}

#[test]
#[cfg(unix)]
fn symlinked_developer_directory_adds_no_rule() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = fake_applications_root(&sandbox);
    let real = fake_xcode_bundle(&root, "Real.app");
    let contents = root.join("Evil.app/Contents");
    std::fs::create_dir_all(&contents).unwrap();
    let link = contents.join("Developer");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(resolve(&root, &link, 0, 0o755, XCODE_BUNDLE_ID), None);
}

#[test]
fn developer_dir_environment_variable_has_no_effect() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = fake_applications_root(&sandbox);
    let selected = fake_xcode_bundle(&root, "Selected.app");
    let env_candidate = fake_xcode_bundle(&root, "Evil.app");
    std::env::set_var("DEVELOPER_DIR", &env_candidate);
    let resolved = resolve(&root, &selected, 0, 0o755, XCODE_BUNDLE_ID);
    let with_env = active_developer_dir();
    std::env::remove_var("DEVELOPER_DIR");
    let without_env = active_developer_dir();
    // A valid candidate in DEVELOPER_DIR never wins; only `xcode-select`.
    assert_eq!(resolved.as_deref(), Some(selected.as_path()));
    assert_eq!(with_env, without_env);
}

#[test]
fn resolved_xcode_developer_dir_gets_read_and_exec_but_never_write() {
    let developer_dir = Path::new("/Applications/Xcode_16.4.app/Contents/Developer");
    let base = profile_with_developer_dir(None);
    let profile = profile_with_developer_dir(Some(developer_dir));

    // The profile without the Xcode grant is byte-for-byte a prefix: no
    // existing rule moves, including the Command Line Tools grants.
    assert!(profile.starts_with(&base));
    let added = &profile[base.len()..];
    let added_rules: Vec<&str> = added
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with(';'))
        .collect();
    let expected = format!(
        "(allow file-read* (subpath \"{dir}\"))\n\
         (allow process-exec* (subpath \"{dir}\"))",
        dir = developer_dir.display()
    );
    assert_eq!(added_rules.join("\n"), expected);

    // Read + exec only: no write, network, file-map or broad
    // `/Applications` grant comes with it.
    assert!(!added.contains("file-map-executable"));
    assert!(!profile.contains("(allow network*"));
    assert!(!profile.contains("(subpath \"/Applications\")"));
    assert!(!added.contains("file-write"));
    for line in profile
        .lines()
        .filter(|line| line.starts_with("(allow file-write*"))
    {
        assert!(
            !line.contains(developer_dir.to_str().unwrap()),
            "the Xcode directory must never be writable: {line}"
        );
    }
}

#[test]
fn resolved_xcode_developer_dir_yields_exactly_read_and_exec() {
    let sandbox = tempfile::tempdir().unwrap();
    let root = fake_applications_root(&sandbox);
    let developer = fake_xcode_bundle(&root, "Xcode_16.4.app");
    let resolved = resolve(&root, &developer, 0, 0o755, XCODE_BUNDLE_ID)
        .expect("a root-owned Xcode bundle must resolve");
    let rules = developer_dir_rules(&resolved).expect("a full Xcode must get a grant");
    let rules: Vec<&str> = rules
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with(';'))
        .collect();
    assert_eq!(
        rules.join("\n"),
        format!(
            "(allow file-read* (subpath \"{dir}\"))\n\
             (allow process-exec* (subpath \"{dir}\"))",
            dir = developer.display()
        )
    );
}

#[test]
fn command_line_tools_rule_is_unchanged_byte_for_byte() {
    let base = profile_with_developer_dir(None);
    let clt = Path::new(CLT_DEVELOPER_DIR);

    // Resolving the Command Line Tools adds no rule: its existing grant is
    // already in the system trees and must not be duplicated or rewritten.
    assert_eq!(profile_with_developer_dir(Some(clt)), base);

    let exec_line = base
        .lines()
        .find(|line| line.starts_with("(allow process-exec*"))
        .expect("exec allow rule");
    assert!(exec_line.contains("(subpath \"/Library/Developer/CommandLineTools\")"));
    let read_line = base
        .lines()
        .find(|line| line.starts_with("(allow file-read*"))
        .expect("read allow rule");
    assert!(read_line.contains("(subpath \"/Library/Developer/CommandLineTools\")"));
    assert_eq!(
        base.matches("(subpath \"/Library/Developer/CommandLineTools\")")
            .count(),
        2,
        "the Command Line Tools grant must stay exactly the two existing rules"
    );
}

#[test]
fn xcode_developer_dir_overlapping_the_workspace_adds_no_rule() {
    // The grant is read-only; a workspace there would turn it writable
    // through the unconditional workspace allow, so it is skipped.
    let developer_dir = Path::new("/Applications/Xcode.app/Contents/Developer");
    let base = seatbelt_profile_with_developer_dir(
        developer_dir,
        Path::new("/tmp/tmp"),
        None,
        false,
        None,
        DeveloperDirGrant::Allow,
    )
    .unwrap();
    let profile = seatbelt_profile_with_developer_dir(
        developer_dir,
        Path::new("/tmp/tmp"),
        None,
        false,
        Some(developer_dir),
        DeveloperDirGrant::Allow,
    )
    .unwrap();
    assert_eq!(profile, base);
}

#[test]
fn the_shell_profile_keeps_the_xcode_grant() {
    // The shell tool is the one caller that gets the Xcode grant: its
    // `xcrun` shims load `libxcrun` from the selected developer directory.
    let developer_dir = Path::new("/Applications/Xcode_16.4.app/Contents/Developer");
    let profile = seatbelt_profile_with_developer_dir(
        Path::new("/tmp/ws"),
        Path::new("/tmp/tmp"),
        Some(Path::new("/Users/tester")),
        false,
        Some(developer_dir),
        DeveloperDirGrant::Allow,
    )
    .unwrap();
    assert!(
        profile.contains("full Xcode selected"),
        "the shell profile must keep the Xcode grant: {profile}"
    );
    assert!(
        profile.contains(&format!(
            "(allow file-read* (subpath \"{dir}\"))",
            dir = developer_dir.display()
        )),
        "the shell profile must keep the read grant: {profile}"
    );
    assert!(
        profile.contains(&format!(
            "(allow process-exec* (subpath \"{dir}\"))",
            dir = developer_dir.display()
        )),
        "the shell profile must keep the exec grant: {profile}"
    );
}

#[test]
fn the_developer_dir_is_looked_up_once_per_process() {
    // The lookup forks `xcode-select`, so it must run at most once per
    // process, however many profiles are built.
    let cache = DeveloperDirCache::new();
    assert_eq!(cache.lookups(), 0, "nothing runs before the first call");
    let selected = PathBuf::from("/Applications/Xcode_16.4.app/Contents/Developer");
    for _ in 0..3 {
        assert_eq!(
            cache.get(|| Some(selected.clone())),
            Some(selected.as_path()),
            "the cached value must be the one the lookup returned"
        );
    }
    assert_eq!(cache.lookups(), 1, "the lookup must run exactly once");
}

#[test]
fn the_process_cache_looks_the_developer_dir_up_at_most_once() {
    // The production cache: whatever the host has selected, the first
    // call resolves it and every later call is served from the cache.
    let first = cached_developer_dir().map(Path::to_path_buf);
    assert_eq!(
        DEVELOPER_DIR.lookups(),
        1,
        "the first call must resolve the developer directory exactly once"
    );
    let second = cached_developer_dir().map(Path::to_path_buf);
    assert_eq!(first, second, "the process cache must serve one value");
    assert_eq!(
        DEVELOPER_DIR.lookups(),
        1,
        "a warm cache must never look Xcode up again"
    );
}
