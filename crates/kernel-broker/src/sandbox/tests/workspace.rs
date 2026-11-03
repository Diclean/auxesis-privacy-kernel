//! The workspace rules: the protected locations a workspace may not
//! overlap, and the quoting of a path that must not shape the profile.

use super::super::{seatbelt_profile, LaunchError};
use std::path::Path;

#[test]
fn profile_refuses_workspaces_that_overlap_protected_locations() {
    let home = Path::new("/Users/tester");
    let temp = Path::new("/tmp/tmp");

    for workspace in [
        "/Users/tester",
        "/Users/tester/.ssh",
        "/Users/tester/.ssh/sub",
        "/Users/tester/.aws",
        "/Users/tester/.config",
        "/Users/tester/Library/Keychains",
        "/Users/tester/Library/Messages",
        "/Users/tester/Library/Safari",
        "/Users/tester/Library/Application Support/Google/Chrome",
        "/Library/Keychains",
        "/Library/Keychains/System",
        "/private/var/db/diagnostics",
        "/private/var/log",
        "/Users",
        // WSD2-P2-04: a workspace that IS a read-only tree would turn it
        // writable through the unconditional workspace allow.
        "/usr",
        "/usr/local",
        "/usr/local/bin",
        "/opt/homebrew",
        "/opt/homebrew/bin",
        "/opt/homebrew/var/log",
        "/System",
        "/System/Library",
        "/private/etc/ssl",
        "/private/var/db/dyld",
        "/dev",
        // WSD3-P2-02: the read-back trees are read-only in the profile
        // too, so they can never be a workspace.
        "/Library/Ruby",
        "/Library/Ruby/Gems",
        "/opt/homebrew/etc/openssl@3/certs",
        "/opt/homebrew/etc/ca-certificates",
    ] {
        let err =
            seatbelt_profile(Path::new(workspace), temp, Some(home), false).expect_err(workspace);
        assert!(
            matches!(err, LaunchError::SensitiveWorkspace(_)),
            "{workspace}: {err}"
        );
    }

    // A workspace inside the Auxesis home is the intended production
    // layout and must stay allowed.
    for workspace in [
        "/Users/tester/.auxesis/agents/main/workspace",
        "/Users/tester/.auxesis/agents/axis/workspace/nested",
    ] {
        assert!(
            seatbelt_profile(Path::new(workspace), temp, Some(home), false).is_ok(),
            "{workspace} must be allowed"
        );
    }

    // An unrelated directory stays fine.
    assert!(seatbelt_profile(Path::new("/Users/other/proj"), temp, Some(home), false).is_ok());
}

#[test]
fn profile_escapes_special_characters_in_paths() {
    let profile = seatbelt_profile(
        Path::new("/tmp/we\"ird\\ws"),
        Path::new("/tmp/tmp"),
        None,
        false,
    )
    .unwrap();
    assert!(profile.contains("(subpath \"/tmp/we\\\"ird\\\\ws\")"));

    let err = seatbelt_profile(
        Path::new("/tmp/line\nbreak"),
        Path::new("/tmp"),
        None,
        false,
    )
    .unwrap_err();
    assert!(matches!(err, LaunchError::UnsafeWorkspace(_)));
}
