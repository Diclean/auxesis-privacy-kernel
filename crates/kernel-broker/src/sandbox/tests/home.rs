//! The real home: the `HOME` fallback and the passwd home.

use super::super::home::{passwd_home, real_home_from};
use super::super::profile::seatbelt_profile;
use std::path::Path;

#[test]
fn real_home_falls_back_to_passwd_when_home_is_unusable() {
    // WSD2-P3-09: an unset/mangled HOME must not silently drop the
    // sensitive-path deny list.
    let Some(expected) = passwd_home() else {
        // No passwd entry on this host: nothing to fall back to.
        return;
    };

    assert_eq!(real_home_from(None), Some(expected.clone()));
    assert_eq!(
        real_home_from(Some(std::ffi::OsStr::new("/nonexistent-aux-home"))),
        Some(expected.clone())
    );
    assert_eq!(
        real_home_from(Some(std::ffi::OsStr::new("/"))),
        Some(expected.clone())
    );

    let profile = seatbelt_profile(
        Path::new("/tmp/ws"),
        Path::new("/tmp/tmp"),
        real_home_from(None).as_deref(),
        false,
    )
    .unwrap();
    assert!(
        profile.contains(&format!("(subpath \"{}/.ssh\")", expected.display())),
        "the passwd home must still be denied"
    );
}
