//! The stdio (MCP) sandbox: the fixed helper, the Xcode-free profile and
//! the configured Auxesis home.

use super::super::developer_dir::DeveloperDirGrant;
use super::super::home::real_home;
use super::super::limits::SANDBOX_EXEC;
use super::super::profile::seatbelt_profile_with_developer_dir;
use super::super::stdio::StdioSandbox;
use std::path::{Path, PathBuf};

#[test]
fn new_always_wraps_the_child_with_the_fixed_sandbox_exec() {
    // No caller picks the sandbox helper. `new` must record the fixed
    // `SANDBOX_EXEC`, and the command it hands out must execute that binary:
    // a substituted wrapper would skip the profile entirely.
    let program = std::env::current_exe().expect("current exe");
    let sandbox = StdioSandbox::new(&program, false).expect("sandbox");
    assert_eq!(sandbox.sandbox_exec, PathBuf::from(SANDBOX_EXEC));
    let command = sandbox.command(&program, &[]);
    assert_eq!(
        command.as_std().get_program(),
        std::ffi::OsStr::new(SANDBOX_EXEC)
    );
}

#[test]
fn stdio_profile_never_carries_the_xcode_grant() {
    // The Xcode grant is a shell-tool affordance. The MCP sandbox must
    // stay exactly what it was before the grant existed, even when a
    // full Xcode is selected.
    let developer_dir = Path::new("/Applications/Xcode_16.4.app/Contents/Developer");
    let program = std::env::current_exe().expect("current exe");
    let sandbox =
        StdioSandbox::build_with_developer_dir(&program, false, None, Some(developer_dir))
            .expect("sandbox");

    assert!(
        !sandbox.profile.contains("full Xcode selected"),
        "the MCP sandbox must never get the Xcode grant: {}",
        sandbox.profile
    );
    assert!(
        !sandbox.profile.contains(developer_dir.to_str().unwrap()),
        "the MCP sandbox must never name the developer directory: {}",
        sandbox.profile
    );

    // It is the pre-Xcode profile, byte for byte, plus the MCP rules.
    let temp = sandbox.temp_path().canonicalize().unwrap();
    let base = seatbelt_profile_with_developer_dir(
        &temp,
        &temp,
        real_home().as_deref(),
        false,
        None,
        DeveloperDirGrant::Deny,
    )
    .unwrap();
    assert!(
        sandbox.profile.starts_with(&base),
        "the MCP profile must be the pre-Xcode profile plus its own rules: {}",
        sandbox.profile
    );
}

#[test]
fn stdio_profile_denies_the_configured_auxesis_home_and_gates_network() {
    let program = std::env::current_exe().expect("current exe");
    // Item 9: the deny follows the daemon's actual AUXESIS_HOME, not
    // `$HOME/.auxesis`. A relocated home is passed explicitly.
    let relocated = Path::new("/tmp/aux-mcp-relocated/.auxesis");
    let denied = StdioSandbox::build(&program, false, Some(relocated)).expect("sandbox");
    assert!(
        denied
            .profile
            .contains("(subpath \"/tmp/aux-mcp-relocated/.auxesis\")"),
        "the configured Auxesis home must be denied: {}",
        denied.profile
    );
    assert!(
        denied
            .profile
            .contains("(literal \"/tmp/aux-mcp-relocated/.auxesis/store.db\")"),
        "the store path must be denied too: {}",
        denied.profile
    );
    assert!(!denied.profile.contains("(allow network*)"));
    let allowed = StdioSandbox::build(&program, true, Some(relocated)).expect("sandbox");
    assert!(allowed.profile.contains("(allow network*)"));
}
