//! Construction, the default shell profile and the web section.

use kernel_core::WebConfig;

use crate::{ShellSandbox, ToolRegistry};

#[test]
fn defaults_carry_the_safe_shell_profile() {
    let registry = ToolRegistry::with_defaults();
    let sandbox = registry.shell_sandbox().expect("defaults build shell");
    assert!(sandbox.enabled, "sandbox on by default");
    assert!(!sandbox.network, "network off by default");
    assert!(!sandbox.allow_unsandboxed, "fail closed by default");
    // The wired registry keeps the WS-C classes: shell output is
    // untrusted (and consequential), read_file is the only read-only tool.
    assert!(registry.is_untrusted_output("shell"));
    assert!(!registry.is_read_only("shell"));
}

#[test]
fn with_shell_passes_the_profile_through() {
    // Config wiring regression (WSD-P2-07): the profile handed to the
    // registry is exactly the one the shell runs with.
    let profile = ShellSandbox::new(false, true, true);
    let registry = ToolRegistry::with_shell(profile.clone());
    assert_eq!(registry.shell_sandbox(), Some(&profile));
    assert!(registry.is_untrusted_output("shell"));
}

#[test]
fn the_registry_carries_the_web_section_for_the_engine() {
    // The default registry carries the documented defaults…
    let registry = ToolRegistry::with_defaults();
    assert_eq!(registry.web_config(), &WebConfig::default());

    // …and the production constructor passes the configured section
    // through, so the engine's egress policy and the tool's own gate agree.
    let web = WebConfig {
        mode: kernel_core::WebMode::AlwaysAsk,
        deny_domains: vec!["bad.example".to_string()],
        ..WebConfig::default()
    };
    let registry = ToolRegistry::with_shell_web(ShellSandbox::default(), web.clone());
    assert_eq!(registry.web_config(), &web);
}
