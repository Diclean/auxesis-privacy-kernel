//! The generated profile text: the rules, rule by rule.

use std::path::PathBuf;

use super::super::{seatbelt_profile, SandboxSpec};

fn spec() -> SandboxSpec {
    SandboxSpec {
        install_dir: PathBuf::from("/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2"),
        work_dir: PathBuf::from("/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2/work"),
        runtime_read_paths: vec![PathBuf::from("/usr/local/bin/node")],
        proxy_port: None,
    }
}

#[test]
fn profile_is_deny_by_default_and_writes_only_the_work_dir() {
    let profile = seatbelt_profile(&spec());
    assert!(profile.starts_with("(version 1)\n(deny default)\n"));
    assert!(
        profile.contains(
            "(allow file-write* (subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2/work\"))"
        ),
        "{profile}"
    );
    assert_eq!(profile.matches("(allow file-write*").count(), 1);
    // The install dir is readable but never writable.
    assert!(
        profile.contains("(subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2\")"),
        "{profile}"
    );
    let write_rule = profile
        .lines()
        .find(|line| line.starts_with("(allow file-write*"))
        .expect("write rule");
    assert!(!write_rule.contains("datagouv-mcp@1.4.2\")"));
}

#[test]
fn metadata_is_scoped_and_not_global() {
    let profile = seatbelt_profile(&spec());
    // No bare global metadata allow.
    assert!(
        !profile.contains("(allow file-read-metadata)\n"),
        "{profile}"
    );
    assert!(
        profile.contains("(allow file-read-metadata (literal \"/\")"),
        "{profile}"
    );
    // The components leading to the install dir are present...
    assert!(
        profile.contains("(literal \"/Users/tester/.auxesis\")"),
        "{profile}"
    );
    assert!(
        profile.contains("(literal \"/Users/tester/.auxesis/extensions\")"),
        "{profile}"
    );
    // ...but the home itself is not a subpath metadata allow.
    assert!(
        !profile.contains("(allow file-read-metadata (subpath \"/Users/tester\")"),
        "{profile}"
    );
}

#[test]
fn no_proxy_port_means_no_network_rule_at_all() {
    let profile = seatbelt_profile(&spec());
    assert!(!profile.contains("network"), "{profile}");
}

#[test]
fn proxy_port_allows_only_tcp_on_the_ipv4_loopback_port() {
    let mut spec = spec();
    spec.proxy_port = Some(49_152);
    let profile = seatbelt_profile(&spec);
    assert!(
        profile.contains("(allow network-outbound (remote tcp4 \"localhost:49152\"))"),
        "{profile}"
    );
    assert!(!profile.contains("network-inbound"), "{profile}");
    assert!(!profile.contains("(allow network*)"), "{profile}");
    assert_eq!(profile.matches("network").count(), 1);
}

#[test]
fn runtime_paths_are_executable_by_exact_path_and_readable() {
    let profile = seatbelt_profile(&spec());
    // Exec is the exact binary, never the whole directory.
    assert!(
        profile.contains("(allow process-exec* (literal \"/usr/local/bin/node\")"),
        "{profile}"
    );
    assert!(
        !profile.contains("(allow process-exec* (subpath \"/usr/local/bin\")"),
        "{profile}"
    );
    assert!(
        profile.contains("(allow file-read* (literal \"/\") (subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2\")"),
        "{profile}"
    );
    assert!(
        profile.contains("(subpath \"/System/Library\")"),
        "{profile}"
    );
    // The dyld shared cache under the Preboot Cryptexes volume.
    assert!(
        profile.contains("(subpath \"/System/Volumes/Preboot/Cryptexes\")"),
        "{profile}"
    );
    assert!(profile.contains("(literal \"/\")"), "{profile}");
}

#[test]
fn work_dir_is_never_executable() {
    let profile = seatbelt_profile(&spec());
    let deny = profile
        .lines()
        .position(|line| line.starts_with("(deny process-exec*"))
        .expect("work exec deny");
    let allow = profile
        .lines()
        .position(|line| line.starts_with("(allow process-exec*"))
        .expect("exec allow");
    assert!(
        allow < deny,
        "the work deny must come after the exec allow: {profile}"
    );
    assert!(
        profile.contains(
            "(deny process-exec* (subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2/work\"))"
        ),
        "{profile}"
    );
}

#[test]
fn process_info_is_denied_and_only_self_is_allowed_back() {
    let profile = seatbelt_profile(&spec());
    let deny = profile
        .lines()
        .position(|line| line.starts_with("(deny process-info*"))
        .expect("process-info deny");
    let allow = profile
        .lines()
        .position(|line| line.starts_with("(allow process-info* (target self)"))
        .expect("process-info self allow");
    assert!(
        deny < allow,
        "the self allow must come after the global deny: {profile}"
    );
}

#[test]
fn work_dir_cannot_be_mapped_and_iokit_properties_are_denied() {
    let profile = seatbelt_profile(&spec());
    assert!(
        profile.contains(
            "(deny file-map-executable (subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2/work\"))"
        ),
        "{profile}"
    );
    assert!(profile.contains("(deny iokit-get-properties)"), "{profile}");
}

#[test]
fn quotes_and_backslashes_in_paths_are_escaped() {
    let spec = SandboxSpec {
        install_dir: PathBuf::from("/tmp/inst\"all\\dir"),
        work_dir: PathBuf::from("/tmp/wo\"rk\\dir"),
        runtime_read_paths: Vec::new(),
        proxy_port: None,
    };
    let profile = seatbelt_profile(&spec);
    assert!(
        profile.contains("(subpath \"/tmp/inst\\\"all\\\\dir\")"),
        "{profile}"
    );
    assert!(
        profile.contains("(allow file-write* (subpath \"/tmp/wo\\\"rk\\\\dir\"))"),
        "{profile}"
    );
    // The quote never terminates the Scheme string early.
    assert!(!profile.contains("\"/tmp/inst\"all"), "{profile}");
}

#[test]
fn control_characters_are_dropped_from_paths() {
    let spec = SandboxSpec {
        install_dir: PathBuf::from("/tmp/inst\nalldir"),
        work_dir: PathBuf::from("/tmp/work\rdir"),
        runtime_read_paths: Vec::new(),
        proxy_port: None,
    };
    let profile = seatbelt_profile(&spec);
    assert!(
        profile.contains("(subpath \"/tmp/installdir\")"),
        "{profile}"
    );
    assert!(
        profile.contains("(allow file-write* (subpath \"/tmp/workdir\"))"),
        "{profile}"
    );
}
