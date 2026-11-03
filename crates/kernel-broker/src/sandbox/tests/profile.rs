//! The generated profile text: the rules, rule by rule.

use super::super::seatbelt_profile;
use std::path::Path;

#[test]
fn profile_is_deny_by_default_and_scopes_writes() {
    let profile = seatbelt_profile(
        Path::new("/tmp/ws"),
        Path::new("/tmp/tmp"),
        Some(Path::new("/Users/tester")),
        false,
    )
    .unwrap();

    assert!(profile.starts_with("(version 1)\n(deny default)\n"));
    assert!(profile.contains("(allow file-write* (subpath \"/tmp/ws\") (subpath \"/tmp/tmp\"))"));
    assert!(profile.contains("(deny file-write* (subpath \"/tmp/ws/.git\"))"));
    assert!(profile.contains("(subpath \"/usr\")"));
    assert!(!profile.contains("(allow network*)"));

    // Sensitive paths are denied after the broad allows, so the deny wins.
    let deny_at = profile.find("(deny file-read*").unwrap();
    let allow_at = profile.find("(allow file-read-metadata)").unwrap();
    assert!(deny_at > allow_at);
    assert!(profile.contains("(subpath \"/Users/tester/.auxesis\")"));
    assert!(profile.contains("(subpath \"/Users/tester/.ssh\")"));
    assert!(profile.contains("(subpath \"/Users/tester/Library/Keychains\")"));
    assert!(profile.contains("(subpath \"/Users/tester/Library/Messages\")"));
    assert!(profile.contains("(subpath \"/Users/tester/Library/Mail\")"));
    assert!(profile.contains("(literal \"/Users/tester/.netrc\")"));
    assert!(profile.contains("(subpath \"/Library/Keychains\")"));

    // The workspace allow comes after the sensitive denies.
    let ws_allow_at = profile
        .rfind("(allow file-read* (subpath \"/tmp/ws\")")
        .unwrap();
    assert!(
        ws_allow_at > deny_at,
        "workspace allow must override the home deny"
    );

    // Network is opt-in only.
    let with_net =
        seatbelt_profile(Path::new("/tmp/ws"), Path::new("/tmp/tmp"), None, true).unwrap();
    assert!(with_net.contains("(allow network*)"));
    assert!(
        with_net.contains("all sockets for v1"),
        "network semantics must stay documented in the profile"
    );
    let no_net =
        seatbelt_profile(Path::new("/tmp/ws"), Path::new("/tmp/tmp"), None, false).unwrap();
    assert!(no_net.contains("all sockets denied"));
}

#[test]
fn read_allowlist_is_minimal() {
    // No blanket `/private/var/db`, `/Library` or `/private/etc` reads:
    // only the explicit paths we can name.
    let profile = seatbelt_profile(
        Path::new("/tmp/ws"),
        Path::new("/tmp/tmp"),
        Some(Path::new("/Users/tester")),
        false,
    )
    .unwrap();

    assert!(!profile.contains("(subpath \"/private/var/db\")"));
    assert!(!profile.contains("(subpath \"/Library\")"));
    assert!(!profile.contains("(subpath \"/private/etc\")"));
    assert!(!profile.contains("(allow file-read* (subpath \"/private/var/log\")"));

    // WSD2-P1-02: the package prefixes must NEVER be allowed wholesale —
    // the top-level trees are owner-owned and hold git checkouts, service
    // state and configs. Only the program directories are allowed.
    assert!(
        !profile.contains("(subpath \"/opt/homebrew\")"),
        "the whole /opt/homebrew prefix must never be allowed"
    );
    assert!(
        !profile.contains("(subpath \"/usr/local\")"),
        "the whole /usr/local prefix must never be allowed"
    );
    for allowed in [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/opt/homebrew/opt",
        "/opt/homebrew/Cellar",
        "/opt/homebrew/lib",
        "/opt/homebrew/include",
        "/opt/homebrew/share",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/local/opt",
        "/usr/local/Cellar",
        "/usr/local/lib",
        "/usr/local/include",
        "/usr/local/share",
    ] {
        assert!(
            profile.contains(&format!("(subpath \"{allowed}\")")),
            "missing package program dir {allowed}"
        );
    }
    assert!(!profile.contains(".cargo"));
    assert!(!profile.contains(".rustup"));

    // The minimal paths that common commands actually need are present.
    for allowed in [
        "/private/var/db/timezone",
        "/private/var/db/dyld",
        "/private/etc/hosts",
        "/private/etc/resolv.conf",
        "/private/etc/localtime",
        "/private/etc/ssl",
    ] {
        assert!(
            profile.contains(&format!("(subpath \"{allowed}\")"))
                || profile.contains(&format!("(literal \"{allowed}\")")),
            "missing minimal allow {allowed}"
        );
    }

    // The unprotected machine-state trees are denied in the deny rule,
    // which is emitted after the system allows.
    let deny_line = profile
        .lines()
        .find(|line| line.starts_with("(deny file-read*"))
        .expect("profile must contain a deny rule");
    let deny_at = profile.find(deny_line).unwrap();
    let system_allow_at = profile.find("(allow file-read*").unwrap();
    assert!(
        deny_at > system_allow_at,
        "deny rule must come after the system allows"
    );
    for denied in [
        "/Library/Keychains",
        "/Library/Logs",
        "/private/var/log",
        "/private/var/db/diagnostics",
        "/private/var/db/uuidtext",
        "/var/root",
        // WSD2-P1-02: package state dirs stay explicitly denied.
        "/opt/homebrew/var",
        "/opt/homebrew/etc",
        "/opt/homebrew/Library",
        "/opt/homebrew/Caskroom",
        "/usr/local/var",
        "/usr/local/etc",
        "/usr/local/Library",
        "/usr/local/Caskroom",
    ] {
        assert!(
            deny_line.contains(&format!("(subpath \"{denied}\")")),
            "missing explicit deny {denied}"
        );
    }

    // WSD3-P2-01 / WSD3-P2-02: the specific read-backs after the deny are
    // present, and *no* read-allow rule ever covers a broad package/`etc`
    // prefix — only the named files and public cert/gem/Homebrew-code
    // directories.
    let allow_lines: Vec<&str> = profile
        .lines()
        .filter(|line| line.starts_with("(allow file-read*"))
        .collect();
    for path in [
        "/opt/homebrew/etc/openssl@3/openssl.cnf",
        "/usr/local/etc/openssl@3/openssl.cnf",
    ] {
        assert!(
            allow_lines
                .iter()
                .any(|line| line.contains(&format!("(literal \"{path}\")"))),
            "missing OpenSSL config read-back {path}"
        );
    }
    for path in [
        "/opt/homebrew/etc/openssl@3/certs",
        "/opt/homebrew/etc/ca-certificates",
        "/Library/Ruby",
    ] {
        assert!(
            allow_lines
                .iter()
                .any(|line| line.contains(&format!("(subpath \"{path}\")"))),
            "missing read-back directory {path}"
        );
    }
    for line in &allow_lines {
        for broad in [
            "(subpath \"/opt/homebrew/etc\")",
            "(subpath \"/opt/homebrew/var\")",
            "(subpath \"/opt/homebrew/Library\")",
            "(subpath \"/usr/local/etc\")",
            "(subpath \"/usr/local/var\")",
            "(subpath \"/usr/local/Library\")",
            "(subpath \"/Library\")",
            "(subpath \"/private/etc\")",
            "(subpath \"/private/var\")",
            "(subpath \"/Users\")",
        ] {
            assert!(
                !line.contains(broad),
                "a broad read allow returned: {broad} in {line}"
            );
        }
    }
}

#[test]
fn homebrew_library_homebrew_is_readable_but_the_rest_of_library_is_not() {
    // H-07 (calibration): `brew --version`/`list`/`info` read their own
    // code out of `Library/Homebrew`. The read-back is emitted *after*
    // the package deny (last-match-wins) so it wins for its own subtree;
    // `etc`, `var` and `Caskroom` keep their deny.
    let profile = seatbelt_profile(
        Path::new("/tmp/ws"),
        Path::new("/tmp/tmp"),
        Some(Path::new("/Users/tester")),
        false,
    )
    .unwrap();

    for path in [
        "/opt/homebrew/Library/Homebrew",
        "/usr/local/Library/Homebrew",
    ] {
        let deny_line = profile
            .lines()
            .find(|line| line.starts_with("(deny file-read*"))
            .expect("deny rule");
        assert!(
            deny_line.contains(&format!("(subpath \"{path}\")"))
                || deny_line.contains("(subpath \"/opt/homebrew/Library\")"),
            "the Library deny must still cover {path}"
        );
        let allow_at = profile
            .find(&format!("(subpath \"{path}\")"))
            .unwrap_or_else(|| panic!("missing read-back {path}"));
        let deny_at = profile.find(deny_line).unwrap();
        assert!(
            allow_at > deny_at,
            "the read-back for {path} must come after the deny (last-match-wins)"
        );
    }
    // The deny itself still names the whole Library tree for both
    // prefixes: only the named subdirectory is read back.
    let deny_line = profile
        .lines()
        .find(|line| line.starts_with("(deny file-read*"))
        .expect("deny rule");
    for denied in [
        "/opt/homebrew/Library",
        "/opt/homebrew/var",
        "/opt/homebrew/etc",
        "/opt/homebrew/Caskroom",
        "/usr/local/Library",
        "/usr/local/var",
        "/usr/local/etc",
        "/usr/local/Caskroom",
    ] {
        assert!(
            deny_line.contains(&format!("(subpath \"{denied}\")")),
            "missing explicit deny {denied}"
        );
    }

    // A read-back alone is not enough for `brew`: its wrapper re-execs
    // the vendored Ruby out of the same tree. The exec allow-back must
    // be narrow (exactly the two Homebrew code dirs) and must never
    // grant write; the rest of the package prefixes stay exec-denied.
    let exec_lines: Vec<&str> = profile
        .lines()
        .filter(|line| line.starts_with("(allow process-exec*"))
        .collect();
    for path in [
        "/opt/homebrew/Library/Homebrew",
        "/usr/local/Library/Homebrew",
    ] {
        assert!(
            exec_lines
                .iter()
                .any(|line| line.contains(&format!("(subpath \"{path}\")"))),
            "missing exec read-back {path}"
        );
    }
    for line in &exec_lines {
        for broad in [
            "(subpath \"/opt/homebrew/Library\")",
            "(subpath \"/opt/homebrew\")",
            "(subpath \"/usr/local/Library\")",
            "(subpath \"/opt/homebrew/etc\")",
            "(subpath \"/opt/homebrew/var\")",
            "(subpath \"/opt/homebrew/Caskroom\")",
        ] {
            assert!(
                !line.contains(broad),
                "a broad exec allow returned: {broad} in {line}"
            );
        }
    }
    assert!(
        !profile.contains("(allow file-write* (subpath \"/opt/homebrew/Library/Homebrew\")"),
        "the Homebrew read-back must never be writable"
    );
}

#[test]
fn profile_tightens_sysctl_and_process_info() {
    // WSD2-P1-01: no broad sysctl-read; process-info is denied globally
    // and allowed back for self only.
    let profile = seatbelt_profile(
        Path::new("/tmp/ws"),
        Path::new("/tmp/tmp"),
        Some(Path::new("/Users/tester")),
        false,
    )
    .unwrap();

    assert!(
        !profile.contains("(allow sysctl-read)\n"),
        "broad sysctl-read must never come back"
    );
    let deny_at = profile
        .find("(deny sysctl-read)")
        .expect("sysctl-read must be denied");
    let allow_at = profile
        .find("(allow sysctl-read (")
        .expect("the minimal sysctl allow-back must be present");
    assert!(
        allow_at > deny_at,
        "the sysctl allow-back must come after the deny (last-match-wins)"
    );
    let allow_line = profile[allow_at..].lines().next().unwrap();
    for name in [
        "hw.machine",
        "hw.memsize",
        "hw.ncpu",
        "kern.hostname",
        "kern.osrelease",
        "kern.ostype",
        "kern.osversion",
        "kern.version",
    ] {
        assert!(
            allow_line.contains(&format!("(sysctl-name \"{name}\")")),
            "missing allowed sysctl {name}"
        );
    }
    assert!(allow_line.contains("(sysctl-name-prefix \"sysctl.\")"));
    assert!(allow_line.contains("(sysctl-name-prefix \"hw.pagesize\")"));
    // No sensitive families may be allowed by name or prefix.
    for forbidden in ["kern.proc", "vm.", "net.", "machdep.", "kern.boottime"] {
        assert!(
            !allow_line.contains(forbidden),
            "sensitive sysctl family {forbidden} must not be allowed"
        );
    }

    assert!(profile.contains("(deny process-info*)"));
    let proc_deny = profile.find("(deny process-info*)").unwrap();
    let proc_allow = profile
        .find("(allow process-info* (target self))")
        .expect("self process-info must stay allowed");
    assert!(
        proc_allow > proc_deny,
        "the self allow must come after the deny"
    );

    // The helper binary cannot be re-entered from a command either.
    assert!(profile.contains("(deny process-exec* (literal \"/usr/bin/sandbox-exec\"))"));
    assert!(profile.contains("(deny process-exec* (literal \"/usr/bin/osascript\"))"));
}
