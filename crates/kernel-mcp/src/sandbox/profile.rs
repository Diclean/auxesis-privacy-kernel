//! The deny-by-default Seatbelt profile text, rule by rule.

use super::paths::{metadata_literals, scheme_string};
use super::spec::SandboxSpec;
use super::system::{MACH_SERVICES, SYSTEM_READ_DIRS, SYSTEM_READ_FILES};

/// Build the deny-by-default Seatbelt profile for one extension.
///
/// Rules are ordered last-match-wins; the deny is the first line and every
/// allow is scoped, so a path that fails to escape can only narrow access. The
/// one deliberate deny-after-allow is `work/` under the install dir: the
/// install tree is executable, the extension's own data dir is not.
pub fn seatbelt_profile(spec: &SandboxSpec) -> String {
    let mut profile = String::from("(version 1)\n(deny default)\n(allow process-fork)\n");

    // Metadata is stat(), not readdir(): scoping it to the allowed trees and
    // their literal path components keeps `stat ~/.ssh/known_hosts` denied
    // while dyld can still traverse to the libraries it loads.
    profile.push_str("(allow file-read-metadata");
    for path in metadata_literals(spec) {
        profile.push_str(&format!(" (literal \"{path}\")"));
    }
    profile.push_str(")\n");

    // Exec: the exact runtime interpreters and the install dir. The work dir
    // is denied last, so a binary copied there never runs even though it sits
    // under the install tree.
    profile.push_str("(allow process-exec*");
    for path in &spec.runtime_read_paths {
        profile.push_str(&format!(" (literal \"{}\")", scheme_string(path)));
    }
    profile.push_str(&format!(
        " (subpath \"{}\"))\n",
        scheme_string(&spec.install_dir)
    ));
    profile.push_str(&format!(
        "(deny process-exec* (subpath \"{}\"))\n",
        scheme_string(&spec.work_dir)
    ));

    profile.push_str("(allow file-read*");
    // dyld opens the root directory itself; without this every child aborts.
    profile.push_str(" (literal \"/\")");
    profile.push_str(&format!(
        " (subpath \"{}\")",
        scheme_string(&spec.install_dir)
    ));
    profile.push_str(&format!(" (subpath \"{}\")", scheme_string(&spec.work_dir)));
    for path in &spec.runtime_read_paths {
        profile.push_str(&format!(" (subpath \"{}\")", scheme_string(path)));
    }
    for path in SYSTEM_READ_DIRS {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    for file in SYSTEM_READ_FILES {
        profile.push_str(&format!(" (literal \"{file}\")"));
    }
    profile.push_str(")\n");

    profile.push_str("(allow mach-lookup");
    for service in MACH_SERVICES {
        profile.push_str(&format!(" (global-name \"{service}\")"));
    }
    profile.push_str(")\n");

    // The only writable tree. The install dir is deliberately absent, so the
    // extension cannot rewrite its own code or its pinned tools.
    profile.push_str(&format!(
        "(allow file-write* (subpath \"{}\"))\n",
        scheme_string(&spec.work_dir)
    ));

    if let Some(port) = spec.proxy_port {
        // `tcp4` pins the rule to TCP on 127.0.0.1: `localhost` would also
        // open ::1, and a bare `ip4` would also allow UDP.
        profile.push_str(&format!(
            "(allow network-outbound (remote tcp4 \"localhost:{port}\"))\n"
        ));
    }

    // Process introspection is denied globally and allowed back for self only
    // (last-match-wins). Without this a child reads any same-uid process's
    // argv/env through `sysctl KERN_PROCARGS2` and `proc_pidpath`.
    profile.push_str("(deny process-info*)\n");
    profile.push_str("(allow process-info* (target self))\n");

    // A dylib dropped into the writable data dir must not be mapped for
    // execution: read access alone would let `dlopen` run it.
    profile.push_str(&format!(
        "(deny file-map-executable (subpath \"{}\"))\n",
        scheme_string(&spec.work_dir)
    ));

    // Hardware identifiers (IOPlatformSerialNumber, board ids, ...) stay
    // unreadable; nothing a server runtime needs depends on them.
    profile.push_str("(deny iokit-get-properties)\n");

    profile
}
