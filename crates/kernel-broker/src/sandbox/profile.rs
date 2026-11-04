//! The deny-by-default Seatbelt profile for one shell call, rule by rule,
//! and the Scheme quoting every path goes through.

use super::developer_dir::{cached_developer_dir, developer_dir_rules, DeveloperDirGrant};
use super::error::LaunchError;
use super::sensitive::{
    absolute_overlap, home_overlap, overlaps, SENSITIVE_ABSOLUTE_DIRS, SENSITIVE_DIRS,
    SENSITIVE_FILES,
};
use super::system::{
    ALLOWED_SYSCTL_NAMES, ALLOWED_SYSCTL_PREFIXES, EXEC_READ_BACK_DIRS, EXTRA_READ_FILES,
    EXTRA_READ_TREES, PACKAGE_DENIED_DIRS, PACKAGE_DIRS, PACKAGE_READ_BACK_FILES, READ_BACK_DIRS,
    SYSTEM_TREES,
};
use std::path::Path;

/// Build the deny-by-default Seatbelt profile for one shell call.
///
/// `home` is the *real* home of the daemon user (canonical), used for the
/// explicit sensitive-path denies. Everything not allowed here is denied by
/// the kernel, and rules are ordered last-match-wins, so the sensitive denies
/// come after the system allows and the workspace/temp allows after the
/// denies. Refuses a workspace that would override a protected location.
///
/// The active developer directory is resolved from `xcode-select -p` (with
/// `DEVELOPER_DIR` removed) and accepted only when it passes the
/// authenticity and ownership checks in `resolve_developer_dir`. When it is
/// a full Xcode, that directory gets the same read+exec grant as the Command
/// Line Tools; every other value adds no rule.
///
/// This is the **shell tool's** profile. The stdio (MCP) sandbox builds its
/// own profile and never carries the developer-directory grant.
pub fn seatbelt_profile(
    workspace: &Path,
    temp: &Path,
    home: Option<&Path>,
    network: bool,
) -> Result<String, LaunchError> {
    let developer_dir = cached_developer_dir();
    seatbelt_profile_with_developer_dir(
        workspace,
        temp,
        home,
        network,
        developer_dir,
        DeveloperDirGrant::Allow,
    )
}

/// [`seatbelt_profile`] with the developer directory passed in: production
/// callers use the resolved value, tests pin it.
///
/// `grant` decides whether the developer directory may be added at all. The
/// stdio (MCP) sandbox passes [`DeveloperDirGrant::Deny`], so its profile
/// stays exactly what it was before the Xcode grant existed.
pub(super) fn seatbelt_profile_with_developer_dir(
    workspace: &Path,
    temp: &Path,
    home: Option<&Path>,
    network: bool,
    developer_dir: Option<&Path>,
    grant: DeveloperDirGrant,
) -> Result<String, LaunchError> {
    // The grant is read-only. A workspace overlapping it would turn it
    // writable through the unconditional workspace allow, so skip the grant
    // exactly as if no Xcode were selected.
    let developer_dir = match grant {
        DeveloperDirGrant::Allow => developer_dir.filter(|dir| !overlaps(workspace, dir)),
        // No grant, not even the read + exec one the shell tool needs.
        DeveloperDirGrant::Deny => None,
    };
    let sensitive = home
        .map(|home| home_overlap(workspace, home).is_some())
        .unwrap_or(false)
        || absolute_overlap(workspace).is_some();
    if sensitive {
        return Err(LaunchError::SensitiveWorkspace(
            workspace.display().to_string(),
        ));
    }

    let workspace = scheme_string(workspace)?;
    let temp = scheme_string(temp)?;

    let mut profile = String::from("(version 1)\n(deny default)\n(allow process-fork)\n");

    profile.push_str("(allow process-exec*");
    for path in SYSTEM_TREES.iter().chain(PACKAGE_DIRS) {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    profile.push_str(")\n");

    profile.push_str(
        "(allow mach-lookup \
         (global-name \"com.apple.system.opendirectoryd.libinfo\") \
         (global-name \"com.apple.cfprefsd.agent\") \
         (global-name \"com.apple.system.logger\") \
         (global-name \"com.apple.logd\"))\n",
    );
    profile.push_str("(allow file-read-metadata)\n");

    profile.push_str("(allow file-read*");
    for path in SYSTEM_TREES
        .iter()
        .chain(PACKAGE_DIRS)
        .chain(EXTRA_READ_TREES)
    {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    for path in EXTRA_READ_FILES {
        profile.push_str(&format!(" (literal \"{path}\")"));
    }
    profile.push_str(
        " (literal \"/\") (literal \"/private/var/select/sh\") \
         (subpath \"/dev\"))\n",
    );

    profile.push_str(
        "(allow file-write* (literal \"/dev/null\") (literal \"/dev/stdout\") \
         (literal \"/dev/stderr\") (literal \"/dev/dtracehelper\"))\n",
    );

    if network {
        // v1 contract: network = true means *all* sockets, any host and port;
        // there is no narrower allowlist.
        profile.push_str("; network = true: all sockets for v1 (loopback included)\n");
        profile.push_str("(allow network*)\n");
    } else {
        profile.push_str("; network = false: all sockets denied (loopback included)\n");
    }

    // Sensitive denies come after the system allows so they always win, and
    // before the workspace/temp allows (a workspace inside `~/.auxesis` is
    // allowed to override its own home's deny for its own subtree only).
    let mut denies: Vec<String> = Vec::new();
    if let Some(home) = home {
        let home = scheme_string(home)?;
        for dir in SENSITIVE_DIRS {
            denies.push(format!("(subpath \"{home}/{dir}\")"));
        }
        for file in SENSITIVE_FILES {
            denies.push(format!("(literal \"{home}/{file}\")"));
        }
    }
    for dir in SENSITIVE_ABSOLUTE_DIRS {
        denies.push(format!("(subpath \"{dir}\")"));
    }
    for dir in PACKAGE_DENIED_DIRS {
        denies.push(format!("(subpath \"{dir}\")"));
    }
    profile.push_str(&format!("(deny file-read* {})\n", denies.join(" ")));

    // Narrow read-backs *after* the deny, so the specific files common
    // toolchains read at startup stay readable without re-opening the broad
    // package `etc` trees: Homebrew's OpenSSL config/CA bundle (node, npm,
    // pnpm, tsc abort without them), Homebrew's own `Library/Homebrew` code
    // (`brew --version`/`list`/`info`, including exec of its vendored
    // Ruby) and system Ruby's gems tree (rubygems globs it in
    // `gem_prelude`, before any user code runs).
    profile.push_str("(allow file-read*");
    for path in PACKAGE_READ_BACK_FILES {
        profile.push_str(&format!(" (literal \"{path}\")"));
    }
    for path in READ_BACK_DIRS {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    profile.push_str(")\n");
    profile.push_str("(allow process-exec*");
    for path in EXEC_READ_BACK_DIRS {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    profile.push_str(")\n");

    // The workspace and temp allows come after the sensitive denies so they
    // win for their own tree (the workspace lives inside the Auxesis home).
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{workspace}\") (subpath \"{temp}\"))\n\
         (allow file-write* (subpath \"{workspace}\") (subpath \"{temp}\"))\n\
         (allow process-exec* (subpath \"{workspace}\") (subpath \"{temp}\"))\n"
    ));
    // Git may run hooks outside this sandbox later. Never let a shell call
    // plant or alter executable repository metadata in the workspace.
    profile.push_str(&format!(
        "(deny file-write* (subpath \"{workspace}/.git\"))\n"
    ));

    // Deny re-entering the sandbox helper: nested `sandbox-exec` can only add
    // restrictions, but there is no reason to run it from a shell. `osascript`
    // is denied too: every out-of-process AppleScript channel is already
    // unreachable, so the only thing left is in-process Cocoa scripting, which
    // nothing in the command matrix needs.
    profile.push_str(
        "(deny process-exec* (literal \"/usr/bin/sandbox-exec\"))\n\
         (deny process-exec* (literal \"/usr/bin/osascript\"))\n",
    );

    // Global diagnostics tightening, last so it beats anything above. Without
    // these two denies, `lsof` reads the whole process table and open-file map
    // (through process-info, not sysctl), `launchctl print` dumps the GUI
    // launchd job table, and `sysctl -a` exposes kern/vm internals. The
    // allow-backs that follow are deliberately tiny: process-info only for
    // **self** (Foundation aborts on `sw_vers`/`osascript` without it), and
    // the non-sensitive sysctl names common commands actually need.
    profile.push_str("(deny sysctl-read)\n");
    profile.push_str("(deny process-info*)\n");
    profile.push_str("(allow process-info* (target self))\n");
    profile.push_str("(allow sysctl-read");
    for prefix in ALLOWED_SYSCTL_PREFIXES {
        profile.push_str(&format!(" (sysctl-name-prefix \"{prefix}\")"));
    }
    for name in ALLOWED_SYSCTL_NAMES {
        profile.push_str(&format!(" (sysctl-name \"{name}\")"));
    }
    profile.push_str(")\n");

    // A full Xcode moves the xcrun shims' libraries and tools under the
    // selected developer directory; without this grant `/usr/bin/git` (and
    // every other xcrun shim) dies with "unable to load libxcrun". The rule is
    // appended last and only ever adds read + exec: the existing profile above
    // is untouched, and nothing grants a write under the directory.
    if let Some(developer_dir) = developer_dir {
        if let Some(rules) = developer_dir_rules(developer_dir) {
            profile.push_str(&rules);
        }
    }
    Ok(profile)
}

/// Quote a path as a Scheme string in a Seatbelt profile.
///
/// Control characters are refused: they cannot be represented safely and a
/// path containing them must never be able to shape the profile.
pub(super) fn scheme_string(path: &Path) -> Result<String, LaunchError> {
    let text = path
        .to_str()
        .ok_or_else(|| LaunchError::UnsafeWorkspace(path.display().to_string()))?;
    if text.chars().any(char::is_control) {
        return Err(LaunchError::UnsafeWorkspace(path.display().to_string()));
    }
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
}
