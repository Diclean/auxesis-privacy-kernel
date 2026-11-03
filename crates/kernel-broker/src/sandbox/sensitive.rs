//! The protected locations: the sensitive home paths, the machine-state
//! trees, and the overlap checks that refuse them as a workspace.

use super::system::{
    EXTRA_READ_TREES, PACKAGE_DENIED_DIRS, PACKAGE_DIRS, READ_BACK_DIRS, SYSTEM_TREES,
};
use std::path::Path;

/// The Auxesis home inside the real home; agent workspaces live inside it, so a
/// workspace *inside* this tree is intended. A workspace equal to it (or an
/// ancestor of it) would expose the daemon's config and every agent.
const AUXESIS_HOME_DIR: &str = ".auxesis";

/// The sensitive directories denied inside the real home. `.auxesis` is
/// denied too (a workspace inside it overrides the deny for its own subtree
/// only, because the workspace allow is emitted after the deny).
pub(super) const SENSITIVE_DIRS: &[&str] = &[
    ".auxesis",
    ".ssh",
    ".aws",
    ".config",
    ".gnupg",
    ".docker",
    ".kube",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Safari",
    "Library/Messages",
    "Library/Mail",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Chromium",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Firefox",
    "Library/Application Support/Microsoft Edge",
];

/// The sensitive files denied inside the real home.
pub(super) const SENSITIVE_FILES: &[&str] = &[".netrc", ".git-credentials"];

/// Absolute directories that are always denied (and never a valid workspace):
/// system keychains, logs, the unified log store, the root account.
pub(super) const SENSITIVE_ABSOLUTE_DIRS: &[&str] = &[
    "/Library/Keychains",
    "/Library/Logs",
    "/private/var/log",
    "/private/var/db/diagnostics",
    "/private/var/db/uuidtext",
    "/var/root",
];

/// True when `workspace` and `other` share any part of their path (equal,
/// one inside the other).
pub(super) fn overlaps(workspace: &Path, other: &Path) -> bool {
    workspace == other || workspace.starts_with(other) || other.starts_with(workspace)
}

/// The protected home path the workspace overlaps, if any.
pub(super) fn home_overlap(workspace: &Path, home: &Path) -> Option<String> {
    // Inside the Auxesis home is fine (that is where workspaces live), but
    // the Auxesis home itself or one of its ancestors would cover the whole
    // home: `config.toml`, every agent, every workspace.
    let auxesis = home.join(AUXESIS_HOME_DIR);
    if workspace == auxesis || auxesis.starts_with(workspace) {
        return Some(auxesis.display().to_string());
    }
    for dir in SENSITIVE_DIRS {
        // `.auxesis` is validated above: only the tree itself/ancestors are
        // refused, a workspace inside it is the intended layout.
        if *dir == AUXESIS_HOME_DIR {
            continue;
        }
        let path = home.join(dir);
        if overlaps(workspace, &path) {
            return Some(path.display().to_string());
        }
    }
    for file in SENSITIVE_FILES {
        let path = home.join(file);
        if overlaps(workspace, &path) {
            return Some(path.display().to_string());
        }
    }
    None
}

/// The absolute protected path the workspace overlaps, if any.
///
/// Besides the sensitive directories this includes every tree the profile
/// declares read-only (system trees, package program directories, extra read
/// trees, read-backs) and the package state dirs it denies. The workspace
/// allow is unconditional, so a workspace equal to or inside any of them
/// would turn a read-only tree writable — or override a deny.
pub(super) fn absolute_overlap(workspace: &Path) -> Option<&'static str> {
    SENSITIVE_ABSOLUTE_DIRS
        .iter()
        .chain(SYSTEM_TREES)
        .chain(PACKAGE_DIRS)
        .chain(PACKAGE_DENIED_DIRS)
        .chain(EXTRA_READ_TREES)
        .chain(READ_BACK_DIRS)
        .copied()
        .find(|dir| overlaps(workspace, Path::new(dir)))
}
