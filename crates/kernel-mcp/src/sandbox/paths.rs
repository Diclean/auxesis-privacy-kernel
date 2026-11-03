//! Path checks: the metadata literals and the Scheme quoting.

use std::collections::BTreeSet;
use std::path::Path;

use super::spec::SandboxSpec;
use super::system::{SYSTEM_READ_DIRS, SYSTEM_READ_FILES};

/// The literal paths whose metadata (stat) the child may read: every allowed
/// tree, every runtime path, and the path components leading to each of them.
///
/// `subpath` matching requires metadata on each ancestor, but a global allow
/// would expose the owner's home. Emitting the components as literals grants
/// exactly the traversal dyld and the runtime need.
pub(super) fn metadata_literals(spec: &SandboxSpec) -> BTreeSet<String> {
    let mut literals = BTreeSet::new();
    literals.insert("/".to_string());
    insert_components(&mut literals, &spec.install_dir);
    insert_components(&mut literals, &spec.work_dir);
    for path in &spec.runtime_read_paths {
        insert_components(&mut literals, path);
    }
    for dir in SYSTEM_READ_DIRS {
        insert_components(&mut literals, Path::new(dir));
    }
    for file in SYSTEM_READ_FILES {
        insert_components(&mut literals, Path::new(file));
    }
    literals
}

/// Insert `path` and every ancestor of it into `literals`.
fn insert_components(literals: &mut BTreeSet<String>, path: &Path) {
    let mut current = Some(path);
    while let Some(component) = current {
        let text = scheme_string(component);
        if !text.is_empty() {
            literals.insert(text);
        }
        current = component.parent();
    }
}

/// Quote a path as a Scheme string in a Seatbelt profile.
///
/// Backslashes and quotes are escaped; control characters are dropped. A
/// control character cannot be represented safely and must never shape the
/// profile; dropping it makes the rule match no real path, which fails closed.
pub(super) fn scheme_string(path: &Path) -> String {
    let mut out = String::new();
    for ch in path.to_string_lossy().chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            ch if ch.is_control() => {}
            ch => out.push(ch),
        }
    }
    out
}
