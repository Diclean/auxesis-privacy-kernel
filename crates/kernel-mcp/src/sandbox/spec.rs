//! The extension spec: the install dir, the work dir and the runtime paths.

use std::path::PathBuf;

/// What one extension is allowed to touch, from its catalog entry.
///
/// `install_dir` is the `~/.auxesis/extensions/<name>@<version>/` tree
/// (read + exec, never write), `work_dir` is its `work/` subdirectory (the
/// only writable place, never executable) and `runtime_read_paths` are the
/// interpreter/system paths the entry's `command` needs. `proxy_port` is the
/// egress proxy's loopback port, or `None` for `network = []`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The extension's install dir: read and exec, never write.
    pub install_dir: PathBuf,
    /// The extension's own workspace: the only writable place, never exec.
    pub work_dir: PathBuf,
    /// Runtime paths (node/python/...) the extension may read and execute.
    /// Exec is granted on the exact path, never on its parent directory.
    pub runtime_read_paths: Vec<PathBuf>,
    /// The egress proxy's loopback port, or `None` when the entry declares
    /// `network = []` (no network rule at all).
    pub proxy_port: Option<u16>,
}
