//! The Xcode developer directory: how it is looked up, how it is
//! authenticated, and the read + exec grant it earns.

use super::profile::scheme_string;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// The only root a full Xcode developer directory may come from. The bundle
/// must sit directly here, and the selected path must already be canonical.
const APPLICATIONS_ROOT: &str = "/Applications";

/// The only bundle identifier accepted for an `/Applications` developer
/// directory: a full Xcode, not just any app that ships a `Developer` folder.
pub(super) const XCODE_BUNDLE_ID: &str = "com.apple.dt.Xcode";

/// Upper bound for the `xcode-select` and `plutil` helpers, so a wedged tool
/// can never stall profile construction.
const DEVELOPER_TOOL_TIMEOUT: Duration = Duration::from_secs(2);

/// The Command Line Tools developer directory. It is already in
/// [`SYSTEM_TREES`](super::system::SYSTEM_TREES), so resolving it adds no rule and no duplicate: the
/// existing grant stays byte for byte what it was.
pub(super) const CLT_DEVELOPER_DIR: &str = "/Library/Developer/CommandLineTools";

/// Filesystem facts the Xcode developer-directory checks need.
pub(super) struct PathFacts {
    pub(super) uid: u32,
    pub(super) mode: u32,
    pub(super) is_dir: bool,
    pub(super) is_symlink: bool,
}

/// Real `symlink_metadata` facts for one path.
fn system_facts(path: &Path) -> Option<PathFacts> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path).ok()?;
        Some(PathFacts {
            uid: meta.uid(),
            mode: meta.mode(),
            is_dir: meta.is_dir(),
            is_symlink: meta.file_type().is_symlink(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// `CFBundleIdentifier` read with `plutil` (XML or binary), under a timeout.
fn system_bundle_id(info_plist: &Path) -> Option<String> {
    let mut command = Command::new("/usr/bin/plutil");
    command
        .args(["-extract", "CFBundleIdentifier", "raw", "-o", "-"])
        .arg(info_plist);
    let output = run_with_timeout(&mut command, DEVELOPER_TOOL_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}

/// Run `command` with a wall-clock limit; kill and reap it on timeout.
fn run_with_timeout(command: &mut Command, timeout: Duration) -> Option<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) => {}
            Err(_) => break,
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// The developer directory `xcrun` shims will use for a sandboxed child.
/// Asked of `xcode-select -p` with `DEVELOPER_DIR` removed: the child's
/// environment is cleared, so that variable must never pick the toolchain.
/// Any failure returns `None` and the caller adds no rule.
pub(super) fn active_developer_dir() -> Option<PathBuf> {
    let mut command = Command::new("/usr/bin/xcode-select");
    command.arg("-p").env_remove("DEVELOPER_DIR");
    let output = run_with_timeout(&mut command, DEVELOPER_TOOL_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    let selected = PathBuf::from(std::str::from_utf8(&output.stdout).ok()?.trim());
    resolve_developer_dir(
        &selected,
        Path::new(APPLICATIONS_ROOT),
        &system_facts,
        &system_bundle_id,
    )
}

/// The developer directory of this process, resolved once.
///
/// The lookup forks `/usr/bin/xcode-select` (and `/usr/bin/plutil` for the
/// bundle id), so it runs at most once per process: the first shell profile
/// pays for it, every later one reuses the answer. Switching the selected
/// Xcode needs a daemon restart to take effect.
pub(super) static DEVELOPER_DIR: DeveloperDirCache = DeveloperDirCache::new();

/// A one-shot cache for the developer directory.
pub(super) struct DeveloperDirCache {
    value: OnceLock<Option<PathBuf>>,
    lookups: AtomicUsize,
}

impl DeveloperDirCache {
    pub(super) const fn new() -> Self {
        Self {
            value: OnceLock::new(),
            lookups: AtomicUsize::new(0),
        }
    }

    /// The cached value. `lookup` runs on the first call only; every later
    /// call is served from the cache.
    pub(super) fn get(&self, lookup: impl FnOnce() -> Option<PathBuf>) -> Option<&Path> {
        self.value
            .get_or_init(|| {
                self.lookups.fetch_add(1, Ordering::Relaxed);
                lookup()
            })
            .as_deref()
    }

    /// How many times the lookup ran: `0` before the first call, `1` after.
    #[cfg(test)]
    pub(super) fn lookups(&self) -> usize {
        self.lookups.load(Ordering::Relaxed)
    }
}

/// The developer directory this process grants the shell tool.
///
/// Resolved once per process (see [`DEVELOPER_DIR`]): the lookup forks
/// `xcode-select`, so it must not run on every profile build. The answer
/// cannot change under a running daemon anyway — switching the selected
/// Xcode needs a daemon restart.
pub(super) fn cached_developer_dir() -> Option<&'static Path> {
    DEVELOPER_DIR.get(active_developer_dir)
}

/// Whether a profile may carry the Xcode developer-directory grant.
///
/// The grant exists for the shell tool: `/usr/bin/git` and every other
/// `xcrun` shim load `libxcrun` from the selected developer directory, so a
/// full Xcode needs a read + exec grant of its own. The stdio (MCP) sandbox
/// must never carry it: an MCP server has no shim to load, and the grant
/// opens a whole developer directory (toolchain, SDKs, private data) for
/// read and exec inside a profile that is otherwise tight.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum DeveloperDirGrant {
    /// The grant is allowed: the shell tool's profile.
    Allow,
    /// No developer-directory grant at all: the stdio (MCP) sandbox.
    Deny,
}

/// The bundle directories of a canonical developer directory.
struct XcodeBundle {
    app: PathBuf,
    contents: PathBuf,
    developer: PathBuf,
}

/// Canonicalise and validate the selected developer directory. The Command
/// Line Tools is accepted (it is already in [`SYSTEM_TREES`](super::system::SYSTEM_TREES), so it adds no
/// rule). A full Xcode is accepted only when the canonical path is exactly
/// `<root>/<bundle>.app/Contents/Developer` with the bundle directly under the
/// root, the selected path is already canonical (no symlink in it), the
/// bundle's `Info.plist` says `CFBundleIdentifier` is [`XCODE_BUNDLE_ID`], and
/// the bundle, `Contents` and `Developer` are each a real directory (checked
/// with `symlink_metadata`), owned by uid 0 with `mode & 0o022 == 0` (not
/// writable by group or others). Every failure returns `None`: no rule.
pub(super) fn resolve_developer_dir(
    selected: &Path,
    applications_root: &Path,
    facts: &dyn Fn(&Path) -> Option<PathFacts>,
    bundle_id: &dyn Fn(&Path) -> Option<String>,
) -> Option<PathBuf> {
    if !selected.is_absolute() {
        return None;
    }
    let canonical = selected.canonicalize().ok()?;
    if canonical == Path::new(CLT_DEVELOPER_DIR) {
        return Some(canonical);
    }
    // Canonicalisation resolves symlinks, which would hide a symlinked
    // `Developer` (or bundle) behind another otherwise valid path. Only the
    // path the tool named is checked, and it must have no symlink in it.
    if canonical != selected {
        return None;
    }
    let bundle = xcode_bundle_paths(&canonical, applications_root)?;
    if bundle_id(&bundle.contents.join("Info.plist")).as_deref() != Some(XCODE_BUNDLE_ID) {
        return None;
    }
    for dir in [&bundle.app, &bundle.contents, &bundle.developer] {
        let facts = facts(dir)?;
        if facts.is_symlink || !facts.is_dir || facts.uid != 0 || facts.mode & 0o022 != 0 {
            return None;
        }
    }
    Some(canonical)
}

/// Split a canonical developer directory into its bundle paths. Requires the
/// bundle to sit directly under `applications_root`:
/// `<root>/<name>.app/Contents/Developer`, never deeper.
fn xcode_bundle_paths(developer: &Path, applications_root: &Path) -> Option<XcodeBundle> {
    let mut parts = developer.strip_prefix(applications_root).ok()?.components();
    let name = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (
            Some(Component::Normal(name)),
            Some(Component::Normal(contents)),
            Some(Component::Normal(dev)),
            None,
        ) if name.to_string_lossy().ends_with(".app")
            && name.len() > ".app".len()
            && contents == "Contents"
            && dev == "Developer" =>
        {
            name.to_owned()
        }
        _ => return None,
    };
    let app = applications_root.join(&name);
    let contents = app.join("Contents");
    let developer = contents.join("Developer");
    Some(XcodeBundle {
        app,
        contents,
        developer,
    })
}

/// The read + exec grant for a full Xcode developer directory, or `None` when
/// the directory is already covered (the Command Line Tools, in
/// [`SYSTEM_TREES`](super::system::SYSTEM_TREES)).
///
/// The caller passes a directory that already passed [`resolve_developer_dir`].
/// The two lines mirror exactly what the profile already grants the Command
/// Line Tools: `file-read*` and `process-exec*`, never a write, network or
/// `file-map-executable` rule.
pub(super) fn developer_dir_rules(developer_dir: &Path) -> Option<String> {
    if developer_dir == Path::new(CLT_DEVELOPER_DIR) {
        return None;
    }
    let dir = scheme_string(developer_dir).ok()?;
    Some(format!(
        "; full Xcode selected: the xcrun shims load libxcrun and exec tools from here\n\
         (allow file-read* (subpath \"{dir}\"))\n\
         (allow process-exec* (subpath \"{dir}\"))\n"
    ))
}
