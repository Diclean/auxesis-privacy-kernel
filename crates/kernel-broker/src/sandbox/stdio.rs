//! The Seatbelt wrapper for a long-lived stdio child (an MCP server): the
//! program allow, the store deny and the private temp dir.

use super::developer_dir::DeveloperDirGrant;
use super::error::LaunchError;
use super::home::real_home;
use super::limits::SANDBOX_EXEC;
use super::profile::{scheme_string, seatbelt_profile_with_developer_dir};
use super::sensitive::{absolute_overlap, home_overlap};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A ready macOS Seatbelt wrapper for a long-lived stdio child (an MCP server).
///
/// Unlike the shell tool, the child speaks a protocol on stdin/stdout and is
/// **not** a shell string: the confirmed program is exec'd directly under the
/// same deny-by-default profile. `~/.auxesis` (and the store inside it) is
/// denied read and write as the last rules of the profile, so nothing above
/// can re-open it. Network is denied unless `network` is set.
///
/// The wrapper owns a private temp dir used as the child's `HOME`/`TMPDIR`;
/// keep the value alive for as long as the child runs.
#[derive(Debug)]
pub struct StdioSandbox {
    temp: TempDir,
    pub(super) profile: String,
    /// Always [`SANDBOX_EXEC`]: set in [`StdioSandbox::build`] and nowhere else.
    pub(super) sandbox_exec: PathBuf,
}

impl StdioSandbox {
    /// Build the profile for `program` and create the private temp dir.
    ///
    /// `program`'s own directory is made readable and executable (it is the
    /// exact path the owner confirmed) unless it lives inside a protected
    /// tree; the auxesis home stays denied either way.
    ///
    /// The store deny uses the daemon's **actual** Auxesis home
    /// (`$AUXESIS_HOME` when set), not `$HOME/.auxesis` (item 9).
    ///
    /// The `sandbox-exec` executable is always the fixed [`SANDBOX_EXEC`]. No
    /// public constructor takes another path: a caller-chosen wrapper that
    /// ignored the profile would launch the MCP child **unsandboxed**.
    ///
    /// ```compile_fail
    /// # use kernel_broker::sandbox::StdioSandbox;
    /// # use std::path::{Path, PathBuf};
    /// // error[E0599]: no function or associated item named `with_exec` found
    /// let _ = StdioSandbox::with_exec(
    ///     Path::new("/usr/bin/true"),
    ///     false,
    ///     PathBuf::from("/tmp/fake-sandbox-exec"),
    /// );
    /// ```
    pub fn new(program: &Path, network: bool) -> Result<Self, LaunchError> {
        let auxesis_home = kernel_core::auxesis_home();
        Self::build(program, network, Some(&auxesis_home))
    }

    /// The shared body of [`StdioSandbox::new`], with an explicit Auxesis home.
    ///
    /// Tests pass a relocated home so the store deny is exercised without
    /// reading or writing the real one. It takes no `sandbox-exec` path on
    /// purpose: every profile wraps [`SANDBOX_EXEC`].
    pub(super) fn build(
        program: &Path,
        network: bool,
        auxesis_home: Option<&Path>,
    ) -> Result<Self, LaunchError> {
        // No developer directory: the MCP sandbox never carries the Xcode
        // grant, so it must not look Xcode up either.
        Self::build_with_developer_dir(program, network, auxesis_home, None)
    }

    /// The shared body, with the developer directory the process has selected.
    ///
    /// The directory is passed in so the test can prove the MCP profile never
    /// carries the Xcode grant — not even when a full Xcode is selected.
    /// Production passes `None`: the stdio sandbox must not look Xcode up at
    /// all.
    pub(super) fn build_with_developer_dir(
        program: &Path,
        network: bool,
        auxesis_home: Option<&Path>,
        developer_dir: Option<&Path>,
    ) -> Result<Self, LaunchError> {
        let temp = tempfile::Builder::new().prefix("aux-mcp-").tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let temp_path = temp.path().canonicalize()?;
        let home = real_home();
        let mut profile = seatbelt_profile_with_developer_dir(
            &temp_path,
            &temp_path,
            home.as_deref(),
            network,
            developer_dir,
            // The Xcode grant is a shell-tool affordance: an MCP stdio
            // server never runs an `xcrun` shim, so it never gets the
            // developer directory.
            DeveloperDirGrant::Deny,
        )?;
        if let Some(dir) = program.parent() {
            let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
            if dir != Path::new("/") && !dir.as_os_str().is_empty() {
                let sensitive = home
                    .as_deref()
                    .is_some_and(|home| home_overlap(&dir, home).is_some())
                    || absolute_overlap(&dir).is_some();
                if !sensitive {
                    if let Ok(dir) = scheme_string(&dir) {
                        profile.push_str(&format!(
                            "(allow file-read* (subpath \"{dir}\"))\n\
                             (allow process-exec* (subpath \"{dir}\"))\n"
                        ));
                    }
                }
            }
        }
        // Last rules win: the daemon's actual Auxesis home **and its store**
        // are denied read and write, wherever `AUXESIS_HOME` points (item 9).
        // The real `$HOME/.auxesis` is still denied by the sensitive-path
        // rules above, so a relocated home never weakens that either.
        if let Some(auxesis) = auxesis_home {
            let root = scheme_string(auxesis)?;
            let store = scheme_string(&kernel_core::store_path(auxesis))?;
            profile.push_str(&format!(
                "(deny file-read* (subpath \"{root}\") (literal \"{store}\"))\n\
                 (deny file-write* (subpath \"{root}\") (literal \"{store}\"))\n"
            ));
        }
        Ok(Self {
            temp,
            profile,
            sandbox_exec: PathBuf::from(SANDBOX_EXEC),
        })
    }

    /// The private temp dir the child uses as `HOME`/`TMPDIR`.
    pub fn temp_path(&self) -> &Path {
        self.temp.path()
    }

    /// Build the sandboxed command that runs `program` with `args`.
    pub fn command(&self, program: &Path, args: &[std::ffi::OsString]) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(&self.sandbox_exec);
        command.arg("-p").arg(&self.profile).arg(program).args(args);
        command
    }
}
