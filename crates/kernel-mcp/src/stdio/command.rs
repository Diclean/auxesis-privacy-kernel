//! The pinned stdio launch command and its closed environment policy.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::McpError;

use super::limits::{MAX_ARGS, MAX_ENV_ENTRIES};

/// The only environment keys a [`StdioCommand`] may set.
///
/// The list is closed on purpose: a config (or, later, a plugin manifest)
/// cannot smuggle `AUX_KEY_*`, `AUXESIS_*` or a session credential into a local
/// server by naming it. `PATH` is deliberately absent: it changes executable
/// resolution, so neither the inherited environment nor a config may set it
/// (see [`env_key_declared`]). `HOME` is deliberately absent too: the
/// child environment must never be pointed at the owner's home by this
/// transport, and the workspace invariant forbids naming it outside the
/// gateway.
pub const ALLOWED_ENV_KEYS: &[&str] = &["LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TMPDIR", "TZ"];

/// Environment prefixes a user-declared secret name may never use.
///
/// Those names belong to Auxesis' own credential store (`AUX_KEY_*` provider
/// keys, `AUX_TELEGRAM_BOT_TOKEN`, ...). A configured MCP server may ask for
/// its own vendor key (for example `DATAGOUV_KEY`) but never for one of ours.
pub const RESERVED_ENV_PREFIXES: [&str; 2] = ["AUX_", "AUXESIS_"];

/// Names that steer the loader, the shell, an interpreter at start-up, or the
/// container CLI itself. A configured server may never declare one: its value
/// would change what runs or which daemon/socket a container talks to.
pub const DENIED_ENV_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "SHELL",
    "TMPDIR",
    "NODE_OPTIONS",
    "NODE_PATH",
    "BASH_ENV",
    "ENV",
    "IFS",
    "SHELLOPTS",
    "BASHOPTS",
    "ZDOTDIR",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5OPT",
    "PERL5LIB",
    "JAVA_TOOL_OPTIONS",
    "JAVA_OPTS",
    "JDK_JAVA_OPTIONS",
    "LUA_INIT",
    "LUA_PATH",
    "LUA_CPATH",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "GIT_EXTERNAL_DIFF",
    // Build- and runtime-hook names: they run another program around the one
    // the owner reviewed (`rustc`, javac's JVM, the Python debugger) or change
    // glibc's charset conversion module search path.
    "RUSTC_WRAPPER",
    "GCONV_PATH",
    "PYTHONBREAKPOINT",
    // Container-CLI steering: these retarget the daemon, socket, config or
    // trust material a `docker`/`podman`/`nerdctl` launch talks to.
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "PODMAN_HOST",
    "CONTAINERS_CONF",
    "BUILDKIT_HOST",
];
/// Loader prefixes (`DYLD_*` on macOS, `LD_*` on Linux), the container-CLI
/// steering namespaces (`CONTAINERD_*`, `DOCKER_*`, `CONTAINER*_`, `PODMAN_*`,
/// `NERDCTL_*`, `BUILDKIT_*`, `REGISTRY_*`), the git config/transport
/// namespace (`GIT_CONFIG_*`) and the XDG user/base-dir controls a configured
/// server may never declare.
///
/// Every comparison in [`env_key_declared`] is case-insensitive, so
/// `docker_host` is refused exactly like `DOCKER_HOST`.
pub const DENIED_ENV_PREFIXES: &[&str] = &[
    "DYLD_",
    "LD_",
    "DOCKER_",
    "CONTAINER_",
    "CONTAINERS_",
    "CONTAINERD_",
    "PODMAN_",
    "NERDCTL_",
    "BUILDKIT_",
    "REGISTRY_",
    "GIT_CONFIG_",
    "XDG_",
];

/// Whether `key` is a syntactically valid user-declared env name that is not
/// reserved to Auxesis itself nor a loader, start-up or container-steering
/// control name.
///
/// The name syntax keeps its original case, but every reserved/denied
/// comparison folds case, so a lowercase spelling cannot slip past.
pub fn env_key_declared(key: &str) -> bool {
    let bytes = key.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    if !valid {
        return false;
    }
    let upper = key.to_ascii_uppercase();
    !RESERVED_ENV_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
        && !DENIED_ENV_NAMES.contains(&upper.as_str())
        && !DENIED_ENV_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
}

/// The pinned launch configuration: program, arguments, environment.
///
/// Built once and immutable during a session. Values may carry runtime secrets
/// (an injected token is the documented path for MCP auth), so the type's
/// `Debug` never prints an argument or an environment value.
#[derive(Clone)]
pub struct StdioCommand {
    program: PathBuf,
    pub(super) args: Vec<OsString>,
    pub(super) env: BTreeMap<&'static str, OsString>,
    /// User-declared secret names from `mcp.toml` (`env = [...]`), resolved
    /// from `~/.auxesis/.env` by the caller. Kept separate from the fixed
    /// allowlist so the reserved-prefix rule is a structural property, not a
    /// naming convention.
    pub(super) declared_env: BTreeMap<String, OsString>,
}

impl StdioCommand {
    /// Pin `program` as the executable.
    ///
    /// `program` must name a path (absolute or containing a separator); a bare
    /// name is refused so the OS never resolves it through an implicit `PATH`.
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, McpError> {
        let program = program.into();
        if !is_explicit_program(&program) {
            return Err(McpError::InvalidCommand {
                reason: "program must be an explicit path, not a bare name resolved through PATH",
            });
        }
        Ok(Self {
            program,
            args: Vec::new(),
            env: BTreeMap::new(),
            declared_env: BTreeMap::new(),
        })
    }

    /// Append one argument, passed to the child verbatim.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments, passed to the child verbatim.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set one environment variable, but only from [`ALLOWED_ENV_KEYS`].
    ///
    /// A non-allowlisted key is refused with a secret-free error: the key and
    /// the value are never echoed.
    pub fn env(mut self, key: &str, value: impl Into<OsString>) -> Result<Self, McpError> {
        let Some(allowed) = ALLOWED_ENV_KEYS.iter().find(|allowed| **allowed == key) else {
            return Err(McpError::InvalidCommand {
                reason: "environment key is not in the allowlist",
            });
        };
        self.env.insert(allowed, value.into());
        Ok(self)
    }

    /// Set one **user-declared** secret variable resolved from
    /// `~/.auxesis/.env`.
    ///
    /// The name must be a valid shell identifier and must not use a reserved
    /// Auxesis prefix ([`RESERVED_ENV_PREFIXES`]). A refused key returns a
    /// secret-free error: neither the key nor the value is echoed past this
    /// point, and `Debug` still prints keys only.
    pub fn env_declared(mut self, key: &str, value: impl Into<OsString>) -> Result<Self, McpError> {
        if !env_key_declared(key) {
            return Err(McpError::InvalidCommand {
                reason: "declared environment key is invalid or reserved",
            });
        }
        self.declared_env.insert(key.to_owned(), value.into());
        Ok(self)
    }

    /// The pinned program path.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The pinned arguments (never logged).
    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }

    /// The pinned environment keys (never the values).
    pub fn env_keys(&self) -> impl Iterator<Item = &str> + '_ {
        self.env
            .keys()
            .copied()
            .chain(self.declared_env.keys().map(String::as_str))
    }

    /// Reject a configuration the OS would refuse or that crosses a cap.
    pub(super) fn validate(&self) -> Result<(), McpError> {
        if !is_explicit_program(&self.program) {
            return Err(McpError::InvalidCommand {
                reason: "program must be an explicit path, not a bare name resolved through PATH",
            });
        }
        if self.args.len() > MAX_ARGS {
            return Err(McpError::InvalidCommand {
                reason: "too many pinned arguments",
            });
        }
        if self.env.len() + self.declared_env.len() > MAX_ENV_ENTRIES {
            return Err(McpError::InvalidCommand {
                reason: "too many pinned environment variables",
            });
        }
        if self.declared_env.keys().any(|key| !env_key_declared(key)) {
            return Err(McpError::InvalidCommand {
                reason: "declared environment key is invalid or reserved",
            });
        }
        if has_nul(self.program.as_os_str()) || self.args.iter().any(|arg| has_nul(arg)) {
            return Err(McpError::InvalidCommand {
                reason: "program or arguments contain a NUL byte",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for StdioCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the argument values (they may carry a token) and never the
        // environment values (an injected secret) — keys and counts only.
        f.debug_struct("StdioCommand")
            .field("program", &self.program)
            .field("arguments", &format_args!("<{} pinned>", self.args.len()))
            .field("env_keys", &self.env_keys().collect::<Vec<_>>())
            .finish()
    }
}

/// A program must name an explicit path; a bare name means an implicit PATH.
fn is_explicit_program(program: &Path) -> bool {
    let raw = program.as_os_str();
    if raw.is_empty() {
        return false;
    }
    program.is_absolute() || raw.to_string_lossy().contains(std::path::MAIN_SEPARATOR)
}

/// Whether an OS string contains a NUL (which `execve` cannot accept).
fn has_nul(value: &OsStr) -> bool {
    value.to_string_lossy().contains('\0')
}
