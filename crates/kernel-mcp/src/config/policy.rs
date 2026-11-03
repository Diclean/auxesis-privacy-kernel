//! The one stdio launch policy and the launcher classes it classifies.

use std::path::Path;

use super::container::{container_policy_refusal, CONTAINER_CLI_TOKENS};
use super::echo::shown;
use super::secrets::{looks_like_secret, secret_pair_refused};
use super::server::refuse;
use super::{ServerRefusal, MAX_MCP_ARG_BYTES};

/// Extra, non-binding classification for one stdio launch.
///
/// The denylist below is **warning text only**: the security boundary is the
/// mandatory per-server confirmation (plus the hard container refusals in
/// [`evaluate_stdio_policy`]). A launcher classified here is shown as
/// "high risk" to the owner; it is never silently allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StdioPolicy {
    /// Stable, content-free warning label, `None` for an ordinary binary.
    pub high_risk: Option<&'static str>,
}

impl StdioPolicy {
    /// Whether the launcher class is flagged as high risk.
    pub fn is_high_risk(&self) -> bool {
        self.high_risk.is_some()
    }
}

/// Shells and script engines that evaluate arbitrary text: high-risk warning.
///
/// Item 3 keeps `osascript` and `awk` here (warning only, still confirmed).
/// The shells that cannot be reduced to one allowlisted `execve` shape moved
/// to [`WRAPPER_LAUNCHERS`] and are refused outright.
const EVAL_LAUNCHERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "osascript",
    "awk",
    "gawk",
    "deno",
    "bun",
];
/// Interpreters: a script file is ordinary, but an eval flag is high-risk.
const INTERPRETERS: &[&str] = &[
    "node", "nodejs", "python", "ruby", "perl", "php", "lua", "tclsh", "rscript", "r", "julia",
    "nu", "octave", "raku", "swift",
];
/// Package runners that download and execute code: high-risk warning.
const PACKAGE_RUNNERS: &[&str] = &[
    "npx", "npm", "pnpm", "yarn", "bunx", "uvx", "uv", "pipx", "pip", "corepack",
];
/// Wrapper and shell launchers **refused outright** (items 2-3).
///
/// Each one either re-executes another program (`env`, `nice`, `timeout`,
/// `nohup`, `sudo`, `doas`, `su`, `xargs`, `stdbuf`, `taskset`, `chrt`,
/// `caffeinate`, `arch`, `script`, `exec`, `command`, `sandbox-exec`, `open`)
/// or evaluates arbitrary text (the POSIX and PowerShell shells plus
/// `busybox`). None can be reduced to the one pinned, secret-free `execve` the
/// stdio transport needs, so there is deliberately **no** warning-only path
/// for them: `argv[0]` naming any of these is refused with the stable code
/// `wrapper_launcher`. `osascript`, `awk` and `python -m` stay warning-only
/// (`high_risk`) — the denylist is defence in depth, never the boundary.
const WRAPPER_LAUNCHERS: &[&str] = &[
    "env",
    "nice",
    "timeout",
    "nohup",
    "sudo",
    "doas",
    "su",
    "xargs",
    "stdbuf",
    "taskset",
    "chrt",
    "caffeinate",
    "arch",
    "script",
    "time",
    "exec",
    "command",
    "sandbox-exec",
    "open",
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "busybox",
];

/// Basename of `command`, lowercased, with trailing version digits removed so
/// `python3.12` and `node18` are classified as `python` and `node`.
fn launcher_name(command: &str) -> String {
    let base = Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .to_owned()
}

/// Whether one argument switches an interpreter into eval mode: `--eval`,
/// `--print`, `--execute`/`--module` (with or without `=`) or a short option
/// cluster that carries `c`, `e`, `p`, `E`, `m` or `r` (`-c`, `-Bc`, `-pe`,
/// `-ne`, `-E`, `-r`, `-m`). Item 3 keeps this a **warning only**: `python -m`
/// is high-risk, never a hard refusal.
fn is_eval_flag(arg: &str) -> bool {
    if arg.starts_with("--") {
        let name = arg.split('=').next().unwrap_or(arg);
        return matches!(
            name,
            "--eval" | "--print" | "--execute" | "--exec" | "--import" | "--module"
        );
    }
    arg.len() > 1
        && arg.starts_with('-')
        && arg[1..]
            .chars()
            .any(|c| matches!(c, 'c' | 'e' | 'p' | 'E' | 'm' | 'r'))
}

/// Split a long flag into its name and an inline `=value`, if any.
pub(super) fn long_flag(arg: &str) -> Option<(&str, Option<&str>)> {
    if !arg.starts_with("--") {
        return None;
    }
    match arg.split_once('=') {
        Some((name, value)) => Some((name, Some(value))),
        None => Some((arg, None)),
    }
}

/// Classify one stdio launch, as warning text only.
pub fn stdio_risk_label(command: &str, args: &[String]) -> Option<&'static str> {
    // Classify the path as written and as it resolves, so a symlink named
    // `helper` that points at `/bin/sh` is still a shell.
    let mut names = vec![launcher_name(command)];
    if let Ok(real) = std::fs::canonicalize(command) {
        names.push(launcher_name(&real.to_string_lossy()));
    }
    let is = |list: &[&str]| names.iter().any(|name| list.contains(&name.as_str()));
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let has = |needle: &str| argv.contains(&needle);
    let contains = |needle: &str| argv.iter().any(|arg| arg.contains(needle));
    if is(EVAL_LAUNCHERS) {
        return Some("shell_launcher");
    }
    if names
        .iter()
        .any(|name| name.contains("npx") || name.contains("npm") || name.contains("uvx"))
        || is(PACKAGE_RUNNERS)
    {
        return Some("package_runner");
    }
    if names.iter().any(|name| name == "ssh") && contains("ProxyCommand") {
        return Some("ssh_proxycommand");
    }
    if names.iter().any(|name| name == "find") && (has("-exec") || has("-execdir")) {
        return Some("find_exec");
    }
    if names.iter().any(|name| name == "git")
        && has("-c")
        && (contains("core.fsmonitor") || contains("core.hooksPath") || contains("core.pager"))
    {
        return Some("git_config_override");
    }
    if is(WRAPPER_LAUNCHERS) {
        return Some("wrapper_launcher");
    }
    if is(INTERPRETERS) && argv.iter().any(|arg| is_eval_flag(arg)) {
        return Some("interpreter_eval");
    }
    if names_carry_token(&names, CONTAINER_CLI_TOKENS) {
        return Some("container_cli");
    }
    None
}

/// Every name `command` can be known by: as written and as it resolves.
pub(super) fn launcher_names(command: &str) -> Vec<String> {
    let mut names = vec![launcher_name(command)];
    if let Ok(real) = std::fs::canonicalize(command) {
        names.push(launcher_name(&real.to_string_lossy()));
    }
    names
}

/// Whether any of `names` carries one of `tokens` as a whole `-`/`_`/`.`
/// separated part (item 4).
///
/// `launcher_name` already lowercases the basename, so the comparison is
/// case-insensitive. Whole-token matching, never substring: `dockerize`,
/// `mydockerhelper`, `composer` and `climate-mcp` are ordinary binaries while
/// `podman-remote-static-linux_amd64`, `docker-compose-v2` and `Docker-Real`
/// still classify as before.
pub(super) fn names_carry_token(names: &[String], tokens: &[&str]) -> bool {
    names.iter().any(|name| {
        name.split(['-', '_', '.'])
            .any(|part| tokens.contains(&part))
    })
}

/// Whether `command` names a wrapper or shell launcher refused outright
/// (items 2-3), as written or after symlink resolution.
pub fn wrapper_launcher_label(command: &str) -> Option<&'static str> {
    let names = launcher_names(command);
    names
        .iter()
        .any(|name| WRAPPER_LAUNCHERS.contains(&name.as_str()))
        .then_some("wrapper_launcher")
}

/// The one stdio launch policy, shared by config validation, the add API and
/// import: an absolute command, a refusal of wrapper/shell launchers, bounded
/// NUL-free arguments, secret-looking arguments, and the container hard
/// refusals.
///
/// `network` is the server's declared network flag; a container server that
/// declares `network = false` must carry `--network=none` (item 4).
///
/// A wrapper or shell as `argv[0]` is refused outright with `wrapper_launcher`
/// (item 2) — no warning-only path. The remaining launcher classes
/// (interpreter eval, package runner, container) are reported as `high_risk`
/// warning text and **still require the owner's per-server confirmation** —
/// the denylist is not the boundary.
pub fn evaluate_stdio_policy(
    server: &str,
    command: &str,
    args: &[String],
    network: bool,
) -> Result<StdioPolicy, ServerRefusal> {
    let server = shown(server, "<id>");
    if command.is_empty() || command.contains('\0') || !Path::new(command).is_absolute() {
        return Err(refuse(
            "command_refused",
            format!("server {server} stdio command must be an absolute path"),
        ));
    }
    if command.len() > MAX_MCP_ARG_BYTES {
        return Err(refuse(
            "command_refused",
            format!("server {server} stdio command is too long"),
        ));
    }
    if let Some(label) = wrapper_launcher_label(command) {
        return Err(refuse(
            label,
            format!("server {server} uses a wrapper or shell launcher, which is refused"),
        ));
    }
    if args.len() > crate::stdio::MAX_ARGS {
        return Err(refuse(
            "command_refused",
            format!("server {server} declares too many stdio arguments"),
        ));
    }
    for (index, arg) in args.iter().enumerate() {
        if arg.contains('\0') || arg.len() > MAX_MCP_ARG_BYTES {
            return Err(refuse(
                "command_refused",
                format!("server {server} declares an unusable stdio argument"),
            ));
        }
        if looks_like_secret(arg) {
            return Err(refuse(
                "secret_in_config",
                format!(
                    "server {server} has a secret-looking argument; keep secrets in ~/.auxesis/.env and list the variable name in env"
                ),
            ));
        }
        if secret_pair_refused(args, index) {
            return Err(refuse(
                "secret_in_config",
                format!(
                    "server {server} has a secret-looking flag value; keep secrets in ~/.auxesis/.env and list the variable name in env"
                ),
            ));
        }
    }
    let high_risk = stdio_risk_label(command, args);
    if let Some(label) = container_policy_refusal(command, args, network) {
        return Err(refuse(
            label,
            format!("server {server} container launch is not allowed ({label})"),
        ));
    }
    Ok(StdioPolicy { high_risk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_util::shared::args;

    #[test]
    fn wrapper_and_shell_launchers_are_refused_outright() {
        // Item 2: the whole list is a hard refusal with one stable code, and
        // there is no warning-only path.
        for command in [
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
            "/bin/fish",
            "/bin/dash",
            "/bin/ksh",
            "/usr/bin/env",
            "/usr/bin/nice",
            "/usr/bin/timeout",
            "/usr/bin/nohup",
            "/usr/bin/sudo",
            "/usr/bin/doas",
            "/usr/bin/su",
            "/usr/bin/xargs",
            "/usr/bin/stdbuf",
            "/usr/bin/taskset",
            "/usr/bin/chrt",
            "/usr/bin/caffeinate",
            "/usr/bin/arch",
        ] {
            let refusal = evaluate_stdio_policy("bad", command, &args(&["server"]), false)
                .expect_err(&format!("{command} must be refused"));
            assert_eq!(refusal.label, "wrapper_launcher", "{command}");
        }
        // A symlink to a shell is refused too.
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("helper");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        assert_eq!(
            evaluate_stdio_policy("bad", &link.to_string_lossy(), &args(&["x"]), false)
                .unwrap_err()
                .label,
            "wrapper_launcher"
        );
        // The classes that were never in the wrapper list keep their warning.
        for command in ["/usr/bin/osascript", "/usr/bin/awk"] {
            let policy = evaluate_stdio_policy("bad", command, &args(&["server"]), false).unwrap();
            assert!(policy.is_high_risk(), "{command} must stay high risk");
        }
        // Item 3: the shell-like launchers moved to the hard refusal, so a
        // missing `high_risk` for one of them can never be reassuring.
        for command in [
            "/bin/csh",
            "/bin/tcsh",
            "/usr/local/bin/pwsh",
            "/usr/local/bin/powershell",
            "/usr/bin/busybox",
            "/usr/bin/script",
            "/usr/bin/time",
            "/usr/bin/exec",
            "/usr/bin/command",
            "/usr/bin/sandbox-exec",
            "/usr/bin/open",
        ] {
            let refusal = evaluate_stdio_policy("bad", command, &args(&["server"]), false)
                .expect_err(&format!("{command} must be refused"));
            assert_eq!(refusal.label, "wrapper_launcher", "{command}");
        }
        // `python -m` stays warning-only with `high_risk` (item 3).
        let policy = evaluate_stdio_policy(
            "warn",
            "/usr/bin/python3",
            &args(&["-m", "http.server"]),
            false,
        )
        .unwrap();
        assert_eq!(policy.high_risk, Some("interpreter_eval"));
        for command in [
            "/opt/homebrew/bin/npx",
            "/usr/local/bin/uvx",
            "/usr/local/bin/pipx",
        ] {
            let policy =
                evaluate_stdio_policy("runner", command, &args(&["run", "pkg"]), false).unwrap();
            assert_eq!(policy.high_risk, Some("package_runner"), "{command}");
        }
    }

    #[test]
    fn eval_flags_on_interpreters_are_flagged_including_clusters_long_forms_and_bypasses() {
        for (command, argv) in [
            ("/opt/homebrew/bin/node", vec!["-e", "1"]),
            ("/opt/homebrew/bin/node", vec!["-pe", "1"]),
            ("/opt/homebrew/bin/node", vec!["--eval=1"]),
            ("/opt/homebrew/bin/node", vec!["--print", "1"]),
            (
                "/opt/homebrew/bin/node",
                vec!["--import=data:text/javascript,1"],
            ),
            ("/usr/bin/python3.12", vec!["-Bc", "print(1)"]),
            ("/usr/bin/python3", vec!["-c", "print(1)"]),
            ("/usr/bin/perl", vec!["-e", "print 1"]),
            ("/usr/bin/ruby", vec!["-ne", "1"]),
            ("/usr/bin/Rscript", vec!["-e", "1"]),
            ("/opt/julia/bin/julia", vec!["-e", "1"]),
            ("/usr/local/bin/nu", vec!["-c", "1"]),
        ] {
            let policy = evaluate_stdio_policy("bad", command, &args(&argv), false).unwrap();
            assert_eq!(
                policy.high_risk,
                Some("interpreter_eval"),
                "{command} {argv:?}"
            );
        }
        // A script file is not an eval flag; a plain binary keeps its flags.
        assert!(
            !evaluate_stdio_policy("ok", "/usr/bin/python3.12", &args(&["server.py"]), false)
                .unwrap()
                .is_high_risk()
        );
        assert!(!evaluate_stdio_policy(
            "ok",
            "/usr/local/bin/rg",
            &args(&["-e", "pattern"]),
            false
        )
        .unwrap()
        .is_high_risk());
    }

    #[test]
    fn dangerous_launcher_bypasses_are_flagged_as_high_risk() {
        for (command, argv, label) in [
            (
                "/usr/bin/ssh",
                vec!["-o", "ProxyCommand=sh -c id", "host"],
                "ssh_proxycommand",
            ),
            ("/usr/bin/find", vec![".", "-exec", "id", ";"], "find_exec"),
            (
                "/usr/bin/git",
                vec!["-c", "core.fsmonitor=id", "status"],
                "git_config_override",
            ),
            (
                "/usr/local/bin/npx-cli.js",
                vec!["--yes", "pkg"],
                "package_runner",
            ),
        ] {
            let policy = evaluate_stdio_policy("bad", command, &args(&argv), false).unwrap();
            assert_eq!(policy.high_risk, Some(label), "{command} {argv:?}");
        }
    }

    #[test]
    fn a_symlink_to_a_shell_is_refused_like_the_shell() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("helper");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        let path = link.to_string_lossy().into_owned();
        assert_eq!(
            evaluate_stdio_policy("link", &path, &args(&["x"]), false)
                .unwrap_err()
                .label,
            "wrapper_launcher"
        );
    }
}
