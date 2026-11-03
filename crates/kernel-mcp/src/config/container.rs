//! The container-CLI `run` allowlist and its hard refusals.

use super::policy::{launcher_names, long_flag, names_carry_token};
use super::MAX_MCP_ENV_NAME_BYTES;

/// Whole tokens that identify a container CLI (item 4).
///
/// Matched as `-`/`_`/`.`-separated parts of the lowercased basename, never as
/// substrings: `dockerize`/`mydockerhelper` are ordinary binaries, while
/// `podman-remote-static-linux_amd64` still resolves to `podman`. `buildah`,
/// `ctr`, Apple's `container` and `orbctl` go through the same `run` allowlist
/// as docker, and are refused when their shape differs.
pub(super) const CONTAINER_CLI_TOKENS: &[&str] = &[
    "docker",
    "podman",
    "nerdctl",
    "buildah",
    "ctr",
    "container",
    "orbctl",
    "orb",
];
/// The whole token naming a compose launcher refused outright (item 4): a
/// `compose` file is a whole program that can mount, escalate and pull.
const CONTAINER_COMPOSE_TOKEN: &str = "compose";
/// Whole tokens naming a VM manager refused outright (item 4): none of them
/// can be reduced to the one allowlisted `run` shape.
const CONTAINER_VM_TOKENS: &[&str] = &["lima", "limactl", "colima", "finch"];

/// Whether `command` names a container CLI, as written or resolved.
///
/// Matched by whole token (item 4), so `podman-remote-static-linux_amd64`, a
/// `docker-real` shim or a case variant all go through the same `run`
/// allowlist, while a substring such as `dockerize` does not.
fn is_container_launcher(command: &str) -> bool {
    names_carry_token(&launcher_names(command), CONTAINER_CLI_TOKENS)
}

/// Whether `command` is a compose/Van Damme wrapper refused outright.
///
/// A basename carrying the whole token `compose` (`docker-compose`, a
/// `*-compose` shim) and the VM managers `lima`/`limactl`, `colima` and `finch`
/// are refused whatever their arguments: none of them can be reduced to the
/// allowlisted one-`run` shape.
fn is_refused_container_wrapper(command: &str) -> Option<&'static str> {
    let names = launcher_names(command);
    if names_carry_token(&names, &[CONTAINER_COMPOSE_TOKEN]) {
        return Some("container_compose");
    }
    if names_carry_token(&names, CONTAINER_VM_TOKENS) {
        return Some("container_vm_tool");
    }
    None
}

/// Whether `value` is a plain environment-variable NAME (no `=`, no value).
fn is_container_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MCP_ENV_NAME_BYTES
        && !value.contains('=')
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
        })
}

/// Whether `value` is a container name (bounded, no option look-alike).
fn is_container_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Whether `value` is a `--pull` policy the allowlist accepts.
fn is_container_pull(value: &str) -> bool {
    value.eq_ignore_ascii_case("never") || value.eq_ignore_ascii_case("missing")
}

/// One parsed `run` shape: the network mode the container would use, if any.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ContainerRun {
    /// `--network` value, lowercase (`none` or `bridge`), when present.
    network: Option<String>,
}

/// The whole allowlist for a container CLI (items 1-3).
///
/// Only this shape is accepted:
///
/// `<cli> run [--rm] [-i] [-t] [--init] [--read-only]
///  [--network=none|bridge] [-e NAME]... [--name X]
///  [--pull=never|missing] IMAGE [ARGS...]`
///
/// Every other flag before IMAGE is refused with a stable reason, which
/// subsumes every mount (`-v`, `--mount`, `--volumes-from`), capability
/// (`--cap-add`), device, namespace (`--ipc`, `--uts`, `--userns`, `--pid`),
/// `--privileged`, `--security-opt`, `-u` and the container socket. `-e`
/// takes env NAMES only: `NAME=value` and `--env-file` are refused. Clustered
/// short flags are expanded before checking and case does not matter.
fn container_run_shape(args: &[String]) -> Result<ContainerRun, &'static str> {
    let Some(first) = args.first() else {
        return Err("container_subcommand");
    };
    if !first.eq_ignore_ascii_case("run") {
        return Err("container_subcommand");
    }
    let mut run = ContainerRun::default();
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if !arg.starts_with('-') {
            // IMAGE, then its own args: accepted verbatim.
            return Ok(run);
        }
        if arg == "--" {
            return Err("container_flag");
        }
        if let Some((name, inline)) = long_flag(arg) {
            let name = name.to_ascii_lowercase();
            match name.as_str() {
                "--rm" | "--init" | "--read-only" => {
                    if inline.is_some() {
                        return Err("container_flag");
                    }
                    index += 1;
                }
                "--network" => {
                    let value = inline
                        .map(str::to_owned)
                        .or_else(|| args.get(index + 1).cloned());
                    let Some(value) = value else {
                        return Err("container_network");
                    };
                    if !value.eq_ignore_ascii_case("none") && !value.eq_ignore_ascii_case("bridge")
                    {
                        return Err("container_network");
                    }
                    run.network = Some(value.to_ascii_lowercase());
                    index += if inline.is_some() { 1 } else { 2 };
                }
                "--env" => {
                    let value = inline
                        .map(str::to_owned)
                        .or_else(|| args.get(index + 1).cloned());
                    if !value.as_deref().is_some_and(is_container_env_name) {
                        return Err("container_env_value");
                    }
                    index += if inline.is_some() { 1 } else { 2 };
                }
                "--name" => {
                    let value = inline
                        .map(str::to_owned)
                        .or_else(|| args.get(index + 1).cloned());
                    if !value.as_deref().is_some_and(is_container_name) {
                        return Err("container_name");
                    }
                    index += if inline.is_some() { 1 } else { 2 };
                }
                "--pull" => {
                    let value = inline
                        .map(str::to_owned)
                        .or_else(|| args.get(index + 1).cloned());
                    if !value.as_deref().is_some_and(is_container_pull) {
                        return Err("container_pull");
                    }
                    index += if inline.is_some() { 1 } else { 2 };
                }
                _ => return Err("container_flag"),
            }
            continue;
        }
        // A clustered/attached short flag: expand one character at a time.
        let body = &arg[1..];
        let mut chars = body.chars();
        let mut short_ok = true;
        let mut consumed_value = false;
        while let Some(flag) = chars.next() {
            match flag.to_ascii_lowercase() {
                'i' | 't' => {}
                'e' => {
                    let rest: String = chars.collect();
                    let value = if rest.is_empty() {
                        consumed_value = true;
                        args.get(index + 1).cloned().unwrap_or_default()
                    } else {
                        rest.strip_prefix('=').unwrap_or(&rest).to_owned()
                    };
                    if !is_container_env_name(&value) {
                        return Err("container_env_value");
                    }
                    break;
                }
                _ => {
                    short_ok = false;
                    break;
                }
            }
        }
        if !short_ok {
            return Err("container_flag");
        }
        index += if consumed_value { 2 } else { 1 };
    }
    Err("container_image_missing")
}

/// Refuse a container launch the policy does not allow (items 1-4).
///
/// `network` is the server's declared network flag. A container server with
/// `network = false` **must** carry `--network=none`: an absent flag (which
/// would default to bridge) and `--network=bridge` are both refused, because
/// otherwise the declared `network = false` would not actually constrain the
/// container. Documented choice: refuse rather than rewrite the argv, so the
/// confirmed launch spec stays exactly what the owner reviewed.
pub(super) fn container_policy_refusal(
    command: &str,
    args: &[String],
    network: bool,
) -> Option<&'static str> {
    if let Some(label) = is_refused_container_wrapper(command) {
        return Some(label);
    }
    if !is_container_launcher(command) {
        return None;
    }
    if args
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case(CONTAINER_COMPOSE_TOKEN))
    {
        return Some("container_compose");
    }
    match container_run_shape(args) {
        Err(label) => Some(label),
        Ok(run) => {
            if network {
                return None;
            }
            match run.network.as_deref() {
                Some("none") => None,
                _ => Some("container_network"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::evaluate_stdio_policy;
    use crate::config::test_util::shared::args;
    use crate::config::{ServerRefusal, StdioPolicy};

    fn docker(argv: &[&str]) -> Result<StdioPolicy, ServerRefusal> {
        evaluate_stdio_policy("docker", "/usr/local/bin/docker", &args(argv), true)
    }

    fn docker_without_network(argv: &[&str]) -> Result<StdioPolicy, ServerRefusal> {
        evaluate_stdio_policy("docker", "/usr/local/bin/docker", &args(argv), false)
    }

    #[test]
    fn container_run_allowlist_accepts_only_the_documented_shape() {
        for argv in [
            vec!["run", "img"],
            vec!["run", "--rm", "-i", "-t", "--init", "--read-only", "img"],
            vec!["RUN", "--RM", "-IT", "img"],
            vec!["run", "--network=none", "img"],
            vec!["run", "--network", "bridge", "img"],
            vec!["run", "-e", "DATAGOUV_KEY", "img"],
            vec!["run", "--env=DATAGOUV_KEY", "img"],
            vec!["run", "--env", "DATAGOUV_KEY", "--name", "x", "img"],
            vec!["run", "--pull=never", "--pull", "missing", "img"],
            // Clustered short flags, attached `-eNAME`, and image args.
            vec!["run", "-it", "img", "sh", "-c", "id"],
            vec!["run", "-eDATAGOUV_KEY", "img"],
        ] {
            assert!(docker(&argv).is_ok(), "{argv:?} must be allowed");
        }
    }

    #[test]
    fn container_run_allowlist_refuses_every_other_flag_and_mount() {
        for (argv, label) in [
            (vec!["build", "."], "container_subcommand"),
            (vec!["-v"], "container_subcommand"),
            (vec!["run"], "container_image_missing"),
            (vec!["run", "--privileged", "img"], "container_flag"),
            (vec!["run", "--privileged=true", "img"], "container_flag"),
            (vec!["run", "--cap-add=ALL", "img"], "container_flag"),
            (
                vec!["run", "--cap-add", "CAP_SYS_ADMIN", "img"],
                "container_flag",
            ),
            (vec!["run", "--ipc=host", "img"], "container_flag"),
            (vec!["run", "--pid=host", "img"], "container_flag"),
            (vec!["run", "--uts=host", "img"], "container_flag"),
            (vec!["run", "--userns=host", "img"], "container_flag"),
            (vec!["run", "--device", "/dev/sda", "img"], "container_flag"),
            (
                vec!["run", "--security-opt=seccomp=unconfined", "img"],
                "container_flag",
            ),
            (vec!["run", "--net=host", "img"], "container_flag"),
            (vec!["run", "--network=host", "img"], "container_network"),
            (vec!["run", "--network", "host", "img"], "container_network"),
            (
                vec!["run", "-v", "./nope/../../Users/x:/h", "img"],
                "container_flag",
            ),
            (vec!["run", "-v", "/USERS/x:/h", "img"], "container_flag"),
            (
                vec![
                    "run",
                    "-v",
                    "/run/podman/podman.sock:/run/podman/podman.sock",
                    "img",
                ],
                "container_flag",
            ),
            (
                vec!["run", "--volume=/Users/fake:/data", "img"],
                "container_flag",
            ),
            (
                vec![
                    "run",
                    "--mount",
                    "type=bind,source=/Users/fake,target=/data",
                    "img",
                ],
                "container_flag",
            ),
            (
                vec!["run", "--volumes-from", "other", "img"],
                "container_flag",
            ),
            (vec!["run", "-itv", "/Users/x:/h", "img"], "container_flag"),
            (vec!["run", "-v/Users/fake:/data", "img"], "container_flag"),
            (vec!["run", "-u", "root", "img"], "container_flag"),
            (vec!["run", "--user", "root", "img"], "container_flag"),
            // The env *name* is what the container allowlist checks; a name
            // that does not look credential-like keeps the container label.
            (
                vec!["run", "-e", "DATAGOUV_CONFIG=value", "img"],
                "container_env_value",
            ),
            (
                vec!["run", "--env=DATAGOUV_CONFIG=value", "img"],
                "container_env_value",
            ),
            // Item 5: `key` is a whole `_`-separated part, so a `..._KEY=value`
            // env pair is a secret first — the stronger, earlier refusal wins.
            (
                vec!["run", "-e", "DATAGOUV_KEY=secret", "img"],
                "secret_in_config",
            ),
            (
                vec!["run", "--env=DATAGOUV_KEY=secret", "img"],
                "secret_in_config",
            ),
            (
                vec!["run", "--env-file=/tmp/fake.env", "img"],
                "container_flag",
            ),
        ] {
            let refusal = docker(&argv).expect_err(&format!("{argv:?} must be refused"));
            assert_eq!(refusal.label, label, "{argv:?}");
        }
        // `nerdctl -v` is not a `run` shape; a podman socket mount is refused.
        let nerdctl = evaluate_stdio_policy("n", "/usr/local/bin/nerdctl", &args(&["-v"]), false)
            .unwrap_err();
        assert_eq!(nerdctl.label, "container_subcommand");
        let podman = evaluate_stdio_policy(
            "p",
            "/usr/local/bin/podman",
            &args(&["run", "-v", "/run/podman/podman.sock:/sock", "img"]),
            false,
        )
        .unwrap_err();
        assert_eq!(podman.label, "container_flag");
    }

    #[test]
    fn compose_and_vm_container_launchers_are_refused_outright() {
        let wrappers: [(&str, Vec<&str>); 12] = [
            ("/usr/local/bin/docker-compose", vec!["up"]),
            ("/usr/local/bin/docker", vec!["compose", "up"]),
            ("/usr/local/bin/lima", vec!["start"]),
            ("/usr/local/bin/limactl", vec!["start", "default"]),
            ("/usr/local/bin/colima", vec!["start"]),
            ("/usr/local/bin/finch", vec!["run", "img"]),
            ("/usr/local/bin/nerdctl", vec!["compose", "up"]),
            ("/opt/homebrew/bin/my-compose-shim", vec!["up"]),
            // Item 3: substring matching, so a renamed/static build is caught.
            ("/usr/local/bin/docker-compose-v2", vec!["up"]),
            ("/usr/local/bin/lima-static-linux_amd64", vec!["start"]),
            ("/usr/local/bin/colima-x86_64", vec!["start"]),
            ("/usr/local/bin/finch-static", vec!["run", "img"]),
        ];
        for (command, base) in wrappers {
            for extra in [
                vec!["-v", "/:/h"],
                vec!["--privileged"],
                vec!["--privileged=true"],
            ] {
                let mut full: Vec<String> = base.iter().map(|arg| (*arg).to_owned()).collect();
                full.extend(extra.iter().map(|arg| (*arg).to_owned()));
                let refusal = evaluate_stdio_policy("x", command, &full, false)
                    .expect_err(&format!("{command} {full:?} must be refused"));
                assert!(
                    matches!(refusal.label, "container_compose" | "container_vm_tool"),
                    "{command} {full:?} -> {}",
                    refusal.label
                );
            }
        }
        // `compose up` through a runnable container CLI is refused too.
        for command in [
            "/usr/local/bin/docker",
            "/usr/local/bin/nerdctl",
            "/usr/local/bin/podman",
        ] {
            for extra in [vec!["-v", "/:/h"], vec!["--privileged"]] {
                let mut full: Vec<String> = vec!["compose".to_owned(), "up".to_owned()];
                full.extend(extra.iter().map(|arg| (*arg).to_owned()));
                let refusal = evaluate_stdio_policy("x", command, &full, false)
                    .expect_err("a compose subcommand must be refused");
                assert_eq!(refusal.label, "container_compose", "{command} {full:?}");
            }
        }
        // Item 3: a container CLI is matched by substring, so a renamed or
        // static build (`podman-remote-static-linux_amd64`) still goes through
        // the same allowlist — and its disallowed flags are still refused.
        assert!(evaluate_stdio_policy(
            "p",
            "/usr/local/bin/podman-remote",
            &args(&["run", "--network=none", "img"]),
            false
        )
        .is_ok());
        assert!(evaluate_stdio_policy(
            "p",
            "/usr/local/bin/podman-remote-static-linux_amd64",
            &args(&["run", "--network=none", "img"]),
            false
        )
        .is_ok());
        assert_eq!(
            evaluate_stdio_policy(
                "p",
                "/opt/homebrew/bin/nerdctl-static-linux_amd64",
                &args(&["run", "--privileged", "img"]),
                false
            )
            .unwrap_err()
            .label,
            "container_flag"
        );
        // A Docker-shaped basename is still a container CLI, case-insensitively.
        assert_eq!(
            evaluate_stdio_policy(
                "p",
                "/usr/local/bin/Docker-Real",
                &args(&["run", "-v", "/:/h", "img"]),
                false
            )
            .unwrap_err()
            .label,
            "container_flag"
        );
    }

    #[test]
    fn container_tokens_match_whole_parts_not_substrings() {
        // Item 4: `climate-mcp`, `composer`, `dockerize` and `mydockerhelper`
        // are NOT container CLIs, so they get neither a container refusal nor
        // a `container_cli` label (substring matching used to flag all four).
        for command in [
            "/usr/local/bin/climate-mcp",
            "/usr/local/bin/composer",
            "/usr/local/bin/dockerize",
            "/usr/local/bin/mydockerhelper",
        ] {
            let policy = evaluate_stdio_policy("ok", command, &args(&["--version"]), false)
                .unwrap_or_else(|refusal| panic!("{command} -> {}", refusal.label));
            assert_ne!(policy.high_risk, Some("container_cli"), "{command}");
        }
        // The whole-token forms still behave exactly as before.
        assert_eq!(
            evaluate_stdio_policy(
                "p",
                "/usr/local/bin/docker-compose",
                &args(&["config"]),
                false
            )
            .unwrap_err()
            .label,
            "container_compose"
        );
        assert_eq!(
            evaluate_stdio_policy("p", "/usr/local/bin/lima", &args(&["start"]), false)
                .unwrap_err()
                .label,
            "container_vm_tool"
        );
        assert!(evaluate_stdio_policy(
            "p",
            "/usr/local/bin/podman-remote-static-linux_amd64",
            &args(&["run", "--network=none", "img"]),
            false
        )
        .is_ok());
        // Item 4: buildah, ctr, Apple's `container` and orbctl go through the
        // same `run` allowlist (`orbctl` accepted in shape, refused otherwise).
        for command in [
            "/usr/local/bin/buildah",
            "/usr/bin/ctr",
            "/usr/local/bin/container",
            "/usr/local/bin/orbctl",
        ] {
            assert!(
                evaluate_stdio_policy(
                    "c",
                    command,
                    &args(&["run", "--network=none", "img"]),
                    false
                )
                .is_ok(),
                "{command} must go through the allowlist"
            );
            assert_eq!(
                evaluate_stdio_policy("c", command, &args(&["run", "--privileged", "img"]), false)
                    .unwrap_err()
                    .label,
                "container_flag",
                "{command} must be refused when its shape differs"
            );
        }
        // Apple `container run -v /:/host` is refused on the mount flag.
        assert_eq!(
            evaluate_stdio_policy(
                "c",
                "/usr/local/bin/container",
                &args(&["run", "-v", "/:/host", "img"]),
                false
            )
            .unwrap_err()
            .label,
            "container_flag"
        );
    }

    #[test]
    fn container_with_network_false_must_carry_network_none() {
        for argv in [
            vec!["run", "img"],
            vec!["run", "--rm", "img"],
            vec!["run", "--network", "bridge", "img"],
            vec!["run", "--network=bridge", "img"],
        ] {
            let refusal = docker_without_network(&argv)
                .expect_err(&format!("{argv:?} must be refused without --network=none"));
            assert_eq!(refusal.label, "container_network", "{argv:?}");
        }
        assert!(docker_without_network(&["run", "--network=none", "img"]).is_ok());
        // `network = true` accepts either mode; the declared flag is honoured.
        assert!(docker(&["run", "--network=bridge", "img"]).is_ok());
        assert!(evaluate_stdio_policy(
            "d",
            "/usr/local/bin/docker",
            &args(&["run", "--network=none", "img"]),
            true
        )
        .is_ok());
    }
}
