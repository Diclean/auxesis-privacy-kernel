//! Per-server validation: ids, env names, URLs and launch refusals.

use super::approval::approval_digest;
use super::confirmation::confirmation_digest;
use super::echo::shown;
use super::policy::{evaluate_stdio_policy, StdioPolicy};
use super::secrets::looks_like_secret;
use super::{
    McpServerConfig, McpTransport, MAX_MCP_AGENTS, MAX_MCP_AGENT_TOOLS, MAX_MCP_ENV_NAME_BYTES,
    MAX_MCP_URL_BYTES,
};

/// Why one `[[server]]` entry is unusable, with a stable static label.
///
/// The label is content-free and is what the API and UI show as a quarantine
/// reason; `detail` is a human-readable, secret-free explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRefusal {
    /// Stable, content-free category (`catalog_mismatch`, `command_refused`, ...).
    pub label: &'static str,
    /// Human-readable, secret-free explanation.
    pub detail: String,
}

pub(super) fn refuse(label: &'static str, detail: impl Into<String>) -> ServerRefusal {
    ServerRefusal {
        label,
        detail: detail.into(),
    }
}

impl McpServerConfig {
    /// Validate this one entry, returning a static-label refusal.
    ///
    /// This is the per-server rule set; the caller quarantines only this
    /// server on failure.
    pub fn check(&self) -> Result<StdioPolicy, ServerRefusal> {
        if !valid_id(&self.id) {
            return Err(refuse(
                "invalid_server_id",
                "server id must match [a-z0-9-]{1,32}",
            ));
        }
        let server = shown(&self.id, "<id>");
        if self.env.len() > crate::stdio::MAX_ENV_ENTRIES {
            return Err(refuse(
                "invalid_env_name",
                format!("server {server} declares too many env names"),
            ));
        }
        for name in &self.env {
            validate_env_name(&self.id, name)?;
        }
        let policy = match self.transport {
            McpTransport::Http => {
                if self.command.is_some() || !self.args.is_empty() {
                    return Err(refuse(
                        "invalid_server",
                        format!("server {server} is http and must not set command/args"),
                    ));
                }
                let url = self.url.as_deref().ok_or_else(|| {
                    refuse(
                        "invalid_server",
                        format!("server {server} is http and needs a url"),
                    )
                })?;
                validate_http_url(&self.id, url)?;
                StdioPolicy::default()
            }
            McpTransport::Stdio => {
                if self.url.is_some() {
                    return Err(refuse(
                        "invalid_server",
                        format!("server {server} is stdio and must not set url"),
                    ));
                }
                let command = self.command.as_deref().ok_or_else(|| {
                    refuse(
                        "invalid_server",
                        format!("server {server} is stdio and needs an absolute command"),
                    )
                })?;
                evaluate_stdio_policy(&self.id, command, &self.args, self.network)?
            }
        };
        if self.agents.len() > MAX_MCP_AGENTS {
            return Err(refuse(
                "invalid_tools",
                format!("server {server} names too many agents"),
            ));
        }
        for (agent, tools) in &self.agents {
            if !valid_agent(agent) {
                return Err(refuse(
                    "invalid_tools",
                    format!("server {server} names an invalid agent"),
                ));
            }
            if tools.len() > MAX_MCP_AGENT_TOOLS {
                return Err(refuse(
                    "invalid_tools",
                    format!(
                        "server {server} lists too many tools for agent {}",
                        shown(agent, "<agent>")
                    ),
                ));
            }
            for tool in tools {
                // The remote name is the argument to `tools/call`: it is
                // refused, never rewritten.
                if !crate::naming::valid_wire_component(tool) || tool.len() > 48 {
                    return Err(refuse(
                        "invalid_tools",
                        format!(
                            "server {server} lists an unusable tool name for agent {}",
                            shown(agent, "<agent>")
                        ),
                    ));
                }
            }
        }
        Ok(policy)
    }

    /// The confirmation binding for this launch, keyed by a daemon-held secret.
    ///
    /// Covers the **whole launch spec** (item 4): canonical command path, args
    /// verbatim, sorted env names, `network`, `data_class`, transport and the
    /// SHA-256 of the binary at the canonical path. No secret → no binding
    /// (fail closed, item 5): there is no unkeyed/plain-hash acceptance.
    pub fn confirmation_binding(&self, secret: &[u8]) -> Option<String> {
        confirmation_digest(secret, self, None)
    }

    /// The same binding, but over a binary SHA-256 the caller already
    /// verified (a catalog pin) instead of re-reading the file. Re-reading
    /// would let a file swapped between the check and the binding get the
    /// swapped binary approved; with the published hash bound in, the spawn
    /// re-check (which hashes the file it is about to run) only passes for
    /// exactly the catalog's binary.
    pub fn confirmation_binding_for_sha(&self, secret: &[u8], sha256: &str) -> Option<String> {
        confirmation_digest(secret, self, Some(sha256))
    }

    /// Whether the owner's confirmation is present **and** still matches this
    /// exact launch under `secret`.
    ///
    /// The daemon passes its API token, so a config file edited by hand (or an
    /// imported snippet) cannot mint a confirmation: it would have to know the
    /// token. A bare `stdio_confirmed = true` is never enough. An empty secret
    /// (the daemon token could not be read) confirms nothing.
    pub fn stdio_is_confirmed_with(&self, secret: &[u8]) -> bool {
        // A missing stored hash is never a confirmation, so `None == None`
        // cannot pass. An empty secret yields `None` from the binding, so it
        // can never match a stored hash either.
        let Some(stored) = self.stdio_confirmation.as_deref() else {
            return false;
        };
        self.stdio_confirmed && self.confirmation_binding(secret).as_deref() == Some(stored)
    }

    /// The M6-2 install approval for this exact preview under `secret`.
    ///
    /// `catalog_pin` is the curated `catalog_hash` for a catalog entry; a
    /// catalog server without a pin gets no binding (fail closed). Like the
    /// confirmation, an empty secret yields `None`.
    ///
    /// A non-catalog `stdio` server's digest includes the SHA-256 of the
    /// program file **as it is now**. A caller that already previewed the file
    /// passes the previewed hash to [`Self::approval_binding_for_sha`] instead,
    /// so a swap between preview and approve cannot be accepted by re-reading
    /// the swapped file.
    pub fn approval_binding(&self, secret: &[u8], catalog_pin: Option<&str>) -> Option<String> {
        approval_digest(secret, self, catalog_pin, None)
    }

    /// The same approval binding, but over a binary SHA-256 the caller already
    /// previewed, instead of re-reading the file.
    ///
    /// Only a non-catalog `stdio` server carries the hash: a catalog entry's
    /// pin covers its published SHA, and an `http` server has no program.
    pub fn approval_binding_for_sha(
        &self,
        secret: &[u8],
        catalog_pin: Option<&str>,
        sha256: &str,
    ) -> Option<String> {
        approval_digest(secret, self, catalog_pin, Some(sha256))
    }

    /// Whether the owner approved **this** install: a keyed digest over the
    /// id, catalog id and pin, transport, endpoint or launch, data class,
    /// network, every agent→tool allowlist and (for a non-catalog stdio
    /// server) the program's SHA-256. A hand-edited `enabled = true` never
    /// passes; the lifecycle fields are deliberately not hashed, so the same
    /// hash the preview returned is still valid for the approve call.
    pub fn is_approved_with(&self, secret: &[u8], catalog_pin: Option<&str>) -> bool {
        let Some(stored) = self.approval.as_deref() else {
            return false;
        };
        self.approval_binding(secret, catalog_pin).as_deref() == Some(stored)
    }

    /// Whether this enabled server carries a valid M6-2 install approval.
    ///
    /// This is the one approval predicate: the daemon passes the curated
    /// catalog pin for a catalog entry, and a caller without the catalog (the
    /// CLI) passes `None`, which fails closed for a catalog server.
    ///
    /// A pre-M6-2 `stdio` server whose old launch confirmation still matches
    /// and which has no approval record is grandfathered: its confirmation was
    /// the install approval of its day. A bad or changed approval record never
    /// falls back to the old gate.
    pub fn is_install_approved(&self, secret: Option<&[u8]>, catalog_pin: Option<&str>) -> bool {
        let Some(secret) = secret else {
            return false;
        };
        if self.is_approved_with(secret, catalog_pin) {
            return true;
        }
        self.approval.is_none()
            && self.transport == McpTransport::Stdio
            && self.catalog_id.is_none()
            && self.stdio_is_confirmed_with(secret)
    }
}

/// `[a-z0-9-]{1,32}`.
fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// An agent name accepted by the daemon: short, ASCII, no path characters.
fn valid_agent(agent: &str) -> bool {
    (1..=64).contains(&agent.len())
        && agent
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// A shell-style env name, bounded and never an Auxesis-reserved key.
fn validate_env_name(server: &str, name: &str) -> Result<(), ServerRefusal> {
    let server = shown(server, "<id>");
    if name.len() > MAX_MCP_ENV_NAME_BYTES || !crate::stdio::env_key_declared(name) {
        return Err(refuse(
            "invalid_env_name",
            format!("server {server} declares an invalid or reserved env name"),
        ));
    }
    Ok(())
}

/// `https`, or plain `http` on loopback only.
fn validate_http_url(server: &str, url: &str) -> Result<(), ServerRefusal> {
    let server = shown(server, "<id>");
    if url.len() > MAX_MCP_URL_BYTES {
        return Err(refuse(
            "invalid_url",
            format!("server {server} has an over-long url"),
        ));
    }
    if looks_like_secret(url) {
        return Err(refuse(
            "secret_in_config",
            format!(
                "server {server} url carries a secret-looking value; keep secrets in ~/.auxesis/.env"
            ),
        ));
    }
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| refuse("invalid_url", format!("server {server} has an invalid url")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(refuse(
            "secret_in_config",
            format!("server {server} must not embed credentials in its url"),
        ));
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(parsed.host_str()) => Ok(()),
        _ => Err(refuse(
            "endpoint_insecure",
            format!(
                "server {server} must use https (http is allowed only for 127.0.0.1/localhost)"
            ),
        )),
    }
}

/// Whether a URL host is loopback (plain `http` allowed there only).
pub fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(
        host,
        Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
    )
}

#[cfg(test)]
mod tests {
    use crate::config::test_util::shared::args;
    use crate::config::{
        evaluate_stdio_policy, McpConfig, McpDataClass, McpServerConfig, McpTransport,
    };

    #[test]
    fn legacy_server_defaults_sensitive_and_plain_binary_is_allowed_but_high_risk_free() {
        let parsed = McpConfig::parse("test", "[[server]]\nid = \"legacy\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n").unwrap();
        assert_eq!(parsed.server[0].data_class, McpDataClass::Sensitive);
        let policy = evaluate_stdio_policy(
            "plain",
            "/usr/local/bin/ripgrep",
            &args(&["--stdio"]),
            false,
        )
        .unwrap();
        assert!(!policy.is_high_risk());
    }

    #[test]
    fn declared_env_names_exclude_loader_start_up_and_home_controls() {
        for name in [
            "PATH",
            "HOME",
            "SHELL",
            "TMPDIR",
            "NODE_OPTIONS",
            "BASH_ENV",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "PYTHONPATH",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "LUA_INIT",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "RUSTC_WRAPPER",
            "GCONV_PATH",
            "PYTHONBREAKPOINT",
            "PYTHONUSERBASE",
            "AUXESIS_API_PORT",
            "AUX_KEY_X",
            // Container-CLI steering names (items 3/4), denied by prefix.
            "DOCKER_HOST",
            "DOCKER_CONFIG",
            "DOCKER_IMAGE",
            "DOCKER_CONTEXT",
            "DOCKER_CERT_PATH",
            "DOCKER_TLS_VERIFY",
            "CONTAINER_HOST",
            "CONTAINER_CONNECTION",
            "CONTAINERS_CONF",
            "CONTAINERD_ADDRESS",
            "PODMAN_HOST",
            "BUILDKIT_HOST",
            "REGISTRY_AUTH_FILE",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_COUNT",
            "NERDCTL_ADDRESS",
            "NERDCTL_NAMESPACE",
            "XDG_CONFIG_HOME",
        ] {
            assert!(!crate::stdio::env_key_declared(name), "{name}");
        }
        // Item 4: the comparison folds case, so a lowercase spelling of a
        // denied name or prefix is refused exactly like the uppercase one.
        for name in [
            "docker_host",
            "Docker_Host",
            "podman_host",
            "xdg_cache_home",
            "shell",
            "tmpdir",
            "ld_preload",
            "dyld_insert_libraries",
            "rustc_wrapper",
            "jdk_java_options",
            "gconv_path",
            "pythonbreakpoint",
            "git_ssh",
            "git_config_system",
            "containerd_address",
        ] {
            assert!(!crate::stdio::env_key_declared(name), "{name}");
        }
        assert!(crate::stdio::env_key_declared("DATAGOUV_KEY"));
        assert!(crate::stdio::env_key_declared("DOCKERFILE_CONTENT"));
        let parsed = McpConfig::parse(
            "t",
            "[[server]]\nid = \"b\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\nenv = [\"NODE_OPTIONS\"]\n",
        )
        .unwrap();
        assert!(parsed.server[0].check().is_err());
        let parsed = McpConfig::parse(
            "t",
            "[[server]]\nid = \"c\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\nenv = [\"DOCKER_HOST\"]\n",
        )
        .unwrap();
        assert!(parsed.server[0].check().is_err());
    }

    #[test]
    fn approval_and_confirmation_digests_separate_args_from_env() {
        // Review P2: `args=["X"], env=[]` and `args=[], env=["X"]` must not
        // collide. The env name is a legal declared name, so without the fix a
        // hand edit moves a `.env` value into the child's argv (or the reverse)
        // while the old approval still validates.
        let mut server = McpServerConfig {
            id: "plain".into(),
            catalog_id: None,
            data_class: McpDataClass::Sensitive,
            stdio_confirmed: false,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: McpTransport::Stdio,
            url: None,
            command: Some("/bin/echo".into()),
            args: vec!["X".into()],
            env: vec![],
            enabled: false,
            agents: Default::default(),
        };
        let secret = b"daemon-token";
        let mut moved = server.clone();
        moved.args = vec![];
        moved.env = vec!["X".into()];
        assert_ne!(
            server.approval_binding(secret, None),
            moved.approval_binding(secret, None),
            "moving an item between args and env must change the approval digest"
        );
        assert_ne!(
            server.confirmation_binding(secret),
            moved.confirmation_binding(secret),
            "moving an item between args and env must change the confirmation digest"
        );
        // The same lists in the same field still bind identically.
        assert_eq!(
            server.approval_binding(secret, None),
            server.clone().approval_binding(secret, None)
        );
        // A tool cannot be moved between agents without changing the digest.
        server.agents.insert("main".into(), vec!["read".into()]);
        server.agents.insert("aux".into(), vec!["write".into()]);
        let mut same_tools_one_agent = server.clone();
        same_tools_one_agent.agents.clear();
        same_tools_one_agent
            .agents
            .insert("main".into(), vec!["read".into(), "write".into()]);
        assert_ne!(
            server.approval_binding(secret, None),
            same_tools_one_agent.approval_binding(secret, None)
        );
    }
}
