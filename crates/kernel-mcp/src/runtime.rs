//! P2 runtime: discover configured servers once, then mount one agent's tools.
//!
//! [`McpRuntime::start`] walks the enabled servers of an [`McpConfig`] and
//! discovers each one **in isolation**: a server that is unreachable, broken or
//! times out is logged by id and a content-free reason, and every other server
//! still comes up. Nothing about a failed server reaches a log as text — only
//! its id and a `McpError::kind` label.
//!
//! # Mounting
//!
//! [`McpRuntime::register_for_agent`] is the P4 gate. An agent sees exactly the
//! remote names its own `[server.agents]` entry lists **and** that discovery
//! actually produced; a listed-but-absent tool is a warning, never a fallback
//! to "everything". Selected tools are ordinary [`kernel_broker::Tool`] values, so
//! the existing broker, taint and audit paths apply unchanged:
//!
//! * risk comes from the server annotations only ([`McpToolDescriptor::risk`]);
//! * every MCP tool sets [`kernel_broker::ToolClassExt::requires_explicit_rule`], so a wildcard
//!   `allow tool = "*"` can never authorize it (server annotations are not
//!   corroborated, so a `readOnlyHint` cannot widen that);
//! * output is untrusted (`mcp__…` plus an explicit registry mark), so running
//!   one taints the conversation exactly like `http_fetch` or mail.
//!
//! # Sandbox guarantee
//!
//! **stdio servers never run without an OS sandbox; platforms without one
//! refuse.** On macOS the launch path attaches the mandatory Seatbelt profile
//! (a missing `sandbox-exec` is `sandbox_unavailable`, never a bare spawn). A
//! host with no OS sandbox at all (non-macOS) is refused with
//! `sandbox_unavailable` too. The sole exception is a crate built with the
//! `test-util` feature: only test `[dev-dependencies]` enable it, so the
//! offline fixtures can still spawn on Linux, and no production build (the daemon,
//! the CLI) ever compiles that escape hatch.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use kernel_broker::ToolRegistry;
use reqwest::header::HeaderMap;
use tokio::time::Instant;

use crate::client::{client, McpClient, ServerInfo};
use crate::config::{McpConfig, McpServerConfig, McpTransport};
use crate::descriptor::McpToolDescriptor;
use crate::discovery::ToolCatalog;
use crate::http::HttpTransport;
use crate::limits::Limits;
use crate::naming::valid_wire_component;
use crate::tools::RemoteTool;

mod spawn;
mod status;
mod tool;

use spawn::build_stdio_transport;

pub use status::{
    McpServerRefusal, McpServerState, McpServerStatus, McpStartError, MAX_DISCOVERY_ROUNDS,
    MCP_CALL_TIMEOUT, STARTUP_DISCOVERY_TIMEOUT,
};
pub use tool::{transport_path, McpTool};

/// Every discovered server, ready to mount per agent.
pub struct McpRuntime {
    config: McpConfig,
    catalog: ToolCatalog,
    clients: BTreeMap<String, Arc<dyn McpClient>>,
    statuses: Vec<McpServerStatus>,
    call_timeout: Duration,
}

impl fmt::Debug for McpRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpRuntime")
            .field("servers", &self.statuses)
            .field("tools", &self.catalog.len())
            .finish()
    }
}

impl Default for McpRuntime {
    fn default() -> Self {
        Self {
            config: McpConfig::default(),
            catalog: ToolCatalog::new(),
            clients: BTreeMap::new(),
            statuses: Vec::new(),
            call_timeout: MCP_CALL_TIMEOUT,
        }
    }
}

impl McpRuntime {
    /// An empty runtime: no server, no tool, no client.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Discover every enabled server of `config`, isolating each failure.
    ///
    /// `secrets` holds the resolved `~/.auxesis/.env` values for the declared
    /// `env` names; a name without a value fails only that server and is
    /// logged by name, never by value.
    pub async fn start(config: McpConfig, secrets: &BTreeMap<String, String>) -> Self {
        Self::start_with(config, secrets, McpStartOptions::default(), &|_| Ok(())).await
    }

    /// Like [`McpRuntime::start`], with the daemon's per-server policy.
    ///
    /// `filter` runs before any transport is built. Returning `Err(refusal)`
    /// quarantines that server — it is reported with the refusal's state and
    /// reason — and every other server still comes up. This is where the
    /// daemon applies the catalog/confirmation policy and the existing `[web]`
    /// egress policy.
    pub async fn start_with(
        config: McpConfig,
        secrets: &BTreeMap<String, String>,
        options: McpStartOptions,
        filter: &(dyn Fn(&McpServerConfig) -> Result<(), McpServerRefusal> + Send + Sync),
    ) -> Self {
        let mut runtime = Self {
            config: config.clone(),
            ..Self::default()
        };
        // Item 6: entries that failed to deserialize are reported as
        // quarantined, so the API/CLI still lists them next to the valid ones.
        for quarantined in config.quarantined.iter().cloned() {
            runtime.statuses.push(McpServerStatus {
                id: quarantined.id,
                transport: quarantined
                    .transport
                    .map(McpTransport::as_str)
                    .unwrap_or("unknown"),
                enabled: false,
                state: McpServerState::Quarantined,
                tool_count: 0,
                reason: Some(quarantined.reason),
            });
        }
        for server in config.server.iter().cloned() {
            let status = |state, reason, tool_count| McpServerStatus {
                id: server.id.clone(),
                transport: server.transport.as_str(),
                enabled: server.enabled,
                state,
                tool_count,
                reason,
            };
            if !server.enabled {
                runtime
                    .statuses
                    .push(status(McpServerState::Disabled, None, 0));
                continue;
            }
            if server.transport == McpTransport::Http && !server.env.is_empty() {
                // The names are validated but only a stdio child receives
                // them; an HTTP endpoint gets no header from this file.
                tracing::warn!(
                    server = %server.id,
                    "declared env names are injected into stdio servers only"
                );
            }
            if let Err(refusal) = filter(&server) {
                tracing::warn!(
                    server = %server.id,
                    state = refusal.state.as_str(),
                    reason = refusal.reason,
                    "MCP server quarantined; continuing without it"
                );
                runtime
                    .statuses
                    .push(status(refusal.state, Some(refusal.reason), 0));
                continue;
            }
            let outcome = tokio::time::timeout(
                STARTUP_DISCOVERY_TIMEOUT,
                discover_server(&server, secrets, options.clone()),
            )
            .await;
            match outcome {
                Ok(Ok((client, tools))) => {
                    // The daemon quarantines a catalog id whose transport or
                    // endpoint does not match the catalog entry *before* this
                    // point, so only a verified catalog server can use its
                    // catalog id as a toolkit name. A `stdio` server never
                    // registers under a catalog toolkit name (item 7), even if
                    // a caller bypasses the daemon policy filter.
                    let toolkit = match server.transport {
                        McpTransport::Http => server.catalog_id.clone().unwrap_or_default(),
                        McpTransport::Stdio => String::new(),
                    };
                    let stats = runtime
                        .catalog
                        .replace_server_tools(&server.id, &toolkit, &tools);
                    runtime.clients.insert(server.id.clone(), client);
                    runtime
                        .statuses
                        .push(status(McpServerState::Ready, None, stats.registered));
                }
                Ok(Err(err)) => {
                    tracing::warn!(
                        server = %server.id,
                        reason = %err,
                        "MCP server unavailable; continuing without it"
                    );
                    // Item 8: a missing mandatory sandbox is a quarantine
                    // (the entry is unusable here), not a transient failure.
                    let state = if matches!(err, McpStartError::SandboxUnavailable) {
                        McpServerState::Quarantined
                    } else {
                        McpServerState::Failed
                    };
                    runtime.statuses.push(status(state, Some(err.kind()), 0));
                }
                Err(_) => {
                    tracing::warn!(
                        server = %server.id,
                        seconds = STARTUP_DISCOVERY_TIMEOUT.as_secs(),
                        "MCP server discovery timed out; continuing without it"
                    );
                    runtime
                        .statuses
                        .push(status(McpServerState::Failed, Some("timeout"), 0));
                }
            }
        }
        runtime
    }

    /// Stop the local process of every server in this runtime. Calls made
    /// afterwards through a tool that still holds the runtime fail; nothing
    /// is respawned by this method.
    pub async fn stop_child_processes(&self) {
        for client in self.clients.values() {
            client.stop().await;
        }
    }

    /// The parsed configuration this runtime was built from.
    pub fn config(&self) -> &McpConfig {
        &self.config
    }

    /// Every server's status, in file order.
    pub fn statuses(&self) -> &[McpServerStatus] {
        &self.statuses
    }

    /// Number of discovered descriptors across every server.
    pub fn tool_count(&self) -> usize {
        self.catalog.len()
    }

    /// The discovered descriptors of one server, in wire-name order.
    pub fn descriptors_for(&self, server_id: &str) -> Vec<&McpToolDescriptor> {
        self.catalog
            .descriptors()
            .filter(|descriptor| descriptor.server == server_id)
            .collect()
    }

    /// Mount `agent`'s explicitly listed tools on `registry`.
    ///
    /// Returns how many were registered. A name the agent lists but discovery
    /// never produced is a warning; a tool already registered under the same
    /// name (a native tool) is never overwritten.
    pub fn register_for_agent(&self, agent: &str, registry: &mut ToolRegistry) -> usize {
        let mut requested: Vec<String> = Vec::new();
        for server in &self.config.server {
            if !server.enabled {
                continue;
            }
            let Some(list) = server.agents.get(agent) else {
                continue;
            };
            for remote in list {
                if !valid_wire_component(remote) {
                    continue;
                }
                if let Some(wire) = self.catalog.wire_for(&server.id, remote) {
                    requested.push(wire.to_owned());
                }
            }
        }
        let selection = self.catalog.for_agent(&requested);
        for missing in &selection.missing {
            tracing::warn!(
                agent,
                wire = %missing,
                "MCP tool listed for this agent was not discovered"
            );
        }
        if selection.over_cap_total > 0 {
            tracing::warn!(
                agent,
                withheld = selection.over_cap_total,
                cap = crate::discovery::PER_AGENT_TOOL_CAP,
                "MCP tools withheld by the per-agent cap"
            );
        }
        let mut registered = 0usize;
        for descriptor in selection.tools {
            let Some(client) = self.clients.get(&descriptor.server) else {
                continue;
            };
            let name = descriptor.wire_name.clone();
            if registry.get(&name).is_some() {
                continue;
            }
            let path = self
                .config
                .server
                .iter()
                .find(|server| server.id == descriptor.server)
                .map_or(kernel_core::privacy::PathId::B14, |server| {
                    transport_path(server.transport)
                });
            registry.register(Box::new(McpTool::new(
                descriptor,
                Arc::clone(client),
                self.call_timeout,
                path,
            )));
            // `mcp__` already marks output untrusted on registration; the
            // explicit mark keeps the class even if the name hook changes.
            registry.mark_untrusted_output(name.clone());
            // Deliberately **not** `mark_read_only`: the read-only class means
            // "read-only by construction", and a server's own `readOnlyHint`
            // is untrusted (see `RiskBasis`). No wildcard `allow` applies to an
            // MCP tool either (`requires_explicit_rule`): with no exact-name
            // rule the broker asks.
            registered += 1;
        }
        registered
    }
}

/// Build the client for one server and run `initialize` + `tools/list`.
/// Daemon-owned hardening applied to every transport it builds.
///
/// There is deliberately **no** field that turns the `stdio` Seatbelt sandbox
/// off. Sandboxing is unconditional on macOS: the launch path attaches the
/// profile itself, and a host without `sandbox-exec` is refused rather than
/// executed unsandboxed (item 8, security review P2 seal). The only platform carve-out is
/// the `cfg(not(target_os = "macos"))` branch inside the *private* sandbox
/// builder, which no caller can reach through this struct.
///
/// # No public opt-out (compile-time tripwire)
///
/// The two fields below are exhaustive and the struct is not
/// `#[non_exhaustive]`, so this literal stops compiling the moment a
/// `sandbox_stdio`-style switch is added back:
///
/// ```compile_fail
/// # use kernel_mcp::McpStartOptions;
/// let _ = McpStartOptions {
///     network_guard: true,
///     confirmation_secret: None,
///     sandbox_stdio: false,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct McpStartOptions {
    /// Enforce the shared SSRF guard and pin the resolved address for runtime
    /// `http` connections (`false` for the loopback tests).
    pub network_guard: bool,
    /// The daemon-held confirmation key. A `stdio` server is always re-checked
    /// at spawn time against its stored confirmation, which also re-hashes the
    /// binary (item 4).
    ///
    /// `None` **refuses** every `stdio` launch (defence in depth, item 6): a
    /// caller with no key can never verify a confirmation, so it must not be a
    /// silent bypass. Tests that need to spawn the fixture supply a key and a
    /// matching `stdio_confirmation`.
    pub confirmation_secret: Option<Vec<u8>>,
}

impl Default for McpStartOptions {
    /// Fail closed (item 9): the SSRF guard is on, and an empty confirmation key
    /// means every `stdio` server is refused at spawn unless a caller supplies
    /// an explicit, non-empty key. The `stdio` sandbox is **not** an option
    /// here — the launch path always attaches it on macOS.
    fn default() -> Self {
        Self {
            network_guard: true,
            confirmation_secret: Some(Vec::new()),
        }
    }
}

async fn discover_server(
    server: &McpServerConfig,
    secrets: &BTreeMap<String, String>,
    options: McpStartOptions,
) -> Result<(Arc<dyn McpClient>, Vec<RemoteTool>), McpStartError> {
    let client = build_client(server, secrets, options).await?;
    client
        .initialize()
        .await
        .map_err(|err| McpStartError::Discovery(err.kind()))?;
    let deadline = Instant::now() + STARTUP_DISCOVERY_TIMEOUT;
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_DISCOVERY_ROUNDS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(McpStartError::Timeout);
        }
        let page = tokio::time::timeout(remaining, client.list_tools(cursor.as_deref()))
            .await
            .map_err(|_| McpStartError::Timeout)?
            .map_err(|err| McpStartError::Discovery(err.kind()))?;
        tools.extend(page.tools);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok((client, tools)),
        }
    }
    Ok((client, tools))
}

/// Build one transport/client pair from the validated server config.
async fn build_client(
    server: &McpServerConfig,
    secrets: &BTreeMap<String, String>,
    options: McpStartOptions,
) -> Result<Arc<dyn McpClient>, McpStartError> {
    match server.transport {
        McpTransport::Http => {
            let url = server
                .url
                .as_deref()
                .ok_or(McpStartError::Command("missing url"))?;
            let transport = if options.network_guard {
                HttpTransport::new_checked(url, HeaderMap::new(), Limits::default()).await
            } else {
                HttpTransport::new(url, HeaderMap::new(), Limits::default())
            }
            .map_err(|err| McpStartError::Transport(err.kind()))?;
            Ok(client(Arc::new(transport), ServerInfo::default()))
        }
        McpTransport::Stdio => {
            let transport =
                build_stdio_transport(server, secrets, options.confirmation_secret.as_deref())?;
            Ok(client(Arc::new(transport), ServerInfo::default()))
        }
    }
}

#[cfg(test)]
mod tests;
