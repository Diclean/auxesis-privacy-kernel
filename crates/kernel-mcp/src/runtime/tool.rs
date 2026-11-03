//! [`McpTool`]: one discovered MCP tool exposed as a broker [`kernel_broker::Tool`].

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kernel_broker::{ExecutionMode, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, Trust};
use kernel_privacy::Gate;
use serde_json::Value;

use crate::client::McpClient;
use crate::config::McpTransport;
use crate::descriptor::McpToolDescriptor;

/// One tool an agent may call: an [`kernel_broker::Tool`] over one MCP connection.
pub struct McpTool {
    descriptor: McpToolDescriptor,
    client: Arc<dyn McpClient>,
    timeout: Duration,
    /// The privacy row of the server's transport (B13 HTTP, B14 stdio).
    path: kernel_core::privacy::PathId,
}

impl McpTool {
    /// Wrap `descriptor` over `client`. `path` is the privacy row for the
    /// server's transport (see [`transport_path`]).
    pub fn new(
        descriptor: McpToolDescriptor,
        client: Arc<dyn McpClient>,
        timeout: Duration,
        path: kernel_core::privacy::PathId,
    ) -> Self {
        Self {
            descriptor,
            client,
            timeout,
            path,
        }
    }

    /// The descriptor behind this tool.
    pub fn descriptor(&self) -> &McpToolDescriptor {
        &self.descriptor
    }
}

/// The privacy row for an MCP transport: HTTP is B13, a local `stdio` child
/// is B14.
pub fn transport_path(transport: McpTransport) -> kernel_core::privacy::PathId {
    match transport {
        McpTransport::Http => kernel_core::privacy::PathId::B13,
        McpTransport::Stdio => kernel_core::privacy::PathId::B14,
    }
}

impl fmt::Debug for McpTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpTool")
            .field("wire_name", &self.descriptor.wire_name)
            .field("server", &self.descriptor.server)
            .field("risk", &self.risk())
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        &self.descriptor.wire_name
    }

    fn path_id(&self) -> kernel_core::privacy::PathId {
        self.path
    }

    fn schema(&self) -> Value {
        self.descriptor.schema.clone()
    }

    fn risk(&self) -> Risk {
        self.descriptor.risk()
    }

    /// The whole class, in one value:
    ///
    /// * no MCP tool can be allowed by a wildcard rule; only a rule naming
    ///   `mcp__<server>__<tool>` exactly may auto-run it. Its risk rests on the
    ///   server's own annotations (never corroborated), so a lying server that
    ///   marks `delete_everything` read-only must not ride an `allow *` rule;
    /// * every MCP result may carry owner data: the
    ///   class is declared, never inferred from the server;
    /// * MCP results are third-party content: data, never instructions;
    /// * MCP calls never run outside the sandbox dimension: they have none;
    /// * the arguments go to a third-party server: the engine screens them for
    ///   identifiers, and holds the call in a conversation that carries private
    ///   data (the arguments are a send, whatever the server says).
    fn class(&self) -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            risk_is_corroborated: false,
            output_trust: Trust::Untrusted,
            execution_mode: ExecutionMode::Sandboxed,
            returns_private_data: true,
            arguments_leave_machine: true,
            ..ToolClass::default()
        }
    }

    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        // Item 5: the arguments a server receives are built from the call's
        // grant. A call without one (a caller that skipped `gate_dispatch`)
        // fails closed instead of sending raw JSON. A stdio server with no
        // network is a local destination; the grant is minted by the engine's
        // gate either way, and this path never sends the raw `Value`.
        let refused = || ToolError::PrivacyDisabled {
            path: self.path.as_str(),
        };
        let grant = ctx.grant().ok_or_else(refused)?;
        // The grant must be this tool's own row: a grant minted for another
        // path carries another policy (mask or pass through), so running under
        // it would send arguments the caller never admitted for this server.
        // A caller that skipped `gate_dispatch` or wired the wrong row fails
        // closed here, before any argument is built or any client is called.
        if grant.path() != self.path {
            return Err(refused());
        }
        // Open mode sends the arguments as they are. Private mode: the model
        // wrote them from session tokens, so those stay (the server never gets
        // a value) and anything still in the clear is masked.
        let mut gate = match grant.policy() {
            kernel_core::privacy::GrantPolicy::Passthrough => Gate::for_passthrough(grant),
            kernel_core::privacy::GrantPolicy::Tokenised => {
                Gate::for_session_tokens(grant, ctx.session_tokens.clone().unwrap_or_default())
            }
        }
        .map_err(|_| refused())?;
        let (safe, report) = gate.value(args).map_err(|err| {
            ToolError::fetch(format!("MCP arguments refused by the privacy gate: {err}"))
        })?;
        if !report.is_empty() {
            // The report says what was (private) or would have been (open)
            // masked, logged without a value.
            tracing::debug!(
                tool = %self.descriptor.wire_name,
                report = %report,
                "MCP arguments admitted"
            );
        }
        let outcome = self
            .client
            .call_tool(&self.descriptor.remote_name, &safe, self.timeout)
            .await
            .map_err(|err| ToolError::fetch(format!("MCP call failed: {}", err.kind())))?;
        let text = outcome.untrusted_text();
        Ok(if outcome.is_error {
            ToolOutput::error(text)
        } else {
            ToolOutput::ok(text)
        })
    }
}
