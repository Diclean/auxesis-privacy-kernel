//! Tests for the privacy gate and mounting of MCP tools.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kernel_broker::{Tool, ToolCtx, ToolError, ToolRegistry};

use crate::descriptor::McpToolDescriptor;
use crate::tools::RemoteTool;

use super::super::*;

/// A client that is never called: the privacy test only checks the registry.
struct NoClient;

#[async_trait]
impl crate::client::McpClient for NoClient {
    async fn initialize(&self) -> Result<crate::client::ServerInfo, crate::McpError> {
        unreachable!("the privacy test never talks to the server")
    }
    async fn list_tools(
        &self,
        _cursor: Option<&str>,
    ) -> Result<crate::tools::ToolPage, crate::McpError> {
        unreachable!("the privacy test never talks to the server")
    }
    async fn call_tool(
        &self,
        _name: &str,
        _args: &kernel_privacy::SafeValue,
        _timeout: Duration,
    ) -> Result<crate::tools::CallOutcome, crate::McpError> {
        unreachable!("the privacy test never talks to the server")
    }
}

fn crm_tool(path: kernel_core::privacy::PathId) -> (String, McpTool) {
    let remote: RemoteTool = serde_json::from_value(serde_json::json!({
        "name": "lookup_contact",
        "inputSchema": {"type": "object"}
    }))
    .expect("remote tool");
    let wire = crate::naming::wire_name("crm", "lookup_contact");
    let descriptor =
        McpToolDescriptor::from_remote("crm", "", wire.clone(), &remote).expect("descriptor");
    let tool = McpTool::new(descriptor, Arc::new(NoClient), Duration::from_secs(5), path);
    (wire, tool)
}

#[test]
fn a_sensitive_http_server_tool_stays_mounted_in_private_mode() {
    // The server's transport decides the row (B13 for HTTP). TOK-7: it is
    // Covered, so the tool stays registered and the model is offered it.
    let path = transport_path(McpTransport::Http);
    let (wire, tool) = crm_tool(path);
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(tool));

    let dropped =
        kernel_broker::retain_mountable(&mut registry, kernel_core::privacy::PrivacyMode::Private);
    assert!(dropped.is_empty());
    assert!(registry.get(&wire).is_some());
}

#[test]
fn the_same_tool_stays_registered_in_open_mode() {
    let (wire, tool) = crm_tool(transport_path(McpTransport::Stdio));
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(tool));

    assert!(kernel_broker::retain_mountable(
        &mut registry,
        kernel_core::privacy::PrivacyMode::Open
    )
    .is_empty());
    assert!(registry.get(&wire).is_some());
}

#[tokio::test]
async fn a_grant_for_another_path_never_reaches_the_mcp_server() {
    // Seal P3-2: the tool runs only under its own row's grant. A grant
    // minted for a different path — a caller that skipped `gate_dispatch`,
    // or a wiring bug that swapped two servers' rows — is refused before
    // the arguments are built, so no payload reaches the server under a
    // policy nobody admitted for it. `NoClient` panics if it is called,
    // which is what proves the refusal happened first.
    let path = transport_path(McpTransport::Http);
    let (_wire, tool) = crm_tool(path);
    let grant = kernel_core::privacy::admit_call(
        kernel_core::privacy::PathId::C9,
        kernel_core::privacy::PrivacyMode::Open,
        kernel_core::privacy::Destination::LocalDisplay,
    )
    .expect("C9 is covered and allowed in open mode");
    assert_ne!(grant.path(), path, "the probe must use a foreign grant");
    let ctx = ToolCtx::new("main", std::env::temp_dir()).with_grant(grant);
    let args = serde_json::json!({});

    match tool.run(&args, &ctx).await {
        Err(ToolError::PrivacyDisabled { path: refused }) => {
            assert_eq!(refused, path.as_str())
        }
        other => panic!("expected privacy_disabled, got {other:?}"),
    }
}
