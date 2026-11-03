//! Fixtures shared by the runtime tests.

use super::super::*;

pub(super) fn stdio_server(id: &str, command: &str) -> McpServerConfig {
    McpServerConfig {
        id: id.to_owned(),
        catalog_id: None,
        data_class: crate::McpDataClass::Sensitive,
        stdio_confirmed: false,
        stdio_confirmation: None,
        approval: None,
        network: false,
        transport: McpTransport::Stdio,
        url: None,
        command: Some(command.to_owned()),
        args: Vec::new(),
        env: Vec::new(),
        enabled: true,
        agents: Default::default(),
    }
}
