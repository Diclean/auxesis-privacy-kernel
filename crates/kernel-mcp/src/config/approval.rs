//! The keyed M6-2 install-approval digest that binds one approval to one
//! exact server preview.

use super::digest::{hash_count, hash_field, hash_flag};
use super::{McpDataClass, McpServerConfig};

/// Bind one install approval to one exact server preview and a daemon secret.
///
/// Covers every install-relevant field, never the mutable lifecycle fields
/// (`enabled`, `approval`, `stdio_confirmed`): the preview hash must stay the
/// same before and after the approve write. `catalog_pin` is required for a
/// catalog server, so a lost or unverifiable entry invalidates the approval.
pub(super) fn approval_digest(
    secret: &[u8],
    server: &McpServerConfig,
    catalog_pin: Option<&str>,
) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    let pin = match (server.catalog_id.as_deref(), catalog_pin) {
        (Some(_), Some(pin)) => pin,
        (Some(_), None) => return None,
        (None, _) => "",
    };
    let mut hasher = blake3::Hasher::new_keyed(blake3::hash(secret).as_bytes());
    // v2: every field carries a tag and a length/count, so no two shapes can
    // serialise to the same byte stream (v1 joined args then env with no
    // boundary, so `args=["X"], env=[]` and `args=[], env=["X"]` collided).
    hasher.update(b"mcp-approval-v2\0");
    hash_field(&mut hasher, b"id:", &server.id);
    hash_field(
        &mut hasher,
        b"catalog:",
        server.catalog_id.as_deref().unwrap_or(""),
    );
    hash_field(&mut hasher, b"pin:", pin);
    hash_field(&mut hasher, b"transport:", server.transport.as_str());
    hash_field(&mut hasher, b"url:", server.url.as_deref().unwrap_or(""));
    hash_field(
        &mut hasher,
        b"command:",
        server.command.as_deref().unwrap_or(""),
    );
    hash_count(&mut hasher, b"args:", server.args.len());
    for arg in &server.args {
        hash_field(&mut hasher, b"arg:", arg);
    }
    let mut names: Vec<&str> = server.env.iter().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    hash_count(&mut hasher, b"env:", names.len());
    for name in names {
        hash_field(&mut hasher, b"env-name:", name);
    }
    hash_flag(&mut hasher, b"network:", server.network);
    hash_field(
        &mut hasher,
        b"class:",
        match server.data_class {
            McpDataClass::Public => "public",
            McpDataClass::Sensitive => "sensitive",
        },
    );
    hash_count(&mut hasher, b"agents:", server.agents.len());
    for (agent, tools) in &server.agents {
        hash_field(&mut hasher, b"agent:", agent);
        hash_count(&mut hasher, b"agent-tools:", tools.len());
        for tool in tools {
            hash_field(&mut hasher, b"tool:", tool);
        }
    }
    Some(hasher.finalize().to_hex().to_string())
}
