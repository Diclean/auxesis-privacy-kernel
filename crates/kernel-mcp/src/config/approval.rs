//! The keyed M6-2 install-approval digest that binds one approval to one
//! exact server preview.

use std::path::Path;

use super::digest::{hash_count, hash_field, hash_flag};
use super::{binary_sha256, McpDataClass, McpServerConfig, McpTransport, UNAVAILABLE_SHA256};

/// Bind one install approval to one exact server preview and a daemon secret.
///
/// Covers every install-relevant field, never the mutable lifecycle fields
/// (`enabled`, `approval`, `stdio_confirmed`): the preview hash must stay the
/// same before and after the approve write. `catalog_pin` is required for a
/// catalog server, so a lost or unverifiable entry invalidates the approval.
/// A non-catalog `stdio` server also binds the program's SHA-256: `binary_sha`
/// is the hash the caller previewed, or `None` to read the file now. A program
/// that cannot be **read** cannot be hashed: the digest is then refused
/// outright (no binding at all) rather than binding the
/// [`UNAVAILABLE_SHA256`] marker as if it were a hash.
pub(super) fn approval_digest(
    secret: &[u8],
    server: &McpServerConfig,
    catalog_pin: Option<&str>,
    binary_sha: Option<&str>,
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
    // Only a non-catalog stdio install names a program file: a catalog entry's
    // pin already covers its published SHA, and an http server has none. The
    // preview passes the hash it showed; a caller with no previewed hash reads
    // the file now, so a swap changes the digest and refuses the old approval.
    if server.transport == McpTransport::Stdio && server.catalog_id.is_none() {
        let sha = match binary_sha {
            Some(sha) => sha.to_ascii_lowercase(),
            None => binary_sha256(
                server
                    .command
                    .as_deref()
                    .map(Path::new)
                    .unwrap_or_else(|| Path::new("")),
            ),
        };
        // A program that cannot be read cannot be hashed, and the marker is
        // not a hash: it never enters a digest. No binding, so the install is
        // never approved (fail closed).
        if sha.eq_ignore_ascii_case(UNAVAILABLE_SHA256) {
            return None;
        }
        hash_field(&mut hasher, b"binary-sha256:", &sha);
    }
    Some(hasher.finalize().to_hex().to_string())
}
