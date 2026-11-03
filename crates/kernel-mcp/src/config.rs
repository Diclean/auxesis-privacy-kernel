//! User-configured MCP servers (`~/.auxesis/mcp.toml`).
//!
//! The file is the only place a person names an MCP server; nothing is
//! activated by default. An absent file means "no servers"; a present but
//! invalid file is a clear error the caller can log while it keeps running
//! without MCP (the daemon must never fail to boot because one server line is
//! wrong).
//!
//! # Bounds
//!
//! Every field is bounded (server count, argument count/length, agent and tool
//! name counts, total file size) and unknown keys are **refused** rather than
//! ignored, so a typo cannot silently change what is launched. A `stdio`
//! command must be an absolute path (never resolved through `PATH`, never a
//! shell string) and an `http` URL must be `https`, except on loopback where
//! the offline test server needs plain `http`.
//!
//! # Secrets
//!
//! `env` names variables only. Values live in `~/.auxesis/.env` and are read by
//! the caller at launch; nothing in this module resolves or stores them, and no
//! value can appear in this file.

//! # Layout
//!
//! The public surface is re-exported here; the implementation is split by
//! responsibility: `model` holds the config types and their read/write API,
//! `document` extracts `[[server]]` entries, `rewrite` edits the parsed
//! document in place, `server` and `confirmation` validate one server,
//! `approval` and `digest` own the keyed install-approval binding, `echo` and
//! `secrets` own secret detection and safe refusal text, and `policy` and
//! `container` own the stdio launch policy.

mod approval;
mod confirmation;
mod container;
mod digest;
mod document;
mod echo;
mod model;
mod policy;
mod rewrite;
mod secrets;
mod server;
#[cfg(test)]
mod test_util;

pub use confirmation::binary_sha256;
pub use model::{
    McpConfig, McpConfigError, McpDataClass, McpServerConfig, McpTransport, QuarantinedServer,
};
pub use policy::{evaluate_stdio_policy, stdio_risk_label, wrapper_launcher_label, StdioPolicy};
pub use secrets::looks_like_secret;
pub use server::{is_loopback_host, ServerRefusal};

/// Refuse to read an `mcp.toml` larger than this (runaway write, device file).
pub const MAX_MCP_CONFIG_BYTES: u64 = 256 * 1024;
/// Most servers the file may declare.
pub const MAX_MCP_SERVERS: usize = 32;
/// Most agents one server may name.
pub const MAX_MCP_AGENTS: usize = 64;
/// Most tool names one agent may list for one server.
pub const MAX_MCP_AGENT_TOOLS: usize = 256;
/// Hard cap on one `stdio` argument, in bytes.
pub const MAX_MCP_ARG_BYTES: usize = 4096;
/// Hard cap on an `http` URL, in bytes.
pub const MAX_MCP_URL_BYTES: usize = 2048;
/// Hard cap on an `env` variable name, in bytes.
pub const MAX_MCP_ENV_NAME_BYTES: usize = 64;
