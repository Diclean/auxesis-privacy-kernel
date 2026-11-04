//! The hard caps and the fixed markers a descriptor is built from.

use crate::tools::{MAX_TOOL_DESCRIPTION_BYTES, MAX_TOOL_SCHEMA_BYTES};

/// Hard cap on a descriptor description, in bytes.
pub const MAX_DESCRIPTION_BYTES: usize = MAX_TOOL_DESCRIPTION_BYTES;
/// Hard cap on a remote tool name, in bytes (parse-time cap).
pub const MAX_NAME_BYTES: usize = 48;
/// Hard cap on a serialised input schema, in bytes (parse-time cap).
pub const MAX_SCHEMA_BYTES: usize = MAX_TOOL_SCHEMA_BYTES;

/// Deepest schema nesting the sanitiser walks before it stops.
pub(super) const MAX_SCHEMA_DEPTH: usize = 64;
/// Byte budget handed to the shared sanitiser when the caller wants cleaning
/// without the head/tail truncation wrapper (the caller applies its own cap).
pub(super) const SANITIZE_BUDGET: usize = 1024 * 1024;
/// Explicit marker left when a description is hard-capped.
pub const TRUNCATION_MARKER: &str = "\n[truncated]";
/// Neutral marker substituted for a line that forges Auxesis' provenance tag.
///
/// A hostile server may try to hide a copy of [`crate::tools::UNTRUSTED_MCP_TAG`]
/// behind case, spacing, homoglyph or line-break variants. The whole forged
/// line is replaced by this fixed, clearly-neutral text rather than scrubbed to
/// nothing, so the model still sees that *something* was removed and cannot
/// mistake the absence for an ordinary empty line.
pub const FORGED_PROVENANCE_MARKER: &str = "[removed: forged provenance line]";
/// The wrapper-marker prefixes Auxesis may add to untrusted text, in one place.
///
/// A peer-supplied copy of any of these is neutralised **before** Auxesis wraps
/// its own text, so a hostile description can never pass itself off as a
/// trusted truncation notice or as Auxesis' own provenance line.
/// `[truncated:` is the head/tail marker emitted by the shared `kernel-broker`
/// sanitiser; [`crate::tools::UNTRUSTED_MCP_TAG`] is the provenance line stamped
/// on every MCP server string, and a server that copies it must not be able to
/// forge a second, indistinguishable tag.
pub const WRAPPER_MARKERS: [&str; 3] = [
    "[truncated]",
    "[truncated:",
    crate::tools::UNTRUSTED_MCP_TAG,
];
