//! The registry type and the entry it keeps per tool.

use std::collections::{BTreeMap, BTreeSet};

use kernel_core::WebConfig;

use crate::{Declaration, ShellSandbox, Tool};

/// One registered tool and the declaration its advertised text came with.
pub(super) struct Entry {
    pub(super) tool: Box<dyn Tool>,
    pub(super) declaration: Declaration,
}

/// Registered tools, keyed by [`Tool::name`].
///
/// Lookup is deterministic (BTreeMap order), which keeps provider tool lists
/// and tests stable.
///
/// The registry also carries the **class** of each tool, which decides what
/// its output does to the conversation:
///
/// - **Output trust is deny-by-default.** A tool is trusted only when it
///   explicitly declares
///   [`ToolClassExt::output_trust`](crate::ToolClassExt::output_trust) as trusted.
///   Shells, fetchers,
///   connectors, mail tools, and any name nobody classified produce
///   untrusted output that taints the conversation.
/// - **Read-only is an explicit class.** Only tools marked with
///   [`ToolRegistry::mark_read_only`] keep their rule while the conversation
///   is tainted; [`Risk`](crate::Risk) is informational and never grants the
///   exemption (a side-effecting tool that under-reports its risk still
///   asks).
///
/// Both classifications fail closed: unclassified names are untrusted and
/// consequential.
#[derive(Default)]
pub struct ToolRegistry {
    pub(super) tools: BTreeMap<String, Entry>,
    pub(super) untrusted_outputs: BTreeSet<String>,
    pub(super) read_only: BTreeSet<String>,
    /// Tools whose output is private owner data (mail, calendar, memory,
    /// notes). Reading one flips the conversation's egress rule. The explicit
    /// set is a manual override; the tool's own
    /// [`ToolClassExt::returns_private_data`](crate::ToolClassExt::returns_private_data) flag is
    /// the class declaration.
    pub(super) private_data: BTreeSet<String>,
    /// Tools kept out of what the model is offered (see
    /// [`ToolRegistry::mark_unoffered`]).
    pub(super) unoffered: BTreeSet<String>,
    /// The sandbox profile the registry built `shell` with, when created
    /// through [`ToolRegistry::with_shell`]. Metadata only: the tool itself
    /// owns the profile it runs with.
    pub(super) shell_sandbox: Option<ShellSandbox>,
    /// The `[web]` section the registry built `http_fetch` with. Metadata for
    /// the engine's egress policy; the tool itself holds its own gate.
    pub(super) web: WebConfig,
}
