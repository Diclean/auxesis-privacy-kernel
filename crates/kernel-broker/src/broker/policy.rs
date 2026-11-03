//! Rule language: execution modes, actions, ordered rules and the skill floor.

use serde::{Deserialize, Serialize};

/// Wildcard that matches any agent or tool in a [`Rule`].
pub const ANY: &str = "*";

/// Cap on an approver-substituted draft (the `edit` decision), in bytes.
///
/// Identical to the 4 KiB tool-preview cap the API already applies
/// (`the daemon's api::wire::MAX_TOOL_ARGS_BYTES`): an edit can shrink a call but
/// never grow it past what the approval card could display.
pub const MAX_EDITED_ARGUMENTS_BYTES: usize = 4 * 1024;

/// How a tool call will execute for authorization purposes.
///
/// The `shell` tool is the only tool with an execution dimension, so
/// [`ToolRegistry`] reports one of the non-default variants for exactly its two
/// dangerous configurations: `Unsandboxed` for the explicit
/// `[shell] allow_unsandboxed` escape hatch, `Networked` for a sandbox that
/// allows **all** sockets (`[shell] network = true`). The broker treats both as
/// an unconditional bar: `allow` rules and persisted "always allow" answers
/// never apply to them. Unknown provenance fails closed:
/// [`crate::ToolRegistry::execution_mode`] answers `Unsandboxed` for a name it
/// cannot classify, and the default of this enum is `Sandboxed` only so callers
/// that already hold a concrete tool profile (and non-shell tools) can use it.
///
/// [`ToolRegistry`]: crate::ToolRegistry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    /// The call runs in its sandbox (or has no sandbox dimension at all).
    #[default]
    Sandboxed,
    /// The call will run without its sandbox: every ask is forced and no
    /// persistent allow may be written for it.
    Unsandboxed,
    /// The call runs sandboxed, but its sandbox has every socket open
    /// (`[shell] network = true`): every ask is forced and no persistent allow
    /// may be written for it, exactly as for [`ExecutionMode::Unsandboxed`].
    Networked,
}

impl ExecutionMode {
    /// True for [`ExecutionMode::Unsandboxed`].
    pub fn is_unsandboxed(self) -> bool {
        matches!(self, ExecutionMode::Unsandboxed)
    }

    /// True for [`ExecutionMode::Networked`].
    pub fn is_networked(self) -> bool {
        matches!(self, ExecutionMode::Networked)
    }

    /// True when no `allow` rule may auto-run the call: it either escapes its
    /// sandbox or has all sockets open. Deny rules and taint are unaffected.
    pub fn forces_ask(self) -> bool {
        !matches!(self, ExecutionMode::Sandboxed)
    }

    /// Lowercase label used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionMode::Sandboxed => "sandboxed",
            ExecutionMode::Unsandboxed => "unsandboxed",
            ExecutionMode::Networked => "networked",
        }
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a matching rule says to do with a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Run without asking.
    Allow,
    /// Ask the [`crate::Approver`] callback.
    Ask,
    /// Refuse; the approver is not consulted.
    Deny,
}

impl Action {
    /// Lowercase label used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Ask => "ask",
            Action::Deny => "deny",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One ordered permission rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Agent this rule applies to, or [`ANY`]. Read from the legacy `dot` key too.
    #[serde(alias = "dot")]
    pub agent: String,
    /// Tool this rule applies to, or [`ANY`].
    pub tool: String,
    /// What to do when the rule matches.
    pub action: Action,
}

impl Rule {
    /// Build a rule.
    pub fn new(agent: impl Into<String>, tool: impl Into<String>, action: Action) -> Self {
        Self {
            agent: agent.into(),
            tool: tool.into(),
            action,
        }
    }

    /// True when this rule covers the given agent and tool.
    pub fn matches(&self, agent: &str, tool: &str) -> bool {
        (self.agent == ANY || self.agent == agent) && (self.tool == ANY || self.tool == tool)
    }
}

/// The fixed denial reason for a skill-only tool requested outside a skill.
/// Callers and tests match this exact string.
pub const SKILL_ONLY_REASON: &str = "skill-only tool";

/// The skill context of one broker call.
///
/// The broker receives it as an `Option<SkillRef>`: `Some` means the call runs
/// inside `skill__<name>`, `None` means the model asked for the tool directly.
/// A skill-only tool is denied without it, and asks at minimum with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillRef {
    /// Skill name (the file stem).
    pub name: String,
    /// Skill version, as declared in the skill file.
    pub version: String,
    /// Content hash of the skill file, so a trace can name the exact bytes the
    /// approval was granted against.
    pub hash: String,
}

/// The rule that decides `tool` for `agent`, with its index: the last match
/// wins, and a wildcard `allow` never covers a tool that requires an explicit
/// rule. [`crate::Broker::authorize`] decides with it; an approver that must agree
/// with the broker on which rule applies calls it too.
pub fn matching_rule<'a>(
    rules: &'a [Rule],
    agent: &str,
    tool: &str,
    requires_explicit_rule: bool,
) -> Option<(usize, &'a Rule)> {
    rules.iter().enumerate().rfind(|(_, rule)| {
        rule.matches(agent, tool)
            && !(requires_explicit_rule && rule.tool == ANY && rule.action == Action::Allow)
    })
}
