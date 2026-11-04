//! Catalog access: wrapping, filtering, lookup and iteration.

use crate::{Declaration, ExecutionMode, Tool, ToolClassExt};

use super::tool_registry::{Entry, ToolRegistry};

impl ToolRegistry {
    /// Replace every registered tool through `f`, keeping each tool's name
    /// and both classification sets. The wrapped tool must keep its original
    /// [`Tool::name`]; a rename would silently drop the classification (the
    /// map is keyed by name).
    ///
    /// Used to wrap the whole set with an output filter (tool results are
    /// scrubbed before persistence) without re-deriving the deny-by-
    /// default trust classes.
    pub fn map_tools(&mut self, mut f: impl FnMut(Box<dyn Tool>) -> Box<dyn Tool>) {
        let tools = std::mem::take(&mut self.tools);
        for (name, entry) in tools {
            let tool = f(entry.tool);
            self.tools.insert(
                name,
                Entry {
                    tool,
                    declaration: entry.declaration,
                },
            );
        }
    }

    /// Keep only the tools `keep` accepts, and return the names it dropped.
    ///
    /// The class sets are left alone: they are keyed by name, so a dropped
    /// name matches nothing. Used by the privacy gate to drop tools that are
    /// not allowed in the current mode before the model sees them.
    pub fn retain(&mut self, mut keep: impl FnMut(&dyn Tool) -> bool) -> Vec<String> {
        let mut dropped = Vec::new();
        self.tools.retain(|name, entry| {
            let kept = keep(entry.tool.as_ref());
            if !kept {
                dropped.push(name.clone());
            }
            kept
        });
        dropped
    }

    /// Names of the registered tools that declare
    /// [`ToolClassExt::skill_only`](crate::ToolClassExt::skill_only), sorted.
    ///
    /// A **snapshot**, for display and audit. The broker's hardline skill floor
    /// does not use it: [`crate::Broker::new`] takes a live
    /// [`crate::SkillOnlyLookup`], and `ToolRegistry` implements it by reading
    /// the class of the tool registered at authorization time, so a tool
    /// registered after the broker was built is covered.
    pub fn skill_only_tools(&self) -> Vec<String> {
        self.tools
            .iter()
            .filter(|(_, entry)| entry.tool.skill_only())
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// How the tool `name` will execute, for the broker's execution-mode bar.
    ///
    /// A registered tool reports its own mode (`shell` derives it from the
    /// `[shell]` profile it was built with; everything else is `Sandboxed`).
    /// **Fail closed:** a name the registry cannot resolve is
    /// [`ExecutionMode::Unsandboxed`], so an unclassified call can never be
    /// auto-run by an `allow` rule. The engine passes this to
    /// [`crate::Broker::authorize`], which raises every unsandboxed or
    /// network-enabled call to an ask on the first call, before any taint mark
    /// exists.
    pub fn execution_mode(&self, name: &str) -> ExecutionMode {
        match self.get(name) {
            Some(tool) => tool.execution_mode(),
            None => ExecutionMode::Unsandboxed,
        }
    }

    /// Look up a tool by name.
    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|entry| entry.tool.as_ref())
    }

    /// Iterate over every registered tool, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Tool> {
        self.tools.values().map(|entry| entry.tool.as_ref())
    }

    /// Iterate over every registered tool with its declaration, sorted by name.
    pub fn iter_declared(&self) -> impl Iterator<Item = (&dyn Tool, Declaration)> {
        self.tools
            .values()
            .map(|entry| (entry.tool.as_ref(), entry.declaration))
    }

    /// Registered names, sorted.
    pub fn names(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// True when no tool is registered.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

impl std::fmt::Debug for ToolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolRegistry")
            .field("tools", &self.names())
            .finish()
    }
}
