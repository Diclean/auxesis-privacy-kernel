//! The live skill floor, including the shared-registry lock.

use std::sync::RwLock;

use crate::{SkillOnlyLookup, ToolClassExt};

use super::tool_registry::ToolRegistry;

/// The live skill floor of a registry: the class of the tool registered under
/// `tool` **at the moment the broker asks**, never a set copied at build time.
impl SkillOnlyLookup for ToolRegistry {
    fn is_skill_only(&self, tool: &str) -> bool {
        self.get(tool).is_some_and(|tool| tool.skill_only())
    }
}

/// The live skill floor of a **shared** registry.
///
/// [`ToolRegistry::register`] takes `&mut self`, so a broker built from an
/// `Arc<ToolRegistry>` can only ever see the tools registered before it. Hold
/// the registry in an `Arc<RwLock<ToolRegistry>>` and hand that to
/// [`crate::Broker::new`]: the read happens at authorization time, so a tool
/// registered after the broker was built is still covered.
///
/// A poisoned lock **raises** the floor instead of lowering it: an unreadable
/// registry answers `true`, so the call is denied without a skill context (or
/// held to an ask inside one). Fail closed.
impl SkillOnlyLookup for RwLock<ToolRegistry> {
    fn is_skill_only(&self, tool: &str) -> bool {
        match self.read() {
            Ok(registry) => registry.is_skill_only(tool),
            Err(_) => true,
        }
    }
}
