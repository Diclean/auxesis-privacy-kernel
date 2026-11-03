//! The deny-by-default output classes and their explicit markers.

use crate::ToolClassExt;

use super::hooks::{private_data_name_hook, untrusted_name_hook};
use super::tool_registry::ToolRegistry;

impl ToolRegistry {
    /// Mark `name` as a tool whose output must taint the conversation.
    pub fn mark_untrusted_output(&mut self, name: impl Into<String>) {
        self.untrusted_outputs.insert(name.into());
    }

    /// Mark `name` as read-only by construction: it observes local state and
    /// produces no side effects beyond its own result. Only this explicit
    /// class keeps an `allow` rule while the conversation is tainted; unknown
    /// names are consequential (fail closed).
    pub fn mark_read_only(&mut self, name: impl Into<String>) {
        self.read_only.insert(name.into());
    }

    /// Mark `name` as a tool whose output is private owner data (mail,
    /// calendar, memory, notes). Reading one flips the conversation's egress
    /// rule: after it, an unseen web host asks instead of running silently.
    pub fn mark_private_data(&mut self, name: impl Into<String>) {
        self.private_data.insert(name.into());
    }

    /// Keep `name` registered but out of what the model is offered: the broker
    /// refuses every call of it for this agent. A call still reaches the
    /// broker, which refuses it and records the decision.
    pub fn mark_unoffered(&mut self, name: impl Into<String>) {
        self.unoffered.insert(name.into());
    }

    /// True when `name` is kept out of what the model is offered.
    pub fn is_unoffered(&self, name: &str) -> bool {
        self.unoffered.contains(name)
    }

    /// True when `name`'s output is private owner data. The explicit set, the
    /// mail/calendar/memory/notes name hook, and the tool's own
    /// [`ToolClassExt::returns_private_data`](crate::ToolClassExt::returns_private_data) class flag
    /// all count; an unregistered or
    /// differently-named tool is not private data (the egress rule stays a
    /// deliberate, named class). Class-based so `read_file` — and any future
    /// file-content tool — is caught without a name prefix.
    pub fn is_private_data(&self, name: &str) -> bool {
        if self.private_data.contains(name) || private_data_name_hook(name) {
            return true;
        }
        self.get(name)
            .is_some_and(|tool| tool.returns_private_data())
    }

    /// True when content produced by `name` must be treated as untrusted.
    ///
    /// Deny-by-default: the explicit untrusted set and the connector name
    /// hook win; a registered tool is otherwise trusted only when it
    /// **explicitly** declares [`crate::Trust::Trusted`]. Anything else —
    /// including a name that is not registered at all — is untrusted, so a
    /// new tool cannot leak outside content into the conversation by simply
    /// existing.
    pub fn is_untrusted_output(&self, name: &str) -> bool {
        if self.untrusted_outputs.contains(name) || untrusted_name_hook(name) {
            return true;
        }
        match self.get(name) {
            Some(tool) => tool.output_trust().is_untrusted(),
            // Unknown provenance: fail closed.
            None => true,
        }
    }

    /// True when `name` is an explicitly declared read-only tool. Unknown
    /// names are consequential (fail closed).
    pub fn is_read_only(&self, name: &str) -> bool {
        self.read_only.contains(name)
    }
}
