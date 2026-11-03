//! Constructors and the registration paths onto the tool map.

use kernel_core::WebConfig;

use crate::{Declaration, NativeDecl, NativeTool, ShellSandbox, Tool};

use super::hooks::{private_data_name_hook, untrusted_name_hook};
use super::tool_registry::{Entry, ToolRegistry};

impl ToolRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry containing the default tool set (M1 files + shell, M2 web).
    ///
    /// `shell` and `http_fetch` are explicitly untrusted: their results are
    /// whatever the outside world produced. `read_file`/`write_file` declare
    /// themselves trusted in their own implementations; `read_file` is the
    /// one read-only tool, so it keeps its configured rule while a
    /// conversation is tainted (taint applies at the workspace level in the
    /// engine, not per file). `read_file` also declares
    /// [`ToolClassExt::returns_private_data`](crate::ToolClassExt::returns_private_data), so a
    /// workspace file read flips the
    /// conversation's egress rule; `http_fetch` declares
    /// [`ToolClassExt::performs_web_egress`](crate::ToolClassExt::performs_web_egress), so the
    /// engine gates it (and any future
    /// fetch tool) by class.
    ///
    /// The shell runs with [`ShellSandbox::default`]: sandboxed, no network,
    /// fail closed. Production runners build the registry from the loaded
    /// config instead (the app's engine's `registry_from_config`); this constructor
    /// is the safe default for tests and callers without a config.
    pub fn with_defaults() -> Self {
        Self::with_shell(ShellSandbox::default())
    }

    /// Like [`ToolRegistry::with_defaults`], with `shell` built from an
    /// explicit sandbox profile (the `[shell]` config section).
    ///
    /// The profile is passed through untouched, so the fail-closed rules stay
    /// in the tool: an unsandboxed run is only reachable with the double
    /// opt-in (`sandbox = false` + `allow_unsandboxed = true`, or an
    /// unavailable sandbox plus `allow_unsandboxed = true`), and `shell` stays
    /// in the untrusted-output class, so every run write-ahead taints the
    /// conversation and the workspace.
    pub fn with_shell(sandbox: ShellSandbox) -> Self {
        Self::with_shell_web(sandbox, WebConfig::default())
    }

    /// Like [`ToolRegistry::with_shell`], with `http_fetch` built from the
    /// `[web]` config section. This is the production entry point: the web
    /// gate must be the configured one, never the default.
    pub fn with_shell_web(sandbox: ShellSandbox, web: WebConfig) -> Self {
        let mut registry = Self::new();
        // The built-in tool implementations live in the app runtime; the
        // kernel registry ships the classes and metadata the engine reads.
        registry.mark_untrusted_output("http_fetch");
        registry.mark_untrusted_output("shell");
        registry.mark_read_only("read_file");
        registry.shell_sandbox = Some(sandbox);
        registry.web = web;
        registry
    }

    /// The `[web]` settings `http_fetch` was built with.
    pub fn web_config(&self) -> &WebConfig {
        &self.web
    }

    /// The sandbox profile `shell` was built with, when this registry was
    /// created through [`ToolRegistry::with_shell`] (and therefore
    /// [`ToolRegistry::with_defaults`]). `None` for an empty registry or one
    /// assembled tool by tool.
    pub fn shell_sandbox(&self) -> Option<&ShellSandbox> {
        self.shell_sandbox.as_ref()
    }

    /// Add a tool whose advertised text is built at runtime (an MCP server's
    /// declaration, a plugin). The prompt gates its name, description and
    /// schema before the model sees them. Returns any previous tool
    /// registered under the same name.
    pub fn register(&mut self, tool: Box<dyn Tool>) -> Option<Box<dyn Tool>> {
        self.insert(tool, Declaration::Dynamic)
    }

    /// Add an application-authored tool whose name, description and schema are
    /// `'static`. The prompt trusts that text without a scan. Returns any
    /// previous tool registered under the same name.
    ///
    /// The declared name must equal [`Tool::name`]. A tool that disagrees with
    /// itself is registered on the gated path instead, so it never advertises
    /// text it did not declare.
    pub fn register_native(&mut self, tool: Box<dyn NativeTool>) -> Option<Box<dyn Tool>> {
        let decl = NativeDecl {
            name: tool.native_name(),
            description: tool.native_description(),
            schema: tool.native_schema(),
        };
        let declaration = if tool.name() == decl.name {
            Declaration::Native(decl)
        } else {
            Declaration::Dynamic
        };
        self.insert(tool, declaration)
    }

    fn insert(&mut self, tool: Box<dyn Tool>, declaration: Declaration) -> Option<Box<dyn Tool>> {
        let name = tool.name().to_string();
        if untrusted_name_hook(&name) {
            self.untrusted_outputs.insert(name.clone());
        }
        if private_data_name_hook(&name) {
            self.private_data.insert(name.clone());
        }
        self.tools
            .insert(name, Entry { tool, declaration })
            .map(|previous| previous.tool)
    }
}
