//! Name conventions that classify a tool before it declares its class.

/// Connector tool names whose output is untrusted by convention.
///
/// `mcp__` is the MCP wire prefix, `mail_` the native mailbox
/// tools: both consume outside content. The name is trimmed and
/// ASCII-lowercased first, so casing, stray whitespace and zero-width
/// modifiers cannot smuggle a connector past the hook. This is the first
/// line of defence for a newly registered connector;
/// [`ToolRegistry::register`] and [`ToolRegistry::mark_untrusted_output`]
/// are the explicit sets, and everything unclassified fails closed anyway.
pub(super) fn untrusted_name_hook(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    name.starts_with("mcp__") || name.starts_with("mail_")
}

/// Tool names whose output is **private owner data**: mail, calendar, memory
/// and notes. Reading one marks the conversation `carries_private_data`, and
/// after that an unseen web host asks. The reads themselves stay
/// silent: they only change the egress rules.
///
/// This name hook is only a backstop for a connector whose output is private
/// by convention. The **class** flag is
/// [`ToolClassExt::returns_private_data`](crate::ToolClassExt::returns_private_data), which
/// the tool itself declares (and which the registry consults in
/// [`ToolRegistry::is_private_data`]); `read_file`, the Google and EventKit
/// reads use that flag, and the EventKit tools are also listed explicitly by
/// [`ToolRegistry::mark_private_data`] at registration. The `apple_*` prefixes
/// are the EventKit tool names; a bare `calendar_` prefix never matched them.
pub(super) fn private_data_name_hook(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    [
        "mail_",
        "calendar_",
        "apple_calendar_",
        "apple_reminders_",
        "memory_",
        "notes_",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}
