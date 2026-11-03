//! Output trust, read-only and private-data classification.

use crate::ToolRegistry;

use super::fixtures::{Dummy, PrivateDummy, TrustedDummy, UntrustedDummy};

#[test]
fn untrusted_output_names_are_explicit_and_extensible() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(TrustedDummy("read_file")));
    registry.register(Box::new(TrustedDummy("write_file")));
    registry.mark_untrusted_output("http_fetch");
    registry.mark_untrusted_output("shell");
    assert!(registry.is_untrusted_output("http_fetch"));
    assert!(registry.is_untrusted_output("shell"));
    assert!(!registry.is_untrusted_output("read_file"));
    assert!(!registry.is_untrusted_output("write_file"));
    let mut registry = ToolRegistry::new();
    registry.mark_untrusted_output("custom_reader");
    assert!(registry.is_untrusted_output("custom_reader"));
    registry.register(Box::new(Dummy("mcp__fakeserv__gmail_send")));
    registry.register(Box::new(Dummy("mail_send")));
    assert!(registry.is_untrusted_output("mcp__fakeserv__gmail_send"));
    assert!(registry.is_untrusted_output("mail_send"));
    registry.register(Box::new(UntrustedDummy));
    assert!(registry.is_untrusted_output("custom_reader"));
}

#[test]
fn unclassified_tool_output_fails_closed() {
    // A registered tool that never declares its trust is untrusted…
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(Dummy("mystery_tool")));
    assert!(registry.is_untrusted_output("mystery_tool"));
    // …and so is a name nobody classified or even registered.
    assert!(registry.is_untrusted_output("never_heard_of_it"));
    let registry = ToolRegistry::with_defaults();
    assert!(registry.is_untrusted_output("unknown_tool"));
}

#[test]
fn the_connector_name_hook_normalizes_case_and_whitespace() {
    // A future connector that declares itself trusted must not slip past
    // the name hook: casing and stray whitespace are normalized before
    // the prefix check.
    for name in [
        "MCP__fakeserv__gmail",
        "Mail_Read",
        " mail_read",
        "MAIL_READ",
        "mail_read\u{200b}",
    ] {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(TrustedDummy(name)));
        assert!(registry.is_untrusted_output(name), "{name:?}");
    }
    // An ordinary trusted name is unaffected.
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(TrustedDummy("read_notes")));
    assert!(!registry.is_untrusted_output("read_notes"));
}

#[test]
fn only_explicitly_declared_read_only_tools_are_exempt() {
    let registry = ToolRegistry::with_defaults();
    assert!(registry.is_read_only("read_file"));
    for name in ["write_file", "shell", "http_fetch", "unclassified"] {
        assert!(!registry.is_read_only(name), "{name}");
    }

    let mut registry = ToolRegistry::new();
    registry.mark_read_only("custom_reader");
    assert!(registry.is_read_only("custom_reader"));
    assert!(!registry.is_read_only("custom_writer"));
}

#[test]
fn private_data_class_is_named_and_testable() {
    // The class is class-based: a tool that declares the flag is private
    // data even without a name prefix.
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(PrivateDummy("workspace_bytes")));
    assert!(registry.is_private_data("workspace_bytes"));
    // The hook recognizes the future mail/calendar/memory/notes tools,
    // case- and whitespace-insensitively.
    for name in [
        "mail_read",
        "Mail_List",
        " calendar_read",
        "memory_search",
        "notes_read",
        "apple_calendar_list_events",
        "apple_reminders_list",
    ] {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(TrustedDummy(name)));
        assert!(registry.is_private_data(name), "{name:?}");
    }
    // An explicit marker works too, and an unrelated name stays out.
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(TrustedDummy("inbox_peek")));
    assert!(!registry.is_private_data("inbox_peek"));
    registry.mark_private_data("inbox_peek");
    assert!(registry.is_private_data("inbox_peek"));
    assert!(!registry.is_private_data("read_file"));
}

#[test]
fn an_undeclared_tool_counts_as_private_data() {
    // Fail toward masking: a tool that never declares
    // the class is private, so its result flips the egress rule.
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(Dummy("brand_new_tool")));
    assert!(registry.is_private_data("brand_new_tool"));
}

#[test]
fn the_private_data_class_is_a_tool_flag_not_only_a_name_prefix() {
    // A name with no private prefix is still private once its tool
    // declares the class flag — the engine hook is class-based.
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(PrivateDummy("workspace_bytes")));
    assert!(registry.is_private_data("workspace_bytes"));
    // The class travels with the tool, not the name: replacing the tool
    // drops the class, as class-based means.
    registry.register(Box::new(TrustedDummy("workspace_bytes")));
    assert!(!registry.is_private_data("workspace_bytes"));
    // An unregistered name is never private data.
    assert!(!registry.is_private_data("never_heard_of_it"));
}
