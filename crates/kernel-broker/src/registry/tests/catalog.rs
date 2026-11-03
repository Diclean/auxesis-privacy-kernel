//! Catalog access: execution mode, lookup, iteration and `Debug`.

use crate::{ExecutionMode, Tool, ToolRegistry};

use super::fixtures::Dummy;

#[test]
fn an_unknown_tool_name_fails_closed_to_unsandboxed() {
    let registry = ToolRegistry::new();
    assert_eq!(
        registry.execution_mode("never_heard_of_it"),
        ExecutionMode::Unsandboxed
    );
}

#[test]
fn unknown_names_are_none() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(Dummy("known")));
    assert!(registry.get("rm_rf").is_none());
    assert!(registry.get("known").is_some());
    assert!(!registry.is_empty());
    assert!(ToolRegistry::new().is_empty());
}

#[test]
fn iter_yields_every_tool_sorted() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(Dummy("beta")));
    registry.register(Box::new(Dummy("alpha")));
    let names: Vec<_> = registry.iter().map(Tool::name).collect();
    assert_eq!(names, vec!["alpha", "beta"]);
}

#[test]
fn debug_lists_names() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(Dummy("alpha")));
    registry.register(Box::new(Dummy("beta")));
    let rendered = format!("{registry:?}");
    assert!(rendered.contains("alpha"));
    assert!(rendered.contains("beta"));
}
