//! Registration, replacement and the declarations a tool carries.

use crate::{Declaration, ToolRegistry};

use super::fixtures::{Declared, Dummy};

#[test]
fn registering_twice_replaces() {
    let mut registry = ToolRegistry::new();
    assert!(registry.register(Box::new(Dummy("one"))).is_none());

    let replaced = registry.register(Box::new(Dummy("one")));
    assert!(replaced.is_some());
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.get("one").unwrap().name(), "one");
}

#[test]
fn a_native_registration_keeps_its_declaration() {
    let mut registry = ToolRegistry::new();
    registry.register_native(Box::new(Declared {
        name: "declared",
        declared_name: "declared",
    }));
    registry.register(Box::new(Dummy("runtime")));

    let declarations: Vec<(&str, bool)> = registry
        .iter_declared()
        .map(|(tool, declaration)| (tool.name(), matches!(declaration, Declaration::Native(_))))
        .collect();
    assert_eq!(declarations, vec![("declared", true), ("runtime", false)]);
}

#[test]
fn a_native_tool_whose_name_disagrees_with_its_declaration_is_dynamic() {
    let mut registry = ToolRegistry::new();
    registry.register_native(Box::new(Declared {
        name: "other",
        declared_name: "declared",
    }));

    let (_, declaration) = registry.iter_declared().next().unwrap();
    assert!(matches!(declaration, Declaration::Dynamic));
    assert!(registry.get("other").is_some());
    assert!(registry.get("declared").is_none());
}

#[test]
fn map_tools_keeps_each_declaration() {
    let mut registry = ToolRegistry::new();
    registry.register_native(Box::new(Declared {
        name: "declared",
        declared_name: "declared",
    }));
    registry.map_tools(|tool| tool);

    let (_, declaration) = registry.iter_declared().next().unwrap();
    assert!(matches!(declaration, Declaration::Native(_)));
}
