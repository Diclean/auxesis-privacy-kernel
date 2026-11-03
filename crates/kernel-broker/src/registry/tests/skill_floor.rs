//! The live skill floor read from a registry, shared or not.

use std::sync::RwLock;

use crate::{SkillOnlyLookup, ToolRegistry};

use super::fixtures::Classed;

#[test]
fn the_skill_floor_is_read_live_from_the_registry() {
    // Seal P2-2(d): the registry answers the broker's `SkillOnlyLookup` at
    // authorization time, so a tool registered after the broker was built
    // is covered — and an unregistered name is never skill-only.
    let registry = ToolRegistry::new();
    assert!(!SkillOnlyLookup::is_skill_only(&registry, "gmail_send"));
    assert!(!SkillOnlyLookup::is_skill_only(&registry, "not_registered"));

    let shared = RwLock::new(ToolRegistry::new());
    assert!(!SkillOnlyLookup::is_skill_only(&shared, "gmail_send"));
    shared
        .write()
        .unwrap()
        .register(Box::new(Classed("gmail_send")));
    assert!(SkillOnlyLookup::is_skill_only(&shared, "gmail_send"));
    assert!(!SkillOnlyLookup::is_skill_only(&shared, "other"));
}
