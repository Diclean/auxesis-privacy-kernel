//! Merging, identity and debug tests: one person per address or phone.

use zeroize::Zeroizing;

use super::super::{ContactIndex, PersonDraft};
use super::{draft, zs};

#[test]
fn same_address_merges_and_keeps_the_oldest_id() {
    let mut index = ContactIndex::new();
    let first = index.add_person(draft("Marie", "Dupont", &["marie@example.invalid"]));
    let second = index.add_person(PersonDraft {
        phones: zs(&["+33 1 99 00 12 34"]),
        ..draft("M.", "Dupont", &["MARIE@example.invalid"])
    });
    assert_eq!(first, second);
    assert_eq!(index.len(), 1);
    let phone_only = index.add_person(PersonDraft {
        phones: zs(&["+33 1 99 00 12 34"]),
        ..PersonDraft::default()
    });
    assert_eq!(phone_only, first);
}

#[test]
fn a_bridge_entry_merges_two_people() {
    let mut index = ContactIndex::new();
    let a = index.add_person(draft("Anna", "Lind", &["anna@example.invalid"]));
    let b = index.add_person(PersonDraft {
        phones: zs(&["0033 6 99 00 11 22"]),
        ..draft("Ben", "Lind", &[])
    });
    assert_ne!(a, b);
    let bridge = index.add_person(PersonDraft {
        phones: zs(&["0033 6 99 00 11 22"]),
        ..draft("Anna", "Lind", &["anna@example.invalid"])
    });
    assert_eq!(bridge, a);
    assert_eq!(index.len(), 1);
}

#[test]
fn empty_draft_is_refused() {
    let mut index = ContactIndex::new();
    assert_eq!(index.add_person(PersonDraft::default()), None);
    assert!(index.is_empty());
}

#[test]
fn debug_never_prints_values() {
    let mut index = ContactIndex::new();
    index.add_person(draft("Marie", "Dupont", &["marie@example.invalid"]));
    let rendered = format!("{index:?}");
    assert!(!rendered.contains("Marie"));
    assert!(!rendered.contains("example.invalid"));
}

#[test]
fn a_draft_and_an_index_debug_never_print_values() {
    let draft = PersonDraft {
        display_name: Some(Zeroizing::new("Marie Dupont".to_string())),
        given: zs(&["Marie"]),
        phones: zs(&["+33 6 12 34 56 78"]),
        ..PersonDraft::default()
    };
    let rendered = format!("{draft:?}");
    assert!(!rendered.contains("Marie") && !rendered.contains("6 12"));
    let mut index = ContactIndex::new();
    index.add_person(draft);
    let rendered = format!("{index:?} {:?}", index.people().next());
    assert!(!rendered.contains("Marie") && !rendered.contains("612"));
}
