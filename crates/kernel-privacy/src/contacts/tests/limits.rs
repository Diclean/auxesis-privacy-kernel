//! Cap and bounded-work tests: drafts, seeding, patterns and windows.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::recognizer::Recognizer;

use super::super::variants::variants_for;
use super::super::{ContactIndex, PersonDraft, SeedLimits};
use super::{first_names_masked, masked_kinds, zs};

#[test]
fn many_contacts_with_one_name_emit_one_span_per_mention() {
    let mut index = first_names_masked();
    for _ in 0..10_000 {
        index.add_person(PersonDraft {
            given: zs(&["Marie"]),
            ..PersonDraft::default()
        });
    }
    assert_eq!(index.len(), 10_000);
    let recognizer = index.recognizer().expect("build");
    // "Marie" and its Hungarian suffix forms: a handful of patterns, each
    // shared by all 10,000 people.
    assert!(recognizer.pattern_count() <= 10);
    assert!(recognizer.ambiguous_patterns() >= 1);

    let mut text = String::new();
    while text.len() < 100_000 {
        text.push_str("Marie a dit bonjour à Paul. ");
    }
    let mentions = text.matches("Marie").count();
    let started = Instant::now();
    let spans = recognizer.analyze(&text);
    let elapsed = started.elapsed();
    assert_eq!(spans.len(), mentions);
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

#[test]
fn seeding_stops_at_the_byte_cap_and_counts_it() {
    let mut index = ContactIndex::new();
    let filler = "é".repeat(SeedLimits::DEFAULT.max_text_bytes / 2 + 10);
    let late = format!("{filler}\nFrom: Marie Dupont <marie.dupont83@example.invalid>");
    assert_eq!(index.seed_from_text(&late), 0);
    assert!(index.is_empty());
    assert_eq!(index.refused(), 1);

    let early = format!(
        "From: Marie Dupont <marie.dupont83@example.invalid>\n{}",
        "é".repeat(40_000)
    );
    assert!(index.seed_from_text(&early) >= 1);
    assert_eq!(index.len(), 1);
    assert_eq!(index.refused(), 2);
}

#[test]
fn seeding_stops_at_the_mailbox_cap() {
    let limits = SeedLimits {
        max_mailboxes: 5,
        ..SeedLimits::DEFAULT
    };
    let mut index = ContactIndex::with_limits(limits);
    let names = [
        "Alba", "Bruno", "Cora", "Dario", "Elin", "Fabio", "Greta", "Hugo",
    ];
    let text: String = names
        .iter()
        .map(|name| format!("Cc: {name} <{name}.x@example.invalid>\n"))
        .collect();
    index.seed_from_text(&text);
    assert_eq!(index.len(), 5);
    assert!(index.refused() >= 1);
}

#[test]
fn a_person_keeps_at_most_the_variant_cap() {
    let limits = SeedLimits {
        max_variants_per_person: 8,
        ..SeedLimits::DEFAULT
    };
    let mut index = ContactIndex::with_limits(limits);
    for name in ["Alba", "Bruno", "Cora", "Dario", "Elin", "Fabio"] {
        index.add_person(PersonDraft {
            given: zs(&[name]),
            family: zs(&["Lind"]),
            emails: zs(&["same@example.invalid"]),
            ..PersonDraft::default()
        });
    }
    assert!(index.refused() >= 1);
    for person in index.people() {
        assert!(variants_for(person, index.mask_first_names()).len() <= 8);
    }
}

#[test]
fn the_index_keeps_at_most_the_pattern_cap() {
    let limits = SeedLimits {
        max_patterns: 12,
        ..SeedLimits::DEFAULT
    };
    let mut index = ContactIndex::with_limits(limits);
    for name in ["Alba", "Bruno", "Cora", "Dario", "Elin", "Fabio"] {
        index.add_person(PersonDraft {
            given: zs(&[name]),
            family: zs(&["Lind"]),
            ..PersonDraft::default()
        });
    }
    assert!(index.pattern_count() <= 12);
    assert!(index.refused() >= 1);
    assert!(index.len() < 6);
}

#[test]
fn seeding_never_panics_on_odd_input() {
    let mut index = ContactIndex::new();
    index.seed_from_text(&"<".repeat(100_000));
    index.seed_from_text(&"=?".repeat(50_000));
    index.seed_from_text(&format!("{}From: a <b@c.d>", "é".repeat(40_000)));
    index.seed_from_text(&"\u{1F600}".repeat(20_000));
}

#[test]
fn a_draft_without_patterns_still_counts_against_the_contact_cap() {
    let limits = SeedLimits {
        max_contacts: 2,
        ..SeedLimits::DEFAULT
    };
    let mut index = ContactIndex::with_limits(limits);
    let alba = index.add_person(PersonDraft {
        given: zs(&["Alba"]),
        emails: zs(&["alba@example.invalid"]),
        ..PersonDraft::default()
    });
    for name in ["Bruno", "Cora", "Dario"] {
        index.add_person(PersonDraft {
            given: zs(&[name]),
            ..PersonDraft::default()
        });
    }
    assert_eq!(index.len(), 2);
    assert_eq!(index.refused(), 2);
    // A draft that merges into a known person adds nobody, so it is kept.
    let merged = index.add_person(PersonDraft {
        given: zs(&["Alba"]),
        emails: zs(&["ALBA@example.invalid"]),
        ..PersonDraft::default()
    });
    assert_eq!(merged, alba);
    assert_eq!(index.len(), 2);
}

#[test]
fn a_header_input_keeps_the_mailbox_cap_and_the_byte_cap() {
    let limits = SeedLimits {
        max_mailboxes: 1,
        ..SeedLimits::DEFAULT
    };
    let mut index = ContactIndex::with_limits(limits);
    index.add_from_header(
        "Marie Dupont <marie@example.invalid>, Paul Martin <paul@example.invalid>",
        "",
    );
    assert_eq!(index.len(), 1);
    assert!(masked_kinds(&index, "paul@example.invalid").is_empty());
    assert!(index.refused() >= 1);

    let mut index = ContactIndex::new();
    let padding = " ".repeat(SeedLimits::DEFAULT.max_text_bytes);
    let display =
        format!("Marie Dupont <marie@example.invalid>,{padding}Paul Martin <paul@example.invalid>");
    index.add_from_header(&display, "");
    assert_eq!(index.len(), 1);
    assert_eq!(index.refused(), 1);
    assert!(masked_kinds(&index, "paul@example.invalid").is_empty());
}

#[test]
fn envelope_seeding_stops_at_the_total_byte_cap() {
    let names = [
        "Alba", "Bruno", "Cora", "Dario", "Elin", "Fabio", "Greta", "Hugo",
    ];
    let entries: Vec<(String, String)> = names
        .iter()
        .map(|name| {
            (
                format!("{name} Lind"),
                format!("{}@example.invalid", name.to_lowercase()),
            )
        })
        .collect();
    let envelope: Vec<(&str, &str)> = entries
        .iter()
        .map(|(name, address)| (name.as_str(), address.as_str()))
        .collect();
    let limits = SeedLimits {
        max_envelope_bytes: 100,
        ..SeedLimits::DEFAULT
    };
    let mut index = ContactIndex::with_limits(limits);
    assert_eq!(index.seed_from_envelope(&envelope), 3);
    assert_eq!(index.len(), 3);
    assert!(index.refused() >= 1);

    let mut index = ContactIndex::new();
    assert_eq!(index.seed_from_envelope(&envelope), names.len());
    assert_eq!(index.refused(), 0);
}

#[test]
fn a_draft_is_bounded_per_list_and_per_value() {
    let mut index = ContactIndex::new();
    let phones: Vec<String> = (0..100).map(|n| format!("+33 6 00 00 {n:04}")).collect();
    let phone_refs: Vec<&str> = phones.iter().map(String::as_str).collect();
    let long = "M".repeat(300);
    let added = index.add_person(PersonDraft {
        display_name: Some(Zeroizing::new("D".repeat(10_000))),
        given: zs(&["Marie", long.as_str()]),
        family: zs(&["Dupont"]),
        phones: zs(&phone_refs),
        ..PersonDraft::default()
    });
    assert!(added.is_some());
    let person = index.person(added.expect("id")).expect("person");
    assert_eq!(person.phones.len(), 32);
    assert!(person.display_name.is_none());
    assert_eq!(person.given.len(), 1);
    assert!(index.refused() >= 3);
}

#[test]
fn repeated_identifiers_do_not_multiply_patterns() {
    let mut index = ContactIndex::new();
    for _ in 0..1_000 {
        index.add_person(PersonDraft {
            given: zs(&["Marie"]),
            family: zs(&["Dupont"]),
            emails: zs(&["marie@example.invalid", "MARIE@example.invalid"]),
            phones: zs(&["+33 6 12 34 56 78", "0033612345678"]),
            ..PersonDraft::default()
        });
    }
    assert_eq!(index.len(), 1);
    assert_eq!(index.refused(), 0);
    assert!(index.recognizer().expect("build").pattern_count() <= 20);
}
