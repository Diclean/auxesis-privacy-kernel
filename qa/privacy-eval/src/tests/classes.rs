//! Tests for the per-class table and the README snapshot.

use kernel_core::privacy::{GrantPolicy, PrivacyMode};
use kernel_privacy::EntityKind;

use crate::classes::*;
use crate::tier_c::tier_c_class;
use crate::tiers::is_name;

/// One mode's table for the snapshot: `plain` no-PII texts, `over` of them
/// over-masked, and `(class, hidden, n)` per class.
fn mode(kept: &[&'static str], rows: &[(&'static str, u64, u64)]) -> ModeTable {
    ModeTable {
        classes: rows.iter().map(|r| (r.0, [r.1, r.2])).collect(),
        kept: kept.iter().copied().collect(),
        ..ModeTable::default()
    }
}

/// Every kind lands on a printed row, and Open keeps that row only when no
/// kind in it is prohibited. `business ID` exists so the non-prohibited
/// SIREN/SIRET/VAT kinds cannot inflate the prohibited `ID` row.
#[test]
fn every_kind_maps_to_a_row_with_the_right_prohibited_status() {
    let kept = kept_by_design(GrantPolicy::Passthrough);
    for kind in EntityKind::ALL {
        let class = report_class(kind);
        assert_eq!(class.is_none(), is_name(kind), "{kind:?}");
        // Postal addresses never leave the Mac (owner rule 10-21) but are
        // not one of the Tier C 100 % classes, so they keep their own row.
        assert_eq!(
            tier_c_class(kind).is_some(),
            kind.is_prohibited() && kind != EntityKind::Address,
            "{kind:?}"
        );
        let Some(class) = class else { continue };
        assert!(CLASS_ORDER.contains(&class), "{class} has no row");
        let prohibited = EntityKind::ALL
            .iter()
            .any(|k| report_class(*k) == Some(class) && k.is_prohibited());
        assert_eq!(kept.contains(class), !prohibited, "{class}");
    }
    assert!(kept_by_design(GrantPolicy::Tokenised).is_empty());
    assert!(kept.contains("e-mail") && kept.contains("business ID"));
    assert!(!kept.contains("ID") && !kept.contains("health"));
    // Religion, union, orientation and ethnicity are not prohibited: Open
    // keeps them, so they must not dilute the health row.
    assert!(kept.contains("special category"));
}

/// The README block is a contract: a column cannot be renamed, dropped or
/// reordered without this failing.
#[test]
fn the_class_table_matches_its_snapshot() {
    let rows = [("e-mail", 6, 7), ("IBAN", 42, 42), ("ID", 59, 64)];
    let open = [("e-mail", 7, 7), ("IBAN", 42, 42), ("ID", 55, 64)];
    let p = mode(&[], &rows);
    let kept = ["e-mail", "phone", "business ID", "address", "date of birth"];
    let o = mode(&kept, &open);
    assert_eq!(
        class_table(&p, &o),
        concat!(
            "| class | n | Private | Open |\n",
            "| --- | ---: | ---: | ---: |\n",
            "| e-mail | 7 | 85.71 % | n/a (kept by design) |\n",
            "| phone | n/a (n = 0) | n/a (n = 0) | n/a (kept by design) |\n",
            "| IBAN | 42 | 100.00 % | 100.00 % |\n",
            "| card | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
            "| ID | 64 | 92.18 % | 85.93 % |\n",
            "| business ID | n/a (n = 0) | n/a (n = 0) | n/a (kept by design) |\n",
            "| secret | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
            "| health | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
            "| special category | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
            "| address | n/a (n = 0) | n/a (n = 0) | n/a (kept by design) |\n",
            "| date of birth | n/a (n = 0) | n/a (n = 0) | n/a (kept by design) |\n",
            "| IP | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
            "| URL | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
            "over-mask on the no-PII texts: Private n/a (n = 0), Open n/a (n = 0)\n",
        )
    );
}

/// End to end through a real gate on real cases: an IBAN is hidden in both
/// modes, and the e-mail beside it reads `n/a (kept by design)` in Open.
#[test]
fn a_real_gate_hides_an_iban_and_keeps_the_email_in_open() {
    let json = r#"{"id":"p1","lang":"en","text":"IBAN FR7630006000011234567890189, mail a@b.org",
        "spans":[{"type":"IBAN","start":5,"end":34},{"type":"EMAIL","start":41,"end":48}]}"#;
    let cases = vec![serde_json::from_str(json).expect("case parses")];
    let open = measure_mode(&cases, PrivacyMode::Open, "Open").expect("open grant");
    let private = measure_mode(&cases, PrivacyMode::Private, "Private").expect("private grant");
    let table = class_table(&private, &open);
    assert!(
        table.contains("| IBAN | 1 | 100.00 % | 100.00 % |"),
        "{table}"
    );
    assert!(
        table.contains("| e-mail | 1 | 100.00 % | n/a (kept by design) |"),
        "{table}"
    );
}
