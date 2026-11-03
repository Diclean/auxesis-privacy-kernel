//! The model labels and their entity kinds.

use crate::span::EntityKind;

use super::super::{label_kind, GLINER_PII_LABELS};

#[test]
fn native_labels_map_to_kinds() {
    assert_eq!(label_kind("person"), Some(EntityKind::Person));
    assert_eq!(label_kind("organization"), Some(EntityKind::Organization));
    assert_eq!(label_kind("address"), Some(EntityKind::Address));
    assert_eq!(label_kind("phone_number"), Some(EntityKind::Phone));
    assert_eq!(label_kind("email"), Some(EntityKind::Email));
    assert_eq!(label_kind("iban"), Some(EntityKind::Iban));
    assert_eq!(label_kind("payment_card"), Some(EntityKind::CreditCard));
    assert_eq!(label_kind("passport_number"), Some(EntityKind::PassportMrz));
    assert_eq!(
        label_kind("national_id_number"),
        Some(EntityKind::NationalId)
    );
    assert_eq!(label_kind("date_of_birth"), Some(EntityKind::DateOfBirth));
    assert_eq!(label_kind("health condition"), Some(EntityKind::Health));
    assert_eq!(label_kind("religion"), Some(EntityKind::Religion));
    // The GLiNER v1 names are gone with the v1 model.
    assert_eq!(label_kind("IBAN"), None);
    assert_eq!(label_kind("phone number"), None);
    // Every default label is recognised.
    assert!(GLINER_PII_LABELS
        .iter()
        .all(|label| label_kind(label).is_some()));
}
