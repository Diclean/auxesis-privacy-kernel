//! The GLiNER2-PII labels, their score floors and their entity kinds.

use crate::span::EntityKind;

/// The GLiNER2-PII labels the runner sends, in the order of the exported graph's
/// fields. Native labels come first; `health condition` and `religion` are
/// zero-shot. The same list is in `scripts/gliner2-parity.py`.
pub const GLINER_PII_LABELS: [&str; 12] = [
    "person",
    "address",
    "phone_number",
    "email",
    "iban",
    "payment_card",
    "passport_number",
    "national_id_number",
    "date_of_birth",
    "organization",
    "health condition",
    "religion",
];

/// Default score floor for every label without its own entry in
/// [`LABEL_THRESHOLDS`]. An internal EN bench picked 0.5 for the native labels.
pub const DEFAULT_THRESHOLD: f32 = 0.5;

/// Score floor for the labels only the model can see: names, organisations and
/// addresses. Private mode tokenises and never
/// refuses, so an extra mask is cheap while a missed name leaks. On the EN
/// messy-email split, name recall rises from 0.85 to 0.91 (bare first names
/// 0.68 to 0.82) for a precision drop from 0.83 to 0.79; clean EN recall is
/// unchanged at 0.98. The pattern-backed labels keep the default.
pub const NAME_THRESHOLD: f32 = 0.15;

/// Per-label score floors. `health condition` is zero-shot and recalls its
/// five EN health spans at 0.3 to 0.4 (0.8 at 0.5), so it runs at 0.4.
pub const LABEL_THRESHOLDS: [(&str, f32); 4] = [
    ("person", NAME_THRESHOLD),
    ("organization", NAME_THRESHOLD),
    ("address", NAME_THRESHOLD),
    ("health condition", 0.4),
];

/// The graph's `max_width` (`config.json` of the checkpoint): spans run at most
/// this many words.
pub const DEFAULT_MAX_WIDTH: usize = 8;

/// Token window used for a long text (benchmark: 300 tokens).
pub const DEFAULT_CHUNK_TOKENS: usize = 300;

/// Token overlap between two windows (benchmark: 50 tokens).
pub const DEFAULT_CHUNK_OVERLAP: usize = 50;

/// Map a GLiNER2-PII label to the crate's [`EntityKind`].
///
/// `payment_card` is a card number, `passport_number` is masked as an
/// unverified passport, and `national_id_number` as the generic national
/// identifier (fail toward masking). An unknown label is ignored.
pub fn label_kind(label: &str) -> Option<EntityKind> {
    Some(match label {
        "person" => EntityKind::Person,
        "organization" => EntityKind::Organization,
        "address" => EntityKind::Address,
        "phone_number" => EntityKind::Phone,
        "email" => EntityKind::Email,
        "iban" => EntityKind::Iban,
        "payment_card" => EntityKind::CreditCard,
        "passport_number" => EntityKind::PassportMrz,
        "national_id_number" => EntityKind::NationalId,
        "date_of_birth" => EntityKind::DateOfBirth,
        "health condition" => EntityKind::Health,
        "religion" => EntityKind::Religion,
        _ => return None,
    })
}
