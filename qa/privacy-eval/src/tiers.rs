//! Sensitivity tiers, coverage and the per-tier tallies the table scores.

use kernel_privacy::eval::GoldSpan;
use kernel_privacy::{EntityKind, Span};

use crate::table::hundredths;

/// Whether a kind belongs to Tier C: [`EntityKind::is_prohibited`] itself, not
/// a list mirrored here -- the five classes the owner requires hidden.
fn tier_c_kind(kind: EntityKind) -> bool {
    kind.is_prohibited()
}

/// Sensitivity tier of a gold span.
///
/// The C/H split follows the kernel's own per-kind classification:
/// [`EntityKind::mask_priority`] (`crates/kernel-privacy/src/span.rs:184`)
/// puts every deterministic recogniser's kind below `9` and every model-emitted
/// kind at `9`. The C+9 (GDPR Art. 9) flag and the N (never leaves) tier come
/// from the sensitivity taxonomy: health and religion are special-category,
/// and no detected [`EntityKind`] is a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tier {
    /// CRITICAL: the prohibited classes, [`tier_c_kind`].
    C,
    /// C+9: special-category data (Art. 9); model-only today.
    C9,
    /// HIGH: the model-emitted kinds that are not names.
    H,
    /// NEVER: secrets, such as API keys and tokens (K10).
    N,
    /// A person or organisation name: not a scored class.
    Name,
}

pub(crate) fn tier_of(kind: EntityKind) -> Tier {
    match kind {
        EntityKind::Health
        | EntityKind::Religion
        | EntityKind::SexualOrientation
        | EntityKind::Union
        | EntityKind::Ethnicity => Tier::C9,
        EntityKind::Secret => Tier::N,
        EntityKind::Person | EntityKind::Organization => Tier::Name,
        EntityKind::Address | EntityKind::DateOfBirth => Tier::H,
        _ if kind.mask_priority() < 9 => Tier::C,
        _ => Tier::H,
    }
}

/// Whether a kind is a name: a person or an organisation.
pub(crate) fn is_name(kind: EntityKind) -> bool {
    tier_of(kind) == Tier::Name
}

/// The tier a gold span is scored under, or `None` when its kind is not: a
/// name never is, and neither is a kind that is not prohibited, which keeps
/// e-mail, phone, address and date of birth in the scored recall but off
/// every bar that is not theirs.
pub(crate) fn scored_tier(kind: EntityKind) -> Option<Tier> {
    match tier_of(kind) {
        Tier::Name => None,
        Tier::C | Tier::C9 | Tier::N => tier_c_kind(kind).then_some(Tier::C),
        tier => Some(tier),
    }
}

/// Whether one predicted region covers every byte of a gold span.
///
/// The registry returns the merged, non-overlapping regions the anonymiser
/// masks, so a token covers a gold span exactly when one region contains it.
pub(crate) fn covered(predicted: &[Span], gold: &GoldSpan) -> bool {
    predicted
        .iter()
        .any(|span| span.start <= gold.start && span.end >= gold.end)
}

/// One tier's held-out tally.
#[derive(Default)]
pub(crate) struct TierTally {
    pub(crate) caught: u64,
    pub(crate) total: u64,
}

impl TierTally {
    pub(crate) fn add(&mut self, hit: bool) {
        self.total += 1;
        if hit {
            self.caught += 1;
        }
    }

    /// The rate in hundredths of a percent, truncated (never rounded up), or
    /// `None` when nothing was measured.
    pub(crate) fn hundredths(&self) -> Option<u64> {
        hundredths(self.caught, self.total)
    }
}

/// The Standard-pipeline measurement over every case.
#[derive(Default)]
pub(crate) struct StandardMeasure {
    pub(crate) c: TierTally,
    pub(crate) h: TierTally,
    /// Every scored class, names excluded, and the names themselves.
    pub(crate) scored: TierTally,
    pub(crate) names: u64,
    pub(crate) trap_fp: u64,
    pub(crate) p95_ms: u64,
}

/// The Deep-pipeline measurement over every case.
#[derive(Default)]
pub(crate) struct DeepMeasure {
    pub(crate) c: TierTally,
    pub(crate) h: TierTally,
    pub(crate) scored: TierTally,
    pub(crate) names: u64,
    pub(crate) trap_fp: u64,
    pub(crate) p95_ms: u64,
    pub(crate) peak_mb: Option<u64>,
}

/// Fold one case's gold spans into the three tallies a measure carries: tier
/// C, tier H, the scored recall. A name is skipped in both directions -- not a
/// miss, not an over-mask, no bar; every other kind enters the scored recall.
pub(crate) fn tally_case(
    (c, h, scored): (&mut TierTally, &mut TierTally, &mut TierTally),
    gold: &[GoldSpan],
    predicted: &[Span],
) {
    for span in gold {
        if is_name(span.kind) {
            continue;
        }
        let hit = covered(predicted, span);
        scored.add(hit);
        match scored_tier(span.kind) {
            Some(Tier::C) => c.add(hit),
            Some(Tier::H) => h.add(hit),
            _ => {}
        }
    }
}
