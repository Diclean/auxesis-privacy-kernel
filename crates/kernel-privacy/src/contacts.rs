//! A local contact index: the people the owner knows, and a recogniser that
//! masks every mention of them (slice 1f).
//!
//! Detectors that read a model miss what a model cannot know: a bare first
//! name, a lower-case name in a quoted reply, a name in a `ps:` line. The
//! index knows the people in advance, from mail headers and `<Name> <address>`
//! pairs, so [`ContactRecognizer`] masks every variant of each of them
//! deterministically: full name in either order, given or family name alone,
//! initials, hyphen and apostrophe forms, the local part of an address,
//! nicknames, declined and affixed forms (Russian cases, Hungarian suffixes,
//! Arabic prefixes, French elision), and every format of an address, a phone
//! number and an IBAN.
//!
//! The index holds personal data. It lives in memory on this machine, is never
//! sent to a cloud model, and is never written in clear: a persistent
//! [`ContactStore`] must be the encrypted local store (see that trait). Its
//! strings are kept in [`Zeroizing`](zeroize::Zeroizing) buffers, so they are wiped when dropped.
//!
//! The recogniser is linear in the text plus the number of matches: the name
//! variants compile into one Aho-Corasick automaton, and every identifier is a
//! key in a map. Seeding from mail is capped (see [`SeedLimits`]).

// The submodules are private on purpose: every type below is re-exported at
// this path, so `crate::contacts::…` is exactly what it was before the split,
// and no new public path appears.
mod index;
mod person;
mod recognizer;
mod store;

pub(crate) mod fold;
mod header;
mod identifiers;
pub(crate) mod inflect;
pub(crate) mod stopwords;
mod variants;

#[cfg(test)]
mod tests;

/// Values one draft may hold in each list. Over it the first are kept and the
/// rest are refused, so a draft costs bounded work.
const MAX_DRAFT_VALUES: usize = 32;
/// Bytes one draft value may hold. A longer value is refused: no name, address,
/// number or IBAN is that long.
const MAX_VALUE_BYTES: usize = 256;
/// Bytes of text that the recogniser scans at once. Longer text is scanned in
/// windows, cut at a line or word break, so its working memory stays bounded.
const WINDOW_BYTES: usize = 1 << 20;
/// Bytes that consecutive windows share, so a match across a cut is whole in
/// one of them. Longer than any name, address, number or IBAN the matcher reads.
const WINDOW_OVERLAP: usize = 4 << 10;

/// Identifier of a person within one [`ContactIndex`]. Stable while the index
/// lives. Every span of one person carries it, so the anonymizer can give all
/// variants of that person the same token.
///
/// TODO(slice 1f): `Anonymizer` keys its tokens by kind and value, so the spans
/// of one person still get one token per spelling. Reading [`Span::person_id`](crate::span::Span::person_id)
/// there would unify them; that edit belongs to `anonymize.rs`, owned by
/// another open PR.
pub type PersonId = u32;

/// Confidence of a contact hit. A known person is named exactly, so the score is
/// high; it stays below `1.0` so a checksum-valid deterministic rule still
/// takes precedence on overlap.
pub const CONTACT_SCORE: f32 = 0.95;

/// Recogniser name echoed in [`Span::recognizer`](crate::span::Span::recognizer).
pub const CONTACT_RECOGNIZER: &str = "contacts";

pub use index::ContactIndex;
pub use person::{Person, PersonDraft, SeedLimits};
pub use recognizer::ContactRecognizer;
pub use store::{ContactStore, ContactStoreError, MemoryContactStore};

pub(crate) use index::Insert;
pub(crate) use person::Key;
