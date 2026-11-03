//! The people a contact index holds, and the caps on what it keeps.

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};

use zeroize::Zeroizing;

use super::PersonId;

/// One known person. Strings are kept as the owner wrote them (names) or in
/// canonical form (addresses lower-case, phones and IBANs compact); matching
/// folds or normalises them again.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Person {
    /// Identifier within the index.
    pub id: PersonId,
    /// The display name as it was seen, if any.
    pub display_name: Option<Zeroizing<String>>,
    /// Given names, e.g. `Jean-Marc`.
    pub given: Vec<Zeroizing<String>>,
    /// Family names, e.g. `Van der Berg`, one entry per word.
    pub family: Vec<Zeroizing<String>>,
    /// Short forms known for this person, e.g. `Sasha`.
    pub nicknames: Vec<Zeroizing<String>>,
    /// E-mail addresses, lower-case.
    pub emails: Vec<Zeroizing<String>>,
    /// Phone numbers: `+` and digits when international, digits otherwise.
    pub phones: Vec<Zeroizing<String>>,
    /// IBANs, upper-case, without separators.
    pub ibans: Vec<Zeroizing<String>>,
}

impl fmt::Debug for Person {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only: a contact is personal data and must not reach a log.
        f.debug_struct("Person")
            .field("id", &self.id)
            .field(
                "names",
                &(self.given.len() + self.family.len() + self.nicknames.len()),
            )
            .field("emails", &self.emails.len())
            .field("phones", &self.phones.len())
            .field("ibans", &self.ibans.len())
            .finish()
    }
}

/// The data for one person, as passed to [`ContactIndex::add_person`](crate::contacts::ContactIndex::add_person). Its
/// strings are wiped when the draft is dropped, as the index's own are.
#[derive(Clone, Default)]
pub struct PersonDraft {
    /// The display name, if any.
    pub display_name: Option<Zeroizing<String>>,
    /// Given names.
    pub given: Vec<Zeroizing<String>>,
    /// Family names, one entry per word.
    pub family: Vec<Zeroizing<String>>,
    /// Known short forms.
    pub nicknames: Vec<Zeroizing<String>>,
    /// E-mail addresses.
    pub emails: Vec<Zeroizing<String>>,
    /// Phone numbers, in any format.
    pub phones: Vec<Zeroizing<String>>,
    /// IBANs, with or without spaces.
    pub ibans: Vec<Zeroizing<String>>,
}

impl fmt::Debug for PersonDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersonDraft")
            .field("names", &(self.given.len() + self.family.len()))
            .field("emails", &self.emails.len())
            .field("phones", &self.phones.len())
            .field("ibans", &self.ibans.len())
            .finish()
    }
}

/// Caps on what seeding reads and holds. Over one, seeding stops, what is
/// already seeded is kept, and [`ContactIndex::refused`](crate::contacts::ContactIndex::refused) counts the refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedLimits {
    /// Bytes of a text that header seeding reads; the rest is not scanned.
    pub max_text_bytes: usize,
    /// Mailboxes taken from one text (or one envelope list).
    pub max_mailboxes: usize,
    /// Name variants one person may compile to.
    pub max_variants_per_person: usize,
    /// Every compiled pattern of the index: name variants plus e-mail, phone
    /// and IBAN keys. A person that would exceed it is refused whole.
    pub max_patterns: usize,
    /// People the index may hold. Counted on every draft, whether or not it
    /// compiles a pattern (given names alone compile none by default).
    pub max_contacts: usize,
    /// Bytes of envelope entries (names and addresses together) that one call
    /// to [`ContactIndex::seed_from_envelope`](crate::contacts::ContactIndex::seed_from_envelope) reads. Over it, seeding stops.
    pub max_envelope_bytes: usize,
}

impl SeedLimits {
    /// The caps the index uses unless told otherwise.
    pub const DEFAULT: Self = Self {
        max_text_bytes: 64 * 1024,
        max_mailboxes: 500,
        max_variants_per_person: 64,
        max_patterns: 200_000,
        max_contacts: 20_000,
        max_envelope_bytes: 256 * 1024,
    };
}

impl Default for SeedLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A stored contact string used as a map key. It hashes and compares as its
/// text, so a `&str` finds it, and it is wiped when the index drops it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Key(pub(super) Zeroizing<String>);

impl Key {
    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl Borrow<str> for Key {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
