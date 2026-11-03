//! The contact index: adding, merging, capping and normalising people.

use std::collections::HashMap;
use std::fmt;

use aho_corasick::BuildError;
use zeroize::Zeroizing;

use super::fold::{lower_nfkc, plain_address};
use super::variants::variants_for;
use super::{
    header, identifiers, ContactRecognizer, Key, Person, PersonDraft, PersonId, SeedLimits,
    MAX_DRAFT_VALUES, MAX_VALUE_BYTES,
};

/// The known people, reachable by e-mail address and by phone number.
///
/// Two entries that share an address or a phone number are the same person:
/// [`ContactIndex::add_person`] merges them into the oldest one.
#[derive(Clone)]
pub struct ContactIndex {
    /// One slot per person ever added; a slot is `None` once merged away.
    people: Vec<Option<Person>>,
    by_email: HashMap<Key, PersonId>,
    by_phone: HashMap<Key, PersonId>,
    pub(super) limits: SeedLimits,
    /// Whether given names alone (a first name, a nickname, a spelling) are
    /// masked. Off by default: a bare first name is common, and masking it
    /// misfires. Fixed at construction, since the patterns depend on it.
    pub(super) mask_first_names: bool,
    /// The live people; kept in step with every change.
    contacts: usize,
    /// Compiled patterns of the live people; kept in step with every change.
    patterns: usize,
    /// Entries and text tails that a cap refused.
    pub(super) refused: usize,
}

impl Default for ContactIndex {
    fn default() -> Self {
        Self::with_limits(SeedLimits::DEFAULT)
    }
}

impl fmt::Debug for ContactIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactIndex")
            .field("people", &self.len())
            .finish()
    }
}

/// The outcome of inserting one draft.
pub(crate) enum Insert {
    /// The draft is in the index under this person.
    Added(PersonId),
    /// The draft has no usable address, phone, IBAN or name.
    Unusable,
    /// A cap refused the draft; nothing changed.
    Capped,
}

impl Insert {
    fn added(self) -> Option<PersonId> {
        match self {
            Insert::Added(id) => Some(id),
            Insert::Unusable | Insert::Capped => None,
        }
    }
}

impl ContactIndex {
    /// An empty index with the default [`SeedLimits`].
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty index with the given caps. Tests use small caps; the app uses
    /// [`SeedLimits::DEFAULT`]. First names are not masked.
    pub fn with_limits(limits: SeedLimits) -> Self {
        Self::with_options(limits, false)
    }

    /// An empty index with the given caps and the given first-name option.
    ///
    /// With `mask_first_names` set, a given name alone (`Jules`, `jules`, a
    /// nickname such as `Alex`, a declined or affixed form of a first name) is
    /// a variant too. Off by default, a first name alone is not masked; full
    /// names, family names, `J. Martin`, initials with the family name, e-mail
    /// addresses and every other identifier are masked either way.
    pub fn with_options(limits: SeedLimits, mask_first_names: bool) -> Self {
        Self {
            people: Vec::new(),
            by_email: HashMap::new(),
            by_phone: HashMap::new(),
            limits,
            mask_first_names,
            contacts: 0,
            patterns: 0,
            refused: 0,
        }
    }

    /// Whether given names alone are masked (see [`ContactIndex::with_options`]).
    pub fn mask_first_names(&self) -> bool {
        self.mask_first_names
    }

    /// The number of known people.
    pub fn len(&self) -> usize {
        self.contacts
    }

    /// Whether the index knows nobody.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every known person, in the order they were first added.
    pub fn people(&self) -> impl Iterator<Item = &Person> {
        self.people.iter().flatten()
    }

    /// The person with identifier `id`, if still known.
    pub fn person(&self, id: PersonId) -> Option<&Person> {
        self.people.get(id as usize)?.as_ref()
    }

    /// How many entries and text tails a cap has refused since the index was
    /// made. Zero means nothing was dropped.
    pub fn refused(&self) -> usize {
        self.refused
    }

    /// The number of patterns the recogniser would compile for this index: an
    /// upper bound, since equal names of different people share one pattern.
    pub fn pattern_count(&self) -> usize {
        self.patterns
    }

    /// Add one person, or merge it into the person who already has one of its
    /// e-mail addresses or phone numbers. Returns the identifier of the person
    /// the data ended up in, or `None` when the draft has no usable key or name,
    /// or a cap refused it (see [`ContactIndex::refused`]).
    pub fn add_person(&mut self, draft: PersonDraft) -> Option<PersonId> {
        self.insert(draft).added()
    }

    /// Add one person from a mail header.
    ///
    /// `display_name` is the name as written (RFC 2047 encoded words, quotes and
    /// `Last, First` order are understood), and `address` the e-mail address. If
    /// `address` is empty and `display_name` holds whole mailboxes, such as
    /// `Marie Dupont <marie.dupont83@example.invalid>`, each one is added.
    /// Returns the identifier of the last person added or merged.
    pub fn add_from_header(&mut self, display_name: &str, address: &str) -> Option<PersonId> {
        // The byte cap applies to the whole input, however many mailboxes it holds.
        let display_name = self.clip(display_name);
        let address = self.clip(address);
        if address.trim().is_empty() && display_name.contains('@') {
            let mailboxes = header::split_mailboxes(display_name);
            return self.add_mailboxes(&mailboxes).1;
        }
        self.add_mailbox(display_name, address).added()
    }

    /// Seed from the envelopes a mail sync returns: `(display name, address)`
    /// pairs. Returns how many entries were added or merged. At most
    /// [`SeedLimits::max_mailboxes`] entries are read, and at most
    /// [`SeedLimits::max_envelope_bytes`] bytes of them in all: the caps span
    /// the whole call, not each entry.
    pub fn seed_from_envelope(&mut self, envelope: &[(&str, &str)]) -> usize {
        let budget = self.limits.max_mailboxes;
        if envelope.len() > budget {
            self.refused += 1;
        }
        let mut touched = 0;
        let mut bytes = 0usize;
        for (name, address) in envelope.iter().take(budget) {
            bytes = bytes
                .saturating_add(name.len())
                .saturating_add(address.len());
            if bytes > self.limits.max_envelope_bytes {
                self.refused += 1;
                break;
            }
            let before = self.refused;
            if self.add_from_header(name, address).is_some() {
                touched += 1;
            }
            if self.refused > before {
                break;
            }
        }
        touched
    }

    /// Merge every person of `other` into this index. The variants follow this
    /// index's first-name option, not `other`'s.
    pub fn merge(&mut self, other: &ContactIndex) {
        for person in other.people() {
            self.add_person(PersonDraft {
                display_name: person.display_name.clone(),
                given: person.given.clone(),
                family: person.family.clone(),
                nicknames: person.nicknames.clone(),
                emails: person.emails.clone(),
                phones: person.phones.clone(),
                ibans: person.ibans.clone(),
            });
        }
    }

    /// Compile the recogniser for the current contents of the index.
    pub fn recognizer(&self) -> Result<ContactRecognizer, BuildError> {
        ContactRecognizer::new(self)
    }

    /// Add or merge one draft, unless a cap refuses the result. A refused draft
    /// changes nothing.
    pub(crate) fn insert(&mut self, mut draft: PersonDraft) -> Insert {
        bound_draft(&mut draft, &mut self.refused);
        let emails: Vec<Zeroizing<String>> = draft
            .emails
            .iter()
            .filter_map(|raw| normalize_email(raw))
            .map(Zeroizing::new)
            .collect();
        let phones: Vec<Zeroizing<String>> = draft
            .phones
            .iter()
            .filter_map(|raw| identifiers::normalize_phone(raw))
            .map(Zeroizing::new)
            .collect();
        let ibans: Vec<Zeroizing<String>> = draft
            .ibans
            .iter()
            .filter_map(|raw| identifiers::normalize_iban(raw))
            .map(Zeroizing::new)
            .collect();
        let has_name = draft
            .given
            .iter()
            .chain(&draft.family)
            .chain(&draft.nicknames)
            .any(|name| !name.trim().is_empty());
        if emails.is_empty() && phones.is_empty() && ibans.is_empty() && !has_name {
            return Insert::Unusable;
        }

        let mut hits: Vec<PersonId> = emails
            .iter()
            .filter_map(|email| self.by_email.get(email.as_str()).copied())
            .chain(
                phones
                    .iter()
                    .filter_map(|phone| self.by_phone.get(phone.as_str()).copied()),
            )
            .collect();
        hits.sort_unstable();
        hits.dedup();
        let survivor = match hits.first() {
            Some(&id) => id,
            None => match PersonId::try_from(self.people.len()) {
                Ok(id) => id,
                Err(_) => return Insert::Unusable,
            },
        };

        // Merge into a fresh copy first, so that a cap can refuse the whole draft.
        let mut merged = Person {
            id: survivor,
            ..Person::default()
        };
        let mut before = 0;
        for &id in &hits {
            if let Some(person) = self.person(id) {
                before += counts(person, self.mask_first_names).1;
                merge_into(&mut merged, person);
            }
        }
        if merged.display_name.is_none() {
            merged.display_name = draft
                .display_name
                .map(|name| Zeroizing::new(name.trim().to_string()))
                .filter(|name| !name.is_empty());
        }
        extend_unique(&mut merged.given, draft.given);
        extend_unique(&mut merged.family, draft.family);
        extend_unique(&mut merged.nicknames, draft.nicknames);
        extend_unique(&mut merged.emails, emails);
        extend_unique(&mut merged.phones, phones);
        extend_unique(&mut merged.ibans, ibans);

        // Merging k people into one leaves k - 1 fewer; a new person adds one.
        let contacts = (self.contacts + 1).saturating_sub(hits.len());
        let (variants, after) = counts(&merged, self.mask_first_names);
        let patterns = self.patterns.saturating_sub(before) + after;
        if variants > self.limits.max_variants_per_person
            || patterns > self.limits.max_patterns
            || contacts > self.limits.max_contacts
        {
            self.refused += 1;
            return Insert::Capped;
        }

        for &other in hits.iter().skip(1) {
            if let Some(slot) = self.people.get_mut(other as usize) {
                *slot = None;
            }
        }
        for email in &merged.emails {
            self.by_email.insert(Key(email.clone()), survivor);
        }
        for phone in &merged.phones {
            self.by_phone.insert(Key(phone.clone()), survivor);
        }
        let slot = survivor as usize;
        if slot < self.people.len() {
            self.people[slot] = Some(merged);
        } else {
            self.people.push(Some(merged));
        }
        self.patterns = patterns;
        self.contacts = contacts;
        Insert::Added(survivor)
    }

    /// Add one mailbox per entry of `mailboxes`, in order, until the mailbox cap
    /// or a cap on the index stops it. Returns how many were added or merged,
    /// and the identifier of the last person added or merged.
    pub(super) fn add_mailboxes(
        &mut self,
        mailboxes: &[(String, String)],
    ) -> (usize, Option<PersonId>) {
        let mut touched = 0;
        let mut last = None;
        for (index, (name, address)) in mailboxes.iter().enumerate() {
            if index == self.limits.max_mailboxes {
                self.refused += 1;
                break;
            }
            match self.add_mailbox(name, address) {
                Insert::Added(id) => {
                    touched += 1;
                    last = Some(id);
                }
                Insert::Unusable => {}
                Insert::Capped => break,
            }
        }
        (touched, last)
    }
}

/// Trim a draft to the value caps: an over-long display name or value is
/// dropped, and a list keeps its first [`MAX_DRAFT_VALUES`] values. Each cut
/// counts as one refusal.
fn bound_draft(draft: &mut PersonDraft, refused: &mut usize) {
    if draft
        .display_name
        .as_ref()
        .is_some_and(|name| name.len() > MAX_VALUE_BYTES)
    {
        draft.display_name = None;
        *refused += 1;
    }
    for list in [
        &mut draft.given,
        &mut draft.family,
        &mut draft.nicknames,
        &mut draft.emails,
        &mut draft.phones,
        &mut draft.ibans,
    ] {
        let before = list.len();
        list.retain(|value| value.len() <= MAX_VALUE_BYTES);
        list.truncate(MAX_DRAFT_VALUES);
        if list.len() != before {
            *refused += 1;
        }
    }
}

/// Add the values of `incoming` that `list` does not already hold, ignoring
/// case and blanks.
fn extend_unique(
    list: &mut Vec<Zeroizing<String>>,
    incoming: impl IntoIterator<Item = Zeroizing<String>>,
) {
    for value in incoming {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if list.iter().any(|known| known.to_lowercase() == lower) {
            continue;
        }
        let kept = if trimmed.len() == value.len() {
            value
        } else {
            Zeroizing::new(trimmed.to_string())
        };
        list.push(kept);
    }
}

/// Copy what `source` knows into `target`, keeping what `target` already has.
fn merge_into(target: &mut Person, source: &Person) {
    if target.display_name.is_none() {
        target.display_name = source.display_name.clone();
    }
    extend_unique(&mut target.given, source.given.iter().cloned());
    extend_unique(&mut target.family, source.family.iter().cloned());
    extend_unique(&mut target.nicknames, source.nicknames.iter().cloned());
    extend_unique(&mut target.emails, source.emails.iter().cloned());
    extend_unique(&mut target.phones, source.phones.iter().cloned());
    extend_unique(&mut target.ibans, source.ibans.iter().cloned());
}

/// The variants of one person, and every pattern the index compiles for them:
/// the variants plus the e-mail, phone and IBAN keys. Returned as
/// `(variants, all patterns)`.
fn counts(person: &Person, mask_first_names: bool) -> (usize, usize) {
    let variants = variants_for(person, mask_first_names).len();
    let identifier_keys = person.emails.len()
        + person
            .phones
            .iter()
            .map(|phone| identifiers::phone_keys(phone).len())
            .sum::<usize>()
        + person.ibans.len();
    (variants, variants + identifier_keys)
}

/// A usable e-mail address, composed and lower-cased (the form the recogniser
/// matches), or `None`.
fn normalize_email(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    // Composed, lower-cased, and with `%40` and `[at]` read as the characters
    // they stand for, so every spelling of an address stores one address.
    let plain = plain_address(&lower_nfkc(trimmed));
    let address = plain.text().trim();
    let address = address.strip_prefix("mailto:").unwrap_or(address).trim();
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || address.contains(char::is_whitespace) {
        return None;
    }
    Some(address.to_string())
}
