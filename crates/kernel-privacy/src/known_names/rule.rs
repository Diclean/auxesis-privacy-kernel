//! What one compiled surface form may match, and on what evidence.

use crate::contacts::fold::is_no_space_script;
use crate::contacts::stopwords;

use super::matching::{
    cased_of, is_capitalised, is_caseless, letters, preceded_by_title, spelling_of,
};

/// How much evidence a compiled surface form carries.
///
/// Ordered from weakest to strongest, so merging two entries for the same
/// pattern keeps the most permissive check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum NameCheck {
    /// Only after a title (`Mme Le`).
    Titled,
    /// Capitalised, all-caps, or after a title (`Wu`).
    Short,
    /// Any casing (`Camille`, `camille exemple`).
    Any,
}

impl NameCheck {
    /// The check a token carries when it stands alone. A caseless script has
    /// no capitalisation to require, so its parts are always eligible. A short
    /// part, and a part that is also a common word (`will`, `may`, `rose`),
    /// needs a capital: the lower-case word is the common one.
    pub(super) fn for_token(token: &str) -> Self {
        if is_caseless(token) {
            Self::Any
        } else if letters(token) == 2 || stopwords::is_common_word(token) {
            Self::Short
        } else {
            Self::Any
        }
    }

    /// Whether a match at `text[start..end]`, whose folded form begins at
    /// `begin`, satisfies this check.
    pub(super) fn passes(
        self,
        text: &str,
        start: usize,
        end: usize,
        folded: &str,
        begin: usize,
    ) -> bool {
        match self {
            Self::Any => true,
            Self::Short => is_capitalised(&text[start..end]) || preceded_by_title(folded, begin),
            Self::Titled => preceded_by_title(folded, begin),
        }
    }
}

/// How one compiled pattern may match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PatternRule {
    /// The evidence the matched text must carry.
    pub(super) check: NameCheck,
    /// The own spelling of each one-part entry with a diacritic that compiles to
    /// this pattern, with that entry's check. A match written in one of these
    /// spellings keeps the entry's rule; any other spelling is derived from it
    /// and needs `check`.
    pub(super) spelled: Vec<(String, NameCheck)>,
    /// The case-kept spelling of each one-part entry written in lower case. A
    /// text word spelled exactly so is that entry, so it matches whatever the
    /// common-word rule says: `rose` for a contact stored as `rose`.
    pub(super) cased: Vec<String>,
    /// A no-space-script pattern matches as a substring, with no boundary.
    pub(super) no_space: bool,
    /// The pattern is a name form, so it matches a whole word on its own. A
    /// stem is not: it matches only a longer word through its [`StemRange`].
    pub(super) exact: bool,
    /// A whole spaced-script name part of three letters or more accepts a tail
    /// of one to six letters of the same script.
    pub(super) tail: bool,
    /// A stem accepts a whole word whose letter count is in this range.
    pub(super) stem: Option<StemRange>,
}

/// The letter counts a stem may stand for: the whole word, from `min` to `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StemRange {
    pub(super) min: usize,
    pub(super) max: usize,
}

impl PatternRule {
    pub(super) fn for_pattern(pattern: &str, check: NameCheck) -> Self {
        Self {
            check,
            spelled: Vec::new(),
            cased: Vec::new(),
            no_space: pattern.chars().any(is_no_space_script),
            exact: true,
            tail: false,
            stem: None,
        }
    }

    /// The check for a match whose source text is `source`.
    pub(super) fn check_for(&self, source: &str) -> NameCheck {
        if !self.cased.is_empty() && self.cased.contains(&cased_of(source)) {
            return NameCheck::Any;
        }
        if self.spelled.is_empty() {
            return self.check;
        }
        let spelling = spelling_of(source);
        match self.spelled.iter().find(|(own, _)| *own == spelling) {
            Some((_, own)) => self.check.max(*own),
            None => self.check,
        }
    }

    /// Keep the most permissive of two rules for the same pattern.
    pub(super) fn merge(&self, other: &Self) -> Self {
        let mut spelled = self.spelled.clone();
        for entry in &other.spelled {
            if !spelled.contains(entry) {
                spelled.push(entry.clone());
            }
        }
        let mut cased = self.cased.clone();
        for spelling in &other.cased {
            if !cased.contains(spelling) {
                cased.push(spelling.clone());
            }
        }
        Self {
            check: self.check.max(other.check),
            spelled,
            cased,
            no_space: self.no_space || other.no_space,
            exact: self.exact || other.exact,
            tail: self.tail || other.tail,
            stem: match (self.stem, other.stem) {
                (Some(a), Some(b)) => Some(StemRange {
                    min: a.min.min(b.min),
                    max: a.max.max(b.max),
                }),
                (a, b) => a.or(b),
            },
        }
    }
}
