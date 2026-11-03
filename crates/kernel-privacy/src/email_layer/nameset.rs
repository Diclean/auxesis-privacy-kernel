//! The seeded-name set that decides which tokens propagate.

use std::collections::{HashMap, HashSet};

use crate::public_terms::{fold, PublicTerms};

use super::display::pick_rule_tokens;
use super::lines::{is_all_caps_surname, opens_line_or_sentence, word_tokens, WordToken};
use super::mail_words::{ROLE_LOCAL_WORDS, STRUCTURAL_WORDS};
use super::stop_words::{is_role_local_part, STOP_WORDS};

/// Seeded name tokens plus the stop-list that keeps common words out.
pub(super) struct NameSet<'a> {
    /// Folded tokens that always propagate: known surnames, ambiguous
    /// single-token seeds and every non-first token of a full name.
    names: HashSet<String>,
    /// Folded tokens that are only a given name in the seeds seen so far: they
    /// propagate alone only when [`super::EmailLayer::with_first_names`] is on.
    given: HashSet<String>,
    /// Folded structural token -> the exact spelling a strong seed used, so a
    /// lone `De`/`Le` can be compared with the seed's capitalisation.
    pub(super) structural: HashMap<String, String>,
    /// Folded token sequences of the strong seed phrases (NER person, header
    /// display name, contact local part). Rule (a) masks a re-ordered sequence,
    /// an initial form (`J. De`, `De J.`) or an honorific prefix (`M. De`).
    pub(super) sequences: Vec<Vec<String>>,
    public: &'a PublicTerms,
}

impl<'a> NameSet<'a> {
    pub(super) fn new(public: &'a PublicTerms) -> Self {
        Self {
            names: HashSet::new(),
            given: HashSet::new(),
            structural: HashMap::new(),
            sequences: Vec::new(),
            public,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.names.is_empty() && self.given.is_empty() && self.structural.is_empty()
    }

    /// Whether a folded token always propagates (a surname, or an ambiguous
    /// single-token seed).
    pub(super) fn is_always(&self, folded: &str) -> bool {
        self.names.contains(folded)
    }

    /// Whether a folded token is only known as a bare given name.
    pub(super) fn is_given(&self, folded: &str) -> bool {
        self.given.contains(folded)
    }

    /// Whether a folded token has the shape of a name word at all.
    pub(super) fn is_name_like(folded: &str) -> bool {
        let length = folded.chars().count();
        (2..=40).contains(&length) && folded.chars().any(char::is_alphabetic)
    }

    /// Whether a weaker source must drop this token.
    pub(super) fn is_weak_filtered(&self, folded: &str) -> bool {
        STOP_WORDS.contains(folded) || self.public.covers_word(folded)
    }

    /// Remember a structural token with the exact spelling the seed used.
    fn remember_structural(&mut self, raw: &str, folded: String) {
        self.structural
            .entry(folded)
            .and_modify(|known| {
                if !known.chars().any(char::is_uppercase) && raw.chars().any(char::is_uppercase) {
                    *known = raw.to_string();
                }
            })
            .or_insert_with(|| raw.to_string());
    }

    /// Add one token that always propagates.
    ///
    /// A seed is the text naming a person itself — a model span, a greeting or
    /// sign-off rule, a header display name, an email local part — so its tokens
    /// propagate even when they collide with a stop word ("Will") or a public
    /// term ("Orange"). Only weaker sources consult the stop and public lists.
    ///
    /// A structural label is never a strong seed on its own: masking every `le`,
    /// `de`, `contact` or `objet` of a mail garbles the text the model reads
    /// without protecting anything. It is kept aside, with the exact spelling the
    /// seed used, because it can still be a surname ("Jean De"): rules (a) and (b)
    /// in [`super::EmailLayer::propagate`] are what decide when it is masked.
    fn add_strong(&mut self, raw: &str) {
        let folded = fold(raw);
        if !Self::is_name_like(&folded) {
            return;
        }
        if STRUCTURAL_WORDS.contains(&folded) {
            self.remember_structural(raw, folded);
        } else {
            // Seen as a surname anywhere: it must never be suppressed as a
            // bare first name.
            self.given.remove(&folded);
            self.names.insert(folded);
        }
    }

    /// Add one token that is only known as a given name so far.
    ///
    /// An ALL-CAPS token is a surname convention (`DUPONT`), a structural token
    /// is a particle, and a token already seen as a surname anywhere stays in the
    /// always-propagate set; everything else is a bare given name.
    fn add_given(&mut self, raw: &str) {
        let folded = fold(raw);
        if !Self::is_name_like(&folded) {
            return;
        }
        if STRUCTURAL_WORDS.contains(&folded) {
            self.remember_structural(raw, folded);
        } else if is_all_caps_surname(raw) || self.names.contains(&folded) {
            self.names.insert(folded);
        } else {
            self.given.insert(folded);
        }
    }

    /// Add a strong seed phrase.
    ///
    /// The full phrase (2+ tokens) always propagates through [`Self::sequences`].
    /// For the lone-token case, `single_always` decides whether one token is
    /// enough evidence on its own (a model span, a header display name or a
    /// mailbox local part) or only a bare given name (a greeting, a sign-off, a
    /// line-start comma, a speech verb). The first token of a full name is its
    /// given name; every later token is a surname.
    fn add_phrase(&mut self, raw_tokens: &[&str], single_always: bool) {
        let mut sequence: Vec<String> = Vec::new();
        for raw in raw_tokens {
            let folded = fold(raw);
            if Self::is_name_like(&folded) {
                sequence.push(folded);
            }
        }
        if sequence.is_empty() {
            return;
        }
        if sequence.len() == 1 {
            if single_always {
                let raw = raw_tokens
                    .iter()
                    .copied()
                    .find(|raw| Self::is_name_like(&fold(raw)))
                    .expect("sequence has one token");
                self.add_strong(raw);
            } else {
                let raw = raw_tokens
                    .iter()
                    .copied()
                    .find(|raw| Self::is_name_like(&fold(raw)))
                    .expect("sequence has one token");
                self.add_given(raw);
            }
            return;
        }
        self.sequences.push(sequence);
        let mut position = 0usize;
        for raw in raw_tokens {
            if !Self::is_name_like(&fold(raw)) {
                continue;
            }
            if position == 0 {
                self.add_given(raw);
            } else {
                self.add_strong(raw);
            }
            position += 1;
        }
    }

    /// Add every token of a strong seed phrase and remember it as an ordered
    /// sequence. A lone token is strong enough on its own.
    pub(super) fn add_strong_phrase(&mut self, raw_tokens: &[&str]) {
        self.add_phrase(raw_tokens, true);
    }

    /// Add a rule-detected name phrase. A lone token is only a bare given name.
    pub(super) fn add_rule_phrase(&mut self, raw_tokens: &[&str]) {
        self.add_phrase(raw_tokens, false);
    }

    /// Add every name-shaped token of a PERSON seed phrase.
    pub(super) fn add_seed_text(&mut self, value: &str) {
        let tokens = word_tokens(value);
        let raws: Vec<&str> = tokens
            .iter()
            .map(|token| &value[token.start..token.end])
            .collect();
        self.add_strong_phrase(&raws);
    }

    /// Seed the local part of an e-mail address, never a role mailbox.
    ///
    /// A role address (`contact@`, `info@`, `compta@`) names a function, not a
    /// person: it seeds nothing, and none of its tokens ever propagate. In a real
    /// mailbox (`marie.dupont@`, `jules+news@`) the name tokens are seeded and any
    /// role token is dropped. The domain part is never seeded at all.
    pub(super) fn add_local_part(&mut self, local: &str) {
        if is_role_local_part(local) {
            return;
        }
        let tokens = word_tokens(local);
        let mut raws: Vec<&str> = Vec::new();
        for token in &tokens {
            if ROLE_LOCAL_WORDS.contains(&token.folded) {
                continue;
            }
            raws.push(&local[token.start..token.end]);
        }
        self.add_strong_phrase(&raws);
    }

    /// Add the name-shaped tokens of a rule phrase, strongly.
    pub(super) fn add_rule_text(&mut self, value: &str, max: usize) {
        let picked = pick_rule_tokens(value, self, max);
        let raws: Vec<&str> = picked
            .iter()
            .map(|token| &value[token.start..token.end])
            .collect();
        self.add_rule_phrase(&raws);
    }

    /// Whether a rule may take a raw token as a name.
    ///
    /// A rule is medium-strength evidence: capitalisation never rescues a
    /// function word or a structural label (`Le`, `De`, `Contact`, `Objet`), but a
    /// capitalised stop word or public term that is a real name (`Will`,
    /// `Orange`) still passes.
    pub(super) fn is_rule_name(&self, token: &WordToken, raw: &str) -> bool {
        if !Self::is_name_like(&token.folded) {
            return false;
        }
        let folded = token.folded.as_str();
        if STRUCTURAL_WORDS.contains(folded) {
            return false;
        }
        let capitalized = raw.chars().next().is_some_and(char::is_uppercase);
        capitalized || !self.is_weak_filtered(&token.folded)
    }

    /// Rule (b): a structural token from a strong seed, masked alone.
    ///
    /// Only when the seed spelled it exactly so, it does not open a sentence or
    /// a line, and it is not followed by a lower-case word that would make it a
    /// function word. A lone lower-case `de`/`le` never passes the first test, so
    /// an article is never masked by this rule.
    pub(super) fn is_lone_structural(
        &self,
        text: &str,
        tokens: &[WordToken],
        index: usize,
    ) -> bool {
        let token = &tokens[index];
        let Some(seed) = self.structural.get(&token.folded) else {
            return false;
        };
        let raw = &text[token.start..token.end];
        // Capitalised exactly as in the seed: a lower-case seed spelling (a
        // mailbox local part) never masks a lower-case article either.
        if !raw.chars().next().is_some_and(char::is_uppercase) || raw != seed.as_str() {
            return false;
        }
        if opens_line_or_sentence(text, token.start) {
            return false;
        }
        if let Some(next) = tokens.get(index + 1) {
            if text[next.start..next.end]
                .chars()
                .next()
                .is_some_and(char::is_lowercase)
            {
                return false;
            }
        }
        true
    }
}
