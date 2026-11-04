//! The compiled lexicon: parsed rows, token index and matching.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;

use crate::span::{EntityKind, Span};

use super::inflect::{Index, Inflection, Token};
use super::text::{fold_str, is_han, joins, Word};
use super::{NAME, SCORE};

/// The versioned lexicon, compiled into the binary.
pub(super) const DATA: &str = include_str!("../../../data/sensitive-terms-v1.tsv");
/// Shortest one-word term, in folded bytes, that a glued tag may hide.
const MIN_TAGGED: usize = 8;
/// Longest ASCII tag glued before or after a term (`ref`, `ok`, `id42`).
const MAX_TAG: usize = 4;

/// A lexicon entry of one or more words.
struct Phrase {
    kind: EntityKind,
    tokens: Vec<Token>,
    /// An ambiguous abbreviation: it stands only next to a health anchor.
    contextual: bool,
    lang: &'static str,
}

/// A lexicon hit. `contextual` marks an ambiguous abbreviation, which the
/// caller keeps only when a health anchor shares its sentence.
pub(super) struct Hit {
    pub(super) span: Span,
    pub(super) contextual: bool,
    /// The language of the row that matched: an ambiguous abbreviation takes its
    /// anchor from the same language only.
    pub(super) lang: &'static str,
}

/// The static name of a lexicon language (`xx` for a brand or INN name).
fn language(lang: &str) -> &'static str {
    match lang {
        "fr" => "fr",
        "en" => "en",
        "af" => "af",
        "hu" => "hu",
        "sl" => "sl",
        "zh" => "zh",
        _ => "xx",
    }
}

/// One compiled lexicon: the terms, or the cues that anchor the ambiguous ones.
pub(super) struct Lexicon {
    phrases: Vec<Phrase>,
    /// Phrases whose first token is an exact word (or its plural or feminine
    /// form), keyed by that form.
    by_word: HashMap<String, Vec<usize>>,
    /// Phrases whose first token is a stem, keyed by the stem.
    by_stem: HashMap<String, Vec<usize>>,
    /// The longest first-token stem, in bytes: a word's prefix longer than this
    /// cannot be a key, so the prefix scan stops there (keeps it linear).
    longest_stem: usize,
    /// Han terms, matched as substrings.
    pub(super) han: Vec<(String, EntityKind)>,
    /// Han exceptions: `(term, suffix)` for a line `term|suffix`, a match of
    /// `term` that the suffix follows is not the term (中风险 is not 中风).
    pub(super) han_except: Vec<(String, String)>,
    /// Single-word terms of four or more letters from the compounding
    /// languages, matched inside a longer word: a compound, or a case ending.
    compounds: Option<(AhoCorasick, Vec<(EntityKind, &'static str)>)>,
}

impl Lexicon {
    fn build(entries: Vec<Entry>) -> Self {
        let mut lexicon = Lexicon {
            phrases: Vec::new(),
            by_word: HashMap::new(),
            by_stem: HashMap::new(),
            longest_stem: 0,
            han: Vec::new(),
            han_except: Vec::new(),
            compounds: None,
        };
        let mut compounds: Vec<(String, EntityKind, &'static str)> = Vec::new();
        // Two spellings that fold to one word (`chimiothérapie` and
        // `chimiotherapie`) index once, so no span is recorded twice.
        let mut seen: HashSet<String> = HashSet::new();
        // The exceptions of the Latin terms, keyed by the row they except.
        let mut excluded: HashMap<(EntityKind, String, String), Vec<String>> = HashMap::new();
        for entry in &entries {
            let Some(list) = &entry.except else { continue };
            if entry.term.chars().any(is_han) {
                lexicon.han_except.push((entry.term.clone(), list.clone()));
            } else {
                excluded.insert(
                    (entry.kind, entry.lang.clone(), entry.term.clone()),
                    list.split(',').map(fold_str).collect(),
                );
            }
        }
        for entry in entries {
            if entry.except.is_some() {
                // An exception row is not a term of its own.
                continue;
            }
            if entry.term.chars().any(is_han) {
                let term = entry.term.trim_end_matches('*').to_string();
                if seen.insert(format!("{}|{term}", entry.kind)) {
                    lexicon.han.push((term, entry.kind));
                }
                continue;
            }
            let exceptions = excluded
                .get(&(entry.kind, entry.lang.clone(), entry.term.clone()))
                .cloned()
                .unwrap_or_default();
            let tokens = tokens_of(&entry.term, &entry.lang, exceptions);
            let Some(first) = tokens.first() else {
                continue;
            };
            // Five letters, not four: a four-letter form (Slovene raka, raku) sits
            // inside ordinary words (poraka, praka). Every repro form is five or more.
            if entry.compound && tokens.len() == 1 && first.text.chars().count() >= 5 {
                compounds.push((first.text.clone(), entry.kind, language(&entry.lang)));
            }
            let key = tokens
                .iter()
                .map(|token| format!("{}{}", token.text, if token.stem { "*" } else { "" }))
                .collect::<Vec<_>>()
                .join(" ");
            if !seen.insert(format!("{}|{}|{key}", entry.kind, entry.lang)) {
                continue;
            }
            let id = lexicon.phrases.len();
            match first.index() {
                Index::Exact(forms) => {
                    for form in forms {
                        lexicon.by_word.entry(form).or_default().push(id);
                    }
                }
                Index::Prefix(stem) => {
                    lexicon.longest_stem = lexicon.longest_stem.max(stem.len());
                    lexicon.by_stem.entry(stem).or_default().push(id);
                }
            }
            lexicon.phrases.push(Phrase {
                kind: entry.kind,
                tokens,
                contextual: entry.contextual,
                lang: language(&entry.lang),
            });
        }
        if !compounds.is_empty() {
            let patterns: Vec<&str> = compounds.iter().map(|(text, _, _)| text.as_str()).collect();
            let kinds = compounds
                .iter()
                .map(|(_, kind, lang)| (*kind, *lang))
                .collect();
            let automaton = AhoCorasick::new(patterns).expect("compound terms build");
            lexicon.compounds = Some((automaton, kinds));
        }
        lexicon
    }

    /// Record each word that holds a compound term. The words are joined with a
    /// separator that no term contains, so one scan finds every compound and a
    /// match always lies inside one word.
    pub(super) fn push_compounds(&self, words: &[Word], out: &mut Vec<Hit>) {
        let Some((automaton, kinds)) = &self.compounds else {
            return;
        };
        let mut joined = String::new();
        let mut starts = Vec::with_capacity(words.len());
        for word in words {
            starts.push(joined.len());
            joined.push_str(&word.folded);
            joined.push('\u{1}');
        }
        for found in automaton.find_iter(joined.as_str()) {
            let (kind, lang) = kinds[found.pattern().as_usize()];
            let index = starts.partition_point(|&start| start <= found.start()) - 1;
            out.push(Hit {
                span: Span::new(kind, words[index].start, words[index].end, SCORE, NAME),
                contextual: false,
                lang,
            });
        }
    }

    /// Record each word that is a one-word health term of [`MIN_TAGGED`] or more
    /// bytes glued to an ASCII tag of at most [`MAX_TAG`] letters or digits before
    /// and after it (`refchimiothérapie`, `chemotherapyok`). A
    /// shorter term (`aids` in `raids`, `hiv` in `archive`) never takes a tag. At
    /// most 25 exact lookups per word, and for a stem of [`MIN_TAGGED`] or more
    /// bytes behind a leading tag (`refdiabetic`, `id42depressive`) at most
    /// [`MAX_TAG`] × the longest stem: linear.
    pub(super) fn push_tagged(&self, words: &[Word], out: &mut Vec<Hit>) {
        let ascii = |b: &u8| b.is_ascii_alphanumeric();
        for word in words {
            let folded = word.folded.as_str();
            if folded.len() <= MIN_TAGGED || folded.len() > MIN_TAGGED + 64 {
                continue;
            }
            let lead = folded.bytes().take_while(ascii).count().min(MAX_TAG);
            let tail = folded.bytes().rev().take_while(ascii).count().min(MAX_TAG);
            let exact = (0..=lead)
                .flat_map(|p| (0..=tail).map(move |s| (p, s)))
                .filter(|&(p, s)| p + s > 0 && p + s + MIN_TAGGED <= folded.len())
                .flat_map(|(p, s)| self.by_word.get(&folded[p..folded.len() - s]))
                .flatten();
            let stems = (1..=lead).flat_map(|p| {
                let rest = &folded[p..];
                rest.char_indices()
                    .map(|(at, ch)| at + ch.len_utf8())
                    .skip_while(|&end| end < MIN_TAGGED)
                    .take_while(|&end| end <= self.longest_stem)
                    .flat_map(move |end| self.by_stem.get(&rest[..end]))
                    .flatten()
                    .filter(move |&&id| self.phrases[id].tokens[0].matches(rest, true))
            });
            let found = exact
                .chain(stems)
                .map(|&id| &self.phrases[id])
                .find(|phrase| {
                    phrase.kind == EntityKind::Health
                        && phrase.tokens.len() == 1
                        && !phrase.contextual
                });
            if let Some(phrase) = found {
                out.push(Hit {
                    span: Span::new(phrase.kind, word.start, word.end, SCORE, NAME),
                    contextual: false,
                    lang: phrase.lang,
                });
            }
        }
    }

    /// Record every phrase that starts at word `index`.
    pub(super) fn match_at(&self, text: &str, words: &[Word], index: usize, out: &mut Vec<Hit>) {
        let word = words[index].folded.as_str();
        if let Some(ids) = self.by_word.get(word) {
            for &id in ids {
                self.phrase_at(id, text, words, index, out);
            }
        }
        let prefixes = word
            .char_indices()
            .map(|(at, ch)| at + ch.len_utf8())
            .take_while(|&end| end <= self.longest_stem);
        for end in prefixes {
            if let Some(ids) = self.by_stem.get(&word[..end]) {
                for &id in ids {
                    self.phrase_at(id, text, words, index, out);
                }
            }
        }
    }

    /// Record phrase `id` if its remaining tokens match the words after `index`.
    fn phrase_at(&self, id: usize, text: &str, words: &[Word], index: usize, out: &mut Vec<Hit>) {
        let phrase = &self.phrases[id];
        let last = index + phrase.tokens.len() - 1;
        if last >= words.len() {
            return;
        }
        for (offset, token) in phrase.tokens.iter().enumerate() {
            let word = &words[index + offset];
            if !token.matches(&word.folded, offset + 1 == phrase.tokens.len()) {
                return;
            }
            if offset > 0 && !joins(text, words[index + offset - 1].end, word.start) {
                return;
            }
        }
        out.push(Hit {
            span: Span::new(
                phrase.kind,
                words[index].start,
                words[last].end,
                SCORE,
                NAME,
            ),
            contextual: phrase.contextual,
            lang: phrase.lang,
        });
    }
}

/// One parsed lexicon line.
pub(super) struct Entry {
    kind: EntityKind,
    pub(super) lang: String,
    pub(super) term: String,
    /// A `?` term: an ambiguous abbreviation, kept only next to a health anchor.
    pub(super) contextual: bool,
    /// A `HEALTHCUE` line: a health cue, not a term.
    pub(super) cue: bool,
    /// A term of a compounding language (Hungarian, Afrikaans, Slovene), which
    /// also matches inside a longer word.
    compound: bool,
    /// For an exception line `term|list`: the exceptions of that term. A Han
    /// term lists the suffix that must not follow it (`中风|险`: 中风险 is not
    /// 中风); a Latin term lists the words it must not match, comma-separated
    /// (`FIV|five,fives`: `FIV` is `FIV`, never `five`).
    pub(super) except: Option<String>,
}

/// Parse a lexicon line. Comments, blank lines and malformed lines give `None`.
pub(super) fn parse_line(line: &str) -> Option<Entry> {
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split('\t');
    let category = fields.next()?;
    let lang = fields.next()?;
    let term = fields.next()?.trim();
    if fields.next().is_some() || term.is_empty() {
        return None;
    }
    if !matches!(lang, "fr" | "en" | "af" | "hu" | "sl" | "zh" | "xx") {
        return None;
    }
    let (kind, cue) = if category == "HEALTHCUE" {
        (EntityKind::Health, true)
    } else {
        let kind = EntityKind::parse(category).filter(|kind| {
            matches!(
                kind,
                EntityKind::Health
                    | EntityKind::Religion
                    | EntityKind::SexualOrientation
                    | EntityKind::Union
                    | EntityKind::Ethnicity
            )
        })?;
        (kind, false)
    };
    let (term, contextual) = match term.strip_prefix('?') {
        Some(rest) => (rest, true),
        None => (term, false),
    };
    if contextual && (cue || kind != EntityKind::Health) || term.is_empty() {
        return None;
    }
    let (term, except) = match term.split_once('|') {
        Some((term, suffix)) if !term.is_empty() && !suffix.is_empty() && !cue => {
            (term, Some(suffix.to_string()))
        }
        Some(_) => return None,
        None => (term, None),
    };
    Some(Entry {
        kind,
        lang: lang.to_string(),
        term: term.to_string(),
        contextual,
        cue,
        compound: matches!(lang, "hu" | "af" | "sl") && !cue && !contextual,
        except,
    })
}

/// The words of a Latin term. A trailing `*` makes a stem; an empty word is
/// dropped. `excluded` are the words the row must not match.
fn tokens_of(term: &str, lang: &str, excluded: Vec<String>) -> Vec<Token> {
    let inflection = match lang {
        "sl" => Inflection::Slovene,
        "hu" => Inflection::Hungarian,
        "en" => Inflection::English,
        "xx" => Inflection::Name,
        _ => Inflection::Plain,
    };
    term.split([' ', '-', '\'', '\u{2019}', '\u{02BC}'])
        .filter_map(|part| {
            let (text, stem) = match part.strip_suffix('*') {
                Some(body) => (body, true),
                None => (part, false),
            };
            let text = fold_str(text);
            (!text.is_empty()).then_some(Token {
                text,
                stem,
                inflection,
                excluded: excluded.clone(),
            })
        })
        .collect()
}

/// The two lexicons, compiled once: the terms, and the health cues.
pub(super) struct Lexicons {
    pub(super) terms: Lexicon,
    pub(super) cues: Lexicon,
}

/// The lexicons, compiled once.
pub(super) fn lexicons() -> &'static Lexicons {
    static LEXICONS: OnceLock<Lexicons> = OnceLock::new();
    LEXICONS.get_or_init(|| {
        let (cues, terms): (Vec<Entry>, Vec<Entry>) = DATA
            .lines()
            .filter_map(parse_line)
            .partition(|entry| entry.cue);
        Lexicons {
            terms: Lexicon::build(terms),
            cues: Lexicon::build(cues),
        }
    })
}
