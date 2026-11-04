//! Token inflection: the forms a lexicon word takes in its language.

use std::sync::OnceLock;

use super::text::fold_str;

/// How a non-stem word of a lexicon term inflects in its language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Inflection {
    /// French and Afrikaans: the base word, with its plural or feminine `s`,
    /// `es` or `e`.
    Plain,
    /// English: the plain forms, and on the final word also the `y` to `ies`,
    /// `ied` and `-ing` forms, the `-ed` and `-d`, `-ing` and `-ation` forms of a
    /// verb or noun stem (see [`english_forms`]).
    English,
    /// Slovene: the stem (the base minus its final vowel) with a case ending.
    Slovene,
    /// Hungarian: the base with case and possessive suffixes, with the linking
    /// and assimilation rules.
    Hungarian,
    /// A brand or INN name (lang `xx`): the name with a suffix of four letters or
    /// fewer.
    Name,
}

/// One word of a lexicon term. `stem` marks a prefix match.
pub(super) struct Token {
    pub(super) text: String,
    pub(super) stem: bool,
    pub(super) inflection: Inflection,
    /// The words this row must not match: `FIV` is `FIV`, never `five`.
    pub(super) excluded: Vec<String>,
}

/// Slovene endings that a noun or an adjective takes after its stem, folded.
const SL_ENDINGS: &[&str] = &[
    "", "a", "e", "i", "o", "u", "om", "em", "ijo", "ije", "iji", "ja", "ju", "jo", "ama", "ah",
    "ih", "mi", "ov", "ev", "ega", "emu", "im", "on",
];

/// The endings an earlier word of a multi-word Slovene term takes: its base form,
/// or an adjective ending.
const SL_ADJECTIVE_ENDINGS: &[&str] = &["", "o", "e", "a", "i", "ega", "emu", "im", "on"];

/// The shortest Slovene stem that takes inflection, in characters: a shorter stem
/// matches its base word only.
const MIN_INFLECTED_STEM: usize = 3;

/// The shortest Hungarian base that takes inflection, in characters: a three-letter
/// acronym such as HIV takes none (hívják is not HIV + jak).
const MIN_HUNGARIAN_BASE: usize = 4;

/// Hungarian case endings, in their accented canonical form (they are compared
/// folded).
const HU_CASE: &[&str] = &[
    "", "t", "ot", "et", "át", "ét", "on", "en", "ön", "ban", "ben", "ba", "be", "ból", "ből",
    "ról", "ről", "tól", "től", "ra", "re", "hoz", "hez", "höz", "nak", "nek", "val", "vel", "mal",
    "mel", "sal", "sel", "szal", "szel", "nyel", "nyal", "ral", "rel", "kal", "kel", "ként", "ig",
    "os", "ös", "ok", "ek", "k",
];

/// Hungarian possessive suffixes, which come before a case ending.
const HU_POSS: &[&str] = &[
    "a", "e", "ja", "je", "m", "om", "am", "em", "unk", "ünk", "tok", "tek", "juk", "jük",
];

/// The folded forms of a list of Hungarian suffixes, built once.
fn hu_folded(list: &'static [&'static str]) -> Vec<String> {
    list.iter().map(|ending| fold_str(ending)).collect()
}

/// Whether a folded Hungarian ending is a case ending, or a possessive followed
/// by a case ending (`-om` + `-ról`, `-ja` + `-val`), or a bare possessive.
pub(super) fn hungarian_ending(rest: &str) -> bool {
    static CASES: OnceLock<Vec<String>> = OnceLock::new();
    static POSSESSIVES: OnceLock<Vec<String>> = OnceLock::new();
    let cases = CASES.get_or_init(|| hu_folded(HU_CASE));
    let possessives = POSSESSIVES.get_or_init(|| hu_folded(HU_POSS));
    cases.iter().any(|case| case == rest)
        || possessives.iter().any(|poss| {
            rest == poss.as_str()
                || rest
                    .strip_prefix(poss.as_str())
                    .is_some_and(|case| cases.iter().any(|c| c == case))
        })
}

/// The Hungarian stem of a base: a `-ny` base loses its `y` before a suffix
/// (fény → fénnyel), every other base is its own stem.
pub(super) fn hungarian_stem(base: &str) -> &str {
    match base.strip_suffix("ny") {
        Some(_) => &base[..base.len() - 1],
        None => base,
    }
}

/// Whether a folded word is a Hungarian inflection of a folded base: the base, its
/// stem with a suffix, or a doubled final consonant with a suffix (sérv → sérvvel).
pub(super) fn hungarian_inflected(word: &str, base: &str) -> bool {
    if word == base {
        return true;
    }
    if let Some(rest) = word.strip_prefix(hungarian_stem(base)) {
        if hungarian_ending(rest) {
            return true;
        }
    }
    if let (Some(last), Some(rest)) = (base.chars().last(), word.strip_prefix(base)) {
        let consonant = last.is_ascii_alphabetic() && !"aeiou".contains(last);
        if consonant {
            if let Some(tail) = rest.strip_prefix(last) {
                // -val/-vel assimilate to the doubled consonant: lázzal.
                return hungarian_ending(tail) || matches!(tail, "al" | "el");
            }
        }
    }
    false
}

/// The Slovene stem of a base: the base minus its final vowel.
pub(super) fn slovene_stem(base: &str) -> &str {
    match base.chars().last() {
        Some('a' | 'e' | 'i' | 'o' | 'u') => &base[..base.len() - 1],
        _ => base,
    }
}

/// Whether a folded word is the base word with a plural or feminine `s`, `es` or `e`.
pub(super) fn plain_match(word: &str, base: &str) -> bool {
    word.strip_prefix(base)
        .is_some_and(|rest| rest.is_empty() || matches!(rest, "s" | "es" | "e"))
}

/// The plain forms of a base word, as [`plain_match`] reads them.
fn plain_forms(base: &str) -> Vec<String> {
    vec![
        base.to_string(),
        format!("{base}s"),
        format!("{base}es"),
        format!("{base}e"),
    ]
}

/// The forms an English final word takes: the plain forms, then `y` to `ies` and
/// `ied` (therapy, miscarry), the `-ed` and `-d` (addict, disable), the `-ing`
/// (overdose, miscarry), and for a stem in `-ize` or `-ise` the `-ation(s)` noun
/// (hospitalize). A word that is not a stem of a lexicon term is not a form.
fn english_forms(base: &str) -> Vec<String> {
    let mut forms = plain_forms(base);
    if let Some(stem) = base.strip_suffix('y') {
        forms.push(format!("{stem}ies"));
        forms.push(format!("{stem}ied"));
        forms.push(format!("{base}ing"));
    } else if let Some(stem) = base.strip_suffix('e') {
        forms.push(format!("{base}d"));
        forms.push(format!("{stem}ing"));
        if base.ends_with("ize") || base.ends_with("ise") {
            forms.push(format!("{stem}ation"));
            forms.push(format!("{stem}ations"));
        }
    } else {
        forms.push(format!("{base}ed"));
        forms.push(format!("{base}ing"));
    }
    forms
}

/// How a token enters the index: an exact set of forms, or a prefix (a stem).
pub(super) enum Index {
    Exact(Vec<String>),
    Prefix(String),
}

impl Token {
    /// Whether a folded word is this token. `last` is set for the final word of a
    /// term: an earlier word takes only its base form (plus an adjective ending in
    /// Slovene), the last word takes the full inflection.
    pub(super) fn matches(&self, word: &str, last: bool) -> bool {
        if self.stem {
            return word.starts_with(&self.text);
        }
        if last && self.excluded.iter().any(|excluded| excluded == word) {
            // The row excepts this word: `FIV` is `FIV`, never `five`.
            return false;
        }
        match self.inflection {
            Inflection::Plain => plain_match(word, &self.text),
            Inflection::English => {
                plain_match(word, &self.text)
                    || (last && english_forms(&self.text).iter().any(|form| form == word))
            }
            Inflection::Slovene => {
                if word == self.text {
                    return true;
                }
                let stem = slovene_stem(&self.text);
                if stem.chars().count() < MIN_INFLECTED_STEM {
                    return false;
                }
                let endings = if last {
                    SL_ENDINGS
                } else {
                    SL_ADJECTIVE_ENDINGS
                };
                word.strip_prefix(stem)
                    .is_some_and(|rest| endings.contains(&rest))
            }
            Inflection::Hungarian => {
                if last && self.text.chars().count() >= MIN_HUNGARIAN_BASE {
                    hungarian_inflected(word, &self.text)
                } else {
                    word == self.text
                }
            }
            Inflection::Name => word.strip_prefix(self.text.as_str()).is_some_and(|rest| {
                rest.chars().count() <= 4 && rest.chars().all(char::is_alphabetic)
            }),
        }
    }

    /// The forms of this token, without the words its row excepts.
    fn kept(&self, forms: Vec<String>) -> Vec<String> {
        forms
            .into_iter()
            .filter(|form| !self.excluded.iter().any(|excluded| excluded == form))
            .collect()
    }

    /// How this token is indexed: its exact forms, or the prefix that every
    /// inflected form starts with.
    pub(super) fn index(&self) -> Index {
        if self.stem {
            return Index::Prefix(self.text.clone());
        }
        match self.inflection {
            Inflection::Plain => Index::Exact(self.kept(plain_forms(&self.text))),
            // A superset: `matches` checks the final-word forms for the last word only.
            Inflection::English => Index::Exact(self.kept(english_forms(&self.text))),
            Inflection::Slovene => {
                let stem = slovene_stem(&self.text);
                if stem.chars().count() < MIN_INFLECTED_STEM {
                    Index::Prefix(self.text.clone())
                } else {
                    Index::Prefix(stem.to_string())
                }
            }
            Inflection::Hungarian => Index::Prefix(hungarian_stem(&self.text).to_string()),
            Inflection::Name => Index::Prefix(self.text.clone()),
        }
    }
}
