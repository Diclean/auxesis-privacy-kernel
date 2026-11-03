//! Compiling one dictionary entry into the surface forms it is written under.

use std::collections::BTreeMap;

use unicode_normalization::UnicodeNormalization;

use crate::contacts::fold::{
    fold_separators, fold_separators_homoglyphs, fold_separators_homoglyphs_plain,
    is_latin_diacritic, is_no_space_script, Folded,
};
use crate::contacts::inflect;

use super::constants::{ARABIC_COMPOUNDS, HEBREW_PREFIXES, PARTICLES, TITLES};
use super::matching::{
    cased_of, is_caseless, is_letter_or_mark, letters, script_family, spelling_of, Script,
};
use super::rule::{NameCheck, PatternRule, StemRange};

/// Record `pattern` with `check`, keeping the most permissive rule when the
/// same pattern arrives twice.
fn add(out: &mut BTreeMap<String, PatternRule>, pattern: String, check: NameCheck) {
    let rule = PatternRule::for_pattern(&pattern, check);
    add_rule(out, pattern, rule);
}

/// Record `pattern` with `rule`, keeping the most permissive rule when the same
/// pattern arrives twice. A pattern with fewer than two letters is never kept.
fn add_rule(out: &mut BTreeMap<String, PatternRule>, pattern: String, rule: PatternRule) {
    if letters(&pattern) < 2 {
        return;
    }
    out.entry(pattern)
        .and_modify(|current| *current = current.merge(&rule))
        .or_insert(rule);
}

/// Add one token as a standalone pattern when it can stand alone, with its
/// inflections, its stem and its attached prefixes. A particle takes none of
/// the inflection rules: it matches as it did before.
fn add_token(out: &mut BTreeMap<String, PatternRule>, token: &str, plain: &str, check: NameCheck) {
    if letters(token) < 2 {
        return;
    }
    let inflects = !is_particle(token);
    let rule = PatternRule {
        tail: inflects && !token.chars().any(is_no_space_script) && letters(token) >= 3,
        ..PatternRule::for_pattern(token, check)
    };
    add_rule(out, token.to_string(), rule);
    if token.chars().any(is_no_space_script) {
        return;
    }
    for title in TITLES {
        add(out, format!("{title} {token}"), NameCheck::Any);
    }
    for form in inflections(plain) {
        add(
            out,
            fold_separators_homoglyphs(&form).text().to_string(),
            check,
        );
    }
    if inflects {
        if let Some((stem, range)) = stem_of(token) {
            let rule = PatternRule {
                exact: false,
                stem: Some(range),
                ..PatternRule::for_pattern(&stem, check)
            };
            add_rule(out, stem, rule);
        }
    }
    add_attached_prefixes(out, token, check);
}

/// The stem of one spaced name part and the letter count of the whole word it
/// may match. The stem is the first `max(3, n−2)` letters of the part, for a
/// part of four letters or more; a cased part of three letters has a two-letter
/// stem that only matches a word of three to six letters (`Ewa` → `Ewy`). A
/// caseless part of three letters has no stem.
fn stem_of(token: &str) -> Option<(String, StemRange)> {
    let count = letters(token);
    let (keep, min, max) = if count >= 4 {
        (count.saturating_sub(2).max(3), count - 1, count + 6)
    } else if count == 3 && !is_caseless(token) {
        (2, count, count + 3)
    } else {
        return None;
    };
    Some((leading_letters(token, keep), StemRange { min, max }))
}

/// The first `count` letters of `token`, with the marks that follow each one.
fn leading_letters(token: &str, count: usize) -> String {
    let mut out = String::new();
    let mut taken = 0;
    for ch in token.chars() {
        if is_letter_or_mark(ch) {
            if taken == count {
                break;
            }
            taken += 1;
        }
        out.push(ch);
    }
    out
}

/// The short inflections of one name part: the English, French and German
/// suffixes the brief lists, plus the Slavic case endings from
/// [`crate::contacts::inflect`] and the Finnish genitive of `-nen` names
/// (`Virtanen` → `Virtasen`).
fn inflections(token: &str) -> Vec<String> {
    let mut forms = vec![
        format!("{token}s"),
        format!("{token}es"),
        format!("{token} s"),
        format!("{token}x"),
        format!("{token}n"),
        format!("{token}en"),
        format!("{token}ns"),
        format!("{token}em"),
    ];
    if let Some(stem) = token.strip_suffix("nen") {
        forms.push(format!("{stem}sen"));
    }
    forms.extend(inflect::word_forms(token, inflect::Role::Family));
    forms.extend(inflect::word_forms(token, inflect::Role::Given));
    forms
}

/// Compile the attached Hebrew prefixes of one name part. The Arabic prefixes
/// come from [`crate::contacts::inflect`] instead.
fn add_attached_prefixes(out: &mut BTreeMap<String, PatternRule>, token: &str, check: NameCheck) {
    if script_family(token.chars().next().unwrap_or(' ')) != Script::Hebrew {
        return;
    }
    for first in HEBREW_PREFIXES {
        add(out, format!("{first}{token}"), check);
        for second in HEBREW_PREFIXES {
            add(out, format!("{first}{second}{token}"), check);
        }
    }
}

/// Every surface form of one dictionary entry, with its check. The entry is
/// compiled twice, with its diacritics transliterated (`Müller` → `mueller`) and
/// with them stripped (`muller`), so either way of typing it matches.
///
/// The forms cover the ways a person is written: full name in order and
/// reversed, given and family runs alone, an initial with the family name, a
/// given name with an initial, each run concatenated without separators, the
/// possessive of the given name and the elided family name. A particle opens
/// the family run (`Camille Le Gall`, `Sinéad O'Connor`); a no-space script
/// also gets its glued run; an Arabic compound gets both its spellings.
pub(super) fn variants_for(entry: &str) -> Vec<(String, PatternRule)> {
    // NFC first: an NFD entry is the same spelling as its NFC form.
    let entry: String = entry.nfc().collect();
    let entry = entry.as_str();
    let plain = fold_separators(entry);
    let transliterated = fold_separators_homoglyphs(entry);
    let stripped = fold_separators_homoglyphs_plain(entry);
    let own = entry
        .chars()
        .any(is_latin_diacritic)
        .then(|| spelling_of(entry));
    let cased = (!entry.chars().any(char::is_uppercase)).then(|| cased_of(entry));
    let mut out = variants_from(&transliterated, &plain, own.as_deref(), cased.as_deref());
    if stripped.text() != transliterated.text() {
        for (variant, rule) in variants_from(&stripped, &plain, own.as_deref(), cased.as_deref()) {
            out.entry(variant)
                .and_modify(|current| *current = current.merge(&rule))
                .or_insert(rule);
        }
    }
    out.into_iter().collect()
}

/// The surface forms of `folded`, one entry spelled in one fold. `plain` is the
/// same entry folded without the homoglyph and transliteration maps. `own` is
/// the spelling of an entry with a Latin diacritic, which keeps its own rule
/// only as written: a one-part spelling derived by a strip or a transliteration
/// needs a capital (`back` for `Bäck`). `cased` is the case-kept spelling of a
/// one-part entry written in lower case, which matches as written.
fn variants_from(
    folded: &Folded,
    plain: &Folded,
    own: Option<&str>,
    cased: Option<&str>,
) -> BTreeMap<String, PatternRule> {
    let tokens: Vec<&str> = folded
        .text()
        .split(' ')
        .filter(|token| !token.is_empty())
        .collect();
    let plain_tokens: Vec<&str> = plain
        .text()
        .split(' ')
        .filter(|token| !token.is_empty())
        .collect();
    let mut out: BTreeMap<String, PatternRule> = BTreeMap::new();
    match tokens.as_slice() {
        [] => {}
        [only] => {
            let plain_only = plain_tokens.first().copied().unwrap_or(only);
            match own {
                Some(spelling) => {
                    add_token(&mut out, only, plain_only, NameCheck::Short);
                    let rule = PatternRule {
                        spelled: vec![(spelling.to_string(), NameCheck::for_token(only))],
                        ..PatternRule::for_pattern(only, NameCheck::Short)
                    };
                    add_rule(&mut out, only.to_string(), rule);
                }
                None => add_token(&mut out, only, plain_only, NameCheck::for_token(only)),
            }
            if let Some(spelling) = cased {
                let rule = PatternRule {
                    cased: vec![spelling.to_string()],
                    ..PatternRule::for_pattern(only, NameCheck::Short)
                };
                add_rule(&mut out, only.to_string(), rule);
            }
            for compound in compound_variants(&tokens) {
                add(&mut out, compound, NameCheck::Any);
            }
        }
        _ => {
            let split = family_split(&tokens);
            let given = &tokens[..split];
            let family = &tokens[split..];
            let plain_given = &plain_tokens[..split];
            let plain_family = &plain_tokens[split..];
            let given_phrase = given.join(" ");
            let family_phrase = family.join(" ");
            let given_concat: String = given.concat();
            let family_concat: String = family.concat();

            add(
                &mut out,
                format!("{given_phrase} {family_phrase}"),
                NameCheck::Any,
            );
            add(
                &mut out,
                format!("{family_phrase} {given_phrase}"),
                NameCheck::Any,
            );
            // A multi-part given name alone is a name too (`Дарʼя`, `Jean Pierre`).
            if given.len() >= 2 {
                add(&mut out, given_phrase.clone(), NameCheck::Any);
            }
            // A script without spaces writes the same name glued or spaced.
            if tokens
                .iter()
                .all(|token| token.chars().any(is_no_space_script))
            {
                add(&mut out, tokens.concat(), NameCheck::Any);
            }
            for compound in compound_variants(&tokens) {
                add(&mut out, compound, NameCheck::Any);
            }
            // A particle that is the whole family run names a person
            // (`Camille De`); a particle inside a longer run does not
            // (`Camille Le Gall`).
            let family_check = if family.len() == 1 {
                if is_particle(family[0]) {
                    NameCheck::Short
                } else {
                    NameCheck::for_token(family[0])
                }
            } else {
                NameCheck::Any
            };
            add(&mut out, family_phrase.clone(), family_check);
            // A particle that is the given name is a normal short part
            // (`Ben Martin`, `Van Nguyen`).
            for (token, plain_token) in given.iter().zip(plain_given) {
                let check = if is_particle(token) {
                    NameCheck::Short
                } else {
                    NameCheck::for_token(token)
                };
                add_token(&mut out, token, plain_token, check);
            }
            for (token, plain_token) in family.iter().zip(plain_family) {
                let check = if is_particle(token) {
                    if family.len() == 1 {
                        NameCheck::Short
                    } else {
                        NameCheck::Titled
                    }
                } else {
                    NameCheck::for_token(token)
                };
                add_token(&mut out, token, plain_token, check);
            }
            if let Some(initial) = given.first().and_then(|token| token.chars().next()) {
                add(
                    &mut out,
                    format!("{initial} {family_phrase}"),
                    NameCheck::Any,
                );
            }
            if let Some(initial) = family.first().and_then(|token| token.chars().next()) {
                add(
                    &mut out,
                    format!("{given_phrase} {initial}"),
                    NameCheck::Any,
                );
            }
            if given.len() >= 2 {
                add(&mut out, given_concat.clone(), NameCheck::Any);
                add(
                    &mut out,
                    format!("{given_concat} {family_phrase}"),
                    NameCheck::Any,
                );
            }
            if family.len() >= 2 {
                add(&mut out, family_concat.clone(), NameCheck::Any);
                add(
                    &mut out,
                    format!("{given_phrase} {family_concat}"),
                    NameCheck::Any,
                );
            }
            add(
                &mut out,
                format!("{given_concat}{family_concat}"),
                NameCheck::Any,
            );
            if let Some(first) = given.first() {
                add(&mut out, format!("{first} s"), NameCheck::Any);
            }
            add(&mut out, format!("d {family_phrase}"), NameCheck::Any);
            if family.len() >= 2 {
                add(&mut out, format!("d {family_concat}"), NameCheck::Any);
            }
        }
    }
    out
}

/// The spaced and glued spellings of an Arabic compound (`عبد الله` /
/// `عبدالله`), for the openers in [`ARABIC_COMPOUNDS`].
fn compound_variants(tokens: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    if tokens.len() >= 2 && ARABIC_COMPOUNDS.contains(&tokens[0]) {
        out.push(tokens.concat());
    }
    if tokens.len() == 1 {
        for opener in ARABIC_COMPOUNDS {
            if let Some(rest) = tokens[0].strip_prefix(opener) {
                if !rest.is_empty() {
                    out.push(format!("{opener} {rest}"));
                }
            }
        }
    }
    out
}

/// The index where the family run starts: the first particle after the first
/// token, or the last token when the entry has none.
fn family_split(tokens: &[&str]) -> usize {
    tokens
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, token)| is_particle(token))
        .map(|(index, _)| index)
        .unwrap_or(tokens.len() - 1)
}

/// Whether `token` is a particle that names nobody on its own.
fn is_particle(token: &str) -> bool {
    PARTICLES.contains(&token)
}
