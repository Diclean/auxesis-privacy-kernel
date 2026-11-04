//! Folded views for look-alike, full-width and invisible characters.
//!
//! The registry scans these in addition to the normalised view.

use std::sync::Arc;

use unicode_normalization::UnicodeNormalization;

use crate::contacts::fold::{homoglyph, is_cyrillic, is_greek};
use crate::decode;

use super::charset::{is_dash, is_unicode_space, is_zero_width};
use super::unicode_digit_value;
use super::{NormalizedText, MAX_FOLDED_RUN, RUN_BOUNDARY};

impl NormalizedText {
    /// The folded views the registry scans besides the text itself, so
    /// a value written with look-alike, full-width, mathematical or invisible
    /// characters is found by every recogniser, ASCII-only ones included:
    ///
    /// * invisible characters (ZWSP, ZWJ, WORD JOINER, BOM, soft hyphen) drop; a
    ///   run of more than [`MAX_FOLDED_RUN`] is a hard boundary;
    /// * Unicode digits, dashes, full-width letters and the mathematical and
    ///   letter-like alphanumerics (`𝐀`, `𝟏`, `ℎ`) read as ASCII;
    /// * full-width punctuation (`＠`, `：`, `．`) reads as ASCII only beside an
    ///   ASCII letter or digit, so Chinese prose keeps its own punctuation;
    /// * a Cyrillic or Greek look-alike (`о`, `а`, `ѕ`, `Α`) reads as its Latin
    ///   letter only in a whitespace-delimited token that holds at least as many
    ///   Latin letters and digits as Cyrillic and Greek letters, so Cyrillic and
    ///   Greek prose keep their letters;
    /// * a Unicode space (NBSP, U+2007, U+202F, U+3000) reads as a space. When
    ///   one sits between two ASCII letters or digits, a second view drops it,
    ///   so `dia betes` reads `diabetes` there.
    ///
    /// The map is exact: a span maps back to every original byte from its first
    /// to its last character, the dropped ones inside it included. Nothing
    /// folds in ASCII text, so it has no view and reads exactly as before.
    pub(crate) fn folded_views(text: &str) -> Vec<Self> {
        Self::fold_views(text, false)
    }

    /// Whether [`NormalizedText::glyph_views`] can read `text` differently from
    /// [`NormalizedText::folded_views`]: only a full-width `＆`, `＃` or `％` reads
    /// another way there.
    pub(crate) fn may_glyph_fold(text: &str) -> bool {
        text.contains(['\u{FF06}', '\u{FF03}', '\u{FF05}'])
    }

    /// The folded views with the glyph escape rule: a look-alike or
    /// full-width `x`, a full-width `＃` and full-width hex digits open an escape
    /// as their ASCII forms do ([`opens_escape_glyph`]). The registry scans these
    /// as an **extra** set of views and unions their spans with those of
    /// [`NormalizedText::folded_views`], which stay exactly as they were: decoding
    /// more filler loses word boundaries and whole-token masks the old views
    /// give, so the new rule may only add masks, never replace the old views.
    pub(crate) fn glyph_views(text: &str) -> Vec<Self> {
        Self::fold_views(text, true)
    }

    fn fold_views(text: &str, glyph: bool) -> Vec<Self> {
        if text.is_ascii() {
            return Vec::new();
        }
        let items: Vec<(usize, char, Fold)> = text
            .char_indices()
            .map(|(at, ch)| (at, ch, fold(ch)))
            .collect();
        let glyphs = latin_tokens(&items);
        // Whether each item reads as an ASCII letter or digit, then the nearest
        // such answer on each side, invisible characters skipped.
        let alnum: Vec<bool> = items
            .iter()
            .zip(&glyphs)
            .map(|(&(_, _, fold), &latin)| match fold {
                Fold::Keep(ch) => ch.is_ascii_alphanumeric(),
                Fold::Glyph(_) => latin,
                _ => false,
            })
            .collect();
        let side = |order: &mut dyn Iterator<Item = usize>| {
            let mut seen = vec![false; items.len()];
            let mut last = false;
            for index in order {
                seen[index] = last;
                if items[index].2 != Fold::Drop {
                    last = alnum[index];
                }
            }
            seen
        };
        let before = side(&mut (0..items.len()));
        let after = side(&mut (0..items.len()).rev());
        let inside = |index: usize| before[index] && after[index];
        let joins = (0..items.len()).any(|i| items[i].2 == Fold::Space && inside(i));
        let mut views = Vec::new();
        for join in [false, true].into_iter().take(1 + usize::from(joins)) {
            let mut chars = Vec::with_capacity(items.len());
            let mut bounds: Vec<(usize, usize)> = Vec::with_capacity(items.len());
            let mut run: Option<(usize, usize)> = None;
            for (index, &(at, ch, fold)) in items.iter().enumerate() {
                let end = at + ch.len_utf8();
                let mapped = match fold {
                    Fold::Drop => None,
                    Fold::Space if join && inside(index) => None,
                    Fold::Space => Some(' '),
                    Fold::Punct(ascii)
                        if before[index]
                            || after[index]
                            || if glyph {
                                opens_escape_glyph(index, ascii, &items, &glyphs)
                            } else {
                                opens_escape(index, ascii, &items)
                            } =>
                    {
                        Some(ascii)
                    }
                    Fold::Glyph(latin) if glyphs[index] => Some(latin),
                    Fold::Keep(mapped) => Some(mapped),
                    Fold::Punct(_) | Fold::Glyph(_) => Some(ch),
                };
                let Some(mapped) = mapped else {
                    let (first, count) = run.unwrap_or((at, 0));
                    run = Some((first, count + 1));
                    if count + 1 > MAX_FOLDED_RUN {
                        // Over the cap: the run is one boundary, no longer dropped.
                        if count == MAX_FOLDED_RUN {
                            chars.push(RUN_BOUNDARY);
                            bounds.push((first, end));
                        }
                        bounds.last_mut().expect("boundary pushed").1 = end;
                    }
                    continue;
                };
                run = None;
                chars.push(mapped);
                bounds.push((at, end));
            }
            let folded: String = chars.iter().collect();
            if folded != text {
                let char_starts = folded.char_indices().map(|(at, _)| at).collect();
                views.push(Self {
                    text: Arc::new(folded),
                    char_starts,
                    orig_bounds: bounds.into(),
                    identity: false,
                    compact: false,
                });
            }
        }
        views
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Fold {
    /// Invisible: dropped.
    Drop,
    /// A Unicode space.
    Space,
    /// Full-width punctuation: its ASCII form beside an ASCII letter or digit.
    Punct(char),
    /// A Cyrillic or Greek look-alike: its Latin letter in a Latin token.
    Glyph(char),
    /// Always read as this character.
    Keep(char),
}

fn fold(ch: char) -> Fold {
    if is_zero_width(ch) {
        return Fold::Drop;
    }
    if is_unicode_space(ch) {
        return Fold::Space;
    }
    if is_dash(ch) {
        return Fold::Keep('-');
    }
    if let Some(digit) = unicode_digit_value(ch) {
        return Fold::Keep(char::from(b'0' + digit as u8));
    }
    if matches!(ch as u32, 0xFF01..=0xFF5E | 0x2100..=0x214F | 0x1D400..=0x1D7FF) {
        let mut compat = std::iter::once(ch).nfkc();
        if let (Some(ascii), None) = (compat.next(), compat.next()) {
            if ascii.is_ascii_alphanumeric() {
                return Fold::Keep(ascii);
            }
            if ascii.is_ascii_graphic() {
                return Fold::Punct(ascii);
            }
        }
    }
    if is_cyrillic(ch) || is_greek(ch) {
        let mut lower = ch.to_lowercase();
        let single = lower.next().filter(|_| lower.next().is_none());
        if let Some(latin) = homoglyph(ch).or_else(|| single.and_then(homoglyph)) {
            let upper = ch.is_uppercase();
            return Fold::Glyph(if upper {
                latin.to_ascii_uppercase()
            } else {
                latin
            });
        }
    }
    Fold::Keep(ch)
}

/// Whether the full-width character at `index`, which reads as `ascii`, opens
/// an escape there — wherever it sits, and whether or not an ASCII letter or
/// digit stands beside it.
///
/// `＆#100;`, `＆#x41;` and `＆nbsp;` each begin an entity, `％41` a percent
/// escape. An escape that opens a value has a blank and a `#` beside it, never
/// the letter or digit the neighbour rule needs, so without this rule the escape
/// it begins is never decoded and the value stays in clear. A `＆` or `％` that
/// opens nothing is ordinary punctuation and stays: no Chinese sentence has
/// `＆#`, so the fold never reaches prose.
fn opens_escape(index: usize, ascii: char, items: &[(usize, char, Fold)]) -> bool {
    // The characters that follow, invisible ones skipped: they drop out of the
    // view, so none of them stands between a fold and the escape it opens.
    let mut after = items[index + 1..]
        .iter()
        .filter(|(_, _, fold)| *fold != Fold::Drop)
        .map(|&(_, ch, _)| ch);
    match ascii {
        // `&#100;` and `&#x41;`: a numeric reference, its `;` optional.
        '&' => match after.next() {
            Some('#') => after.next().is_some_and(|ch| ch.is_ascii_hexdigit()),
            // `&nbsp;`: a named reference reads to its `;`.
            Some(ch) if ch.is_ascii_alphabetic() => {
                let mut name = 1;
                while name < decode::MAX_ENTITY_BODY
                    && after.next().is_some_and(|ch| ch.is_ascii_alphanumeric())
                {
                    name += 1;
                }
                after.next() == Some(';')
            }
            _ => false,
        },
        // `％41`: a percent escape is two hex digits.
        '%' => {
            after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
                && after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
        }
        _ => false,
    }
}

/// [`opens_escape`] for the glyph views only: the escape is read as the folded view reads it ([`escape_read`]), so a
/// look-alike `x` (`＆#х73;`) or a look-alike hex digit opens it like the ASCII
/// one, and the full-width `＃` of `＆＃73;` folds with it.
fn opens_escape_glyph(
    index: usize,
    ascii: char,
    items: &[(usize, char, Fold)],
    latin: &[bool],
) -> bool {
    // The characters that follow, invisible ones skipped: they drop out of the
    // view, so none of them stands between a fold and the escape it opens.
    let mut after = items[index + 1..]
        .iter()
        .enumerate()
        .map(|(at, _)| index + 1 + at)
        .filter(|&at| items[at].2 != Fold::Drop)
        .map(|at| escape_read(at, items, latin));
    match ascii {
        // `&#100;`, `&#x41;` and `&#X41;`: a numeric reference, its `;` optional.
        // The body is one hex digit (decimal) or an `x` and one hex digit, read
        // off the same iterator so the `x` is not consumed twice.
        '&' => match after.next() {
            Some('#') => {
                let body = after.by_ref();
                let first = body.next();
                first.is_some_and(|ch| ch.is_ascii_hexdigit())
                    || matches!(first, Some('x' | 'X')
                        if body.next().is_some_and(|ch| ch.is_ascii_hexdigit()))
            }
            // `&nbsp;`: a named reference reads to its `;`.
            Some(ch) if ch.is_ascii_alphabetic() => {
                let mut name = 1;
                while name < decode::MAX_ENTITY_BODY
                    && after.next().is_some_and(|ch| ch.is_ascii_alphanumeric())
                {
                    name += 1;
                }
                after.next() == Some(';')
            }
            _ => false,
        },
        // `％41`: a percent escape is two hex digits.
        '%' => {
            after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
                && after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
        }
        // `＆＃100;`: the `#` of a reference is full-width too, and folds once
        // the ampersand before it has been shown to open the escape.
        '#' => {
            opens_reference(index, items, latin)
                && after.next().is_some_and(|ch| ch.is_ascii_hexdigit())
        }
        _ => false,
    }
}

/// How the character at `index` reads inside an escape: a full-width
/// punctuation as its ASCII form, a look-alike as its Latin letter where the
/// view folds it (a Latin token, the rule the glyph fold itself reads), and a
/// mapped character as what it maps to. Anything else reads as itself.
///
/// A `Fold::Drop` never reaches here: the callers skip those, exactly as they do
/// for the invisible characters between the two halves of an escape.
fn escape_read(index: usize, items: &[(usize, char, Fold)], latin: &[bool]) -> char {
    match items[index].2 {
        Fold::Glyph(letter) if latin[index] => letter,
        Fold::Keep(mapped) => mapped,
        Fold::Punct(mapped) => mapped,
        _ => items[index].1,
    }
}

/// Whether the character before `index`, invisible ones skipped, reads as the
/// ampersand of a reference. One backward step per caller, so the whole scan
/// stays linear.
fn opens_reference(index: usize, items: &[(usize, char, Fold)], latin: &[bool]) -> bool {
    items[..index]
        .iter()
        .rposition(|&(_, _, fold)| fold != Fold::Drop)
        .is_some_and(|at| escape_read(at, items, latin) == '&')
}

/// Per item, whether its whitespace-delimited token is Latin: it holds a Latin
/// letter or ASCII digit, and at least as many of them as Cyrillic and Greek
/// letters (look-alikes included). One pass per token: linear.
fn latin_tokens(items: &[(usize, char, Fold)]) -> Vec<bool> {
    let mut latin = vec![false; items.len()];
    let mut start = 0;
    let (mut ours, mut theirs) = (0usize, 0usize);
    for index in 0..=items.len() {
        let read = items.get(index).map(|&(_, ch, fold)| match fold {
            Fold::Space => ' ',
            Fold::Keep(mapped) => mapped,
            _ => ch,
        });
        match read {
            Some(ch) if !ch.is_whitespace() => {
                if ch.is_ascii_alphanumeric() || matches!(ch, '\u{C0}'..='\u{24F}') {
                    ours += 1;
                } else if is_cyrillic(ch) || is_greek(ch) {
                    theirs += 1;
                }
            }
            _ => {
                let is_latin = ours > 0 && ours >= theirs;
                latin[start..index].iter_mut().for_each(|at| *at = is_latin);
                start = index + 1;
                (ours, theirs) = (0, 0);
            }
        }
    }
    latin
}
