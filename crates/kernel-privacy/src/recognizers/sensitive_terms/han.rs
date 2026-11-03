//! Han terms and Han disease names.

use crate::span::{EntityKind, Span};

use super::disease::health;
use super::lexicon::Hit;
use super::text::{is_han, HanView};
use super::{NAME, SCORE};

/// Han disease words that end a disease name, with the anchor each one asks
/// for: 晨雾热 is a fever word and needs a health anchor in its sentence
/// (天气热 is the weather), 灰羽病, 晨雾症 and 综合征 are disease words and do
/// not.
const HAN_DISEASE_ENDS: &[(char, bool)] =
    &[('热', true), ('病', false), ('症', false), ('征', false)];

/// Han characters that never start a two-character disease name: degree words,
/// verbs and particles (很热, 生病, 看病, 毛病).
const HAN_NOT_A_NAME: &[char] = &[
    '很', '太', '真', '好', '挺', '更', '最', '超', '不', '怪', '蛮', '较', '特', '发', '生', '看',
    '得', '患', '有', '的', '了', '在', '做', '是', '和', '与', '毛', '气', '天',
];

/// Han characters that may follow a disease name: particles and conjunctions.
const HAN_AFTER_NAME: &[char] = &['的', '了', '和', '与', '及', '等', '请', '复', '已', '又'];

/// Push the two-character Han names a disease word ends (晨雾热). A `病`, `症` or
/// `综合征` hit stands on its own; a `热` hit stands only when a health term or
/// cue shares its sentence.
pub(super) fn push_han_disease_names(view: &HanView, text: &str, out: &mut Vec<Hit>) {
    let chars: Vec<(usize, char)> = view.text.char_indices().collect();
    for at in 2..chars.len() {
        let (end_at, end) = chars[at];
        let Some(&(_, contextual)) = HAN_DISEASE_ENDS.iter().find(|(ch, _)| *ch == end) else {
            continue;
        };
        // `综合征` ends in 征, a common word (征收, 应征): it is a disease word
        // only after 综合, and the name is then the three characters.
        let first = if end == '征' {
            (at >= 2 && chars[at - 2].1 == '综' && chars[at - 1].1 == '合').then_some(at - 2)
        } else {
            Some(at - 2)
        };
        let Some(first) = first else { continue };
        let heads = [chars[first].1, chars[first + 1].1];
        if !heads
            .iter()
            .all(|&ch| is_han(ch) && !HAN_NOT_A_NAME.contains(&ch))
        {
            continue;
        }
        let Some((from, to)) = view.original(chars[first].0, end_at + end.len_utf8()) else {
            continue;
        };
        let next = text[to..].chars().next();
        if next.is_some_and(|ch| is_han(ch) && !HAN_AFTER_NAME.contains(&ch)) {
            continue;
        }
        out.push(health(from, to, contextual, "zh"));
    }
}

/// Whether an ambiguous abbreviation is a date: a day or a year sits next to it
/// (`12 SEP 2025`, `SEP 12`), so it is a month, not the disease.
pub(super) fn dated(text: &str, span: Span) -> bool {
    let is_space = |ch: char| ch == ' ' || ch == '\u{a0}';
    let after = text[span.end..].trim_start_matches(is_space).chars().next();
    let before = text[..span.start]
        .trim_end_matches(is_space)
        .chars()
        .next_back();
    after.is_some_and(|ch| ch.is_ascii_digit()) || before.is_some_and(|ch| ch.is_ascii_digit())
}

/// Push the Han terms found in the view, mapped back to the original text. A
/// match that an exception's suffix follows is skipped.
pub(super) fn push_han(
    view: &HanView,
    terms: &[(String, EntityKind)],
    except: &[(String, String)],
    out: &mut Vec<Hit>,
) {
    for (term, kind) in terms {
        for (start, matched) in view.text.match_indices(term.as_str()) {
            let end = start + matched.len();
            let excepted = except.iter().any(|(excepted, suffix)| {
                excepted == term && view.text[end..].starts_with(suffix.as_str())
            });
            if excepted {
                continue;
            }
            if let Some((from, to)) = view.original(start, end) {
                out.push(Hit {
                    span: Span::new(*kind, from, to, SCORE, NAME),
                    contextual: false,
                    lang: "zh",
                });
            }
        }
    }
}
