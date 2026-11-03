//! Signature/header context, vocative position and the other span predicates.

use crate::decode::DecodedText;
use crate::name_lexicon;
use crate::public_terms::fold;
use crate::span::{EntityKind, Span};

use super::cues::{ADDRESS_THANKS, CLAUSE_MARKS, REPLY_VERBS, SENDER_KEYS, SPEECH_VERBS, TITLES};
use super::display::{is_closing, starts_with_greeting};
use super::lines::{
    is_all_caps_surname, is_word_separator, preceded_by_honorific, strip_quote_prefix, word_tokens,
};
use super::nameset::NameSet;
use super::RULE_SCORE;

/// Whether a kind is a private signal that keeps public-term model spans.
pub(super) fn is_private_signal(kind: EntityKind) -> bool {
    !matches!(
        kind,
        EntityKind::Organization | EntityKind::Address | EntityKind::Url
    )
}

/// Whether a span lies inside `text` on char boundaries.
pub(super) fn well_formed(text: &str, span: &Span) -> bool {
    span.start < span.end
        && span.end <= text.len()
        && text.is_char_boundary(span.start)
        && text.is_char_boundary(span.end)
}

/// Push a person span mapped back to the original bytes.
pub(super) fn push_person(
    decoded: &DecodedText,
    start: usize,
    end: usize,
    recognizer: &'static str,
    spans: &mut Vec<Span>,
) {
    if let Some((orig_start, orig_end)) = decoded.source_bounds(start, end) {
        spans.push(Span::new(
            EntityKind::Person,
            orig_start,
            orig_end,
            RULE_SCORE,
            recognizer,
        ));
    }
}

/// Whether the byte range `start..end` sits on a signature or header line.
///
/// Signature and header context always keeps a span, whatever its token count:
/// a sender or recipient header (`From`, `To`, `Cc`, `De`, `Van`, `Von`, `От`,
/// `Feladó`, `من`, `发件人`), a reply or speech line (`a écrit`, `wrote:`, `said`),
/// a `Name <email>` display name, or a line inside a signature block (a closing
/// or a `--` separator in the lines above).
pub(super) fn is_signature_or_header_range(text: &str, start: usize, end: usize) -> bool {
    if start >= end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return false;
    }
    let line_start = text[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let line_end = text[start..]
        .find('\n')
        .map(|at| start + at)
        .unwrap_or(text.len());
    let line = &text[line_start..line_end];
    // A `P.S.` / `PS` / `NB` author is a signature name, whatever the line says.
    if is_ps_or_nb_line(line) {
        return true;
    }
    let body = &line[strip_quote_prefix(line)..];
    let lowered = body.to_lowercase();
    if SENDER_KEYS.iter().any(|key| {
        lowered
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    }) {
        return true;
    }
    if REPLY_VERBS
        .iter()
        .copied()
        .chain(SPEECH_VERBS.iter().map(|(verb, _)| *verb))
        .any(|verb| lowered.contains(verb))
    {
        return true;
    }
    // A `Name <local@domain>` display name: the span is the name before the
    // angle address, even without a header key.
    let before_angle_address = body.find('<').is_some_and(|angle| {
        body[angle..].contains('@') && end <= line_start + strip_quote_prefix(line) + angle
    });
    if before_angle_address {
        return true;
    }
    // A signature block: a closing line or a `--` separator in the lines above.
    // GATE-PERF-1: walk up from this line instead of splitting the whole text,
    // so a text of many short lines costs linear time, not lines × bytes.
    let mut seen = 0usize;
    let mut cursor = line_start;
    while cursor > 0 {
        let line_end_above = cursor - 1;
        let line_start_above = text[..line_end_above].rfind('\n').map_or(0, |at| at + 1);
        cursor = line_start_above;
        let candidate = text[line_start_above..line_end_above].trim();
        if candidate.is_empty() {
            continue;
        }
        seen += 1;
        if seen > 6 {
            break;
        }
        if matches!(candidate, "--" | "---" | "—" | "––")
            || (word_tokens(candidate).len() <= 6 && is_closing(candidate))
            || is_ps_or_nb_line(candidate)
        {
            return true;
        }
    }
    false
}

/// Whether the lone name `start..end` may stay in clear under the default
/// (first-names-off) policy.
///
/// The lexicons alone are not evidence enough. A lone token is left in clear
/// only when **all** of these hold:
///
/// * it is a known given name in the closed lexicon and **not** a known surname
///   (the surname list carries every verified given/surname collision);
/// * it sits in a vocative or address position ([`super::signals::in_vocative_or_address`]):
///   right after a greeting or a thanks word that closes its clause, or at the
///   start of a line followed by a comma;
/// * it is not on a signature or header line (`From`/`To`/`Cc`, a reply line, a
///   closing block, a `Name <email>` pair, a `P.S.`/`PS`/`NB` author);
/// * it is not ALL-CAPS, not honorific-led, not a surname a strong seed already
///   carries, and not CJK.
///
/// Everywhere else the span is masked, whatever the lexicons say: running text,
/// an NER singleton outside a vocative position, and a rule token the given-name
/// lexicon does not know.
pub(super) fn leaves_lone_name_in_clear(
    text: &str,
    start: usize,
    end: usize,
    names: &NameSet<'_>,
) -> bool {
    if start >= end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return false;
    }
    let raw = &text[start..end];
    if is_cjk_script(raw)
        || is_all_caps_surname(raw)
        || preceded_by_honorific(text, start)
        || is_signature_or_header_range(text, start, end)
    {
        return false;
    }
    let folded = fold(raw);
    if names.is_always(&folded) || name_lexicon::is_surname(&folded) {
        return false;
    }
    name_lexicon::is_given_name(&folded) && in_vocative_or_address(text, start, end)
}

/// Whether `start..end` is a vocative or address position: right after a
/// greeting or a thanks word that closes its clause (`Salut Jules`, `Hi Mila,`,
/// `merci Mila`), or at the start of a line followed by a comma (`Jules, peux-tu`).
///
/// A greeting or thanks word followed by a sentence (`Hi, Mila was called`,
/// `Hello Mila said`) is not an address: the name is the subject of that sentence
/// and stays masked. A `P.S.`, `PS` or `NB` author is a signature line, not a
/// vocative, so it never reaches this check (see [`is_ps_or_nb_line`]).
fn in_vocative_or_address(text: &str, start: usize, end: usize) -> bool {
    let line_start = text[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let before = &text[line_start..start];
    let offset = strip_quote_prefix(before);
    let lead = &before[offset..];
    if preceded_by_address_lead(lead) && closes_address_clause(text, end) {
        return true;
    }
    // A name that opens the line and is followed by a comma (`Jules, peux-tu`).
    if lead.trim().is_empty() {
        let after = text[end..].trim_start_matches([' ', '\t']);
        if after.starts_with(',') || after.starts_with('\u{060C}') {
            return true;
        }
    }
    false
}

/// Whether the name ending at `end` closes its greeting or thanks clause: the
/// rest of its line is empty, or it is followed by a clause mark (`,` `!` `:`
/// `;` `.` `?`, or their CJK and Arabic forms). Any other word after the name
/// continues the sentence, so the name is its subject, not its addressee.
fn closes_address_clause(text: &str, end: usize) -> bool {
    let rest = text[end..].trim_start_matches([' ', '\t']);
    rest.chars()
        .next()
        .is_none_or(|ch| CLAUSE_MARKS.contains(ch))
}

/// Whether `line` is a `P.S.`, `PS` or `NB` line: a postscript or note whose
/// author is a signature name, so a name on it always stays masked.
pub(super) fn is_ps_or_nb_line(line: &str) -> bool {
    ps_marker_end(line).is_some()
}

/// The byte offset in `line` just past its `P.S.` / `PS` / `NB` marker (quote
/// prefix and indent included), or `None`. The marker must end at a word
/// boundary, so `Psychologue` is not a postscript.
pub(super) fn ps_marker_end(line: &str) -> Option<usize> {
    let indent = strip_quote_prefix(line);
    let lowered = line[indent..].to_lowercase();
    ["p.s.", "p.s", "ps", "nb"]
        .into_iter()
        .find(|marker| {
            lowered
                .strip_prefix(marker)
                .is_some_and(|after| after.chars().next().is_none_or(|ch| !ch.is_alphanumeric()))
        })
        .map(|marker| indent + marker.len())
}

/// Whether `lead` (the text before a name on its line, quote prefix removed) is a
/// greeting or a thanks word followed only by separators.
fn preceded_by_address_lead(lead: &str) -> bool {
    let trimmed = lead.trim_end();
    if trimmed.is_empty() {
        return false;
    }
    if let Some(greeting_end) = starts_with_greeting(trimmed) {
        let after = &trimmed[greeting_end..];
        if after.chars().all(|ch| {
            ch.is_whitespace() || matches!(ch, ',' | ':' | ';' | '.' | '!' | '?' | '-' | '–' | '—')
        }) {
            return true;
        }
    }
    let folded = fold(trimmed);
    if ADDRESS_THANKS
        .iter()
        .filter_map(|thanks| folded.strip_suffix(*thanks))
        .any(|prefix| {
            prefix
                .chars()
                .next_back()
                .is_none_or(|ch| !ch.is_alphanumeric())
        })
    {
        return true;
    }
    false
}

/// Whether `raw` holds a Han, CJK or Hangul character.
///
/// A `PERSON` span in one of these scripts is a full name or a surname the
/// bare-first-name rule cannot read, so it is always kept; so is a single Han
/// character that follows an honorific (`preceded_by_honorific`).
fn is_cjk_script(raw: &str) -> bool {
    raw.chars().any(|ch| {
        matches!(
            ch as u32,
            0x1100..=0x11FF   // Hangul Jamo
                | 0x2E80..=0x2EFF // CJK radicals
                | 0x3000..=0x303F // CJK punctuation
                | 0x3040..=0x30FF // Hiragana / Katakana
                | 0x3130..=0x318F // Hangul compatibility Jamo
                | 0x3400..=0x4DBF // CJK extension A
                | 0x4E00..=0x9FFF // CJK unified ideographs
                | 0xAC00..=0xD7AF // Hangul syllables
                | 0xF900..=0xFAFF // CJK compatibility ideographs
                | 0x20000..=0x2FA1F // CJK extensions B..F
        )
    })
}

/// Whether a folded token is an honorific a name may follow.
pub(super) fn is_honorific(folded: &str) -> bool {
    folded == "m" || TITLES.iter().any(|title| fold(title) == folded)
}

/// Whether the bytes between two token bounds are only the short separators that
/// join a given name to its surname.
pub(super) fn joined_by_separator(text: &str, from: usize, to: usize) -> bool {
    from <= to
        && text.is_char_boundary(from)
        && text.is_char_boundary(to)
        && text[from..to].chars().all(is_word_separator)
}
