//! Blood groups and the blood-column scan.

use crate::span::{EntityKind, Span};

use super::lexicon::is_blood_label;
use super::recognizer::NAME;
use super::table::cells;
use super::text::{ends_word, fold};

/// Longest ASCII tag glued to a blood label or sign (`ref`, `ok`), HEALTH-LABEL-1.
const MAX_TAG: usize = 4;
/// Rows read under a blood-group column header.
pub(super) const MAX_ROWS: usize = 10_000;
/// Longest header line a blood column is read under, in bytes.
const MAX_HEADER: usize = 4_096;

const BLOOD_SIGNS: &str = "positive positif positiv pozitiv pozitivna pozitiven pos negative \
    negatif negativ negativna negativen neg 阳性 阴性";

/// The end of a blood group at `start` (`O negative`, `AB+`, `A型Rh阴性`); a bare
/// group counts only after a strong link and in capitals (`Blood type: O`).
pub(super) fn blood(text: &str, start: usize, strong: bool) -> Option<usize> {
    let rest = &text[start..];
    let group = ["AB", "ab", "A", "B", "O", "0", "a", "b", "o"]
        .into_iter()
        .find(|g| rest.starts_with(g))?;
    let mut at = group.len();
    if !ends_word(&rest[at..]) && !rest[at..].starts_with(['+', '-', '−']) {
        return None;
    }
    let bare = (strong && group.chars().all(|c| !c.is_lowercase())).then_some(start + at);
    at += rest[at..].strip_prefix('型').map_or(0, |_| '型'.len_utf8());
    // The sign, read on a short folded view (accents, case, Unicode blanks) whose map
    // leads back to the original end.
    let view = &rest[at..rest.floor_char_boundary(at + 48)];
    let (folded, map) = fold(view);
    // Blanks before the sign, across one line break (`AB\r\nnegative`, HEALTH-LABEL-1).
    let skip = |f: usize| {
        let mut breaks = 0;
        f + folded[f..]
            .find(|c: char| {
                breaks += usize::from(c == '\n');
                !c.is_whitespace() || breaks > 1
            })
            .unwrap_or(folded.len() - f)
    };
    // A `-` sign reads as a blank once folded, so it is looked for in the raw view
    // right after the group or `Rh` (`AB-`, `O Rh-`); a `-` before a letter is a
    // hyphen (`A-negative`) and goes on to the sign word (HEALTH-LABEL).
    let dash = |f: usize| {
        let raw = &view[map[f]..];
        (raw.starts_with('-') && !raw[1..].starts_with(char::is_alphanumeric))
            .then_some(start + at + map[f] + 1)
    };
    let mut early = dash(0);
    let mut f = skip(0);
    if folded[f..].starts_with("rh") {
        let after = f + if folded[f..].starts_with("rhd") { 3 } else { 2 };
        early = early.or(dash(after));
        f = skip(after);
    }
    if view[map[f]..].starts_with(['+', '-', '−']) {
        return Some(start + at + map[f] + view[map[f]..].chars().next().map_or(0, char::len_utf8));
    }
    // A whole sign word may carry a short glued tag (`negativeok`, HEALTH-LABEL-1).
    let sign = BLOOD_SIGNS.split(' ').find_map(|sign| {
        let rest = folded[f..].strip_prefix(sign)?;
        // An adverb is no tag (`negatively`, `positively`).
        let tag = rest.bytes().take_while(u8::is_ascii_alphanumeric).count();
        if tag > MAX_TAG || tag > 0 && rest[..tag].ends_with("ly") {
            return None;
        }
        ends_word(&rest[tag..]).then_some(sign.len() + tag)
    });
    // The longer reading wins, so a value main read whole is never cut short.
    sign.map_or(bare, |len| Some(start + at + map[f + len]))
        .max(early)
}

/// The end of a blood group glued to its label at `from`, behind at most
/// [`MAX_TAG`] ASCII letters or digits (`Blood typeAB-`, `Blood typerefAB
/// negative`). The group must carry its sign.
pub(super) fn glued_blood(text: &str, from: usize) -> Option<usize> {
    let tag = text[from..]
        .bytes()
        .take_while(u8::is_ascii_alphanumeric)
        .count();
    (0..=tag.min(MAX_TAG)).find_map(|skip| blood(text, from + skip, false))
}

/// The cells under every blood-group column of the header holding the label at
/// `start..end` (`id,blood_type,city` then `17,AB negative,Lyon`), HEALTH-LABEL-1.
/// The label must fill its cell; the delimiter is `,`, `;`, a tab or `|`. At most
/// [`MAX_ROWS`] rows are read, up to a blank line; the rows read end at `rows`,
/// and a header before that is skipped.
pub(super) fn blood_column(
    text: &str,
    (start, end): (usize, usize),
    (line_start, line_end): (usize, usize),
    rows: &mut usize,
) -> Vec<Span> {
    if line_start < *rows || line_end - line_start > MAX_HEADER {
        return Vec::new();
    }
    let before = text[line_start..start]
        .trim_end_matches([' ', '"'])
        .chars()
        .next_back();
    let after = text[end..line_end]
        .trim_start_matches([' ', '"', '\r'])
        .chars()
        .next();
    let delimiter = match (before, after) {
        (_, Some(d @ (',' | ';' | '\t' | '|'))) | (Some(d @ (',' | ';' | '\t' | '|')), None) => d,
        _ => return Vec::new(),
    };
    if before.is_some_and(|b| b != delimiter) {
        return Vec::new();
    }
    let (header, _) = cells(text, line_start, delimiter);
    let columns: Vec<usize> = (0..header.len())
        .filter(|&n| is_blood_label(&text[header[n].0..header[n].1]))
        .collect();
    let mut spans = Vec::new();
    let mut at = line_end;
    for _ in 0..MAX_ROWS {
        if at >= text.len() {
            break;
        }
        let (row, row_end) = cells(text, at + 1, delimiter);
        if text[at + 1..row_end].trim().is_empty() {
            break;
        }
        at = row_end;
        for &(cell_start, cell_end) in columns.iter().filter_map(|&n| row.get(n)) {
            if cell_start < cell_end
                && blood(text, cell_start, true).is_some_and(|value| value >= cell_end)
            {
                spans.push(Span::new(
                    EntityKind::Health,
                    cell_start,
                    cell_end,
                    1.0,
                    NAME,
                ));
            }
        }
    }
    *rows = at;
    spans
}
