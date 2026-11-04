//! Code rows after a recovery-code key: list items and table cells.

use super::runs::{code_run, RecoveryRun};
use super::value::bounded;

/// Bullets a list item of codes may start with.
const BULLETS: &[char] = &['-', '*', '+', '•', '◦', '‣', '–'];

/// The length of the list marker that starts `item` (`- `, `• `, `1. `, `1) `),
/// the blanks after it and a checkbox (`[ ] `), or `None`.
fn marker(item: &str) -> Option<usize> {
    let digits = item.bytes().take(4).take_while(u8::is_ascii_digit).count();
    let numbered = matches!(item.as_bytes().get(digits), Some(b'.' | b')'));
    let bullet = item.chars().next().filter(|ch| BULLETS.contains(ch));
    let mark = match digits {
        1..=3 if numbered => digits + 1,
        _ => bullet?.len_utf8(),
    };
    let rest = &item[mark..];
    let gap = rest.len() - rest.trim_start_matches([' ', '\t']).len();
    let rest = &rest[gap..];
    let boxed = ["[ ] ", "[x] ", "[X] "].iter().any(|b| rest.starts_with(b));
    (gap > 0).then_some(mark + gap + if boxed { 4 } else { 0 })
}

/// The [`code_run`](super::runs::code_run) of each cell of `line`, which starts at `at`: after each
/// `|`, tab, and comma with no blank after it, or a comma after an active
/// recovery-code run. Returns where the last run ended, or `None` with no cell.
fn cells(
    text: &str,
    at: usize,
    line: &str,
    recovery_codes: bool,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> Option<usize> {
    let mut done = None;
    for (cut, sep) in line.match_indices(['|', '\t', ',']) {
        let cell = &line[cut + 1..];
        let blank = cell.len() - cell.trim_start_matches([' ', '\t']).len();
        let cue_comma = sep == ","
            && line[..cut]
                .trim_matches([' ', '\t', ':', '=', ',', '：'])
                .is_empty();
        let comma_cell = sep == ","
            && !cue_comma
            && (blank == 0 && !cell.is_empty() || recovery_codes && recovery.active());
        if sep != "," || comma_cell {
            done = done.max(Some(code_run(
                text,
                at + cut + 1 + blank,
                false,
                recovery_codes,
                recovery,
                spans,
            )));
        }
    }
    done
}

/// The code rows after a recovery-code key ending at `from`.
/// In a table row (`| Recovery codes | 7KQ2-9XZ1 |`) the [`cells`] after the
/// key are read; when the key ends its line or a `:` header (`Backup codes:`),
/// each next list item (`- `, `• `, `1. `, `- [ ] `) or row of cells is read
/// too. One blank line may follow the key; a later one or any other line ends
/// the rows. Returns where the scan stopped (linear: a row is read once, a key
/// line at most [`MAX_WORD`](super::keys::MAX_WORD) bytes).
pub(super) fn row_runs(
    text: &str,
    from: usize,
    recovery: &mut RecoveryRun,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let head = bounded(text, from);
    let (head, ends) = head
        .split_once('\n')
        .map_or((head, false), |(line, _)| (line, true));
    let bare = head.trim().trim_matches(['*', '_', '#']);
    let done = cells(text, from, head, true, recovery, spans);
    if done.is_none() && !(bare.is_empty() || bare.ends_with([':', '：'])) {
        return from;
    }
    let mut done = done.unwrap_or(from);
    if !ends {
        return done;
    }
    let (mut at, mut first) = (from + head.len() + 1, true);
    while at < text.len() {
        let line_end = text[at..].find('\n').map_or(text.len(), |len| at + len);
        let line = text[at..line_end].trim_end_matches('\r');
        let lead = line.len() - line.trim_start().len();
        let item = marker(&line[lead..]);
        let celled = cells(text, at, line, true, recovery, spans);
        if item.is_none() && celled.is_none() && !(first && line.trim().is_empty()) {
            break;
        }
        if let Some(skip) = item {
            code_run(text, at + lead + skip, false, true, recovery, spans);
        }
        (done, first) = (line_end, false);
        at = line_end + 1;
    }
    done
}
