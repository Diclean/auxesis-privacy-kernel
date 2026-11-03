//! Explicit NI labels and the aside a label may carry (ID-LABEL-2).

/// Explicit NI labels, folded to lower case: after one, a loose number in
/// mixed case or after a short word, suffix glued, is the value (seal A r1).
const NI_LABELS: &[&str] = &[
    "national insurance number",
    "national insurance no",
    "ni number",
    "ni no",
    "nino",
];

/// Whether an [`NI_LABELS`] label, not glued to a letter or digit before it,
/// ends right before char `at`, past up to twelve blanks, `:`, `#`, `=`, `.`,
/// `,` or `-` with at most one line break among them (ID-LABEL-2: `NI number:\n…`,
/// `NI number:      …`). It reads at most forty characters back: linear.
pub(super) fn ni_labelled(chars: &[(usize, char)], at: usize) -> bool {
    let run = || {
        chars[..at].iter().rev().take(13).take_while(|&&(_, c)| {
            matches!(
                c,
                ' ' | '\t' | '\u{a0}' | ':' | '#' | '=' | '.' | ',' | '-' | '\r' | '\n'
            )
        })
    };
    let link = run().count();
    if link == 0 || link > 12 || run().filter(|&&(_, c)| c == '\n').count() > 1 {
        return false;
    }
    let end = aside_start(chars, at - link);
    NI_LABELS.iter().any(|label| {
        let len = label.chars().count();
        end >= len
            && chars[end - len..end]
                .iter()
                .map(|&(_, c)| c.to_ascii_lowercase())
                .eq(label.chars())
            && !(end > len && chars[end - len - 1].1.is_alphanumeric())
    })
}

/// Where an NI label ends when one short aside closes right before `end`
/// (`NI number (if applicable): …`, ID-LABEL-2 r1): one to thirty letters,
/// blanks, `'`, `-` or `/` in parentheses, and up to three blanks before them.
/// `end` itself when there is none. At most thirty-five characters back.
fn aside_start(chars: &[(usize, char)], end: usize) -> usize {
    if end == 0 || chars[end - 1].1 != ')' {
        return end;
    }
    let inner = chars[..end - 1]
        .iter()
        .rev()
        .take(31)
        .take_while(|&&(_, c)| c.is_alphabetic() || matches!(c, ' ' | '\'' | '’' | '-' | '/'))
        .count();
    let open = end - 1 - inner;
    if inner == 0 || inner > 30 || open == 0 || chars[open - 1].1 != '(' {
        return end;
    }
    if !chars[open..end - 1].iter().any(|&(_, c)| c.is_alphabetic()) {
        return end;
    }
    let blanks = chars[..open - 1]
        .iter()
        .rev()
        .take(4)
        .take_while(|&&(_, c)| matches!(c, ' ' | '\t'))
        .count();
    if blanks > 3 {
        return end;
    }
    open - 1 - blanks
}
