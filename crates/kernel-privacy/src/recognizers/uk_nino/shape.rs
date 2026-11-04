//! The byte shapes a number may take, and the tests both passes share.

use crate::normalize::NormalizedText;

use super::separated::separated_shape_at;

/// The offset one past the six digits of a National Insurance number that starts
/// at `start`: two prefix letters HMRC can issue, then three pairs of digits
/// with at most one space or hyphen at each boundary. No suffix letter, so this
/// also reads a number whose own suffix is glued to a value, which only the
/// residue round sees whole (NINO-GLUED-NEXT). At most eleven bytes (linear
/// scan).
pub(super) fn head_at(bytes: &[u8], start: usize) -> Option<usize> {
    let letter = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_alphabetic);
    let digit = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_digit);
    if !(letter(start) && letter(start + 1)) || !prefix_allowed(bytes[start], bytes[start + 1]) {
        return None;
    }
    let mut index = start + 2;
    for _ in 0..3 {
        if matches!(bytes.get(index), Some(b' ' | b'-')) {
            index += 1;
        }
        if !(digit(index) && digit(index + 1)) {
            return None;
        }
        index += 2;
    }
    Some(index)
}

/// Whether the normalised separator at `index` came from a run that held a line
/// break in `text`. One binary search per call, so a scan stays
/// linear-logarithmic in the length of its input. Read only where a suffix
/// letter is glued to a following letter (NINO-NEWLINE-SUFFIX).
pub(super) fn broke_line(text: &str, view: &NormalizedText, index: usize) -> bool {
    view.to_original(index, index + 1)
        .is_some_and(|(start, end)| crate::normalize::holds_line_break(&text[start..end]))
}

/// Whether a National Insurance number starts at `at`, in every shape this file
/// reads: the compact and single-separator shapes of [`head_at`] and the
/// separated shapes of [`separated_shape_at`](super::separated::separated_shape_at) (one to three spaces, or one `-`,
/// `/` or `.`, in any case). One predicate for the one question the glue rule
/// asks, so the suffix letter is kept only where the residue round really will
/// read a number from it.
///
/// It must be a superset of what either pass reads there, never a subset: a
/// second pattern list that read only single spaces and hyphens let the suffix
/// swallow the first letter of every other shape, and the number behind that
/// letter was then no number at all and stood in clear,
/// `AB 12 34 56\nCB/12/34/56/A`). So neither rule on what *follows* a number —
/// the digit glued to its suffix, the capitals the separated pass asks for — is
/// Both only narrow what a pass reads, and narrowing here would eat a letter
/// that opens a line some pass still reads. At most twenty-one bytes per try
/// (linear scan), and it is only reached where a suffix is already glued.
pub(super) fn number_starts_at(bytes: &[u8], at: usize) -> bool {
    head_at(bytes, at).is_some() || separated_shape_at(bytes, at).is_some()
}

/// Whether the two letters of a National Insurance number are a HMRC prefix that
/// can be issued. The first letter is not D, F, I, Q, U or V; the second is not D,
/// F, I, O, Q, U or V; and BG, GB, NK, KN, TN, NT and ZZ are refused. QQ is the
/// HMRC documentation example, and it is masked as a real shape (K13).
pub(super) fn prefix_allowed(first: u8, second: u8) -> bool {
    let pair = [first.to_ascii_uppercase(), second.to_ascii_uppercase()];
    if &pair == b"QQ" {
        return true;
    }
    !(b"DFIQUV".contains(&pair[0])
        || b"DFIOQUV".contains(&pair[1])
        || matches!(&pair, b"BG" | b"GB" | b"NK" | b"KN" | b"TN" | b"NT" | b"ZZ"))
}
