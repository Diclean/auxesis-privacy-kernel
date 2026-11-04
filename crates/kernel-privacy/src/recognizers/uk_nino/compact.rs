//! The compact pass, and the read table a chain of numbers is proved from.

use crate::normalize::NormalizedText;

use super::separated::{separated_nino_at, separated_shape_at};
use super::shape::{broke_line, head_at, number_starts_at};

/// A National Insurance number, with no checksum: two letters, six digits and a
/// suffix letter A to D. Each pair boundary may hold one space or hyphen, in any
/// mix. It runs on the normalised view, so NBSP and fullwidth forms fold first.
/// A number starts only where no ASCII letter or digit precedes it — except on
/// the offsets a number just read left open ([`opens_another`]) — and ends only
/// where none follows; an underscore or a combining mark is no part of it.
/// Every such start is tried on its own, so a rejected shape never hides the
/// number after it, and each try reads at most thirteen bytes (linear scan).
///
/// A suffix letter glued to a following letter or digit is refused, unless a
/// number's shape starts at that letter, a pass reads another number within
/// three bytes behind it ([`read_near`]), or a line break sits
/// before it. In the first case the
/// letter is kept and the caller reads the next number from there as well
/// where that number starts at the letter, the two spans overlap
/// and [`union`](super::recognizer::union) makes them one, so neither number gives a byte to the other
/// (`AB 12 34 56\ncb123456a` left its head in clear: this rule refused it, and
/// the separated cut needs capitals). In the second, the letter opens the next line,
/// so it is masked with this number, which makes the next line a word again, so
/// its label still matches and the value behind it stays masked
/// its label still matches and the value behind it stays masked.
///
/// A whole number at that letter that no pass reads on its own (its suffix is
/// glued to an IBAN or a key) is read with this one, to its own suffix
/// ([`glued_next_end`]): taking only its first letter left
/// `l 05 51 39 d` in clear in `ak 67 18 39\r\nbl 05 51 39 dGB82…`, where main
/// left the letter to the residue round. Open mode has no residue round, so
/// the chain is read whole in the first.
pub(super) fn nino_at(
    bytes: &[u8],
    start: usize,
    text: &str,
    view: &NormalizedText,
    reads: &[bool],
) -> Option<usize> {
    let separator = |index: usize| matches!(bytes.get(index), Some(b' ' | b'-'));
    let mut index = head_at(bytes, start)?;
    let (before, spaced) = (index, separator(index));
    index += usize::from(spaced);
    let suffix = index;
    if !matches!(bytes.get(index), Some(b'A'..=b'D' | b'a'..=b'd')) {
        return None;
    }
    index += 1;
    if bytes.get(index).is_some_and(u8::is_ascii_alphanumeric) {
        if let Some(next) = glued_next_end(bytes, suffix, reads) {
            return Some(next);
        }
        let near = number_starts_at(bytes, suffix) || read_near(reads, suffix).is_some();
        if !near && !(spaced && broke_line(text, view, before)) {
            return None;
        }
    }
    Some(index)
}

/// The offset one past the suffix letter of a whole number — prefix, six
/// digits and a suffix letter A to D — that starts at `at` where no pass reads
/// it on its own: its suffix is glued to a value (an IBAN, a key). The number
/// whose suffix letter is its first letter reads it with itself: a chain is
/// evidence of its own. A shape with no suffix letter is no
/// number in any round, so the number before it keeps only the letter, as on
/// main. At most thirty-four bytes.
pub(super) fn glued_next_end(bytes: &[u8], at: usize, reads: &[bool]) -> Option<usize> {
    if read_at(reads, at) {
        return None;
    }
    let compact = head_at(bytes, at).and_then(|end| {
        let end = end + usize::from(matches!(bytes.get(end), Some(b' ' | b'-')));
        matches!(bytes.get(end), Some(b'A'..=b'D' | b'a'..=b'd')).then_some(end + 1)
    });
    compact.max(separated_shape_at(bytes, at).map(|shape| shape.end))
}

/// Whether a pass reads a National Insurance number at `at` ([`nino_at`] or
/// [`separated_nino_at`](super::separated::separated_nino_at), start rule waived), from the table [`reads_table`]
/// fills. `false` past the end.
fn read_at(reads: &[bool], at: usize) -> bool {
    reads.get(at).copied().unwrap_or(false)
}

/// The first offset from `at` to `at + 3` where a pass reads a National
/// Insurance number: the suffix letter of the number before it, or one of the
/// three bytes behind it (`AB 12 34 56\nBAB…`, `AB123456CXAB…`). One window for
/// both places that ask (NINO-CHAIN): the glue rule of [`nino_at`] and
/// [`opens_another`]. Four table reads.
fn read_near(reads: &[bool], at: usize) -> Option<usize> {
    (0..=3)
        .map(|step| at + step)
        .find(|&offset| read_at(reads, offset))
}

/// For every offset, whether a pass reads a number there. A
/// number's glue rule asks only about offsets at least eight bytes behind its
/// start, so one walk from the end fills the table with no recursion: a chain
/// of any length costs one try per offset, and each try reads at most
/// twenty-one bytes (linear scan). Only offsets where a number's shape starts
/// are tried at all.
pub(super) fn reads_table(bytes: &[u8], text: &str, view: &NormalizedText) -> Vec<bool> {
    let mut reads = vec![false; bytes.len()];
    for at in (0..bytes.len()).rev() {
        if number_starts_at(bytes, at) {
            reads[at] = nino_at(bytes, at, text, view, &reads).is_some()
                || separated_nino_at(bytes, at, text, view, &reads).is_some();
        }
    }
    reads
}

/// Where the next number may start after a number that ended at `end`: one that
/// kept its suffix letter looks from that letter on ([`read_near`]); one the
/// separated cut ended before the letter looks at the letter. `None` when no pass
/// reads a number there.
///
/// A letter or digit may precede that offset, and [`analyze`](crate::recognizer::Recognizer::analyze) waives its start
/// rule there and reads from it even inside the span just read:
/// the letter is shared by both numbers, so a start rule that read the whole
/// word, or a scan that went on past the span, left the next number in clear
/// (`AB 12 34 56\nBAB123456B`, the middle of `XY 12 34 56 AB 12 34 56 AB …`).
pub(super) fn opens_another(bytes: &[u8], end: usize, reads: &[bool]) -> Option<usize> {
    let last = end.checked_sub(1)?;
    if bytes[last].is_ascii_alphabetic() {
        read_near(reads, last)
    } else {
        read_at(reads, end).then_some(end)
    }
}
