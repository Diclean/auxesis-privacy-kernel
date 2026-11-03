//! The FIN-6 separated pass: one separator shape at every pair boundary.

use crate::normalize::NormalizedText;

use super::compact::glued_next_end;
use super::shape::{broke_line, number_starts_at, prefix_allowed};

/// What a FIN-6 separated shape reads at one offset, before any rule on what
/// follows its suffix letter: the two prefix letters, the suffix letter with the
/// offset one past it, and the offset where the separator run that precedes the
/// suffix begins — a line break inside that run puts whatever follows the suffix
/// on the next line.
pub(super) struct Separated {
    first: u8,
    second: u8,
    suffix: usize,
    pub(super) end: usize,
    last: usize,
}

/// FIN-6: the shape of a number whose four pair boundaries hold the same
/// separator: one to three spaces, or one `-`, `/` or `.` (`PN/48/15/16/C`,
/// `PN  48  15  16  C`, `CB 12  34 56 A`), with a suffix letter A to D. The
/// shape alone, which is what the glue rule asks about
/// ([`number_starts_at`](super::shape::number_starts_at)) and what [`separated_nino_at`] then judges. Each try
/// reads at most twenty-one bytes (linear scan).
pub(super) fn separated_shape_at(bytes: &[u8], start: usize) -> Option<Separated> {
    let (first, second) = (*bytes.get(start)?, *bytes.get(start + 1)?);
    if !(first.is_ascii_alphabetic() && second.is_ascii_alphabetic())
        || !prefix_allowed(first, second)
    {
        return None;
    }
    let sep = *bytes.get(start + 2)?;
    let most = match sep {
        b' ' => 3,
        b'-' | b'/' | b'.' => 1,
        _ => return None,
    };
    let mut index = start + 2;
    // Where the run that precedes the suffix letter starts.
    let mut last = start + 2;
    for pair in 0..4 {
        let run = bytes[index..]
            .iter()
            .take(most + 1)
            .take_while(|&&b| b == sep);
        let run = run.count();
        if run == 0 || run > most {
            return None;
        }
        last = index;
        index += run;
        if pair < 3 {
            if !bytes.get(index..index + 2)?.iter().all(u8::is_ascii_digit) {
                return None;
            }
            index += 2;
        }
    }
    let suffix = *bytes.get(index)?;
    if !matches!(suffix, b'A'..=b'D' | b'a'..=b'd') {
        return None;
    }
    Some(Separated {
        first,
        second,
        suffix: index,
        end: index + 1,
        last,
    })
}

/// FIN-6: a number whose four pair boundaries hold the same separator. A digit
/// may not touch it. A letter may (`refPN 48 15 16 C`, `PN 48 15 16 Cok`) when
/// the prefix and the suffix are capitals: then the separators still mark it.
/// A suffix letter that opens another number lifts both rules on its side
/// (NINO-CHAIN): the digit before, and the case of a letter after.
/// A suffix glued to a following letter across a line break ends the shape at the
/// break, so the next line is read whole from its own first letter, but only
/// where another number starts there (NINO-GLUED-NEXT): a word the suffix took
/// its first letter from is masked letter and all, which leaves the word a label
/// can match. At most twenty-one bytes (linear scan).
pub(super) fn separated_nino_at(
    bytes: &[u8],
    start: usize,
    text: &str,
    view: &NormalizedText,
    reads: &[bool],
) -> Option<usize> {
    let Separated {
        first,
        second,
        suffix,
        end,
        last,
    } = separated_shape_at(bytes, start)?;
    let after = bytes.get(end).copied();
    // Its suffix letter opens another number: a chain is evidence of its own,
    // so neither a digit before it nor lower case glued to the next number
    // refuses it (NINO-CHAIN). A value masked before a chain
    // (`…9268 19AB 65  43 21\tCB-87 …`) left its last digit there, and only the
    // residue round read the number behind it, from the next number's letter:
    // masking that letter first left the number in clear. A whole number that
    // no pass reads on its own there (its suffix is glued to an IBAN or a key)
    // is read with this one ([`glued_next_end`], NINO-CHAIN r1).
    let shared = after.is_some_and(|b| b.is_ascii_alphabetic()) && number_starts_at(bytes, suffix);
    let glued_next = shared
        .then(|| glued_next_end(bytes, suffix, reads))
        .flatten();
    if start > 0 && bytes[start - 1].is_ascii_digit() && !shared {
        return None;
    }
    // A line break before the suffix puts what follows on the next line, so a
    // letter or digit glued to it is that line's first character, not this
    // number's (NINO-GLUED-NEXT).
    let next_line = matches!(after, Some(alphanumeric) if alphanumeric.is_ascii_alphanumeric())
        && broke_line(text, view, last);
    if after.is_some_and(|b| b.is_ascii_digit()) && !next_line {
        return None;
    }
    let glued = (start > 0 && bytes[start - 1].is_ascii_alphabetic())
        || (after.is_some_and(|b| b.is_ascii_alphabetic()) && !shared);
    let capitals = [first, second, *bytes.get(suffix)?]
        .iter()
        .all(u8::is_ascii_uppercase);
    if !glued || capitals {
        // The suffix is masked with the number and the next line is read from
        // its second character: a word whose first letter the suffix took is
        // then a word again, so its label still matches and its value stays
        // masked. One exception, and the reason the cut exists: another number
        // starts at that letter, whose own digits must be read whole (FIN-6).
        // `number_starts_at` knows every shape, not only the spaced ones, so
        // the cut lands on all of them (NINO-GLUED-NEXT r1). On one line the
        // letter is kept, and the scan reads the next number from it too
        // ([`opens_another`], NINO-CHAIN), unless no pass reads it there.
        return Some(match glued_next {
            Some(next) => next,
            None if shared && next_line => suffix,
            None => end,
        });
    }
    None
}
