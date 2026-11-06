//! The seams of [`SafeText::join`](super::SafeText::join), each read again by
//! the private recognisers with the tokens and markers the kernel wrote (its
//! marks) as fixed stand-ins, never edited. A value found that the mode hides,
//! or clear text a seam ties to a mark, becomes a fixed marker.

use std::cell::LazyCell;
use std::iter::once;
use std::sync::LazyLock;

use kernel_core::privacy::GrantPolicy;

use super::detector::Detector;
use super::prohibited::{is_hash_fragment, removal_text};
use super::residue::MASKED_STAND_IN;
use super::tokens::session_token_len;
use crate::anonymize::{kind_of_token, PLACEHOLDER_OPEN};
use crate::public_terms::{fold, PublicTerms};
use crate::recognizer::span_is_well_formed;
use crate::recognizers::labels_a_secret;
use crate::recognizers::secrets::value_too_long;
use crate::span::{EntityKind, Span};

/// A byte range of a text.
pub(super) type Mark = (usize, usize);
/// Byte ranges, sorted and disjoint, of the tokens and markers the kernel wrote.
pub(super) type Marks = Vec<Mark>;
/// A range a join hides, and the marker it writes there.
type Piece = (Mark, &'static str);

/// What a join writes in place of clear text whose class has no marker.
const VALUE_REMOVED: &str = "[value removed]";
/// What a join issues when it cannot hide what crosses a seam.
const WITHHELD: &str = "[auxesis: withheld]";
/// The characters read each side of a seam, out to whole words.
const WINDOW_CHARS: usize = 40;
/// The longest run a join ties to a mark.
const MAX_RUN_BYTES: usize = 512;
/// The longest key a join reads on from a key mark, in bytes.
const MAX_KEY_BYTES: usize = 16 * 1024;
/// The most words a join reads on from an address mark.
const MAX_ADDRESS_WORDS: usize = 8;
/// The most blank characters a seam rule reads across, and the most bytes of
/// one address word: past them the rule stops, so a join stays linear.
const MAX_BLANKS: usize = 4096;

/// The byte length of the blanks `text` ends with (`back`) or starts with,
/// `None` past [`MAX_BLANKS`] characters.
fn blanks(text: &str, back: bool) -> Option<usize> {
    let mut chars: Box<dyn Iterator<Item = char>> = match back {
        true => Box::new(text.chars().rev()),
        false => Box::new(text.chars()),
    };
    let mut len = 0;
    for _ in 0..=MAX_BLANKS {
        match chars.next() {
            Some(ch) if ch.is_whitespace() => len += ch.len_utf8(),
            _ => return Some(len),
        }
    }
    None
}
/// The built-in public terms an address may end with, as on 0.1.5 (their
/// capitals, and brands kept so no join shows more than it did).
static PUBLIC: LazyLock<PublicTerms> = LazyLock::new(PublicTerms::builtin);
/// Major cities past the capitals of [`PUBLIC`] that an address may end with.
const CITIES: &str = "lyon lille marseille toulouse nice nantes strasbourg montpellier \
    bordeaux rennes reims grenoble dijon angers nîmes toulon brest metz rouen caen nancy \
    orléans tours limoges amiens perpignan besançon mulhouse avignon clermont-ferrand \
    manchester birmingham liverpool leeds glasgow edinburgh bristol sheffield cardiff belfast \
    hamburg munich münchen cologne köln frankfurt stuttgart düsseldorf leipzig dresden \
    barcelona valencia seville sevilla milan milano naples napoli turin torino florence \
    porto rotterdam antwerp antwerpen ghent gent liège geneva genève zurich zürich basel \
    lausanne bern luxembourg debrecen szeged pécs győr miskolc ljubljana maribor kraków \
    gdańsk wrocław brno bratislava zagreb split durban bloemfontein";
static CITY_FOLDS: LazyLock<Vec<String>> =
    LazyLock::new(|| CITIES.split_whitespace().map(fold).collect());
/// Words on the line above a base64 block that name a key.
const KEY_WORDS: &str = "key secret token password passphrase private credential";

/// The marks of a text a tokenising gate issued: it doubles a typed `⟦`.
pub(super) fn token_marks(text: &str) -> Marks {
    let (mut marks, mut at, open) = (Vec::new(), 0, PLACEHOLDER_OPEN.len_utf8());
    while let Some(offset) = text[at..].find(PLACEHOLDER_OPEN) {
        let start = at + offset;
        let doubled = text[start + open..].starts_with(PLACEHOLDER_OPEN);
        let len = session_token_len(&text[start..]).filter(|_| !doubled);
        marks.extend(len.map(|len| (start, start + len)));
        at = start + len.unwrap_or(if doubled { 2 * open } else { open });
    }
    marks
}

/// The join of `text`, read again 4, then 16 times wider at an edge, or [`WITHHELD`].
pub(super) fn mend(
    text: &str,
    marks: &[Mark],
    seams: &[usize],
    policy: GrantPolicy,
    scan: &dyn Detector,
) -> (String, Marks) {
    let mut pieces = Vec::new();
    let last = seams.iter().copied().max().unwrap_or(0);
    let tables = crate::recognizers::secret_table_lines(text, last, marks);
    let cells = secret_cells(text, marks);
    let blocks = key_blocks(text, marks, last, &mut 0);
    for &seam in seams {
        let framed = LazyCell::new(|| framed(text, seam));
        let read = [1, 4, 16]
            .into_iter()
            .map(|times| {
                let at = window(text, marks, seam, times * WINDOW_CHARS);
                let key = |edge| key_break(text, marks, edge, &|| *framed);
                let key = key(at.0) || key(at.1);
                if times < 16 && (key || cuts(text, at.0) || cuts(text, at.1)) {
                    return Some(false);
                }
                if key {
                    return None;
                }
                read(text, marks, at, (policy, scan), &mut pieces)
            })
            .find(|read| *read != Some(false));
        if in_secret_table(text, (&tables, &cells), seam) || in_key_block(&blocks, seam) {
            return (WITHHELD.to_string(), vec![(0, WITHHELD.len())]);
        }
        let (run, more) = (run(text, marks, seam), beside(text, marks, seam));
        let (Some(_), Some(run), Some(more)) = (read.flatten(), run, more) else {
            return (WITHHELD.to_string(), vec![(0, WITHHELD.len())]);
        };
        pieces.extend(run.into_iter().map(|at| (at, VALUE_REMOVED)).chain(more));
    }
    rewrite(text, marks, pieces)
}

/// `reach` characters each side of `seam`, out to blanks within `reach` more.
fn window(text: &str, marks: &[Mark], seam: usize, reach: usize) -> Mark {
    let blank = |&(_, ch): &(usize, char)| ch.is_whitespace();
    let mut back = text[..seam].char_indices().rev().skip(reach);
    let from = match back.by_ref().take(reach).find(blank) {
        Some((at, ch)) => at + ch.len_utf8(),
        None => back.next().map_or(0, |(at, ch)| at + ch.len_utf8()),
    };
    let mut on = text[seam..].char_indices().skip(reach);
    let to = match on.by_ref().take(reach).find(blank) {
        Some((at, _)) => seam + at,
        None => on.next().map_or(text.len(), |(at, _)| seam + at),
    };
    let around = |at: usize| marks_in(marks, (at, at)).next().unwrap_or((at, at));
    (around(from).0, around(to).1)
}

/// Whether a window edge at `at` cuts a run of `text` (no blank either side).
fn cuts(text: &str, at: usize) -> bool {
    let blank = char::is_whitespace;
    0 < at && at < text.len() && !text[..at].ends_with(blank) && !text[at..].starts_with(blank)
}

/// Whether `text` has a key frame (`-----BEGIN`, `---- END`, …) or a PuTTY
/// header within 16 KiB ([`MAX_KEY_BYTES`]) each way of `seam`; a bare
/// `----` (a rule) is none.
fn framed(text: &str, seam: usize) -> bool {
    let lo = text.floor_char_boundary(seam.saturating_sub(MAX_KEY_BYTES));
    let hi = text.floor_char_boundary(text.len().min(seam + MAX_KEY_BYTES));
    let signs = [
        "----BEGIN",
        "---- BEGIN",
        "----END",
        "---- END",
        "PuTTY-User-Key-File",
    ];
    signs.iter().any(|sign| text[lo..hi].contains(sign))
}

/// Whether a window edge at `at` is a line break inside a key: 16 base64
/// characters or more on each side, and a sign of a key: a frame near the
/// seam (`framed`), a line of 40 base64 characters or more beside the break,
/// a key mark on a line beside it, or a word naming a key on the line above
/// the base64 block, within 16 KiB.
fn key_break(text: &str, marks: &[Mark], at: usize, framed: &dyn Fn() -> bool) -> bool {
    let (Some(back), Some(on)) = (blanks(&text[..at], true), blanks(&text[at..], false)) else {
        return false;
    };
    let (head, tail) = (&text[..at - back], &text[at + on..]);
    let long = |chars: &mut dyn Iterator<Item = char>, len: usize| {
        chars.take(len).filter(|&c| b64(c)).count() == len
    };
    let cut = text[at - back..at + on].contains('\n')
        && long(&mut head.chars().rev(), 16)
        && long(&mut tail.chars(), 16);
    if !cut {
        return false;
    }
    let lo = text.floor_char_boundary(at.saturating_sub(MAX_KEY_BYTES));
    let hi = text.floor_char_boundary(text.len().min(at + MAX_KEY_BYTES));
    let wide = long(&mut head.chars().rev(), 40) || long(&mut tail.chars(), 40);
    let from = text[lo..at - back].rfind('\n').map_or(lo, |i| lo + i);
    let to = text[at + on..hi].find('\n').map_or(hi, |i| at + on + i);
    let secret = |(start, end): Mark| kind(&text[start..end]) == Some(EntityKind::Secret);
    let mut end = at - back;
    let label = loop {
        let start = text[lo..end].rfind('\n').map_or(lo, |i| lo + i + 1);
        let line = text[start..end].trim();
        // The block rule reads a key's block across blank lines too.
        if start == lo || !(line.is_empty() || base64(line) && line.len() >= 16) {
            break line;
        }
        end = start - 1;
    };
    let named = words(label).iter().any(|word| key_word(word)) || labels_a_secret(label);
    wide || named || marks_in(marks, (from, to)).any(secret) || framed()
}

/// The key blocks of `text` to the line holding `last`, and on to the first
/// line past it a block reaches: under a label line the gate reads as a
/// secret's ([`label_line`]: `myapikey:`, `pin:`, `password: |`), the lines
/// that are blank, indented deeper than the label (the block the gate hides)
/// or of base64 or marks at any depth, however far. Each runs from the label
/// line (past its first byte: a seam on it cuts the label or its header) to
/// the end of its last line that is not blank. One pass; `work` counts the
/// lines read.
fn key_blocks(text: &str, marks: &[Mark], last: usize, work: &mut usize) -> Marks {
    let (bytes, mut blocks, mut at) = (text.as_bytes(), Vec::new(), 0);
    // The open block: its label's depth, its start, the end of its last line,
    // and whether a line is under the label yet.
    let mut open: Option<(usize, usize, usize, bool)> = None;
    let mut close = |open: Option<(usize, usize, usize, bool)>| {
        blocks.extend(
            open.filter(|b| b.3 && b.1 < b.2)
                .map(|(_, start, stop, _)| (start, stop)),
        );
    };
    // A block with no line yet, or whose lines end by `last`, is read on, so
    // a seam on its label or its last line sees whether it runs past.
    while at <= text.len() && (at <= last || open.is_some_and(|b| !b.3 || b.2 <= last)) {
        *work += 1;
        let next = bytes[at..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(text.len(), |n| at + n);
        let end = next - usize::from(text[..next].ends_with('\r'));
        let line = &text[at..end];
        let depth = line.len() - line.trim_start_matches([' ', '\t']).len();
        let blank = line.trim().is_empty();
        if let Some((deep, start, _, _)) = open.filter(|_| !blank) {
            if depth > deep || block_line(text, marks, (at, end)) {
                open = Some((deep, start, end, true));
            } else {
                close(open.take());
            }
        }
        if open.is_none() && !blank && label_line(text, marks, (at, end)) {
            // A seam on the label line past its first byte cuts the label or
            // its header: the part with the block does not read it whole.
            open = Some((depth, (at + 1).min(end), end, false));
        }
        at = next + 1;
    }
    close(open);
    blocks
}

/// Whether `text[start..end]` is a label line the gate reads as a secret's:
/// read whole, or up to its first or its last key mark (the gate hides a
/// block-scalar header with a comment on the label line, `dbapikey: | # the
/// db one`, so a part shows only `dbapikey: ⟦…⟧`). Other marks are read as
/// they stand, so a value before the label (`Contact ⟦…⟧ for the password:
/// ⟦…⟧`, `Authorization: Bearer ⟦…⟧ password: ⟦…⟧`) still opens the block.
/// Three label reads at most, so a line stays linear.
///
/// Accepted since #114: a commented header takes its block from the header
/// on, so a very long block under one is tokenised where it was refused with
/// TooLong. That is the owner rule: private means tokenise, never block.
fn label_line(text: &str, marks: &[Mark], (start, end): Mark) -> bool {
    let key = |&(from, to): &Mark| from < to && kind(&text[from..to]) == Some(EntityKind::Secret);
    let mut keys = marks_in(marks, (start, end)).filter(key);
    let first = keys.next();
    let last = keys.last().or(first);
    let before = |(from, _): Mark| &text[start..from.max(start)];
    once(&text[start..end])
        .chain(first.map(before))
        .chain(last.filter(|_| last != first).map(before))
        .any(labels_a_secret)
}

/// Whether `seam` is in one of the key `blocks` (its ends included): the
/// whole text hides the block, and a part read alone does not see the label.
fn in_key_block(blocks: &[Mark], seam: usize) -> bool {
    let at = blocks.partition_point(|block| block.1 < seam);
    blocks.get(at).is_some_and(|block| block.0 <= seam)
}

/// Whether `text[start..end]` is a line of a key block: base64 once its marks
/// are taken out, or only marks and blanks. No allocation.
fn block_line(text: &str, marks: &[Mark], (start, end): Mark) -> bool {
    let (mut at, mut marked, mut seen, mut gap) = (start, false, false, false);
    for (from, to) in marks_in(marks, (start, end)) {
        let from = from.clamp(at, end);
        for ch in text[at..from].chars() {
            match ch.is_whitespace() {
                true => gap |= seen,
                // A blank inside the value, or a character out of base64.
                false if gap || !b64(ch) => return false,
                false => seen = true,
            }
        }
        marked |= from < to;
        at = to.clamp(from, end);
    }
    seen || marked
}

/// The cell delimiters of a table.
const CELLS: [char; 4] = [',', '\t', ';', '|'];

/// The key marks beside a cell delimiter (a padded or quoted cell, `, "…" ,`,
/// too), read once for every seam.
fn secret_cells(text: &str, marks: &[Mark]) -> Marks {
    let pad = |ch: char| ch == ' ' || ch == '"' || ch == '\'';
    let cell = |&&(start, end): &&Mark| {
        let before = text[..start].trim_end_matches(pad);
        let after = text[end..].trim_start_matches(pad);
        let beside = before.ends_with(CELLS) || after.starts_with(CELLS);
        beside && kind(&text[start..end]) == Some(EntityKind::Secret)
    };
    marks.iter().filter(cell).copied().collect()
}

/// Whether `seam` is in a table whose secret column a gate hid before it: on
/// a line of a table under a header naming a secret column (`tables`, however
/// far back the header; the header line itself, which a seam may cut), or on a
/// line with a cell delimiter and a key mark beside one (`cells`) within
/// 16 KiB back. A table that a line closed reaches no further.
fn in_secret_table(text: &str, (tables, cells): (&[Mark], &[Mark]), seam: usize) -> bool {
    let table = tables.partition_point(|t| t.1 < seam);
    if tables.get(table).is_some_and(|t| t.0 <= seam) {
        return true;
    }
    let lo = text.floor_char_boundary(seam.saturating_sub(MAX_KEY_BYTES));
    let hi = text.floor_char_boundary(text.len().min(seam + MAX_KEY_BYTES));
    let from = text[lo..seam].rfind('\n').map_or(lo, |i| lo + i);
    let to = text[seam..hi].find('\n').map_or(hi, |i| seam + i);
    let last = cells.partition_point(|c| c.0 < seam).checked_sub(1);
    let cell = last.is_some_and(|at| cells[at].1 > lo);
    cell && text[from..to].contains(CELLS)
}

/// The words of a label: runs of letters and digits, split before a capital
/// after a small letter or digit (`privateKey`), lower-cased.
fn words(label: &str) -> Vec<String> {
    let (mut words, mut word, mut small) = (Vec::new(), String::new(), false);
    for ch in label.chars() {
        if !ch.is_alphanumeric() || (ch.is_uppercase() && small) {
            words.extend((!word.is_empty()).then(|| std::mem::take(&mut word)));
        }
        if ch.is_alphanumeric() {
            word.extend(ch.to_lowercase());
        }
        small = ch.is_lowercase() || ch.is_ascii_digit();
    }
    words.extend((!word.is_empty()).then_some(word));
    words
}

/// Whether a label word names a key: a key word, its plural, or a compound
/// ending with one (`accesstoken`, a `key` only after a key name's head, as
/// `apikey`), never a word that merely holds one (`monkey`, `tokenizer`).
fn key_word(word: &str) -> bool {
    const HEADS: &str = "api access private encryption master app account subscription \
        preshared secret ssh signing priv gpg pgp rsa host deploy";
    KEY_WORDS.split_whitespace().any(|key| {
        let head = word.strip_suffix('s').unwrap_or(word).strip_suffix(key);
        let head = head.or_else(|| word.strip_suffix(key));
        head.is_some_and(|head| {
            head.is_empty() || key != "key" || HEADS.split_whitespace().any(|h| h == head)
        })
    })
}

/// Whether `ch` is a base64 character, and `value` a line of them.
fn b64(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || "+/=".contains(ch)
}
fn base64(value: &str) -> bool {
    !value.is_empty() && value.chars().all(b64)
}

/// Adds to `pieces` the clear bytes of the values in `text[from..to]` that
/// `policy` hides; `Some(false)` when one is at an edge, `None` on a failure.
fn read(
    text: &str,
    marks: &[Mark],
    (from, to): Mark,
    (policy, scan): (GrantPolicy, &dyn Detector),
    pieces: &mut Vec<Piece>,
) -> Option<bool> {
    let (mut view, mut clear, mut at) = (String::new(), Vec::new(), from);
    for (start, end) in marks_in(marks, (from, to)) {
        clear.push((view.len(), at, start - at));
        view.push_str(&text[at..start]);
        push_stand_in(&mut view, &text[start..end]);
        at = end;
    }
    let tokenised = policy == GrantPolicy::Tokenised;
    // The gate's full read: its e-mail layer adds keyword IDs to the residue
    // scan and drops only a public-term name or address (never one with a digit).
    let spans = scan.detect(&view).ok()?;
    if tokenised && view.len() > 1024 && value_too_long(&view) {
        return None; // No secret the gate reads is over 1 KiB.
    }
    let mut hide = Vec::new();
    for span in spans.iter().filter(|span| span_is_well_formed(&view, span)) {
        let first = clear.partition_point(|c| c.0 + c.2 <= span.start);
        // A digest is one in the text too, when the span is in one clear stretch.
        let in_text = clear
            .get(first)
            .filter(|c| c.0 <= span.start && span.end <= c.0 + c.2);
        let in_text = in_text.map(|&(view_at, text_at, _)| Span {
            start: text_at + span.start - view_at,
            end: text_at + span.end - view_at,
            ..*span
        });
        let digest = is_hash_fragment(&view, span)
            && in_text.is_none_or(|span| is_hash_fragment(text, &span));
        if !tokenised && (!span.is_prohibited() || digest) {
            continue;
        }
        let found = hide.len();
        for &(view_at, text_at, len) in clear[first..].iter().take_while(|c| c.0 < span.end) {
            let (start, end) = (span.start.max(view_at), span.end.min(view_at + len));
            let bytes = (text_at + start - view_at, text_at + end - view_at);
            if text[bytes.0..bytes.1].contains(char::is_alphanumeric) {
                hide.push((bytes, removal_text(span.kind).unwrap_or(VALUE_REMOVED)));
            }
        }
        let edge = (span.start == 0 && from > 0) || (span.end == view.len() && to < text.len());
        if edge && hide.len() > found {
            return Some(false);
        }
    }
    pieces.extend(hide);
    Some(true)
}

/// What `mark` reads as: a value that runs on past it (an address after a
/// street, a comma and a short city, as their postcode; a phone as digits a
/// keyword ID can take), or a stand-in and a line end.
fn push_stand_in(view: &mut String, mark: &str) {
    let (_, tail) = view.rsplit_once("1 Main Street, ").unwrap_or_default();
    let city = tail.starts_with(char::is_uppercase) && tail.split_whitespace().nth(3).is_none();
    match kind(mark) {
        _ if mark.is_empty() => {}
        Some(EntityKind::Health) => view.push_str("Cancer"),
        Some(EntityKind::Address) if city => view.push_str("W1A 1AA"),
        Some(EntityKind::Address) => view.push_str("1 Main Street"),
        Some(EntityKind::Secret) => view.push_str("Fake-Pass-42"),
        Some(EntityKind::Phone) => view.push_str("123 4567 82"),
        _ => view.extend([MASKED_STAND_IN, '\n']),
    }
}

/// The class of a mark: its token's kind, or the first one its marker stands for.
fn kind(mark: &str) -> Option<EntityKind> {
    match mark.strip_prefix(PLACEHOLDER_OPEN) {
        Some(token) => kind_of_token(token),
        None => EntityKind::ALL
            .into_iter()
            .find(|&kind| removal_text(kind) == Some(mark)),
    }
}

/// Whether a mark of `kind` is a number often written in groups (`06 12 34`).
fn grouped(kind: EntityKind) -> bool {
    use EntityKind::*;
    let kinds = [
        Phone, Iban, CreditCard, FrNir, FrSiren, FrSiret, FrVat, HuTaj, HuTaxId, ZaId, UkNino,
        NationalId,
    ];
    kinds.contains(&kind)
}

/// The clear text a seam carries on from a key or an address mark beside it
/// (blanks between): the lines of the key, and the words of the address;
/// `None` when a key runs on past [`MAX_KEY_BYTES`].
fn beside(text: &str, marks: &[Mark], seam: usize) -> Option<Vec<Piece>> {
    let before = blanks(&text[..seam], true).map(|len| seam - len);
    let after = blanks(&text[seam..], false).map(|len| seam + len);
    let glued = before == Some(seam) && after == Some(seam);
    let mut pieces = Vec::new();
    for (back, edge) in [(false, before), (true, after)] {
        let Some(edge) = edge else { continue };
        let Ok(at) = marks.binary_search_by_key(&edge, |m| if back { m.0 } else { m.1 }) else {
            continue;
        };
        let (start, end) = marks[at];
        let (found, kind) = match kind(&text[start..end]) {
            Some(kind @ EntityKind::Secret) => (key_lines(text, marks, seam, back, glued)?, kind),
            Some(kind @ EntityKind::Address) => (address_words(text, marks, seam, back), kind),
            _ => continue,
        };
        let marker = removal_text(kind).unwrap_or(VALUE_REMOVED);
        pieces.extend(found.into_iter().map(|at| (at, marker)));
    }
    Some(pieces)
}

/// The lines of a key that run on from its mark across `seam`, going `back`
/// or on: the rest of a glued line, then each line of base64 (16 characters
/// or more, or padded) or of marks, and a short last one, up to and with a
/// `----` frame (or the cut end of one); `None` for a short line inside the
/// key or past [`MAX_KEY_BYTES`].
fn key_lines(text: &str, marks: &[Mark], seam: usize, back: bool, glued: bool) -> Option<Marks> {
    let line_at = |at: usize| {
        let line = match back {
            true => {
                let lo = text.floor_char_boundary(at.saturating_sub(MAX_KEY_BYTES));
                (text[lo..at].rfind('\n').map_or(lo, |i| lo + i + 1), at)
            }
            false => {
                let hi = text.floor_char_boundary(text.len().min(at + MAX_KEY_BYTES));
                (at, text[at..hi].find('\n').map_or(hi, |i| at + i))
            }
        };
        let (mut clear, mut parts, mut from) = (String::new(), Vec::new(), line.0);
        for (start, end) in marks_in(marks, line) {
            clear.push_str(&text[from..start]);
            parts.push((from, start));
            from = end;
        }
        (if back { line.0 } else { line.1 }, parts, clear)
    };
    let frame = |value: &str| value.starts_with("----") || value.ends_with("----");
    let long = |value: &str| base64(value) && (value.len() >= 16 || value.ends_with('='));
    let (mut lines, mut at, mut body, mut fresh) = (Vec::new(), seam, false, true);
    loop {
        let (far, parts, clear) = line_at(at);
        let (value, first, marked) = (clear.trim(), at == seam, parts.len() > 1);
        let edge = far == if back { 0 } else { text.len() };
        let bounded = !edge && text.as_bytes()[if back { far - 1 } else { far }] != b'\n';
        let next = (!edge && !bounded).then(|| line_at(if back { far - 1 } else { far + 1 }).2);
        let next = next.as_deref().map(str::trim);
        // A short line ends the key: before a frame, after a body line, or
        // as the first line with text on from the key's mark (its cut-off last line).
        let short = base64(value) && !long(value);
        let cut_off = fresh && !back && !glued;
        if short && (body || cut_off) && next.is_some_and(long) {
            return None;
        }
        let short = short && (body || cut_off || next.is_some_and(frame));
        let empty = value.is_empty() && (first || marked);
        if !(frame(value) || long(value) || short || empty || (first && glued)) {
            break;
        }
        if bounded || at.abs_diff(seam) > MAX_KEY_BYTES {
            return None;
        }
        body |= long(value) || marked || (first && glued);
        fresh &= value.is_empty();
        lines.extend(parts);
        if frame(value) || edge {
            break;
        }
        at = if back { far - 1 } else { far + 1 };
    }
    Some(lines)
}

/// The words of an address that run on from its mark across `seam`, going
/// `back` or on, at most [`MAX_ADDRESS_WORDS`], to a sentence end, a blank line
/// or a mark: those up to a number, a street word or an address mark, a city
/// after a number and a city ([`CITIES`], or a public term). Other
/// capitalised words are prose.
fn address_words(text: &str, marks: &[Mark], seam: usize, back: bool) -> Marks {
    const STREET: &str = "rue avenue boulevard bd place chemin allée impasse quai route \
        street road lane";
    const LINK: &str = "de la le les du des";
    let (mut taken, mut words, mut at, mut number) = (None, None::<Mark>, seam, false);
    for _ in 0..MAX_ADDRESS_WORDS {
        let rest = if back { &text[..at] } else { &text[at..] };
        let Some(gap) = blanks(rest, back) else { break };
        let trimmed = if back {
            &rest[..rest.len() - gap]
        } else {
            &rest[gap..]
        };
        let word = match back {
            true => {
                let lo = trimmed.floor_char_boundary(trimmed.len().saturating_sub(MAX_BLANKS));
                match trimmed[lo..]
                    .char_indices()
                    .rfind(|&(_, ch)| ch.is_whitespace())
                {
                    Some((i, ch)) => (lo + i + ch.len_utf8(), trimmed.len()),
                    None if lo == 0 => (0, trimmed.len()),
                    None => break,
                }
            }
            false => {
                let hi = trimmed.floor_char_boundary(trimmed.len().min(MAX_BLANKS));
                match trimmed[..hi].find(char::is_whitespace) {
                    Some(i) => (at + gap, at + gap + i),
                    None if hi == trimmed.len() => (at + gap, at + gap + trimmed.len()),
                    None => break,
                }
            }
        };
        let blanks = if back { (word.1, at) } else { (at, word.0) };
        let mark = marks_in(marks, word).find(|(from, to)| from < to);
        if let Some((from, to)) = mark {
            if kind(&text[from..to]) == Some(EntityKind::Address) {
                taken = words;
            }
            break;
        }
        let value = &text[word.0..word.1];
        let bare = value.trim_matches(|ch: char| ",.;:!?()".contains(ch));
        let ends = value.ends_with(['.', ';', ':', '!', '?']);
        let lower = bare.to_lowercase();
        let street = STREET.split_whitespace().any(|word| word == lower);
        let digits = bare.contains(|ch: char| ch.is_ascii_digit());
        let capital = bare.starts_with(char::is_uppercase);
        let link = bare.is_empty() || LINK.split_whitespace().any(|word| word == lower);
        let stop = word.0 == word.1
            || text[blanks.0..blanks.1].matches('\n').count() > 1
            || (back && ends);
        if stop || !(street || digits || capital || link) {
            break;
        }
        words = Some(words.map_or(word, |(from, to)| (from.min(word.0), to.max(word.1))));
        let city = PUBLIC.contains(bare) || CITY_FOLDS.contains(&fold(bare));
        if street || digits || (capital && number && !back) || city {
            taken = words;
        }
        (at, number) = (if back { word.0 } else { word.1 }, digits);
        if ends {
            break;
        }
    }
    taken.into_iter().collect()
}

/// The clear text a seam ties to a mark: the word glued across it and the
/// number in groups through it (`⟦IBAN_…⟧ 3456`), each when it holds one.
fn run(text: &str, marks: &[Mark], seam: usize) -> Option<Marks> {
    let glued = !text[..seam].ends_with(char::is_whitespace)
        && !text[seam..].starts_with(char::is_whitespace);
    let mut pieces = Vec::new();
    for number in [glued.then_some(false), Some(true)].into_iter().flatten() {
        let (start, cut) = walk(text, marks, seam, (true, number));
        let (end, cap) = walk(text, marks, seam, (false, number));
        if marks_in(marks, (start, end)).all(|(from, to)| from == to) {
            continue;
        }
        if cut || cap {
            return None;
        }
        let mut at = start;
        for (from, to) in marks_in(marks, (start, end)) {
            pieces.push((at, from));
            at = to;
        }
    }
    Some(pieces)
}

/// Where the word through `seam` ends, going `back` or on, or the `number`
/// (digits, capitals, `+-./`, lone spaces, number marks), and if it was cut.
fn walk(text: &str, marks: &[Mark], seam: usize, (back, number): (bool, bool)) -> (usize, bool) {
    let step = |at: usize| match back {
        true => text[..at].chars().next_back(),
        false => text[at..].chars().next(),
    };
    let joins = |ch: char, at: usize| match number {
        false => !ch.is_whitespace() && !"[]⟦⟧".contains(ch),
        true => {
            let lone = ch == ' ' && step(if back { at - 1 } else { at + 1 }) != Some(' ');
            lone || ch.is_ascii_digit() || ch.is_ascii_uppercase() || "+-./".contains(ch)
        }
    };
    let mut at = seam;
    loop {
        if let Ok(next) = marks.binary_search_by_key(&at, |m| if back { m.1 } else { m.0 }) {
            let (start, end) = marks[next];
            if number && !kind(&text[start..end]).is_some_and(grouped) {
                return (at, false);
            }
            at = if back { start } else { end };
        } else if let Some(ch) = step(at).filter(|&ch| joins(ch, at)) {
            if at.abs_diff(seam) >= MAX_RUN_BYTES {
                return (at, true);
            }
            let len = ch.len_utf8();
            at = if back { at - len } else { at + len };
        } else {
            return (at, false);
        }
    }
}

/// The marks in `from..to`, then an empty one at `to`.
fn marks_in(marks: &[Mark], (from, to): Mark) -> impl Iterator<Item = Mark> + '_ {
    let first = marks.partition_point(|m| m.1 <= from);
    let inner = marks[first..].iter().take_while(move |m| m.0 < to);
    inner.copied().chain(once((to, to)))
}

/// `text` with each trimmed piece that holds a letter or digit replaced by its
/// marker (an overlap writes its tail), and the marks moved, plus one for each marker.
fn rewrite(text: &str, marks: &[Mark], mut pieces: Vec<Piece>) -> (String, Marks) {
    pieces.sort_unstable();
    let (mut out, mut kept) = (String::with_capacity(text.len()), Vec::new());
    let (mut from, mut next) = (0, 0);
    for ((start, end), marker) in pieces.into_iter().chain([((text.len(), text.len()), "")]) {
        if start < from && end <= from {
            continue;
        }
        let start = start.max(from);
        let piece = &text[start..end];
        let start = start + piece.len() - piece.trim_start().len();
        let end = start + piece.trim().len();
        if start < end && !text[start..end].contains(char::is_alphanumeric) {
            continue;
        }
        let base = out.len();
        while next < marks.len() && marks[next].1 <= start {
            kept.push((base + marks[next].0 - from, base + marks[next].1 - from));
            next += 1;
        }
        out.push_str(&text[from..start]);
        if start < end {
            kept.push((out.len(), out.len() + marker.len()));
            out.push_str(marker);
        }
        from = end;
    }
    (out, kept)
}

#[cfg(test)]
mod tests {
    use super::super::detector::{without_names, StandardDetector};
    use super::{in_key_block, key_blocks, mend, rewrite, GrantPolicy};

    /// Open shows a digest, judged on the text too: a hex run after a key
    /// marker is 30 characters there, though the key's stand-in (`…42`) makes
    /// it 32 in the read.
    #[test]
    fn a_digest_is_one_in_the_text_too() {
        let text = "x [secret removed]DE00ABCDEF0123456789ABCDEF0123 ok";
        let seam = text.find(" ok").expect("seam");
        let scan = without_names(StandardDetector::new());
        let open = GrantPolicy::Passthrough;
        let (out, _) = mend(text, &[(2, 18)], &[seam], open, scan.as_ref());
        assert!(!out.contains("ABCDEF0123456789"), "{out}");
    }

    /// A piece that overlaps one already written writes its tail: no byte vanishes.
    #[test]
    fn an_overlapping_piece_writes_its_tail() {
        let pieces = vec![((0, 5), "[a]"), ((3, 8), "[b]"), ((4, 6), "[c]")];
        let (out, marks) = rewrite("abcdefghij", &[(9, 10)], pieces);
        assert_eq!(out, "[a][b]ij");
        assert_eq!(marks, vec![(0, 3), (3, 6), (7, 8)]);
    }

    /// A 1 MiB block under `password:` joined in 16-byte parts: the key
    /// blocks are read once, a line each, and every seam is in the block.
    #[test]
    fn a_megabyte_block_in_16_byte_parts_is_read_once() {
        let text = format!(
            "password:\n{}",
            "  QUJDREVGR0g_x-1 ok\n".repeat((1 << 20) / 21 + 1)
        );
        let seams: Vec<usize> = (16..text.len()).step_by(16).collect();
        let mut work = 0;
        let blocks = key_blocks(&text, &[], text.len(), &mut work);
        assert!(work <= text.lines().count() + 1, "{work} lines read");
        assert!(seams.iter().all(|&seam| in_key_block(&blocks, seam)));
    }

    /// A label line with another mark before the key's (`Pay [iban removed]
    /// for the password: [secret removed]`, or a bearer token's key mark
    /// first): its block opens, and a seam on a block line is in it.
    #[test]
    fn a_label_line_with_another_mark_before_the_key_opens_its_block() {
        for label in [
            "Pay [iban removed] for the password: [secret removed]",
            "Authorization: Bearer [secret removed] password: [secret removed]",
        ] {
            let text = format!("{label}\n  aaaa-bbbb\n  cccc-dddd\nThat was all.\n");
            let marks: Vec<_> = ["[iban removed]", "[secret removed]"]
                .iter()
                .flat_map(|mark| text.match_indices(mark))
                .map(|(at, mark)| (at, at + mark.len()))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let seam = text.find("cccc").expect("seam");
            let blocks = key_blocks(&text, &marks, text.len(), &mut 0);
            assert!(in_key_block(&blocks, seam), "{label}: {blocks:?}");
        }
    }

    /// A label line under an open block (`password` under a deeper label
    /// line) opens its own block: the shallower line under it is in one, at
    /// every byte, and so is the label line itself.
    #[test]
    fn a_label_line_under_an_open_block_opens_its_own() {
        let first = "Contact [email removed] for the password: [secret removed]";
        let value = "zzzz-wwww-yyyy-xxxx";
        let text = format!(
            "{}{first}\npassword\n{}{value}\n",
            " ".repeat(100),
            " ".repeat(60)
        );
        let marks: Vec<_> = ["[email removed]", "[secret removed]"]
            .iter()
            .flat_map(|mark| text.match_indices(mark))
            .map(|(at, mark)| (at, at + mark.len()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let blocks = key_blocks(&text, &marks, text.len(), &mut 0);
        let from = text.find("\npassword").expect("label") + 1;
        let to = text.find(value).expect("value") + value.len();
        for seam in from..=to {
            assert!(in_key_block(&blocks, seam), "{seam}: {blocks:?}");
        }
    }
}
