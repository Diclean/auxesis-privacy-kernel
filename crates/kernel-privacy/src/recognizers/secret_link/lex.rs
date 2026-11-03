//! Key folding, line shapes and key boundaries for the secret-link scanner.

use crate::contacts::fold::is_default_ignorable;

use super::{Kind, Shape, KEY_RE};

/// U+E000 and U+FFFD read as the letter `x` everywhere.
pub(super) fn is_sentinel(ch: char) -> bool {
    matches!(ch, '\u{E000}' | '\u{FFFD}')
}

/// Byte length, with each sentinel counted as one byte (the length of `x`).
fn eff(text: &str) -> usize {
    text.len() - 2 * text.chars().filter(|&ch| is_sentinel(ch)).count()
}

pub(super) fn is_mark(ch: char) -> bool {
    "*_`~\"'\u{201C}\u{201D}\u{2018}\u{2019}\u{AB}\u{BB}".contains(ch)
}

/// Push the key form of `ch`: lowercase, Latin accents gone, invisible marks dropped.
pub(super) fn fold(ch: char, out: &mut String) {
    let ch = match ch {
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
        _ => ch,
    };
    let ch = match ch {
        '\u{E000}' | '\u{FFFD}' => 'x',
        '-' | '_' | '\u{A0}' | '\u{202F}' => ' ',
        '\u{2018}' | '\u{2019}' | '\u{2BC}' => '\'',
        '\u{300}'..='\u{36F}' => return,
        _ if is_default_ignorable(ch) => return,
        _ => ch,
    };
    for low in ch.to_lowercase() {
        let at = "éèêëàâóöőúüűíçčšž".chars().position(|ch| ch == low);
        out.push(at.map_or(low, |at| char::from(b"eeeeaaooouuuiccsz"[at])));
    }
}

fn is_header(value: &str) -> bool {
    value.strip_prefix(['|', '>']).is_some_and(|rest| {
        let rest = rest.trim_start_matches(|ch: char| matches!(ch, '-' | '+' | '0'..='9'));
        let rest = rest.trim_start_matches([' ', '\t']);
        rest.is_empty() || rest.starts_with('#')
    })
}

/// `^[ \t]*(- )?(export[ \t]+)?KEY[ \t]*SEP`, read at most 80 effective bytes in.
fn entry(line: &str, indent: usize, at: usize) -> Option<Shape> {
    let bytes = line.as_bytes();
    let blanks = |from: usize| {
        from + line[from..].len() - line[from..].trim_start_matches([' ', '\t']).len()
    };
    let mut i = indent + 2 * usize::from(line[indent..].starts_with("- "));
    if line[i..].starts_with("export") && matches!(bytes.get(i + 6), Some(b' ' | b'\t')) {
        i = blanks(i + 6);
    }
    let key_start = i;
    if let Some(&quote @ (b'"' | b'\'')) = bytes.get(i) {
        let close = i + 1 + line[i + 1..].find(quote as char)?;
        if !(1..=64).contains(&eff(&line[i + 1..close])) {
            return None;
        }
        i = close + 1;
    } else {
        for (n, ch) in line[i..].chars().enumerate() {
            let first = ch.is_ascii_alphabetic() || ch == '_';
            if n == 64
                || !(first
                    || is_sentinel(ch)
                    || n > 0 && (ch.is_ascii_digit() || ch == '.' || ch == '-'))
            {
                break;
            }
            i += ch.len_utf8();
        }
    }
    let key = (at + key_start, at + i);
    let rest = &line[blanks(i)..];
    let (sep, len) = match rest.as_bytes() {
        [b':', b'=', ..] => (1, 2),
        [b'=', b'>', ..] => (2, 2),
        [b'=', b'=', ..] => return None,
        [b'=', ..] => (3, 1),
        [b':'] | [b':', b' ' | b'\t' | b'\r', ..] => (4, 1),
        _ if rest.starts_with('：') => (5, 3),
        _ => return None,
    };
    let sep_end = line.len() - rest.len() + len;
    if key.0 == key.1 || eff(&line[indent..sep_end]) > 80 {
        return None;
    }
    let value = line[sep_end..].trim_matches([' ', '\t', '\r']);
    let kind = match value {
        "" => Kind::Empty,
        "[" | "{" => Kind::Opener,
        _ if is_header(value) => Kind::Header,
        _ => Kind::Inline,
    };
    Some(Shape::Entry(sep, kind, key))
}

pub(super) fn shape(line: &str, at: usize) -> (usize, Shape) {
    let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
    let body = line[indent..].trim_end_matches([' ', '\t', '\r']);
    let spaces = line.len() - line.trim_start_matches(' ').len();
    let run = |fence: char| line[spaces..].chars().take_while(|&ch| ch == fence).count() >= 3;
    let shape = if body.is_empty() {
        Shape::Blank
    } else if spaces <= 3 && (run('`') || run('~')) {
        Shape::Fence
    } else if body.starts_with(['#', ';'])
        || body.starts_with("//")
        || body.starts_with('[') && body.ends_with(']')
        || body == "---"
        || body == "..."
        || body.bytes().all(|byte| b"{}[], \t".contains(&byte))
    {
        Shape::Structure
    } else {
        entry(line, indent, at).unwrap_or(Shape::Other)
    };
    (indent, shape)
}

/// The end of a key match past one plural `s`, if it passes the boundary.
pub(super) fn bounded(folded: &str, start: usize, end: usize) -> Option<usize> {
    if !folded[start..end].is_ascii() {
        return Some(end);
    }
    let end = end + usize::from(folded[end..].starts_with('s'));
    let word = |ch: Option<char>| ch.is_some_and(char::is_alphanumeric);
    (!word(folded[..start].chars().next_back()) && !word(folded[end..].chars().next()))
        .then_some(end)
}

pub(super) fn secret_key(token: &str) -> bool {
    let mut folded = String::new();
    token.chars().for_each(|ch| fold(ch, &mut folded));
    KEY_RE
        .find_iter(&folded)
        .any(|found| bounded(&folded, found.start(), found.end()).is_some())
}

/// Indent `a` is deeper than `b`: `b` is a strict prefix of it.
pub(super) fn deeper_than(a: &str, b: &str) -> bool {
    a.len() > b.len() && a.starts_with(b)
}

/// The closers of a quote opener; empty for any other char.
pub(super) fn closers(open: char) -> &'static str {
    match open {
        '"' => "\"",
        '\'' => "'",
        '”' => "”",
        '’' => "’",
        '“' => "”",
        '„' => "“”",
        '‘' => "’",
        '‚' => "‘’",
        '«' => "»",
        '»' => "«",
        '‹' => "›",
        '›' => "‹",
        '「' => "」",
        '『' => "』",
        _ => "",
    }
}
