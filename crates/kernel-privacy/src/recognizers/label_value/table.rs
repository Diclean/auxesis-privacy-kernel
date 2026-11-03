//! Delimited rows and cookie pairs.

use crate::span::{EntityKind, Span};

use super::recognizer::NAME;

/// A cookie attribute after `; ` marks the `name=value` before it as a cookie.
const COOKIE_ATTRIBUTES: &str = "path= domain= expires= samesite= httponly secure";

/// The cells of the delimited row at `from`, up to its line end, and that end,
/// RFC 4180 style: a cell that opens with `"` runs to its closing `"`, a doubled
/// `""` in it being a quote, so a delimiter inside it splits nothing
/// (`"fictional,subject",AB negative`). A quote never runs past its line, so a
/// stray one costs only its row. Each cell is its content without the quotes and
/// the blanks around it. One pass over the row: linear.
pub(super) fn cells(text: &str, from: usize, delimiter: char) -> (Vec<(usize, usize)>, usize) {
    let end = text[from..].find('\n').map_or(text.len(), |n| from + n);
    let next = |at: usize| text[at..end].find(delimiter).map_or(end, |n| at + n);
    let (mut out, mut at) = (Vec::new(), from);
    loop {
        let lead = at + (text[at..end].len() - text[at..end].trim_start_matches(' ').len());
        let (content, stop) = if text[lead..end].starts_with('"') {
            let mut close = lead + 1;
            loop {
                match text[close..end].find('"') {
                    None => close = end,
                    Some(n) if text[close + n + 1..end].starts_with('"') => {
                        close += n + 2;
                        continue;
                    }
                    Some(n) => close += n,
                }
                break;
            }
            ((lead + 1, close), next(close))
        } else {
            let stop = next(lead);
            let trimmed = text[lead..stop].trim_end_matches([' ', '"', '\r']);
            ((lead, lead + trimmed.len()), stop)
        };
        out.push(content);
        if stop >= end {
            return (out, end);
        }
        at = stop + 1;
    }
}
/// `name=value; Path=/`: the value of the cookie pair before a cookie attribute.
pub(super) fn cookie_pairs<'a>(
    text: &'a str,
    folded: &'a str,
    map: &'a [usize],
) -> impl Iterator<Item = Span> + 'a {
    // Each pair is searched back to the previous `; ` only, so no byte is read twice.
    let mut floor = 0;
    folded.match_indices("; ").filter_map(move |(at, _)| {
        let attribute = &folded[at + 2..];
        let (floor, end) = (std::mem::replace(&mut floor, map[at]), map[at]);
        if !COOKIE_ATTRIBUTES
            .split(' ')
            .any(|a| attribute.starts_with(a))
        {
            return None;
        }
        let blank = text[floor..end]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace());
        let from = blank.map_or(floor, |(w, c)| floor + w + c.len_utf8());
        let equals = from + text[from..end].find('=')? + 1;
        (text[equals..end].chars().count() >= 4)
            .then(|| Span::new(EntityKind::Secret, equals, end, 1.0, NAME))
    })
}
