//! Folding to lower case without accents, and the byte map back to the original.

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

pub(super) fn is_cjk(ch: char) -> bool {
    matches!(ch, '\u{3400}'..='\u{9FFF}' | '\u{F900}'..='\u{FAFF}' | '\u{20000}'..='\u{2FA1F}')
}

/// `text` folded (lower case, no accents, `_` and `-` as a space, a markdown
/// escape `\_` dropped, curly apostrophes straight) and, per folded byte, the
/// original byte it came from (plus one entry for the end).
pub(crate) fn fold(text: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len() + 1);
    let mut chars = text.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        let mut push = |c: char, out: &mut String| {
            map.extend(std::iter::repeat_n(at, c.len_utf8()));
            out.push(c);
        };
        match ch {
            '\\' if chars
                .peek()
                .is_some_and(|(_, next)| next.is_ascii_punctuation()) => {}
            '_' | '-' | '\u{2010}' | '\u{2011}' => push(' ', &mut out),
            '’' | '‘' | 'ʼ' => push('\'', &mut out),
            _ => {
                for lower in ch.to_lowercase() {
                    for c in std::iter::once(lower)
                        .nfd()
                        .filter(|c| !is_combining_mark(*c))
                    {
                        push(c, &mut out);
                    }
                }
            }
        }
    }
    map.push(text.len());
    (out, map)
}

pub(super) fn ends_word(rest: &str) -> bool {
    !rest.starts_with(|c: char| c.is_alphanumeric() && !is_cjk(c))
}
