//! One linear link scanner. A secret's value runs from its
//! link to a structural end: the end of its paragraph, or in an unambiguous config
//! paragraph the end of its logical line. No end depends on a word of the value.
//! Its spans are only added to the older scans' spans; it never removes one.

mod layout;
mod lex;
mod link;
mod scan;
mod table;

pub(crate) use scan::link_scan;

use std::sync::LazyLock;

use regex::Regex;

/// Fewest non-whitespace characters a value needs over its whole extent.
const FLOOR: usize = 4;
/// The link must end within this many effective bytes of the key end.
const WINDOW: usize = 96;
const LINKS: &[&str] = &[
    "is", "was", "are", "were", "est", "etait", "sont", "etaient",
];
const WEAK: &[&str] = &[
    "pass", "pw", "pin", "pins", "code", "codes", "secret", "secrets", "token", "tokens", "jeton",
    "jetons", "code pin",
];
const HEADS: &[&str] = &[
    "for", "to", "of", "on", "at", "in", "with", "from", "du", "de", "des", "pour", "sur", "au",
    "a",
];

/// Every key, on the folded text, longest alternatives first; the weak keys last.
static KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"passwords?|passwd|pwd|passphrases?|passcodes?|mots? +de +passe|mdp|code +d'acces|",
        r"code +secret|code +pin|api *key|secret +key|access +key|private +key|access +token|auth +token|",
        r"seed +phrase|recovery +phrase|jelszo|geslo|wagwoord|密码|密碼|口令|",
        r"pass|pw|pins?|codes?|secrets?|tokens?|jetons?"
    ))
    .expect("key list compiles")
});

/// Whether `line` is a block header this scanner hides the block under: an
/// entry whose value is a block-scalar header (`seed_phrase: |`, `pw: >-`,
/// `code: | # x`) and whose key holds a key (a weak one too: an entry key
/// always counts). One line, its key read at most 64 characters in.
pub(crate) fn heads_key_block(line: &str) -> bool {
    matches!(lex::shape(line, 0).1, Shape::Entry(_, Kind::Header, key)
        if lex::secret_key(&line[key.0..key.1]))
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Empty,
    Header,
    Opener,
    Inline,
}

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Blank,
    /// Separator, value kind, key token range.
    Entry(u8, Kind, (usize, usize)),
    Structure,
    Fence,
    Other,
}

/// One physical (LF) line of the original text.
struct Line {
    start: usize,
    end: usize,
    indent: usize,
    shape: Shape,
    child: bool,
    config: bool,
    value_end: usize,
    /// End of the paragraph, including when it also looks like config.
    paragraph_end: usize,
    /// The line starts inside an owned region: it joins the logical line above.
    joined: bool,
    /// Its paragraph is Prose: a multi-line quote, a fence, an unclosed or mismatched
    /// region, or an unsure indent.
    taint: bool,
    /// The line ends a key block: its dedent is checked against the indent stack.
    ends_block: bool,
}

#[cfg(test)]
mod tests;
