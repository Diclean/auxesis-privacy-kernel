//! The clause-tail reading of a key in a sentence (K-SECRET-TAIL-2), and the
//! linked clause end the label-value rule reads.

use std::sync::LazyLock;

use regex::Regex;

use super::key_names::{is_key_mark, SecretValue, MAX_TERMINATOR_WORD};
use super::key_values::Breaks;
use super::phrase::{
    next_word, one_of, phrase_value, push_tail, set_to_value, Need, FILLERS, MAX_QUALIFIER_BYTES,
    MAX_QUALIFIER_WORDS, QUALIFIER_HEADS,
};
use super::prose::{value_word, PROSE_STOPWORDS};

/// French words that open a qualifier (`mot de passe du portail`, `pour le site`).
const FRENCH_HEADS: &str = "du de des pour sur au à";

/// French words that may stand between a link and the value; one is skipped.
const FRENCH_FILLERS: &str = "maintenant toujours désormais actuellement bien";

/// French words after a link that are not a value: a status or a function word.
const FRENCH_STOPWORDS: &str = "oublié oubliée incorrect incorrecte invalide expiré expirée \
     requis requise obligatoire faux fausse erroné erronée changé changée modifié modifiée \
     perdu perdue bloqué bloquée trop vide court courte long longue nécessaire différent \
     pareil même ici dans pour votre notre cette celui celle";

/// The keys whose value may run to its clause end (K-SECRET-TAIL-2): the cues of
/// [`PHRASE_CUE_RE`](super::phrase::PHRASE_CUE_RE) that take any value, and the French `mot de passe` and `mdp`. A
/// `-` or `_` between key words reads as a space (`mot-de-passe`). The word edges are
/// checked by [`key_tail_scan`], so emphasis may touch the key (`__password__`). It
/// reads the text in ASCII lower case, so its literals stay fast to find.
static TAIL_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"password|passwd|pwd|passphrase|(?:seed|recovery)[ \t_-]+phrase|api[ \t_-]?key|(?:secret|access|private)[ \t_-]+key|(?:access|auth)[ \t_-]+token|mot[ \t_-]+de[ \t_-]+passe|mdp",
    )
    .expect("tail key shape compiles")
});

/// Most emphasis marks skipped after a tail key (`**~~pwd~~**`).
const MAX_EMPHASIS: usize = 4;

/// A Markdown emphasis or code mark, or a closing quote (`*`, `_`, `` ` ``, `~`, `”`).
fn is_emphasis(ch: char) -> bool {
    ch == '~' || is_key_mark(ch)
}

/// `at` moved past a run of at most [`MAX_EMPHASIS`] emphasis marks.
fn skip_emphasis(text: &str, at: usize) -> usize {
    let marks = text[at..]
        .chars()
        .take(MAX_EMPHASIS)
        .take_while(|&ch| is_emphasis(ch));
    at + marks.map(char::len_utf8).sum::<usize>()
}

/// Whether `word`, its emphasis aside, links a tail key to its value: `is`, `was`,
/// `est`, `était`, or a bare separator (`: `, `**Password:**`).
fn is_tail_link(word: &str) -> bool {
    let word = word.trim_matches(is_emphasis);
    one_of("is was est était", word) || matches!(word, ":" | "=" | "->" | "=>" | "：")
}

/// Whether the value at `start..end` is a stopword (English or French), its emphasis
/// and closing punctuation aside (`__required__.`).
fn is_tail_stopword(text: &str, start: usize, end: usize) -> bool {
    let word = value_word(&text[start..end]).trim_matches(is_emphasis);
    let english = || {
        PROSE_STOPWORDS
            .iter()
            .any(|stop| stop.eq_ignore_ascii_case(word))
    };
    english() || one_of(FRENCH_STOPWORDS, word)
}

/// The value after a tail key's link, from `at`: after `set to` or `changed to` it must
/// look like a secret, as on main; else after one optional filler (`is now`, `est
/// maintenant`) it is the next word that is no stopword; else a word ending in `:`
/// within the qualifier caps brings a value that looks like a secret (`is the same as
/// before: …`).
fn tail_value(text: &str, at: usize, stop: usize) -> Option<SecretValue> {
    let next = next_word(text, at, stop, MAX_TERMINATOR_WORD)?;
    let word = &text[next.0..next.1];
    if one_of("set changed reset updated switched", word) {
        return set_to_value(text, at, stop, Need::Any);
    }
    let filler = one_of(FILLERS, word) || one_of(FRENCH_FILLERS, word);
    let from = if filler { next.1 } else { at };
    let (value, _) = phrase_value(text, from, stop, Need::Any, false);
    if let Some(value) = value.filter(|value| !is_tail_stopword(text, value.start, value.end)) {
        return Some(value);
    }
    let mut from = at;
    // `is the same as before: …`
    for _ in 0..MAX_QUALIFIER_WORDS {
        let (start, end) = next_word(text, from, stop, MAX_TERMINATOR_WORD)?;
        from = end;
        if end - at > MAX_QUALIFIER_BYTES || text[start..end].contains(['.', ',', ';', '!', '?']) {
            return None;
        }
        if text[..end].ends_with(':') {
            return phrase_value(text, end, stop, Need::Any, true).0;
        }
    }
    None
}

/// The K-SECRET-TAIL-2 spans, one reading for every phrasing (`My **password** is …`,
/// `password is set to …`, `Mon mot-de-passe est …`): a tail key and its emphasis, an
/// optional qualifier opened by an English or French head (`for the portal`, `du
/// portail`), a link ([`is_tail_link`]), and the value ([`tail_value`]) with its clause
/// tail unless it is quoted. It runs apart from [`phrase_scan`](super::phrase::phrase_scan) and only adds spans
/// (strict superset by construction). A key inside text already read is skipped, so the
/// scan stays linear.
pub(super) fn key_tail_scan(text: &str, breaks: &Breaks) -> Vec<SecretValue> {
    let mut extra = Vec::new();
    let (mut reach, mut resume) = (0, 0);
    // Same byte offsets: only ASCII letters change.
    let lower = text.to_ascii_lowercase();
    for key in TAIL_KEY_RE.find_iter(&lower) {
        let inside = text[..key.start()].ends_with(char::is_alphanumeric)
            || text[key.end()..].starts_with(char::is_alphanumeric);
        if key.start() < resume || inside {
            continue;
        }
        let stop = breaks.break_from(key.end());
        let mut at = skip_emphasis(text, key.end());
        let mut linked = false;
        // The link may follow the full qualifier, so it is read as one word more.
        for index in 0..=MAX_QUALIFIER_WORDS {
            let Some((start, end)) = next_word(text, at, stop, MAX_TERMINATOR_WORD) else {
                break;
            };
            let word = &text[start..end];
            at = end;
            if is_tail_link(word) {
                linked = true;
                break;
            }
            let head = one_of(FRENCH_HEADS, word)
                || QUALIFIER_HEADS
                    .iter()
                    .any(|head| head.eq_ignore_ascii_case(word));
            if (index == 0 && !head)
                || word.contains(['.', ',', ';', '!', '?', ':'])
                || end - key.end() > MAX_QUALIFIER_BYTES
            {
                break;
            }
        }
        resume = at;
        let value = linked.then(|| tail_value(text, at, stop)).flatten();
        resume = resume.max(value.map_or(0, |value| value.end));
        if let Some(value) = value {
            if !text[..value.start].ends_with(['"', '\'', '“', '‘', '«']) {
                push_tail(text, Some(&value), stop, &mut extra, &mut reach);
            }
            extra.push(value);
        }
    }
    // These spans are new to K-SECRET-TAIL-2: a long one is masked whole, never
    // refused, like `rest_value`'s whole-line remainder (`Mon mdp est `
    // + 1025 bytes was admitted on main and refused here). Every byte stays masked.
    for span in &mut extra {
        span.long = false;
    }
    extra
}

/// LABEL-VALUE-1 reads a value after its own prose links (`might be`, `,`, `set
/// to`) as [`key_tail_scan`] reads one after `is`: `None` for a stopword value at
/// `start..end`, else the end of its clause (`. , ; ! ?` or `stop`), never before `end`.
pub(crate) fn linked_clause_end(
    text: &str,
    start: usize,
    end: usize,
    stop: usize,
) -> Option<usize> {
    if is_tail_stopword(text, start, end) {
        return None;
    }
    let clause = text[start..stop]
        .split(['.', ',', ';', '!', '?'])
        .next()
        .unwrap_or("");
    Some(end.max(start + clause.trim_end().len()))
}
