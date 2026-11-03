//! Lower-case AWS access key ids, and the random letter bodies that read as no word.

use std::sync::LazyLock;

use regex::Regex;

/// An AWS access key id in any case, its sixteen characters read by the caller.
static AWS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:akia|asia)[0-9a-z]{16}").expect("AWS shape compiles"));

/// Vowels at most in an all-letter id body: random letters, not a word.
const MAX_ID_VOWELS: usize = 5;

/// Letter pairs seen ten times or fewer across an English word list
/// (`/usr/share/dict/words`, 143 pairs): random letters hold one far more often
/// than words do.
const RARE_PAIRS: &str = concat!(
    "bqbxbzcbcfcgcjcvcwcxdqdxfcfjfkfqfvfxfzgjgqgvgxgzhjhqhxhzjbjcjdjfjgjhjjjk",
    "jljmjnjpjqjrjsjtjvjwjxjyjzkqkvkxkzljlqlxmjmqmxmzpqpvpxpzqaqbqcqdqeqfqgqh",
    "qiqjqkqlqmqnqoqpqqqrqsqtqvqwqxqyqzrxsxtqtxvbvcvdvfvgvhvjvkvlvmvnvpvqvsvt",
    "vwvxvzwjwqwvwxxdxgxjxkxnxqxrxvxxxzyjyqyyzczfzgzhzjzkzmznzpzqzrzszvzwzx",
);

/// An id body with a digit, or a body of sixteen letters that reads as no word
/// (few vowels, or a pair words almost never hold) after `akia` in any case or
/// a lower-case `asia`.
fn id_body(key: &str) -> bool {
    let body = &key.as_bytes()[4..];
    if body.iter().any(u8::is_ascii_digit) {
        return true;
    }
    let lower = !key.bytes().any(|b| b.is_ascii_uppercase());
    let folded = body.to_ascii_lowercase();
    let vowels = folded.iter().filter(|b| b"aeiou".contains(b)).count();
    let rare = folded
        .windows(2)
        .any(|pair| RARE_PAIRS.as_bytes().chunks(2).any(|known| known == pair));
    (lower || key[..4].eq_ignore_ascii_case("akia")) && (vowels <= MAX_ID_VOWELS || rare)
}

pub(super) fn glued_aws(text: &str, spans: &mut Vec<(usize, usize)>) {
    let bytes = text.as_bytes();
    for key in AWS_RE.find_iter(text) {
        let joined = key.start() > 0 && bytes[key.start() - 1].is_ascii_alphanumeric();
        if !joined && id_body(key.as_str()) {
            // A glued suffix goes with the id: the word is one value.
            let glued = bytes[key.end()..]
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric());
            spans.push((key.start(), key.end() + glued.count()));
        }
    }
}
