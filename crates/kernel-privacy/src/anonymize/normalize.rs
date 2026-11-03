//! Folding a value so spellings of one value share a token.

use unicode_normalization::UnicodeNormalization;

use crate::span::EntityKind;

/// Fold a value so visually identical values share a token, and distinct values
/// never do.
///
/// Every kind is NFKC-folded and trimmed first, so full-width forms match their
/// ASCII spelling. Then:
///
/// * a phone keeps its numeric characters and any `+`, so `+33 6 12 34 56 78`
///   and `+33612345678` match while `33612345678` stays apart;
/// * a card keeps its numeric characters only;
/// * the other identifier kinds (IBAN, NIR, passport…) keep every letter and
///   digit, folded to uppercase: a NIR's `2A` and `2B` department codes, and a
///   passport's letters, are part of the value;
/// * textual kinds (e-mails, names, places) keep every letter, accents and CJK
///   included, and are casefolded.
///
/// Dropping non-ASCII characters was the old collision: `ÉA1` became `A1`.
pub(crate) fn normalize_value(kind: EntityKind, value: &str) -> String {
    let folded: String = value.nfkc().collect();
    let trimmed = folded.trim();
    match kind {
        EntityKind::Phone => {
            let digits: String = trimmed
                .chars()
                .filter(|ch| ch.is_numeric() || *ch == '+')
                .collect();
            // A bare Chinese mobile is keyed in its E.164 form, so `13800138000`
            // and `+86 138 0013 8000` share one token.
            if is_bare_cn_mobile(&digits) {
                format!("+86{digits}")
            } else {
                digits
            }
        }
        EntityKind::CreditCard => trimmed.chars().filter(|ch| ch.is_numeric()).collect(),
        _ if kind.is_identifier() => trimmed
            .chars()
            .filter(|ch| ch.is_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect(),
        // An address keeps its case folding, which its tests pin. Other text
        // keys on the exact spelling: `Le` and `le`, or `GROSS` and `Groß`, are
        // two tokens, and restore gives back each original byte for byte.
        EntityKind::Email => casefold(trimmed),
        _ => value.to_string(),
    }
}

/// Whether a phone value is eleven national digits starting `1[3-9]` with no
/// country code: the Chinese mobile shape the Standard phone rule masks bare.
fn is_bare_cn_mobile(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    bytes.len() == 11
        && bytes[0] == b'1'
        && (b'3'..=b'9').contains(&bytes[1])
        && bytes.iter().all(u8::is_ascii_digit)
}

/// Full case folding for textual values. Each character is lowercased on its
/// own, so no context rule applies (the final sigma folds like any other Σ, and
/// the Turkish dotless `ı` stays apart from `i`). The two letters whose fold is
/// more than one letter are spelled out, and NFKC runs again so a folded letter
/// keeps the composed form of its peers.
pub(crate) fn casefold(text: &str) -> String {
    let mut lowered = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            'ß' | 'ẞ' => lowered.push_str("ss"),
            'ς' => lowered.push('σ'),
            _ => lowered.extend(ch.to_lowercase()),
        }
    }
    lowered.nfkc().collect()
}

/// The kind a token was minted for, read from its `KIND_` prefix. The longest
/// matching kind name wins, so no kind name can shadow a longer one.
pub(crate) fn kind_of_token(token: &str) -> Option<EntityKind> {
    EntityKind::ALL
        .into_iter()
        .filter(|kind| {
            token
                .strip_prefix(kind.as_str())
                .is_some_and(|rest| rest.starts_with('_'))
        })
        .max_by_key(|kind| kind.as_str().len())
}
