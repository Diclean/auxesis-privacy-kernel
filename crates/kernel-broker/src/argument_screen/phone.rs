//! Phone candidates: bare digit runs that open with a calling code or a national
//! trunk `0`.

use super::COUNTRY_CODES;

/// Whether an all-digit text is shaped like a phone number: 10 to 15 digits that
/// open with a country code, or a national trunk `0` followed by 9 or 10 digits.
/// An epoch timestamp is never one.
pub(super) fn phone_shaped_digits(text: &str) -> bool {
    let len = text.len();
    if !(10..=15).contains(&len) || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if is_epoch_shaped(text) {
        return false;
    }
    (text.starts_with('0') && len <= 11) || starts_with_country_code(text)
}

/// Whether `text` is an epoch timestamp: all digits, ten long in seconds or
/// thirteen in milliseconds, opening with `1`. No national US number opens with
/// `1`, so such a value is not a phone.
pub(super) fn is_epoch_shaped(text: &str) -> bool {
    matches!(text.len(), 10 | 13)
        && text.starts_with('1')
        && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `digits` opens with a calling code from [`COUNTRY_CODES`].
fn starts_with_country_code(digits: &str) -> bool {
    (1..=3).any(|len| {
        digits
            .get(..len)
            .is_some_and(|prefix| COUNTRY_CODES.split_whitespace().any(|code| code == prefix))
    })
}
