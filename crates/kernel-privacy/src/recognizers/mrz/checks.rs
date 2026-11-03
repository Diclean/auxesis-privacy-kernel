//! ICAO 9303 check digits and the layout check tables.

use crate::checksum::passport_mrz_ok;

/// A check digit of a layout: the `(start, end)` payload fields it covers,
/// then its position.
pub(super) type Check = (&'static [(usize, usize)], usize);

/// TD3 line 2 (44): document, birth, expiry, personal number, composite.
pub(super) const TD3_CHECKS: &[Check] = &[
    (&[(0, 9)], 9),
    (&[(13, 19)], 19),
    (&[(21, 27)], 27),
    (&[(28, 42)], 42),
    (&[(0, 10), (13, 20), (21, 43)], 43),
];
/// TD2 line 2 (36): document, birth, expiry, composite.
pub(super) const TD2_CHECKS: &[Check] = &[
    (&[(0, 9)], 9),
    (&[(13, 19)], 19),
    (&[(21, 27)], 27),
    (&[(0, 10), (13, 20), (21, 35)], 35),
];
/// A visa row (MRV-A 44, MRV-B 36): document, birth and expiry only.
pub(super) const MRV_CHECKS: &[Check] = &[(&[(0, 9)], 9), (&[(13, 19)], 19), (&[(21, 27)], 27)];
/// TD1 line 2 (30): birth and expiry. Its composite also covers line 1, which
/// a row alone does not hold.
pub(super) const TD1_LINE2_CHECKS: &[Check] = &[(&[(0, 6)], 6), (&[(8, 14)], 14)];
/// TD1 line 1 (30): document.
pub(super) const TD1_LINE1_CHECKS: &[Check] = &[(&[(5, 14)], 14)];

/// Whether every check digit of `checks` is valid on `b`. A `<` check digit is
/// valid only on an all-`<` payload (an empty optional field); the document,
/// birth and expiry checks are digits, never `<`.
pub(super) fn holds(b: &[u8], checks: &[Check]) -> bool {
    checks.iter().all(|(from, at)| {
        let payload: Vec<u8> = from
            .iter()
            .flat_map(|&(s, e)| b[s..e].iter().copied())
            .collect();
        let payload = std::str::from_utf8(&payload).unwrap_or("");
        match b[*at] {
            b'<' => ![9, 19, 27].contains(at) && payload.bytes().all(|c| c == b'<'),
            digit @ b'0'..=b'9' => passport_mrz_ok(payload, digit - b'0'),
            _ => false,
        }
    })
}

/// The 7-3-1 score of a ten-character `payload + check digit` value, if valid.
///
/// The value may be lower case (the rule is case-insensitive), so it is
/// upper-cased before the check.
pub(super) fn check_score(value: &str) -> Option<f32> {
    if value.len() != 10 {
        return None;
    }
    let upper = value.to_ascii_uppercase();
    let (payload, check) = upper.split_at(9);
    let digit = check.bytes().next().map(|byte| byte - b'0');
    let shaped = payload.chars().any(|ch| ch.is_ascii_digit())
        && payload.chars().any(|ch| ch.is_ascii_uppercase());
    if shaped && digit.is_some_and(|digit| passport_mrz_ok(payload, digit)) {
        Some(1.0)
    } else {
        None
    }
}
