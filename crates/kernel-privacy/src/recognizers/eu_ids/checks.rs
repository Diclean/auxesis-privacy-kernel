//! The check digits of the EU national and tax identifiers.

use super::scan::compact;

/// The German Steuer-ID: eleven digits, the last one the ISO 7064 check.
pub(super) fn de_steuer_id_ok(digits: &str) -> bool {
    if digits.len() != 11 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let mut product = 10u32;
    for byte in digits.as_bytes()[..10].iter() {
        let mut sum = (u32::from(byte - b'0') + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (2 * sum) % 11;
    }
    let expected = if 11 - product == 10 { 0 } else { 11 - product };
    expected == u32::from(digits.as_bytes()[10] - b'0')
}

/// The Dutch BSN: nine digits whose weighted sum is a multiple of eleven.
pub(super) fn nl_bsn_ok(digits: &str) -> bool {
    if digits.len() != 9 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    const WEIGHTS: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum: i32 = digits
        .bytes()
        .zip(WEIGHTS)
        .map(|(byte, weight)| i32::from(byte - b'0') * weight)
        .sum();
    sum % 11 == 0
}

/// The Belgian national number: the control number is `97 - (prefix mod 97)`,
/// the date must hold, and the century may stand in front.
///
/// A birth after 2000 is written with the century in front, and its check is
/// computed on the number with that century in front. Either check may hold.
pub(super) fn be_national_ok(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    let (prefix, control) = match bytes.len() {
        11 => (&digits[0..9], &digits[9..11]),
        12 if matches!(bytes[0], b'1' | b'2') => (&digits[1..10], &digits[10..12]),
        _ => return false,
    };
    // The date must hold: a month of the year and a day of that month.
    let month = prefix[2..4].parse::<u32>().unwrap_or(0);
    let day = prefix[4..6].parse::<u32>().unwrap_or(0);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    let Ok(number) = prefix.parse::<u64>() else {
        return false;
    };
    let Ok(got) = control.parse::<u64>() else {
        return false;
    };
    // The check of a birth after 2000 is computed on the number with the
    // century in front: a `2` and the nine digits.
    let with_century = number + 2 * 1_000_000_000;
    got == 97 - (number % 97) || got == 97 - (with_century % 97)
}

/// The digits of `digits` as numbers, when every byte is an ASCII digit.
fn digit_values(digits: &str, len: usize) -> Option<Vec<u32>> {
    (digits.len() == len && compact(digits))
        .then(|| digits.bytes().map(|byte| u32::from(byte - b'0')).collect())
}

/// The sum of the digits times their weights.
fn weighted(digits: &[u32], weights: &[u32]) -> u32 {
    digits
        .iter()
        .zip(weights)
        .map(|(digit, weight)| digit * weight)
        .sum()
}

/// Whether `DD MM` read from two digit pairs is a day of a month: the day may
/// carry `offset` (a Swedish coordination number adds 60).
fn day_month_ok(day: u32, month: u32, offset: u32) -> bool {
    (1..=12).contains(&month)
        && ((1..=31).contains(&day) || (offset > 0 && (1 + offset..=31 + offset).contains(&day)))
}

/// The Polish PESEL: `YYMMDD`, the month carrying the century (+80, +0, +20,
/// +40, +60), a serial, and the check over the weights 1 3 7 9.
pub(super) fn pl_pesel_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 11) else {
        return false;
    };
    let sum = weighted(&d, &[1, 3, 7, 9, 1, 3, 7, 9, 1, 3]);
    let month = (d[2] * 10 + d[3]) % 20;
    let day = d[4] * 10 + d[5];
    day_month_ok(day, month, 0) && (10 - sum % 10) % 10 == d[10]
}

/// The Portuguese NIF: the first digit names the kind, the weights 9 to 2,
/// modulo 11; a remainder under two is a 0.
pub(super) fn pt_nif_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 9) else {
        return false;
    };
    if d[0] == 0 || d[0] == 4 && d[1] != 5 || d[0] == 7 {
        return false;
    }
    let rest = weighted(&d, &[9, 8, 7, 6, 5, 4, 3, 2]) % 11;
    (if rest < 2 { 0 } else { 11 - rest }) == d[8]
}

/// The Austrian SV-Nr: a serial that never starts with 0, the check digit,
/// and the birth date `DDMMYY`; the weights 3 7 9 5 8 4 2 1 6, modulo 11, a
/// remainder of 10 never issued.
pub(super) fn at_sv_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 10) else {
        return false;
    };
    let serial_and_date = [d[0], d[1], d[2], d[4], d[5], d[6], d[7], d[8], d[9]];
    let sum = weighted(&serial_and_date, &[3, 7, 9, 5, 8, 4, 2, 1, 6]);
    d[0] != 0 && day_month_ok(d[4] * 10 + d[5], d[6] * 10 + d[7], 0) && sum % 11 == d[3]
}

/// The Swedish personnummer: ten digits, or twelve with the century (`18`,
/// `19` or `20`) in front; the date holds, the day of a coordination number
/// carrying 60, and Luhn holds over the ten digits.
pub(super) fn se_personnummer_ok(digits: &str) -> bool {
    let ten = match digits.len() {
        10 => digits,
        12 if matches!(&digits[..2], "18" | "19" | "20") => &digits[2..],
        _ => return false,
    };
    let Some(d) = digit_values(ten, 10) else {
        return false;
    };
    let luhn: u32 = d
        .iter()
        .enumerate()
        .map(|(at, &digit)| match (at % 2, digit * 2) {
            (0, doubled) if doubled > 9 => doubled - 9,
            (0, doubled) => doubled,
            _ => digit,
        })
        .sum();
    day_month_ok(d[4] * 10 + d[5], d[2] * 10 + d[3], 60) && luhn.is_multiple_of(10)
}

/// The Romanian CNP: the sex and century digit, `YYMMDD`, the county (01 to
/// 52, or 70), a serial and the check over the weights 2 7 9 1 4 6 3 5 8 2 7
/// 9, modulo 11, a remainder of 10 written 1.
pub(super) fn ro_cnp_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 13) else {
        return false;
    };
    let rest = weighted(&d, &[2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9]) % 11;
    let county = d[7] * 10 + d[8];
    d[0] != 0
        && day_month_ok(d[5] * 10 + d[6], d[3] * 10 + d[4], 0)
        && ((1..=52).contains(&county) || county == 70)
        && (if rest == 10 { 1 } else { rest }) == d[12]
}

/// The Czech and Slovak rodné číslo of ten digits: `YYMMDD`, the month of a
/// woman carrying 50 and, from 2004, either month 20 more; the number is a
/// multiple of eleven, or its first nine digits leave 10 and it ends with 0.
/// The nine digits of a birth before 1954 carry no check.
pub(super) fn cz_rodne_cislo_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 10) else {
        return false;
    };
    let Ok(number) = digits.parse::<u64>() else {
        return false;
    };
    let month = (d[2] * 10 + d[3]) % 50;
    let month = if month > 20 { month - 20 } else { month };
    day_month_ok(d[4] * 10 + d[5], month, 0)
        && (number % 11 == 0 || (number / 10) % 11 == 10 && d[9] == 0)
}

/// The Greek AMKA: `DDMMYY`, a serial, and Luhn over the eleven digits.
pub(super) fn gr_amka_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 11) else {
        return false;
    };
    day_month_ok(d[0] * 10 + d[1], d[2] * 10 + d[3], 0) && luhn(&d)
}

/// The Bulgarian EGN: `YYMMDD`, the month carrying 20 for the 1800s and 40
/// for the 2000s, a serial and the check over the weights 2 4 8 5 10 9 7 3 6,
/// modulo 11, a remainder of 10 written 0.
pub(super) fn bg_egn_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 10) else {
        return false;
    };
    let month = d[2] * 10 + d[3];
    let month = if month > 40 { month - 40 } else { month % 20 };
    let rest = weighted(&d, &[2, 4, 8, 5, 10, 9, 7, 3, 6]) % 11;
    day_month_ok(d[4] * 10 + d[5], month, 0) && rest % 10 == d[9]
}

/// Whether Luhn holds: from the right, every second digit doubled.
fn luhn(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(at, &digit)| match (at % 2, digit * 2) {
            (1, doubled) if doubled > 9 => doubled - 9,
            (1, doubled) => doubled,
            _ => digit,
        })
        .sum();
    sum.is_multiple_of(10)
}
