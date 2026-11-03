//! MRZ line and data-row detection.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use super::checks::{
    holds, MRV_CHECKS, TD1_LINE1_CHECKS, TD1_LINE2_CHECKS, TD2_CHECKS, TD3_CHECKS,
};

/// A machine-readable zone line (ICAO 9303 TD1/TD2/TD3: 30, 36 or 44 chars,
/// OCR may drop a few): a run of at least [`MRZ_LINE_MIN`] letters, digits and
/// `<` that holds a `<<` filler. Such a run is one maximal match, so no earlier
/// match can hide it, and it is masked whole: the name, the document number and
/// the dates all sit inside it. The scan is one regex pass (linear).
pub(super) static MRZ_LINE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9<]{28,}").expect("mrz line regex compiles"));
/// The shortest run read as an MRZ line (TD1 is 30 chars; two may be lost to OCR).
pub(super) const MRZ_LINE_MIN: usize = 28;
/// The longest data row, in characters (TD3 and MRV-A).
const MRZ_ROW_MAX: usize = 44;
/// The most tokens a data row spans: OCR may split it at blanks.
const MRZ_MAX_TOKENS: usize = 6;
/// The most spaces between two tokens of a data row.
const MRZ_MAX_GAP: usize = 3;
/// The most windows read in one token.
const MRZ_MAX_WINDOWS: usize = 4096;

/// A token of a data row: letters, digits, `<`, and `«` (OCR's `<`).
static MRZ_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9<«]+").expect("mrz token regex compiles"));

/// The issuers a TD1 line 1 may carry at positions 2-4 (ICAO 9303 part 3): ISO
/// 3166-1 alpha-3, then the ICAO codes (`D<<` Germany, the EU, British,
/// UN and other organisations, the stateless `XX*`, Kosovo, the former
/// Netherlands Antilles and the `UTO` specimen). A code the 7-3-1 check
/// passes by chance (one in ten) is no ID card line without one of them.
const TD1_ISSUERS: &str = "\
    ABW AFG AGO AIA ALA ALB AND ARE ARG ARM ASM ATA ATF ATG AUS AUT AZE BDI BEL BEN BES BFA BGD \
    BGR BHR BHS BIH BLM BLR BLZ BMU BOL BRA BRB BRN BTN BVT BWA CAF CAN CCK CHE CHL CHN CIV CMR \
    COD COG COK COL COM CPV CRI CUB CUW CXR CYM CYP CZE DEU DJI DMA DNK DOM DZA ECU EGY ERI ESH \
    ESP EST ETH FIN FJI FLK FRA FRO FSM GAB GBR GEO GGY GHA GIB GIN GLP GMB GNB GNQ GRC GRD GRL \
    GTM GUF GUM GUY HKG HMD HND HRV HTI HUN IDN IMN IND IOT IRL IRN IRQ ISL ISR ITA JAM JEY JOR \
    JPN KAZ KEN KGZ KHM KIR KNA KOR KWT LAO LBN LBR LBY LCA LIE LKA LSO LTU LUX LVA MAC MAF MAR \
    MCO MDA MDG MDV MEX MHL MKD MLI MLT MMR MNE MNG MNP MOZ MRT MSR MTQ MUS MWI MYS MYT NAM NCL \
    NER NFK NGA NIC NIU NLD NOR NPL NRU NZL OMN PAK PAN PCN PER PHL PLW PNG POL PRI PRK PRT PRY \
    PSE PYF QAT REU ROU RUS RWA SAU SDN SEN SGP SGS SHN SJM SLB SLE SLV SMR SOM SPM SRB SSD STP \
    SUR SVK SVN SWE SWZ SXM SYC SYR TCA TCD TGO THA TJK TKL TKM TLS TON TTO TUN TUR TUV TWN TZA \
    UGA UKR UMI URY USA UZB VAT VCT VEN VGB VIR VNM VUT WLF WSM YEM ZAF ZMB ZWE D<< EUE GBD GBN \
    GBO GBP GBS UNA UNK UNO XOM XXA XXB XXC XXX RKS ANT XBA XCC XCE XCO XDC XEC XES XIM XMP XPO \
    UTO";

/// The data rows of `body` with no `<<` filler, as byte ranges of `body`. A row
/// is the exact length of its layout (TD1 30, TD2 36, TD3 44, visa 36 or 44)
/// once its blanks are dropped: whole tokens of letters, digits, `<` and `«`
/// (OCR's `<`) joined by at most [`MRZ_MAX_GAP`] spaces, at most
/// [`MRZ_MAX_TOKENS`] tokens, never across a line break. The range runs from the
/// first character of the first token to the last of the last, spaces
/// included. Linear: each token starts at most [`MRZ_MAX_TOKENS`] windows, and
/// only a window of a layout's exact length is read.
pub(super) fn data_rows(body: &str) -> Vec<(usize, usize)> {
    let tokens: Vec<(usize, usize)> = MRZ_TOKEN_RE
        .find_iter(body)
        .map(|found| (found.start(), found.end()))
        .collect();
    let mut rows = Vec::new();
    let mut row: Vec<u8> = Vec::with_capacity(MRZ_ROW_MAX + 1);
    for (first, &(start, _)) in tokens.iter().enumerate() {
        row.clear();
        for (at, &(from, to)) in tokens[first..].iter().enumerate().take(MRZ_MAX_TOKENS) {
            if at > 0 {
                let gap = &body[tokens[first + at - 1].1..from];
                if gap.len() > MRZ_MAX_GAP || !gap.bytes().all(|b| b == b' ') {
                    break;
                }
            }
            row.extend(body[from..to].chars().map(read_char));
            if row.len() > MRZ_ROW_MAX {
                break;
            }
            if at > 0 && matches!(row.len(), 30 | 36 | 44) && is_data_row(&row, true) {
                rows.push((start, to));
                break;
            }
        }
    }
    for &(from, to) in &tokens {
        token_rows(body, from, to, &mut rows);
    }
    rows
}

/// A row as a byte: `«` is OCR's `<`.
fn read_char(ch: char) -> u8 {
    if ch == '«' {
        b'<'
    } else {
        ch as u8
    }
}

/// The rows inside one token, a row alone or glued to text or to other rows
/// with no separator (`xX4R2…18y`, two rows end to end): every window of a
/// layout's width (44, 36, 30) that is a data row, as its own byte range, so
/// the text around it is left as it was. A cheap shape test ([`plausible`])
/// keeps a window from being read, and at most [`MRZ_MAX_WINDOWS`] windows of a
/// token are read: linear in the token.
fn token_rows(body: &str, from: usize, to: usize, rows: &mut Vec<(usize, usize)>) {
    let token = &body[from..to];
    let chars: Vec<(usize, char)> = token.char_indices().collect();
    if chars.len() < 30 {
        return;
    }
    let bytes: Vec<u8> = chars
        .iter()
        .map(|&(_, ch)| read_char(ch).to_ascii_uppercase())
        .collect();
    let mut read = 0;
    for width in [44, 36, 30] {
        for first in 0..(bytes.len() + 1).saturating_sub(width) {
            let row = &bytes[first..first + width];
            if !plausible(row) {
                continue;
            }
            read += 1;
            if read > MRZ_MAX_WINDOWS {
                return;
            }
            if is_data_row(row, width == bytes.len()) {
                let end = chars.get(first + width).map_or(token.len(), |&(at, _)| at);
                rows.push((from + chars[first].0, from + end));
            }
        }
    }
}

/// Whether the upper-case `row` (30, 36 or 44) has the shape of a data row, a
/// letter OCR may read for a digit counting as a digit: no allocation, and
/// almost every window of ordinary text stops at its first test.
fn plausible(row: &[u8]) -> bool {
    let digit = |c: u8| c.is_ascii_digit() || matches!(c, b'O' | b'I' | b'L');
    let digits = |r: Range<usize>| row[r].iter().all(|&c| digit(c));
    let letters = |r: Range<usize>| row[r].iter().all(|&c| c.is_ascii_uppercase() || c == b'<');
    let sex = |at: usize| matches!(row[at], b'M' | b'F' | b'X' | b'<');
    match row.len() {
        44 | 36 => letters(10..13) && sex(20) && digit(row[9]) && digits(13..20) && digits(21..28),
        _ => {
            digits(0..7) && sex(7) && digits(8..15) && letters(15..18)
                || matches!(row[0], b'I' | b'A' | b'C') && letters(1..5) && digit(row[14])
        }
    }
}

/// Whether `row` (characters of a row of 30, 36 or 44, `«` already `<`) is an
/// MRZ data row. It is read upper-cased; the letters OCR reads for a digit
/// (`O`, `I`, `l`) in the numeric fields and check positions are read as that
/// digit.
///
/// `whole` is false for a window inside a longer token.
///
/// A row holds only if every check digit of its layout validates, however clean
/// it looks: TD3 document, birth, expiry, personal number and composite; TD2
/// document, birth, expiry and composite; a visa row (MRV-A, MRV-B) document,
/// birth and expiry, with a `<` in its optional data; TD1 line 1 document; TD1
/// line 2 birth and expiry. A shape alone is no row: a code that fails its
/// checks is main's, not masked whole. The document number and the optional
/// data are tried as written and with OCR letters read as digits, the optional
/// data also with `K` and `C` read as `<`.
fn is_data_row(row: &[u8], whole: bool) -> bool {
    let mut b = row.to_ascii_uppercase();
    let nation =
        |b: &[u8], r: Range<usize>| b[r].iter().all(|c| c.is_ascii_uppercase() || *c == b'<');
    let digits = |b: &[u8], r: Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let sex = |b: &[u8], at: usize| matches!(b[at], b'M' | b'F' | b'X' | b'<');
    match b.len() {
        44 | 36 => {
            // Numeric: document check, birth with its check, expiry with its check.
            let (long, optional_end) = if b.len() == 44 {
                (TD3_CHECKS, 42)
            } else {
                (TD2_CHECKS, 35)
            };
            digits_read(&mut b, [9..10, 13..20, 21..28].into_iter().flatten());
            if !(nation(&b, 10..13) && digits(&b, 13..19) && sex(&b, 20) && digits(&b, 21..27))
                || !b[9].is_ascii_digit()
            {
                return false;
            }
            // A visa row's optional data runs to the end of the row.
            let visa = variants(&b, 0..9, 28..b.len());
            // The personal-number and composite check positions are numeric too.
            let tail = b.len() - 1;
            digits_read(&mut b, [optional_end, tail]);
            variants(&b, 0..9, 28..optional_end)
                .iter()
                .any(|variant| holds(variant, long))
                || visa
                    .iter()
                    .any(|v| holds(v, MRV_CHECKS) && v[28..].contains(&b'<'))
        }
        30 => {
            let mut line2 = b.clone();
            digits_read(&mut line2, (0..7).chain(8..15));
            if digits(&line2, 0..6)
                && sex(&line2, 7)
                && digits(&line2, 8..14)
                && nation(&line2, 15..18)
                && line2[6].is_ascii_digit()
                && line2[14].is_ascii_digit()
                && holds(&line2, TD1_LINE2_CHECKS)
            {
                return true;
            }
            // TD1 line 1 has the weakest evidence (one check digit): inside a longer
            // token it must show a filler `<`.
            // ICAO 9303: an `I`, `A` or `C` document code, then a letter or `<`,
            // then a known issuer.
            let issuer = |b: &[u8]| {
                TD1_ISSUERS
                    .split_whitespace()
                    .any(|c| c.as_bytes() == &b[2..5])
            };
            if !(matches!(b[0], b'I' | b'A' | b'C') && nation(&b, 1..2) && issuer(&b))
                || !whole && !b.contains(&b'<')
            {
                return false;
            }
            digits_read(&mut b, [14]);
            if !b[14].is_ascii_digit() {
                return false;
            }
            let digit_count = |b: &[u8]| b.iter().filter(|c| c.is_ascii_digit()).count();
            variants(&b, 5..14, 15..15)
                .iter()
                .any(|v| digit_count(v) >= 6 && holds(v, TD1_LINE1_CHECKS))
        }
        _ => false,
    }
}

/// Read the letters OCR mistakes for a digit (`O` as `0`, `I` and `L` as `1`)
/// at the positions `at` of `b` as digits; how many were read.
fn digits_read(b: &mut [u8], at: impl IntoIterator<Item = usize>) -> usize {
    let mut read = 0;
    for at in at {
        let digit = match b[at] {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            _ => continue,
        };
        b[at] = digit;
        read += 1;
    }
    read
}

/// The readings of `b` to try: its `document` number as written or with OCR
/// letters read as digits, crossed with its `optional` data as written, with
/// letters read as digits, with `K` and `C` read as `<`, and both.
fn variants(b: &[u8], document: Range<usize>, optional: Range<usize>) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(8);
    for doc in [false, true] {
        for opt in 0..4 {
            let mut v = b.to_vec();
            if doc {
                digits_read(&mut v, document.clone());
            }
            if opt & 1 == 1 {
                digits_read(&mut v, optional.clone());
            }
            if opt & 2 == 2 {
                for c in &mut v[optional.clone()] {
                    if matches!(*c, b'K' | b'C') {
                        *c = b'<';
                    }
                }
            }
            out.push(v);
        }
    }
    out
}
