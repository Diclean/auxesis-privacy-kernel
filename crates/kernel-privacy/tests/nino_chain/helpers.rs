//! The vocabulary every NINO-CHAIN module shares: the shapes of a number,
//! the builders that write them, and the reader that reads a masked text back
//! exactly.

#[allow(dead_code)]
mod cases {
    include!("../data/norm1_cases.rs");
}
pub(crate) use cases::{covered, exact_ranges, issue, masked, MODES};

/// The line breaks and the glue the normaliser folds into one separator: LF,
/// CRLF, CR, tab, VT, NEL, U+2028, U+2029, a plain space, a break with an
/// indent, and no separator at all (two numbers written together). Glue is
/// last, so [`break_for`] can drop it by length alone.
pub(crate) const BREAKS: &[&str] = &[
    "\n", "\r\n", "\r", "\t", "\u{b}", "\u{85}", "\u{2028}", " ", "\n  ", "\r\n\t", "",
];

/// How many shapes of number this file builds, and the digits each one is built
/// from. A chain gives every number its own triple, so no two of them are the
/// same value.
pub(crate) const PAIRS: [[&str; 3]; 8] = [
    ["12", "34", "56"],
    ["65", "43", "21"],
    ["87", "16", "49"],
    ["23", "58", "90"],
    ["41", "72", "06"],
    ["95", "38", "14"],
    ["60", "29", "83"],
    ["74", "51", "36"],
];

/// The twelve shapes a number may take: compact, spaced, one to three spaces,
/// `-`, `/`, `.`, mixed spacing, a spaced prefix before compact digits, mixed
/// hyphen and space, and the lower-case form of spaced and slashed. Kind 7
/// (`{p} {a}  {b} {c}`) is the one shape neither pass reads, kept so a chain
/// that holds it asks for the same mask as one that does not.
pub(crate) const KINDS: usize = 12;

/// Every shape except the seventh, which no pass reads: three of its four
/// boundaries hold one separator and one holds two, and each pass wants one
/// separator count throughout. A chain that holds one is a near miss, so it is
/// generated as a neighbour and is never asked to mask.
pub(crate) const SHAPES: [usize; 11] = [0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11];

/// The one shape that is not a number when it is written straight onto a
/// letter: the lower-case separated one. FIN-6 ([`separated_nino_at`]) asks for
/// capitals where a letter touches a separated number, so no pass reads
/// `refab/65/43/21/b` on any base — there it is a near miss, not a leak, and a
/// chain that glues one must not be asked to mask it.
pub(crate) const GLUE_SAFE: [bool; KINDS] = [
    true, true, true, true, true, true, true, false, true, false, true, true,
];

/// The shapes only the separated pass reads. They need something that is not a
/// digit in front of them, which a number with a suffix letter of its own gives
/// them and a bare head does not.
pub(crate) const SEPARATED: [bool; KINDS] = [
    false, false, false, true, true, true, true, true, false, true, false, false,
];

/// The breaks a chain of these shapes may use: every one, glue included, where
/// the chain can carry glue (see [`GLUE_SAFE`], [`SEPARATED`] and `bare_head`),
/// and every one but the glue otherwise. Glue is last in [`BREAKS`], so a
/// prefix of the list is the same list without it.
pub(crate) fn breaks_for(kinds: &[usize], bare_head: bool) -> &'static [&'static str] {
    let carries = kinds.iter().all(|kind| GLUE_SAFE[*kind])
        && !(bare_head && kinds.iter().any(|kind| SEPARATED[*kind]));
    if carries {
        BREAKS
    } else {
        &BREAKS[..BREAKS.len() - 1]
    }
}

/// The prefix letters, all of them ones HMRC can issue.
pub(crate) const PREFIXES: [&str; 6] = ["AB", "CB", "CE", "JG", "PN", "XY"];

/// Heads that stand on their digits (shape, prefix): the letter behind one is
/// its suffix, so it needs a separator there and cannot carry glue at all.
pub(crate) const BARE_HEADS: [(usize, &str); 6] = [
    (0, "AB"),
    (5, "AB"),
    (2, "AB"),
    (1, "AB"),
    (5, "QQ"),
    (10, "AB"),
];

/// Heads that close with a suffix letter `C` of their own (shape, prefix), so a
/// letter glued behind them lands on that letter.
pub(crate) const WHOLE_HEADS: [(usize, &str); 6] = [
    (1, "AB"),
    (0, "AB"),
    (2, "AB"),
    (5, "QQ"),
    (3, "PN"),
    (4, "AB"),
];

/// The shapes a head with no suffix letter of its own may take: the ones the
/// compact pass reads, because the letter that follows such a head is its
/// suffix and has to sit behind a separator that pass accepts. A separated head
/// would need its own `/`, `.` or second space there instead.
pub(crate) const HEADS: [usize; 6] = [0, 1, 2, 8, 10, 11];

/// The prefixes of a chain that holds a head with no suffix letter: the letter
/// behind that head is its suffix, so the next number must open with A to D.
pub(crate) const HEAD_PREFIXES: [&str; 3] = ["AB", "CB", "CE"];

/// The suffix letters, A to D.
pub(crate) const LETTERS: [char; 4] = ['A', 'B', 'C', 'D'];

/// One number in shape `kind`, with the digits of `triple` and the suffix
/// `suffix` (no letter is a head whose digits end a line). Built from the index
/// every time, never written out as a literal.
pub(crate) fn number(kind: usize, prefix: &str, triple: usize, suffix: Option<char>) -> String {
    let (p, s) = match kind {
        8 | 9 => (
            prefix.to_ascii_lowercase(),
            suffix.map(|letter| letter.to_ascii_lowercase()),
        ),
        _ => (prefix.to_string(), suffix),
    };
    let [a, b, c] = PAIRS[triple % PAIRS.len()];
    let body = match kind {
        0 | 8 => format!("{p} {a} {b} {c}"),
        1 => format!("{p}{a}{b}{c}"),
        2 => format!("{p}-{a}-{b}-{c}"),
        3 | 9 => format!("{p}/{a}/{b}/{c}"),
        4 => format!("{p}.{a}.{b}.{c}"),
        5 => format!("{p}  {a}  {b}  {c}"),
        6 => format!("{p}   {a}   {b}   {c}"),
        7 => format!("{p} {a}  {b} {c}"),
        10 => format!("{p} {a}{b}{c}"),
        _ => format!("{p}-{a} {b}-{c}"),
    };
    let sep = match kind {
        1 | 10 => "",
        2 => "-",
        3 | 9 => "/",
        4 => ".",
        5 => "  ",
        6 => "   ",
        _ => " ",
    };
    s.map_or(body.clone(), |letter| format!("{body}{sep}{letter}"))
}

/// Every number a gate must mask, checked with the shared exact reader: a
/// refusal or an output that does not read back exactly is a finding, as is a
/// value that sits in the clear.
pub(crate) fn check(out: &mut Vec<String>, text: &str, keep: &[String]) {
    for &mode in &MODES {
        let ranges = match masked(mode, text) {
            None => {
                out.push(format!("{mode:?} refused {text:?}"));
                continue;
            }
            Some(ranges) => ranges,
        };
        for value in keep {
            let at = match text.find(value.as_str()) {
                Some(at) => at,
                None => {
                    out.push(format!("{text:?}: {value:?} is not in the text"));
                    break;
                }
            };
            if !covered(&ranges, at, at + value.len()) {
                out.push(format!("{mode:?} {text:?}: {value:?} is in clear",));
            }
        }
    }
}

/// The values a next number's suffix is glued to in [`targeted`]: values the
/// first round masks whole, so only the residue round reads that number. The
/// IBANs are the public specimens; each key is built at run time.
pub(crate) fn tails() -> [String; 5] {
    let body: String = (0..36)
        .map(|at| (b'a' + (at * 7 % 26) as u8) as char)
        .collect();
    [
        "GB82WEST12345698765432".to_string(),
        "FR7630006000011234567890189".to_string(),
        format!("ghp_{body}"),
        format!("AKIA{}", body[..16].to_ascii_uppercase()),
        format!("glpat-{}", &body[..20]),
    ]
}

/// The exact ranges a gate masked, or `None` for a refusal or for an output the
/// shared reader cannot read back (`exact_mask.rs`): a first-round span of one
/// class that the residue round then split into pieces of another. A baseline
/// records `!` for those, so it claims nothing there rather than reading them a
/// second way.
pub(crate) fn read(
    mode: kernel_core::privacy::PrivacyMode,
    text: &str,
) -> Option<Option<Vec<(usize, usize)>>> {
    issue(mode, text).map(|(output, minted)| exact_ranges(mode, text, &output, &minted))
}

/// The `start-end` ranges of one masked text as a record; `!` is a refusal or an
/// output the shared reader cannot read back.
pub(crate) fn record_of(ranges: &Option<Option<Vec<(usize, usize)>>>) -> String {
    ranges.clone().flatten().map_or("!".into(), |ranges| {
        ranges
            .iter()
            .map(|(start, end)| format!("{start}-{end},"))
            .collect()
    })
}

pub(crate) fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

pub(crate) fn probe(text: &str, ranges: &[(usize, usize)]) -> Vec<String> {
    ranges
        .iter()
        .map(|&(s, e)| text.get(s..e).unwrap_or("<oob>").to_string())
        .collect()
}

/// The text count and an FNV-1a hash of every text, so a refreeze is deliberate.
pub(crate) fn header(inputs: &[String]) -> String {
    let hash = inputs
        .iter()
        .flat_map(|t| t.bytes().chain([0]))
        .fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        });
    format!("{} {hash}", inputs.len())
}

/// One fixture: the header, then the records of 128 texts per line.
pub(crate) fn fixture(inputs: &[String]) -> String {
    let each = |text: &String| MODES.map(|mode| record_of(&read(mode, text))).join("|");
    let lines: Vec<String> = inputs
        .chunks(128)
        .map(|chunk| chunk.iter().map(each).collect::<Vec<_>>().join(";") + ";")
        .collect();
    format!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(inputs),
        lines.join("\n")
    )
}
