//! Header cells, the names they hold, and the table a header line opens.

/// The header names a table pass reads: main's list under the row cap, the
/// wider list with no cap, and that list with a bare `pass`
/// and the password manager export names. Each pass only
/// adds spans, so a new name never changes what the older passes hide.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Names {
    Main,
    Wide,
    Export,
}

impl Names {
    pub(super) fn wide(self) -> bool {
        self != Names::Main
    }
}

/// `cell` lower-cased, without blanks, `_` or `-`; `wide` also drops a last
/// colon (`Mot de passe :`), no-break blanks and combining accents, so an NFD
/// `Clé privée` reads as its NFC form.
pub(super) fn folded(cell: &str, wide: bool) -> String {
    let cell = cell.trim().trim_matches('"');
    let cell = if wide {
        cell.trim_end_matches([':', ' ', '\t', '\u{a0}', '\u{202f}'])
    } else {
        cell
    };
    if cell.is_ascii() {
        // ASCII lowercases to one byte and has none of the wide-only
        // characters above, so the Unicode path is pure overhead here.
        let mut out = String::with_capacity(cell.len());
        for &byte in cell.as_bytes() {
            if matches!(byte, b'_' | b'-' | b' ') {
                continue;
            }
            out.push(byte.to_ascii_lowercase() as char);
        }
        return out;
    }
    cell.chars()
        .filter(|ch| !matches!(ch, '_' | '-' | ' '))
        .filter(|&ch| !wide || !matches!(ch, '\u{a0}' | '\u{202f}' | '\u{300}'..='\u{36f}'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// A header cell that names a secret column (closed list); a wide list adds
/// the French names and the compound English ones, the
/// export list a bare `pass` and the password manager column names.
pub(super) fn secret_header(cell: &str, names: Names) -> bool {
    let wide = names.wide();
    let folded = folded(cell, wide);
    [
        "password",
        "passwd",
        "pwd",
        "apikey",
        "token",
        "secret",
        "privatekey",
        "passphrase",
        "pin",
    ]
    .contains(&folded.as_str())
        || wide
            && [
                "motdepasse",
                "mdp",
                "codesecret",
                "codepin",
                "cleprivee",
                "cléprivée",
                "passcode",
                "secretkey",
                "clientsecret",
                "apisecret",
                "accesstoken",
                "authtoken",
                "apitoken",
            ]
            .contains(&folded.as_str())
        || names == Names::Export
            && ["pass", "loginpassword", "logintotp", "totp", "otpauth"].contains(&folded.as_str())
}

/// The cell ranges of `text[start..end]` split on `delim`, a `"…"` cell read as
/// one even when it holds the delimiter.
pub(super) fn cells(text: &str, start: usize, end: usize, delim: u8) -> Vec<(usize, usize)> {
    let (mut out, mut from, mut quoted) = (Vec::new(), start, false);
    for (at, &byte) in text.as_bytes()[start..end].iter().enumerate() {
        let at = start + at;
        match byte {
            b'"' => quoted = !quoted,
            byte if byte == delim && !quoted => {
                out.push((from, at));
                from = at + 1;
            }
            _ => {}
        }
    }
    out.push((from, end));
    out
}

/// An open table: its delimiter, cell count, secret columns and rows read.
pub(super) struct Table {
    pub(super) delim: u8,
    pub(super) count: usize,
    pub(super) secret: Vec<usize>,
    pub(super) rows: usize,
    /// The last row broke it: a header line next opens its own table.
    pub(super) broke: bool,
    /// A cookie leads its header: the residue view reads the header after
    /// the masked value, and each row from its first hidden cell on.
    pub(super) tail: bool,
    /// A blank line came after the last row (`wide` passes only).
    pub(super) gap: bool,
    /// The header line's range.
    pub(super) head: (usize, usize),
    /// The header ends with a blank cell (`id,password,city,`).
    pub(super) loose: bool,
    /// Secret columns only the export list names, sorted.
    pub(super) extra: Vec<usize>,
    /// Secret columns named a bare `pass`, sorted: a verdict there is no value.
    pub(super) verdict: Vec<usize>,
}

/// The table a header line opens, if a cell of it names a secret column.
pub(super) fn header(text: &str, start: usize, end: usize, names: Names) -> Option<Table> {
    DELIMS.iter().find_map(|&delim| {
        let row = cells(text, start, end, delim);
        header_of(text, (start, end), names, delim, &row)
    })
}

/// The cell delimiters a table may use, in the order a header line tries them.
pub(super) const DELIMS: [u8; 4] = *b",\t;|";

/// The table a header line opens under `names` when split on `delim` as `row`.
pub(super) fn header_of(
    text: &str,
    (start, end): (usize, usize),
    names: Names,
    delim: u8,
    row: &[(usize, usize)],
) -> Option<Table> {
    if row.len() < 2 || row.iter().any(|&(s, e)| e - s > 64) {
        return None;
    }
    let cell = |column: usize| &text[row[column].0..row[column].1];
    let led = |column: usize| {
        let (pair, name) = cell(column).trim().rsplit_once(' ').unwrap_or_default();
        pair.contains('=') && secret_header(name, names)
    };
    let secret: Vec<usize> = (0..row.len())
        .filter(|&column| secret_header(cell(column), names) || led(column))
        .collect();
    let tail = secret
        .iter()
        .any(|&column| !secret_header(cell(column), names));
    let extra: Vec<usize> = secret
        .iter()
        .copied()
        .filter(|&column| {
            names == Names::Export && !secret_header(cell(column), Names::Wide) && !led(column)
        })
        .collect();
    let verdict = extra
        .iter()
        .copied()
        .filter(|&column| folded(cell(column), true) == "pass")
        .collect();
    (!secret.is_empty()).then_some(Table {
        delim,
        count: row.len(),
        secret,
        rows: 0,
        broke: false,
        tail,
        gap: false,
        head: (start, end),
        loose: row
            .last()
            .is_some_and(|&(s, e)| text[s..e].trim().is_empty()),
        extra,
        verdict,
    })
}
