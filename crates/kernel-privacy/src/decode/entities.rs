//! The HTML5 named character references. Generated, do not edit.
//!
//! Source: Python's `html.entities.html5` (the WHATWG list, 2231 entries: 2125
//! names, 106 of them also legacy names that decode without `;`). Generator, run
//! with `python3 -I`: `ENTITIES` is every name sorted by bytes as
//! `(name, value, legacy)`; `FOLDED` maps each lowercase name to the entry whose
//! name is that lowercase, else to the first name that folds to it. Values are
//! written as `\u{..}` escapes except ASCII letters and digits.

mod folded_a_k;
mod folded_l_r;
mod folded_s_z;
mod names_lower_a_m;
mod names_lower_n_z;
mod names_upper;

/// One generated table entry: `(name without ";", value, decodes without ";")`.
type Entry = (&'static str, &'static str, bool);

// The generated tables are one list each. They are stored in lettered parts so
// every file stays under 30 KB; `entities` and `folded` copy the parts back into
// one array in the same order, and the lookup code in `decode.rs` is unchanged.
const ENTITIES_LEN: usize =
    names_upper::ENTRIES.len() + names_lower_a_m::ENTRIES.len() + names_lower_n_z::ENTRIES.len();
const FOLDED_LEN: usize =
    folded_a_k::ENTRIES.len() + folded_l_r::ENTRIES.len() + folded_s_z::ENTRIES.len();

/// Copies `part` into `out` at `at`, returning the next free index.
const fn append(out: &mut [Entry], at: usize, part: &[Entry]) -> usize {
    let mut i = 0;
    while i < part.len() {
        out[at + i] = part[i];
        i += 1;
    }
    at + i
}

/// Rebuilds `ENTITIES` from its lettered parts, in order.
const fn entities() -> [Entry; ENTITIES_LEN] {
    let mut out = [("", "", false); ENTITIES_LEN];
    let at = append(&mut out, 0, names_upper::ENTRIES);
    let at = append(&mut out, at, names_lower_a_m::ENTRIES);
    append(&mut out, at, names_lower_n_z::ENTRIES);
    out
}

/// Rebuilds `FOLDED` from its lettered parts, in order.
const fn folded() -> [Entry; FOLDED_LEN] {
    let mut out = [("", "", false); FOLDED_LEN];
    let at = append(&mut out, 0, folded_a_k::ENTRIES);
    let at = append(&mut out, at, folded_l_r::ENTRIES);
    append(&mut out, at, folded_s_z::ENTRIES);
    out
}

static ENTITIES_TABLE: [Entry; ENTITIES_LEN] = entities();
static FOLDED_TABLE: [Entry; FOLDED_LEN] = folded();

/// `(name without ";", value, decodes without ";")`, sorted by name bytes.
pub(super) static ENTITIES: &[(&str, &str, bool)] = &ENTITIES_TABLE;

/// `(lowercase name, value, decodes without ";")`, sorted by name bytes: the
/// case-folded lookup. A name that is its own lowercase wins (`ccaron` over
/// `Ccaron`).
pub(super) static FOLDED: &[(&str, &str, bool)] = &FOLDED_TABLE;
