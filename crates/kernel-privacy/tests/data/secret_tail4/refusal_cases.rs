// K-REFUSALS: the cases Private refused and never leaked. Part of
// `secret_tail4_cases.rs`, the entry point every test includes.

/// K-REFUSALS: Private refused these (main 62c75fd0), never a leak. Masking turns a
/// neighbour of a clear quote into a stand-in and a line break, so in the residue view
/// that quote pairs differently and owns the rest. Every quote pair nested in another
/// before a key, between clear `''`; a quote opener in a non-key cell of a table row
/// (with and without the edge pipe, before another column); main's closing-line mask.
fn refusal_cases() -> Vec<(String, String, Vec<&'static str>, Vec<&'static str>)> {
    const PAIRS: &[(&str, &str)] = &[("\"", "\""), ("'", "'"), ("“", "”"), ("„", "“"), ("‘", "’"), ("‚", "’"), ("«", "»"), ("»", "«"), ("‹", "›"), ("›", "‹"), ("”", "”"), ("’", "’"), ("「", "」"), ("『", "』")];
    let mut cases = Vec::new();
    for &(outer, outer_close) in PAIRS {
        for &(inner, inner_close) in PAIRS {
            let text = format!("''{outer}{outer}{inner}passwd is red horse{inner_close}{outer_close}{outer_close}''\n\nBye");
            cases.push((format!("KR1 {outer}{inner}"), text, vec!["red horse"], vec!["passwd is"]));
        }
        for row in [
            "| site | password |\n|---|---|\n| {q}foo | red horse |",
            "| site | password |\n|---|---|\n| {q}foo | red horse",
            "| site | password | note |\n|---|---|---|\n| {q}foo | red horse | ok |",
            "site | password\n---|---\n{q}foo | red horse |\n\nBye",
        ] {
            let text = row.replace("{q}", outer);
            cases.push((format!("KR2 {text:?}"), text, vec!["red horse"], vec!["site"]));
        }
    }
    // Main masks `AFTER` past the quote end (the closing line, whole): kept, never narrowed.
    let after = "| password |\n|---|\n| \"red |\nhorse\" AFTER\n\nBYE";
    cases.push(("KR3".to_owned(), after.to_owned(), vec!["\"red", "horse\" AFTER"], vec!["BYE"]));
    cases
}
