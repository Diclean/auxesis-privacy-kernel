// P2-2: the key cells that open an owned region. Part of
// `secret_tail4_cases.rs`, the entry point every test includes.

/// P2-2: a key cell that opens an owned region (each quote pair, closed and unclosed,
/// a key block, a flow, a block scalar), or a fence right under a row. Returns the
/// text and the parts that must be masked.
fn owned_cells() -> Vec<(String, Vec<&'static str>)> {
    const PAIRS: &[(&str, &str)] = &[
        ("\"", "\""), ("'", "'"), ("\u{201D}", "\u{201D}"), ("\u{2019}", "\u{2019}"),
        ("\u{201C}", "\u{201D}"), ("\u{201E}", "\u{201C}"), ("\u{2018}", "\u{2019}"),
        ("\u{201A}", "\u{2018}"), ("\u{AB}", "\u{BB}"), ("\u{BB}", "\u{AB}"),
        ("\u{2039}", "\u{203A}"), ("\u{203A}", "\u{2039}"), ("\u{300C}", "\u{300D}"),
        ("\u{300E}", "\u{300F}"),
    ];
    let head = "| password |\n|---|\n";
    let mut cases = Vec::new();
    for &(open, close) in PAIRS {
        cases.push((format!("{head}| {open}red |\nhorse{close}\n\nBye"), vec!["red", "horse"]));
        cases.push((format!("{head}| {open}red |\nhorse\n\nBye"), vec!["red", "horse"]));
        cases.push((format!("| pin |\n---\n{open}red |\nhorse{close}"), vec!["red", "horse"]));
    }
    for (text, hide) in [
        ("secret: red\n  horse staple", vec!["red", "horse staple"]),
        ("token: {\n  red horse\n}", vec!["red horse"]),
        ("note: |\n  red horse", vec!["red horse"]),
        ("| red horse |\n```\nbattery staple\n```", vec!["red horse"]),
    ] {
        cases.push((format!("{head}{text}"), hide));
    }
    cases
}
