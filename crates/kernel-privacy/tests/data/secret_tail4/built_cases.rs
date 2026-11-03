// The PR1a cases built by code. Part of `secret_tail4_cases.rs`, the entry
// point every test includes.

/// The PR1a cases built by code: H11, H12, T3a, T3b, R2 and B1–B4 in their U+E000,
/// U+FFFD and `x` forms.
fn built_cases() -> Vec<(String, String, Vec<String>, Vec<String>)> {
    let s = |text: &str| text.to_owned();
    let long = "a".repeat(1025);
    let words = "word ".repeat(110);
    let mut cases = vec![
        (s("H11"), format!("Mon mdp est {long}"), vec![long.clone()], vec![s("Mon mdp est")]),
        (s("H12"), format!("Mon mot de passe est {long}"), vec![long.clone()], vec![]),
        (s("T3a"), format!("password is \"red. {}battery staple\"", "horse ".repeat(30)), vec![format!("\"red. {}battery staple\"", "horse ".repeat(30))], vec![]),
        (s("T3b"), format!("password is {}\"red. horse battery staple\"", "a ".repeat(45)), vec![format!("{}\"red. horse battery staple\"", "a ".repeat(45))], vec![]),
        (s("R2a"), format!("password is {words}. Next"), vec![format!("{words}. Next")], vec![]),
        (s("R2b"), format!("password is {words}\n\nNext"), vec![words.clone()], vec![s("Next")]),
        (s("R2c"), s("password is red horse\nbattery staple\nmore words"), vec![s("red horse"), s("battery staple"), s("more words")], vec![]),
    ];
    for form in ["\u{E000}", "\u{FFFD}", "x"] {
        for (id, n, quote, config) in [("B1", 64, "\"", true), ("B2", 65, "\"", false), ("B3", 64, "", true), ("B4", 65, "", false)] {
            let line = format!("{quote}{}{quote}: ok", form.repeat(n));
            let (hide, clear) = if config { (vec![s("red horse")], vec![line.clone()]) } else { (vec![s("red horse"), line.clone()], vec![]) };
            cases.push((format!("{id} {form:?}"), format!("password: red horse\n{line}"), hide, clear));
        }
    }
    cases
}
