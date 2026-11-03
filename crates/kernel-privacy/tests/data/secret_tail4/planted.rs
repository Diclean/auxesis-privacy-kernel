// P2: the planted passphrases. Part of `secret_tail4_cases.rs`, the entry
// point every test includes.

/// P2: a passphrase planted after a key, a mark and a link, in prose (one line or
/// wrapped over lines, a zero-width-only or NBSP-only line), a config entry (one
/// separator, with Structure lines and Block children around it, or continued on a
/// Structure line) or a quoted form. Never K4. Returns the text, the passphrase's
/// byte range and its words.
fn planted() -> impl proptest::strategy::Strategy<Value = (String, std::ops::Range<usize>, Vec<String>)> {
    use proptest::prelude::*;
    let word = prop_oneof![
        4 => "[A-Za-z0-9]{1,8}",
        2 => "[A-Za-z0-9.!?:,=;'\"é😀אב密\u{200B}]{1,6}",
        1 => Just("\\\"".to_owned()),
    ];
    let prose_key = prop::sample::select(&["password", "Password", "PASSWORD", "mot de passe", "mdp", "passphrase", "api key", "pwd", "passcode", "jelszó", "wagwoord", "secret key"][..]);
    let entry_key = prop::sample::select(&["password", "DB_PASSWORD", "api_key", "passphrase", "PIN", "\"password\"", "token"][..]);
    let mark = prop::sample::select(&["", "**", "__", "`", "~~"][..]);
    let link = prop::sample::select(&[" is", " was", " est", " are", ":", " :", " =", " for the portal is", " de la banque est"][..]);
    let sep = prop::sample::select(&[": ", "=", " = ", " := "][..]);
    let lead = prop::sample::select(&["", "Ref: ", "Hi,\nmy "][..]);
    let trail = prop::sample::select(&["", ". Thanks", "\n\nBye", "\nsee you"][..]);
    let gap = prop::sample::select(&["\n", "\n\u{200B}\n", "\n\u{A0}\n", " "][..]);
    let quote = prop::sample::select(&[("\"", "\""), ("'", "'"), ("“", "”"), ("«", "»"), ("「", "」")][..]);
    (("[A-Za-z0-9]{4,8}", prop::collection::vec(word, 0..6)), 0..5usize, (prose_key, entry_key, mark, link), (sep, lead, trail, gap), (quote, 1..6usize)).prop_map(
        |((first, mut words), layout, (key, entry_key, mark, link), (sep, lead, trail, gap), (quote, cut))| {
            words.insert(0, first);
            let cut = cut.min(words.len());
            let (head, tail) = (words[..cut].join(" "), words[cut..].join(" "));
            let wrap = if link.contains(['=', ':']) { " is" } else { link };
            let (before, value, after) = match layout {
                0 => (format!("{lead}{mark}{key}{mark}{link} "), format!("{head} {tail}"), trail.to_owned()),
                1 => (format!("{lead}{mark}{key}{mark}{wrap} "), format!("{head}{gap}{tail}"), trail.to_owned()),
                2 => (format!("# app\nhosts{sep}\n  - a.example\nuser{sep}admin\n{entry_key}{sep}"), format!("{head} {tail}"), format!("\n[next]\nport{sep}5432")),
                3 => (format!("user{sep}admin\n{entry_key}{sep}"), format!("{head}\n# {tail}"), format!("\nport{sep}5432")),
                _ => (format!("{lead}{key}{link} {}", quote.0), format!("{head} {tail}"), format!("{} ok{trail}", quote.1)),
            };
            (format!("{before}{value}{after}"), before.len()..before.len() + value.len(), words)
        },
    )
}
