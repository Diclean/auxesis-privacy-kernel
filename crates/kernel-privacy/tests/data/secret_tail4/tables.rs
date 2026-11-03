// P4: the random tables. Part of `secret_tail4_cases.rs`, the entry point
// every test includes.

/// P4: a random table (edge pipes per row, blank, padded and key header cells, ragged
/// rows, rows with no pipe, a valid or malformed delimiter, inside a fence or not).
/// Returns the text and the ranges that must be masked: each data cell of ≥ 4
/// non-whitespace chars under a key header of a valid table outside a fence.
fn tables() -> impl proptest::strategy::Strategy<Value = (String, Vec<std::ops::Range<usize>>)> {
    use proptest::prelude::*;
    const KEYS: &[&str] = &["password", "Secret", "PIN", "api_key", "mot de passe"];
    let head = prop::sample::select(&["password", "Secret", "PIN", "api_key", "mot de passe", "site", "user", "note", "", "   "][..]);
    let cell = prop_oneof![3 => "[a-z0-9]{1,8}( [a-z0-9]{1,8}){0,2}", 1 => Just(String::new()), 1 => Just("    ".to_owned())];
    let edges = (any::<bool>(), any::<bool>());
    let row = (prop::collection::vec(cell, 0..6), edges, 0..8usize);
    let delim = prop::sample::select(&["---", ":--", "--:", ":-:", " - "][..]);
    (prop::collection::vec(head, 1..5), edges, prop::collection::vec(delim, 1..5), 0..4usize, prop::collection::vec(row, 0..6), any::<bool>()).prop_map(
        |(heads, edges, delims, malformed, rows, fenced)| {
            // A leading pipe when asked, or when the first cell would read as an indent; a
            // final one when asked, or when the last cell is blank (else it is dropped).
            let lead = |cells: &[&str], lead: bool| lead || cells.len() < 2 || cells[0].trim().is_empty();
            let line = |cells: &[&str], (first, trail): (bool, bool)| {
                let trail = trail || cells.last().is_some_and(|cell| cell.trim().is_empty());
                format!("{}{}{}", if lead(cells, first) { "| " } else { "" }, cells.join(" | "), if trail { " |" } else { "" })
            };
            // 0: valid; 1: one cell short or long; 2: a bad cell; 3: no pipe at all.
            let mut cells: Vec<&str> = (0..heads.len()).map(|n| delims[n % delims.len()]).collect();
            match malformed {
                1 if cells.len() > 1 => _ = cells.pop(),
                1 => cells.push("---"),
                2 => cells[0] = "-x-",
                _ => {}
            }
            // A pipe-free delimiter is valid under a one-cell header (it has a pipe).
            let delimiter = if malformed == 3 { delims[0].to_owned() } else { line(&cells, (true, true)) };
            let valid = (malformed == 0 || malformed == 3 && heads.len() == 1) && !fenced;
            let mut text = String::from(if fenced { "```\n" } else { "" });
            text += &line(&heads, edges);
            text += "\n";
            text += &delimiter;
            let mut hide = Vec::new();
            for (cells, edges, plain) in rows {
                text += "\n";
                if plain == 0 || cells.is_empty() {
                    // A row with no pipe: one cell, the whole line.
                    text += "plain row";
                    if valid && KEYS.contains(&heads[0]) {
                        hide.push(text.len() - 9..text.len());
                    }
                    continue;
                }
                let cells: Vec<&str> = cells.iter().map(String::as_str).collect();
                text += if lead(&cells, edges.0) { "| " } else { "" };
                for (n, cell) in cells.iter().enumerate() {
                    if n > 0 {
                        text += " | ";
                    }
                    let key = heads.get(n).is_some_and(|head| KEYS.contains(head));
                    if valid && key && cell.chars().filter(|ch| !ch.is_whitespace()).count() >= 4 {
                        hide.push(text.len()..text.len() + cell.len());
                    }
                    text += cell;
                }
                text += if edges.1 { " |" } else { "" };
            }
            text += if fenced { "\n```\n\nBye" } else { "\n\nBye" };
            (text, hide)
        },
    )
}
