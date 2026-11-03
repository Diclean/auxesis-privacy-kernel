// P8: the owned passphrases. Part of `secret_tail4_cases.rs`, the entry
// point every test includes.

/// P8: a passphrase owned by a quote (every pair kind, nested 1–3 deep, with an escape
/// and an ambiguous quote inside; opened before or after the key; closed, unclosed or
/// mismatched), a fence, a block scalar, a key block (singular or plural key, empty or
/// inline value, children of any shape at deeper indents) or a flow value (nested 1–3,
/// fields at any indent, brackets in quotes, a comment), each across 0–3 blank lines.
/// Returns the text, the ranges that must be masked (the words, the openers before the
/// value when text follows, the tail when unclosed) and the words.
fn owned() -> impl proptest::strategy::Strategy<Value = (String, Vec<std::ops::Range<usize>>, Vec<String>)> {
    use proptest::prelude::*;
    const PAIRS: &[(&str, &str)] = &[("\"", "\""), ("'", "'"), ("“", "”"), ("„", "“"), ("‘", "’"), ("‚", "’"), ("«", "»"), ("»", "«"), ("‹", "›"), ("›", "‹"), ("”", "”"), ("’", "’"), ("「", "」"), ("『", "』")];
    let words = prop::collection::vec("[a-z][a-z0-9]{3,7}", 1..5);
    let gaps = prop::collection::vec(prop::sample::select(&[" ", "\n", "\n\n", "\n\n\n", "\n\n\n\n"][..]), 5);
    let quotes = prop::collection::vec(prop::sample::select(PAIRS), 1..4);
    let key = prop::sample::select(&["password", "passwords", "secret", "secrets", "DB_PASSWORD", "api_key", "tokens", "- password"][..]);
    let child = prop::collection::vec((prop::sample::select(&["  ", "    ", "  - ", "\t"][..]), 0..7usize), 5);
    (0..5usize, words, gaps, quotes, (0..3usize, any::<bool>(), any::<bool>()), (key, child)).prop_map(
        |(layout, words, gaps, quotes, (end, before, follows), (key, child))| {
            let (mut text, mut hide) = (String::new(), Vec::new());
            let put = |text: &mut String, hide: &mut Vec<std::ops::Range<usize>>, part: &str, masked: bool| {
                let at = text.len();
                text.push_str(part);
                if masked {
                    hide.push(at..text.len());
                }
            };
            let tail = if follows { " ok\n\nBye" } else { "" };
            match layout {
                0 => {
                    // `end`: 0 closed, 1 unclosed, 2 mismatched innermost closer.
                    if !before {
                        text.push_str("password is ");
                    }
                    for (open, _) in &quotes {
                        put(&mut text, &mut hide, open, before && follows && end == 0);
                        text.push_str("x ");
                    }
                    if before {
                        text.push_str("password is ");
                    }
                    for (n, word) in words.iter().enumerate() {
                        put(&mut text, &mut hide, word, true);
                        text.push_str(if n + 1 < words.len() { [gaps[n], " \\\" ", " \" "][n % 3] } else { "" });
                    }
                    for (n, (open, close)) in quotes.iter().enumerate().rev() {
                        let wrong = if *open == "「" { "»" } else { "」" };
                        text.push_str(match end { 0 => close, 1 => "", _ if n + 1 == quotes.len() => wrong, _ => close });
                        text.push_str(" x");
                    }
                    put(&mut text, &mut hide, tail, end != 0);
                }
                1 => {
                    let fence = if before { "~~~\npassword is " } else { "My password is\n```\n" };
                    put(&mut text, &mut hide, &fence[..3], before && follows);
                    text.push_str(&fence[3..]);
                    for (n, word) in words.iter().enumerate() {
                        put(&mut text, &mut hide, word, true);
                        text.push_str(gaps[n]);
                    }
                    text.push_str(if before { "\n~~~" } else { "\n```" });
                    text.push_str(if follows { "\n\nBye" } else { "" });
                }
                2 | 3 => {
                    let indent = if before { "  " } else { "" };
                    text.push_str(if before { "db:\n" } else { "user: admin\n" });
                    text.push_str(&format!("{indent}{key}:{}\n", [" |", "", " red"][if layout == 2 { 0 } else { end }]));
                    for (n, word) in words.iter().enumerate() {
                        let (lead, shape) = child[n];
                        let lead = if layout == 2 { "  " } else { lead };
                        let (head, after) = [("a: ", ""), ("- ", ""), ("# ", ""), ("[", "]"), ("", ""), ("x = ", ""), ("\"q\": \"", "\"")][if layout == 2 { 4 } else { shape }];
                        text.push_str(&format!("{indent}{lead}{head}"));
                        put(&mut text, &mut hide, word, true);
                        text.push_str(after);
                        text.push_str(&"\n".repeat(gaps[n].matches('\n').count().max(1)));
                    }
                    text.push_str(&format!("{indent}user: admin"));
                }
                _ => {
                    let opens: Vec<&str> = quotes.iter().map(|(open, _)| if open.len() % 2 == 0 { "{" } else { "[" }).collect();
                    text.push_str(&format!("{{\n\"{key}\": {}{}\n", opens.concat(), if before { " # }" } else { "" }));
                    for (n, word) in words.iter().enumerate() {
                        let (lead, shape) = child[n];
                        text.push_str(["", lead][usize::from(follows)]);
                        let (head, after) = [("\"f\": \"", "\","), ("\"a] { ", "\","), ("", ",")][shape % 3];
                        text.push_str(head);
                        put(&mut text, &mut hide, word, true);
                        text.push_str(after);
                        text.push_str(&"\n".repeat(gaps[n].matches('\n').count().max(1)));
                    }
                    let closes: String = opens.iter().rev().map(|open| if *open == "{" { "}" } else { "]" }).collect();
                    text.push_str(&format!("{closes},\n\"user\": \"admin\"\n}}"));
                }
            }
            (text, hide, words)
        },
    )
}
