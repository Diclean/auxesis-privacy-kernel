// The PR2 cases: the `|` link and the column form. Part of
// `secret_tail4_cases.rs`, the entry point every test includes.

/// The PR2 cases: the `|` link and the column form.
const PR2_CASES: &[(&str, &str, &[&str], &[&str])] = &[
    ("H10", "| password | Tr0ub4dor horse |", &["Tr0ub4dor horse"], &["password"]),
    ("S1a", "| | password |\n|---|---|\n| bank | hunter2 horse |", &["hunter2 horse"], &["bank"]),
    ("S1b", "|   | password |\n|---|---|\n| bank |    |", &[], &["bank"]),
    ("S1c", "| password | | hunter2 horse |", &["hunter2 horse"], &[]),
    ("S4a", "| password | required horse battery staple |", &["required horse battery staple"], &[]),
    ("S4b", "| password | in horse battery staple |", &["in horse battery staple"], &[]),
    ("S4c", "| password | now horse battery staple |", &["now horse battery staple"], &[]),
    ("S4da", "| key | value |\n|---|---|\n| password | required horse battery staple |", &["required horse battery staple"], &["key", "value"]),
    ("S4db", "| key | value |\n|---|---|\n| password | in horse battery staple |", &["in horse battery staple"], &["key", "value"]),
    ("S4dc", "| key | value |\n|---|---|\n| password | now horse battery staple |", &["now horse battery staple"], &["key", "value"]),
    ("S6e", "| code d'accès | red horse battery staple |", &["red horse battery staple"], &[]),
    ("S6f", "| site | Secret |\n|---|---|\n| bank | red horse battery staple |", &["red horse battery staple"], &["bank"]),
    // Ragged rows, a row with no pipe, edge pipes off, CRLF, an escaped pipe.
    ("TB1", "site | PIN | note\n:--|:-:|--:\nbank | 4821 9937 | ok\nshop | 7700\nmail", &["4821 9937", "7700"], &["bank", "shop", "mail"]),
    // D-2 find: no table, but the rest of the header after `site` meets the 1-cell
    // delimiter in the residue view; `site` is masked to the line end.
    ("TB3", "| password | site | PIN |\n| --- |\n| bank |\nmore words", &["site | PIN"], &["bank", "more words"]),
    // D-2 stress finds (Private refused before the fix): the rest of a row after a masked
    // value reads from column 0; a short cell merges with the masked value after it; a
    // header inside a run reads as a table once the outer header is masked away.
    ("SR1", "| pw |\n| --- |\n| secrets | red horse |. Thanks", &["red horse", ". Thanks"], &[]),
    ("SR2", "| password |\n| --: |\n口令: |\n  red horse\n\nBye", &["red horse"], &["Bye"]),
    ("SR3", "| site | password | user |\n|---|---|---|\n| bank | hunter2 | admin |\n| pin |\n| - |\n| 4821 9937 |", &["hunter2", "4821 9937"], &["bank", "admin"]),
    ("TB2", "| user | password |\r\n|---|---|\r\n| admin | red \\| horse |\r\n| guest | battery staple |", &["red \\| horse", "battery staple"], &["admin", "guest"]),
    // A pipe-free delimiter (one cell) under a one-cell header with a pipe: a table.
    ("TP1", "| password |\n---\n| red horse |", &["red horse"], &[]),
    ("TP2", "| password |\n:---:\n| red horse |\n\nBye", &["red horse"], &["Bye"]),
    ("TP3", "| password |\r\n---\r\n| red horse |\r\n", &["red horse"], &[]),
    ("TP4", "| password |\n --- \n| red horse |\nbattery staple\n\nBye", &["red horse", "battery staple"], &["Bye"]),
    ("TP5", "password |\n-\nbattery staple", &["battery staple"], &[]),
    // No table: a heading rule under a plain line, a YAML document marker, a header of
    // two cells.
    ("TP6", "Password reset\n---\nbattery staple", &[], &["battery staple"]),
    ("TP7", "---\nuser: admin\n---\nbattery staple", &[], &["battery staple"]),
    ("TP8", "| password | site |\n---\n| bank | battery staple |", &[], &["battery staple"]),
];
