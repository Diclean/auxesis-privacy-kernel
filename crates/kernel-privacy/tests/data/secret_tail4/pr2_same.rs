// The texts no table rule applies to (P2-1). Part of
// `secret_tail4_cases.rs`, the entry point every test includes.

/// No table rule applies (P2-1): a pipe-free delimiter under a plain line, YAML
/// markers, M18 and M19. `scan` gives the same spans with and without PR2.
const PR2_SAME: &[&str] = &[
    "Password reset\n---\nbattery staple",
    "password: red horse\n---\nuser: admin",
    "---\npassword: red horse\n---\nuser: admin\n",
    "| note |\n---\npassword staple",
    "~~~\npassword is red horse | x\n|---|---|\nbattery staple\n~~~",
    "password is red horse | x\n|---|\nbattery staple",
];
