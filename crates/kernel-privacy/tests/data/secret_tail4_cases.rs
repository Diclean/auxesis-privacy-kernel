// K-SECRET-TAIL-4 acceptance cases, shared by `tests/secret_tail4.rs` and the
// `secret_link` unit tests. (id, input, hide, clear): every non-whitespace byte of the
// last occurrence of each hide is masked; each clear stays in the gate output.
//
// The cases live in `secret_tail4/`, one file per group. This file is the entry
// point every test includes, and it chains the groups in the order the original
// file held them, so every test reads the same sequence of cases.

include!("secret_tail4/pr1a.rs");
include!("secret_tail4/pr1b.rs");
include!("secret_tail4/pr2.rs");
include!("secret_tail4/pr2_same.rs");
include!("secret_tail4/owned_cells.rs");
include!("secret_tail4/refusal_cases.rs");
include!("secret_tail4/built_cases.rs");
include!("secret_tail4/planted.rs");
include!("secret_tail4/owned.rs");
include!("secret_tail4/tables.rs");
