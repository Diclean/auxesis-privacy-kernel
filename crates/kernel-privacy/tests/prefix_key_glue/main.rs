//! K-SKPROJ-GLUE acceptance: a prefixed key glued after a letter, a digit or `_`
//! (`notesk-proj-…`, `2024ghp_…`, `my_AKIA…`) is hidden whole in both modes, at
//! line start, mid-line and after a break, for every prefix of the family:
//! `sk-`, `sk-proj-`, `sk-ant-`, `ghp_`, `gho_`, `ghs_`, `github_pat_`, `xoxb-`,
//! `xoxp-`, `AKIA`, `ASIA`, `AIza`, `GOCSPX-`, `ya29.`, `sk_live_`, `rk_live_`,
//! `glpat-`, `npm_`, `sl.` and the JWT `eyJ`. Words that only hold a prefix
//! (`desk-top`, `risk-free`, `Asia`, `eyJustice`) gain no mask, and the head is a
//! strict byte superset of main on a seeded differential frozen from origin/main
//! in `data/prefix_key_glue_main.txt` (`-- --ignored freeze --nocapture`, on main
//! only). Every mask is read with the shared exact reader `data/exact_mask.rs`.
//! Round 1: each issuer format of the `sk-` / `sl.` family (OpenAI legacy 48,
//! DeepSeek 32 hex, OpenRouter `sk-or-v1-` 64 hex, `sk-proj-`, `sk-svcacct-`,
//! `sk-admin-`, `sk-ant-api03-`, `sk-ant-admin01-`, `sl.`, `sl.u.`) glued after
//! letters and digits has 0 misses in both modes, from a fixed seed (20,000 per
//! format in the ignored `glued_exact_formats_20k`). Round 2: the same keys
//! followed by `-`, `_`, `-prod` or `_old`, and on the line after a glued `sk-`
//! run (`high-risk-\n<key>`).
//! Every key is invented and built at runtime from parts.

mod corpus;
mod dense;
mod formats;
mod helpers;
mod prefixes;
mod shapes;
mod supersets;
