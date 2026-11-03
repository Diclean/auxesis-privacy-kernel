//! The dense run: glued keys and near-misses through both gates.

use std::time::Instant;

use super::formats::format_positives;
use super::helpers::{alnum, issue, keys, MODES};

/// Release only: dense glued keys and near-misses through both gates at 16 KiB,
/// 64 KiB, 256 KiB and 1 MiB, best of three. Bar: each 4x step at most 6x.
#[test]
#[ignore = "release timing: cargo test --release --test prefix_key_glue -- --ignored dense --nocapture"]
fn dense_glued_keys_scale_linearly() {
    if cfg!(debug_assertions) {
        return;
    }
    let glued: String = keys(1)
        .iter()
        .map(|(_, key)| format!("note{key} "))
        .collect();
    let units = [
        glued,
        format!("x{} ", keys(2)[1].1),
        "task-desk-risk-ask-".to_string(),
        "asksk-sk-sk-".to_string(),
        format!("asksk-{}\n", alnum(3, 31)),
        "risk-free desk-top eyJustice Asia ".to_string(),
        format!("ask-{}\nk", "aB1".repeat(20)),
        format_positives(1, 7)
            .into_iter()
            .map(|(_, text, _, _)| text + " ")
            .collect(),
        format!("tasksk-{}-", "a1".repeat(16)),
        "asksl.u.sl.u.sk-or-v1-".to_string(),
        format!("notesk-{}-prod ", "0123456789abcdef".repeat(2)),
        format!("high-risk-\nnotesk-{}_ ", "fedcba9876543210".repeat(2)),
    ];
    for unit in units {
        let mut last = 0.0;
        for size in [16_384usize, 65_536, 262_144, 1_048_576] {
            let text = unit.repeat(size / unit.len() + 1);
            let mut best = f64::MAX;
            for _ in 0..3 {
                let start = Instant::now();
                for mode in MODES {
                    let _ = issue(mode, &text);
                }
                best = best.min(start.elapsed().as_secs_f64());
            }
            let ratio = if last == 0.0 { 0.0 } else { best / last };
            eprintln!("{size} bytes: {best:.3}s ratio {ratio:.2}");
            assert!(ratio <= 6.0, "{size} bytes scales {ratio:.2}");
            last = best;
        }
    }
}
