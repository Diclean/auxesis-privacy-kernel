//! Release timing: dense NI chains through both gates.

use super::helpers::{masked, number, tails, BREAKS, HEAD_PREFIXES, KINDS, LETTERS, MODES};

/// Release only: dense NI chains through both gates, best of three.
#[test]
#[ignore = "release timing: cargo test --release --test nino_chain -- --ignored scales"]
fn chain_dense_text_scales_linearly() {
    // Every shape and break in turn; a compact chain glued end to end, where
    // each number reopens one letter on; a one-line chain of bare heads, where
    // each scan steps back onto the shared letter.
    let mixed: String = (0..KINDS * 4)
        .map(|at| {
            let prefix = HEAD_PREFIXES[at % HEAD_PREFIXES.len()];
            let suffix = (!at.is_multiple_of(3)).then_some(LETTERS[at % 4]);
            number(at % KINDS, prefix, at, suffix) + BREAKS[at % BREAKS.len()]
        })
        .collect();
    let glued: String = (0..8).map(|at| number(1, "CB", at, Some('C'))).collect();
    let heads: String = (0..8).map(|at| number(0, "AB", at, None) + " ").collect();
    // A shared-letter chain whose last number is glued to a key, so every
    // number asks the read table about the next one (NINO-CHAIN r1).
    let shared: String = (0..8).map(|at| number(1, "CB", at, None)).collect();
    let [_, _, key, _, _] = tails();
    for unit in [
        mixed,
        glued + "\n",
        heads + "C\n",
        format!("{shared}D{key}\n"),
    ] {
        scales(&unit);
    }
}

fn scales(unit: &str) {
    let mut last = 0.0;
    for size in [16_384usize, 65_536, 262_144, 1_048_576] {
        let unit = unit.repeat(size / unit.len());
        let mut best = f64::MAX;
        for _ in 0..3.min(1 + (262_144 / size)) {
            let start = std::time::Instant::now();
            for mode in MODES {
                let _ = masked(mode, &unit);
            }
            best = best.min(start.elapsed().as_secs_f64());
        }
        let ratio = if last == 0.0 { 0.0 } else { best / last };
        eprintln!("{size} bytes: {best:.3}s ratio {ratio:.2}");
        assert!(ratio < 6.0, "{size} bytes scales {ratio:.2}");
        last = best;
    }
}
