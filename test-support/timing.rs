// A stopwatch shared by the linear-time tests. Included as a private module by
// the unit tests (`mod timing { include!(...) }`) and by the integration tests
// (`tests/common/mod.rs`), so it is never part of the public API.

use std::time::{Duration, Instant};

/// One warm-up run, then the fastest of nine timed runs of `run`.
///
/// A shared CI runner or a busy Mac can stall one run for hundreds of
/// milliseconds. The fastest run measures the work, not the scheduler; callers
/// keep their ratio bounds and floors unchanged.
#[allow(dead_code)] // not every includer measures a single run
pub fn fastest(mut run: impl FnMut()) -> Duration {
    run();
    (0..9)
        .map(|_| {
            let started = Instant::now();
            run();
            started.elapsed()
        })
        .min()
        .expect("nine runs")
}

/// The two sides of a linearity bound, each the fastest of nine windows of
/// about the same length.
///
/// A linearity bound compares two sizes, so it is only as steady as the pair
/// it comes from. The long side takes ten times as long as the short one, so
/// a machine that stalls a run in proportion to its length treats the two
/// sides differently: the ratio then reads 21.5x against a 20x bound even
/// though the scan is linear. A shared macOS runner read exactly that on
/// 2026-11-03, on the EU ID scan, and the same test fails here whenever the
/// machine is busy.
///
/// Each side is therefore timed over windows of about the same length: the
/// long side runs once per window and the short side runs as many times as it
/// takes to fill a window of that length. The machine then slows both sides
/// down alike, and the fastest of the nine windows of each side is the work,
/// not the scheduler. The sizes and the bound do not change.
#[allow(dead_code)] // not every includer measures a pair of sizes
pub fn best_pair(
    mut short: impl FnMut() -> Duration,
    mut long: impl FnMut() -> Duration,
) -> (Duration, Duration) {
    // How many short runs fill the time of one long run.
    let long_once = long();
    let short_once = short();
    let batch = ((long_once.as_secs_f64() / short_once.as_secs_f64().max(1e-9)).round() as usize).max(1);
    let mut small = Duration::MAX;
    let mut big = Duration::MAX;
    for _ in 0..9 {
        let started = Instant::now();
        for _ in 0..batch {
            let _ = short();
        }
        small = small.min(started.elapsed());
        let started = Instant::now();
        let _ = long();
        big = big.min(started.elapsed());
    }
    (small / batch as u32, big)
}
