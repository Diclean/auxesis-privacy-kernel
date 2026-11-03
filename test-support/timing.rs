// A stopwatch shared by the linear-time tests. Included as a private module by
// the unit tests (`mod timing { include!(...) }`) and by the integration tests
// (`tests/common/mod.rs`), so it is never part of the public API.

use std::time::{Duration, Instant};

/// One warm-up run, then the fastest of nine timed runs of `run`.
///
/// A shared CI runner or a busy Mac can stall one run for hundreds of
/// milliseconds. The fastest run measures the work, not the scheduler; callers
/// keep their ratio bounds and floors unchanged.
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
