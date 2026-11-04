//! The rules scan in linear time: ten times the input costs ten times the
//! work.

use super::helpers::rules;

mod stopwatch {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/timing.rs"
    ));
}

/// The rules scan in linear time: ten times the input costs ten times the
/// work, not a hundred. The bound and the floor are the ones of the H14
/// test. The runs read 10 KB and 100 KB, so even the small one sits well
/// above timer noise on a shared runner. Both sides are timed over windows
/// of the same length, so a machine that stalls a run in proportion to its
/// length slows both sides down alike: a shared macOS runner read 21.5x
/// against the 20x bound that way on 2026-11-03.
#[test]
fn the_rules_scan_in_linear_time() {
    for unit in [
        "26954371827 ",
        "12345678Z ",
        "X1234567L ",
        "ZMRPKC73R12H780Z ",
        "456789236 ",
        "91.07.22-406.21 ",
        "05.03.14-\n238.79 ",
        "26.954.\n371.827 ",
        "92071314764 ",
        "NIF 234567899 ",
        "1230 150885 ",
        "1234567TA ",
        "850709+3253 ",
        "1850709401231 ",
        "855709/1235 ",
        "AFM 123456783 ",
        "09078512341 ",
        "8507091237 ",
    ] {
        let flood = |size: usize| unit.repeat(size / unit.len());
        let (small_text, big_text) = (flood(10_000), flood(100_000));
        let rules = rules();
        let (small, big) =
            stopwatch::best_pair(|| time(&rules, &small_text), || time(&rules, &big_text));
        println!(
            "{unit:?}: {small:?} -> {big:?} ({:.1}x)",
            big.as_secs_f64() / small.as_secs_f64().max(1e-9)
        );
        assert!(
            big.as_secs_f64() <= 20.0 * small.as_secs_f64().max(1e-5),
            "{unit:?}: {small:?} -> {big:?}"
        );
    }
}

/// One run of every rule over `text`: the time of the work itself, without
/// the rules to build.
fn time(rules: &[Box<dyn kernel_privacy::Recognizer>], text: &str) -> std::time::Duration {
    let started = std::time::Instant::now();
    for rule in rules {
        let _ = rule.analyze(text);
    }
    started.elapsed()
}
