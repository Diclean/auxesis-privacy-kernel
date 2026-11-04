//! Linear-time and size tests for the secret-link scanner.

use super::*;

#[test]
fn s2_t4_and_h14_scan_in_under_a_second() {
    let n = 20_000;
    let t4 = "|".to_owned()
        + &"password|".repeat(n / 3)
        + "\n|"
        + &"---|".repeat(n / 3)
        + "\n"
        + &"x\n".repeat(n * 3);
    let s2 = " ".repeat(12_000) + &"password is \"x\" ".repeat(12_000);
    assert_eq!(link_scan(&s2), [(12_012, s2.len() - 1)]);
    for unit in ["*_*_password-_-", "mot de passe "] {
        let flood = |size: usize| unit.repeat(size / unit.len());
        let (small_text, big_text) = (flood(10_000), flood(100_000));
        // Both sides timed over windows of the same length, so a machine
        // that stalls a run in proportion to its length slows both sides
        // down alike.
        let (small, big) = timing::best_pair(|| time(&small_text), || time(&big_text));
        assert!(big < Duration::from_secs(1), "H14 {unit:?}: {big:?}");
        assert!(
            // 10x input: linear is ~10x, quadratic ~100x. The Mac CI runner
            // measures ~13x under load, so 20x keeps a margin and still fails
            // on any quadratic path.
            big.as_secs_f64() <= 20.0 * small.as_secs_f64().max(1e-5),
            "H14 {unit:?}: {small:?} -> {big:?}"
        );
    }
    for text in [t4, s2] {
        assert!(
            fastest(&text) < Duration::from_secs(1),
            "{:?}",
            fastest(&text)
        );
    }
}

/// N5: balanced nested openers, all flagged by one
/// value on their own line, scan in linear time up to 3.2 MB.
#[test]
fn n5_balanced_nesting_scans_in_linear_time() {
    let nested = |n: usize| "«“".repeat(n) + "password is red horse" + &"”»".repeat(n) + "\n\nBye";
    let (small, big) = (nested(40_000), nested(320_000));
    assert!(big.len() > 3_200_000);
    // The flagged-opener path: every opener masked, then the value.
    let value = small.find("red").unwrap_or_default();
    assert_eq!(
        link_scan(&small),
        [(0, value - "password is ".len()), (value, small.len() - 5)]
    );
    let (small, big) = timing::best_pair(|| time(&small), || time(&big));
    assert!(big < Duration::from_secs(3), "N5: {big:?}");
    assert!(
        big.as_secs_f64() <= 20.0 * small.as_secs_f64().max(1e-3),
        "N5: {small:?} -> {big:?}"
    );
}

/// PR2 bar: a 1 MB table (10,000 key columns, short rows) scans in linear time,
/// under a second in a debug `link_scan` (the release gate bar is in
/// `tests/secret_value_runs_to_paragraph_end.rs`). A loop over every header column for each row would walk
/// 10,000 × 75,000 cells.
#[test]
fn a_megabyte_of_wide_tables_scans_in_under_a_second() {
    let text = "|".to_owned()
        + &"password|".repeat(10_000)
        + "\n|"
        + &"---|".repeat(10_000)
        + "\n"
        + &"| hunter2 |\n".repeat(75_000);
    assert!(text.len() > 1_000_000);
    assert!(link_scan(&text).len() >= 75_000);
    let took = fastest(&text);
    assert!(took < Duration::from_secs(1), "{took:?}");
}

/// P5: every family scans in linear time, `t(2n) / t(n) ≤ 2.6` (fastest of
/// nine) from 100 KB to 200 KB (plus the deep mixed-kind flow).
#[test]
#[ignore = "release perf ratio: cargo test --release -- --ignored"]
fn p5_every_family_scans_in_linear_time() {
    let fill = |head: &str, unit: &str, tail: &str, size: usize| {
        head.to_owned() + &unit.repeat(size / unit.len()) + tail
    };
    let lines = |line: fn(usize) -> String, size: usize| {
        let mut text = String::new();
        for i in 0.. {
            if text.len() >= size {
                break;
            }
            text += &line(i);
        }
        text
    };
    type Family<'a> = Box<dyn Fn(usize) -> String + 'a>;
    let families: Vec<(&str, Family<'_>)> = vec![
        (
            "T4",
            Box::new(|size| {
                fill("|", "password|", "\n", size / 6)
                    + &fill("|", "---|", "\n", size / 6)
                    + &"x\n".repeat(size / 3)
            }),
        ),
        (
            "S2",
            Box::new(|size| fill(&" ".repeat(size / 17), "password is \"x\" ", "", size)),
        ),
        (
            "H14a",
            Box::new(|size| fill("", "*_*_password-_-", "", size)),
        ),
        ("H14b", Box::new(|size| fill("", "mot de passe ", "", size))),
        (
            "quote '",
            Box::new(|size| fill("", "password is '", "", size)),
        ),
        (
            "quote \"",
            Box::new(|size| fill("password is ", "\"", "", size)),
        ),
        (
            "quote “",
            Box::new(|size| fill("password is ", "“", "", size)),
        ),
        (
            "escape",
            Box::new(|size| fill("password is ", "\\\"", "", size)),
        ),
        ("pipe", Box::new(|size| fill("password is ", "|", "", size))),
        (
            "paragraphs",
            Box::new(|size| fill("", "password is a\n\n", "", size)),
        ),
        (
            "fences",
            Box::new(|size| fill("password is ", "```\n", "", size)),
        ),
        (
            "lists",
            Box::new(|size| fill("password is x\n", "a:\n  - b\n\n", "", size)),
        ),
        (
            "comments",
            Box::new(|size| fill("", "password: x\n# c\n", "", size)),
        ),
        (
            "unclosed",
            Box::new(|size| fill("'", "password is x\n\n", "", size)),
        ),
        (
            "indent keys",
            Box::new(|size| lines(|i| " ".repeat(i % 4096) + "password is \"x\"\n", size)),
        ),
        (
            "indent headers",
            Box::new(|size| {
                "password is x\n".to_owned() + &lines(|i| " ".repeat(i % 4096) + "a: |\n", size)
            }),
        ),
        (
            "key block",
            Box::new(|size| fill("password:\n", "  - a: b\n\n", "", size)),
        ),
        (
            "indent secrets",
            Box::new(|size| lines(|i| " ".repeat(i % 4096) + "password:\n", size)),
        ),
        (
            "mixed indents",
            Box::new(|size| fill("", "  password:\n\tx\n", "", size)),
        ),
        (
            "nested pairs",
            Box::new(|size| {
                fill("", "«“", "", size / 2) + "password is x" + &"”»".repeat(size / 8) + "\n\nBye"
            }),
        ),
        (
            "balanced nesting",
            Box::new(|size| {
                fill("", "«“", "password is red horse", size / 2)
                    + &"”»".repeat(size / 10)
                    + "\n\nBye"
            }),
        ),
        (
            "balanced cjk",
            Box::new(|size| {
                fill("", "「『", "密码是 red horse", size / 2)
                    + &"』」".repeat(size / 12)
                    + "\n\nBye"
            }),
        ),
        (
            "balanced lines",
            Box::new(|size| {
                fill("", "«“\n", "password is red horse", size / 2)
                    + &"”»\n".repeat(size / 12)
                    + "\nBye"
            }),
        ),
        (
            "deep flow",
            Box::new(|size| fill("password: ", "{[", "x", size / 2) + &"]}".repeat(size / 4)),
        ),
    ];
    let best = fastest;
    for (name, family) in &families {
        let (small, big) = (best(&family(100_000)), best(&family(200_000)));
        assert!(
            big.as_secs_f64() <= 2.6 * small.as_secs_f64().max(1e-3),
            "P5 {name}: {small:?} -> {big:?}"
        );
    }
}
