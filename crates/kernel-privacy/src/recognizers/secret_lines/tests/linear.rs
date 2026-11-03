use super::lines_scan;

mod timing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/timing.rs"
    ));
}

/// 10× the input costs at most 20× the time on every scan path (fastest of
/// nine after one warm-up): a cookie header, cookie pairs, label lines, a
/// same-line passphrase, CSV rows, open quotes in CSV rows and AWS ids.
#[test]
fn every_path_scales_linearly() {
    use std::time::Duration;
    let paths: [(&str, &str, &str); 7] = [
        ("cookie header", "", "Cookie: "),
        ("cookie pairs", "", "Cookie: sid=k2Lp9xQe7Rv3Wm8T;"),
        ("labels", "", "Password\n"),
        ("phrase", "", "Passphrase: "),
        ("csv", "id,password,note\n", "1,Cherry6!,ok\n"),
        ("csv quotes", "id,password,note\n", "1,pw,\"open\n"),
        ("aws", "", "akiabcdfghjklmnpqrst "),
    ];
    let tail = |bytes: usize| {
        let n = bytes / 16;
        format!(
            "id,{}note\n1,{}token",
            "password,".repeat(n),
            "secret,".repeat(n)
        )
    };
    let (s, l) = (tail(160_000), tail(1_600_000));
    let small = timing::fastest(|| {
        let _ = lines_scan(&s);
    });
    let large = timing::fastest(|| {
        let _ = lines_scan(&l);
    });
    assert!(
        large <= small * 20 + Duration::from_millis(50),
        "csv tail: 160 KB {small:?}, 1.6 MB {large:?}"
    );
    for (name, head, unit) in paths {
        let text = |bytes: usize| head.to_string() + &unit.repeat(bytes / unit.len());
        let best = |t: &str| {
            timing::fastest(|| {
                let _ = lines_scan(t);
            })
        };
        let (s, l) = (best(&text(160_000)), best(&text(1_600_000)));
        assert!(
            l <= s * 20 + Duration::from_millis(50),
            "{name}: 160 KB {s:?}, 1.6 MB {l:?}"
        );
    }
}
