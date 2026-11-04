//! Tests for the linear-time bar on adversarial encoded values.

use super::super::*;

use serde_json::json;

mod timing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/timing.rs"
    ));
}

#[test]
fn adversarial_encoded_values_finish_within_the_bar() {
    // A 1 MB value, and one just under the text cap, both nested escapes.
    let bar = std::time::Duration::from_secs(10);
    for value in [
        "%25".repeat(350_000),
        "q7f3k9%25252540example.com ".repeat(9_000),
    ] {
        // The fastest of nine runs, after one warm-up: the bar is on the
        // work, not on the scheduler. A shared runner read 12.9 s and
        // 16.9 s for the second value on 2026-11-01, against the 10 s bar.
        let elapsed = timing::fastest(|| {
            assert!(identifier_in_arguments(&json!({ "memo": value })).is_some());
        });
        assert!(elapsed < bar, "{} bytes took {elapsed:?}", value.len());
    }
}
