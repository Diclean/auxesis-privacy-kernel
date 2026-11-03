//! Tests for the linear-time bar on adversarial encoded values.

use super::super::*;

use serde_json::json;

#[test]
fn adversarial_encoded_values_finish_within_the_bar() {
    // A 1 MB value, and one just under the text cap, both nested escapes.
    let bar = std::time::Duration::from_secs(10);
    for value in [
        "%25".repeat(350_000),
        "q7f3k9%25252540example.com ".repeat(9_000),
    ] {
        let started = std::time::Instant::now();
        assert!(identifier_in_arguments(&json!({ "memo": value })).is_some());
        let elapsed = started.elapsed();
        assert!(elapsed < bar, "{} bytes took {elapsed:?}", value.len());
    }
}
