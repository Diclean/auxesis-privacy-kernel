//! Tests for corpus loading.

use crate::cases::Case;

#[test]
fn external_fixture_parses() {
    let text = include_str!("../../scripts/fixtures/sample-cases.jsonl");
    let mut count = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let _: Case = serde_json::from_str(line).expect("fixture case parses");
        count += 1;
    }
    assert_eq!(count, 3);
}
