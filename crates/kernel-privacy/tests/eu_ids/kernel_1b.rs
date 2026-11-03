//! EU-KERNEL-1b: Poland, Portugal, Austria, Ireland and Sweden, and the
//! look-alikes they leave in clear.

use super::helpers::rules;

/// EU-KERNEL-1b: look-alikes in prose stay in clear: a telephone number, a
/// word after the digits, a letter that fails the check, a machine line.
#[test]
fn the_1b_rules_leave_look_alikes_alone() {
    for text in [
        "call 070-123 45 67 or 0701 234 567",
        "invoice 1234567 Tuesday",
        "1234567BAX was filed",
        "ref1234567Atail",
        "0953692M4359008FXT<K1",
        "ref7654321PAtail",
        "PPS number ref7654321PBtail",
        "1234567/Tuesday",
        "ticket 1234567 - Tuesday",
        "1234567   /   T",
        "Order 92071314765 shipped.",
    ] {
        let spans: Vec<_> = rules().iter().flat_map(|rule| rule.analyze(text)).collect();
        assert!(spans.is_empty(), "{text:?} -> {spans:?}");
    }
}
