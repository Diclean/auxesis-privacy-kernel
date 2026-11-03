//! Helpers shared by the K10 test modules.

use kernel_privacy::{Anonymizer, Registry};

/// The text as the anonymiser would send it to a provider.
pub(crate) fn masked(text: &str) -> String {
    let spans = Registry::new().analyze(text);
    Anonymizer::new([0x4B; 32]).anonymize(text, &spans).0
}

/// No nine-character window of `key` may survive in clear in `out`: a masked key
/// can still leak its tail through a neighbouring label.
pub(crate) fn assert_no_window_in_clear(out: &str, key: &str) {
    for start in 0..key.len() - 9 {
        let window = &key[start..start + 9];
        assert!(!out.contains(window), "{window} left in clear: {out}");
    }
}
