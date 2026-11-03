//! Tests for title and display scrubbing.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// FAKE: values invented for the tests, never a real person's.
    const TITLE_VALUES: [(&str, &str); 2] = [
        ("lena.ortiz@example.org", "lena"),
        ("FR76 3000 6000 0112 3456 7890 189", "FR76"),
    ];

    #[test]
    fn title_detects_values_at_every_display_boundary() {
        for boundary in [47, 60, 186, 200, 400] {
            for (value, marker) in TITLE_VALUES {
                let text = format!("{} {value}", "x".repeat(boundary));
                let title = scrub_title(&text);
                assert!(
                    !title.contains(marker),
                    "boundary {boundary}: {title:?} leaked {marker}"
                );
                assert!(
                    title.chars().count() <= 200,
                    "boundary {boundary}: {} chars",
                    title.chars().count()
                );
            }
        }
    }

    #[test]
    fn title_scan_cap_drops_a_run_it_would_cut() {
        for (value, marker) in TITLE_VALUES {
            // No whitespace around the value: the 400-character scan would end
            // inside it, so the whole run must be dropped.
            let title = scrub_title(&format!("{}{value}", "x".repeat(395)));
            assert!(title.ends_with('…'), "{title:?}");
            assert!(!title.contains(marker), "{title:?} leaked {marker}");

            // A run that begins after the last space is dropped whole too.
            let title = scrub_title(&format!("{} {value}", "x".repeat(390)));
            assert!(title.ends_with('…'), "{title:?}");
            assert!(!title.contains(marker), "{title:?} leaked {marker}");
        }
    }

    #[test]
    fn display_scrub_detects_a_value_on_a_later_line() {
        assert_eq!(
            scrub_display_text("Hello\nlena.ortiz@example.org", 4096),
            "Hello\n[e-mail]"
        );
    }
}
