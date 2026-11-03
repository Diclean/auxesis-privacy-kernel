//! Tests for the external-text sanitisers, error details and previews.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_large_text_on_char_boundary() {
        let raw = "é".repeat(100); // 200 bytes
        let capped = sanitize_external_text(&raw, 101);
        assert!(capped.starts_with(&"é".repeat(30)));
        assert!(capped.contains("of 200 bytes"), "marker: {capped}");
        assert!(capped.chars().filter(|c| *c == 'é').count() >= 50);
    }

    #[test]
    fn truncation_keeps_the_tail_marker() {
        let raw = format!("{}{}", "x".repeat(5000), "STDERR-MARKER-END");
        let capped = sanitize_external_text(&raw, 256);
        assert!(capped.contains("STDERR-MARKER-END"), "tail lost");
        assert!(capped.contains("truncated"), "marker lost");
    }

    #[test]
    fn small_text_is_untouched() {
        assert_eq!(sanitize_external_text("hello", 1024), "hello");
    }

    #[test]
    fn error_detail_is_one_safe_capped_line() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = format!(
            "boom at {}/store.db\u{1b}[31m AUX_KEY_DEEPSEEK=sk-live-abcdef12345 \n\
             second\u{202e} line\n{}",
            home.display(),
            "x".repeat(10_000)
        );
        let clean = sanitize_error_detail(home, &raw, 512);
        assert!(!clean.contains("/Users/secret/.auxesis"), "{clean}");
        assert!(clean.contains("<home>/store.db"), "{clean}");
        assert!(!clean.contains("sk-live-abcdef12345"), "{clean}");
        assert!(clean.contains("AUX_KEY_DEEPSEEK=<redacted>"), "{clean}");
        assert!(
            !clean.contains('\n') && !clean.contains('\u{1b}') && !clean.contains('\u{202e}'),
            "details must be one control-free line: {clean:?}"
        );
        assert!(clean.chars().count() <= 512);
    }

    #[test]
    fn preview_keeps_lines_but_hides_paths_and_keys() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = format!(
            "line one\ncd {}/agents/main\nAUX_KEY_FAKE=sk-live-abcdef \nline four",
            home.display()
        );
        let clean = scrub_external_preview(home, &raw, 4096);
        assert!(clean.contains("line one\n"), "lines are preserved");
        assert!(!clean.contains("/Users/secret/.auxesis"), "{clean}");
        assert!(clean.contains("<home>/agents/main"), "{clean}");
        assert!(!clean.contains("sk-live-abcdef"), "{clean}");
        assert!(clean.contains("AUX_KEY_FAKE=<redacted>"), "{clean}");
    }

    #[test]
    fn redaction_is_shared_with_error_and_preview_scrubbers() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = format!(
            "at {}/store.db: ghp_0123456789abcdefghijklmnop and password=hunter2swordfish",
            home.display()
        );
        let detail = sanitize_error_detail(home, &raw, 512);
        assert!(
            !detail.contains("ghp_0123456789abcdefghijklmnop"),
            "{detail}"
        );
        assert!(!detail.contains("hunter2swordfish"), "{detail}");
        assert!(!detail.contains("/Users/secret/.auxesis"), "{detail}");

        let preview = scrub_external_preview(home, &raw, 4096);
        assert!(
            !preview.contains("ghp_0123456789abcdefghijklmnop"),
            "{preview}"
        );
        assert!(!preview.contains("hunter2swordfish"), "{preview}");
        assert!(preview.contains("<redacted>"), "{preview}");
    }
}
