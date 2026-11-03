//! Decoding stays linear: the cost bounds, on debug and release budgets.

use std::time::{Duration, Instant};

use super::super::DecodedText;

/// The decode pass must stay linear: the range lookup is a cursor, not a
/// scan of every URL, and the entity scan is bounded before it looks for the
/// terminator.
///
/// Release on a Linux build server: 77 ms for the escape/URL case and 27 ms
/// for the bare `&` case. Debug is about 7x slower, so the debug bound is
/// 2 s.
fn decode_budget() -> Duration {
    if cfg!(debug_assertions) {
        Duration::from_secs(2)
    } else {
        Duration::from_millis(200)
    }
}

#[test]
fn many_escapes_and_urls_decode_within_the_budget() {
    // 10 000 URLs, five percent escapes each. The old range lookup tested
    // every one of the 50 000 escapes against every URL.
    let url = "https://h.invalid/p?x=%41%42%43%44%45 ";
    let mut text = String::with_capacity(1_100_000);
    for _ in 0..10_000 {
        text.push_str(url);
    }
    while text.len() < 1_000_000 {
        text.push_str("padding ");
    }
    assert_eq!(text.matches('%').count(), 50_000);
    assert_eq!(text.matches("://").count(), 10_000);
    let start = Instant::now();
    let decoded = DecodedText::new(&text);
    let elapsed = start.elapsed();
    eprintln!(
        "decode {} bytes / 50 000 escapes / 10 000 URLs: {elapsed:?}",
        text.len()
    );
    assert!(decoded.text().contains("ABCDE"));
    assert!(
        elapsed < decode_budget(),
        "decode of {} bytes with 50 000 escapes took {elapsed:?}",
        text.len()
    );
}

/// 1 MiB of adversarial entity soup: deep `&amp;` nesting, long digit runs,
/// markers and hidden characters. Every pass is linear and there are at
/// most [`MAX_PASSES`] of them, so the bound is the same as for one pass
/// times the cap: 10 s debug, 1 s release.
#[test]
fn adversarial_entity_soup_stays_linear() {
    let nested = "amp;".repeat(40);
    let piece =
        format!("&{nested}#45;&#000000000000000045&EACUTE⟦PERSON_ABC⟧⟦\u{200B}&shy;&#x27E6;&am");
    let text = piece.repeat((1 << 20) / piece.len() + 1);
    let start = Instant::now();
    let decoded = DecodedText::new(&text);
    let elapsed = start.elapsed();
    eprintln!("decode 1 MiB of entity soup: {elapsed:?}");
    assert!(!decoded.text().contains('⟦'));
    let bound = decode_budget() * 5;
    assert!(elapsed < bound, "1 MiB of entity soup took {elapsed:?}");
    // Openers with no `⟧` anywhere: each looks for its bracket once.
    let start = Instant::now();
    assert_eq!(
        DecodedText::new(&"⟦a".repeat(1 << 18)).text().len(),
        1 << 18
    );
    assert!(
        start.elapsed() < bound,
        "1 MiB of openers took {:?}",
        start.elapsed()
    );
}

#[test]
fn an_ampersand_with_no_semicolon_stays_bounded() {
    let text = "&".repeat(1_000_000);
    let start = Instant::now();
    let decoded = DecodedText::new(&text);
    let elapsed = start.elapsed();
    eprintln!("decode 1 MB of bare `&`: {elapsed:?}",);
    assert_eq!(decoded.text().len(), text.len());
    assert!(
        elapsed < decode_budget(),
        "decode of 1 MB of bare `&` took {elapsed:?}"
    );
}
