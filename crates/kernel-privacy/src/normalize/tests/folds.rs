//! Folded views: look-alikes, full-width characters and escape prefixes.

use super::super::NormalizedText;

fn folded(text: &str) -> Vec<String> {
    let views = NormalizedText::folded_views(text);
    views.iter().map(|view| view.text().to_string()).collect()
}

/// NORM-1: what the folded views read, and what they leave alone.
#[test]
fn folded_views_read_look_alikes_and_leave_prose_alone() {
    assert!(folded("plain ASCII: a@b.c 4111 1111").is_empty());
    assert!(folded("Привет, как дела? 今天，好！ Ελλάδα").is_empty());
    assert_eq!(folded("ali\u{200B}ce@gmail.c\u{43E}m"), ["alice@gmail.com"]);
    assert_eq!(folded("𝐀𝐊𝐈𝐀 𝟒𝟐 ℎ ＭＲＮ："), ["AKIA 42 h MRN:"]);
    assert_eq!(folded("\u{455}k-pr\u{43E}j AKI\u{410}"), ["sk-proj AKIA"]);
    // Punctuation folds beside ASCII only; a Cyrillic word keeps its letters.
    assert_eq!(folded("注意：１２ 你好：好"), ["注意:12 你好：好"]);
    assert_eq!(folded("сом com\u{3000}"), ["сом com "]);
    // A space inside an ASCII word: a spaced view, then a joined one.
    assert_eq!(
        folded("dia\u{A0}betes 06\u{202F}12"),
        ["dia betes 06 12", "diabetes 0612"]
    );
}

/// NORM-2 r1: a full-width `＆` or `％` folds wherever it sits when it
/// opens an escape, and stays ordinary punctuation when it does not.
#[test]
fn a_full_width_escape_character_folds_wherever_it_sits() {
    // At the start of a token, beside a blank and a `#`.
    assert_eq!(
        folded("I have \u{ff06}#100;iabetes"),
        ["I have &#100;iabetes"]
    );
    assert_eq!(folded("x\u{ff06}#x41;"), ["x&#x41;"]);
    // A named escape and a percent escape fold the same way.
    assert_eq!(folded("mail \u{ff06}nbsp;x"), ["mail &nbsp;x"]);
    assert_eq!(folded("x.invalid/\u{ff05}41x"), ["x.invalid/%41x"]);
    // An invisible character between the `＆` and its body drops out of the
    // view, so it does not stand in the way of the escape.
    assert_eq!(folded("x\u{ff06}\u{200B}#41;y"), ["x&#41;y"]);
    // Ordinary punctuation: nothing to fold, so no view at all.
    assert!(folded("\u{ff06}\u{ff05}\u{ff06}\u{ff05}").is_empty());
    assert!(folded("\u{ff06} note \u{ff05} of it").is_empty());
    assert!(folded("价％和＆人").is_empty());
    // Chinese prose keeps both, whatever stands beside them.
    for text in [
        "预算增加１５％，库存＆物流都正常。",
        "他说：“明天见！”然后就走了，＆其它人无关。",
    ] {
        let views = folded(text);
        assert!(
            views.iter().all(|view| view.contains('＆')),
            "{text:?} -> {views:?}"
        );
    }
    // Beside no ASCII letter or digit and opening no escape, a `％` stays
    // too: the neighbour rule alone would not have touched it either.
    assert!(folded("预算增加％，库存正常。").is_empty());
}

#[test]
fn a_folded_span_maps_back_to_every_original_byte() {
    let text = "x \u{415}S91\u{200B}2100\u{AD}\u{A0}0418 y";
    for view in NormalizedText::folded_views(text) {
        let start = view.text().find("ES91").expect("folded value");
        let end = view.text().find(" y").expect("end");
        let (from, to) = view.to_original(start, end).expect("maps back");
        assert_eq!(&text[from..to], "\u{415}S91\u{200B}2100\u{AD}\u{A0}0418");
    }
}

#[test]
fn an_invisible_run_over_the_cap_is_a_boundary_in_the_folded_view() {
    let within = format!("FR76{}3000\u{43E}", "\u{200B}".repeat(8));
    assert_eq!(folded(&within), ["FR763000o"]);
    let over = format!("FR76{}3000", "\u{200B}".repeat(30));
    let views = NormalizedText::folded_views(&over);
    assert_eq!(views[0].text(), "FR76\u{0}3000");
    assert_eq!(views[0].to_original(4, 5), Some((4, over.len() - 4)));
}
