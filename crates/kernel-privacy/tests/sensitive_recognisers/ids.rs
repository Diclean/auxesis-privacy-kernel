//! Chinese resident identity numbers and the cues that name them.

use super::helpers::masked;

#[test]
fn cn_resident_id_is_masked_as_national_id() {
    let id = "11010519491231002X";
    let fullwidth = "１１０１０５１９４９１２３１００２Ｘ";
    let grouped_six_eight_four = "110105 19491231 002X";
    let grouped_dashes = "110105-19491231-002X";
    let grouped_six_four_four_four = "110105 1949 1231 002X";
    let legacy = "110105491231002";
    for (text, value) in [
        (id.to_string(), id),
        (format!("身份证号：{id}"), id),
        (format!("身份证号：{fullwidth}"), fullwidth),
        (
            format!("身份证号：{grouped_six_eight_four}"),
            grouped_six_eight_four,
        ),
        (format!("身份证号：{grouped_dashes}"), grouped_dashes),
        (
            format!("身份证号：{grouped_six_four_four_four}"),
            grouped_six_four_four_four,
        ),
        (format!("我的身份证{id}号"), id),
        (format!("身份证号：{legacy}"), legacy),
        // A bad check character is still an ID when a cue sits next to it.
        (
            "身份证号：110105194912310021".to_string(),
            "110105194912310021",
        ),
    ] {
        let out = masked(&text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(
            out.contains("NATIONAL_ID_"),
            "no NATIONAL_ID token for {value}: {out}"
        );
    }
}

#[test]
fn cn_resident_id_cues_include_the_formal_and_short_names() {
    // A bad check character needs a cue: 公民身份号码 (citizen identity number)
    // and 身份号码 (identity number) name the card as 身份证 does.
    for text in [
        "公民身份号码：110105194912310021",
        "身份号码：110105194912310021",
    ] {
        let out = masked(text);
        assert!(
            !out.contains("110105194912310021"),
            "the CN ID left in clear: {text} -> {out}"
        );
        assert!(
            out.contains("NATIONAL_ID_"),
            "no NATIONAL_ID token: {text} -> {out}"
        );
    }
}
