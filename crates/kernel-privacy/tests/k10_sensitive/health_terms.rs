//! Health and Art. 9 terms: the words themselves, in every language
//! the lexicon covers.

use super::helpers::masked;
use kernel_privacy::{Anonymizer, EntityKind, Registry};

#[test]
fn health_terms_are_masked_in_every_language() {
    let cases = [
        ("She has cancer and starts chemotherapy.", "cancer"),
        ("Type 2 diabetes was found at the checkup.", "diabetes"),
        ("He tested HIV positive in 2019.", "HIV"),
        (
            "Elle suit une chimiothérapie depuis mars.",
            "chimiothérapie",
        ),
        ("Il vit avec le VIH depuis 2015.", "VIH"),
        ("Hy is al drie jaar met kanker besig.", "kanker"),
        ("Anyám cukorbetegségben szenved.", "cukorbetegségben"),
        ("Oče ima sladkorno bolezen že dvajset let.", "sladkorno"),
        ("Mama je prejela diagnozo raka.", "raka"),
        ("他两年前被确诊为糖尿病。", "糖尿病"),
    ];
    for (text, term) in cases {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn health_terms_match_case_plural_and_accents() {
    for term in [
        "CANCER",
        "Cancers",
        "chimiotherapie",
        "Diabètes",
        "SÉROPOSITIF",
        "KANKERS",
    ] {
        let out = masked(&format!("Dossier : {term} ."));
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn health_terms_must_be_whole_words() {
    for text in [
        "The cancelled flight left at noon.",
        "Rakete za Bohinj.",
        "Rákóczi úti lakás.",
        "Le goût du café est riche.",
    ] {
        assert!(!masked(text).contains("HEALTH_"), "over-masked: {text}");
    }
}

#[test]
fn health_kind_is_the_existing_health_label() {
    let spans = Registry::new().analyze("She has cancer.");
    assert!(
        spans.iter().any(|span| span.kind == EntityKind::Health),
        "no Health span: {spans:?}"
    );
}

#[test]
fn art9_terms_are_masked_under_their_own_label() {
    let cases = [
        ("Il est musulman depuis l'enfance.", "musulman", "RELIGION_"),
        ("She is Jewish and works in finance.", "Jewish", "RELIGION_"),
        (
            "Elle est homosexuelle et vit à Lyon.",
            "homosexuelle",
            "SEXUAL_ORIENTATION_",
        ),
        (
            "He came out as gay at the conference.",
            "gay",
            "SEXUAL_ORIENTATION_",
        ),
        ("Il est syndiqué à la CGT.", "syndiqué", "TRADE_UNION_"),
        (
            "She is a union member at the plant.",
            "union member",
            "TRADE_UNION_",
        ),
        (
            "Données sur l'origine ethnique des salariés.",
            "origine ethnique",
            "ETHNIC_ORIGIN_",
        ),
    ];
    for (text, term, label) in cases {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {term}: {out}");
    }
}

#[test]
fn art9_terms_must_not_mask_a_given_name() {
    let out = masked("Christian Dior opened a store.");
    assert!(!out.contains("RELIGION_"), "over-masked: {out}");
    assert!(!out.contains("SEXUAL_ORIENTATION_"), "over-masked: {out}");
}

#[test]
fn traditional_chinese_health_terms_are_masked() {
    for term in ["憂鬱症", "愛滋病", "腫瘤", "懷孕", "高血壓", "化療", "癲癇"] {
        let out = masked(&format!("他有{term}。"));
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn han_terms_match_across_zero_width_characters_and_spaces() {
    for text in ["他有糖\u{200B}尿病。", "他有糖 尿 病。"] {
        let out = masked(text);
        assert!(
            !out.contains('糖') && !out.contains('尿'),
            "left in clear: {out}"
        );
        assert!(out.contains("HEALTH_"), "no HEALTH token: {out}");
    }
}

#[test]
fn french_feminine_forms_are_masked_like_the_masculine() {
    for (text, term, label) in [
        (
            "Elle est séropositive depuis 2015.",
            "séropositive",
            "HEALTH_",
        ),
        (
            "Elle est dépressive depuis l'hiver.",
            "dépressive",
            "HEALTH_",
        ),
        ("Elle est syndiquée à la CGT.", "syndiquée", "TRADE_UNION_"),
        (
            "Traitement antirétroviral quotidien.",
            "antirétroviral",
            "HEALTH_",
        ),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {term}: {out}");
    }
}

#[test]
fn ambiguous_abbreviations_are_masked_next_to_a_health_cue() {
    for (text, term) in [
        ("She has MS and is in pain.", "MS"),
        ("Il a une SEP diagnostiquée.", "SEP"),
        ("Patient souffrant de TOC.", "TOC"),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn ambiguous_abbreviations_stay_clear_without_a_health_cue() {
    for text in ["Microsoft MS Office update", "Voir le TOC du document."] {
        assert!(!masked(text).contains("HEALTH_"), "over-masked: {text}");
    }
}

#[test]
fn stroke_anxiety_antidepressants_ocd_crohn_herpes_and_drugs_are_masked() {
    for (text, term) in [
        ("He had a stroke last year.", "stroke"),
        ("Il a eu un AVC en mars.", "AVC"),
        ("Anxiety is common in students.", "Anxiety"),
        ("Elle souffre d'anxiété.", "anxiété"),
        ("Il prend un antidépresseur.", "antidépresseur"),
        ("She takes an antidepressant.", "antidepressant"),
        ("OCD affects her daily life.", "OCD"),
        ("Il a la maladie de Crohn.", "Crohn"),
        ("Herpes outbreak on the lip.", "Herpes"),
        ("Elle prend du Prozac.", "Prozac"),
        ("Zoloft prescription renewed.", "Zoloft"),
        ("Hy gebruik 'n antidepressant.", "antidepressant"),
        ("Hy het 'n dwangneurose.", "dwangneurose"),
        ("Egy agyvérzés után.", "agyvérzés"),
        ("Ima anksiozno motnjo.", "anksiozno"),
        ("Ima možganska kap.", "možganska kap"),
        ("Ima Crohnovo bolezen.", "Crohnovo"),
        ("他患过卒中。", "卒中"),
        ("他有焦虑。", "焦虑"),
        ("他在吃抗抑郁药。", "抗抑郁"),
        ("她患有強迫症。", "強迫症"),
        ("他得了克罗恩病。", "克罗恩病"),
        ("他有疱疹。", "疱疹"),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn compounds_and_case_endings_in_hu_af_and_sl_are_masked() {
    for (text, term) in [
        ("A tüdőrákja miatt kezelik.", "tüdőrákja"),
        ("Prosztatarákban szenved.", "prosztatarákban"),
        ("Az orvos rákja súlyos.", "rákja"),
        ("Ez a ráknak szól.", "ráknak"),
        ("Terhesen dolgozik.", "Terhesen"),
        ("Hy het borskanker.", "borskanker"),
        ("Sy het longkanker.", "longkanker"),
        ("Die suikersiektepasiënt rus.", "suikersiektepasiënt"),
        ("Oče ima diabetesom.", "diabetesom"),
        ("Ima hepatitisom.", "hepatitisom"),
        ("Ima multiplo sklerozo.", "sklerozo"),
        ("Ima možgansko kap.", "možgansko"),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn traditional_taiwan_and_mainland_forms_are_masked_with_their_label() {
    let cases = [
        ("胰島素", "HEALTH_"),
        ("中風", "HEALTH_"),
        ("自閉症", "HEALTH_"),
        ("自殺", "HEALTH_"),
        ("殘疾", "HEALTH_"),
        ("孕婦", "HEALTH_"),
        ("成癮", "HEALTH_"),
        ("自殘", "HEALTH_"),
        ("失智症", "HEALTH_"),
        ("阿茲海默症", "HEALTH_"),
        ("阿爾茲海默症", "HEALTH_"),
        ("猶太人", "RELIGION_"),
        ("伊斯蘭教徒", "RELIGION_"),
        ("錫克教徒", "RELIGION_"),
    ];
    for (term, label) in cases {
        let out = masked(&format!("他是{term}。"));
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {term}: {out}");
    }
}

#[test]
fn the_breaker_terms_are_masked_in_their_languages() {
    let cases = [
        ("Elle est anorexique depuis un an.", "anorexique", "HEALTH_"),
        ("Il est boulimique depuis l'été.", "boulimique", "HEALTH_"),
        ("Il est bipolaire depuis 2010.", "bipolaire", "HEALTH_"),
        ("Elle est déprimée depuis l'hiver.", "déprimée", "HEALTH_"),
        ("Une patiente leucémique.", "leucémique", "HEALTH_"),
        ("Il est insomniaque.", "insomniaque", "HEALTH_"),
        ("Il est obèse.", "obèse", "HEALTH_"),
        ("Il est toxicomane.", "toxicomane", "HEALTH_"),
        ("Elle a subi une IVG en mars.", "IVG", "HEALTH_"),
        ("Il a parlé de son avortement.", "avortement", "HEALTH_"),
        ("Elle a une trisomie 21.", "trisomie", "HEALTH_"),
        ("Il prend du Lexomil le soir.", "Lexomil", "HEALTH_"),
        ("He is bipolar and works nights.", "bipolar", "HEALTH_"),
        ("She felt depressed all week.", "depressed", "HEALTH_"),
        ("The cancerous cells spread.", "cancerous", "HEALTH_"),
        ("She had an abortion in 2019.", "abortion", "HEALTH_"),
        ("A case of syphilis was reported.", "syphilis", "HEALTH_"),
        (
            "A chlamydia test came back positive.",
            "chlamydia",
            "HEALTH_",
        ),
        ("Her lupus flared up in spring.", "lupus", "HEALTH_"),
        ("He has cirrhosis of the liver.", "cirrhosis", "HEALTH_"),
        (
            "She takes sertraline each morning.",
            "sertraline",
            "HEALTH_",
        ),
        ("He switched to fluoxetine.", "fluoxetine", "HEALTH_"),
        ("He takes PrEP for HIV prevention.", "PrEP", "HEALTH_"),
        ("Sy het 'n aborsie gehad.", "aborsie", "HEALTH_"),
        ("A bipoláris zavar kezelése.", "bipoláris", "HEALTH_"),
        ("Szívroham érte tavaly.", "Szívroham", "HEALTH_"),
        ("Oče je imel infarkt.", "infarkt", "HEALTH_"),
        ("Bolnik je imel kap in je v bolnišnici.", "kap", "HEALTH_"),
    ];
    let registry = Registry::new();
    for (text, term, label) in cases {
        let spans = registry.analyze(text);
        let out = Anonymizer::new([0x4B; 32]).anonymize(text, &spans).0;
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {term}: {out}");
    }
}
