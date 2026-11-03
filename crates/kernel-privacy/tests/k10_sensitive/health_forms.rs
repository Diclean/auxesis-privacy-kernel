//! Health terms that need the right inflection, accent or case to be
//! recognised, and the near misses that must stay in clear.

use super::helpers::masked;

#[test]
fn common_words_that_contain_a_short_health_root_are_not_masked() {
    for text in ["Poraka je prišla včeraj.", "Praka je bila v muzeju."] {
        let out = masked(text);
        assert!(!out.contains("HEALTH_"), "over-masked: {text} -> {out}");
    }
}

#[test]
fn hungarian_rak_compounds_and_case_forms_need_the_accent() {
    for (text, term) in [
        ("A méhnyakrák miatt kezelik.", "méhnyakrák"),
        ("A vastagbélrák szűrése pénteken.", "vastagbélrák"),
        ("Rákszűrés lesz pénteken.", "Rákszűrés"),
        ("Rákkutatás folyik az egyetemen.", "Rákkutatás"),
        ("Rákból gyógyult meg.", "Rákból"),
        ("Ráktól fél a családja.", "Ráktól"),
        ("Rákba került a betegség.", "Rákba"),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
    for text in [
        "Rak le a dobozt a padlóra.",
        "Az árak emelkedtek a héten.",
        "Rakospalota a kerület neve.",
    ] {
        assert!(!masked(text).contains("HEALTH_"), "over-masked: {text}");
    }
}

#[test]
fn medium_risk_is_not_a_stroke_and_a_stroke_is() {
    assert!(
        !masked("这是中风险等级的项目。").contains("HEALTH_"),
        "中风险 over-masked"
    );
    assert!(
        masked("他患有中风。").contains("HEALTH_"),
        "中风 not masked"
    );
}

#[test]
fn sep_followed_by_a_year_or_a_day_is_a_month() {
    let out = masked("Patient, rendez-vous le 12 SEP 2025.");
    assert!(
        !out.contains("HEALTH_"),
        "SEP 2025 masked as the disease: {out}"
    );
    let out = masked("Patient, réunion le SEP 12.");
    assert!(
        !out.contains("HEALTH_"),
        "SEP 12 masked as the disease: {out}"
    );
}

#[test]
fn han_terms_split_by_a_middle_dot_or_a_hyphen_are_masked() {
    for text in ["他有糖·尿·病。", "他有糖-尿-病。"] {
        let out = masked(text);
        assert!(
            !out.contains('糖') && !out.contains('尿'),
            "left in clear: {out}"
        );
        assert!(out.contains("HEALTH_"), "no HEALTH token: {out}");
    }
}

#[test]
fn afrikaans_kaartjies_is_not_varicose_veins() {
    let out = masked("Wys asseblief die kaartjies by die hek.");
    assert!(
        !out.contains("HEALTH_"),
        "kaartjies (tickets) over-masked: {out}"
    );
}

#[test]
fn inflected_forms_of_health_terms_are_masked_hu_sl_and_brand() {
    for (text, form, label) in [
        ("Magas vérnyomással él.", "vérnyomással", "HEALTH_"),
        ("Krónikus fájdalommal küzd.", "fájdalommal", "HEALTH_"),
        ("Ízületi gyulladással jár.", "gyulladással", "HEALTH_"),
        ("Down-szindrómával született.", "szindrómával", "HEALTH_"),
        ("Orvosi igazolást kért.", "igazolást", "HEALTH_"),
        ("Kórházi kezelésen volt.", "kezelésen", "HEALTH_"),
        (
            "Posttraumás stresszzavarral küzd.",
            "stresszzavarral",
            "HEALTH_",
        ),
        ("Szklerózis multiplexszel él.", "multiplexszel", "HEALTH_"),
        ("Etnikai származása miatt.", "származása", "ETHNIC_ORIGIN_"),
        ("Sérvvel operálták.", "Sérvvel", "HEALTH_"),
        ("Köszvénnyel küzd.", "Köszvénnyel", "HEALTH_"),
        ("Mama ima levkemijo.", "levkemijo", "HEALTH_"),
        ("Zaradi hipertenzije je bolna.", "hipertenzije", "HEALTH_"),
        ("Pacient s pljučnico.", "pljučnico", "HEALTH_"),
        ("Ima gripo.", "gripo", "HEALTH_"),
        ("Ima psihoze.", "psihoze", "HEALTH_"),
        ("Ima osteoporozo.", "osteoporozo", "HEALTH_"),
        ("Ima tromboze.", "tromboze", "HEALTH_"),
        ("Ima sepso.", "sepso", "HEALTH_"),
        ("Ima ciroze.", "ciroze", "HEALTH_"),
        ("Ima anemijo.", "anemijo", "HEALTH_"),
        ("Ima razjedo.", "razjedo", "HEALTH_"),
        ("Ima klamidijo.", "klamidijo", "HEALTH_"),
        ("Imel je cerebralno paralizo.", "paralizo", "HEALTH_"),
        ("Ima panične motnje.", "motnje", "HEALTH_"),
        ("Ima kronično bolečino.", "bolečino", "HEALTH_"),
        ("Zaradi raka prostate.", "raka", "HEALTH_"),
        ("Umrl je za rakom.", "rakom", "HEALTH_"),
        ("Vzel je Xanaxot.", "Xanaxot", "HEALTH_"),
        ("Jemlje Truvadát.", "Truvadát", "HEALTH_"),
        ("Vzel je Seroquelt.", "Seroquelt", "HEALTH_"),
        ("Vzel je Prozacom.", "Prozacom", "HEALTH_"),
        ("Vzel je Xanaxa.", "Xanaxa", "HEALTH_"),
    ] {
        let out = masked(text);
        assert!(!out.contains(form), "{form} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {form}: {out}");
    }
}

#[test]
fn hungarian_rak_with_a_possessive_and_a_case_is_masked() {
    for (text, form) in [
        ("Rákomról beszél.", "Rákomról"),
        ("Rákjával küzd.", "Rákjával"),
        ("Rákommal él.", "Rákommal"),
        ("Rákunkról szól.", "Rákunkról"),
        ("Rákjukat kezelik.", "Rákjukat"),
    ] {
        let out = masked(text);
        assert!(!out.contains(form), "{form} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {form}: {out}");
    }
    let out = masked("A Rákos-patak mellett sétáltunk.");
    assert!(
        !out.contains("HEALTH_"),
        "the stream Rákos-patak over-masked: {out}"
    );
}

#[test]
fn hungarian_hivjak_and_kap_are_not_health_terms() {
    let out = masked("A hívják gomb nem működik.");
    assert!(!out.contains("HEALTH_"), "hívják over-masked as HIV: {out}");
    let out = masked("Bíró Mira kezelést kap; ez bizalmas adat.");
    assert!(
        out.contains("kap"),
        "the Hungarian verb kap over-masked as the Slovene health word: {out}"
    );
}
