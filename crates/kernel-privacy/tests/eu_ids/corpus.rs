//! The corpus of every spelling: the plain one, the labelled one and the
//! one whose check digit fails.

/// Every spelling of every class: the text, the value inside it and the class
/// it belongs to. The spellings are the ones the leak-finder mutates: a
/// glued prefix and suffix, lower case, full-width digits and the four
/// separators a printed number may use.
pub(crate) const SPELLINGS: &[(&str, &str, &str)] = &[
    // Germany.
    ("de_steuer_id", "26954371827", "26954371827"),
    ("de_steuer_id", "26 954 371 827", "26 954 371 827"),
    ("de_steuer_id", "26.954.371.827", "26.954.371.827"),
    ("de_steuer_id", "26-954-371-827", "26-954-371-827"),
    ("de_steuer_id", "26/954/371/827", "26/954/371/827"),
    ("de_steuer_id", "ref26954371827ok", "26954371827"),
    (
        "de_steuer_id",
        "２６９５４３７１８２７",
        "２６９５４３７１８２７",
    ),
    // Spain: the DNI and the NIE.
    ("es_dni", "12345678Z", "12345678Z"),
    ("es_dni", "12.345.678Z", "12.345.678Z"),
    ("es_dni", "12345678z", "12345678z"),
    ("es_dni", "ref12345678Zok", "12345678Z"),
    ("es_dni", "X1234567L", "X1234567L"),
    ("es_dni", "x1234567l", "x1234567l"),
    ("es_dni", "refX1234567Lok", "X1234567L"),
    // Spain: the control letter after a separator, and the NIE with one.
    ("es_dni", "12345678-Z", "12345678-Z"),
    ("es_dni", "12345678 Z", "12345678 Z"),
    ("es_dni", "12345678\nZ", "12345678\nZ"),
    ("es_dni", "X-1234567-L", "X-1234567-L"),
    // Italy.
    ("it_codice_fiscale", "ZMRPKC73R12H780Z", "ZMRPKC73R12H780Z"),
    ("it_codice_fiscale", "zmrpkc73r12h780z", "zmrpkc73r12h780z"),
    (
        "it_codice_fiscale",
        "ZMRPKC７３R１２H７８０Z",
        "ZMRPKC７３R１２H７８０Z",
    ),
    (
        "it_codice_fiscale",
        "refZMRPKC73R12H780Zok",
        "ZMRPKC73R12H780Z",
    ),
    // Italy: the control character is a letter, the place keeps three digits
    // and a digit of the omocodia stands for its letter.
    ("it_codice_fiscale", "AAAAAA00A10H501B", "AAAAAA00A10H501B"),
    ("it_codice_fiscale", "ZMRPKC99R12H780J", "ZMRPKC99R12H780J"),
    ("it_codice_fiscale", "ZMRPKCV9R12H780J", "ZMRPKCV9R12H780J"),
    // The Netherlands: nine consecutive digits, never a grouped run.
    ("nl_bsn", "456789236", "456789236"),
    ("nl_bsn", "ref456789236ok", "456789236"),
    // Belgium: a birth before 2000 and a birth after it.
    ("be_national_number", "91.07.22-406.21", "91.07.22-406.21"),
    ("be_national_number", "91072240621", "91072240621"),
    ("be_national_number", "91 07 22 406 21", "91 07 22 406 21"),
    ("be_national_number", "291.07.22-406.21", "291.07.22-406.21"),
    ("be_national_number", "205.03.14-237.51", "205.03.14-237.51"),
    ("be_national_number", "87111523456", "87111523456"),
    // Belgium: the check of a birth after 2000 is computed on the number
    // with the century in front.
    ("be_national_number", "05031423780", "05031423780"),
    ("be_national_number", "99.03.14-237.17", "99.03.14-237.17"),
    ("be_national_number", "299.03.14-237.17", "299.03.14-237.17"),
    ("be_national_number", "05.03.14-237.80", "05.03.14-237.80"),
    // Poland: issued without a separator; a birth after 2000.
    ("pl_pesel", "92071314764", "92071314764"),
    ("pl_pesel", "ref92071314764tail", "92071314764"),
    ("pl_pesel", "02221503788", "02221503788"),
    (
        "pl_pesel",
        "９２０７１３１４７６４",
        "９２０７１３１４７６４",
    ),
    // Austria: whole or `NNNC DDMMYY`.
    ("at_sv_nr", "1230150885", "1230150885"),
    ("at_sv_nr", "1230 150885", "1230 150885"),
    ("at_sv_nr", "ref1230150885tail", "1230150885"),
    // Ireland: one or two letters, glued on one side, wrapped.
    ("ie_ppsn", "1234567T", "1234567T"),
    ("ie_ppsn", "7654321PA", "7654321PA"),
    ("ie_ppsn", "1234567t", "1234567t"),
    ("ie_ppsn", "ref1234567T", "1234567T"),
    ("ie_ppsn", "7654321PAtail", "7654321PA"),
    ("ie_ppsn", "1234567 . T", "1234567 . T"),
    ("ie_ppsn", "7654321  /  PA", "7654321  /  PA"),
    ("ie_ppsn", "7654321\nPA", "7654321\nPA"),
    // Sweden: ten or twelve digits, a dash or a plus.
    ("se_personnummer", "850709-3253", "850709-3253"),
    ("se_personnummer", "8507093253", "8507093253"),
    ("se_personnummer", "19850709-3253", "19850709-3253"),
    ("se_personnummer", "850709+3253", "850709+3253"),
    ("se_personnummer", "ref850709-3253tail", "850709-3253"),
    // Romania: thirteen digits, issued without a separator.
    ("ro_cnp", "1850709401231", "1850709401231"),
    ("ro_cnp", "2981215123455", "2981215123455"),
    ("ro_cnp", "ref1850709401231ok", "1850709401231"),
    (
        "ro_cnp",
        "１８５０７０９４０１２３１",
        "１８５０７０９４０１２３１",
    ),
    // Czechia and Slovakia: a woman (+50), a birth from 2004 (+70), the 10 -> 0
    // remainder, whole or with the slash.
    ("cz_sk_rodne_cislo", "855709/1235", "855709/1235"),
    ("cz_sk_rodne_cislo", "8557091235", "8557091235"),
    ("cz_sk_rodne_cislo", "850709/1241", "850709/1241"),
    ("cz_sk_rodne_cislo", "057715/1245", "057715/1245"),
    ("cz_sk_rodne_cislo", "052715/1230", "052715/1230"),
    ("cz_sk_rodne_cislo", "ref855709/1235tail", "855709/1235"),
    // Greece: the AMKA, issued without a separator.
    ("gr_amka", "09078512341", "09078512341"),
    ("gr_amka", "ref09078512341tail", "09078512341"),
    // Bulgaria: a birth in the 1900s and one in the 2000s (+40).
    ("bg_egn", "8507091237", "8507091237"),
    ("bg_egn", "0547151238", "0547151238"),
    ("bg_egn", "ref8507091237tail", "8507091237"),
    ("bg_egn", "８５０７０９１２３７", "８５０７０９１２３７"),
];

/// The labelled spelling of every class: a label names the value.
pub(crate) const LABELLED: &[(&str, &str, &str)] = &[
    ("de_steuer_id", "Steuer-ID 26954371827", "26954371827"),
    ("es_dni", "DNI 12345678Z", "12345678Z"),
    ("es_dni", "NIE X1234567L", "X1234567L"),
    (
        "it_codice_fiscale",
        "codice fiscale ZMRPKC73R12H780Z",
        "ZMRPKC73R12H780Z",
    ),
    ("nl_bsn", "BSN 456789236", "456789236"),
    (
        "be_national_number",
        "rijksregisternummer 91.07.22-406.21",
        "91.07.22-406.21",
    ),
    (
        "be_national_number",
        "rijksregisternummer 205.03.14-237.51",
        "205.03.14-237.51",
    ),
    (
        "be_national_number",
        "rijksregisternummer 299.03.14-237.17",
        "299.03.14-237.17",
    ),
    ("pl_pesel", "PESEL number 920 713 147 64", "920 713 147 64"),
    ("pt_nif", "NIF 234567899", "234567899"),
    (
        "pt_nif",
        "número de contribuinte: 162 738 498",
        "162 738 498",
    ),
    ("pt_nif", "tax number 234567899", "234567899"),
    ("at_sv_nr", "SV-Nr. 1230 150885", "1230 150885"),
    (
        "at_sv_nr",
        "social insurance number 1230-150885",
        "1230-150885",
    ),
    ("ie_ppsn", "PPSN: 1234567 T", "1234567 T"),
    ("ie_ppsn", "PPS number 7654321PA", "7654321PA"),
    ("ie_ppsn", "PPSN 1234567/T", "1234567/T"),
    ("ie_ppsn", "PPSN:1234567 / T", "1234567 / T"),
    ("ie_ppsn", "PPS No 1234567 - TW", "1234567 - TW"),
    ("ie_ppsn", "PPS number ref7654321PAtail", "7654321PA"),
    ("se_personnummer", "personnummer 850709-3253", "850709-3253"),
    (
        "se_personnummer",
        "personal identity number: 19850709 3253",
        "19850709 3253",
    ),
    ("ro_cnp", "CNP: 1850709401231", "1850709401231"),
    (
        "ro_cnp",
        "cod numeric personal 1 850709 401231",
        "1 850709 401231",
    ),
    (
        "ro_cnp",
        "personal numeric code 1850709401231",
        "1850709401231",
    ),
    (
        "cz_sk_rodne_cislo",
        "rodné číslo 855709/1235",
        "855709/1235",
    ),
    (
        "cz_sk_rodne_cislo",
        "rodne cislo: 855709 1235",
        "855709 1235",
    ),
    ("cz_sk_rodne_cislo", "RČ 450709/123", "450709/123"),
    ("cz_sk_rodne_cislo", "birth number 450709123", "450709123"),
    ("gr_afm", "AFM 123456783", "123456783"),
    ("gr_afm", "A.F.M.: 090 876 541", "090 876 541"),
    ("gr_amka", "AMKA 09078512341", "09078512341"),
    ("gr_amka", "AMKA: 090785 12341", "090785 12341"),
    (
        "gr_amka",
        "Greek social insurance number: 09078512341",
        "09078512341",
    ),
    ("gr_afm", "Greek tax number: 123456783", "123456783"),
    ("bg_egn", "EGN 8507091237", "8507091237"),
    ("bg_egn", "unified civil number 850709 1237", "850709 1237"),
];

/// A value whose check digit fails: it stays in clear while no label names
/// it, and a label names it.
///
/// The Italian value is the lower-case spelling: the bank rule reads the last
/// twelve characters of an upper-case codice fiscale as an IBAN guess, which
/// is main's business and not this rule's.
pub(crate) const FAILURES: &[(&str, &str, &str)] = &[
    ("de_steuer_id", "26954371828", "Steuer-ID 26954371828"),
    ("es_dni", "12345678A", "DNI 12345678A"),
    ("es_dni", "X1234567A", "NIE X1234567A"),
    (
        "it_codice_fiscale",
        "zmrpkc73r12h780y",
        "codice fiscale zmrpkc73r12h780y",
    ),
    ("nl_bsn", "456789237", "BSN 456789237"),
    (
        "be_national_number",
        "91.07.22-406.22",
        "rijksregisternummer 91.07.22-406.22",
    ),
    (
        "be_national_number",
        "205.03.14-237.52",
        "rijksregisternummer 205.03.14-237.52",
    ),
    (
        "be_national_number",
        "299.03.14-237.18",
        "rijksregisternummer 299.03.14-237.18",
    ),
    ("pl_pesel", "92071314765", "PESEL 92071314765"),
    ("at_sv_nr", "1231150885", "SV-Nr 1231150885"),
    ("ie_ppsn", "1234567A", "PPSN 1234567A"),
    ("ie_ppsn", "1234567/A", "PPSN 1234567/A"),
    ("ie_ppsn", "1234567 / A", "PPSN:1234567 / A"),
    ("ie_ppsn", "1234567 - AB", "PPS No 1234567 - AB"),
    ("ie_ppsn", "1234567 . A", "PPSN 1234567 . A"),
    // `850709-3254` is a valid rodné číslo: the failing value is another.
    ("se_personnummer", "850709-3255", "personnummer 850709-3255"),
    // A valid NIF stays in clear without a label: the rule reads labels only.
    ("pt_nif", "234567899", "NIF 234567899"),
    (
        "cz_sk_rodne_cislo",
        "855709/1236",
        "rodné číslo 855709/1236",
    ),
    ("gr_amka", "09078512342", "AMKA 09078512342"),
    // Seal A r1 (#348): the English label names a check-failing AMKA too.
    (
        "gr_amka",
        "09078512342",
        "Greek social insurance number: 09078512342",
    ),
    ("gr_afm", "123456783", "tax identification number 123456783"),
    ("bg_egn", "8507091238", "EGN 8507091238"),
    // A valid AFM and a rodné číslo of nine digits stay in clear without a
    // label: they carry no check that keeps a bare rule rare.
    ("gr_afm", "123456783", "AFM 123456783"),
    ("cz_sk_rodne_cislo", "450709/123", "RČ 450709/123"),
];
