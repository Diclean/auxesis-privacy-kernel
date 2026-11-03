//! Inflected, stemmed and transliterated forms of a name part.

use super::assert_all;

#[test]
fn inflected_forms_of_a_name_part_match() {
    assert_all(&[
        ("John Smith", &["dinner with the Smiths"]),
        ("Anna Schmidt", &["Annas Auto steht hier", "Schmidts Büro"]),
        ("Camille Exemple", &["les Exemples"]),
        ("Иван Петров", &["Петрова", "Петрову"]),
    ]);
}

#[test]
fn generic_suffixes_and_stem_loss() {
    assert_all(&[
        ("Νίκος Παπαδόπουλος", &["του Νίκου", "του Παπαδόπουλου"]),
        ("Jan Kowalski", &["u Kowalskiego", "z Kowalskim", "Janem"]),
        ("Anna Nowak", &["z Nowakiem"]),
        ("Petr Novák", &["Novákovi", "paní Nováková"]),
        ("Олена Шевченко", &["Олени"]),
        ("Mikko Virtanen", &["Virtasen"]),
    ]);
}

#[test]
fn ascii_transliteration_both_ways() {
    assert_all(&[
        ("Jürgen Müller", &["Juergen Mueller", "Mueller", "JUERGEN"]),
        ("Søren Kierkegård", &["Soeren", "Kierkegaard"]),
        ("Åsa Ångström", &["Aasa Aangstroem"]),
    ]);
}
