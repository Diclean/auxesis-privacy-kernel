use super::super::rows::data_rows;
use super::hits;

#[test]
fn a_machine_readable_zone_line_is_masked_whole() {
    // FAKE: the ICAO 9303 TD3 specimen and a TD1-style German specimen,
    // with no passport cue nearby.
    let td3 = "scan:\nP<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10";
    let found = hits(td3);
    for line in [
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
    ] {
        assert!(
            found.iter().any(|hit| hit.contains(line)),
            "{line} is not masked whole: {found:?}"
        );
    }
    let de = "C01X00T478D<<6408125F2702283<<<<<<<<<<<<<<<4\nMUSTERMANN<<ERIKA<<<<<<<<<<<<<<";
    let found = hits(de);
    for line in [
        "C01X00T478D<<6408125F2702283<<<<<<<<<<<<<<<4",
        "MUSTERMANN<<ERIKA<<<<<<<<<<<<<<",
    ] {
        assert!(
            found.iter().any(|hit| hit.contains(line)),
            "{line}: {found:?}"
        );
    }
    // A short `<<` run, a shell heredoc or generics stay clear.
    assert!(hits("cat <<EOF and Vec<Vec<u8>>").is_empty());
}

#[test]
fn a_data_line_with_no_filler_is_masked_whole_when_its_checks_hold() {
    let is_data_line = |row: &str| !data_rows(row).is_empty();
    let td3 = "X4R2T9M716UTO8703145M31092255820411773094106";
    let td3b = "KD7Q0P2Z80UTO9201051F29061177103992645812096";
    let td1 = "IDUTOR8M4K2T075395820174461823";
    let td1_2 = "8703145M3109225UTO581041177364";
    // A row may also give a shorter hit inside itself (a 36-character prefix
    // whose composite check holds by chance): it lies within the row.
    let whole = |text: &str, rows: &[&str]| {
        let found = hits(text);
        rows.iter().all(|row| found.iter().any(|hit| hit == row))
            && found
                .iter()
                .all(|hit| rows.iter().any(|row| row.contains(hit.as_str())))
    };
    assert!(whole(&format!("MRZ\n{td3}"), &[td3]));
    assert!(whole(td1, &[td1]));
    assert!(whole(td1_2, &[td1_2]));
    // Two rows glued with no separator, and a row attached to text: each row
    // is masked, the text is not.
    assert!(whole(&format!("{td3}{td3b}"), &[td3, td3b]));
    assert!(whole(&format!("x{td3}y"), &[td3]));
    // One character short: not a layout, so main's masks only.
    for short in [&td1[1..], &td1_2[..29]] {
        assert!(!is_data_line(short), "{short}");
    }
    // A shape with a wrong check digit, a `<` on a document check digit, or
    // a wrong one once read, is no row (its first 36 characters may still be
    // one, a TD2 row whose composite check holds by chance).
    for no_row in [
        "AZQVODDGMSGA3C9A<BYZ2N135VE7JH",
        "X4R2T9M716UTO8703145M31092255820411773094107",
        "AB1234567<UTO8703042F30091521234567890123458",
        "X4R2T9M71oUTO8703145M31092255820411773094106",
    ] {
        assert!(!hits(no_row).iter().any(|hit| hit == no_row), "{no_row}");
    }
    assert!(hits("3F2A9C41B07D58E6A1C3F2A9C41B07D58E6A1C3FA").is_empty());
}
