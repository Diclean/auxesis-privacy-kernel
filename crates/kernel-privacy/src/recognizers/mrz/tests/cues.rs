use super::super::cues::CUE_WINDOW;
use super::hits;

#[test]
fn broad_shape_only_masks_near_a_cue() {
    // `A1B2C3D4E5` is not the strict shape, so only a cue widens it.
    assert!(hits("A1B2C3D4E5").is_empty());
    assert_eq!(
        hits("passeport A1B2C3D4E5"),
        vec!["A1B2C3D4E5"],
        "cued broad shape missed"
    );
    assert_eq!(hits("P<FRADUPONT A1B2C3D4E5"), vec!["A1B2C3D4E5"]);
}

#[test]
fn cue_window_looks_after_the_value_too() {
    // The cue may follow the value within the window (P3).
    assert_eq!(hits("A1B2C3D4E5 passeport"), vec!["A1B2C3D4E5"]);
    // A cue beyond the 64-character window does not widen the shape.
    let mut distant = String::from("A1B2C3D4E5 ");
    distant.push_str(&"x".repeat(CUE_WINDOW));
    distant.push_str(" passeport");
    assert!(hits(&distant).is_empty());
}

#[test]
fn a_cued_bad_check_digit_is_still_masked() {
    assert_eq!(
        hits("passeport L898902C35"),
        vec!["L898902C35"],
        "a typo near a passport cue leaked"
    );
}
