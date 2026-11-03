//! Tests for the frozen held-out sets and their pins.

use crate::cases::Case;
use crate::heldout::*;
use crate::private_sets::{self, HeldOut, HELDOUT_1, HELDOUT_2};

#[test]
fn heldout_2_out_of_scope_cases_are_rejected() {
    let case: Case =
        serde_json::from_str(r#"{"id":"synthetic-ru","lang":"ru","text":"пример","spans":[]}"#)
            .expect("synthetic case parses");
    let error = validate_heldout_2_scope(&[case]).expect_err("out-of-scope is rejected");
    assert!(
        error.contains("synthetic-ru") && error.contains("ru"),
        "{error}"
    );
}

/// The set is pinned to a code constant; a synthetically rehashed body
/// cannot authorize re-baselining by changing only its data header.
#[test]
fn the_heldout_2_pin_rejects_a_rehashed_synthetic_body() {
    assert_eq!(
        HELDOUT_2_SHA256,
        "8ed06af51b9d6bcc030d21421bdd7a59bfbba6eb3b9c6d76e5fed24700a64bef"
    );
    let body = "{\"id\":\"synthetic\",\"lang\":\"en\",\"text\":\"sample\",\"spans\":[]}\n";
    let header = sha256_hex(body.as_bytes());
    let error = parse_heldout_2(&format!("# sha256: {header}\n{body}"))
        .err()
        .expect("a self-consistent but unapproved hash is rejected");
    assert!(error.contains("lead decision"), "{error}");
}

/// With the sets in `$AUXESIS_EVAL_DIR`, both pass their pins and the
/// header check; without them, the test says it skipped.
#[test]
fn the_held_out_sets_verify_when_present() {
    let dir = private_sets::eval_dir().expect("eval dir");
    match private_sets::load(&dir, HELDOUT_1).expect("held-out split") {
        HeldOut::Present(text) => assert!(!load_heldout(&text).is_empty()),
        HeldOut::Absent(path) => eprintln!("held-out set absent, skipped: {}", path.display()),
    }
    match private_sets::load(&dir, HELDOUT_2).expect("held-out-2") {
        HeldOut::Present(text) => {
            let (_, cases) = parse_heldout_2(&text).expect("held-out-2 header and code pin");
            validate_heldout_2_scope(&cases).expect("held-out-2 scope");
        }
        HeldOut::Absent(path) => eprintln!("held-out set absent, skipped: {}", path.display()),
    }
}
