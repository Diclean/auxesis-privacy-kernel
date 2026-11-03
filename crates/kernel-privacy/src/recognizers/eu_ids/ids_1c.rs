//! EU-KERNEL-1c: Romania, Czechia and Slovakia, Greece and Bulgaria.

use super::checks::{bg_egn_ok, cz_rodne_cislo_ok, gr_amka_ok, ro_cnp_ok};
use super::scan::{compact, grouped, wrapped_runs};
use super::{Body, Candidate};

/// The Romanian CNP: thirteen digits, issued without a separator.
pub(super) fn ro_candidates(body: &Body) -> Vec<Candidate> {
    wrapped_runs(body, &[13], compact, ro_cnp_ok)
}

/// The Czech and Slovak rodné číslo: `YYMMDD/SSSC`, whole or with the slash.
/// The nine digits of a birth before 1954 carry no check: a label names them.
pub(super) fn cz_candidates(body: &Body) -> Vec<Candidate> {
    let bare = |raw: &str| compact(raw) || grouped(raw, &[6, 4]);
    wrapped_runs(body, &[9, 10], bare, cz_rodne_cislo_ok)
}

/// The Greek AFM: nine digits, mod 11. Nine digits with a mod-11 check match
/// one number in ten, so the rule reads an AFM only after a label.
pub(super) fn gr_afm_candidates(body: &Body) -> Vec<Candidate> {
    wrapped_runs(body, &[9], |_| false, |_| false)
}

/// The Greek AMKA: eleven digits, `DDMMYY`, a serial and the Luhn check,
/// issued without a separator.
pub(super) fn gr_amka_candidates(body: &Body) -> Vec<Candidate> {
    wrapped_runs(body, &[11], compact, gr_amka_ok)
}

/// The Bulgarian EGN: ten digits, issued without a separator.
pub(super) fn bg_candidates(body: &Body) -> Vec<Candidate> {
    wrapped_runs(body, &[10], compact, bg_egn_ok)
}
