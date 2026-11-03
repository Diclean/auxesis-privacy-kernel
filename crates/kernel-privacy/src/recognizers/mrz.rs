//! Passport-number recogniser.
//!
//! A passport number is masked on its shape, never on its check digit alone:
//! a typo in a real document is still personal data (maintainer policy, P1).
//!
//! * the ICAO 9303 7-3-1 check digit is still computed, but only to *raise* the
//!   score of a ten-character payload+check value;
//! * without a cue the strict `[A-Z]{1,3}[0-9]{6,9}` passport shape is masked
//!   on sight, with at most one hyphen or dot between the letter prefix and the
//!   digits; a single *space* is masked too for **every** 1–3 letter prefix and
//!   7–9 digits, or when the de-spaced value passes the ICAO 7-3-1 check digit.
//!   `ISO` and a short business-reference denylist (`BUSINESS_PREFIXES`, e.g.
//!   `REF 1234567`) stay clear, and the cued `TAJ 123456788` keeps its `HU_TAJ`
//!   label, because those prefixes are cues for other rules;
//! * a passport cue (`passeport`, `passport`, `paspoort`, `útlevél`,
//!   `паспорт`, `جواز`, `MRZ`, `P<`) is searched for 64 characters *before and
//!   after* a value; near one the broader 8–10 alphanumeric shape with at least
//!   five digits is masked too.
//!
//! Every rule runs over the shared normalised view (P1): Arabic-Indic, Persian
//! and fullwidth digits all become ASCII digits and fullwidth letters become
//! ASCII, while matching is case-insensitive, so `passeport l898902c36` and
//! `جواز السفر QXZ١٢٣٤٥٦٧` are both masked. Spans are reported on the original
//! byte offsets.
//!
//! The recogniser is `verified: false`, so the registry labels its hits
//! `NATIONAL_ID` at a lower score; that is deliberate, the specific ICAO rule
//! is not confirmed against Doc 9303.

mod checks;
mod cues;
mod recognizer;
mod rows;

pub use recognizer::PassportMrzRecognizer;

/// Score of an 8–10 alphanumeric value near a cue with no valid check digit.
pub const BROAD_SCORE: f32 = 0.55;
/// Score of the strict passport shape with no valid check digit.
pub const STRICT_SCORE: f32 = 0.8;

/// Score of a machine-readable zone line.
pub const MRZ_LINE_SCORE: f32 = 1.0;

#[cfg(test)]
mod tests;
