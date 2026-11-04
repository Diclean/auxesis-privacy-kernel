//! A sensitive label followed by its value.
//!
//! One lexicon (`data/label-value-v1.tsv`) maps a label (`MRN`, `blood type`,
//! `the pin`, `Personalausweis`, `护照号`) to a class; the value after it is
//! masked when it has that class's shape:
//!
//! * `SECRET`: one token of 4+ characters holding a digit or a symbol, or a
//!   quoted value (`the password might be G9$rP2zT@qWk`, `the pin, 719836`);
//! * `COOKIE`: the rest of the line when it holds `=` (`Cookie: sid=…; b=…`);
//! * `ID` and `HEALTH`: an alphanumeric run with `-./` or single-space groups,
//!   5+ (ID) or 4+ (HEALTH) alphanumerics with 2+ digits (`CNI : 1234…`);
//! * `BLOOD`: a blood group with its sign (`O negative`, `AB+`, `B Rh-`), or
//!   bare after `:` when written in capitals;
//! * `MEMBER`: a `HEALTH` number after a label that is health only near a
//!   health word (`member ID` by a health insurer, not a gym's).
//!
//! The link between label and value is bounded: decoration (`**`, quotes, `|`,
//! and for an ID or health label an opening parenthesis), `:`, `=`, `#`, `,`,
//! number words (`no.`, `Nr`,
//! `n°`, and one glued to its value: `n°12AB34567`) and prose links (`is`,
//! `might be`, `changed … to` reads as `to`; a health or ID label also takes
//! `of`, `such as`, `c'est` and `for … is`), at most `MAX_LINK` bytes with each blank run
//! counted once. A `name=value; Path=/` cookie is masked too.
//! Every lookup is a bounded look-ahead from one automaton match: linear.
//! Values are `SECRET`, `NATIONAL_ID` or `HEALTH`, classes open mode removes.

mod blood;
mod cues;
mod lexicon;
mod links;
mod recognizer;
mod table;
mod text;
mod values;

pub use recognizer::LabelValueRecognizer;
pub(crate) use text::fold;

#[cfg(test)]
mod tests;
