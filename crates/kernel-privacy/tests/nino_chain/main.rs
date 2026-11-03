//! NINO-CHAIN: every number of a chain of National Insurance numbers stays
//! masked, in both modes.
//!
//! Three leaks on main 041c9c46, one root cause: a suffix letter A to D that
//! also opens the *next* number belongs to both, and each pass gave it to one
//! side only, then never looked back:
//!
//! ```text
//! AB 12 34 56\ncb123456a                  ->  AB 12 34 56\n⟦UK_NINO⟧
//! XY 12 34 56 AB 12 34 56 AB 12 34 56 C   ->  ⟦UK_NINO⟧B 12 34 56 ⟦UK_NINO⟧
//! AB 12 34 56\nBAB123456B                 ->  ⟦UK_NINO⟧AB123456B
//! ```
//!
//! * `nino_at` refused a number whose suffix letter opens another one, and the
//!   FIN-6 cut that should take over needs capitals: the head stayed in clear;
//! * the separated pass kept the letter on one line and went on past it: the
//!   middle number of a chain stayed in clear;
//! * a number that starts one letter *behind* the suffix letter is preceded by
//!   a letter, so the start rule never tried it.
//!
//! Now both passes keep the letter and read the next number from it as well;
//! the overlapping spans become one.
//!
//! Below: the three rows over every shape and break, chains of two to five
//! numbers in every shape combination, a seeded 1,800-document differential of
//! NI chains mixed with the other classes, a prose set that must not gain a
//! mask, and the release timing. Every range is read with the one shared reader
//! `tests/data/exact_mask.rs` (TEST-FITS-EXACT-2) — never `fits()`, never
//! `norm1::ranges`. Every number is built at run time from its own index, so no
//! two numbers in a text are the same value: one value twice is one token twice,
//! which the reader cannot place. Every value is invented.

mod chain_shapes;
mod chains;
mod corpus;
mod differential;
mod freeze;
mod glued;
mod helpers;
mod perf;
mod prose;
mod targeted;
