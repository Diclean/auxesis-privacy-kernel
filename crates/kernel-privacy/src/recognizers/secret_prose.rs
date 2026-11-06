//! A password, API key, PIN or cookie whose value follows its key
//! through a prose link (`might be`, `,`, `is`, `will be`, `was`, `changed … to`,
//! `set it to`, `use`, `as`, `such as`, `which is`, `:`), a key written with
//! Markdown escapes (`api\_key`), and a cookie value (`Cookie:`, `Set-Cookie:`, a
//! `name=value; Path=` pair). Like the link scan next to it, its
//! spans are only added to the older scans' spans; it never removes one.
//!
//! A value must look like a secret, so prose after a link stays clear: six or more
//! characters with letters and digits, or a password sign (`!`, `@`, `$`, …) with
//! either, or four to eight digits after a PIN key. A bare `token` needs twelve
//! token characters with letters and digits; a bare `key` is left to the older
//! scans (`key` is too common a word). Each key reads at most [`MAX_WORDS`](keys::MAX_WORDS)
//! words of at most [`MAX_WORD`](keys::MAX_WORD) bytes, on its own line, so the scan is linear
//! with a constant that does not depend on how long the words of the text are.

mod keys;
mod rows;
mod runs;
mod scan;
mod value;
mod wifi;

pub(crate) use keys::ends_with_key;
pub(crate) use scan::prose_scan;

#[cfg(test)]
mod tests;
