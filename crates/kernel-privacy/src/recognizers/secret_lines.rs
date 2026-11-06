//! Four secret forms the older scans miss. A session or auth cookie
//! value (`sessionid=…`, or any pair after `Cookie:` / `Set-Cookie:`), a value on
//! the line after its label (`Passphrase` then the words), a value in a CSV/TSV
//! column whose header names a secret, and a lower-case AWS access key id glued
//! to a word. Like the scans next to it, its spans are only added to the older
//! spans; it never removes one. Each line is read a bounded number of times, so
//! the scan is linear.

mod aws;
mod cookies;
mod header;
mod labels;
mod rows;
mod scan;
mod table;

pub(crate) use scan::lines_scan;
pub(crate) use table::{export_scan, secret_table_lines};

#[cfg(test)]
mod tests;
