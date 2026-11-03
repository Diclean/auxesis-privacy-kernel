//! The fixture freezer: run on the base only.

use super::corpus::documents;
use super::glued::glued_texts;
use super::helpers::{fixture, header, read, record_of, MODES};
use super::prose::prose;
use super::targeted::targeted_texts;

#[test]
#[ignore = "freezes a base fixture: run on the base only"]
fn freeze() {
    println!("{}", fixture(&documents()));
    println!("PROSE-BEGIN\n{}", header(&prose()));
    for text in prose() {
        let each = MODES.map(|mode| record_of(&read(mode, &text))).join("|");
        println!("{each}");
    }
    println!("PROSE-END\n{}", fixture(&targeted_texts()));
    println!("{}", fixture(&glued_texts()));
}
