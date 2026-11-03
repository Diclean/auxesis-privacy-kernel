//! The decode tests, split by topic.

mod entities;
mod escapes;
mod limits;
mod view;

use super::DecodedText;

fn decode(source: &str) -> String {
    DecodedText::new(source).text().to_string()
}
