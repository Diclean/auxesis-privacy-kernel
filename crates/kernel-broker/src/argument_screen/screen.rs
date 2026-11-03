//! The entry point: screening the joined views and the leaves, and naming the hit.

use std::sync::OnceLock;

use kernel_privacy::{EntityKind, Registry, Span};
use serde_json::Value;

use super::decode::collect_views;
use super::false_hits::is_false_hit;
use super::phone::phone_shaped_digits;
use super::views::{collect_leaves, digits_and_letters};
use super::{
    MAX_DECODED_PER_CALL, MAX_SCREENED_TEXT, RESIDUE_LABEL, UNSCREENED_LABEL, VIEW_SEPARATOR,
};

/// The plain-language label of the first identifier in `arguments`, or `None`.
///
/// IP addresses and URLs are not identifiers here: a fetch-style call carries a
/// URL on almost every run, so counting it would ask on routine calls.
pub fn identifier_in_arguments(arguments: &Value) -> Option<&'static str> {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(Registry::new);
    let mut leaves = Vec::new();
    let mut values = Vec::new();
    collect_leaves(arguments, &mut leaves, &mut values);
    if leaves.iter().map(String::len).sum::<usize>() > MAX_SCREENED_TEXT {
        return Some(UNSCREENED_LABEL);
    }
    // The concatenated views go through the same screen as one more leaf, so
    // their own encoded forms are decoded too. Only a single leaf carries the
    // residue rule: a join of several fields is not a value that must decode
    // on its own.
    let reconstructed = values.join(VIEW_SEPARATOR);
    let in_order = leaves.join(VIEW_SEPARATOR);
    let digits = digits_and_letters(&leaves);
    let mut budget = MAX_DECODED_PER_CALL;
    // The digits view comes first: a split IBAN is named for what it is, not for a
    // grouped run the joined text happens to contain.
    let views = [digits.as_str(), reconstructed.as_str(), in_order.as_str()];
    let hit = views
        .into_iter()
        .find_map(|view| screen_text_and_views(registry, view, &mut budget, false))
        .or_else(|| phone_shaped_digits(&digits).then_some(label(EntityKind::Phone)));
    hit.or_else(|| {
        leaves.iter().find_map(|leaf| {
            phone_shaped_digits(leaf)
                .then_some(label(EntityKind::Phone))
                .or_else(|| screen_text_and_views(registry, leaf, &mut budget, true))
        })
    })
}

/// The label of the first hit in `text` or in one of its decoded views. A decode
/// that runs out of room asks. With `residue`, a decoding chain that stops while
/// its text still looks encoded asks too.
fn screen_text_and_views(
    registry: &Registry,
    text: &str,
    budget: &mut usize,
    residue: bool,
) -> Option<&'static str> {
    if let Some(label) = screen_text(registry, text) {
        return Some(label);
    }
    let mut views = Vec::new();
    let Ok(still_encoded) = collect_views(text, 0, budget, &mut views) else {
        return Some(UNSCREENED_LABEL);
    };
    views
        .iter()
        .find_map(|view| screen_text(registry, view))
        .or((residue && still_encoded).then_some(RESIDUE_LABEL))
}

/// The label of the first identifier in `text`, IP addresses and URLs aside, that
/// is not a false hit (see [`is_false_hit`]).
fn screen_text(registry: &Registry, text: &str) -> Option<&'static str> {
    let hits: Vec<Span> = registry
        .analyze(text)
        .into_iter()
        .filter(|span| !matches!(span.kind, EntityKind::IpV4 | EntityKind::Url))
        .filter(|span| !is_false_hit(text, span))
        .collect();
    // The e-mail layer reads a name off an address's local part, so a name hit
    // sits on top of the address: the address names the hit when both match.
    hits.iter()
        .find(|span| span.kind != EntityKind::Person)
        .or(hits.first())
        .map(|span| label(span.kind))
}

/// Plain-language label for a kind. Never the value.
fn label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::Email => "an e-mail address",
        EntityKind::Phone => "a phone number",
        EntityKind::Iban => "an IBAN",
        EntityKind::CreditCard => "a payment card number",
        _ => "a national identifier",
    }
}
