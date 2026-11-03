//! Tests for usage dimensions and totals.

use super::super::*;

#[test]
fn kind_strings_round_trip() {
    for kind in UsageKind::ALL {
        assert_eq!(UsageKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(UsageKind::parse("tokens"), None);
    assert_eq!(UsageKind::TokensIn.to_string(), "tokens_in");
    assert_eq!(UsageKind::UsdCents.unit(), "cents");
    assert_eq!(UsageKind::TokensOut.unit(), "tokens");
}

#[test]
fn totals_get_and_zero() {
    let totals = UsageTotals {
        tokens_in: 1,
        tokens_out: 0,
        usd_cents: 5,
    };
    assert_eq!(totals.get(UsageKind::TokensIn), 1);
    assert_eq!(totals.get(UsageKind::TokensOut), 0);
    assert_eq!(totals.get(UsageKind::UsdCents), 5);
    assert!(!totals.is_zero());
    assert!(UsageTotals::default().is_zero());
}

// ---- connector calls (S2b) ----

#[test]
fn connector_calls_kind_round_trips_after_usd_cents() {
    assert_eq!(
        UsageKind::ALL,
        [
            UsageKind::TokensIn,
            UsageKind::TokensOut,
            UsageKind::UsdCents,
            UsageKind::ConnectorCalls,
        ],
        "ConnectorCalls is appended after UsdCents"
    );
    assert_eq!(
        UsageKind::PROVIDER,
        [
            UsageKind::TokensIn,
            UsageKind::TokensOut,
            UsageKind::UsdCents,
        ],
        "the provider spend path must not carry ConnectorCalls"
    );
    assert_eq!(
        UsageKind::parse(UsageKind::ConnectorCalls.as_str()),
        Some(UsageKind::ConnectorCalls)
    );
    assert_eq!(UsageKind::ConnectorCalls.as_str(), "connector_calls");
    assert_eq!(UsageKind::ConnectorCalls.unit(), "calls");
    assert_eq!(
        UsageKind::parse("connector_calls"),
        Some(UsageKind::ConnectorCalls)
    );
}
