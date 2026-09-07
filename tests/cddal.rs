//! Integration tests for CDDAL content negotiation (T-06 / item
//! 83): real HTTP against spawned servers. JSON stays the default;
//! `Accept: text/cddal` serves the canonical plain-text dictionary
//! form (byte-deterministic across calls) on the flat `/items`
//! listing and every subregister listing (including
//! `/data-elements`); the served form parses back into the term
//! entries projected from the registered items (the canonicalization
//! round trip); an `Accept` listing nothing servable falls back to
//! JSON with the `x-content-negotiation: unknown-accept-fallback`
//! warning header.

mod support;

use serde_json::{json, Value};
use support::{enc, get, get_with_headers, json_of};
use unidpp_registry::{cddal, Config, Item, TestServer, Timestamp};

const REGISTER: &str = "unidpp-dev";

async fn spawn_open() -> TestServer {
    TestServer::spawn(Config::default())
        .await
        .expect("spawn server")
}

async fn post(base: &str, path: &str, body: &Value) -> support::HttpResponse {
    support::json_request(
        "POST",
        &format!("{base}{path}"),
        Some(&body.to_string()),
        None,
    )
    .await
}

async fn seed_fixture(base: &str) {
    for (path, body) in [
        (
            "/data-elements",
            json!({
                "register_id": "untded",
                "item_id": "urn:untded:de:1000",
                "definition": "The name of the document.",
                "version": "1.0.0",
                "effective_from": "2005-01-01T00:00:00Z",
                "submitting_organization": "UNTDED 2005 (ECE/TRADE/362)",
                "manifest": {"version": "1.0.0", "name": "Document name", "tag": 1000, "representation": "an..35"}
            }),
        ),
        (
            "/data-elements",
            json!({
                "register_id": REGISTER,
                "item_id": "urn:unidpp:de:lot-mass",
                "definition": "Mass of the lot the subject was drawn from.",
                "version": "1.0.0",
                "manifest": {"version": "1.0.0", "required_unit": "units:kg"}
            }),
        ),
        (
            "/data-elements",
            json!({
                "register_id": "gb-std",
                "item_id": "gb-4943-1",
                "definition": "GB 4943.1-2022 standard designation",
                "version": "2022"
            }),
        ),
        (
            "/data-elements",
            json!({
                "register_id": "iec",
                "item_id": "iec-62368-1",
                "definition": "IEC 62368-1 standard designation",
                "version": "2018"
            }),
        ),
        (
            "/profiles",
            json!({
                "register_id": REGISTER,
                "item_id": "eu-espr-textiles",
                "definition": "EU ESPR textiles jurisdiction profile",
                "version": "1.0.0",
                "effective_from": "2026-10-18T00:00:00Z"
            }),
        ),
        (
            "/units",
            json!({
                "register_id": "unitsml",
                "item_id": "unitsml:u:kilowatt_hour",
                "definition": "kilowatt hour — energy; 1 kW·h = 3.6 MJ exactly",
                "version": "1.0.0",
                "manifest": {"version": "1.0.0", "name": "kilowatt hour", "symbol": "kW·h"}
            }),
        ),
        (
            "/cross-register-mappings",
            json!({
                "register_id": REGISTER,
                "item_id": "map-gb4943-iec62368",
                "definition": "GB 4943.1-2022 corresponds to IEC 62368-1 for charger conformity evidence",
                "version": "1.0.0",
                "manifest": {
                    "version": "1.0.0",
                    "source": {"register": "gb-std", "item": "gb-4943-1", "version": "2022"},
                    "target": {"register": "iec", "item": "iec-62368-1"},
                    "mapping_type": "equivalent",
                    "attester": "CQC-pattern notified body"
                }
            }),
        ),
    ] {
        let resp = post(base, path, &body).await;
        assert_eq!(resp.status, 201, "{}", resp.body_string());
    }
}

/// Fetches one item through the JSON form and projects it the way
/// the server does (the full wire item parses back into the model;
/// extra view keys are ignored by `Item::from_json`).
async fn item_entry(base: &str, identifier: &str, at: Option<&str>) -> cddal::TermEntry {
    let mut url = format!("{base}/items/{}", enc(identifier));
    if let Some(t) = at {
        url.push_str(&format!("?at={}", enc(t)));
    }
    let resp = get(&url).await;
    assert_eq!(resp.status, 200, "{}", resp.body_string());
    let item = Item::from_json(&json_of(&resp)).expect("wire item parses into the model");
    cddal::TermEntry::of(&item, at.and_then(|t| Timestamp::parse(t).ok()))
}

#[tokio::test]
async fn cddal_negotiation_serving_and_round_trip() {
    let server = spawn_open().await;
    let base = &server.base_url;
    seed_fixture(base).await;

    // -- Default: JSON, no negotiation header ----------------------
    let resp = get(&format!("{base}/data-elements")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("content-type").unwrap(), "application/json");
    assert!(resp.header("x-content-negotiation").is_none());
    assert_eq!(json_of(&resp)["count"], 4);

    // -- text/cddal is served with the right content type ----------
    let resp = get_with_headers(
        &format!("{base}/data-elements"),
        &[("accept", "text/cddal")],
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("content-type").unwrap(), "text/cddal");
    assert!(Timestamp::parse(resp.header("x-as-of").unwrap()).is_ok());
    assert!(resp.header("x-content-negotiation").is_none());

    // -- Round trip: the served form parses back into exactly the
    //    term entries projected from the registered items ---------
    let text = resp.body_string();
    let entries = cddal::parse(&text).expect("served CDDAL parses");
    assert_eq!(
        entries.len(),
        4,
        "the data-element subregister lists its four items"
    );
    let mut expected: Vec<cddal::TermEntry> = Vec::new();
    for id in [
        "urn:untded:de:1000",
        "urn:unidpp:de:lot-mass",
        "gb-4943-1",
        "iec-62368-1",
    ] {
        expected.push(item_entry(base, id, None).await);
    }
    expected.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    assert_eq!(entries, expected, "canonicalization round trip");

    // The dictionary slots are present (the UNTDED element carries
    // name + representation; the unit-bearing one its unit).
    let by_id = |id: &str| entries.iter().find(|e| e.identifier == id).unwrap();
    let de1000 = by_id("urn:untded:de:1000");
    assert_eq!(de1000.name, "Document name");
    assert_eq!(de1000.representation.as_deref(), Some("an..35"));
    let lot_mass = by_id("urn:unidpp:de:lot-mass");
    assert_eq!(lot_mass.unit.as_deref(), Some("units:kg"));

    // -- Byte-determinism: two calls are byte-identical ------------
    let again = get_with_headers(
        &format!("{base}/data-elements"),
        &[("accept", "text/cddal")],
    )
    .await
    .body;
    assert_eq!(again, resp.body, "byte-identical across two calls");

    // -- The flat /items listing: every class, still canonical -----
    let resp = get_with_headers(&format!("{base}/items"), &[("accept", "text/cddal")]).await;
    assert_eq!(resp.header("content-type").unwrap(), "text/cddal");
    let entries = cddal::parse(&resp.body_string()).unwrap();
    let mut expected: Vec<cddal::TermEntry> = Vec::new();
    for id in [
        "urn:untded:de:1000",
        "urn:unidpp:de:lot-mass",
        "gb-4943-1",
        "iec-62368-1",
        "eu-espr-textiles",
        "unitsml:u:kilowatt_hour",
        "map-gb4943-iec62368",
    ] {
        expected.push(item_entry(base, id, None).await);
    }
    expected.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    assert_eq!(entries, expected);
    // identifier-sorted (the store's canonical listing order)
    let ids: Vec<&str> = entries.iter().map(|e| e.identifier.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);

    // -- Subregister scoping under negotiation ---------------------
    let resp = get_with_headers(&format!("{base}/units"), &[("accept", "text/cddal")]).await;
    let entries = cddal::parse(&resp.body_string()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].unit_symbol.as_deref(), Some("kW·h"));
    assert_eq!(entries[0].name, "kilowatt hour");

    // -- Point-in-time: the `at` resolution reaches the CDDAL view --
    // (eu-espr-textiles' window opens 2026-10-18; before that
    // nothing is in force for it)
    let resp = get_with_headers(
        &format!(
            "{base}/items?class=profile&at={}",
            enc("2026-06-01T00:00:00Z")
        ),
        &[("accept", "text/cddal")],
    )
    .await;
    let entries = cddal::parse(&resp.body_string()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].version, None, "window not yet open → no version");
    assert_eq!(
        entries[0],
        item_entry(base, "eu-espr-textiles", Some("2026-06-01T00:00:00Z")).await
    );

    server.stop().await;
}

#[tokio::test]
async fn unknown_accept_falls_back_to_json_with_warning_header() {
    let server = spawn_open().await;
    let base = &server.base_url;
    seed_fixture(base).await;

    // An Accept nothing in which the service can serve → JSON with
    // the warning header.
    for accept in ["application/ld+json", "application/xml", "text/plain"] {
        let resp = get_with_headers(&format!("{base}/items"), &[("accept", accept)]).await;
        assert_eq!(resp.status, 200, "{accept}");
        assert_eq!(resp.header("content-type").unwrap(), "application/json");
        assert_eq!(
            resp.header("x-content-negotiation").unwrap(),
            "unknown-accept-fallback",
            "{accept}"
        );
        assert!(json_of(&resp)["count"].as_u64().is_some());
        // The subregister listing behaves identically.
        let resp = get_with_headers(&format!("{base}/data-elements"), &[("accept", accept)]).await;
        assert_eq!(
            resp.header("x-content-negotiation").unwrap(),
            "unknown-accept-fallback"
        );
    }

    // Servable Accepts stay silent (no warning header).
    for accept in [
        "*/*",
        "application/json",
        "application/json, application/xml",
    ] {
        let resp = get_with_headers(&format!("{base}/items"), &[("accept", accept)]).await;
        assert_eq!(resp.header("content-type").unwrap(), "application/json");
        assert!(
            resp.header("x-content-negotiation").is_none(),
            "{accept} should not warn"
        );
    }

    // Accept parameters and case are tolerated for CDDAL.
    let resp = get_with_headers(
        &format!("{base}/items"),
        &[("accept", "application/json, TEXT/CDDAL; charset=utf-8")],
    )
    .await;
    assert_eq!(resp.header("content-type").unwrap(), "text/cddal");
    assert!(resp.header("x-content-negotiation").is_none());

    server.stop().await;
}
