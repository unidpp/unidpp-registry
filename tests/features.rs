//! Integration tests for the v3 feature set (real HTTP against
//! spawned servers):
//!
//! - item 51 — the profile-manifest JSON Schema is served (draft
//!   2020-12) and enforced at `POST /items` intake with precise
//!   field paths; both pilot manifest dialects pass;
//! - item 52 — clock-predicate applicability: the antique-vehicle
//!   case, subject_facts via query parameter and POST body;
//! - item 57 — cross-register mappings: CRUD, referential
//!   integrity, lookup from either direction;
//! - item 58 — EXPRESS deposits: content hash, expressir validation
//!   (with the pending degrade path), hash-pinned retrieval,
//!   re-validation;
//! - item 71 — profile satisfiability: S3 demands on S0 rejected,
//!   warning-only mode.

mod support;

use serde_json::{json, Value};
use support::{enc, get, json_of};
use unidpp_registry::{expressir_available, Config, TestServer, Timestamp};

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

// ---------------------------------------------------------------------------
// Item 51 — profile manifest schema served + enforced at intake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn profile_manifest_schema_is_served() {
    let server = spawn_open().await;
    let resp = get(&format!("{}/schemas/profile-manifest", server.base_url)).await;
    assert_eq!(resp.status, 200, "{}", resp.body_string());
    assert_eq!(
        resp.header("content-type").unwrap(),
        "application/schema+json"
    );
    assert!(Timestamp::parse(resp.header("x-as-of").unwrap()).is_ok());
    let schema = json_of(&resp);
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        schema["$id"],
        "https://unidpp.org/schemas/profile-manifest/v1"
    );
    assert_eq!(schema["type"], "object");
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&json!("version")));
    assert!(schema["properties"]["triggers"].is_object());
    assert!(
        schema["as_of"].as_str().is_some(),
        "served with as-of semantics"
    );
    // as-of stamp follows the query instant
    let resp = get(&format!(
        "{}/schemas/profile-manifest?at={}",
        server.base_url,
        enc("2024-01-01T00:00:00Z")
    ))
    .await;
    assert_eq!(json_of(&resp)["as_of"], "2024-01-01T00:00:00Z");
    server.stop().await;
}

/// A dialect-A manifest (the pilot material-loop shape).
fn material_loop_manifest() -> Value {
    json!({
        "version": "1.0.0",
        "axes": ["characteristic"],
        "issuing_role": "manufacturer",
        "custody": {"default_model": "mass_balance", "standard": "ISO 22095:2020"},
        "legal_basis": [{
            "instrument": "Regulation (EU) 2024/1252",
            "citation": "Art. 15",
            "force": "binding"
        }],
        "data_points": [
            {
                "element": "de/m/crm-identity",
                "min_capability": "S0",
                "required_provenance": "type_declared",
                "subject_granularity": "type",
                "tier_a": false,
                "traversal_depth": 1,
                "trust_floor": "attested",
                "cardinality": "1..n"
            }
        ],
        "transforms": [
            {"transform_ref": "urn:unidpp:transform:x", "transform_class": "aggregation"}
        ],
        "triggers": [
            {
                "predicate_class": "fact_predicate",
                "predicate_ref": "pred/contains-crm",
                "evaluation_mode": "on_event"
            }
        ],
        "notes": "dialect A"
    })
}

/// A dialect-B manifest (the pilot projector-lens shape).
fn lens_manifest() -> Value {
    json!({
        "version": "1.0.0",
        "profile": {
            "id": "urn:unidpp:profile:lens",
            "axes": {"jurisdiction": "EU"},
            "trigger": "Any",
            "min_capability": "silent",
            "data_points": [{"register": REGISTER, "item": "de.dpp.x", "version": "1.0.0"}]
        },
        "bindings": [{"element": "unidpp-dev/de.dpp.x@1.0.0", "min_trust": "attested"}],
        "transforms": [{"kind": "classification", "id": "bands", "bands": [{"label": "A"}]}]
    })
}

#[tokio::test]
async fn profile_manifest_intake_validates_with_field_paths() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let register = |manifest: Value, mut extra: Value| async move {
        let mut body = json!({
            "register_id": REGISTER,
            "item_id": "profile-under-test",
            "class": "profile",
            "definition": "profile under test",
            "version": "1.0.0",
            "manifest": manifest,
        });
        if let (Some(o), Some(e)) = (body.as_object_mut(), extra.as_object_mut()) {
            for (k, v) in e.iter() {
                o.insert(k.clone(), v.clone());
            }
        }
        post(base, "/items", &body).await
    };

    // Both pilot dialects pass intake (acceptance: the pilot's
    // seeded profiles validate).
    let resp = register(material_loop_manifest(), json!({})).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let resp = register(lens_manifest(), json!({"item_id": "lens-under-test"})).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());

    // A malformed manifest is rejected with the field path.
    let mut bad = material_loop_manifest();
    bad["data_points"][0]["min_capability"] = json!("S9");
    let resp = register(bad, json!({"item_id": "bad-capability"})).await;
    assert_eq!(resp.status, 400);
    let doc = json_of(&resp);
    let errors = doc["errors"].as_array().unwrap();
    assert!(errors
        .iter()
        .any(|e| e["path"] == "data_points[0].min_capability"
            && e["check"] == "profile-manifest-schema"));

    // Missing version (also caught by the seam-S4 pinning rule, but
    // the schema runs first now).
    let mut bad = material_loop_manifest();
    bad.as_object_mut().unwrap().remove("version");
    let resp = register(bad, json!({"item_id": "no-version"})).await;
    assert_eq!(resp.status, 400);

    // A time trigger without its duration names the field.
    let mut bad = material_loop_manifest();
    bad["triggers"][0] =
        json!({"predicate_class": "time", "basis": "manufactured_at", "operator": ">="});
    let resp = register(bad, json!({"item_id": "bad-trigger"})).await;
    assert_eq!(resp.status, 400);
    let doc = json_of(&resp);
    assert!(doc["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["message"]
            .as_str()
            .unwrap()
            .contains("`duration` is missing")));

    // The subregister path validates identically.
    let mut body = json!({
        "register_id": REGISTER,
        "item_id": "subregister-profile",
        "definition": "via /profiles",
        "version": "1.0.0",
        "manifest": material_loop_manifest(),
    });
    body["manifest"]["data_points"][0]["traversal_depth"] = json!(-3);
    let resp = post(base, "/profiles", &body).await;
    assert_eq!(resp.status, 400);
    assert!(json_of(&resp)["errors"][0]["path"]
        .as_str()
        .unwrap()
        .contains("traversal_depth"));

    // And a superseding version's new manifest is validated too.
    let mut good = json!({
        "version": "2.0.0",
        "data_points": [{"element": "de/x", "min_capability": "S0"}],
        "triggers": []
    });
    good["data_points"][0]["min_capability"] = json!("S99");
    let resp = post(
        base,
        "/items/profile-under-test/versions",
        &json!({"version": "2.0.0", "reason": "new manifest", "manifest": good}),
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.body_string());

    // Nothing was registered by the rejected requests.
    for id in [
        "bad-capability",
        "no-version",
        "bad-trigger",
        "subregister-profile",
    ] {
        assert_eq!(get(&format!("{base}/items/{id}")).await.status, 404);
    }
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Item 52 — clock predicates (the antique Super-Cub case)
// ---------------------------------------------------------------------------

/// Registers the historic-vehicle profile: binds when the subject is
/// at least 40 years past `manufactured_at`.
async fn seed_clock_profile(base: &str) {
    let manifest = json!({
        "version": "1.0.0",
        "axes": ["characteristic"],
        "triggers": [
            {
                "predicate_class": "time",
                "basis": "manufactured_at",
                "operator": ">=",
                "duration": "P40Y",
                "description": "at least forty years since manufacture"
            }
        ]
    });
    let resp = post(
        base,
        "/items",
        &json!({
            "register_id": REGISTER,
            "item_id": "historic-vehicle",
            "class": "profile",
            "definition": "Historic vehicle profile (clock-fired)",
            "version": "1.0.0",
            "manifest": manifest,
        }),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let resp = post(
        base,
        "/applicability",
        &json!({
            "profile_id": "historic-vehicle",
            "product_type": "gtin:06901234000016",
            "effective_from": "1990-01-01T00:00:00Z",
            "retroactive": true
        }),
    )
    .await;
    assert_eq!(resp.status, 201);
}

const SUBJECT: &str = "gtin:06901234000016";
/// manufactured 1962-05-04 → the P40Y threshold is 2002-05-04.
const FACTS: &str = r#"{"manufactured_at":"1962-05-04T00:00:00Z"}"#;

#[tokio::test]
async fn clock_predicate_binds_only_after_the_threshold() {
    let server = spawn_open().await;
    let base = &server.base_url;
    seed_clock_profile(base).await;

    let query = |at: &str| {
        format!(
            "{base}/applicability?product_type={}&at={}&subject_facts={}",
            enc(SUBJECT),
            enc(at),
            enc(FACTS)
        )
    };

    // Before the threshold (T = 2001): the binding's as-of window is
    // open and retroactive, but the clock predicate has not fired.
    let resp = get(&query("2001-06-01T00:00:00Z")).await;
    assert_eq!(resp.status, 200);
    let doc = json_of(&resp);
    assert_eq!(doc["applicability"].as_array().unwrap().len(), 0);

    // After the threshold (T = 2002-06-01): the profile binds, with
    // the evaluation recorded.
    let resp = get(&query("2002-06-01T00:00:00Z")).await;
    let doc = json_of(&resp);
    let entries = doc["applicability"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "binds at the later instant only");
    assert_eq!(entries[0]["binding"]["profile_item"], "historic-vehicle");
    let tt = &entries[0]["time_triggers"][0];
    assert_eq!(tt["threshold"], "2002-05-04T00:00:00Z");
    assert_eq!(tt["duration"], "P40Y");
    assert_eq!(tt["satisfied"], true);

    // The boundary instant itself: >= is inclusive.
    let doc = json_of(&get(&query("2002-05-04T00:00:00Z")).await);
    assert_eq!(doc["applicability"].as_array().unwrap().len(), 1);
    // One second before: not yet.
    let doc = json_of(&get(&query("2002-05-03T23:59:59Z")).await);
    assert_eq!(doc["applicability"].as_array().unwrap().len(), 0);

    // Without subject_facts the clock-fired binding is unresolved,
    // not silently applicable.
    let resp = get(&format!(
        "{base}/applicability?product_type={}&at=2020-01-01T00:00:00Z",
        enc(SUBJECT)
    ))
    .await;
    let doc = json_of(&resp);
    assert_eq!(doc["applicability"].as_array().unwrap().len(), 0);
    assert_eq!(doc["unresolved"].as_array().unwrap().len(), 1);

    // Malformed facts JSON is a 400.
    let resp = get(&format!(
        "{base}/applicability?product_type={}&subject_facts=not-json",
        enc(SUBJECT)
    ))
    .await;
    assert_eq!(resp.status, 400);
    // Facts that are not an object: 400.
    let resp = get(&format!(
        "{base}/applicability?product_type={}&subject_facts=%5B1%5D",
        enc(SUBJECT)
    ))
    .await;
    assert_eq!(resp.status, 400);

    server.stop().await;
}

#[tokio::test]
async fn clock_predicate_evaluates_from_the_post_body() {
    let server = spawn_open().await;
    let base = &server.base_url;
    seed_clock_profile(base).await;

    // POST /applicability with subject_facts is an evaluation, not a
    // binding mutation.
    let resp = post(
        base,
        "/applicability",
        &json!({
            "product_type": SUBJECT,
            "at": "1999-01-01T00:00:00Z",
            "subject_facts": {"manufactured_at": "1962-05-04T00:00:00Z"}
        }),
    )
    .await;
    assert_eq!(resp.status, 200);
    let doc = json_of(&resp);
    assert_eq!(doc["applicability"].as_array().unwrap().len(), 0);

    let resp = post(
        base,
        "/applicability",
        &json!({
            "product_type": SUBJECT,
            "at": "2005-01-01T00:00:00Z",
            "subject_facts": {"manufactured_at": "1962-05-04T00:00:00Z"}
        }),
    )
    .await;
    let doc = json_of(&resp);
    assert_eq!(doc["applicability"].as_array().unwrap().len(), 1);
    assert_eq!(
        doc["applicability"][0]["time_triggers"][0]["threshold"],
        "2002-05-04T00:00:00Z"
    );

    // A subject that carries no manufacture date is outside the
    // predicate's scope: not bound, no crash.
    let resp = post(
        base,
        "/applicability",
        &json!({"product_type": SUBJECT, "subject_facts": {}}),
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(json_of(&resp)["applicability"].as_array().unwrap().len(), 0);

    // Binding with subject_facts is a 400 (mutually exclusive).
    let resp = post(
        base,
        "/applicability",
        &json!({
            "profile_id": "historic-vehicle",
            "product_type": SUBJECT,
            "subject_facts": {"manufactured_at": "1962-05-04T00:00:00Z"}
        }),
    )
    .await;
    assert_eq!(resp.status, 400);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Item 57 — cross-register mappings
// ---------------------------------------------------------------------------

async fn seed_two_standards(base: &str) {
    for (id, register) in [("gb-4943-1", "gb-std"), ("iec-62368-1", "iec")] {
        let resp = post(
            base,
            "/items",
            &json!({
                "register_id": register,
                "item_id": id,
                "class": "data-element",
                "definition": format!("{id} standard designation"),
                "version": "1.0.0",
            }),
        )
        .await;
        assert_eq!(resp.status, 201, "{}", resp.body_string());
    }
}

#[tokio::test]
async fn cross_register_mapping_lifecycle_and_integrity() {
    let server = spawn_open().await;
    let base = &server.base_url;
    seed_two_standards(base).await;

    let mapping = json!({
        "register_id": REGISTER,
        "item_id": "equiv-gb4943-iec62368",
        "class": "cross-register-mapping",
        "definition": "GB 4943.1-2022 corresponds to IEC 62368-1 for charger conformity evidence",
        "version": "1.0.0",
        "manifest": {
            "version": "1.0.0",
            "source": {"register": "gb-std", "item": "gb-4943-1", "version": "1.0.0"},
            "target": {"register": "iec", "item": "iec-62368-1"},
            "mapping_type": "equivalent",
            "attester": "CQC-pattern notified body",
            "evidence_ref": "https://example/evidence"
        }
    });

    // Register (the underscore class spelling from the TODO also
    // parses).
    let resp = post(base, "/items", &mapping).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let created = json_of(&resp);
    assert_eq!(created["item_class"], "cross-register-mapping");
    assert_eq!(created["manifest"]["mapping_type"], "equivalent");

    // And through the dedicated subregister.
    let mut via_sub = mapping.clone();
    via_sub["item_id"] = json!("map-via-subregister");
    let resp = post(base, "/cross-register-mappings", &via_sub).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());

    // Dangling reference → 400 with the field path.
    let mut bad = mapping.clone();
    bad["item_id"] = json!("map-dangling");
    bad["manifest"]["target"]["item"] = json!("iec-does-not-exist");
    let resp = post(base, "/items", &bad).await;
    assert_eq!(resp.status, 400);
    let errors = json_of(&resp)["errors"].as_array().unwrap().clone();
    assert!(errors
        .iter()
        .any(|e| e["path"] == "target.item" && e["check"] == "cross-register-mapping-integrity"));

    // Unknown mapping type → schema rejection.
    let mut bad = mapping.clone();
    bad["item_id"] = json!("map-bad-type");
    bad["manifest"]["mapping_type"] = json!("same-ish");
    let resp = post(base, "/items", &bad).await;
    assert_eq!(resp.status, 400);
    assert!(json_of(&resp)["errors"][0]["path"] == "mapping_type");

    // Wrong register claim → integrity rejection.
    let mut bad = mapping.clone();
    bad["item_id"] = json!("map-bad-register");
    bad["manifest"]["source"]["register"] = json!("cen");
    let resp = post(base, "/items", &bad).await;
    assert_eq!(resp.status, 400);
    assert!(json_of(&resp)["errors"][0]["path"] == "source.register");

    // Unregistered version pin → integrity rejection.
    let mut bad = mapping.clone();
    bad["item_id"] = json!("map-bad-version");
    bad["manifest"]["source"]["version"] = json!("9.9.9");
    let resp = post(base, "/items", &bad).await;
    assert_eq!(resp.status, 400);
    assert!(json_of(&resp)["errors"][0]["path"] == "source.version");

    // Nothing rejected was registered.
    for id in [
        "map-dangling",
        "map-bad-type",
        "map-bad-register",
        "map-bad-version",
    ] {
        assert_eq!(get(&format!("{base}/items/{id}")).await.status, 404);
    }

    // Lookup from either direction.
    let by_source = json_of(&get(&format!("{base}/cross-register-mappings?item=gb-4943-1")).await);
    assert_eq!(by_source["count"], 2, "both mappings reference gb-4943-1");
    let by_target =
        json_of(&get(&format!("{base}/cross-register-mappings?item=iec-62368-1")).await);
    assert_eq!(by_target["count"], 2);
    let named_side = json_of(
        &get(&format!(
            "{base}/cross-register-mappings?source=gb-4943-1&target=iec-62368-1"
        ))
        .await,
    );
    assert_eq!(named_side["count"], 2);
    let wrong_side =
        json_of(&get(&format!("{base}/cross-register-mappings?target=gb-4943-1")).await);
    assert_eq!(wrong_side["count"], 0, "gb-4943-1 is only a source");
    assert_eq!(wrong_side["mappings"].as_array().unwrap().len(), 0);

    // The item itself resolves (generic item view + subregister).
    let resp = get(&format!("{base}/items/equiv-gb4943-iec62368")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        json_of(&resp)["manifest"]["attester"],
        "CQC-pattern notified body"
    );
    let resp = get(&format!(
        "{base}/cross-register-mappings/equiv-gb4943-iec62368"
    ))
    .await;
    assert_eq!(resp.status, 200);

    // Duplicate registration still conflicts.
    let resp = post(base, "/items", &mapping).await;
    assert_eq!(resp.status, 409);

    // The audit log carries the registration.
    let log = json_of(&get(&format!("{base}/admin/log?limit=10")).await);
    assert!(
        log["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["op"] == "register-item"
                && r["item"]["item_class"] == "cross-register-mapping")
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Item 58 — EXPRESS model deposits
// ---------------------------------------------------------------------------

const VALID_EXPRESS: &str = "SCHEMA registry_deposit_min '1.0.0';\nEND_SCHEMA;\n";

#[tokio::test]
async fn express_deposit_round_trip_with_hash_and_validation() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let deposit = json!({
        "register_id": REGISTER,
        "item_id": "min-schema",
        "definition": "A minimal EXPRESS deposit",
        "version": "1.0.0",
        "source": VALID_EXPRESS,
        "submitting_organization": "UniDPP pilot",
    });
    let resp = post(base, "/models", &deposit).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let created = json_of(&resp);
    let hash = created["content_hash"].as_str().unwrap().to_string();
    assert!(hash.starts_with("sha256:"));
    assert_eq!(hash.len(), 71);
    assert!(matches!(
        created["validation"]["status"].as_str().unwrap(),
        "valid" | "pending"
    ));

    // GET returns the source, hash, and validation status.
    let resp = get(&format!("{base}/models/min-schema")).await;
    assert_eq!(resp.status, 200);
    let model = json_of(&resp);
    assert_eq!(model["source"], VALID_EXPRESS);
    assert_eq!(model["content_hash"], hash.as_str());
    assert_eq!(model["item_class"], "model");
    assert_eq!(model["version"]["version"], "1.0.0");

    // Hash-pinned retrieval: the right hash passes…
    let resp = get(&format!("{base}/models/min-schema?hash={}", enc(&hash))).await;
    assert_eq!(resp.status, 200);
    // …a wrong hash is a conflict.
    let resp = get(&format!("{base}/models/min-schema?hash=sha256:deadbeef")).await;
    assert_eq!(resp.status, 409);

    // The listing carries the validation status.
    let list = json_of(&get(&format!("{base}/models")).await);
    assert_eq!(list["count"], 1);
    assert_eq!(list["models"][0]["identifier"], "min-schema");
    assert!(list["models"][0]["validation"].is_string());

    // Re-validation is idempotent and audited.
    let resp = post(base, "/models/min-schema/validate", &json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.body_string());
    let doc = json_of(&resp);
    assert!(matches!(
        doc["validation"]["status"].as_str().unwrap(),
        "valid" | "pending"
    ));
    let log = json_of(&get(&format!("{base}/admin/log?limit=10")).await);
    assert!(log["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["op"] == "update-model-validation"));

    // The generic /items surface sees the model; the class cannot be
    // created there.
    let resp = get(&format!("{base}/items/min-schema")).await;
    assert_eq!(json_of(&resp)["item_class"], "model");
    let resp = post(
        base,
        "/items",
        &json!({
            "register_id": REGISTER,
            "item_id": "direct-model",
            "class": "model",
            "definition": "no direct creation",
            "version": "1.0.0"
        }),
    )
    .await;
    assert_eq!(resp.status, 400);

    // Unknown model 404s; missing source is a 400.
    assert_eq!(get(&format!("{base}/models/nope")).await.status, 404);
    let mut bad = deposit.clone();
    bad["item_id"] = json!("no-source");
    bad["source"] = Value::Null;
    assert_eq!(post(base, "/models", &bad).await.status, 400);

    // Duplicate deposit conflicts.
    assert_eq!(post(base, "/models", &deposit).await.status, 409);

    server.stop().await;
}

#[tokio::test]
async fn invalid_express_source_is_rejected_when_expressir_is_present() {
    let server = spawn_open().await;
    let base = &server.base_url;
    let resp = post(
        base,
        "/models",
        &json!({
            "register_id": REGISTER,
            "item_id": "broken-schema",
            "definition": "A broken EXPRESS deposit",
            "version": "1.0.0",
            "source": "SCHEMA broken here;\n",
        }),
    )
    .await;
    if expressir_available() {
        assert_eq!(resp.status, 400, "{}", resp.body_string());
        assert!(resp.body_string().contains("expressir"));
        assert_eq!(
            get(&format!("{base}/models/broken-schema")).await.status,
            404
        );
    } else {
        // Degrade path: stored pending, later re-validatable.
        assert_eq!(resp.status, 201);
        assert_eq!(json_of(&resp)["validation"]["status"], "pending");
    }
    server.stop().await;
}

#[tokio::test]
async fn journal_replays_model_deposits_and_validation_updates() {
    let dir =
        std::env::temp_dir().join(format!("unidpp-registry-models-it-{}", std::process::id()));
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir_all(&dir).unwrap();
    let config = Config {
        state_file: Some(path.clone()),
        ..Config::default()
    };
    {
        let server = TestServer::spawn(config.clone()).await.expect("spawn A");
        let base = &server.base_url;
        let resp = post(
            base,
            "/models",
            &json!({
                "register_id": REGISTER,
                "item_id": "journaled-schema",
                "definition": "journaled deposit",
                "version": "1.0.0",
                "source": VALID_EXPRESS,
            }),
        )
        .await;
        assert_eq!(resp.status, 201);
        server.stop().await;
    }
    let server = TestServer::spawn(config).await.expect("spawn B");
    let base = &server.base_url;
    let model = json_of(&get(&format!("{base}/models/journaled-schema")).await);
    assert_eq!(model["source"], VALID_EXPRESS);
    assert_eq!(
        model["content_hash"],
        unidpp_registry::content_hash(VALID_EXPRESS)
    );
    server.stop().await;
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Item 71 — profile satisfiability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn satisfiability_rejects_unservable_capability_demands() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let demanding = |subject: &str| {
        json!({
            "version": "1.0.0",
            "subject_capability": subject,
            "data_points": [
                {"element": "de/live-state", "min_capability": "S3", "fresh_within": "P1D"}
            ]
        })
    };

    // S3 freshness on an S0 subject: rejected with the field path.
    let resp = post(
        base,
        "/items",
        &json!({
            "register_id": REGISTER,
            "item_id": "live-profile-on-s0",
            "class": "profile",
            "definition": "demands live freshness from a silent subject",
            "version": "1.0.0",
            "manifest": demanding("S0"),
        }),
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.body_string());
    let doc = json_of(&resp);
    let errors = doc["errors"].as_array().unwrap();
    assert!(errors.iter().any(|e| e["check"] == "profile-satisfiability"
        && (e["path"] == "data_points[0].min_capability"
            || e["path"] == "data_points[0].fresh_within")));

    // The same profile on an S3 subject passes.
    let resp = post(
        base,
        "/items",
        &json!({
            "register_id": REGISTER,
            "item_id": "live-profile-on-s3",
            "class": "profile",
            "definition": "live freshness for a connected subject",
            "version": "1.0.0",
            "manifest": demanding("S3"),
        }),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());

    // Warning-only mode: strict=false registers with warnings.
    let resp = post(
        base,
        "/items",
        &json!({
            "register_id": REGISTER,
            "item_id": "live-profile-warned",
            "class": "profile",
            "definition": "registered with a warning",
            "version": "1.0.0",
            "strict": false,
            "manifest": demanding("S0"),
        }),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let doc = json_of(&resp);
    let warnings = doc["warnings"].as_array().unwrap();
    assert!(warnings
        .iter()
        .any(|w| w["check"] == "profile-satisfiability"));

    // Bounded freshness alone is unsatisfiable on S1 too.
    let mut s1 = json!({
        "version": "1.0.0",
        "subject_capability": "S1",
        "data_points": [{"element": "de/x", "min_capability": "S0", "fresh_within": "PT6H"}]
    });
    let resp = post(
        base,
        "/items",
        &json!({
            "register_id": REGISTER,
            "item_id": "s1-freshness",
            "class": "profile",
            "definition": "passive-auth cannot serve freshness",
            "version": "1.0.0",
            "manifest": s1.clone(),
        }),
    )
    .await;
    assert_eq!(resp.status, 400);
    // …but fine on S2.
    s1["subject_capability"] = json!("S2");
    let resp = post(
        base,
        "/items",
        &json!({
            "register_id": REGISTER,
            "item_id": "s2-freshness",
            "class": "profile",
            "definition": "logged-contact serves read-time freshness",
            "version": "1.0.0",
            "manifest": s1,
        }),
    )
    .await;
    assert_eq!(resp.status, 201);

    // An undeclared subject class is not checkable (the pilot
    // manifests declare none and pass).
    let mut undeclared = demanding("S0");
    undeclared
        .as_object_mut()
        .unwrap()
        .remove("subject_capability");
    let resp = post(
        base,
        "/items",
        &json!({
            "register_id": REGISTER,
            "item_id": "undeclared-subject",
            "class": "profile",
            "definition": "no declared subject class",
            "version": "1.0.0",
            "manifest": undeclared,
        }),
    )
    .await;
    assert_eq!(resp.status, 201);

    server.stop().await;
}
