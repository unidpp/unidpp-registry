//! Integration tests: real HTTP against servers spawned on ephemeral
//! ports. Covers the required behaviours: register → supersede →
//! point-in-time as-of queries (before/during/after windows, with
//! derived window ends), supersession chains, retroactive
//! applicability (incl. effective_until closure and the
//! registered_at gate for non-retroactive bindings), subregisters as
//! class-scoped endpoints, admin auth, the append-only mutation audit
//! log, and journal replay across restarts.

mod support;

use serde_json::{json, Value};
use support::{enc, get, json_of, json_request};
use unidpp_registry::{Config, TestServer, Timestamp};

const REGISTER: &str = "unidpp-dev";

async fn spawn_open() -> TestServer {
    TestServer::spawn(Config::default())
        .await
        .expect("spawn server")
}

async fn post(base: &str, path: &str, body: &Value, token: Option<&str>) -> support::HttpResponse {
    support::json_request(
        "POST",
        &format!("{base}{path}"),
        Some(&body.to_string()),
        token,
    )
    .await
}

// ---------------------------------------------------------------------------
// Registration, current version, discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_item_current_version_and_discovery() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // Discovery declares the subregisters and as-of convention.
    let resp = get(&format!("{base}/")).await;
    assert_eq!(resp.status, 200);
    let doc = json_of(&resp);
    assert_eq!(doc["service"], "unidpp-registry");
    assert_eq!(
        doc["subregisters"]["crypto-suites"]["class"],
        "crypto-suite"
    );
    assert_eq!(
        doc["subregisters"]["trust-anchors"]["path"],
        "/trust-anchors"
    );
    assert_eq!(doc["as_of"]["response_header"], "x-as-of");
    assert_eq!(get(&format!("{base}/healthz")).await.status, 200);

    // Register the kilowatt-hour unit.
    let body = json!({
        "register_id": REGISTER,
        "item_id": "unit-kwh",
        "class": "unit",
        "definition": "kilowatt hour",
        "version": "1.0.0",
        "status": "valid",
        "effective_from": "2026-01-01T00:00:00Z",
        "submitting_organization": "ISO/TC 12"
    });
    let resp = post(base, "/items", &body, None).await;
    assert_eq!(resp.status, 201);
    let created = json_of(&resp);
    assert_eq!(created["identifier"], "unit-kwh");
    assert_eq!(created["register"], REGISTER);
    assert_eq!(created["item_class"], "unit");
    assert_eq!(created["title"], "kilowatt hour");
    assert_eq!(created["submitting_organization"], "ISO/TC 12");
    assert_eq!(created["versions"].as_array().unwrap().len(), 1);
    assert_eq!(created["versions"][0]["status"], "valid");
    assert!(created["versions"][0]["registered_at"].as_str().is_some());
    assert_eq!(created["version"]["version"], "1.0.0");
    assert_eq!(created["audit_seq"], 1);
    // as-of stamp on header and body
    assert!(Timestamp::parse(resp.header("x-as-of").unwrap()).is_ok());
    assert!(Timestamp::parse(created["as_of"].as_str().unwrap()).is_ok());

    // Current version without `at`.
    let resp = get(&format!("{base}/items/unit-kwh")).await;
    assert_eq!(resp.status, 200);
    let item = json_of(&resp);
    assert_eq!(item["version"]["version"], "1.0.0");
    assert_eq!(item["version"]["status"], "valid");

    // List, class-scoped.
    let resp = get(&format!("{base}/items?class=unit")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 1);
    assert_eq!(list["items"][0]["identifier"], "unit-kwh");
    let resp = get(&format!("{base}/items?class=profile")).await;
    assert_eq!(json_of(&resp)["count"], 0);

    // Duplicate registration conflicts (versions go through the
    // versions endpoint).
    let resp = post(base, "/items", &body, None).await;
    assert_eq!(resp.status, 409);

    // Validation: missing definition, unknown class, bad status,
    // path-unsafe identifier.
    let mut bad = body.clone();
    bad["definition"] = Value::Null;
    assert_eq!(post(base, "/items", &bad, None).await.status, 400);
    let mut bad = body.clone();
    bad["item_id"] = json!("unit-kwh-2");
    bad["class"] = json!("bogus");
    assert_eq!(post(base, "/items", &bad, None).await.status, 400);
    let mut bad = body.clone();
    bad["item_id"] = json!("unit-kwh-3");
    bad["status"] = json!("retired");
    assert_eq!(post(base, "/items", &bad, None).await.status, 400);
    let mut bad = body.clone();
    bad["item_id"] = json!("slash/id");
    assert_eq!(post(base, "/items", &bad, None).await.status, 400);

    // Unknown item and malformed `at`.
    assert_eq!(get(&format!("{base}/items/nope")).await.status, 404);
    assert_eq!(
        get(&format!("{base}/items/unit-kwh?at=Yesterday"))
            .await
            .status,
        400
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Supersession and point-in-time windows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn supersede_and_point_in_time_windows() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let register = json!({
        "register_id": REGISTER,
        "item_id": "eu-espr-textiles",
        "class": "profile",
        "definition": "EU ESPR textiles jurisdiction profile",
        "manifest": {"version": "0.9.0", "issuer_class": "law", "issuer": "ec-espr", "signature": {"signature": "ab01"}},
        "version": "0.9.0",
        "effective_from": "2026-10-18T00:00:00Z"
    });
    assert_eq!(post(base, "/items", &register, None).await.status, 201);

    // Supersede: new version + reason; the old transitions to
    // superseded with a derived window end.
    let supersede = json!({
        "version": "1.0.0",
        "reason": "consolidated edition",
        "effective_from": "2027-10-18T00:00:00Z"
    });
    let resp = post(base, "/items/eu-espr-textiles/versions", &supersede, None).await;
    assert_eq!(resp.status, 201);
    let result = json_of(&resp);
    assert_eq!(result["new_version"]["version"], "1.0.0");
    assert_eq!(result["new_version"]["status"], "valid");
    assert_eq!(result["new_version"]["notes"], "consolidated edition");
    assert_eq!(result["superseded_version"]["version"], "0.9.0");
    assert_eq!(result["superseded_version"]["status"], "superseded");
    assert_eq!(
        result["superseded_version"]["superseded_by_version"],
        "1.0.0"
    );
    assert_eq!(
        result["superseded_version"]["window_end"],
        "2027-10-18T00:00:00Z"
    );
    assert_eq!(result["audit_seq"], 2);

    let at = |when: &str| format!("{base}/items/eu-espr-textiles?at={}", enc(when));

    // Before the item existed: known item, nothing in force.
    let resp = get(&at("2026-06-01T00:00:00Z")).await;
    assert_eq!(resp.status, 200);
    let early = json_of(&resp);
    assert_eq!(early["version"], Value::Null);

    // During the 0.9.0 window.
    let resp = get(&at("2027-06-01T00:00:00Z")).await;
    assert_eq!(resp.status, 200);
    let during = json_of(&resp);
    assert_eq!(during["version"]["version"], "0.9.0");
    assert_eq!(during["version"]["status"], "superseded");
    assert_eq!(during["as_of"], "2027-06-01T00:00:00Z");
    assert_eq!(resp.header("x-as-of").unwrap(), "2027-06-01T00:00:00Z");

    // After the successor took over (half-open window: at the
    // boundary instant the new version rules).
    let resp = get(&at("2027-10-18T00:00:00Z")).await;
    assert_eq!(json_of(&resp)["version"]["version"], "1.0.0");
    let resp = get(&at("2028-01-01T00:00:00Z")).await;
    assert_eq!(json_of(&resp)["version"]["version"], "1.0.0");

    // Current (no `at`): the valid version.
    let resp = get(&format!("{base}/items/eu-espr-textiles")).await;
    assert_eq!(json_of(&resp)["version"]["version"], "1.0.0");

    // History is immutable: both versions are on the item.
    let item = json_of(&resp);
    assert_eq!(item["versions"].as_array().unwrap().len(), 2);

    // Error cases.
    let dupe = json!({"version": "1.0.0", "reason": "again"});
    assert_eq!(
        post(base, "/items/eu-espr-textiles/versions", &dupe, None)
            .await
            .status,
        409
    );
    let no_reason = json!({"version": "2.0.0"});
    assert_eq!(
        post(base, "/items/eu-espr-textiles/versions", &no_reason, None)
            .await
            .status,
        400
    );
    let bad_target = json!({"version": "2.0.0", "reason": "x", "supersede_version": "9.9.9"});
    assert_eq!(
        post(base, "/items/eu-espr-textiles/versions", &bad_target, None)
            .await
            .status,
        400
    );
    // only the valid version can be superseded
    let old_target = json!({"version": "2.0.0", "reason": "x", "supersede_version": "0.9.0"});
    assert_eq!(
        post(base, "/items/eu-espr-textiles/versions", &old_target, None)
            .await
            .status,
        400
    );
    // the new window cannot start before the superseded version's
    let backdated =
        json!({"version": "2.0.0", "reason": "x", "effective_from": "2026-01-01T00:00:00Z"});
    assert_eq!(
        post(base, "/items/eu-espr-textiles/versions", &backdated, None)
            .await
            .status,
        400
    );
    // unknown item
    assert_eq!(
        post(base, "/items/nope/versions", &supersede, None)
            .await
            .status,
        404
    );

    server.stop().await;
}

#[tokio::test]
async fn supersession_chain() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let register = json!({
        "register_id": REGISTER,
        "item_id": "historic-vehicle",
        "class": "profile",
        "definition": "Historic vehicle profile",
        "manifest": {"version": "1.0.0", "issuer_class": "law", "issuer": "ec-espr", "signature": {"signature": "ab01"}},
        "version": "1.0.0",
        "effective_from": "2018-06-01T00:00:00Z"
    });
    assert_eq!(post(base, "/items", &register, None).await.status, 201);
    for (version, from) in [
        ("2.0.0", "2021-06-01T00:00:00Z"),
        ("3.0.0", "2024-06-01T00:00:00Z"),
    ] {
        let resp = post(
            base,
            "/items/historic-vehicle/versions",
            &json!({"version": version, "reason": "edition", "effective_from": from}),
            None,
        )
        .await;
        assert_eq!(resp.status, 201);
    }

    // The whole chain in supersession order.
    let resp = get(&format!("{base}/items/historic-vehicle/supersession")).await;
    assert_eq!(resp.status, 200);
    let chain = json_of(&resp);
    let versions: Vec<&str> = chain["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, vec!["1.0.0", "2.0.0", "3.0.0"]);
    let statuses: Vec<&str> = chain["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, vec!["superseded", "superseded", "valid"]);
    assert_eq!(chain["terminal"]["version"], "3.0.0");
    // derived window ends at each hop
    assert_eq!(chain["chain"][0]["window_end"], "2021-06-01T00:00:00Z");
    assert_eq!(chain["chain"][1]["window_end"], "2024-06-01T00:00:00Z");
    assert!(chain["chain"][2].get("window_end").is_none());

    // From any version.
    let resp = get(&format!(
        "{base}/items/historic-vehicle/supersession?from=2.0.0"
    ))
    .await;
    let from_middle = json_of(&resp);
    assert_eq!(from_middle["chain"].as_array().unwrap().len(), 2);
    assert_eq!(from_middle["terminal"]["version"], "3.0.0");

    // Unknown start version and unknown item.
    assert_eq!(
        get(&format!(
            "{base}/items/historic-vehicle/supersession?from=9.9.9"
        ))
        .await
        .status,
        400
    );
    assert_eq!(
        get(&format!("{base}/items/nope/supersession")).await.status,
        404
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Applicability (retroactive and not)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn applicability_retroactivity_and_windows() {
    let server = spawn_open().await;
    let base = &server.base_url;

    for (id, from) in [
        ("eu-espr-textiles", "2020-01-01T00:00:00Z"),
        ("conflict-minerals", "2020-01-01T00:00:00Z"),
    ] {
        let resp = post(
            base,
            "/items",
            &json!({
                "register_id": REGISTER,
                "item_id": id,
                "class": "profile",
                "definition": "profile",
                "manifest": {"version": "1.0.0", "issuer_class": "law", "issuer": "ec-espr", "signature": {"signature": "ab01"}},
                "version": "1.0.0",
                "effective_from": from
            }),
            None,
        )
        .await;
        assert_eq!(resp.status, 201);
    }

    const SUBJECT: &str = "gtin:06901234000016";
    let query = |at: &str| {
        format!(
            "{base}/applicability?product_type={}&at={}",
            enc(SUBJECT),
            enc(at)
        )
    };

    // Retroactive: applies from its effective_from even though
    // registered now (end-of-waste style re-qualification).
    let retro = json!({
        "profile_id": "eu-espr-textiles",
        "product_type": SUBJECT,
        "effective_from": "1996-01-01T00:00:00Z",
        "retroactive": true
    });
    let resp = post(base, "/applicability", &retro, None).await;
    assert_eq!(resp.status, 201);
    let binding = json_of(&resp);
    assert_eq!(binding["subject"], SUBJECT);
    assert_eq!(binding["profile_item"], "eu-espr-textiles");
    assert_eq!(binding["retroactive"], true);
    assert_eq!(binding["id"], 1);
    assert!(Timestamp::parse(binding["registered_at"].as_str().unwrap()).is_ok());

    // Non-retroactive: cannot impose obligations before the authority
    // declared it (registered_at).
    let forward = json!({
        "profile_id": "conflict-minerals",
        "product_type": SUBJECT,
        "effective_from": "2021-01-01T00:00:00Z",
        "retroactive": false
    });
    assert_eq!(
        post(base, "/applicability", &forward, None).await.status,
        201
    );

    // Bounded window (retroactive, closed by effective_until).
    let bounded = json!({
        "profile_id": "eu-espr-textiles",
        "product_type": SUBJECT,
        "effective_from": "2020-01-01T00:00:00Z",
        "effective_until": "2023-01-01T00:00:00Z",
        "retroactive": true
    });
    assert_eq!(
        post(base, "/applicability", &bounded, None).await.status,
        201
    );

    // 2022: the retroactive open binding and the bounded one; the
    // non-retroactive one is gated by registered_at (now, 2026).
    let resp = get(&query("2022-01-01T00:00:00Z")).await;
    assert_eq!(resp.status, 200);
    let applied = json_of(&resp);
    assert_eq!(applied["product_type"], SUBJECT);
    assert_eq!(applied["as_of"], "2022-01-01T00:00:00Z");
    let entries = applied["applicability"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "retroactive + bounded apply in 2022");
    let profile_versions: Vec<&str> = entries
        .iter()
        .map(|e| e["profile"]["version"]["version"].as_str().unwrap())
        .collect();
    assert!(profile_versions.iter().all(|v| *v == "1.0.0"));

    // 2024: the bounded binding has closed; the non-retroactive one is
    // still before its registered_at.
    let entries = json_of(&get(&query("2024-01-01T00:00:00Z")).await)["applicability"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["binding"]["profile_item"], "eu-espr-textiles");

    // 2027: retroactive open + non-retroactive (past registered_at).
    let entries = json_of(&get(&query("2027-01-01T00:00:00Z")).await)["applicability"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .any(|e| e["binding"]["profile_item"] == "conflict-minerals"));

    // Validation: unknown profile, wrong class, inverted window,
    // missing subject on the query.
    let mut bad = retro.clone();
    bad["profile_id"] = json!("nope");
    assert_eq!(post(base, "/applicability", &bad, None).await.status, 400);
    let mut bad = retro.clone();
    bad["profile_id"] = json!("unit-kwh");
    assert_eq!(post(base, "/applicability", &bad, None).await.status, 400);
    let mut bad = retro.clone();
    bad["effective_until"] = json!("1995-01-01T00:00:00Z");
    assert_eq!(post(base, "/applicability", &bad, None).await.status, 400);
    assert_eq!(get(&format!("{base}/applicability")).await.status, 400);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Admin auth and the mutation audit log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_auth_and_mutation_audit() {
    let server = TestServer::spawn(Config {
        admin_token: Some("s3cret".to_string()),
        ..Config::default()
    })
    .await
    .expect("spawn server");
    let base = &server.base_url;

    let register = json!({
        "register_id": REGISTER,
        "item_id": "jp-meti-electronics",
        "class": "profile",
        "definition": "JP METI electronics profile",
        "manifest": {"version": "1.0.0", "issuer_class": "law", "issuer": "ec-espr", "signature": {"signature": "ab01"}},
        "version": "1.0.0",
        "effective_from": "2026-01-01T00:00:00Z"
    });

    // Mutations are guarded.
    assert_eq!(post(base, "/items", &register, None).await.status, 401);
    assert_eq!(
        post(base, "/items", &register, Some("wrong")).await.status,
        401
    );
    let resp = post(base, "/items", &register, Some("s3cret")).await;
    assert_eq!(resp.status, 201);
    assert_eq!(json_of(&resp)["audit_seq"], 1);

    let resp = post(
        base,
        "/items/jp-meti-electronics/versions",
        &json!({"version": "2.0.0", "reason": "PSE scope update", "effective_from": "2027-01-01T00:00:00Z"}),
        Some("s3cret"),
    )
    .await;
    assert_eq!(resp.status, 201);

    let resp = post(
        base,
        "/applicability",
        &json!({"profile_id": "jp-meti-electronics", "product_type": "gtin:06901234000016", "effective_from": "2026-01-01T00:00:00Z"}),
        Some("s3cret"),
    )
    .await;
    assert_eq!(resp.status, 201);

    // Reads stay public.
    let resp = get(&format!("{base}/items/jp-meti-electronics")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(json_of(&resp)["version"]["version"], "2.0.0");

    // The audit log is admin-only and records every mutation, in
    // order, with monotonic sequence numbers.
    assert_eq!(get(&format!("{base}/admin/log")).await.status, 401);
    let resp = get(&format!("{base}/admin/log?limit=100")).await;
    assert_eq!(resp.status, 401);
    let resp = json_request(
        "GET",
        &format!("{base}/admin/log?limit=100"),
        None,
        Some("s3cret"),
    )
    .await;
    assert_eq!(resp.status, 200);
    let log = json_of(&resp);
    assert_eq!(log["total"], 3);
    let records = log["records"].as_array().unwrap();
    let ops: Vec<&str> = records.iter().map(|r| r["op"].as_str().unwrap()).collect();
    assert_eq!(
        ops,
        vec!["register-item", "supersede-version", "bind-applicability"]
    );
    let seqs: Vec<u64> = records.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    for r in records {
        assert!(Timestamp::parse(r["recorded_at"].as_str().unwrap()).is_ok());
    }
    let supersede = &records[1];
    assert_eq!(supersede["identifier"], "jp-meti-electronics");
    assert_eq!(supersede["superseded_version"], "1.0.0");
    assert_eq!(supersede["prior_status"], "valid");
    assert_eq!(supersede["successor"]["version"], "2.0.0");
    assert_eq!(supersede["successor"]["notes"], "PSE scope update");
    let registration = &records[0];
    assert_eq!(registration["item"]["identifier"], "jp-meti-electronics");
    assert_eq!(registration["item"]["versions"][0]["status"], "valid");

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Subregisters (class-scoped endpoints)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subregisters_are_class_scoped() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // POST /crypto-suites pins the class from the mount point.
    let resp = post(
        base,
        "/crypto-suites",
        &json!({
            "register_id": REGISTER,
            "item_id": "ed25519",
            "definition": "Ed25519 signatures",
            "version": "1.0.0",
            "effective_from": "2026-01-01T00:00:00Z"
        }),
        None,
    )
    .await;
    assert_eq!(resp.status, 201);
    assert_eq!(json_of(&resp)["item_class"], "crypto-suite");

    // An explicit conflicting class is rejected.
    let resp = post(
        base,
        "/crypto-suites",
        &json!({
            "register_id": REGISTER,
            "item_id": "p256",
            "class": "unit",
            "definition": "P-256",
            "version": "1.0.0"
        }),
        None,
    )
    .await;
    assert_eq!(resp.status, 400);

    // Other subregisters.
    for (path, id, class) in [
        ("/units", "unit-kwh", "unit"),
        ("/profiles", "eu-espr-textiles", "profile"),
        ("/trust-anchors", "ta-nist", "trust-anchor"),
        ("/data-elements", "dp-recycled-content", "data-element"),
    ] {
        // Profiles carry their signed manifest (PR-1); the other
        // classes need none.
        let manifest = (class == "profile").then(|| {
            json!({
                "version": "1.0.0",
                "issuer_class": "law",
                "issuer": "ec-espr",
                "signature": {"signature": "ab01"}
            })
        });
        let mut body = json!({
            "register_id": REGISTER,
            "item_id": id,
            "definition": "test item",
            "version": "1.0.0",
            "effective_from": "2026-01-01T00:00:00Z"
        });
        if let (Some(b), Some(m)) = (body.as_object_mut(), manifest) {
            b.insert("manifest".into(), m);
        }
        let resp = post(base, path, &body, None).await;
        assert_eq!(resp.status, 201);
        assert_eq!(json_of(&resp)["item_class"], class);
    }

    // Listing is class-scoped.
    let resp = get(&format!("{base}/crypto-suites")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 1);
    assert_eq!(list["items"][0]["identifier"], "ed25519");

    // The same endpoints work under the subregister mount.
    let resp = get(&format!("{base}/units/unit-kwh")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(json_of(&resp)["item_class"], "unit");
    let resp = post(
        base,
        "/trust-anchors/ta-nist/versions",
        &json!({"version": "2.0.0", "reason": "key rotation", "effective_from": "2027-01-01T00:00:00Z"}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201);
    let resp = get(&format!("{base}/trust-anchors/ta-nist/supersession")).await;
    let chain = json_of(&resp);
    assert_eq!(chain["chain"].as_array().unwrap().len(), 2);
    assert_eq!(chain["terminal"]["version"], "2.0.0");

    // Class scoping hides items of other classes.
    assert_eq!(get(&format!("{base}/units/ed25519")).await.status, 404);
    assert_eq!(
        get(&format!("{base}/crypto-suites/ta-nist")).await.status,
        404
    );

    // The flat endpoints see everything.
    let resp = get(&format!("{base}/items?class=trust-anchor")).await;
    assert_eq!(json_of(&resp)["count"], 1);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Journal persistence across restarts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn journal_replays_state_across_restart() {
    let dir = std::env::temp_dir().join(format!("unidpp-registry-it-{}", std::process::id()));
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir_all(&dir).unwrap();
    let config = Config {
        state_file: Some(path.clone()),
        ..Config::default()
    };

    const SUBJECT: &str = "gtin:06901234000016";
    {
        let server = TestServer::spawn(config.clone()).await.expect("spawn A");
        let base = &server.base_url;
        assert_eq!(
            post(
                base,
                "/items",
                &json!({
                    "register_id": REGISTER,
                    "item_id": "eu-espr-textiles",
                    "class": "profile",
                    "definition": "EU ESPR textiles profile",
                    "manifest": {"version": "0.9.0", "issuer_class": "law", "issuer": "ec-espr", "signature": {"signature": "ab01"}},
                    "version": "0.9.0",
                    "effective_from": "2026-10-18T00:00:00Z"
                }),
                None
            )
            .await
            .status,
            201
        );
        assert_eq!(
            post(
                base,
                "/items/eu-espr-textiles/versions",
                &json!({
                    "version": "1.0.0",
                    "reason": "consolidated edition",
                    "effective_from": "2027-10-18T00:00:00Z"
                }),
                None
            )
            .await
            .status,
            201
        );
        assert_eq!(
            post(
                base,
                "/applicability",
                &json!({
                    "profile_id": "eu-espr-textiles",
                    "product_type": SUBJECT,
                    "effective_from": "1996-01-01T00:00:00Z",
                    "retroactive": true
                }),
                None
            )
            .await
            .status,
            201
        );
        server.stop().await;
    }

    // A fresh server on the same journal replays the audit log.
    let server = TestServer::spawn(config).await.expect("spawn B");
    let base = &server.base_url;
    let resp = get(&format!(
        "{base}/items/eu-espr-textiles?at=2028-01-01T00:00:00Z"
    ))
    .await;
    assert_eq!(resp.status, 200);
    let item = json_of(&resp);
    assert_eq!(item["version"]["version"], "1.0.0");
    assert_eq!(item["versions"].as_array().unwrap().len(), 2);
    assert_eq!(item["versions"][0]["status"], "superseded");
    let resp = get(&format!(
        "{base}/applicability?product_type={}&at=2020-01-01T00:00:00Z",
        enc(SUBJECT)
    ))
    .await;
    assert_eq!(json_of(&resp)["applicability"].as_array().unwrap().len(), 1);
    let log = json_of(&get(&format!("{base}/admin/log")).await);
    assert_eq!(log["total"], 3);
    server.stop().await;

    let _ = std::fs::remove_file(&path);
}
