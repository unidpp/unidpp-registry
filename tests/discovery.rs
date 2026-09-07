//! Integration tests for the discovery registry (v2): signed C3
//! service descriptors, C4 protocol bindings, C5 verification
//! mechanisms, the seed dataset, and the units subregister seeding.
//!
//! The signing helpers construct descriptors signed by the seeded dev
//! operator keyring (same deterministic scheme the server verifies
//! against), so the happy paths exercise real Ed25519 verification —
//! and the failure paths exercise real rejections.

mod support;

use serde_json::{json, Value};
use support::{enc, get, json_of};
use unidpp_registry::{operator_public_key, operator_record, sign_body, Config, TestServer};

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

/// Sign a service-descriptor body with the given operator label and
/// return the full POST body (`{identifier, version, effective_from,
/// body, signature}` — the signature is over the canonical body).
fn signed_service_body(
    operator_label: &str,
    identifier: &str,
    class: &str,
    uri: &str,
    jurisdiction: &str,
    effective_from: &str,
) -> Value {
    let pk = operator_public_key(operator_label);
    let key_id = unidpp_registry::key_id(&pk);
    let op_id = unidpp_registry::operator_id(&pk);
    let mut body = json!({
        "identifier": identifier,
        "operator": operator_record(operator_label),
        "class": class,
        "endpoints": [{"uri": uri, "protocol_binding_ref": "pb-tier-a-binary"}],
        "protocol_binding_ref": "pb-tier-a-binary",
        "jurisdiction": jurisdiction,
        "residency_class": "anywhere",
        "status": "active",
    });
    sign_body(&mut body, operator_label, &op_id, &key_id).expect("sign body");
    json!({
        "identifier": identifier,
        "version": "1.0.0",
        "effective_from": effective_from,
        "body": body,
        "signature": body["signature"].clone(),
    })
}

/// A tampered variant: same shape, but the signature is computed over a
/// different body than the one submitted.
fn tampered_service_body(identifier: &str) -> Value {
    let label = "unidpp-issuer";
    let mut signed = json!({
        "identifier": identifier,
        "operator": operator_record(label),
        "class": "issuer",
        "endpoints": [{"uri": "https://issuer.unidpp.org/", "protocol_binding_ref": "pb-tier-a-binary"}],
        "protocol_binding_ref": "pb-tier-a-binary",
        "jurisdiction": "DE",
        "residency_class": "eu",
        "status": "active",
    });
    let pk = operator_public_key(label);
    sign_body(
        &mut signed,
        label,
        &unidpp_registry::operator_id(&pk),
        &unidpp_registry::key_id(&pk),
    )
    .expect("sign");
    // swap in a different (tampered) body under the original signature
    let mut tampered = signed.clone();
    tampered["jurisdiction"] = json!("CN");
    json!({
        "identifier": identifier,
        "version": "1.0.0",
        "effective_from": "2026-09-01T00:00:00Z",
        "body": tampered,
        "signature": signed["signature"].clone(),
    })
}

// ---------------------------------------------------------------------------
// Signed service descriptors (C3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn services_signed_registration_and_filters() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // Two services from different operators, jurisdictions, classes.
    let de_issuer = signed_service_body(
        "unidpp-issuer",
        "issuer-de-1",
        "issuer",
        "https://issuer-de.unidpp.org/",
        "DE",
        "2026-01-01T00:00:00Z",
    );
    let fr_resolver = signed_service_body(
        "unidpp-resolver",
        "resolver-fr-1",
        "resolver",
        "https://resolver-fr.unidpp.org/",
        "FR",
        "2026-02-01T00:00:00Z",
    );
    let resp = post(base, "/services", &de_issuer, None).await;
    assert_eq!(
        resp.status,
        201,
        "valid signature accepted: {}",
        resp.body_string()
    );
    let created = json_of(&resp);
    assert_eq!(created["identifier"], "issuer-de-1");
    assert_eq!(created["version"]["version"], "1.0.0");
    assert_eq!(created["version"]["status"], "active");
    assert_eq!(created["audit_seq"], 1);

    let resp = post(base, "/services", &fr_resolver, None).await;
    assert_eq!(resp.status, 201);

    // Tampered body under a valid signature: rejected.
    let tampered = tampered_service_body("issuer-evil-1");
    let resp = post(base, "/services", &tampered, None).await;
    assert_eq!(resp.status, 400, "tampered body rejected");

    // Unknown operator (key not in the keyring): rejected.
    let mut unknown = signed_service_body(
        "unidpp-issuer",
        "issuer-unknown-key-1",
        "issuer",
        "https://x.example/",
        "DE",
        "2026-01-01T00:00:00Z",
    );
    // forge an operator block with a random public key; the signature
    // will fail verification because the keyring has no such operator.
    unknown["body"]["operator"]["id"] = json!("op-0000000000000000");
    let resp = post(base, "/services", &unknown, None).await;
    assert_eq!(resp.status, 400, "unknown operator rejected");

    // List with class filter.
    let resp = get(&format!("{base}/services?class=issuer")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 1);
    assert_eq!(list["services"][0]["identifier"], "issuer-de-1");

    // Jurisdiction filter.
    let resp = get(&format!("{base}/services?jurisdiction=FR")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 1);
    assert_eq!(list["services"][0]["identifier"], "resolver-fr-1");

    // Combined filters.
    let resp = get(&format!("{base}/services?class=resolver&jurisdiction=DE")).await;
    assert_eq!(json_of(&resp)["count"], 0);

    // Unknown class filter value is a 400.
    assert_eq!(
        get(&format!("{base}/services?class=nope")).await.status,
        400
    );

    // Single service lookup with as-of semantics: before its window the
    // resolved version is null; the x-as-of header carries the instant.
    let resp = get(&format!(
        "{base}/services/issuer-de-1?at={}",
        enc("2025-06-01T00:00:00Z")
    ))
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("x-as-of").unwrap(), "2025-06-01T00:00:00Z");
    assert_eq!(json_of(&resp)["version"], Value::Null);

    let resp = get(&format!(
        "{base}/services/issuer-de-1?at={}",
        enc("2026-06-01T00:00:00Z")
    ))
    .await;
    assert_eq!(json_of(&resp)["version"]["version"], "1.0.0");

    // Current view without `at`.
    let resp = get(&format!("{base}/services/issuer-de-1")).await;
    let svc = json_of(&resp);
    assert_eq!(svc["version"]["version"], "1.0.0");
    assert_eq!(svc["version"]["body"]["class"], "issuer");
    assert_eq!(svc["version"]["body"]["jurisdiction"], "DE");
    assert_eq!(
        svc["version"]["body"]["endpoints"][0]["uri"],
        "https://issuer-de.unidpp.org/"
    );

    // Duplicate registration conflicts.
    let resp = post(base, "/services", &de_issuer, None).await;
    assert_eq!(resp.status, 409);

    // Unknown service.
    assert_eq!(get(&format!("{base}/services/nope")).await.status, 404);

    // Validation: missing body / signature.
    let mut bad = de_issuer.clone();
    bad["body"] = Value::Null;
    assert_eq!(post(base, "/services", &bad, None).await.status, 400);
    let mut bad = de_issuer.clone();
    bad["identifier"] = json!("issuer-de-2");
    bad["signature"] = Value::Null;
    assert_eq!(post(base, "/services", &bad, None).await.status, 400);

    server.stop().await;
}

#[tokio::test]
async fn services_supersession_and_as_of() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let v1 = signed_service_body(
        "unidpp-trust",
        "trust-unidpp-1",
        "trust",
        "https://trust-v1.unidpp.org/",
        "ZZ",
        "2026-01-01T00:00:00Z",
    );
    assert_eq!(post(base, "/services", &v1, None).await.status, 201);

    // Supersede with a new signed version (different endpoint).
    let label = "unidpp-trust";
    let mut body = json!({
        "identifier": "trust-unidpp-1",
        "operator": operator_record(label),
        "class": "trust",
        "endpoints": [{"uri": "https://trust-v2.unidpp.org/", "protocol_binding_ref": "pb-tier-a-binary"}],
        "protocol_binding_ref": "pb-tier-a-binary",
        "jurisdiction": "ZZ",
        "residency_class": "anywhere",
        "status": "active",
    });
    let pk = operator_public_key(label);
    sign_body(
        &mut body,
        label,
        &unidpp_registry::operator_id(&pk),
        &unidpp_registry::key_id(&pk),
    )
    .expect("sign");
    let supersede = json!({
        "identifier": "trust-unidpp-1",
        "version": "2.0.0",
        "effective_from": "2027-01-01T00:00:00Z",
        "body": body,
        "signature": body["signature"].clone(),
    });
    let resp = post(base, "/services/trust-unidpp-1/versions", &supersede, None).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let result = json_of(&resp);
    assert_eq!(result["new_version"]["version"], "2.0.0");
    assert_eq!(result["superseded_version"]["version"], "1.0.0");
    assert_eq!(result["superseded_version"]["status"], "superseded");
    assert_eq!(
        result["superseded_version"]["window_end"],
        "2027-01-01T00:00:00Z"
    );

    // As-of: 2026 → v1 in force (status superseded, window derived);
    // 2027+ → v2.
    let at = |when: &str| format!("{base}/services/trust-unidpp-1?at={}", enc(when));
    assert_eq!(
        json_of(&get(&at("2026-06-01T00:00:00Z")).await)["version"]["version"],
        "1.0.0"
    );
    assert_eq!(
        json_of(&get(&at("2027-06-01T00:00:00Z")).await)["version"]["version"],
        "2.0.0"
    );
    assert_eq!(
        json_of(&get(&format!("{base}/services/trust-unidpp-1")).await)["version"]["version"],
        "2.0.0"
    );

    // Supersession chain.
    let resp = get(&format!("{base}/services/trust-unidpp-1/supersession")).await;
    let chain = json_of(&resp);
    let versions: Vec<&str> = chain["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, vec!["1.0.0", "2.0.0"]);
    assert_eq!(chain["terminal"]["version"], "2.0.0");

    // Duplicate version number conflicts; unknown service 404s.
    let mut dupe = supersede.clone();
    dupe["version"] = json!("2.0.0");
    dupe["body"]["endpoints"][0]["uri"] = json!("https://trust-v3.unidpp.org/");
    let pk = operator_public_key(label);
    sign_body(
        &mut dupe["body"],
        label,
        &unidpp_registry::operator_id(&pk),
        &unidpp_registry::key_id(&pk),
    )
    .expect("sign dupe");
    dupe["signature"] = dupe["body"]["signature"].clone();
    assert_eq!(
        post(base, "/services/trust-unidpp-1/versions", &dupe, None)
            .await
            .status,
        409
    );
    assert_eq!(
        post(base, "/services/nope/versions", &supersede, None)
            .await
            .status,
        404
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Protocol bindings (C4) and verification mechanisms (C5)
// ---------------------------------------------------------------------------

fn signed_protocol_binding(identifier: &str, grammar_ref: &str) -> Value {
    let label = "unidpp-registry";
    let mut wire = json!({
        "identifier": identifier,
        "description": "test binding",
        "version": "1.0.0",
        "grammar_ref": grammar_ref,
        "media_types": ["application/test+json"],
        "operator": operator_record(label),
    });
    let pk = operator_public_key(label);
    sign_body(
        &mut wire,
        label,
        &unidpp_registry::operator_id(&pk),
        &unidpp_registry::key_id(&pk),
    )
    .expect("sign");
    // The POST endpoint expects {identifier, version, body, signature}
    // where the signature is over the body.
    json!({
        "identifier": identifier,
        "version": "1.0.0",
        "body": wire.clone(),
        "signature": wire["signature"].clone(),
    })
}

fn signed_verification_mechanism(identifier: &str, suite: &str) -> Value {
    let label = "unidpp-registry";
    let mut wire = json!({
        "identifier": identifier,
        "suite": suite,
        "agility_status": "active",
        "trust_framework": "SIGNATIF",
        "trust_list_endpoint": "https://trust.unidpp.org/list",
        "master_list_ref": "https://unidpp.org/spec/signatif/master-list",
        "operator": operator_record(label),
    });
    let pk = operator_public_key(label);
    sign_body(
        &mut wire,
        label,
        &unidpp_registry::operator_id(&pk),
        &unidpp_registry::key_id(&pk),
    )
    .expect("sign");
    json!({
        "identifier": identifier,
        "body": wire.clone(),
        "signature": wire["signature"].clone(),
    })
}

#[tokio::test]
async fn protocol_bindings_and_verification_mechanisms() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // C4: register + list + get.
    let resp = post(
        base,
        "/protocol-bindings",
        &signed_protocol_binding("pb-test-1", "https://example/grammar"),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let created = json_of(&resp);
    assert_eq!(created["identifier"], "pb-test-1");
    assert_eq!(created["binding"]["grammar_ref"], "https://example/grammar");
    assert_eq!(
        created["binding"]["media_types"][0],
        "application/test+json"
    );
    assert_eq!(created["audit_seq"], 1);

    let resp = get(&format!("{base}/protocol-bindings")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 1);
    assert_eq!(list["protocol_bindings"][0]["identifier"], "pb-test-1");

    let resp = get(&format!("{base}/protocol-bindings/pb-test-1")).await;
    assert_eq!(json_of(&resp)["grammar_ref"], "https://example/grammar");

    // Duplicate conflicts; unknown 404.
    assert_eq!(
        post(
            base,
            "/protocol-bindings",
            &signed_protocol_binding("pb-test-1", "https://example/grammar"),
            None
        )
        .await
        .status,
        409
    );
    assert_eq!(
        get(&format!("{base}/protocol-bindings/nope")).await.status,
        404
    );

    // C5: register + list + get.
    let resp = post(
        base,
        "/verification-mechanisms",
        &signed_verification_mechanism("vm-test-1", "SM2-SM3-SM4"),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let created = json_of(&resp);
    assert_eq!(created["identifier"], "vm-test-1");
    assert_eq!(created["mechanism"]["suite"], "SM2-SM3-SM4");
    assert_eq!(created["mechanism"]["agility_status"], "active");
    assert_eq!(created["mechanism"]["trust_framework"], "SIGNATIF");
    assert_eq!(created["audit_seq"], 2);

    let resp = get(&format!("{base}/verification-mechanisms")).await;
    assert_eq!(json_of(&resp)["count"], 1);
    let resp = get(&format!("{base}/verification-mechanisms/vm-test-1")).await;
    assert_eq!(json_of(&resp)["suite"], "SM2-SM3-SM4");
    assert_eq!(
        post(
            base,
            "/verification-mechanisms",
            &signed_verification_mechanism("vm-test-1", "SM2-SM3-SM4"),
            None
        )
        .await
        .status,
        409
    );
    assert_eq!(
        get(&format!("{base}/verification-mechanisms/nope"))
            .await
            .status,
        404
    );

    // Missing required fields.
    let mut bad = signed_protocol_binding("pb-bad-1", "https://example/g");
    bad["body"]["grammar_ref"] = Value::Null;
    assert_eq!(
        post(base, "/protocol-bindings", &bad, None).await.status,
        400
    );
    let mut bad = signed_verification_mechanism("vm-bad-1", "x");
    bad["body"]["suite"] = Value::Null;
    assert_eq!(
        post(base, "/verification-mechanisms", &bad, None)
            .await
            .status,
        400
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Seed dataset + units subregister (C1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn seed_dataset_populates_discovery_and_units() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // Seed.
    let resp = post(base, "/admin/seed", &json!({}), None).await;
    assert_eq!(resp.status, 200, "{}", resp.body_string());
    let report = json_of(&resp);
    assert_eq!(report["status"], "seeded");
    assert_eq!(report["counts"]["services"], 8);
    assert_eq!(report["counts"]["protocol_bindings"], 5);
    assert_eq!(report["counts"]["verification_mechanisms"], 3);
    assert_eq!(report["counts"]["units"], 10);

    // Idempotent.
    let resp = post(base, "/admin/seed", &json!({}), None).await;
    assert_eq!(json_of(&resp)["status"], "already-seeded");

    // Services: all classes covered, filters work, identifiers are the
    // operator-label form (no doubled prefix).
    let resp = get(&format!("{base}/services")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 8);
    let svc_ids: Vec<&str> = list["services"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["identifier"].as_str().unwrap())
        .collect();
    for expected in [
        "unidpp-registry-v1",
        "unidpp-issuer-v1",
        "unidpp-resolver-v1",
        "unidpp-trust-v1",
        "unidpp-log-v1",
        "unidpp-archive-v1",
        "unidpp-cli-verifier-v1",
        "unidpp-edge-v1",
    ] {
        assert!(
            svc_ids.contains(&expected),
            "seed service {expected} (got {svc_ids:?})"
        );
    }
    for class in [
        "registry", "issuer", "resolver", "trust", "log", "archive", "edge",
    ] {
        let resp = get(&format!("{base}/services?class={class}")).await;
        let filtered = json_of(&resp);
        assert!(
            filtered["count"].as_u64().unwrap() >= 1,
            "class {class} has at least one service"
        );
    }

    // Protocol bindings: the five seed entries.
    let resp = get(&format!("{base}/protocol-bindings")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 5);
    let ids: Vec<&str> = list["protocol_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["identifier"].as_str().unwrap())
        .collect();
    for expected in [
        "pb-en18222-rest",
        "pb-gs1-digital-link",
        "pb-gbt-33993",
        "pb-untp-vc",
        "pb-tier-a-binary",
    ] {
        assert!(ids.contains(&expected), "seed protocol binding {expected}");
    }
    let en18222 = &list["protocol_bindings"][0];
    assert_eq!(
        en18222["grammar_ref"],
        "https://standards.cen-cenelec.eu/EN-18222"
    );
    assert_eq!(en18222["media_types"][0], "application/vnd.en18222+json");

    // Verification mechanisms: SM2 / FIPS / ML-DSA.
    let resp = get(&format!("{base}/verification-mechanisms")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 3);
    let ids: Vec<&str> = list["verification_mechanisms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["identifier"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"vm-sm2-sm3-sm4"));
    assert!(ids.contains(&"vm-fips"));
    assert!(ids.contains(&"vm-ml-dsa"));
    let ml_dsa = list["verification_mechanisms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["identifier"] == "vm-ml-dsa")
        .unwrap();
    assert_eq!(ml_dsa["agility_status"], "migration");

    // Units: SI base + kWh/MJ/J, ISO 80000 citations in the manifest.
    let resp = get(&format!("{base}/units")).await;
    let list = json_of(&resp);
    assert_eq!(list["count"], 10);
    let ids: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["identifier"].as_str().unwrap())
        .collect();
    for expected in [
        "unit-m", "unit-kg", "unit-s", "unit-a", "unit-k", "unit-mol", "unit-cd", "unit-kwh",
        "unit-mj", "unit-j",
    ] {
        assert!(ids.contains(&expected), "seed unit {expected}");
    }
    let resp = get(&format!("{base}/units/unit-kwh")).await;
    let kwh = json_of(&resp);
    assert_eq!(kwh["title"], "kilowatt hour");
    assert!(kwh["manifest"]["iso_80000_citation"]
        .as_str()
        .unwrap()
        .starts_with("ISO 80000-4"));
    assert_eq!(kwh["submitting_organization"], "ISO/TC 12");
    assert_eq!(kwh["version"]["version"], "1.0.0");

    // Everything is in the audit log (seed is journaled like any other
    // mutation).
    let log = json_of(&get(&format!("{base}/admin/log")).await);
    assert_eq!(log["total"], 8 + 5 + 3 + 10);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Journal replay of discovery descriptors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_journal_replays_across_restart() {
    let dir = std::env::temp_dir().join(format!("unidpp-registry-disc-it-{}", std::process::id()));
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
        let svc = signed_service_body(
            "unidpp-log",
            "log-unidpp-1",
            "log",
            "https://log.unidpp.org/",
            "ZZ",
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(post(base, "/services", &svc, None).await.status, 201);
        assert_eq!(
            post(
                base,
                "/protocol-bindings",
                &signed_protocol_binding("pb-jr-1", "https://example/g"),
                None
            )
            .await
            .status,
            201
        );
        assert_eq!(
            post(
                base,
                "/verification-mechanisms",
                &signed_verification_mechanism("vm-jr-1", "FIPS 186-4"),
                None
            )
            .await
            .status,
            201
        );
        server.stop().await;
    }

    // Replaying re-applies the descriptors; signatures are not
    // re-verified (they were verified at intake).
    let server = TestServer::spawn(config).await.expect("spawn B");
    let base = &server.base_url;
    let resp = get(&format!("{base}/services/log-unidpp-1")).await;
    assert_eq!(resp.status, 200);
    let svc = json_of(&resp);
    assert_eq!(svc["version"]["version"], "1.0.0");
    assert_eq!(svc["version"]["body"]["class"], "log");
    assert_eq!(
        json_of(&get(&format!("{base}/protocol-bindings")).await)["count"],
        1
    );
    assert_eq!(
        json_of(&get(&format!("{base}/verification-mechanisms")).await)["count"],
        1
    );
    let log = json_of(&get(&format!("{base}/admin/log")).await);
    assert_eq!(log["total"], 3);
    let ops: Vec<&str> = log["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["op"].as_str().unwrap())
        .collect();
    assert_eq!(
        ops,
        vec![
            "register-service",
            "register-protocol-binding",
            "register-verification-mechanism"
        ]
    );
    server.stop().await;

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Admin auth on discovery endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_endpoints_require_admin_when_configured() {
    let server = TestServer::spawn(Config {
        admin_token: Some("s3cret".to_string()),
        ..Config::default()
    })
    .await
    .expect("spawn server");
    let base = &server.base_url;

    let svc = signed_service_body(
        "unidpp-issuer",
        "issuer-auth-1",
        "issuer",
        "https://issuer.unidpp.org/",
        "DE",
        "2026-01-01T00:00:00Z",
    );
    // Unauthenticated mutation is denied.
    assert_eq!(post(base, "/services", &svc, None).await.status, 401);
    assert_eq!(
        post(
            base,
            "/protocol-bindings",
            &signed_protocol_binding("pb-auth-1", "https://g/"),
            None
        )
        .await
        .status,
        401
    );
    assert_eq!(
        post(
            base,
            "/verification-mechanisms",
            &signed_verification_mechanism("vm-auth-1", "SM2-SM3-SM4"),
            None
        )
        .await
        .status,
        401
    );
    assert_eq!(
        post(base, "/admin/seed", &json!({}), None).await.status,
        401
    );

    // Authenticated works.
    assert_eq!(
        post(base, "/services", &svc, Some("s3cret")).await.status,
        201
    );

    // Reads stay public.
    assert_eq!(get(&format!("{base}/services")).await.status, 200);
    assert_eq!(get(&format!("{base}/protocol-bindings")).await.status, 200);
    assert_eq!(
        get(&format!("{base}/verification-mechanisms")).await.status,
        200
    );

    server.stop().await;
}
