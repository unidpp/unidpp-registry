//! The contract gates: the committed `openapi.yaml` golden is the
//! served contract, the router serves exactly it, and the discovery
//! document names only contracted operations.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;
#[allow(dead_code)] // shared support: each test binary uses a subset
mod support;
use support::request;
use unidpp_registry::api::{contract_yaml, paths};
use unidpp_registry::model::ItemClass;
use unidpp_registry::{Config, TestServer};

const VERBS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

/// The contract paths with their documented methods.
fn documented() -> BTreeMap<String, Vec<String>> {
    let doc: Value = serde_yaml::from_str(&contract_yaml()).expect("contract parses");
    doc["paths"]
        .as_object()
        .expect("paths object")
        .iter()
        .map(|(path, item)| {
            let methods = VERBS
                .iter()
                .filter(|v| item.get(*v).is_some())
                .map(|v| v.to_string())
                .collect();
            (path.clone(), methods)
        })
        .collect()
}

/// Every path the router serves: the static constants plus the
/// class-generic subregister templates.
fn routed() -> Vec<String> {
    [
        paths::ROOT,
        paths::HEALTHZ,
        paths::ITEMS,
        paths::ITEM,
        paths::ITEM_VERSIONS,
        paths::ITEM_CHAIN,
        paths::APPLICABILITY,
        paths::SERVICES,
        paths::SERVICE,
        paths::SERVICE_VERSIONS,
        paths::SERVICE_CHAIN,
        paths::PROTOCOL_BINDINGS,
        paths::PROTOCOL_BINDING,
        paths::VERIFICATION_MECHANISMS,
        paths::VERIFICATION_MECHANISM,
        paths::ADMIN_LOG,
        paths::ADMIN_SEED,
        paths::PROFILE_MANIFEST_SCHEMA,
        paths::MODELS,
        paths::MODEL,
        paths::MODEL_VALIDATE,
        paths::CROSS_REGISTER_MAPPINGS,
        paths::CROSS_REGISTER_MAPPING,
        paths::CROSS_REGISTER_MAPPING_VERSIONS,
        paths::CROSS_REGISTER_MAPPING_CHAIN,
    ]
    .into_iter()
    .map(str::to_string)
    .chain(paths::SUB_TEMPLATES.iter().map(|p| p.to_string()))
    .collect()
}

/// The first mounted subregister class (concretizes `{class}` for the
/// live probe).
fn a_mounted_class() -> String {
    ItemClass::ALL
        .iter()
        .find(|c| !matches!(c, ItemClass::Model | ItemClass::CrossRegisterMapping))
        .map(|c| c.plural().to_string())
        .expect("a mounted class exists")
}

#[test]
fn the_golden_matches_the_committed_contract() {
    assert_eq!(contract_yaml(), include_str!("../openapi.yaml"));
}

#[test]
#[ignore = "regenerates openapi.yaml after a route change: cargo test --test contract_gates -- --ignored export"]
fn export_golden() {
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"),
        contract_yaml(),
    )
    .expect("golden written");
}

#[test]
fn every_routed_path_is_documented() {
    let doc = documented();
    for path in routed() {
        assert!(doc.contains_key(&path), "routed but undocumented: {path}");
    }
}

#[test]
fn every_documented_path_is_routed() {
    let routed = routed();
    for path in documented().keys() {
        assert!(routed.contains(path), "documented but not routed: {path}");
    }
}

#[test]
fn routes_are_declared_by_constant_not_literal() {
    let flat: String = include_str!("../src/api.rs")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut idx = 0;
    while let Some(pos) = flat[idx..].find(".route(") {
        let abs = idx + pos;
        let after = flat[abs + 7..].trim_start();
        assert!(
            after.starts_with("paths::"),
            "route paths come from the paths:: constants: `{}`",
            &flat[abs..(abs + 60).min(flat.len())]
        );
        idx = abs + 7;
    }
}

/// The `VERB /path` endpoint references embedded in the discovery
/// document must all be contracted operations.
#[tokio::test]
async fn discovery_names_only_contracted_endpoints() {
    let ts = TestServer::spawn(Config::default()).await.expect("server");
    let resp = request(
        "GET",
        &support::Url::parse(&format!("{}/", ts.base_url)).expect("url"),
        &[],
        None,
        Duration::from_secs(5),
    )
    .await
    .expect("discovery answered");
    let doc = resp.body_string();
    ts.stop().await;
    let documented: Vec<String> = documented().into_keys().collect();
    for verb in VERBS.map(str::to_uppercase) {
        let mut rest = doc.as_str();
        while let Some(pos) = rest.find(&verb) {
            let after = &rest[pos + verb.len()..];
            rest = after;
            let Some(path) = after.strip_prefix(" /") else {
                continue;
            };
            let taken: String = path
                .chars()
                .take_while(|c| !matches!(c, ' ' | '"' | '<'))
                .collect();
            let path = taken.split('?').next().unwrap_or("").to_string();
            if path.is_empty() {
                continue;
            }
            assert!(
                documented.contains(&format!("/{path}")),
                "discovery names `{verb} /{path}` — no such operation in the contract"
            );
        }
    }
}

/// The behavioral half: every documented operation answers anything
/// but 405, and every undocumented method on a documented path
/// answers 405 — on the live router.
#[tokio::test]
async fn the_router_serves_the_contract_exactly() {
    let ts = TestServer::spawn(Config::default()).await.expect("server");
    let class = a_mounted_class();
    for (path, methods) in documented() {
        let concrete = path
            .replace("{class}", &class)
            .replace("{id}", "probe-x");
        for verb in VERBS {
            let resp = request(
                &verb.to_uppercase(),
                &support::Url::parse(&format!("{}{concrete}", ts.base_url)).expect("probe url"),
                &[],
                if verb == "get" {
                    None
                } else {
                    Some(b"{}".as_slice())
                },
                Duration::from_secs(5),
            )
            .await
            .expect("probe answered");
            if methods.contains(&verb.to_string()) {
                assert_ne!(
                    resp.status, 405,
                    "{verb} {concrete}: the contract says routed, the router says otherwise"
                );
            } else {
                assert_eq!(
                    resp.status, 405,
                    "{verb} {concrete}: served but not in the contract"
                );
            }
        }
    }
    ts.stop().await;
}
