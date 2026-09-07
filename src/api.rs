//! HTTP surface: axum router, handlers, `Config`, `TestServer`.
//!
//! Reads are public (consumers resolve references); mutations require
//! a Bearer token when `UNIDPP_REGISTRY_ADMIN_TOKEN` is set (open in
//! dev mode, mirroring the resolver). Every response is as-of stamped
//! (`x-as-of` header plus an `as_of` body field on JSON documents;
//! point-in-time queries take `?at=`, with `asof` accepted as an
//! alias). Every mutation is appended to the audit log
//! (`GET /admin/log`) and, when `UNIDPP_REGISTRY_STATE_FILE` is set,
//! journaled as JSONL and replayed on start.
//!
//! Subregisters are item classes mounted at their plural names
//! (`/data-elements`, `/profiles`, `/crypto-suites`, `/transforms`,
//! `/trust-anchors`, `/units`, `/cross-register-mappings`) with the
//! same endpoints, class-scoped. Two classes have dedicated
//! surfaces: `/models` (EXPRESS deposits with content hash and
//! expressir validation) and `/schemas/profile-manifest` (the
//! generated manifest JSON Schema).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;

use crate::clock;
use crate::discovery::{
    key_id as operator_key_id, operator_id as operator_id_of, operator_public_key, operator_record,
    parse_protocol_body, parse_service_body, parse_verification_body, sign_body, OperatorKeyring,
    ProtocolBinding, ServiceClass, ServiceDescriptor, ServiceStatus, ServiceVersion,
    SignatureValue, VerificationMechanism,
};
use crate::express::{self, ValidationRecord};
use crate::intake::{self, IntakeContext, IntakeError, IntakeWarning};
use crate::manifest;
use crate::mapping;
use crate::model::{ApplicabilityBinding, Item, ItemClass, ItemVersion, Status};
use crate::store::{Store, StoreError};
use crate::time::Timestamp;

/// Deployment configuration (environment-driven; see `main.rs`).
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    /// Bearer token guarding mutations and `/admin/*`; `None` = open
    /// (dev mode).
    pub admin_token: Option<String>,
    /// Optional JSONL journal file (append-only audit log, replayed on
    /// start).
    pub state_file: Option<PathBuf>,
    /// When true, `POST /admin/seed` populates the seed dataset on
    /// demand (UniDPP's own services + EN 18222 / GS1 DL / GB/T 33993 /
    /// UNTP / Tier-A binary protocol bindings + SM2 / FIPS / ML-DSA
    /// verification mechanisms + SI base + kWh / MJ / J units with ISO
    /// 80000 citations). Defaults to `true`.
    pub seed_on_demand: bool,
    /// When true, the serving binary deposits the vendored UniDPP
    /// EXPRESS core schema as the first `model` item (item 58's
    /// first deposit). Defaults to `true`; disabled with
    /// `UNIDPP_REGISTRY_SEED_EXPRESS=0`.
    pub seed_express: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8090".parse().unwrap(),
            admin_token: None,
            state_file: None,
            seed_on_demand: true,
            seed_express: true,
        }
    }
}

impl Config {
    pub fn from_env() -> Config {
        let mut c = Config::default();
        if let Ok(bind) = std::env::var("UNIDPP_REGISTRY_BIND") {
            match bind.parse() {
                Ok(addr) => c.bind = addr,
                Err(_) => eprintln!("unidpp-registry: ignoring bad UNIDPP_REGISTRY_BIND `{bind}`"),
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_REGISTRY_ADMIN_TOKEN") {
            if !token.is_empty() {
                c.admin_token = Some(token);
            }
        }
        if let Ok(path) = std::env::var("UNIDPP_REGISTRY_STATE_FILE") {
            if !path.is_empty() {
                c.state_file = Some(PathBuf::from(path));
            }
        }
        if let Ok(s) = std::env::var("UNIDPP_REGISTRY_SEED_ON_DEMAND") {
            c.seed_on_demand = !matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            );
        }
        if let Ok(s) = std::env::var("UNIDPP_REGISTRY_SEED_EXPRESS") {
            c.seed_express = !matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            );
        }
        c
    }
}

/// Shared application state.
pub struct AppState {
    pub config: Config,
    pub store: Mutex<Store>,
    /// The discovery-layer operator keyring (seeded dev keyring for
    /// self-hosted deployments; production replaces by an external trust
    /// list). Mutex-bounded because a future reload path will mutate it.
    pub keyring: Mutex<OperatorKeyring>,
    /// `true` once `POST /admin/seed` has populated the seed dataset;
    /// prevents double-seeding on journal replay.
    pub seeded: Mutex<bool>,
}

impl AppState {
    pub fn new(config: Config) -> std::io::Result<AppState> {
        let store = Store::open(config.state_file.as_deref())?;
        Ok(AppState {
            config,
            store: Mutex::new(store),
            keyring: Mutex::new(OperatorKeyring::seeded_dev()),
            seeded: Mutex::new(false),
        })
    }
}

// ---------------------------------------------------------------------------
// Response helpers (every response is as-of stamped)
// ---------------------------------------------------------------------------

fn build_response(status: StatusCode, headers: Vec<(String, String)>, body: String) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

fn stamped(status: StatusCode, body: &Value, as_of: Timestamp) -> Response {
    build_response(
        status,
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-as-of".into(), as_of.to_string()),
        ],
        serde_json::to_string_pretty(body).unwrap(),
    )
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    stamped(status, &json!({ "error": msg }), Timestamp::now())
}

fn bad_request(msg: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, msg)
}

fn conflict(msg: &str) -> Response {
    error_response(StatusCode::CONFLICT, msg)
}

fn not_found(msg: &str) -> Response {
    error_response(StatusCode::NOT_FOUND, msg)
}

fn unauthorized() -> Response {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized")
}

fn store_error(e: StoreError) -> Response {
    match e {
        StoreError::Conflict(m) => conflict(&m),
        StoreError::Invalid(m) => bad_request(&m),
    }
}

/// Structured intake rejection: the failing check and the precise
/// field paths, machine-readable.
fn intake_error_response(errors: &[IntakeError]) -> Response {
    let list: Vec<serde_json::Value> = errors
        .iter()
        .map(|e| json!({"check": e.check, "path": e.path, "message": e.message}))
        .collect();
    let msg = match errors.first() {
        Some(e) => format!("{} rejected the item: {}", e.check, e.message),
        None => "intake validation failed".to_string(),
    };
    stamped(
        StatusCode::BAD_REQUEST,
        &json!({"error": msg, "errors": list}),
        Timestamp::now(),
    )
}

/// Runs the intake validator chain against the store (read-only
/// borrows; integrity checks look, they never mutate).
fn run_intake_checks(
    store: &Store,
    item: &Item,
    strict: bool,
) -> Result<Vec<IntakeWarning>, Response> {
    let ctx = IntakeContext { store, strict };
    intake::run(&intake::default_chain(), item, &ctx).map_err(|e| intake_error_response(&e))
}

fn warnings_json(warnings: &[IntakeWarning]) -> Option<serde_json::Value> {
    (!warnings.is_empty()).then(|| {
        json!(warnings
            .iter()
            .map(|w| json!({"check": w.check, "path": w.path, "message": w.message}))
            .collect::<Vec<_>>())
    })
}

// ---------------------------------------------------------------------------
// Body/query parsing
// ---------------------------------------------------------------------------

fn parse_body(body: &str) -> Result<Value, Response> {
    serde_json::from_str(body).map_err(|e| bad_request(&format!("invalid JSON body: {e}")))
}

fn req_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, Response> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| bad_request(&format!("`{key}` is required")))
}

fn opt_str(v: &Value, key: &str) -> Result<Option<String>, Response> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
        Some(_) => Err(bad_request(&format!("`{key}` must be a non-empty string"))),
    }
}

fn opt_ts(v: &Value, key: &str) -> Result<Option<Timestamp>, Response> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Timestamp::parse(s)
            .map(Some)
            .map_err(|e| bad_request(&format!("`{key}`: {e}"))),
        Some(_) => Err(bad_request(&format!("`{key}` must be an RFC 3339 string"))),
    }
}

fn opt_bool(v: &Value, key: &str) -> Result<Option<bool>, Response> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(bad_request(&format!("`{key}` must be a boolean"))),
    }
}

fn opt_object(v: &Value, key: &str) -> Result<Option<Value>, Response> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(o @ Value::Object(_)) => Ok(Some(o.clone())),
        Some(_) => Err(bad_request(&format!("`{key}` must be an object"))),
    }
}

/// The item definition text. The 19135 name/definition slot is stored
/// as the item title (Ruby `Item#title`); requests name it
/// `definition` (with `title` accepted as an alias).
fn body_title(v: &Value) -> Result<String, Response> {
    match v.get("definition").or_else(|| v.get("title")) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        Some(_) => Err(bad_request("`definition` must be a non-empty string")),
        None => Err(bad_request("`definition` is required")),
    }
}

fn body_class(v: &Value, scope: Option<ItemClass>) -> Result<ItemClass, Response> {
    let given = match v.get("class") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s),
        Some(_) => return Err(bad_request("`class` must be a string")),
    };
    match scope {
        Some(fixed) => {
            if let Some(s) = given {
                let parsed = ItemClass::parse(s)
                    .ok_or_else(|| bad_request(&format!("unknown item class `{s}`")))?;
                if parsed != fixed {
                    return Err(bad_request(&format!(
                        "class `{s}` does not match subregister `{}`",
                        fixed.plural()
                    )));
                }
            }
            Ok(fixed)
        }
        None => match given {
            Some(s) => ItemClass::parse(s).ok_or_else(|| {
                bad_request(&format!(
                    "unknown item class `{s}` (expected one of {})",
                    ItemClass::help()
                ))
            }),
            None => Err(bad_request("`class` is required")),
        },
    }
}

/// Path-segment-safe identifier or version token.
fn validate_token(s: &str, field: &str) -> Result<(), Response> {
    if s.is_empty() || s.contains('/') || s.chars().any(char::is_whitespace) || s.len() > 256 {
        return Err(bad_request(&format!(
            "`{field}` must be 1-256 characters without `/` or whitespace"
        )));
    }
    Ok(())
}

/// The point-in-time query instant: `None` (absent `at`/`asof`) means
/// "the current registered state", not "in force at wall-clock now".
fn parse_at(params: &HashMap<String, String>) -> Result<Option<Timestamp>, Response> {
    let raw = params
        .get("at")
        .or_else(|| params.get("asof"))
        .map(String::as_str);
    match raw {
        None | Some("") => Ok(None),
        Some(s) => Timestamp::parse(s)
            .map(Some)
            .map_err(|e| bad_request(&format!("invalid `at` parameter: {e}"))),
    }
}

fn opt_query(params: &HashMap<String, String>, key: &str) -> Option<String> {
    params
        .get(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn require_admin(app: &AppState, headers: &HeaderMap) -> Option<Response> {
    let token = app.config.admin_token.as_ref()?;
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if got == Some(token.as_str()) {
        None
    } else {
        Some(unauthorized())
    }
}

// ---------------------------------------------------------------------------
// Item views
// ---------------------------------------------------------------------------

/// The version this query resolves to: with an explicit `at`, the
/// version in force at that instant (point-in-time registry state,
/// null when nothing was in force); without one, the current
/// registered version (Ruby `Client#version_of` default — latest
/// valid, regardless of whether its window has started yet).
fn version_json(item: &Item, at: Option<Timestamp>) -> Value {
    match at {
        Some(t) => item
            .in_force_at(t)
            .map(|v| v.to_json(item.window_until(v)))
            .unwrap_or(Value::Null),
        None => item
            .current_version()
            .map(|v| v.to_json(item.window_until(v)))
            .unwrap_or(Value::Null),
    }
}

/// Compact item view (applicability resolution).
fn item_summary(item: &Item, at: Option<Timestamp>) -> Value {
    let mut m = Map::new();
    m.insert("identifier".into(), json!(item.identifier));
    m.insert("register".into(), json!(item.register));
    m.insert("item_class".into(), json!(item.item_class.as_str()));
    m.insert("title".into(), json!(item.title));
    if let Some(s) = &item.submitting_organization {
        m.insert("submitting_organization".into(), json!(s));
    }
    m.insert("version".into(), version_json(item, at));
    Value::Object(m)
}

/// Full item view (Ruby `Item` JSON shape) plus the resolved version
/// and the as-of stamp.
fn item_view(item: &Item, at: Option<Timestamp>, as_of: Timestamp) -> Value {
    let mut v = item.to_json();
    if let Some(m) = v.as_object_mut() {
        m.insert("version".into(), version_json(item, at));
        m.insert("as_of".into(), json!(as_of.to_string()));
    }
    v
}

fn find_item<'a>(
    store: &'a Store,
    identifier: &str,
    scope: Option<ItemClass>,
    register: Option<&str>,
) -> Option<&'a Item> {
    store
        .item(identifier)
        .filter(|i| scope.map_or(true, |c| i.item_class == c))
        .filter(|i| register.map_or(true, |r| i.register == r))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn discovery() -> Result<Response, Response> {
    let mut subregisters = Map::new();
    for class in ItemClass::ALL {
        subregisters.insert(
            class.plural().to_string(),
            json!({"class": class.as_str(), "path": format!("/{}", class.plural())}),
        );
    }
    let doc = json!({
        "service": "unidpp-registry",
        "description": "UniDPP ISO 19135 register service: item registration, version supersession, point-in-time resolution, applicability bindings, and the discovery registry (C3 services, C4 protocol bindings, C5 verification mechanisms)",
        "endpoints": {
            "register_item": "POST /items",
            "list_items": "GET /items?class=&register=&at=",
            "item_as_of": "GET /items/{id}?at=",
            "supersede": "POST /items/{id}/versions",
            "supersession_chain": "GET /items/{id}/supersession?from=",
            "bind_applicability": "POST /applicability",
            "applicability_as_of": "GET /applicability?product_type=&at=",
            "register_service": "POST /services",
            "list_services": "GET /services?class=&jurisdiction=&at=",
            "service_as_of": "GET /services/{id}?at=",
            "supersede_service": "POST /services/{id}/versions",
            "service_supersession": "GET /services/{id}/supersession?from=",
            "register_protocol_binding": "POST /protocol-bindings",
            "list_protocol_bindings": "GET /protocol-bindings",
            "protocol_binding": "GET /protocol-bindings/{id}",
            "register_verification_mechanism": "POST /verification-mechanisms",
            "list_verification_mechanisms": "GET /verification-mechanisms",
            "verification_mechanism": "GET /verification-mechanisms/{id}",
            "profile_manifest_schema": "GET /schemas/profile-manifest",
            "deposit_model": "POST /models (EXPRESS source + metadata; content hash + expressir validation)",
            "list_models": "GET /models?register=&at=",
            "model_as_of": "GET /models/{id}?at=&hash= (hash-pinned retrieval)",
            "validate_model": "POST /models/{id}/validate",
            "list_cross_register_mappings": "GET /cross-register-mappings?item=&source=&target=&register=&at=",
            "applicability_subject_facts": "GET /applicability?product_type=&at=&subject_facts=<json> (or POST with {product_type, at, subject_facts}) — evaluates clock predicates",
            "audit_log": "GET /admin/log?limit=&offset=",
            "seed": "POST /admin/seed",
            "health": "GET /healthz"
        },
        "item_classes": ItemClass::ALL.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        "statuses": Status::VALUES.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "service_classes": ServiceClass::ALL.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        "service_statuses": ["active", "superseded", "suspended", "succeeded"],
        "subregisters": Value::Object(subregisters),
        "as_of": {
            "query_parameter": "at (alias: asof)",
            "response_header": "x-as-of"
        },
        "discovery": {
            "service_descriptor_signature": "Ed25519 over canonical-JSON of body (signature block excluded); operator id is content-derived from the public key",
            "operator_keyring": "seeded dev keyring: unidpp-{registry,issuer,resolver,trust,log,archive,cli-verifier,edge}; loaded at startup; signatures are verified at intake only (replay re-applies the stored record)"
        },
        "intake_checks": ["profile-manifest-schema", "profile-satisfiability", "cross-register-mapping-integrity"],
        "model_validation": "expressir (gem install expressir; `expressir validate load` run as a subprocess); deposits without expressir on PATH are stored with validation.status = pending",
        "auth": "mutations require a Bearer token when UNIDPP_REGISTRY_ADMIN_TOKEN is set"
    });
    Ok(stamped(StatusCode::OK, &doc, Timestamp::now()))
}

async fn healthz() -> Result<Response, Response> {
    Ok(build_response(
        StatusCode::OK,
        vec![
            ("content-type".into(), "text/plain".into()),
            ("x-as-of".into(), Timestamp::now().to_string()),
        ],
        "ok".into(),
    ))
}

/// POST /items — register a new 19135 item with its first version
/// (`{register_id, item_id, class, definition, version, status: valid}`).
async fn create_item(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
    scope: Option<ItemClass>,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let register = req_str(&v, "register_id")?.trim().to_string();
    let identifier = req_str(&v, "item_id")?.trim().to_string();
    validate_token(&identifier, "item_id")?;
    let item_class = body_class(&v, scope)?;
    if item_class == ItemClass::Model {
        return Err(bad_request(
            "model items are deposited through POST /models (EXPRESS source + content hash + expressir validation)",
        ));
    }
    let strict = opt_bool(&v, "strict")?.unwrap_or(true);
    let title = body_title(&v)?;
    let submitting_organization = opt_str(&v, "submitting_organization")?;
    let version_number = req_str(&v, "version")?.trim().to_string();
    validate_token(&version_number, "version")?;
    let status = match v.get("status") {
        None | Some(Value::Null) => Status::Valid,
        Some(Value::String(s)) => Status::parse(s).ok_or_else(|| {
            bad_request(&format!(
                "invalid `status` `{s}` (expected one of {})",
                Status::VALUES
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?,
        Some(_) => return Err(bad_request("`status` must be a string")),
    };
    if status != Status::Valid {
        return Err(bad_request(
            "a new item must be registered with status `valid`; supersession happens through POST /items/{id}/versions",
        ));
    }
    let now = Timestamp::now();
    let effective_from = opt_ts(&v, "effective_from")?.unwrap_or(now);
    let effective_until = opt_ts(&v, "effective_until")?;
    if let Some(until) = effective_until {
        if until <= effective_from {
            return Err(bad_request(
                "`effective_until` must be after `effective_from`",
            ));
        }
    }
    let manifest = opt_object(&v, "manifest")?;
    let item = Item {
        identifier,
        register,
        item_class,
        title,
        submitting_organization,
        versions: vec![ItemVersion {
            version: version_number,
            status,
            effective_from: Some(effective_from),
            effective_until,
            registered_at: Some(now),
            superseded_by_version: None,
            notes: None,
        }],
        manifest,
    };
    if !item.manifest_version_pinned() {
        return Err(bad_request(
            "manifest `version` must be pinned to a registered version of the item",
        ));
    }
    let (audit_seq, warnings) = {
        let mut store = app.store.lock().expect("store poisoned");
        let warnings = run_intake_checks(&store, &item, strict)?;
        let seq = store.register_item(item.clone()).map_err(store_error)?.seq;
        (seq, warnings)
    };
    let mut body = item_view(&item, None, now);
    if let Some(m) = body.as_object_mut() {
        m.insert("audit_seq".into(), json!(audit_seq));
        if let Some(w) = warnings_json(&warnings) {
            m.insert("warnings".into(), w);
        }
    }
    Ok(stamped(StatusCode::CREATED, &body, now))
}

/// GET /items — list items (optionally class-/register-scoped), each
/// with the version in force at `at`.
async fn list_items(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    scope: Option<ItemClass>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let class = match scope {
        Some(fixed) => Some(fixed),
        None => match opt_query(&params, "class") {
            None => None,
            Some(s) => Some(ItemClass::parse(&s).ok_or_else(|| {
                bad_request(&format!(
                    "unknown item class `{s}` (expected one of {})",
                    ItemClass::help()
                ))
            })?),
        },
    };
    let register = opt_query(&params, "register");
    let items = {
        let store = app.store.lock().expect("store poisoned");
        store
            .items_filtered(class, register.as_deref())
            .iter()
            .map(|item| item_summary(item, at))
            .collect::<Vec<_>>()
    };
    Ok(stamped(
        StatusCode::OK,
        &json!({"as_of": as_of.to_string(), "count": items.len(), "items": items}),
        as_of,
    ))
}

/// GET /items/{id} — the item with the version in force at `at`
/// (point-in-time registry state; `version` is null before the item's
/// first effective window).
async fn get_item(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(identifier): Path<String>,
    scope: Option<ItemClass>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let register = opt_query(&params, "register");
    let found = {
        let store = app.store.lock().expect("store poisoned");
        find_item(&store, &identifier, scope, register.as_deref()).cloned()
    };
    let Some(item) = found else {
        return Err(not_found(&format!("no registry item `{identifier}`")));
    };
    Ok(stamped(StatusCode::OK, &item_view(&item, at, as_of), as_of))
}

/// POST /items/{id}/versions — supersede: register a new version with
/// a reason; the old version transitions to `superseded` with a
/// successor link (deriving its window end).
async fn supersede_item(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Path(identifier): Path<String>,
    body: String,
    scope: Option<ItemClass>,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let register = opt_query(&params, "register");
    let now = Timestamp::now();
    let version_number = req_str(&v, "version")?.trim().to_string();
    validate_token(&version_number, "version")?;
    let reason = req_str(&v, "reason")?.trim().to_string();
    let effective_from = opt_ts(&v, "effective_from")?.unwrap_or(now);
    let effective_until = opt_ts(&v, "effective_until")?;
    if let Some(until) = effective_until {
        if until <= effective_from {
            return Err(bad_request(
                "`effective_until` must be after `effective_from`",
            ));
        }
    }
    let strict = opt_bool(&v, "strict")?.unwrap_or(true);
    let manifest = opt_object(&v, "manifest")?;
    let successor = ItemVersion {
        version: version_number.clone(),
        status: Status::Valid,
        effective_from: Some(effective_from),
        effective_until,
        registered_at: Some(now),
        superseded_by_version: None,
        notes: Some(reason.clone()),
    };
    let outcome = {
        let mut store = app.store.lock().expect("store poisoned");
        let item = find_item(&store, &identifier, scope, register.as_deref())
            .ok_or_else(|| not_found(&format!("no registry item `{identifier}`")))?
            .clone();
        // the effective manifest (new, or carried over) is validated
        // like an intake — the class checks pick the item up by
        // class, not by endpoint
        let mut candidate = item.clone();
        if manifest.is_some() {
            candidate.manifest = manifest.clone();
        }
        let warnings = run_intake_checks(&store, &candidate, strict)?;
        if let Some(pinned) = manifest
            .as_ref()
            .and_then(|m| m.get("version"))
            .and_then(Value::as_str)
        {
            if pinned != version_number && item.version(pinned).is_none() {
                return Err(bad_request(&format!(
                    "manifest `version` `{pinned}` is not a registered version of `{identifier}`"
                )));
            }
        }
        let target = match opt_str(&v, "supersede_version")? {
            Some(explicit) => explicit,
            None => match item.current_version() {
                Some(current) if current.status == Status::Valid => current.version.clone(),
                _ => {
                    return Err(bad_request(&format!(
                        "item `{identifier}` has no valid version to supersede"
                    )))
                }
            },
        };
        let rec = store
            .supersede(&identifier, &target, successor, manifest)
            .map_err(store_error)?;
        let after = find_item(&store, &identifier, scope, register.as_deref())
            .cloned()
            .expect("item exists after supersede");
        (rec.seq, after, target, warnings)
    };
    let (audit_seq, after, target, warnings) = outcome;
    let new_version = after
        .version(&version_number)
        .expect("successor registered");
    let old_version = after.version(&target).expect("target retained");
    let mut body = json!({
        "identifier": identifier,
        "new_version": new_version.to_json(after.window_until(new_version)),
        "superseded_version": old_version.to_json(after.window_until(old_version)),
        "item": after.to_json(),
        "reason": reason,
        "audit_seq": audit_seq,
        "as_of": now.to_string(),
    });
    if let Some(w) = warnings_json(&warnings) {
        if let Some(m) = body.as_object_mut() {
            m.insert("warnings".into(), w);
        }
    }
    Ok(stamped(StatusCode::CREATED, &body, now))
}

/// GET /items/{id}/supersession — the supersession chain.
async fn item_chain(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(identifier): Path<String>,
    scope: Option<ItemClass>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let register = opt_query(&params, "register");
    let from = opt_query(&params, "from");
    let (chain, terminal) = {
        let store = app.store.lock().expect("store poisoned");
        let item = find_item(&store, &identifier, scope, register.as_deref())
            .ok_or_else(|| not_found(&format!("no registry item `{identifier}`")))?;
        let chain = item
            .supersession_chain(from.as_deref())
            .map_err(|e| bad_request(&e))?;
        let rendered: Vec<Value> = chain
            .iter()
            .map(|ver| ver.to_json(item.window_until(ver)))
            .collect();
        let terminal = rendered.last().cloned().unwrap_or(Value::Null);
        (rendered, terminal)
    };
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "identifier": identifier,
            "chain": chain,
            "terminal": terminal,
            "as_of": as_of.to_string(),
        }),
        as_of,
    ))
}

/// POST /applicability — bind a profile to a product type with an
/// effective window and a retroactivity flag.
async fn bind_applicability(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let now = Timestamp::now();
    // POST /applicability with `subject_facts` (and no profile to
    // bind) is an evaluation request, not a mutation.
    if v.get("subject_facts").is_some() {
        if v.get("profile_id").is_some() {
            return Err(bad_request(
                "cannot bind with `subject_facts`: subject_facts marks an evaluation request (drop `profile_id`)",
            ));
        }
        let subject = match v.get("product_type").or_else(|| v.get("subject")) {
            Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
            _ => return Err(bad_request("`product_type` is required")),
        };
        let facts = match v.get("subject_facts") {
            Some(f @ Value::Object(_)) => f.clone(),
            _ => return Err(bad_request("`subject_facts` must be a JSON object")),
        };
        let at = opt_ts(&v, "at")?;
        let doc = evaluate_applicability(&app, &subject, at, Some(&facts))?;
        return Ok(stamped(StatusCode::OK, &doc, now));
    }
    let profile_item = req_str(&v, "profile_id")?.trim().to_string();
    validate_token(&profile_item, "profile_id")?;
    let subject = match v.get("product_type").or_else(|| v.get("subject")) {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        Some(_) => return Err(bad_request("`product_type` must be a non-empty string")),
        None => return Err(bad_request("`product_type` is required")),
    };
    let register = opt_str(&v, "register")?;
    let profile_version = opt_str(&v, "profile_version")?;
    let effective_from = opt_ts(&v, "effective_from")?.unwrap_or(now);
    let effective_until = opt_ts(&v, "effective_until")?;
    if let Some(until) = effective_until {
        if until <= effective_from {
            return Err(bad_request(
                "`effective_until` must be after `effective_from`",
            ));
        }
    }
    let retroactive = opt_bool(&v, "retroactive")?.unwrap_or(false);
    let binding = ApplicabilityBinding {
        id: 0,
        subject,
        profile_item,
        register,
        profile_version,
        effective_from: Some(effective_from),
        effective_until,
        registered_at: Some(now),
        retroactive,
    };
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        store.bind(binding).map_err(store_error)?.to_json()
    };
    let mut body = rec["binding"].clone();
    if let Some(m) = body.as_object_mut() {
        m.insert("audit_seq".into(), json!(rec["seq"]));
        m.insert("as_of".into(), json!(now.to_string()));
    }
    Ok(stamped(StatusCode::CREATED, &body, now))
}

/// GET /applicability?product_type=&at=&subject_facts= — which
/// profiles applied at `at` (legal as-of semantics: retroactive
/// bindings apply from their `effective_from`; non-retroactive ones
/// only from `registered_at`). With `subject_facts` (a JSON object),
/// clock predicates on the bound profiles' manifests are evaluated
/// at the query instant: a time-triggered profile binds only once
/// its threshold (`basis + duration`) is crossed. Fact predicates
/// are evaluated locally by the subject's custodian, never here.
async fn applicability_query(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let subject = match opt_query(&params, "product_type").or_else(|| opt_query(&params, "subject"))
    {
        Some(s) => s,
        None => return Err(bad_request("`product_type` is required")),
    };
    let facts = match opt_query(&params, "subject_facts") {
        None => None,
        Some(raw) => Some(parse_subject_facts(&raw)?),
    };
    let doc = evaluate_applicability(&app, &subject, at, facts.as_ref())?;
    Ok(stamped(
        StatusCode::OK,
        &doc,
        at.unwrap_or_else(Timestamp::now),
    ))
}

/// Parses the `subject_facts` JSON document (query parameter or
/// request body): must be a JSON object.
fn parse_subject_facts(raw: &str) -> Result<Value, Response> {
    let v: Value = serde_json::from_str(raw)
        .map_err(|e| bad_request(&format!("`subject_facts` must be a JSON object: {e}")))?;
    if !v.is_object() {
        return Err(bad_request("`subject_facts` must be a JSON object"));
    }
    Ok(v)
}

/// The applicability evaluation core, shared by the GET (query
/// parameter) and POST (request body) forms: reuses the binding
/// store's as-of machinery (`applies_at`), then — only when subject
/// facts were supplied — evaluates each bound profile's clock
/// predicates at the same instant.
fn evaluate_applicability(
    app: &Arc<AppState>,
    subject: &str,
    at: Option<Timestamp>,
    facts: Option<&Value>,
) -> Result<Value, Response> {
    let as_of = at.unwrap_or_else(Timestamp::now);
    let mut applicability = Vec::new();
    let mut unresolved = Vec::new();
    {
        let store = app.store.lock().expect("store poisoned");
        for b in store.bindings_for(subject) {
            if !b.applies_at(as_of) {
                continue;
            }
            let profile = store.item(&b.profile_item);
            let triggers = match profile
                .and_then(|p| p.manifest.as_ref())
                .map(clock::time_triggers)
            {
                None => Vec::new(),
                Some(Ok(t)) => t,
                Some(Err(e)) => {
                    return Err(bad_request(&format!(
                        "profile `{}` carries a malformed time trigger: {e}",
                        b.profile_item
                    )))
                }
            };
            if triggers.is_empty() {
                applicability.push(json!({
                    "binding": b.to_json(),
                    "profile": profile.map(|item| item_summary(item, at)).unwrap_or(Value::Null),
                }));
                continue;
            }
            // clock-fired applicability: the registry can only decide
            // with the subject's facts
            let Some(facts) = facts else {
                unresolved.push(json!({
                    "binding": b.to_json(),
                    "profile_item": b.profile_item,
                    "reason": "the profile's triggers are clock predicates; supply subject_facts to evaluate them",
                }));
                continue;
            };
            let mut evaluations = Vec::new();
            let mut binds = true;
            for (index, t) in &triggers {
                match clock::evaluate(t, facts, as_of) {
                    Ok(e) => {
                        if !e.satisfied {
                            binds = false;
                        }
                        evaluations.push(json!({
                            "index": index,
                            "basis": t.basis,
                            "operator": t.operator,
                            "duration": t.duration_raw,
                            "threshold": e.threshold.to_string(),
                            "satisfied": e.satisfied,
                        }));
                    }
                    // a subject that does not carry the basis fact is
                    // not in the predicate's scope
                    Err(_) => binds = false,
                }
            }
            if binds {
                applicability.push(json!({
                    "binding": b.to_json(),
                    "profile": profile.map(|item| item_summary(item, at)).unwrap_or(Value::Null),
                    "time_triggers": evaluations,
                }));
            }
        }
    }
    Ok(json!({
        "as_of": as_of.to_string(),
        "product_type": subject,
        "applicability": applicability,
        "unresolved": unresolved,
    }))
}

/// GET /admin/log — the append-only audit log (admin, paged).
async fn admin_log(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(10_000);
    let offset = params
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let view = {
        let store = app.store.lock().expect("store poisoned");
        store.log_json(limit, offset)
    };
    Ok(stamped(StatusCode::OK, &view, Timestamp::now()))
}

// ---------------------------------------------------------------------------
// Discovery handlers (C3 services, C4 protocol bindings, C5 verification
// mechanisms). Mutations verify the descriptor signature against the
// operator keyring first; the verified record is then recorded in the
// audit log + journal.
// ---------------------------------------------------------------------------

/// Translate a `DiscoveryError` into an HTTP response (400). Discovery
/// errors never leak server state — they describe what the caller's
/// descriptor did wrong.
fn discovery_error(e: crate::discovery::DiscoveryError) -> Response {
    bad_request(&e.to_string())
}

/// `POST /services` — register a signed C3 service descriptor.
async fn create_service(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let identifier = req_str(&v, "identifier")?.trim().to_string();
    validate_token(&identifier, "identifier")?;
    let version = req_str(&v, "version")?.trim().to_string();
    validate_token(&version, "version")?;
    let body_val = v
        .get("body")
        .cloned()
        .ok_or_else(|| bad_request("missing `body`"))?;
    let signature = v
        .get("signature")
        .ok_or_else(|| bad_request("missing `signature`"))
        .and_then(|s| {
            SignatureValue::from_json(s).map_err(|e| bad_request(&format!("`signature`: {e}")))
        })?;
    let effective_from = opt_ts(&v, "effective_from")?.unwrap_or_else(Timestamp::now);
    let effective_until = opt_ts(&v, "effective_until")?;
    if let Some(until) = effective_until {
        if until <= effective_from {
            return Err(bad_request(
                "`effective_until` must be after `effective_from`",
            ));
        }
    }
    let parsed = parse_service_body(&body_val, &identifier).map_err(discovery_error)?;
    {
        let kr = app.keyring.lock().expect("keyring poisoned");
        // Signature is over canonical-JSON of body with `signature` removed.
        let mut signed_body = body_val.clone();
        if let Some(o) = signed_body.as_object_mut() {
            o.remove("signature");
        }
        let payload = serde_json::to_vec(&signed_body)
            .map_err(|e| bad_request(&format!("serialize body: {e}")))?;
        kr.verify(&parsed.operator.id, &payload, &signature.value)
            .map_err(discovery_error)?;
        // The key id in the signature must match the content-derived key
        // id of the operator's public key (catches cross-key forgeries).
        let expected_key_id = operator_key_id(&parsed.operator.public_key);
        if signature.key_id != expected_key_id {
            return Err(bad_request(&format!(
                "signature `key_id` `{}` does not match the content-derived key id `{}` for operator `{}`",
                signature.key_id, expected_key_id, parsed.operator.id
            )));
        }
    }
    let now = Timestamp::now();
    let svc_version = ServiceVersion {
        version,
        status: parsed.status,
        effective_from,
        effective_until,
        registered_at: now,
        superseded_by_version: None,
        body: body_val,
        signature,
    };
    let audit_seq = {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .register_service(ServiceDescriptor {
                identifier: identifier.clone(),
                versions: vec![svc_version.clone()],
            })
            .map_err(store_error)?
            .seq
    };
    let body = json!({
        "identifier": identifier,
        "version": svc_version.to_json(None),
        "audit_seq": audit_seq,
        "as_of": now.to_string(),
    });
    Ok(stamped(StatusCode::CREATED, &body, now))
}

/// `GET /services` — list services with optional `class=` and
/// `jurisdiction=` filters and `at=` point-in-time semantics.
async fn list_services(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let class_filter = match opt_query(&params, "class") {
        None => None,
        Some(s) => Some(ServiceClass::parse(&s).ok_or_else(|| {
            bad_request(&format!(
                "unknown service class `{s}` (expected one of {})",
                ServiceClass::help()
            ))
        })?),
    };
    let jurisdiction_filter = opt_query(&params, "jurisdiction");
    let services: Vec<ServiceDescriptor> = {
        let store = app.store.lock().expect("store poisoned");
        store
            .services_filtered(class_filter, jurisdiction_filter.as_deref())
            .into_iter()
            .cloned()
            .collect()
    };
    let items: Vec<Value> = services.into_iter().map(|s| s.to_json(as_of, at)).collect();
    Ok(stamped(
        StatusCode::OK,
        &json!({"as_of": as_of.to_string(), "count": items.len(), "services": items}),
        as_of,
    ))
}

/// `GET /services/{id}` — a single service descriptor with the version
/// in force at `at`.
async fn get_service(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(identifier): Path<String>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let svc = {
        let store = app.store.lock().expect("store poisoned");
        store.service(&identifier).cloned()
    };
    let Some(svc) = svc else {
        return Err(not_found(&format!("no service descriptor `{identifier}`")));
    };
    Ok(stamped(StatusCode::OK, &svc.to_json(as_of, at), as_of))
}

/// `POST /services/{id}/versions` — supersede a service descriptor
/// with a new signed version.
async fn supersede_service(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(identifier): Path<String>,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    // Existence first: an unknown service is a 404 regardless of what
    // the body says (the item handler's convention).
    {
        let store = app.store.lock().expect("store poisoned");
        if store.service(&identifier).is_none() {
            return Err(not_found(&format!("no service descriptor `{identifier}`")));
        }
    }
    let v = parse_body(&body)?;
    let version = req_str(&v, "version")?.trim().to_string();
    validate_token(&version, "version")?;
    let body_val = v
        .get("body")
        .cloned()
        .ok_or_else(|| bad_request("missing `body`"))?;
    let signature = v
        .get("signature")
        .ok_or_else(|| bad_request("missing `signature`"))
        .and_then(|s| {
            SignatureValue::from_json(s).map_err(|e| bad_request(&format!("`signature`: {e}")))
        })?;
    let effective_from = opt_ts(&v, "effective_from")?.unwrap_or_else(Timestamp::now);
    let effective_until = opt_ts(&v, "effective_until")?;
    if let Some(until) = effective_until {
        if until <= effective_from {
            return Err(bad_request(
                "`effective_until` must be after `effective_from`",
            ));
        }
    }
    let parsed = parse_service_body(&body_val, &identifier).map_err(discovery_error)?;
    {
        let kr = app.keyring.lock().expect("keyring poisoned");
        let mut signed_body = body_val.clone();
        if let Some(o) = signed_body.as_object_mut() {
            o.remove("signature");
        }
        let payload = serde_json::to_vec(&signed_body)
            .map_err(|e| bad_request(&format!("serialize body: {e}")))?;
        kr.verify(&parsed.operator.id, &payload, &signature.value)
            .map_err(discovery_error)?;
        let expected_key_id = operator_key_id(&parsed.operator.public_key);
        if signature.key_id != expected_key_id {
            return Err(bad_request(&format!(
                "signature `key_id` `{}` does not match the content-derived key id `{}`",
                signature.key_id, expected_key_id
            )));
        }
    }
    let now = Timestamp::now();
    let successor = ServiceVersion {
        version,
        status: parsed.status,
        effective_from,
        effective_until,
        registered_at: now,
        superseded_by_version: None,
        body: body_val,
        signature,
    };
    let target = match opt_str(&v, "supersede_version")? {
        Some(explicit) => explicit,
        None => {
            let current = {
                let store = app.store.lock().expect("store poisoned");
                let svc = store
                    .service(&identifier)
                    .ok_or_else(|| not_found(&format!("no service descriptor `{identifier}`")))?;
                svc.current_version().map(|v| v.version.clone())
            };
            current.ok_or_else(|| {
                bad_request(&format!(
                    "service `{identifier}` has no active version to supersede"
                ))
            })?
        }
    };
    {
        let store = app.store.lock().expect("store poisoned");
        if store.service(&identifier).is_none() {
            return Err(not_found(&format!("no service descriptor `{identifier}`")));
        }
    }
    let outcome = {
        let mut store = app.store.lock().expect("store poisoned");
        let rec = store
            .supersede_service(&identifier, &target, successor.clone())
            .map_err(store_error)?;
        let after = store
            .service(&identifier)
            .cloned()
            .expect("service exists after supersede");
        (rec.seq, after, target)
    };
    let (audit_seq, after, target) = outcome;
    let body = json!({
        "identifier": identifier,
        "new_version": after
            .version(&successor.version)
            .map(|v| v.to_json(after.window_until(v))),
        "superseded_version": after
            .version(&target)
            .map(|v| v.to_json(after.window_until(v))),
        "audit_seq": audit_seq,
        "as_of": now.to_string(),
    });
    Ok(stamped(StatusCode::CREATED, &body, now))
}

/// `GET /services/{id}/supersession` — the supersession chain for a
/// service descriptor.
async fn service_chain(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(identifier): Path<String>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let from = opt_query(&params, "from");
    let svc = {
        let store = app.store.lock().expect("store poisoned");
        store.service(&identifier).cloned()
    };
    let Some(svc) = svc else {
        return Err(not_found(&format!("no service descriptor `{identifier}`")));
    };
    let chain = svc
        .supersession_chain(from.as_deref())
        .map_err(|e| bad_request(&e))?;
    let rendered: Vec<Value> = chain
        .iter()
        .map(|v| v.to_json(svc.window_until(v)))
        .collect();
    let terminal = rendered.last().cloned().unwrap_or(Value::Null);
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "identifier": identifier,
            "chain": rendered,
            "terminal": terminal,
            "as_of": as_of.to_string()
        }),
        as_of,
    ))
}

/// `POST /protocol-bindings` — register a signed C4 protocol binding.
async fn create_protocol_binding(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let identifier = req_str(&v, "identifier")?.trim().to_string();
    validate_token(&identifier, "identifier")?;
    let version = req_str(&v, "version")?.trim().to_string();
    validate_token(&version, "version")?;
    let body_val = v
        .get("body")
        .cloned()
        .ok_or_else(|| bad_request("missing `body`"))?;
    let signature = v
        .get("signature")
        .ok_or_else(|| bad_request("missing `signature`"))
        .and_then(|s| {
            SignatureValue::from_json(s).map_err(|e| bad_request(&format!("`signature`: {e}")))
        })?;
    let parsed = parse_protocol_body(&body_val).map_err(discovery_error)?;
    let operator_val = body_val
        .get("operator")
        .ok_or_else(|| bad_request("body missing `operator`"))
        .and_then(|o| {
            crate::discovery::OperatorRef::from_json(o)
                .map_err(|e| bad_request(&format!("`operator`: {e}")))
        })?;
    {
        let kr = app.keyring.lock().expect("keyring poisoned");
        // The signature is over the canonical body (with any `signature`
        // block removed) — the same convention as services.
        let payload = {
            let mut b = body_val.clone();
            if let Some(o) = b.as_object_mut() {
                o.remove("signature");
            }
            serde_json::to_vec(&b).map_err(|e| bad_request(&format!("serialize body: {e}")))?
        };
        kr.verify(&operator_val.id, &payload, &signature.value)
            .map_err(discovery_error)?;
    }
    let binding = ProtocolBinding {
        identifier: identifier.clone(),
        grammar_ref: parsed.grammar_ref,
        media_types: parsed.media_types,
        version,
        conformance_suite_ref: parsed.conformance_suite_ref,
        body: body_val,
        signature,
    };
    let audit_seq = {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .register_protocol_binding(binding.clone())
            .map_err(store_error)?
            .seq
    };
    let body = json!({
        "identifier": identifier,
        "binding": binding.to_json(),
        "audit_seq": audit_seq,
        "as_of": Timestamp::now().to_string(),
    });
    Ok(stamped(StatusCode::CREATED, &body, Timestamp::now()))
}

/// `GET /protocol-bindings` — list all registered protocol bindings.
async fn list_protocol_bindings(State(app): State<Arc<AppState>>) -> Result<Response, Response> {
    let as_of = Timestamp::now();
    let bindings: Vec<ProtocolBinding> = {
        let store = app.store.lock().expect("store poisoned");
        store.protocol_bindings_all().into_iter().cloned().collect()
    };
    let items: Vec<Value> = bindings.into_iter().map(|b| b.to_json()).collect();
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "as_of": as_of.to_string(),
            "count": items.len(),
            "protocol_bindings": items
        }),
        as_of,
    ))
}

/// `GET /protocol-bindings/{id}` — a single protocol binding.
async fn get_protocol_binding(
    State(app): State<Arc<AppState>>,
    Path(identifier): Path<String>,
) -> Result<Response, Response> {
    let as_of = Timestamp::now();
    let binding = {
        let store = app.store.lock().expect("store poisoned");
        store.protocol_binding(&identifier).cloned()
    };
    let Some(binding) = binding else {
        return Err(not_found(&format!("no protocol binding `{identifier}`")));
    };
    Ok(stamped(StatusCode::OK, &binding.to_json(), as_of))
}

/// `POST /verification-mechanisms` — register a signed C5 verification
/// mechanism.
async fn create_verification_mechanism(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let identifier = req_str(&v, "identifier")?.trim().to_string();
    validate_token(&identifier, "identifier")?;
    let body_val = v
        .get("body")
        .cloned()
        .ok_or_else(|| bad_request("missing `body`"))?;
    let signature = v
        .get("signature")
        .ok_or_else(|| bad_request("missing `signature`"))
        .and_then(|s| {
            SignatureValue::from_json(s).map_err(|e| bad_request(&format!("`signature`: {e}")))
        })?;
    let parsed = parse_verification_body(&body_val).map_err(discovery_error)?;
    let operator_val = body_val
        .get("operator")
        .ok_or_else(|| bad_request("body missing `operator`"))
        .and_then(|o| {
            crate::discovery::OperatorRef::from_json(o)
                .map_err(|e| bad_request(&format!("`operator`: {e}")))
        })?;
    {
        let kr = app.keyring.lock().expect("keyring poisoned");
        // The signature is over the canonical body (with any `signature`
        // block removed) — the same convention as services.
        let payload = {
            let mut b = body_val.clone();
            if let Some(o) = b.as_object_mut() {
                o.remove("signature");
            }
            serde_json::to_vec(&b).map_err(|e| bad_request(&format!("serialize body: {e}")))?
        };
        kr.verify(&operator_val.id, &payload, &signature.value)
            .map_err(discovery_error)?;
    }
    let mechanism = VerificationMechanism {
        identifier: identifier.clone(),
        suite: parsed.suite,
        agility_status: parsed.agility_status,
        trust_framework: parsed.trust_framework,
        trust_list_endpoint: parsed.trust_list_endpoint,
        master_list_ref: parsed.master_list_ref,
        verdict_grammar_ref: parsed.verdict_grammar_ref,
        body: body_val,
        signature,
    };
    let audit_seq = {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .register_verification_mechanism(mechanism.clone())
            .map_err(store_error)?
            .seq
    };
    let body = json!({
        "identifier": identifier,
        "mechanism": mechanism.to_json(),
        "audit_seq": audit_seq,
        "as_of": Timestamp::now().to_string(),
    });
    Ok(stamped(StatusCode::CREATED, &body, Timestamp::now()))
}

/// `GET /verification-mechanisms` — list all registered verification
/// mechanisms.
async fn list_verification_mechanisms(
    State(app): State<Arc<AppState>>,
) -> Result<Response, Response> {
    let as_of = Timestamp::now();
    let mechanisms: Vec<VerificationMechanism> = {
        let store = app.store.lock().expect("store poisoned");
        store
            .verification_mechanisms_all()
            .into_iter()
            .cloned()
            .collect()
    };
    let items: Vec<Value> = mechanisms.into_iter().map(|m| m.to_json()).collect();
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "as_of": as_of.to_string(),
            "count": items.len(),
            "verification_mechanisms": items
        }),
        as_of,
    ))
}

/// `GET /verification-mechanisms/{id}` — a single verification
/// mechanism.
async fn get_verification_mechanism(
    State(app): State<Arc<AppState>>,
    Path(identifier): Path<String>,
) -> Result<Response, Response> {
    let as_of = Timestamp::now();
    let mech = {
        let store = app.store.lock().expect("store poisoned");
        store.verification_mechanism(&identifier).cloned()
    };
    let Some(mech) = mech else {
        return Err(not_found(&format!(
            "no verification mechanism `{identifier}`"
        )));
    };
    Ok(stamped(StatusCode::OK, &mech.to_json(), as_of))
}

// ---------------------------------------------------------------------------
// Profile manifest schema (item 51) — the generated JSON Schema,
// served with as-of semantics
// ---------------------------------------------------------------------------

/// GET /schemas/profile-manifest — the JSON Schema (draft 2020-12)
/// generated from the canonical manifest model. The `as_of` member
/// is serving metadata (not a validation keyword; draft 2020-12
/// validators ignore it); the schema version rides in `$id`.
async fn get_profile_manifest_schema(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let doc = manifest::stamped_schema(manifest::profile_manifest_schema(), as_of);
    Ok(build_response(
        StatusCode::OK,
        vec![
            ("content-type".into(), "application/schema+json".into()),
            ("x-as-of".into(), as_of.to_string()),
        ],
        serde_json::to_string_pretty(&doc).unwrap(),
    ))
}

// ---------------------------------------------------------------------------
// EXPRESS model deposits (item 58 / T-08)
// ---------------------------------------------------------------------------

/// POST /models — deposit an EXPRESS model: source text + metadata;
/// content hash over the exact bytes; expressir validation
/// (subprocess; `pending` when the binary is absent; `invalid`
/// deposits are rejected).
async fn deposit_model(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let register = req_str(&v, "register_id")?.trim().to_string();
    let identifier = req_str(&v, "item_id")?.trim().to_string();
    validate_token(&identifier, "item_id")?;
    let title = body_title(&v)?;
    let submitting_organization = opt_str(&v, "submitting_organization")?;
    let version_number = req_str(&v, "version")?.trim().to_string();
    validate_token(&version_number, "version")?;
    let source = req_str(&v, "source")?.to_string();
    let now = Timestamp::now();
    let effective_from = opt_ts(&v, "effective_from")?.unwrap_or(now);
    let effective_until = opt_ts(&v, "effective_until")?;
    if let Some(until) = effective_until {
        if until <= effective_from {
            return Err(bad_request(
                "`effective_until` must be after `effective_from`",
            ));
        }
    }
    let validation = express::validate_with_expressir(&source);
    if validation.status == express::ValidationStatus::Invalid {
        return Err(bad_request(&format!(
            "expressir rejected the EXPRESS source: {}",
            validation
                .detail
                .as_deref()
                .unwrap_or("no detail available")
        )));
    }
    let item = Item {
        identifier: identifier.clone(),
        register,
        item_class: ItemClass::Model,
        title,
        submitting_organization,
        versions: vec![ItemVersion {
            version: version_number.clone(),
            status: Status::Valid,
            effective_from: Some(effective_from),
            effective_until,
            registered_at: Some(now),
            superseded_by_version: None,
            notes: None,
        }],
        manifest: Some(express::model_manifest(
            &version_number,
            &source,
            &validation,
        )),
    };
    let audit_seq = {
        let mut store = app.store.lock().expect("store poisoned");
        store.register_item(item).map_err(store_error)?.seq
    };
    let body = json!({
        "identifier": identifier,
        "item_class": "model",
        "version": version_number,
        "content_hash": express::content_hash(&source),
        "validation": validation.to_json(),
        "audit_seq": audit_seq,
        "as_of": now.to_string(),
    });
    Ok(stamped(StatusCode::CREATED, &body, now))
}

/// GET /models — list deposited models with their validation status.
async fn list_models(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let register = opt_query(&params, "register");
    let items: Vec<Value> = {
        let store = app.store.lock().expect("store poisoned");
        store
            .items_filtered(Some(ItemClass::Model), register.as_deref())
            .iter()
            .map(|item| {
                let mut summary = item_summary(item, at);
                if let Some(m) = summary.as_object_mut() {
                    m.insert(
                        "validation".into(),
                        json!(intake::model_validation_status(item).as_str()),
                    );
                }
                summary
            })
            .collect()
    };
    Ok(stamped(
        StatusCode::OK,
        &json!({"as_of": as_of.to_string(), "count": items.len(), "models": items}),
        as_of,
    ))
}

/// GET /models/{id}?at=&hash= — the deposited source, its content
/// hash and validation status. With `hash=`, retrieval is pinned to
/// that hash (mismatch → 409).
async fn get_model(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(identifier): Path<String>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let found = {
        let store = app.store.lock().expect("store poisoned");
        find_item(&store, &identifier, Some(ItemClass::Model), None).cloned()
    };
    let Some(item) = found else {
        return Err(not_found(&format!("no model item `{identifier}`")));
    };
    let Some(manifest) = &item.manifest else {
        return Err(bad_request("model item carries no deposit manifest"));
    };
    let deposit = express::deposit_from_manifest(manifest)
        .map_err(|e| bad_request(&format!("corrupt model manifest: {e}")))?;
    if let Some(pinned) = opt_query(&params, "hash") {
        if pinned != deposit.content_hash {
            return Err(conflict(&format!(
                "content hash mismatch: the deposit is `{}` but `{pinned}` was pinned",
                deposit.content_hash
            )));
        }
    }
    let mut body = item_view(&item, at, as_of);
    if let Some(m) = body.as_object_mut() {
        m.insert("source".into(), json!(deposit.source));
        m.insert("content_hash".into(), json!(deposit.content_hash));
        m.insert("validation".into(), deposit.validation.to_json());
    }
    Ok(stamped(StatusCode::OK, &body, as_of))
}

/// POST /models/{id}/validate — re-run expressir validation over the
/// stored source and record the outcome (the degrade path: deposits
/// stored `pending` become `valid`/`invalid` once expressir is
/// available).
async fn validate_model(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(identifier): Path<String>,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let now = Timestamp::now();
    // Read the stored source under one short lock, run the validator
    // with no lock held, then record the outcome under a second
    // short lock (never hold the store across the subprocess).
    let (source, current) = {
        let store = app.store.lock().expect("store poisoned");
        let Some(item) = find_item(&store, &identifier, Some(ItemClass::Model), None) else {
            return Err(not_found(&format!("no model item `{identifier}`")));
        };
        let Some(manifest) = &item.manifest else {
            return Err(bad_request("model item carries no deposit manifest"));
        };
        let deposit = express::deposit_from_manifest(manifest)
            .map_err(|e| bad_request(&format!("corrupt model manifest: {e}")))?;
        let current = item
            .current_version()
            .map(|v| v.version.clone())
            .ok_or_else(|| bad_request(&format!("model `{identifier}` has no current version")))?;
        (deposit.source, current)
    };
    let validation: ValidationRecord = express::validate_with_expressir(&source);
    {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .update_model_validation(&identifier, &current, &validation)
            .map_err(store_error)?;
    }
    let body = json!({
        "identifier": identifier,
        "validation": validation.to_json(),
        "as_of": now.to_string(),
    });
    Ok(stamped(StatusCode::OK, &body, now))
}

// ---------------------------------------------------------------------------
// Cross-register mappings (item 57 / T-07) — lookup from either
// direction
// ---------------------------------------------------------------------------

/// GET /cross-register-mappings?item=&source=&target= — mappings by
/// referenced item: `item` matches either end; `source`/`target`
/// match the named end.
async fn list_cross_register_mappings(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let register = opt_query(&params, "register");
    let lookup_item = opt_query(&params, "item");
    let source = opt_query(&params, "source");
    let target = opt_query(&params, "target");
    if lookup_item.is_none() && source.is_none() && target.is_none() {
        return Err(bad_request(
            "one of `item` (either direction), `source` or `target` is required",
        ));
    }
    let items: Vec<Value> = {
        let store = app.store.lock().expect("store poisoned");
        store
            .items_filtered(Some(ItemClass::CrossRegisterMapping), register.as_deref())
            .iter()
            .filter(|item| {
                mapping::matches_query(
                    item,
                    lookup_item.as_deref(),
                    source.as_deref(),
                    target.as_deref(),
                )
            })
            .map(|item| {
                let mut summary = item_summary(item, at);
                if let Some(m) = summary.as_object_mut() {
                    if let Some(manifest) = &item.manifest {
                        m.insert("manifest".into(), manifest.clone());
                    }
                }
                summary
            })
            .collect()
    };
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "as_of": as_of.to_string(),
            "count": items.len(),
            "mappings": items,
            "query": {
                "item": lookup_item,
                "source": source,
                "target": target,
            },
        }),
        as_of,
    ))
}

// ---------------------------------------------------------------------------
// Seed endpoint (admin) — populates the seed dataset: our own services,
// protocol bindings, verification mechanisms, and units (ISO 80000-
// cited SI base + kWh / MJ / J).
// ---------------------------------------------------------------------------

/// `POST /admin/seed` — idempotent: populates the seed dataset only once
/// per process (or until the journal is wiped). Returns a summary of
/// counts registered. Disabled with `UNIDPP_REGISTRY_SEED_ON_DEMAND=0`.
async fn admin_seed(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    if !app.config.seed_on_demand {
        return Err(bad_request(
            "seeding is disabled (UNIDPP_REGISTRY_SEED_ON_DEMAND=0)",
        ));
    }
    {
        let already = *app.seeded.lock().expect("seeded poisoned");
        if already {
            return Ok(stamped(
                StatusCode::OK,
                &json!({"status": "already-seeded"}),
                Timestamp::now(),
            ));
        }
    }
    let report = run_seed(&app).map_err(|e| bad_request(&format!("seed failed: {e}")))?;
    {
        let mut flag = app.seeded.lock().expect("seeded poisoned");
        *flag = true;
    }
    Ok(stamped(StatusCode::OK, &report, Timestamp::now()))
}

/// The seed routine — populates the discovery layer + the units
/// subregister with the dataset named in the task. Returns a JSON
/// summary; on a partial failure no records are committed (the journal
/// is not written until each record passes through `Store::record`).
fn run_seed(app: &Arc<AppState>) -> Result<Value, String> {
    let mut counts = json!({
        "services": 0,
        "protocol_bindings": 0,
        "verification_mechanisms": 0,
        "units": 0
    });

    // ---- Units (C1 subregister: SI base + kWh/MJ/J with ISO 80000
    // citations) -------------------------------------------------------
    let units = [
        ("unit-m", "metre", "ISO 80000-3:2006"),
        ("unit-kg", "kilogram", "ISO 80000-4:2006"),
        ("unit-s", "second", "ISO 80000-3:2006"),
        ("unit-a", "ampere", "ISO 80000-6:2006"),
        ("unit-k", "kelvin", "ISO 80000-5:2007"),
        ("unit-mol", "mole", "ISO 80000-9:2009"),
        ("unit-cd", "candela", "ISO 80000-7:2008"),
        (
            "unit-kwh",
            "kilowatt hour",
            "ISO 80000-4:2006 (energy); 1 kWh = 3.6 MJ exactly",
        ),
        ("unit-mj", "megajoule", "ISO 80000-4:2006 (energy)"),
        ("unit-j", "joule", "ISO 80000-4:2006 (energy)"),
    ];
    for (id, name, citation) in units {
        let item = Item {
            identifier: id.to_string(),
            register: "unidpp-seed".to_string(),
            item_class: ItemClass::Unit,
            title: name.to_string(),
            submitting_organization: Some("ISO/TC 12".to_string()),
            versions: vec![ItemVersion {
                version: "1.0.0".to_string(),
                status: Status::Valid,
                effective_from: Some(Timestamp::parse("2026-01-01T00:00:00Z").unwrap()),
                effective_until: None,
                registered_at: Some(Timestamp::now()),
                superseded_by_version: None,
                notes: Some(citation.to_string()),
            }],
            manifest: Some(json!({
                "version": "1.0.0",
                "name": name,
                "iso_80000_citation": citation
            })),
        };
        let mut store = app.store.lock().expect("store poisoned");
        store
            .register_item(item)
            .map_err(|e| format!("seed unit `{id}`: {e:?}"))?;
        counts["units"] = json!(counts["units"].as_u64().unwrap() + 1);
    }
    drop(app.store.lock());

    // ---- Protocol bindings (C4) --------------------------------------
    // Each binding carries a signed body authored by its owning operator.
    // For seed descriptors authored by UniDPP itself, the operator is
    // `unidpp-registry` (the registry is itself the meta-descriptor).
    let protocol_bindings = seed_protocol_bindings();
    for (label, pb) in protocol_bindings {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .register_protocol_binding(pb)
            .map_err(|e| format!("seed protocol binding `{label}`: {e:?}"))?;
        counts["protocol_bindings"] = json!(counts["protocol_bindings"].as_u64().unwrap() + 1);
    }
    drop(app.store.lock());

    // ---- Verification mechanisms (C5) --------------------------------
    let verification_mechanisms = seed_verification_mechanisms();
    for (label, mech) in verification_mechanisms {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .register_verification_mechanism(mech)
            .map_err(|e| format!("seed verification mechanism `{label}`: {e:?}"))?;
        counts["verification_mechanisms"] =
            json!(counts["verification_mechanisms"].as_u64().unwrap() + 1);
    }
    drop(app.store.lock());

    // ---- Services (C3) ------------------------------------------------
    let services = seed_services();
    for (label, svc) in services {
        // sign and register the first version only (supersession is the
        // operator's prerogative; seeds don't pre-populate successors).
        let mut store = app.store.lock().expect("store poisoned");
        store
            .register_service(svc)
            .map_err(|e| format!("seed service `{label}`: {e:?}"))?;
        counts["services"] = json!(counts["services"].as_u64().unwrap() + 1);
    }
    drop(app.store.lock());

    Ok(json!({
        "status": "seeded",
        "counts": counts,
    }))
}

/// One seed protocol-binding specification (C4).
struct SeedProtocol {
    id: &'static str,
    description: &'static str,
    grammar_ref: &'static str,
    media_types: Vec<&'static str>,
    conformance_suite_ref: Option<&'static str>,
}

/// Build the seed protocol-binding set: EN 18222 REST, GS1 DL URI,
/// GB/T 33993, UNTP VC profile, Tier-A binary grammar. All signed by
/// the `unidpp-registry` operator.
fn seed_protocol_bindings() -> Vec<(String, ProtocolBinding)> {
    let entries = [
        SeedProtocol {
            id: "pb-en18222-rest",
            description: "EN 18222:2026 REST resource model",
            grammar_ref: "https://standards.cen-cenelec.eu/EN-18222",
            media_types: vec!["application/vnd.en18222+json"],
            conformance_suite_ref: Some("https://standards.cen-cenelec.eu/EN-18222/conformance"),
        },
        SeedProtocol {
            id: "pb-gs1-digital-link",
            description: "GS1 Digital Link URI grammar (v1.2)",
            grammar_ref: "https://www.gs1.org/standards/gs1-digital-link",
            media_types: vec!["application/gs1dl+json"],
            conformance_suite_ref: Some(
                "https://www.gs1.org/standards/gs1-digital-link/conformance",
            ),
        },
        SeedProtocol {
            id: "pb-gbt-33993",
            description: "GB/T 33993 DPP wrapper envelope",
            grammar_ref: "https://openstd.samr.gov.cn/GB/T-33993",
            media_types: vec!["application/vnd.gbt33993+json"],
            conformance_suite_ref: Some("https://openstd.samr.gov.cn/GB/T-33993/conformance"),
        },
        SeedProtocol {
            id: "pb-untp-vc",
            description: "UN Transparency Protocol Verifiable Credential profile",
            grammar_ref: "https://uncefact.unece.org/untp",
            media_types: vec!["application/vc+json", "application/vp+json"],
            conformance_suite_ref: Some("https://uncefact.unece.org/untp/conformance"),
        },
        SeedProtocol {
            id: "pb-tier-a-binary",
            description: "UniDPP Tier-A signed binary pack",
            grammar_ref: "https://unidpp.org/spec/tier-a-binary",
            media_types: vec!["application/vnd.unidpp.tier-a"],
            conformance_suite_ref: Some("https://unidpp.org/spec/tier-a-binary/conformance"),
        },
    ];
    let pk = operator_public_key("unidpp-registry");
    let op = operator_record("unidpp-registry");
    let key_id_str = operator_key_id(&pk);
    let op_id_str = operator_id_of(&pk);
    entries
        .into_iter()
        .map(|e| {
            // The signed envelope is the canonical wire shape (the same
            // object `ProtocolBinding::to_json` reproduces minus the
            // signature block).
            let mut wire = json!({
                "identifier": e.id,
                "description": e.description,
                "version": "1.0.0",
                "grammar_ref": e.grammar_ref,
                "media_types": e.media_types,
                "conformance_suite_ref": e.conformance_suite_ref,
                "operator": op.clone(),
            });
            sign_body(&mut wire, "unidpp-registry", &op_id_str, &key_id_str)
                .expect("sign protocol binding");
            let signature = SignatureValue::from_json(&wire["signature"]).expect("signature parse");
            let parsed = parse_protocol_body(&wire).expect("parse body");
            (
                e.id.to_string(),
                ProtocolBinding {
                    identifier: e.id.to_string(),
                    grammar_ref: parsed.grammar_ref,
                    media_types: parsed.media_types,
                    version: "1.0.0".to_string(),
                    conformance_suite_ref: parsed.conformance_suite_ref,
                    body: wire,
                    signature,
                },
            )
        })
        .collect()
}

/// One seed verification-mechanism specification (C5).
struct SeedMechanism {
    id: &'static str,
    suite: &'static str,
    agility_status: &'static str,
    trust_list_endpoint: &'static str,
}

/// Build the seed verification-mechanism set: SM2/SM3/SM4, FIPS 186-4
/// with FIPS 204 (ML-DSA), and the SIGNATIF trust framework as the
/// trust-graph reference.
fn seed_verification_mechanisms() -> Vec<(String, VerificationMechanism)> {
    let entries = [
        SeedMechanism {
            id: "vm-sm2-sm3-sm4",
            suite: "SM2-SM3-SM4",
            agility_status: "active",
            trust_list_endpoint: "https://trust.unidpp.org/sm2-list",
        },
        SeedMechanism {
            id: "vm-fips",
            suite: "FIPS 186-4 (ECDSA-P256 + RSA-PSS)",
            agility_status: "active",
            trust_list_endpoint: "https://trust.unidpp.org/fips-list",
        },
        SeedMechanism {
            id: "vm-ml-dsa",
            suite: "FIPS 204 ML-DSA-65 (migration phase)",
            agility_status: "migration",
            trust_list_endpoint: "https://trust.unidpp.org/pq-list",
        },
    ];
    let pk = operator_public_key("unidpp-registry");
    let op = operator_record("unidpp-registry");
    let key_id_str = operator_key_id(&pk);
    let op_id_str = operator_id_of(&pk);
    entries
        .into_iter()
        .map(|e| {
            let mut wire = json!({
                "identifier": e.id,
                "suite": e.suite,
                "agility_status": e.agility_status,
                "trust_framework": "SIGNATIF",
                "trust_list_endpoint": e.trust_list_endpoint,
                "master_list_ref": "https://unidpp.org/spec/signatif/master-list",
                "operator": op.clone(),
            });
            sign_body(&mut wire, "unidpp-registry", &op_id_str, &key_id_str)
                .expect("sign verification mechanism");
            let signature = SignatureValue::from_json(&wire["signature"]).expect("signature parse");
            let parsed = parse_verification_body(&wire).expect("parse body");
            (
                e.id.to_string(),
                VerificationMechanism {
                    identifier: e.id.to_string(),
                    suite: parsed.suite,
                    agility_status: parsed.agility_status,
                    trust_framework: parsed.trust_framework,
                    trust_list_endpoint: parsed.trust_list_endpoint,
                    master_list_ref: parsed.master_list_ref,
                    verdict_grammar_ref: parsed.verdict_grammar_ref,
                    body: wire,
                    signature,
                },
            )
        })
        .collect()
}

/// Build the seed service set: the services UniDPP itself runs
/// (registry, issuer, resolver, trust, log, archive, CLI-class
/// verifier, edge). Each is signed by its own operator.
fn seed_services() -> Vec<(String, ServiceDescriptor)> {
    let now = Timestamp::now();
    let eff = Timestamp::parse("2026-09-01T00:00:00Z").unwrap();
    let operators = [
        ("unidpp-registry", ServiceClass::Registry),
        ("unidpp-issuer", ServiceClass::Issuer),
        ("unidpp-resolver", ServiceClass::Resolver),
        ("unidpp-trust", ServiceClass::Trust),
        ("unidpp-log", ServiceClass::Log),
        ("unidpp-archive", ServiceClass::Archive),
        ("unidpp-cli-verifier", ServiceClass::Edge),
        ("unidpp-edge", ServiceClass::Edge),
    ];
    operators
        .into_iter()
        .map(|(label, class)| {
            let identifier = format!("{label}-v1");
            let pk = crate::discovery::operator_public_key(label);
            let key_id_str = operator_key_id(&pk);
            let op_id_str = operator_id_of(&pk);
            let uri = format!("https://{label}.unidpp.org/");
            let mut body = json!({
                "identifier": identifier,
                "operator": crate::discovery::operator_record(label),
                "class": class.as_str(),
                "endpoints": [{"uri": uri, "protocol_binding_ref": "pb-tier-a-binary"}],
                "protocol_binding_ref": "pb-tier-a-binary",
                "jurisdiction": "ZZ",
                "residency_class": "anywhere",
                "status": "active",
                "version": "1.0.0",
                "effective_from": eff.to_string(),
            });
            sign_body(&mut body, label, &op_id_str, &key_id_str).expect("sign service body");
            let signature = SignatureValue::from_json(&body["signature"]).expect("sig parse");
            let version = ServiceVersion {
                version: "1.0.0".to_string(),
                status: ServiceStatus::Active,
                effective_from: eff,
                effective_until: None,
                registered_at: now,
                superseded_by_version: None,
                body,
                signature,
            };
            (
                identifier.clone(),
                ServiceDescriptor {
                    identifier,
                    versions: vec![version],
                },
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Route wiring
// ---------------------------------------------------------------------------

async fn create_items(
    state: State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    create_item(state, headers, body, None).await
}

async fn list_all_items(
    state: State<Arc<AppState>>,
    query: Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    list_items(state, query, None).await
}

async fn get_one_item(
    state: State<Arc<AppState>>,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
) -> Result<Response, Response> {
    get_item(state, query, path, None).await
}

async fn supersede_one_item(
    state: State<Arc<AppState>>,
    headers: HeaderMap,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
    body: String,
) -> Result<Response, Response> {
    supersede_item(state, headers, query, path, body, None).await
}

async fn one_item_chain(
    state: State<Arc<AppState>>,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
) -> Result<Response, Response> {
    item_chain(state, query, path, None).await
}

// Cross-register-mapping subregister wrappers (class from the mount
// point; the intake chain does the class's own validation).

async fn mappings_create(
    state: State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    create_item(state, headers, body, Some(ItemClass::CrossRegisterMapping)).await
}

/// GET /cross-register-mappings — with `item`/`source`/`target`
/// filters, the directional lookup; without them, the generic
/// class-scoped listing.
async fn mappings_get_or_list(
    state: State<Arc<AppState>>,
    query: Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let directional = ["item", "source", "target"]
        .iter()
        .any(|k| query.get(*k).map(|v| !v.trim().is_empty()).unwrap_or(false));
    if directional {
        list_cross_register_mappings(state, query).await
    } else {
        list_items(state, query, Some(ItemClass::CrossRegisterMapping)).await
    }
}

async fn mappings_get_one(
    state: State<Arc<AppState>>,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
) -> Result<Response, Response> {
    get_item(state, query, path, Some(ItemClass::CrossRegisterMapping)).await
}

async fn mappings_supersede_one(
    state: State<Arc<AppState>>,
    headers: HeaderMap,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
    body: String,
) -> Result<Response, Response> {
    supersede_item(
        state,
        headers,
        query,
        path,
        body,
        Some(ItemClass::CrossRegisterMapping),
    )
    .await
}

async fn mappings_chain(
    state: State<Arc<AppState>>,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
) -> Result<Response, Response> {
    item_chain(state, query, path, Some(ItemClass::CrossRegisterMapping)).await
}

// Subregister wrappers (class from the mount point).

async fn sub_create(
    state: State<Arc<AppState>>,
    Extension(class): Extension<ItemClass>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    create_item(state, headers, body, Some(class)).await
}

async fn sub_list(
    state: State<Arc<AppState>>,
    Extension(class): Extension<ItemClass>,
    query: Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    list_items(state, query, Some(class)).await
}

async fn sub_get(
    state: State<Arc<AppState>>,
    Extension(class): Extension<ItemClass>,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
) -> Result<Response, Response> {
    get_item(state, query, path, Some(class)).await
}

async fn sub_supersede(
    state: State<Arc<AppState>>,
    Extension(class): Extension<ItemClass>,
    headers: HeaderMap,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
    body: String,
) -> Result<Response, Response> {
    supersede_item(state, headers, query, path, body, Some(class)).await
}

async fn sub_chain(
    state: State<Arc<AppState>>,
    Extension(class): Extension<ItemClass>,
    query: Query<HashMap<String, String>>,
    path: Path<String>,
) -> Result<Response, Response> {
    item_chain(state, query, path, Some(class)).await
}

/// One subregister's router: the same endpoints as `/items`,
/// class-scoped.
fn subregister(app: Arc<AppState>, class: ItemClass) -> Router {
    Router::new()
        .route("/", post(sub_create).get(sub_list))
        .route("/{id}", get(sub_get))
        .route("/{id}/versions", post(sub_supersede))
        .route("/{id}/supersession", get(sub_chain))
        .layer(Extension(class))
        .with_state(app)
}

pub fn router(app: Arc<AppState>) -> Router {
    let mut r = Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/items", get(list_all_items).post(create_items))
        .route("/items/{id}", get(get_one_item))
        .route("/items/{id}/versions", post(supersede_one_item))
        .route("/items/{id}/supersession", get(one_item_chain))
        .route(
            "/applicability",
            get(applicability_query).post(bind_applicability),
        )
        .route("/services", get(list_services).post(create_service))
        .route("/services/{id}", get(get_service))
        .route("/services/{id}/versions", post(supersede_service))
        .route("/services/{id}/supersession", get(service_chain))
        .route(
            "/protocol-bindings",
            get(list_protocol_bindings).post(create_protocol_binding),
        )
        .route("/protocol-bindings/{id}", get(get_protocol_binding))
        .route(
            "/verification-mechanisms",
            get(list_verification_mechanisms).post(create_verification_mechanism),
        )
        .route(
            "/verification-mechanisms/{id}",
            get(get_verification_mechanism),
        )
        .route("/admin/log", get(admin_log))
        .route("/admin/seed", post(admin_seed))
        .route(
            "/schemas/profile-manifest",
            get(get_profile_manifest_schema),
        )
        .route("/models", get(list_models).post(deposit_model))
        .route("/models/{id}", get(get_model))
        .route("/models/{id}/validate", post(validate_model))
        .route(
            "/cross-register-mappings",
            get(mappings_get_or_list).post(mappings_create),
        )
        .route("/cross-register-mappings/{id}", get(mappings_get_one))
        .route(
            "/cross-register-mappings/{id}/versions",
            post(mappings_supersede_one),
        )
        .route(
            "/cross-register-mappings/{id}/supersession",
            get(mappings_chain),
        )
        .with_state(app.clone());
    // Model and cross-register-mapping have dedicated surfaces
    // (deposit semantics / directional lookup); every other class
    // mounts the generic subregister.
    for class in ItemClass::ALL {
        if matches!(class, ItemClass::Model | ItemClass::CrossRegisterMapping) {
            continue;
        }
        r = r.nest(
            &format!("/{}", class.plural()),
            subregister(app.clone(), class),
        );
    }
    r
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> std::io::Result<()> {
    let app = Arc::new(AppState::new(config.clone())?);
    seed_express_deposit(&app);
    let listener = TcpListener::bind(config.bind).await?;
    eprintln!("unidpp-registry listening on http://{}", config.bind);
    axum::serve(listener, router(app)).await
}

/// A spawned server on an ephemeral port (integration tests and
/// embedders). `stop()` waits for the listener to be released.
pub struct TestServer {
    pub addr: SocketAddr,
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    pub async fn spawn(config: Config) -> std::io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = Arc::new(AppState::new(config)?);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let serve = axum::serve(listener, router(app)).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(e) = serve.await {
                eprintln!("unidpp-registry: server task ended: {e}");
            }
        });
        Ok(TestServer {
            addr,
            base_url: format!("http://{addr}"),
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    /// Stop the server and wait until its listener is released.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

// ---------------------------------------------------------------------------
// The first model deposit (item 58): the vendored UniDPP EXPRESS
// core schema, deposited by the serving binary (not the test
// TestServer, and not /admin/seed — the seed dataset's counts are a
// stable contract). Idempotent: a journaled deposit is not repeated.
// ---------------------------------------------------------------------------

/// The vendored UNIDPP_CORE schema (see assets/unidpp-core.express
/// for provenance).
pub const UNIDPP_CORE_EXPRESS: &str = include_str!("../assets/unidpp-core.express");

/// Deposits the UniDPP EXPRESS core schema as the first `model` item
/// (validation runs through the same expressir path as any deposit;
/// absent expressir leaves it `pending` for `POST
/// /models/{id}/validate`). No-op when the config disables it or the
/// item is already registered.
pub fn seed_express_deposit(app: &Arc<AppState>) {
    if !app.config.seed_express {
        return;
    }
    const ID: &str = "unidpp-core-express";
    const VERSION: &str = "0.1.0";
    {
        let store = app.store.lock().expect("store poisoned");
        if store.item(ID).is_some() {
            return;
        }
    }
    let validation = express::validate_with_expressir(UNIDPP_CORE_EXPRESS);
    let now = Timestamp::now();
    let item = Item {
        identifier: ID.to_string(),
        register: "unidpp-seed".to_string(),
        item_class: ItemClass::Model,
        title: "UniDPP EXPRESS core model (UNIDPP_CORE)".to_string(),
        submitting_organization: Some("UniDPP".to_string()),
        versions: vec![ItemVersion {
            version: VERSION.to_string(),
            status: Status::Valid,
            effective_from: Some(now),
            effective_until: None,
            registered_at: Some(now),
            superseded_by_version: None,
            notes: Some("the registry's first EXPRESS deposit (T-08)".to_string()),
        }],
        manifest: Some(express::model_manifest(
            VERSION,
            UNIDPP_CORE_EXPRESS,
            &validation,
        )),
    };
    let mut store = app.store.lock().expect("store poisoned");
    if let Err(e) = store.register_item(item) {
        eprintln!("unidpp-registry: express seed deposit failed: {e:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn express_seed_deposits_once_with_hash_and_validation() {
        let app = Arc::new(AppState::new(Config::default()).unwrap());
        seed_express_deposit(&app);
        seed_express_deposit(&app); // idempotent
        let store = app.store.lock().expect("store poisoned");
        let item = store.item("unidpp-core-express").expect("seeded");
        assert_eq!(item.item_class, ItemClass::Model);
        assert_eq!(store.log_len(), 1, "one audit record, not two");
        let deposit =
            express::deposit_from_manifest(item.manifest.as_ref().unwrap()).expect("manifest");
        assert_eq!(deposit.source, UNIDPP_CORE_EXPRESS);
        assert_eq!(
            deposit.content_hash,
            express::content_hash(UNIDPP_CORE_EXPRESS)
        );
        assert_ne!(
            deposit.validation.status,
            express::ValidationStatus::Invalid,
            "the vendored schema validates (or is pending without expressir)"
        );
    }

    #[tokio::test]
    async fn express_seed_respects_the_config_flag() {
        let app = Arc::new(
            AppState::new(Config {
                seed_express: false,
                ..Config::default()
            })
            .unwrap(),
        );
        seed_express_deposit(&app);
        let store = app.store.lock().expect("store poisoned");
        assert!(store.item("unidpp-core-express").is_none());
    }
}
