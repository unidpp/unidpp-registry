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
//! `/trust-anchors`, `/units`) with the same endpoints, class-scoped.

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
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8090".parse().unwrap(),
            admin_token: None,
            state_file: None,
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
        c
    }
}

/// Shared application state.
pub struct AppState {
    pub config: Config,
    pub store: Mutex<Store>,
}

impl AppState {
    pub fn new(config: Config) -> std::io::Result<AppState> {
        let store = Store::open(config.state_file.as_deref())?;
        Ok(AppState {
            config,
            store: Mutex::new(store),
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
        "description": "UniDPP ISO 19135 register service: item registration, version supersession, point-in-time resolution and applicability bindings",
        "endpoints": {
            "register_item": "POST /items",
            "list_items": "GET /items?class=&register=&at=",
            "item_as_of": "GET /items/{id}?at=",
            "supersede": "POST /items/{id}/versions",
            "supersession_chain": "GET /items/{id}/supersession?from=",
            "bind_applicability": "POST /applicability",
            "applicability_as_of": "GET /applicability?product_type=&at=",
            "audit_log": "GET /admin/log?limit=&offset=",
            "health": "GET /healthz"
        },
        "item_classes": ItemClass::ALL.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        "statuses": Status::VALUES.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "subregisters": Value::Object(subregisters),
        "as_of": {
            "query_parameter": "at (alias: asof)",
            "response_header": "x-as-of",
        },
        "auth": "mutations require a Bearer token when UNIDPP_REGISTRY_ADMIN_TOKEN is set",
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
            return Err(bad_request("`effective_until` must be after `effective_from`"));
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
    let audit_seq = {
        let mut store = app.store.lock().expect("store poisoned");
        store.register_item(item.clone()).map_err(store_error)?.seq
    };
    let mut body = item_view(&item, None, now);
    if let Some(m) = body.as_object_mut() {
        m.insert("audit_seq".into(), json!(audit_seq));
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
            return Err(bad_request("`effective_until` must be after `effective_from`"));
        }
    }
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
        (rec.seq, after, target)
    };
    let (audit_seq, after, target) = outcome;
    let new_version = after.version(&version_number).expect("successor registered");
    let old_version = after.version(&target).expect("target retained");
    let body = json!({
        "identifier": identifier,
        "new_version": new_version.to_json(after.window_until(new_version)),
        "superseded_version": old_version.to_json(after.window_until(old_version)),
        "item": after.to_json(),
        "reason": reason,
        "audit_seq": audit_seq,
        "as_of": now.to_string(),
    });
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
            return Err(bad_request("`effective_until` must be after `effective_from`"));
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

/// GET /applicability?product_type=&at= — which profiles applied at
/// `at` (legal as-of semantics: retroactive bindings apply from their
/// `effective_from`; non-retroactive ones only from `registered_at`).
async fn applicability_query(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let subject = match opt_query(&params, "product_type").or_else(|| opt_query(&params, "subject"))
    {
        Some(s) => s,
        None => return Err(bad_request("`product_type` is required")),
    };
    let applicability = {
        let store = app.store.lock().expect("store poisoned");
        store
            .bindings_for(&subject)
            .iter()
            .filter(|b| b.applies_at(as_of))
            .map(|b| {
                let profile = store
                    .item(&b.profile_item)
                    .map(|item| item_summary(item, at))
                    .unwrap_or(Value::Null);
                json!({"binding": b.to_json(), "profile": profile})
            })
            .collect::<Vec<_>>()
    };
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "as_of": as_of.to_string(),
            "product_type": subject,
            "applicability": applicability,
        }),
        as_of,
    ))
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
        .route("/applicability", get(applicability_query).post(bind_applicability))
        .route("/admin/log", get(admin_log))
        .with_state(app.clone());
    for class in ItemClass::ALL {
        r = r.nest(&format!("/{}", class.plural()), subregister(app.clone(), class));
    }
    r
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> std::io::Result<()> {
    let app = Arc::new(AppState::new(config.clone())?);
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
