//! UniDPP ISO 19135 registry service (crate `unidpp-registry`).
//!
//! Part of UniDPP (github.com/unidpp) — implements TODO.impl
//! `10-remaining-tasks-definitive.md` item 12: a running registry
//! (19135 item service) that the issuer and resolver both consume.
//! The model mirrors the Ruby reference `unidpp-rb/lib/unidpp/registry`
//! (`Item` / `ItemVersion` / `ApplicabilityBinding`; the read-only
//! Ruby `Client` maps onto this service's HTTP surface); the server
//! conventions mirror `unidpp-resolver`.
//!
//! - register items (data elements, profiles, crypto suites,
//!   transforms, trust anchors, units) with versioned 19135
//!   lifecycle statuses;
//! - supersede versions: the old version transitions to `superseded`
//!   with a successor link that *derives* its window end;
//! - point-in-time (`?at=`) resolution of the version in force;
//! - applicability bindings with effective windows and retroactivity
//!   (a retroactive binding legally backdates);
//! - subregisters as item classes (`/data-elements`, `/profiles`,
//!   `/crypto-suites`, `/transforms`, `/trust-anchors`, `/units`) with
//!   the same endpoints, class-scoped;
//! - admin auth (Bearer token), as-of stamps on all responses, and an
//!   append-only audit log of every mutation (JSONL journal, replayed
//!   on start).
//!
//! Server: axum (0.8) over tokio. Dependency-light on purpose: axum,
//! tokio, serde_json — no tracing, no metrics, no TLS stack, no
//! database (the audit journal is the storage; see `store`).

// Handlers and parse helpers return `Result<_, Response>` with the
// ready-made error response by value — the idiomatic axum pattern;
// boxing the error would complicate every call site for no gain.
#![allow(clippy::result_large_err)]

pub mod api;
pub mod discovery;
pub mod model;
pub mod store;
pub mod time;

pub use api::{run, Config, TestServer};
pub use discovery::{
    key_id, operator_id, operator_public_key, operator_record, sign_body, DiscoveryError,
    Endpoint, OperatorKeyring, OperatorRef, ProtocolBinding, ServiceClass, ServiceDescriptor,
    ServiceStatus, ServiceVersion, SignatureValue, VerificationMechanism,
};
pub use model::{ApplicabilityBinding, Item, ItemClass, ItemVersion, Status};
pub use store::{AuditRecord, Op, Store, StoreError};
pub use time::Timestamp;