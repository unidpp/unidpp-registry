//! UniDPP discovery registry: signed service descriptors (C3),
//! protocol bindings (C4) and verification mechanisms (C5).
//!
//! Per operator-model §1 (the global registry of DPP services and
//! semantics), the discovery layer registers the *shape* of every
//! service, the *grammar* of every protocol to reach it, and the
//! *mechanism* to verify it — as discoverable, versioned, signed items
//! that any conforming client can use directly.
//!
//! Design:
//!
//! - Each descriptor carries its full content (the "body") plus an
//!   Ed25519 `signature` over a canonical JSON serialization of the
//!   body. The body never includes the signature field (a fork-bomb is
//!   not worth a small gain in shape) — the wire shape is a single
//!   object `{ ...body, signature: { ... } }`.
//! - Verification is done against a seeded operator keyring: the
//!   operator id is content-derived (`op-` + 16 hex chars of
//!   `H(suite || public-key)`), and the keyring holds the
//!   corresponding public key. The keyring is populated by the
//!   `seed_operators` family of constructors and is the only trust
//!   anchor the registry itself maintains.
//! - Versions are immutable per version; supersession follows the same
//!   pattern as 19135 items (old transitions to `superseded`, successor
//!   takes over, derived window end). Statuses are `active`,
//!   `superseded`, `suspended`, `succeeded`. `succeeded` is the
//!   "succession_pointer in effect" state — the registrar keeps the
//!   history; clients follow the pointer.
//! - The JSON Schemas are documented inline below; each `to_json` /
//!   `from_json` pair is the canonical form. The wire shape uses
//!   RFC 3339 UTC timestamps, lowercase enum values, and absent-when-
//!   None (no `null`).

use std::collections::HashMap;
use std::fmt;

use ed25519_dalek::{Signature as EdSignature, Signer, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};

use crate::time::Timestamp;

// ---------------------------------------------------------------------------
// Service class (C3) — the operational role a descriptor advertises
// ---------------------------------------------------------------------------

/// The operational role a `ServiceDescriptor` advertises (the UniDPP operator model
/// §1.1 row C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceClass {
    Issuer,
    Registry,
    Resolver,
    Trust,
    Log,
    Archive,
    Gateway,
    MarketplaceGate,
    Edge,
}

impl ServiceClass {
    pub const ALL: [ServiceClass; 9] = [
        ServiceClass::Issuer,
        ServiceClass::Registry,
        ServiceClass::Resolver,
        ServiceClass::Trust,
        ServiceClass::Log,
        ServiceClass::Archive,
        ServiceClass::Gateway,
        ServiceClass::MarketplaceGate,
        ServiceClass::Edge,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ServiceClass::Issuer => "issuer",
            ServiceClass::Registry => "registry",
            ServiceClass::Resolver => "resolver",
            ServiceClass::Trust => "trust",
            ServiceClass::Log => "log",
            ServiceClass::Archive => "archive",
            ServiceClass::Gateway => "gateway",
            ServiceClass::MarketplaceGate => "marketplace-gate",
            ServiceClass::Edge => "edge",
        }
    }

    pub fn parse(s: &str) -> Option<ServiceClass> {
        let t = s.trim();
        ServiceClass::ALL.into_iter().find(|c| c.as_str() == t)
    }

    pub fn help() -> String {
        ServiceClass::ALL
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for ServiceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Lifecycle status
// ---------------------------------------------------------------------------

/// Lifecycle status of a discovery descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceStatus {
    /// Operationally serving.
    Active,
    /// Replaced by a successor (descriptor's `superseded_by_version`
    /// carries the new version).
    Superseded,
    /// Operator-paused; not serving, but the successor has not been
    /// named yet.
    Suspended,
    /// Replaced and the operator has named a `succession_pointer` (the
    /// client is expected to follow the pointer, not the version chain,
    /// for the operational meaning).
    Succeeded,
}

impl ServiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceStatus::Active => "active",
            ServiceStatus::Superseded => "superseded",
            ServiceStatus::Suspended => "suspended",
            ServiceStatus::Succeeded => "succeeded",
        }
    }

    pub fn parse(s: &str) -> Option<ServiceStatus> {
        match s.trim() {
            "active" => Some(ServiceStatus::Active),
            "superseded" => Some(ServiceStatus::Superseded),
            "suspended" => Some(ServiceStatus::Suspended),
            "succeeded" => Some(ServiceStatus::Succeeded),
            _ => None,
        }
    }
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Operator keyring (dev seeded) — the only trust anchor the registry
// maintains for the discovery layer. Production deployments source the
// keys from an external trust list; the seeded keyring is for dev /
// fixtures / the self-hosted UniDPP first-customer deployment.
// ---------------------------------------------------------------------------

/// An operator identity. The `id` is content-derived
/// (`op-` + 16 hex chars of `H(suite-code || public-key)`) so that an
/// operator id pins exactly one public key (operator-model §1.4 — the
/// "no service is mandatory" rule is mechanical, not asserted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorId {
    pub id: String,
    pub public_key: [u8; 32],
}

/// Operator keyring: seeded dev keyring. Constructor populates
/// deterministic keys from `(operator_id, seed)` pairs; production
/// replaces the seeded population by an external trust list fed in
/// (out of scope for this crate).
pub struct OperatorKeyring {
    keys: HashMap<String, [u8; 32]>,
}

impl OperatorKeyring {
    pub fn new() -> OperatorKeyring {
        OperatorKeyring {
            keys: HashMap::new(),
        }
    }

    /// The dev seeded keyring: the operators that the UniDPP project
    /// itself runs (issuer, registry, resolver, trust, log, archive,
    /// edge, plus CLI-class verifiers). All keys are deterministic
    /// Ed25519 keys derived from `H("UNIDPP-DISCOVERY/OPERATOR-SEED"
    /// || label)` — same scheme as signatif's `KeyPair::seeded`.
    pub fn seeded_dev() -> OperatorKeyring {
        let mut k = OperatorKeyring::new();
        for label in [
            "unidpp-registry",
            "unidpp-issuer",
            "unidpp-resolver",
            "unidpp-trust",
            "unidpp-log",
            "unidpp-archive",
            "unidpp-cli-verifier",
            "unidpp-edge",
        ] {
            k.add(label);
        }
        k
    }

    /// Add a deterministic operator from a label (the operator id is
    /// also derived from the label, so the id is reproducible from the
    /// label alone — the seed and the public key follow deterministically).
    pub fn add(&mut self, label: &str) {
        let seed = deterministic_seed(b"UNIDPP-DISCOVERY/OPERATOR-SEED", label.as_bytes());
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = sk.verifying_key().to_bytes();
        let id = operator_id(&public);
        self.keys.insert(id, public);
    }

    pub fn get(&self, operator_id: &str) -> Option<&[u8; 32]> {
        self.keys.get(operator_id)
    }

    pub fn contains(&self, operator_id: &str) -> bool {
        self.keys.contains_key(operator_id)
    }

    pub fn operator_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.keys.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Resolve an operator's public key, returning a structured error
    /// for missing operators.
    pub fn public_key(&self, operator_id: &str) -> Result<[u8; 32], DiscoveryError> {
        self.keys
            .get(operator_id)
            .copied()
            .ok_or_else(|| DiscoveryError::UnknownOperator(operator_id.to_string()))
    }

    /// Verify an Ed25519 signature over `payload` against `operator_id`'s
    /// public key.
    pub fn verify(
        &self,
        operator_id: &str,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), DiscoveryError> {
        let pk = self.public_key(operator_id)?;
        let vk = VerifyingKey::from_bytes(&pk)
            .map_err(|e| DiscoveryError::BadKey(format!("`{operator_id}`: {e}")))?;
        let sig = EdSignature::from_slice(signature)
            .map_err(|e| DiscoveryError::BadSignature(format!("length: {e}")))?;
        vk.verify(payload, &sig)
            .map_err(|_| DiscoveryError::BadSignature(format!("signature does not verify for `{operator_id}`")))
    }
}

impl Default for OperatorKeyring {
    fn default() -> Self {
        OperatorKeyring::seeded_dev()
    }
}

/// Derive the deterministic 32-byte seed from a domain-separation tag
/// and a label (matches the signatif `KeyPair::seeded` scheme).
fn deterministic_seed(domain: &[u8], label: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(label);
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out);
    seed
}

/// Derive an operator id from a 32-byte Ed25519 public key: `op-` +
/// 16 hex chars of `H(b"op" || public_key)`.
pub fn operator_id(public_key: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"op");
    h.update(public_key);
    let digest = h.finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("op-{hex}")
}

/// Derive a key id from a 32-byte Ed25519 public key (companion to
/// `operator_id`): `k-` + 16 hex chars of `H(b"key" || public_key)`.
/// Used inside descriptor bodies where the operator's key id (not the
/// operator id) is the content that pins the signing key.
pub fn key_id(public_key: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"key");
    h.update(public_key);
    let digest = h.finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("k-{hex}")
}

/// The public key bytes for a seeded operator label (the same scheme
/// `OperatorKeyring::add` derives). Public so the seed routine and
/// external tooling (tests, CLI clients that want to author signed
/// descriptors against the dev keyring) can construct operator
/// identity blocks deterministically.
pub fn operator_public_key(label: &str) -> [u8; 32] {
    let seed = deterministic_seed(b"UNIDPP-DISCOVERY/OPERATOR-SEED", label.as_bytes());
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    sk.verifying_key().to_bytes()
}

/// The operator identity block as it appears inside signed descriptor
/// bodies (id, key_id, public_key, algorithm, label).
pub fn operator_record(label: &str) -> Value {
    let pk = operator_public_key(label);
    let pk_hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
    json!({
        "id": operator_id(&pk),
        "key_id": key_id(&pk),
        "public_key": pk_hex,
        "algorithm": "ed25519",
        "label": label,
    })
}

// ---------------------------------------------------------------------------
// Discovery descriptor errors
// ---------------------------------------------------------------------------

/// Errors raised by the discovery layer. The store / API layer maps
/// these to HTTP responses (`UnknownOperator` / `BadKey` → 400, signature
/// failures → 400, structural problems → 400).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    UnknownOperator(String),
    BadKey(String),
    BadSignature(String),
    Invalid(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::UnknownOperator(id) => write!(f, "unknown operator `{id}`"),
            DiscoveryError::BadKey(m) => write!(f, "bad key: {m}"),
            DiscoveryError::BadSignature(m) => write!(f, "signature verification failed: {m}"),
            DiscoveryError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Wire representation of the signature block (Ed25519 only — the
/// discovery layer pins one suite per descriptor; multi-suite signature
/// shapes live in the trust graph of unidpp-signatif, not the
/// registry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureValue {
    pub key_id: String,
    pub algorithm: String, // "ed25519"
    pub value: Vec<u8>,
}

impl SignatureValue {
    pub fn to_json(&self) -> Value {
        json!({
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "value": hex_lower(&self.value),
        })
    }

    pub fn from_json(v: &Value) -> Result<SignatureValue, String> {
        let obj = v.as_object().ok_or("signature must be an object")?;
        let key_id = obj
            .get("key_id")
            .and_then(Value::as_str)
            .ok_or("missing `key_id`")?
            .to_string();
        let algorithm = obj
            .get("algorithm")
            .and_then(Value::as_str)
            .ok_or("missing `algorithm`")?
            .to_string();
        if algorithm != "ed25519" {
            return Err(format!(
                "unsupported signature algorithm `{algorithm}` (only `ed25519` is accepted)"
            ));
        }
        let value_hex = obj
            .get("value")
            .and_then(Value::as_str)
            .ok_or("missing `value`")?;
        let value = hex_decode(value_hex)
            .ok_or_else(|| format!("`value` is not a hex string: `{value_hex}`"))?;
        if value.len() != 64 {
            return Err(format!(
                "Ed25519 signature must be 64 bytes (got {})",
                value.len()
            ));
        }
        Ok(SignatureValue {
            key_id,
            algorithm,
            value,
        })
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// C3 — Service descriptor
// ---------------------------------------------------------------------------

/// One endpoint a service exposes. The URI is descriptive; `protocol_binding_ref`
/// carries the actual grammar (C4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub uri: String,
    pub protocol_binding_ref: Option<String>,
}

impl Endpoint {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("uri".into(), json!(self.uri));
        if let Some(r) = &self.protocol_binding_ref {
            m.insert("protocol_binding_ref".into(), json!(r));
        }
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Result<Endpoint, String> {
        let obj = v.as_object().ok_or("endpoint must be an object")?;
        let uri = obj
            .get("uri")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("missing `uri`")?
            .to_string();
        let protocol_binding_ref = match obj.get("protocol_binding_ref") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err("`protocol_binding_ref` must be a string".into()),
        };
        Ok(Endpoint {
            uri,
            protocol_binding_ref,
        })
    }
}

/// Operator identity block inside a descriptor body. Carries the
/// operator id (content-derived) and the public key (Ed25519, 32
/// bytes). The public key is the trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorRef {
    pub id: String,
    pub public_key: [u8; 32],
}

impl OperatorRef {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "key_id": key_id(&self.public_key),
            "public_key": hex_lower(&self.public_key),
            "algorithm": "ed25519",
        })
    }

    pub fn from_json(v: &Value) -> Result<OperatorRef, String> {
        let obj = v.as_object().ok_or("operator must be an object")?;
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("missing `operator.id`")?
            .to_string();
        let hex = obj
            .get("public_key")
            .and_then(Value::as_str)
            .ok_or("missing `operator.public_key`")?;
        let bytes = hex_decode(hex)
            .ok_or_else(|| format!("`operator.public_key` is not a hex string: `{hex}`"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "Ed25519 public key must be 32 bytes (got {})",
                bytes.len()
            ));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes);
        let expected_op = operator_id(&public_key);
        if id != expected_op {
            return Err(format!(
                "operator id `{id}` does not match the content-derived id `{expected_op}` for the public key"
            ));
        }
        Ok(OperatorRef { id, public_key })
    }
}

/// One version of a service descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceVersion {
    pub version: String,
    pub status: ServiceStatus,
    pub effective_from: Timestamp,
    pub effective_until: Option<Timestamp>,
    pub registered_at: Timestamp,
    pub superseded_by_version: Option<String>,
    pub body: Value,
    pub signature: SignatureValue,
}

impl ServiceVersion {
    /// The body used as the signature input (deserialized as a JSON
    /// object with `signature` removed).
    fn signed_payload(&self) -> Result<Vec<u8>, String> {
        let mut body = self.body.clone();
        let obj = body
            .as_object_mut()
            .ok_or("service descriptor body must be an object")?;
        obj.remove("signature");
        // canonical JSON: serde_json with sorted keys is sufficient
        // (no floats; the body is structurally ordered text)
        serde_json::to_vec(&body).map_err(|e| format!("serialize body: {e}"))
    }

    /// Verify this version's signature against the operator keyring.
    pub fn verify(&self, keyring: &OperatorKeyring) -> Result<(), DiscoveryError> {
        let payload = self
            .signed_payload()
            .map_err(DiscoveryError::Invalid)?;
        keyring.verify(&self.body_operator_id(), &payload, &self.signature.value)
    }

    fn body_operator_id(&self) -> String {
        self.body
            .get("operator")
            .and_then(|o| o.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    pub fn to_json(&self, window_end: Option<Timestamp>) -> Value {
        let mut m = Map::new();
        m.insert("version".into(), json!(self.version));
        m.insert("status".into(), json!(self.status.as_str()));
        m.insert("effective_from".into(), json!(self.effective_from.to_string()));
        if let Some(t) = self.effective_until {
            m.insert("effective_until".into(), json!(t.to_string()));
        }
        m.insert("registered_at".into(), json!(self.registered_at.to_string()));
        if let Some(s) = &self.superseded_by_version {
            m.insert("superseded_by_version".into(), json!(s));
        }
        m.insert("body".into(), self.body.clone());
        m.insert("signature".into(), self.signature.to_json());
        if let Some(t) = window_end {
            m.insert("window_end".into(), json!(t.to_string()));
        }
        Value::Object(m)
    }

    /// Canonical wire → struct parse (journal replay). The body's
    /// `signature` block is removed before parsing; it is reattached as
    /// a separate field.
    pub fn from_json_value(v: &Value) -> Result<ServiceVersion, String> {
        let obj = v.as_object().ok_or("service version must be an object")?;
        let version = obj
            .get("version")
            .and_then(Value::as_str)
            .ok_or("missing `version`")?
            .to_string();
        let status = obj
            .get("status")
            .and_then(Value::as_str)
            .and_then(ServiceStatus::parse)
            .ok_or_else(|| "invalid `status`".to_string())?;
        let effective_from = obj
            .get("effective_from")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing `effective_from`".to_string())
            .and_then(|s| Timestamp::parse(s).map_err(|e| e.to_string()))?;
        let effective_until = match obj.get("effective_until") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(Timestamp::parse(s).map_err(|e| e.to_string())?),
            Some(_) => return Err("`effective_until` must be a string".into()),
        };
        let registered_at = obj
            .get("registered_at")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing `registered_at`".to_string())
            .and_then(|s| Timestamp::parse(s).map_err(|e| e.to_string()))?;
        let superseded_by_version = obj
            .get("superseded_by_version")
            .and_then(Value::as_str)
            .map(str::to_string);
        let body = obj
            .get("body")
            .cloned()
            .ok_or_else(|| "missing `body`".to_string())?;
        let signature = obj
            .get("signature")
            .ok_or_else(|| "missing `signature`".to_string())
            .and_then(SignatureValue::from_json)?;
        Ok(ServiceVersion {
            version,
            status,
            effective_from,
            effective_until,
            registered_at,
            superseded_by_version,
            body,
            signature,
        })
    }
}

/// A service descriptor: the operator-published description of one
/// `ServiceClass` service, signed by the operator. Keyed by
/// `identifier` (the operator id + a per-service name, e.g.
/// `unidpp-registry:registry.v1`); versioning follows the same
/// supersession discipline as 19135 items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDescriptor {
    pub identifier: String,
    pub versions: Vec<ServiceVersion>,
}

impl ServiceDescriptor {
    pub fn version(&self, n: &str) -> Option<&ServiceVersion> {
        self.versions.iter().find(|v| v.version == n)
    }

    pub fn version_mut(&mut self, n: &str) -> Option<&mut ServiceVersion> {
        self.versions.iter_mut().find(|v| v.version == n)
    }

    /// Versions ordered by `(effective_from, version)` — Ruby parity.
    pub fn ordered_versions(&self) -> Vec<&ServiceVersion> {
        let mut vs: Vec<&ServiceVersion> = self.versions.iter().collect();
        vs.sort_by_key(|v| (v.effective_from.secs, v.version.clone()));
        vs
    }

    /// The current version: latest active, else any non-superseded.
    pub fn current_version(&self) -> Option<&ServiceVersion> {
        let ordered = self.ordered_versions();
        let mut rev = ordered.into_iter().rev();
        rev.find(|v| v.status == ServiceStatus::Active)
            .or_else(|| rev.find(|v| v.status != ServiceStatus::Superseded))
    }

    /// The version in force at time `t`.
    pub fn in_force_at(&self, t: Timestamp) -> Option<&ServiceVersion> {
        self.ordered_versions()
            .into_iter()
            .rfind(|v| {
                if t < v.effective_from {
                    return false;
                }
                if let Some(u) = v.effective_until {
                    if t >= u {
                        return false;
                    }
                }
                true
            })
    }

    /// Resolved window end: explicit `effective_until`, else the
    /// successor's `effective_from`, else open.
    pub fn window_until(&self, v: &ServiceVersion) -> Option<Timestamp> {
        if v.effective_until.is_some() {
            return v.effective_until;
        }
        v.superseded_by_version
            .as_deref()
            .and_then(|n| self.version(n))
            .map(|s| s.effective_from)
    }

    pub fn supersession_chain(&self, from: Option<&str>) -> Result<Vec<&ServiceVersion>, String> {
        let start = match from {
            Some(n) => self.version(n).ok_or_else(|| {
                format!("service `{0}` has no version `{n}`", self.identifier)
            })?,
            None => *self.ordered_versions().first().ok_or_else(|| {
                format!("service `{}` has no versions", self.identifier)
            })?,
        };
        let mut chain = vec![start];
        while let Some(next) = chain.last().and_then(|v| v.superseded_by_version.as_deref()) {
            let nv = self.version(next).ok_or_else(|| {
                format!(
                    "service `{0}` has no version `{next}` (broken supersession link)",
                    self.identifier
                )
            })?;
            if chain.iter().any(|v| v.version == nv.version) {
                return Err(format!(
                    "supersession cycle at version `{}` of service `{}`",
                    nv.version, self.identifier
                ));
            }
            chain.push(nv);
        }
        Ok(chain)
    }

    pub fn to_json(&self, as_of: Timestamp, at: Option<Timestamp>) -> Value {
        let resolved = match at {
            Some(t) => self.in_force_at(t).map(|v| v.to_json(self.window_until(v))),
            None => self.current_version().map(|v| v.to_json(self.window_until(v))),
        };
        let mut m = Map::new();
        m.insert("identifier".into(), json!(self.identifier));
        m.insert("kind".into(), json!("service"));
        m.insert("versions".into(), json!(self.ordered_versions()
            .into_iter()
            .map(|v| v.to_json(self.window_until(v)))
            .collect::<Vec<_>>()));
        m.insert("version".into(), resolved.unwrap_or(Value::Null));
        m.insert("as_of".into(), json!(as_of.to_string()));
        Value::Object(m)
    }

    /// Canonical wire → struct parse (journal replay).
    pub fn from_json_value(v: &Value) -> Result<ServiceDescriptor, String> {
        let obj = v.as_object().ok_or("service descriptor must be an object")?;
        let identifier = obj
            .get("identifier")
            .and_then(Value::as_str)
            .ok_or("missing `identifier`")?
            .to_string();
        let versions = match obj.get("versions") {
            Some(Value::Array(a)) => a
                .iter()
                .map(ServiceVersion::from_json_value)
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("missing `versions` array".into()),
        };
        Ok(ServiceDescriptor { identifier, versions })
    }

    /// Canonical struct → wire (journal storage). Same shape as
    /// `to_json` minus the `as_of` field (the journal carries no as-of
    /// semantics; replays resolve to wall-clock now).
    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("identifier".into(), json!(self.identifier));
        m.insert(
            "versions".into(),
            json!(self
                .ordered_versions()
                .into_iter()
                .map(|v| v.to_json(None))
                .collect::<Vec<_>>()),
        );
        Value::Object(m)
    }
}

/// The parsed content of a C3 service-descriptor body (the result of
/// [`parse_service_body`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBody {
    pub class: ServiceClass,
    pub operator: OperatorRef,
    pub endpoints: Vec<Endpoint>,
    pub protocol_binding_ref: Option<String>,
    pub jurisdiction: Option<String>,
    pub residency_class: Option<String>,
    pub status: ServiceStatus,
    pub succession_pointer: Option<String>,
}

/// Parses the wire body of a service descriptor (the inner object that
/// gets signed) and validates its structural shape.
pub fn parse_service_body(body: &Value, identifier: &str) -> Result<ServiceBody, DiscoveryError> {
    let obj = body.as_object().ok_or_else(|| DiscoveryError::Invalid("body must be an object".into()))?;
    let class = obj
        .get("class")
        .and_then(Value::as_str)
        .ok_or_else(|| DiscoveryError::Invalid("body missing `class`".into()))
        .and_then(|s| ServiceClass::parse(s).ok_or_else(|| DiscoveryError::Invalid(format!("unknown service class `{s}` (expected one of {})", ServiceClass::help()))))?;
    let operator_val = obj
        .get("operator")
        .ok_or_else(|| DiscoveryError::Invalid("body missing `operator`".into()))?;
    let operator = OperatorRef::from_json(operator_val)
        .map_err(DiscoveryError::Invalid)?;
    let endpoints_val = obj
        .get("endpoints")
        .ok_or_else(|| DiscoveryError::Invalid("body missing `endpoints`".into()))?;
    let endpoints = match endpoints_val {
        Value::Array(a) => a
            .iter()
            .map(Endpoint::from_json)
            .collect::<Result<Vec<_>, _>>()
            .map_err(DiscoveryError::Invalid)?,
        _ => return Err(DiscoveryError::Invalid("`endpoints` must be an array".into())),
    };
    if endpoints.is_empty() {
        return Err(DiscoveryError::Invalid("`endpoints` must not be empty".into()));
    }
    let opt = |k: &str| -> Option<String> {
        obj.get(k).and_then(Value::as_str).map(str::to_string)
    };
    let status = match obj.get("status") {
        None | Some(Value::Null) => ServiceStatus::Active,
        Some(Value::String(s)) => ServiceStatus::parse(s).ok_or_else(|| {
            DiscoveryError::Invalid(format!("unknown `status` value `{s}`"))
        })?,
        Some(_) => return Err(DiscoveryError::Invalid("`status` must be a string".into())),
    };
    let body_id = obj
        .get("identifier")
        .and_then(Value::as_str)
        .unwrap_or(identifier);
    if body_id != identifier {
        return Err(DiscoveryError::Invalid(format!(
            "body `identifier` `{body_id}` does not match the path identifier `{identifier}`"
        )));
    }
    Ok(ServiceBody {
        class,
        operator,
        endpoints,
        protocol_binding_ref: opt("protocol_binding_ref"),
        jurisdiction: opt("jurisdiction"),
        residency_class: opt("residency_class"),
        status,
        succession_pointer: opt("succession_pointer"),
    })
}

// ---------------------------------------------------------------------------
// C4 — Protocol binding
// ---------------------------------------------------------------------------

/// One protocol binding (operator-model §1.1 row C4). The grammar
/// reference is the normative pointer; media types are advisory
/// strings (`application/vnd.unidpp.tier-a+json`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolBinding {
    pub identifier: String,
    pub grammar_ref: String,
    pub media_types: Vec<String>,
    pub version: String,
    pub conformance_suite_ref: Option<String>,
    pub body: Value,
    pub signature: SignatureValue,
}

impl ProtocolBinding {
    pub fn to_json(&self) -> Value {
        let mut m = self.body.as_object().cloned().unwrap_or_default();
        m.insert("identifier".into(), json!(self.identifier));
        m.insert("version".into(), json!(self.version));
        m.insert("grammar_ref".into(), json!(self.grammar_ref));
        m.insert("media_types".into(), json!(self.media_types));
        if let Some(s) = &self.conformance_suite_ref {
            m.insert("conformance_suite_ref".into(), json!(s));
        }
        m.insert("signature".into(), self.signature.to_json());
        Value::Object(m)
    }

    /// The body used as the signature input (deserialized as a JSON
    /// object with `signature` removed).
    pub fn signed_payload(&self) -> Result<Vec<u8>, String> {
        let mut body = self.to_json();
        if let Some(obj) = body.as_object_mut() {
            obj.remove("signature");
        }
        serde_json::to_vec(&body).map_err(|e| format!("serialize body: {e}"))
    }

    pub fn verify(&self, keyring: &OperatorKeyring) -> Result<(), DiscoveryError> {
        let payload = self.signed_payload().map_err(DiscoveryError::Invalid)?;
        let operator_id = self
            .body
            .get("operator")
            .and_then(|o| o.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        keyring.verify(operator_id, &payload, &self.signature.value)
    }

    /// Canonical wire → struct parse (journal replay). The body's
    /// `signature` block is removed before parsing.
    pub fn from_json_value(v: &Value) -> Result<ProtocolBinding, String> {
        let obj = v.as_object().ok_or("protocol binding must be an object")?;
        let identifier = obj
            .get("identifier")
            .and_then(Value::as_str)
            .ok_or("missing `identifier`")?
            .to_string();
        let version = obj
            .get("version")
            .and_then(Value::as_str)
            .ok_or("missing `version`")?
            .to_string();
        let grammar_ref = obj
            .get("grammar_ref")
            .and_then(Value::as_str)
            .ok_or("missing `grammar_ref`")?
            .to_string();
        let media_types = obj
            .get("media_types")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let conformance_suite_ref = obj
            .get("conformance_suite_ref")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut body = v.clone();
        if let Some(o) = body.as_object_mut() {
            o.remove("signature");
        }
        let signature = obj
            .get("signature")
            .ok_or_else(|| "missing `signature`".to_string())
            .and_then(SignatureValue::from_json)?;
        Ok(ProtocolBinding {
            identifier,
            grammar_ref,
            media_types,
            version,
            conformance_suite_ref,
            body,
            signature,
        })
    }
}

/// The parsed content of a C4 protocol-binding body (the result of
/// [`parse_protocol_body`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolBody {
    pub grammar_ref: String,
    pub media_types: Vec<String>,
    pub conformance_suite_ref: Option<String>,
}

/// Parse the body of a protocol binding from the wire.
pub fn parse_protocol_body(body: &Value) -> Result<ProtocolBody, DiscoveryError> {
    let obj = body.as_object().ok_or_else(|| DiscoveryError::Invalid("body must be an object".into()))?;
    let grammar_ref = obj
        .get("grammar_ref")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DiscoveryError::Invalid("body missing `grammar_ref`".into()))?
        .to_string();
    let media_types = obj
        .get("media_types")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if media_types.is_empty() {
        return Err(DiscoveryError::Invalid("body missing `media_types`".into()));
    }
    let conformance_suite_ref = obj
        .get("conformance_suite_ref")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(ProtocolBody {
        grammar_ref,
        media_types,
        conformance_suite_ref,
    })
}

// ---------------------------------------------------------------------------
// C5 — Verification mechanism
// ---------------------------------------------------------------------------

/// One verification mechanism (operator-model §1.1 row C5). The
/// `suite` is the canonical name registered in the SIGNATIF model;
/// the `trust_list_endpoint` and `master_list_ref` are the trust-graph
/// wires a client needs to verify verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMechanism {
    pub identifier: String,
    pub suite: String,
    pub agility_status: String,
    pub trust_framework: Option<String>,
    pub trust_list_endpoint: Option<String>,
    pub master_list_ref: Option<String>,
    pub verdict_grammar_ref: Option<String>,
    pub body: Value,
    pub signature: SignatureValue,
}

impl VerificationMechanism {
    pub fn to_json(&self) -> Value {
        let mut m = self.body.as_object().cloned().unwrap_or_default();
        m.insert("identifier".into(), json!(self.identifier));
        m.insert("suite".into(), json!(self.suite));
        m.insert("agility_status".into(), json!(self.agility_status));
        if let Some(s) = &self.trust_framework {
            m.insert("trust_framework".into(), json!(s));
        }
        if let Some(s) = &self.trust_list_endpoint {
            m.insert("trust_list_endpoint".into(), json!(s));
        }
        if let Some(s) = &self.master_list_ref {
            m.insert("master_list_ref".into(), json!(s));
        }
        if let Some(s) = &self.verdict_grammar_ref {
            m.insert("verdict_grammar_ref".into(), json!(s));
        }
        m.insert("signature".into(), self.signature.to_json());
        Value::Object(m)
    }

    pub fn signed_payload(&self) -> Result<Vec<u8>, String> {
        let mut body = self.to_json();
        if let Some(obj) = body.as_object_mut() {
            obj.remove("signature");
        }
        serde_json::to_vec(&body).map_err(|e| format!("serialize body: {e}"))
    }

    pub fn verify(&self, keyring: &OperatorKeyring) -> Result<(), DiscoveryError> {
        let payload = self.signed_payload().map_err(DiscoveryError::Invalid)?;
        let operator_id = self
            .body
            .get("operator")
            .and_then(|o| o.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        keyring.verify(operator_id, &payload, &self.signature.value)
    }

    /// Canonical wire → struct parse (journal replay).
    pub fn from_json_value(v: &Value) -> Result<VerificationMechanism, String> {
        let obj = v.as_object().ok_or("verification mechanism must be an object")?;
        let identifier = obj
            .get("identifier")
            .and_then(Value::as_str)
            .ok_or("missing `identifier`")?
            .to_string();
        let suite = obj
            .get("suite")
            .and_then(Value::as_str)
            .ok_or("missing `suite`")?
            .to_string();
        let agility_status = obj
            .get("agility_status")
            .and_then(Value::as_str)
            .ok_or("missing `agility_status`")?
            .to_string();
        let trust_framework = obj
            .get("trust_framework")
            .and_then(Value::as_str)
            .map(str::to_string);
        let trust_list_endpoint = obj
            .get("trust_list_endpoint")
            .and_then(Value::as_str)
            .map(str::to_string);
        let master_list_ref = obj
            .get("master_list_ref")
            .and_then(Value::as_str)
            .map(str::to_string);
        let verdict_grammar_ref = obj
            .get("verdict_grammar_ref")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut body = v.clone();
        if let Some(o) = body.as_object_mut() {
            o.remove("signature");
        }
        let signature = obj
            .get("signature")
            .ok_or_else(|| "missing `signature`".to_string())
            .and_then(SignatureValue::from_json)?;
        Ok(VerificationMechanism {
            identifier,
            suite,
            agility_status,
            trust_framework,
            trust_list_endpoint,
            master_list_ref,
            verdict_grammar_ref,
            body,
            signature,
        })
    }
}

/// The parsed content of a C5 verification-mechanism body (the result
/// of [`parse_verification_body`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationBody {
    pub suite: String,
    pub agility_status: String,
    pub trust_framework: Option<String>,
    pub trust_list_endpoint: Option<String>,
    pub master_list_ref: Option<String>,
    pub verdict_grammar_ref: Option<String>,
}

pub fn parse_verification_body(body: &Value) -> Result<VerificationBody, DiscoveryError> {
    let obj = body.as_object().ok_or_else(|| DiscoveryError::Invalid("body must be an object".into()))?;
    let req = |k: &str| -> Result<String, DiscoveryError> {
        obj.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| DiscoveryError::Invalid(format!("body missing `{k}`")))
    };
    let opt = |k: &str| -> Option<String> {
        obj.get(k).and_then(Value::as_str).map(str::to_string)
    };
    Ok(VerificationBody {
        suite: req("suite")?,
        agility_status: req("agility_status")?,
        trust_framework: opt("trust_framework"),
        trust_list_endpoint: opt("trust_list_endpoint"),
        master_list_ref: opt("master_list_ref"),
        verdict_grammar_ref: opt("verdict_grammar_ref"),
    })
}

// ---------------------------------------------------------------------------
// Signing helper — used by the seed routine (and by callers that want
// to produce a signed descriptor from outside the crate). Pure function:
// pass a keypair (operator secret), the body, and receive the wire
// object with its signature block.
// ---------------------------------------------------------------------------

/// Sign a descriptor body with the given operator private key, returning
/// a wire-ready object that includes the `signature` block.
///
/// `algorithm` is fixed to `ed25519`; the multi-suite signatures live in
/// the SIGNATIF trust graph, not the registry.
pub fn sign_body(
    body: &mut Value,
    operator_label: &str,
    operator_id_str: &str,
    key_id_str: &str,
) -> Result<(), String> {
    let seed = deterministic_seed(b"UNIDPP-DISCOVERY/OPERATOR-SEED", operator_label.as_bytes());
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    // remove any pre-existing signature block before signing
    if let Some(obj) = body.as_object_mut() {
        obj.remove("signature");
    }
    let payload = serde_json::to_vec(body).map_err(|e| format!("serialize body: {e}"))?;
    let sig = sk.sign(&payload);
    let sig_value = SignatureValue {
        key_id: key_id_str.to_string(),
        algorithm: "ed25519".to_string(),
        value: sig.to_bytes().to_vec(),
    };
    if let Some(obj) = body.as_object_mut() {
        obj.insert("signature".into(), sig_value.to_json());
    }
    // Validate that operator_id_str matches the key
    let public = sk.verifying_key().to_bytes();
    let expected = operator_id(&public);
    if operator_id_str != expected {
        return Err(format!(
            "operator id `{operator_id_str}` does not match the content-derived id `{expected}`"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_template(operator_id_str: &str, public_key_hex: &str, class: &str, uri: &str) -> Value {
        json!({
            "identifier": "unidpp-registry",
            "operator": {
                "id": operator_id_str,
                "key_id": key_id(&hex_to_32(public_key_hex).unwrap()),
                "public_key": public_key_hex,
                "algorithm": "ed25519",
            },
            "class": class,
            "endpoints": [{"uri": uri}],
            "protocol_binding_ref": "pb-rest",
            "jurisdiction": "ZZ",
            "residency_class": "anywhere",
            "status": "active",
            "version": "1.0.0",
            "effective_from": "2026-09-01T00:00:00Z",
        })
    }

    fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
        if s.len() != 64 {
            return Err("expected 64 hex chars".into());
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
        }
        Ok(out)
    }

    #[test]
    fn service_class_round_trip() {
        for c in ServiceClass::ALL {
            assert_eq!(ServiceClass::parse(c.as_str()), Some(c));
        }
        assert_eq!(ServiceClass::parse("bogus"), None);
        assert_eq!(ServiceClass::MarketplaceGate.as_str(), "marketplace-gate");
    }

    #[test]
    fn keying_is_deterministic() {
        let k1 = OperatorKeyring::seeded_dev();
        let k2 = OperatorKeyring::seeded_dev();
        assert_eq!(k1.operator_ids(), k2.operator_ids());
        // the registry's operator id is in the seeded set
        assert!(k1.operator_ids().iter().any(|id| id == &operator_id_for_label("unidpp-registry")));
    }

    fn operator_id_for_label(label: &str) -> String {
        let seed = deterministic_seed(b"UNIDPP-DISCOVERY/OPERATOR-SEED", label.as_bytes());
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        operator_id(&sk.verifying_key().to_bytes())
    }

    #[test]
    fn signature_round_trip_and_reject() {
        let kr = OperatorKeyring::seeded_dev();
        let op_id = operator_id_for_label("unidpp-issuer");
        let pk = kr.public_key(&op_id).unwrap();
        let pk_hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        let mut body = body_template(&op_id, &pk_hex, "issuer", "https://issuer.example/");
        sign_body(&mut body, "unidpp-issuer", &op_id, &key_id(&pk)).unwrap();
        let sig_val = SignatureValue::from_json(&body["signature"]).unwrap();
        let payload = {
            let mut b = body.clone();
            if let Some(o) = b.as_object_mut() {
                o.remove("signature");
            }
            serde_json::to_vec(&b).unwrap()
        };
        kr.verify(&op_id, &payload, &sig_val.value).unwrap();
        // tamper: signature no longer verifies
        let mut tampered = body.clone();
        tampered["endpoints"][0]["uri"] = json!("https://evil.example/");
        let bad_sig = SignatureValue::from_json(&tampered["signature"]).unwrap();
        let bad_payload = {
            let mut b = tampered.clone();
            if let Some(o) = b.as_object_mut() {
                o.remove("signature");
            }
            serde_json::to_vec(&b).unwrap()
        };
        assert!(kr.verify(&op_id, &bad_payload, &bad_sig.value).is_err());
    }

    #[test]
    fn unknown_operator_is_an_error() {
        let kr = OperatorKeyring::seeded_dev();
        let err = kr.verify("op-doesnotexist", b"x", &[0u8; 64]).unwrap_err();
        assert!(matches!(err, DiscoveryError::UnknownOperator(_)));
    }

    #[test]
    fn operator_id_mismatch_in_body_is_rejected() {
        let pk = {
            let seed = deterministic_seed(b"UNIDPP-DISCOVERY/OPERATOR-SEED", b"unidpp-issuer");
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            sk.verifying_key().to_bytes()
        };
        let pk_hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        // claim a different operator id while providing the right key
        let body = json!({
            "identifier": "x",
            "operator": {
                "id": "op-deadbeefdeadbeef",
                "key_id": key_id(&pk),
                "public_key": pk_hex,
                "algorithm": "ed25519",
            },
        });
        let err = OperatorRef::from_json(&body["operator"]).unwrap_err();
        assert!(err.contains("does not match"));
    }

    // -- ServiceDescriptor lifecycle semantics (mirroring the Item
    // model's tests) -----------------------------------------------

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    /// Build a signed service version (operator `unidpp-issuer`).
    fn signed_version(version: &str, from: &str, uri: &str) -> ServiceVersion {
        let label = "unidpp-issuer";
        let pk = operator_public_key(label);
        let mut body = json!({
            "identifier": "svc-issuer",
            "operator": operator_record(label),
            "class": "issuer",
            "endpoints": [{"uri": uri}],
            "protocol_binding_ref": "pb-tier-a-binary",
            "jurisdiction": "DE",
            "residency_class": "eu",
            "status": "active",
        });
        sign_body(
            &mut body,
            label,
            &operator_id(&pk),
            &key_id(&pk),
        )
        .expect("sign");
        let signature = SignatureValue::from_json(&body["signature"]).expect("sig");
        ServiceVersion {
            version: version.to_string(),
            status: ServiceStatus::Active,
            effective_from: ts(from),
            effective_until: None,
            registered_at: ts("2026-09-01T00:00:00Z"),
            superseded_by_version: None,
            body,
            signature,
        }
    }

    fn issuer_service() -> ServiceDescriptor {
        let mut v1 = signed_version("1.0.0", "2026-01-01T00:00:00Z", "https://v1.example/");
        v1.status = ServiceStatus::Superseded;
        v1.superseded_by_version = Some("2.0.0".into());
        let v2 = signed_version("2.0.0", "2027-01-01T00:00:00Z", "https://v2.example/");
        ServiceDescriptor {
            identifier: "svc-issuer".into(),
            versions: vec![v1, v2],
        }
    }

    #[test]
    fn service_windows_and_point_in_time() {
        let svc = issuer_service();
        assert_eq!(svc.in_force_at(ts("2025-06-01T00:00:00Z")), None);
        assert_eq!(
            svc.in_force_at(ts("2026-06-01T00:00:00Z")).unwrap().version,
            "1.0.0"
        );
        // half-open window: at the boundary the successor rules
        assert_eq!(
            svc.in_force_at(ts("2027-01-01T00:00:00Z")).unwrap().version,
            "2.0.0"
        );
        assert_eq!(svc.current_version().unwrap().version, "2.0.0");
        // derived window end from the successor's effective_from
        let v1 = svc.version("1.0.0").unwrap();
        assert_eq!(
            svc.window_until(v1),
            Some(ts("2027-01-01T00:00:00Z"))
        );
        assert_eq!(svc.window_until(svc.version("2.0.0").unwrap()), None);
    }

    #[test]
    fn service_supersession_chain_whole_and_broken() {
        let svc = issuer_service();
        let chain = svc.supersession_chain(None).unwrap();
        let versions: Vec<&str> = chain.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(versions, vec!["1.0.0", "2.0.0"]);
        assert!(svc.supersession_chain(Some("9.9.9")).is_err());
        let mut broken = svc.clone();
        broken.versions[1].superseded_by_version = Some("9.9.9".into());
        assert!(broken.supersession_chain(None).is_err());
        // from the middle
        assert_eq!(svc.supersession_chain(Some("2.0.0")).unwrap().len(), 1);
    }

    #[test]
    fn service_version_signature_verifies() {
        let kr = OperatorKeyring::seeded_dev();
        let v = signed_version("1.0.0", "2026-01-01T00:00:00Z", "https://v1.example/");
        assert!(v.verify(&kr).is_ok());
        // tamper the body under the stored signature
        let mut tampered = v.clone();
        tampered
            .body
            .as_object_mut()
            .unwrap()
            .insert("jurisdiction".into(), json!("CN"));
        assert!(tampered.verify(&kr).is_err());
    }

    #[test]
    fn service_descriptor_json_round_trip() {
        let svc = issuer_service();
        let round = ServiceDescriptor::from_json_value(&svc.to_json_value()).unwrap();
        assert_eq!(round, svc);
        // the rendered view carries the resolved version and as_of
        let view = svc.to_json(ts("2026-06-01T00:00:00Z"), Some(ts("2026-06-01T00:00:00Z")));
        assert_eq!(view["kind"], "service");
        assert_eq!(view["version"]["version"], "1.0.0");
        assert_eq!(view["as_of"], "2026-06-01T00:00:00Z");
        // before any window: null version
        let early = svc.to_json(ts("2020-01-01T00:00:00Z"), Some(ts("2020-01-01T00:00:00Z")));
        assert_eq!(early["version"], Value::Null);
    }

    #[test]
    fn parse_service_body_validates_shape() {
        let label = "unidpp-issuer";
        let mut body = json!({
            "operator": operator_record(label),
            "class": "issuer",
            "endpoints": [{"uri": "https://x/"}],
        });
        // identifier defaults to the caller's when absent
        let parsed = parse_service_body(&body, "svc-x").unwrap();
        assert_eq!(parsed.class, ServiceClass::Issuer);
        assert_eq!(parsed.status, ServiceStatus::Active);
        assert_eq!(parsed.endpoints.len(), 1);
        // mismatched identifier is rejected
        body["identifier"] = json!("svc-other");
        assert!(parse_service_body(&body, "svc-x").is_err());
        // unknown class, missing endpoints, empty endpoints, bad operator
        body["identifier"] = Value::Null;
        body["class"] = json!("nope");
        assert!(parse_service_body(&body, "svc-x").is_err());
        body["class"] = json!("issuer");
        body["endpoints"] = json!([]);
        assert!(parse_service_body(&body, "svc-x").is_err());
        body["endpoints"] = Value::Null;
        assert!(parse_service_body(&body, "svc-x").is_err());
        body["endpoints"] = json!([{"uri": "https://x/"}]);
        body["operator"] = json!({});
        assert!(parse_service_body(&body, "svc-x").is_err());
    }

    #[test]
    fn protocol_and_verification_bodies_parse() {
        let pb = parse_protocol_body(&json!({
            "grammar_ref": "https://g/",
            "media_types": ["application/x"],
            "conformance_suite_ref": "https://c/",
        }))
        .unwrap();
        assert_eq!(pb.grammar_ref, "https://g/");
        assert_eq!(pb.conformance_suite_ref.as_deref(), Some("https://c/"));
        assert!(parse_protocol_body(&json!({"grammar_ref": "https://g/"})).is_err());

        let vm = parse_verification_body(&json!({
            "suite": "SM2-SM3-SM4",
            "agility_status": "active",
        }))
        .unwrap();
        assert_eq!(vm.suite, "SM2-SM3-SM4");
        assert!(vm.trust_framework.is_none());
        assert!(parse_verification_body(&json!({"suite": "x"})).is_err());
    }

    #[test]
    fn operator_helpers_agree_with_keyring() {
        for label in [
            "unidpp-registry",
            "unidpp-issuer",
            "unidpp-cli-verifier",
        ] {
            let pk = operator_public_key(label);
            let record = operator_record(label);
            let kr = OperatorKeyring::seeded_dev();
            assert_eq!(record["id"].as_str().unwrap(), operator_id(&pk));
            assert!(kr.contains(&operator_id(&pk)), "keyring has {label}");
        }
    }
}
