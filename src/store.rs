//! Registry store: items keyed by identifier, applicability bindings,
//! and the append-only audit log of every registry mutation. The
//! optional JSONL journal persists the audit log and is replayed on
//! start — the log *is* the storage (nothing is edited in place;
//! lifecycle transitions are appended operations, mirroring the
//! resolver's I4 doctrine and the Ruby model's immutable versions).
//!
//! The store also holds the discovery descriptors (C3 services, C4
//! protocol bindings, C5 verification mechanisms) — they are versioned
//! supersede-able records, the same lifecycle discipline as 19135
//! items. Signatures are verified at intake; replay re-applies the
//! already-verified records (signature verification is a creation-time
//! concern, not a re-validation one).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde_json::{json, Value};

use crate::discovery::{ProtocolBinding, ServiceDescriptor, VerificationMechanism};
use crate::model::{ApplicabilityBinding, Item, ItemClass, ItemVersion, Status};
use crate::time::Timestamp;

/// An append-only registry mutation.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// Initial registration of an item (carrying its first version).
    RegisterItem { item: Item },
    /// A new version of an item that supersedes `superseded_version`:
    /// the old version transitions to `superseded` (with the successor
    /// link that derives its window end); `manifest`, when `Some`,
    /// replaces the item-level manifest.
    SupersedeVersion {
        identifier: String,
        superseded_version: String,
        prior_status: Status,
        successor: ItemVersion,
        manifest: Option<Value>,
    },
    /// A dated applicability binding of a profile item to a subject.
    BindApplicability { binding: ApplicabilityBinding },
    /// Initial registration of a C3 service descriptor (carrying its
    /// first signed version).
    RegisterService { descriptor: ServiceDescriptor },
    /// A new signed version of a service descriptor that supersedes
    /// `superseded_version`: the old version transitions to
    /// `superseded` with a successor link.
    SupersedeService {
        identifier: String,
        superseded_version: String,
        prior_status: crate::discovery::ServiceStatus,
        successor: crate::discovery::ServiceVersion,
    },
    /// A C4 protocol binding.
    RegisterProtocolBinding { binding: ProtocolBinding },
    /// A C5 verification mechanism.
    RegisterVerificationMechanism { mechanism: VerificationMechanism },
    /// Re-validated the EXPRESS source of a `model` item's version:
    /// the manifest's `express.validation` block is replaced.
    UpdateModelValidation {
        identifier: String,
        version: String,
        status: String,
        tool: String,
        detail: Option<String>,
    },
}

/// One record in the append-only audit log.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditRecord {
    pub seq: u64,
    pub recorded_at: Timestamp,
    pub op: Op,
}

impl AuditRecord {
    pub fn to_json(&self) -> Value {
        let mut m = match &self.op {
            Op::RegisterItem { item } => json!({"op": "register-item", "item": item.to_json()}),
            Op::SupersedeVersion {
                identifier,
                superseded_version,
                prior_status,
                successor,
                manifest,
            } => {
                let mut m = json!({
                    "op": "supersede-version",
                    "identifier": identifier,
                    "superseded_version": superseded_version,
                    "prior_status": prior_status.as_str(),
                    "successor": successor.to_json(None),
                });
                if let Some(man) = manifest {
                    if let Some(o) = m.as_object_mut() {
                        o.insert("manifest".into(), man.clone());
                    }
                }
                m
            }
            Op::BindApplicability { binding } => {
                json!({"op": "bind-applicability", "binding": binding.to_json()})
            }
            Op::RegisterService { descriptor } => json!({
                "op": "register-service",
                "descriptor": descriptor.to_json_value(),
            }),
            Op::SupersedeService {
                identifier,
                superseded_version,
                prior_status,
                successor,
            } => json!({
                "op": "supersede-service",
                "identifier": identifier,
                "superseded_version": superseded_version,
                "prior_status": prior_status.as_str(),
                "successor": successor.to_json(None),
            }),
            Op::RegisterProtocolBinding { binding } => json!({
                "op": "register-protocol-binding",
                "binding": binding.to_json(),
            }),
            Op::RegisterVerificationMechanism { mechanism } => json!({
                "op": "register-verification-mechanism",
                "mechanism": mechanism.to_json(),
            }),
            Op::UpdateModelValidation {
                identifier,
                version,
                status,
                tool,
                detail,
            } => {
                let mut m = json!({
                    "op": "update-model-validation",
                    "identifier": identifier,
                    "version": version,
                    "status": status,
                    "tool": tool,
                });
                if let Some(d) = detail {
                    if let Some(o) = m.as_object_mut() {
                        o.insert("detail".into(), json!(d));
                    }
                }
                m
            }
        }
        .as_object()
        .cloned()
        .unwrap_or_default();
        m.insert("seq".into(), json!(self.seq));
        m.insert("recorded_at".into(), json!(self.recorded_at.to_string()));
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Result<AuditRecord, String> {
        let obj = v.as_object().ok_or("audit record must be an object")?;
        let seq = obj
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or("missing `seq`")?;
        let recorded_at = obj
            .get("recorded_at")
            .and_then(Value::as_str)
            .and_then(|s| Timestamp::parse(s).ok())
            .ok_or("missing/invalid `recorded_at`")?;
        let op = match obj.get("op").and_then(Value::as_str) {
            Some("register-item") => Op::RegisterItem {
                item: Item::from_json(obj.get("item").ok_or("missing `item`")?)?,
            },
            Some("supersede-version") => Op::SupersedeVersion {
                identifier: obj
                    .get("identifier")
                    .and_then(Value::as_str)
                    .ok_or("missing `identifier`")?
                    .to_string(),
                superseded_version: obj
                    .get("superseded_version")
                    .and_then(Value::as_str)
                    .ok_or("missing `superseded_version`")?
                    .to_string(),
                prior_status: Status::parse(
                    obj.get("prior_status")
                        .and_then(Value::as_str)
                        .ok_or("missing `prior_status`")?,
                )
                .ok_or("invalid `prior_status`")?,
                successor: ItemVersion::from_json(
                    obj.get("successor").ok_or("missing `successor`")?,
                )?,
                manifest: obj.get("manifest").filter(|m| !m.is_null()).cloned(),
            },
            Some("bind-applicability") => Op::BindApplicability {
                binding: ApplicabilityBinding::from_json(
                    obj.get("binding").ok_or("missing `binding`")?,
                )?,
            },
            Some("register-service") => Op::RegisterService {
                descriptor: ServiceDescriptor::from_json_value(
                    obj.get("descriptor").ok_or("missing `descriptor`")?,
                )?,
            },
            Some("supersede-service") => Op::SupersedeService {
                identifier: obj
                    .get("identifier")
                    .and_then(Value::as_str)
                    .ok_or("missing `identifier`")?
                    .to_string(),
                superseded_version: obj
                    .get("superseded_version")
                    .and_then(Value::as_str)
                    .ok_or("missing `superseded_version`")?
                    .to_string(),
                prior_status: crate::discovery::ServiceStatus::parse(
                    obj.get("prior_status")
                        .and_then(Value::as_str)
                        .ok_or("missing `prior_status`")?,
                )
                .ok_or("invalid `prior_status`")?,
                successor: crate::discovery::ServiceVersion::from_json_value(
                    obj.get("successor").ok_or("missing `successor`")?,
                )?,
            },
            Some("register-protocol-binding") => Op::RegisterProtocolBinding {
                binding: ProtocolBinding::from_json_value(
                    obj.get("binding").ok_or("missing `binding`")?,
                )?,
            },
            Some("register-verification-mechanism") => Op::RegisterVerificationMechanism {
                mechanism: VerificationMechanism::from_json_value(
                    obj.get("mechanism").ok_or("missing `mechanism`")?,
                )?,
            },
            Some("update-model-validation") => Op::UpdateModelValidation {
                identifier: obj
                    .get("identifier")
                    .and_then(Value::as_str)
                    .ok_or("missing `identifier`")?
                    .to_string(),
                version: obj
                    .get("version")
                    .and_then(Value::as_str)
                    .ok_or("missing `version`")?
                    .to_string(),
                status: obj
                    .get("status")
                    .and_then(Value::as_str)
                    .ok_or("missing `status`")?
                    .to_string(),
                tool: obj
                    .get("tool")
                    .and_then(Value::as_str)
                    .ok_or("missing `tool`")?
                    .to_string(),
                detail: obj
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            },
            _ => return Err("unknown `op`".to_string()),
        };
        Ok(AuditRecord {
            seq,
            recorded_at,
            op,
        })
    }
}

/// Store-level validation failures mapped by the API layer
/// (`Conflict` → 409, `Invalid` → 400).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Conflict(String),
    Invalid(String),
}

/// The registry store: items keyed by identifier (identifiers are
/// unique per service instance; the register is an item attribute —
/// registers federate as siblings, none is the universal envelope),
/// applicability bindings, the audit log, the JSONL journal, and the
/// discovery descriptors (C3 services, C4 protocol bindings, C5
/// verification mechanisms).
pub struct Store {
    items: HashMap<String, Item>,
    bindings: Vec<ApplicabilityBinding>,
    services: HashMap<String, ServiceDescriptor>,
    protocol_bindings: HashMap<String, ProtocolBinding>,
    verification_mechanisms: HashMap<String, VerificationMechanism>,
    log: Vec<AuditRecord>,
    next_binding_id: u64,
    journal: Option<File>,
}

impl Store {
    /// Fresh store with an optional JSONL journal (opened for append;
    /// existing lines are replayed).
    pub fn open(journal: Option<&Path>) -> std::io::Result<Store> {
        let mut store = Store {
            items: HashMap::new(),
            bindings: Vec::new(),
            services: HashMap::new(),
            protocol_bindings: HashMap::new(),
            verification_mechanisms: HashMap::new(),
            log: Vec::new(),
            next_binding_id: 1,
            journal: None,
        };
        if let Some(path) = journal {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if path.exists() {
                store.replay(path)?;
            }
            store.journal = Some(OpenOptions::new().create(true).append(true).open(path)?);
        }
        Ok(store)
    }

    fn replay(&mut self, path: &Path) -> std::io::Result<()> {
        let file = File::open(path)?;
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(&line)
                .map_err(|e| e.to_string())
                .and_then(|v| AuditRecord::from_json(&v))
            {
                Ok(rec) => {
                    self.apply(&rec);
                    self.log.push(rec);
                }
                Err(e) => {
                    // A torn final line (crash mid-write) is tolerated;
                    // anything else is reported and skipped loudly.
                    eprintln!("unidpp-registry: journal line {}: {e}", i + 1);
                }
            }
        }
        Ok(())
    }

    /// Append a record to the audit log (and journal), then apply it.
    pub fn record(&mut self, op: Op) -> AuditRecord {
        let rec = AuditRecord {
            seq: self.log.len() as u64 + 1,
            recorded_at: Timestamp::now(),
            op,
        };
        if let Some(j) = self.journal.as_mut() {
            if let Err(e) = writeln!(j, "{}", rec.to_json()) {
                eprintln!("unidpp-registry: journal write failed: {e}");
            }
        }
        self.apply(&rec);
        self.log.push(rec.clone());
        rec
    }

    /// Pure state transition used by both live recording and journal
    /// replay.
    fn apply(&mut self, rec: &AuditRecord) {
        match &rec.op {
            Op::RegisterItem { item } => {
                self.items.insert(item.identifier.clone(), item.clone());
            }
            Op::SupersedeVersion {
                identifier,
                superseded_version,
                successor,
                manifest,
                ..
            } => {
                if let Some(item) = self.items.get_mut(identifier) {
                    if let Some(old) = item.version_mut(superseded_version) {
                        old.status = Status::Superseded;
                        old.superseded_by_version = Some(successor.version.clone());
                    }
                    item.versions.push(successor.clone());
                    if let Some(man) = manifest {
                        item.manifest = Some(man.clone());
                    }
                }
            }
            Op::BindApplicability { binding } => {
                self.next_binding_id = self.next_binding_id.max(binding.id + 1);
                self.bindings.push(binding.clone());
            }
            Op::RegisterService { descriptor } => {
                self.services
                    .insert(descriptor.identifier.clone(), descriptor.clone());
            }
            Op::SupersedeService {
                identifier,
                superseded_version,
                successor,
                ..
            } => {
                if let Some(svc) = self.services.get_mut(identifier) {
                    if let Some(old) = svc.version_mut(superseded_version) {
                        old.status = crate::discovery::ServiceStatus::Superseded;
                        old.superseded_by_version = Some(successor.version.clone());
                    }
                    svc.versions.push(successor.clone());
                }
            }
            Op::RegisterProtocolBinding { binding } => {
                self.protocol_bindings
                    .insert(binding.identifier.clone(), binding.clone());
            }
            Op::RegisterVerificationMechanism { mechanism } => {
                self.verification_mechanisms
                    .insert(mechanism.identifier.clone(), mechanism.clone());
            }
            Op::UpdateModelValidation {
                identifier,
                status,
                tool,
                detail,
                ..
            } => {
                if let Some(item) = self.items.get_mut(identifier) {
                    if let Some(manifest) = item.manifest.as_mut() {
                        if let Some(express) = manifest.get_mut("express") {
                            if let Some(o) = express.as_object_mut() {
                                let mut record = serde_json::Map::new();
                                record.insert("status".into(), json!(status));
                                record.insert("tool".into(), json!(tool));
                                if let Some(d) = detail {
                                    record.insert("detail".into(), json!(d));
                                }
                                o.insert("validation".into(), Value::Object(record));
                            }
                        }
                    }
                }
            }
        }
    }

    // -- reads ----------------------------------------------------------

    pub fn item(&self, identifier: &str) -> Option<&Item> {
        self.items.get(identifier)
    }

    /// Items filtered by item class and/or register.
    pub fn items_filtered(&self, class: Option<ItemClass>, register: Option<&str>) -> Vec<&Item> {
        let mut items: Vec<&Item> = self
            .items
            .values()
            .filter(|i| class.map_or(true, |c| i.item_class == c))
            .filter(|i| register.map_or(true, |r| i.register == r))
            .collect();
        items.sort_by(|a, b| a.identifier.cmp(&b.identifier));
        items
    }

    pub fn bindings_for(&self, subject: &str) -> Vec<&ApplicabilityBinding> {
        self.bindings
            .iter()
            .filter(|b| b.subject == subject)
            .collect()
    }

    // -- discovery reads (C3 / C4 / C5) ----------------------------------

    pub fn service(&self, identifier: &str) -> Option<&ServiceDescriptor> {
        self.services.get(identifier)
    }

    /// Services filtered by class and/or jurisdiction (as-of at the
    /// current instant — the descriptor's current version is used for
    /// the filter values).
    pub fn services_filtered(
        &self,
        class: Option<crate::discovery::ServiceClass>,
        jurisdiction: Option<&str>,
    ) -> Vec<&ServiceDescriptor> {
        let mut out: Vec<&ServiceDescriptor> = self
            .services
            .values()
            .filter(|s| {
                let v = match s.current_version() {
                    Some(v) => v,
                    None => return false,
                };
                if let Some(c) = class {
                    let body_class = v
                        .body
                        .get("class")
                        .and_then(Value::as_str)
                        .and_then(crate::discovery::ServiceClass::parse);
                    if body_class != Some(c) {
                        return false;
                    }
                }
                if let Some(j) = jurisdiction {
                    let body_jur = v.body.get("jurisdiction").and_then(Value::as_str);
                    if body_jur != Some(j) {
                        return false;
                    }
                }
                true
            })
            .collect();
        out.sort_by(|a, b| a.identifier.cmp(&b.identifier));
        out
    }

    pub fn protocol_binding(&self, identifier: &str) -> Option<&ProtocolBinding> {
        self.protocol_bindings.get(identifier)
    }

    pub fn protocol_bindings_all(&self) -> Vec<&ProtocolBinding> {
        let mut out: Vec<&ProtocolBinding> = self.protocol_bindings.values().collect();
        out.sort_by(|a, b| a.identifier.cmp(&b.identifier));
        out
    }

    pub fn verification_mechanism(&self, identifier: &str) -> Option<&VerificationMechanism> {
        self.verification_mechanisms.get(identifier)
    }

    pub fn verification_mechanisms_all(&self) -> Vec<&VerificationMechanism> {
        let mut out: Vec<&VerificationMechanism> = self.verification_mechanisms.values().collect();
        out.sort_by(|a, b| a.identifier.cmp(&b.identifier));
        out
    }

    // -- mutations (validated, audited) ----------------------------------

    /// Registers a new item with its first version.
    pub fn register_item(&mut self, item: Item) -> Result<AuditRecord, StoreError> {
        if self.items.contains_key(&item.identifier) {
            return Err(StoreError::Conflict(format!(
                "item `{}` is already registered; add versions through POST /items/{}/versions",
                item.identifier, item.identifier
            )));
        }
        Ok(self.record(Op::RegisterItem { item }))
    }

    /// Adds `successor` to the item and transitions `target_version`
    /// to `superseded` with a successor link (which derives its window
    /// end). `manifest`, when `Some`, replaces the item-level manifest.
    pub fn supersede(
        &mut self,
        identifier: &str,
        target_version: &str,
        successor: ItemVersion,
        manifest: Option<Value>,
    ) -> Result<AuditRecord, StoreError> {
        let Some(item) = self.items.get(identifier) else {
            return Err(StoreError::Invalid(format!(
                "no registry item `{identifier}`"
            )));
        };
        if item.version(&successor.version).is_some() {
            return Err(StoreError::Conflict(format!(
                "item `{identifier}` already has a version `{}`",
                successor.version
            )));
        }
        let Some(target) = item.version(target_version) else {
            return Err(StoreError::Invalid(format!(
                "item `{identifier}` has no version `{target_version}`"
            )));
        };
        if target.status != Status::Valid {
            return Err(StoreError::Invalid(format!(
                "version `{target_version}` of `{identifier}` is {} — only the valid version can be superseded",
                target.status.as_str()
            )));
        }
        if let (Some(new_from), Some(target_from)) =
            (successor.effective_from, target.effective_from)
        {
            if new_from < target_from {
                return Err(StoreError::Invalid(format!(
                    "`effective_from` {new_from} precedes the superseded version's window start {target_from}"
                )));
            }
        }
        let prior_status = target.status;
        Ok(self.record(Op::SupersedeVersion {
            identifier: identifier.to_string(),
            superseded_version: target_version.to_string(),
            prior_status,
            successor,
            manifest,
        }))
    }

    /// Adds a dated applicability binding. The profile item must exist
    /// and be of class `profile`; a pinned `profile_version` must be a
    /// registered version of it.
    pub fn bind(&mut self, binding: ApplicabilityBinding) -> Result<AuditRecord, StoreError> {
        let Some(profile) = self.items.get(&binding.profile_item) else {
            return Err(StoreError::Invalid(format!(
                "profile item `{}` is not registered",
                binding.profile_item
            )));
        };
        if profile.item_class != ItemClass::Profile {
            return Err(StoreError::Invalid(format!(
                "item `{}` has class `{}`, not `profile`",
                binding.profile_item, profile.item_class
            )));
        }
        if let Some(pv) = &binding.profile_version {
            if profile.version(pv).is_none() {
                return Err(StoreError::Invalid(format!(
                    "item `{}` has no version `{pv}`",
                    binding.profile_item
                )));
            }
        }
        let mut binding = binding;
        binding.id = self.next_binding_id;
        self.next_binding_id += 1;
        Ok(self.record(Op::BindApplicability { binding }))
    }

    // -- discovery mutations (C3 / C4 / C5) ------------------------------

    /// Registers a new C3 service descriptor (with its first signed
    /// version). The caller has already verified the descriptor's
    /// signature against the operator keyring.
    pub fn register_service(
        &mut self,
        descriptor: ServiceDescriptor,
    ) -> Result<AuditRecord, StoreError> {
        if self.services.contains_key(&descriptor.identifier) {
            return Err(StoreError::Conflict(format!(
                "service `{}` is already registered; add versions through POST /services/{}/versions",
                descriptor.identifier, descriptor.identifier
            )));
        }
        Ok(self.record(Op::RegisterService { descriptor }))
    }

    /// Adds a new signed version of a service descriptor (supersedes
    /// `target_version`, which must be the current active version).
    pub fn supersede_service(
        &mut self,
        identifier: &str,
        target_version: &str,
        successor: crate::discovery::ServiceVersion,
    ) -> Result<AuditRecord, StoreError> {
        let Some(svc) = self.services.get(identifier) else {
            return Err(StoreError::Invalid(format!(
                "no service descriptor `{identifier}`"
            )));
        };
        if svc.version(&successor.version).is_some() {
            return Err(StoreError::Conflict(format!(
                "service `{identifier}` already has a version `{}`",
                successor.version
            )));
        }
        let Some(target) = svc.version(target_version) else {
            return Err(StoreError::Invalid(format!(
                "service `{identifier}` has no version `{target_version}`"
            )));
        };
        if target.status != crate::discovery::ServiceStatus::Active {
            return Err(StoreError::Invalid(format!(
                "service version `{target_version}` of `{identifier}` is {} — only the active version can be superseded",
                target.status.as_str()
            )));
        }
        if successor.effective_from < target.effective_from {
            return Err(StoreError::Invalid(
                "new version's `effective_from` precedes the superseded version's window start"
                    .to_string(),
            ));
        }
        let prior_status = target.status;
        Ok(self.record(Op::SupersedeService {
            identifier: identifier.to_string(),
            superseded_version: target_version.to_string(),
            prior_status,
            successor,
        }))
    }

    /// Registers a C4 protocol binding.
    pub fn register_protocol_binding(
        &mut self,
        binding: ProtocolBinding,
    ) -> Result<AuditRecord, StoreError> {
        if self.protocol_bindings.contains_key(&binding.identifier) {
            return Err(StoreError::Conflict(format!(
                "protocol binding `{}` is already registered",
                binding.identifier
            )));
        }
        Ok(self.record(Op::RegisterProtocolBinding { binding }))
    }

    /// Registers a C5 verification mechanism.
    pub fn register_verification_mechanism(
        &mut self,
        mechanism: VerificationMechanism,
    ) -> Result<AuditRecord, StoreError> {
        if self
            .verification_mechanisms
            .contains_key(&mechanism.identifier)
        {
            return Err(StoreError::Conflict(format!(
                "verification mechanism `{}` is already registered",
                mechanism.identifier
            )));
        }
        Ok(self.record(Op::RegisterVerificationMechanism { mechanism }))
    }

    /// Records a fresh expressir validation outcome for a `model`
    /// item's version (appended to the audit log; the manifest's
    /// `express.validation` block is replaced on apply).
    pub fn update_model_validation(
        &mut self,
        identifier: &str,
        version: &str,
        record: &crate::express::ValidationRecord,
    ) -> Result<AuditRecord, StoreError> {
        let Some(item) = self.items.get(identifier) else {
            return Err(StoreError::Invalid(format!(
                "no registry item `{identifier}`"
            )));
        };
        if item.item_class != ItemClass::Model {
            return Err(StoreError::Invalid(format!(
                "item `{identifier}` has class `{}`, not `model`",
                item.item_class
            )));
        }
        if item.version(version).is_none() {
            return Err(StoreError::Invalid(format!(
                "item `{identifier}` has no version `{version}`"
            )));
        }
        Ok(self.record(Op::UpdateModelValidation {
            identifier: identifier.to_string(),
            version: version.to_string(),
            status: record.status.as_str().to_string(),
            tool: record.tool.clone(),
            detail: record.detail.clone(),
        }))
    }

    // -- audit views ------------------------------------------------------

    /// The append-only audit log (admin view, paged).
    pub fn log_json(&self, limit: usize, offset: usize) -> Value {
        let total = self.log.len();
        let records: Vec<Value> = self
            .log
            .iter()
            .skip(offset)
            .take(limit)
            .map(AuditRecord::to_json)
            .collect();
        json!({
            "total": total,
            "offset": offset,
            "records": records,
        })
    }

    /// Number of records in the audit log (tests and admin stats).
    pub fn log_len(&self) -> usize {
        self.log.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    fn profile_item(id: &str, version: &str, from: &str) -> Item {
        Item {
            identifier: id.to_string(),
            register: "unidpp-dev".to_string(),
            item_class: ItemClass::Profile,
            title: format!("{id} profile"),
            submitting_organization: None,
            versions: vec![ItemVersion {
                version: version.to_string(),
                status: Status::Valid,
                effective_from: Some(ts(from)),
                effective_until: None,
                registered_at: Some(ts("2026-09-01T00:00:00Z")),
                superseded_by_version: None,
                notes: None,
            }],
            manifest: None,
        }
    }

    fn successor(version: &str, from: &str, reason: &str) -> ItemVersion {
        ItemVersion {
            version: version.to_string(),
            status: Status::Valid,
            effective_from: Some(ts(from)),
            effective_until: None,
            registered_at: Some(ts("2026-09-02T00:00:00Z")),
            superseded_by_version: None,
            notes: Some(reason.to_string()),
        }
    }

    #[test]
    fn register_and_lookup() {
        let mut store = Store::open(None).unwrap();
        store
            .register_item(profile_item(
                "eu-espr-textiles",
                "1.0.0",
                "2026-10-18T00:00:00Z",
            ))
            .unwrap();
        assert!(store.item("eu-espr-textiles").is_some());
        assert!(store.item("nope").is_none());
        assert_eq!(store.log_len(), 1);
        // duplicate registration conflicts
        let err = store
            .register_item(profile_item(
                "eu-espr-textiles",
                "2.0.0",
                "2027-01-01T00:00:00Z",
            ))
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }

    #[test]
    fn supersede_transitions_the_old_version() {
        let mut store = Store::open(None).unwrap();
        store
            .register_item(profile_item("p", "0.9.0", "2026-01-01T00:00:00Z"))
            .unwrap();
        store
            .supersede(
                "p",
                "0.9.0",
                successor("1.0.0", "2026-07-01T00:00:00Z", "consolidated edition"),
                None,
            )
            .unwrap();
        let item = store.item("p").unwrap();
        let old = item.version("0.9.0").unwrap();
        assert_eq!(old.status, Status::Superseded);
        assert_eq!(old.superseded_by_version.as_deref(), Some("1.0.0"));
        // derived window end
        assert_eq!(item.window_until(old), Some(ts("2026-07-01T00:00:00Z")));
        assert_eq!(item.current_version().unwrap().version, "1.0.0");
        assert_eq!(store.log_len(), 2);
    }

    #[test]
    fn supersede_rejects_bad_targets() {
        let mut store = Store::open(None).unwrap();
        store
            .register_item(profile_item("p", "0.9.0", "2026-01-01T00:00:00Z"))
            .unwrap();
        store
            .supersede(
                "p",
                "0.9.0",
                successor("1.0.0", "2026-07-01T00:00:00Z", "r"),
                None,
            )
            .unwrap();
        // unknown target
        assert!(matches!(
            store.supersede(
                "p",
                "9.9.9",
                successor("2.0.0", "2027-01-01T00:00:00Z", "r"),
                None
            ),
            Err(StoreError::Invalid(_))
        ));
        // already-superseded target
        assert!(matches!(
            store.supersede(
                "p",
                "0.9.0",
                successor("2.0.0", "2027-01-01T00:00:00Z", "r"),
                None
            ),
            Err(StoreError::Invalid(_))
        ));
        // duplicate version number
        assert!(matches!(
            store.supersede(
                "p",
                "1.0.0",
                successor("1.0.0", "2027-01-01T00:00:00Z", "r"),
                None
            ),
            Err(StoreError::Conflict(_))
        ));
        // window start before the superseded version's window start
        assert!(matches!(
            store.supersede(
                "p",
                "1.0.0",
                successor("2.0.0", "2026-06-01T00:00:00Z", "r"),
                None
            ),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn bind_validates_profile_items() {
        let mut store = Store::open(None).unwrap();
        store
            .register_item(profile_item("p", "1.0.0", "2026-01-01T00:00:00Z"))
            .unwrap();
        store
            .register_item(Item {
                identifier: "unit-kwh".into(),
                register: "unidpp-dev".into(),
                item_class: ItemClass::Unit,
                title: "kilowatt hour".into(),
                submitting_organization: None,
                versions: profile_item("p", "1.0.0", "2026-01-01T00:00:00Z").versions,
                manifest: None,
            })
            .unwrap();
        let binding = |profile: &str| ApplicabilityBinding {
            id: 0,
            subject: "gtin:06901234000016".into(),
            profile_item: profile.into(),
            register: None,
            profile_version: None,
            effective_from: Some(ts("2026-01-01T00:00:00Z")),
            effective_until: None,
            registered_at: Some(ts("2026-09-01T00:00:00Z")),
            retroactive: false,
        };
        // unknown profile item
        assert!(matches!(
            store.bind(binding("nope")),
            Err(StoreError::Invalid(_))
        ));
        // wrong class
        assert!(matches!(
            store.bind(binding("unit-kwh")),
            Err(StoreError::Invalid(_))
        ));
        // good binding gets a sequential id
        let rec = store.bind(binding("p")).unwrap();
        match &rec.op {
            Op::BindApplicability { binding } => assert_eq!(binding.id, 1),
            _ => panic!("expected a bind record"),
        }
        // pinned version must exist
        let mut pinned = binding("p");
        pinned.profile_version = Some("9.9.9".into());
        assert!(matches!(store.bind(pinned), Err(StoreError::Invalid(_))));
    }

    fn model_item(id: &str) -> Item {
        let rec = crate::express::ValidationRecord {
            status: crate::express::ValidationStatus::Pending,
            tool: "expressir".to_string(),
            detail: Some("not available".to_string()),
        };
        Item {
            identifier: id.to_string(),
            register: "unidpp-dev".to_string(),
            item_class: ItemClass::Model,
            title: "express model".to_string(),
            submitting_organization: None,
            versions: vec![ItemVersion {
                version: "1.0.0".to_string(),
                status: Status::Valid,
                effective_from: Some(ts("2026-01-01T00:00:00Z")),
                effective_until: None,
                registered_at: Some(ts("2026-09-07T00:00:00Z")),
                superseded_by_version: None,
                notes: None,
            }],
            manifest: Some(crate::express::model_manifest(
                "1.0.0",
                "SCHEMA m '1.0.0'; END_SCHEMA;",
                &rec,
            )),
        }
    }

    #[test]
    fn update_model_validation_replaces_the_record_and_journals() {
        let dir = std::env::temp_dir().join(format!("unidpp-registry-mv-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut store = Store::open(Some(&path)).unwrap();
            store.register_item(model_item("m")).unwrap();
            let rec = crate::express::ValidationRecord {
                status: crate::express::ValidationStatus::Valid,
                tool: "expressir".to_string(),
                detail: None,
            };
            store.update_model_validation("m", "1.0.0", &rec).unwrap();
            let manifest = store.item("m").unwrap().manifest.clone().unwrap();
            assert_eq!(manifest["express"]["validation"]["status"], "valid");
            // wrong class / unknown item / unknown version are rejected
            store
                .register_item(profile_item("p", "1.0.0", "2026-01-01T00:00:00Z"))
                .unwrap();
            assert!(matches!(
                store.update_model_validation("p", "1.0.0", &rec),
                Err(StoreError::Invalid(_))
            ));
            assert!(matches!(
                store.update_model_validation("nope", "1.0.0", &rec),
                Err(StoreError::Invalid(_))
            ));
            assert!(matches!(
                store.update_model_validation("m", "9.9.9", &rec),
                Err(StoreError::Invalid(_))
            ));
            // register m + update m + register p (the wrong-class probe)
            assert_eq!(store.log_len(), 3);
        }
        // replay re-applies the validation update
        let store = Store::open(Some(&path)).unwrap();
        assert_eq!(store.log_len(), 3);
        let manifest = store.item("m").unwrap().manifest.clone().unwrap();
        assert_eq!(manifest["express"]["validation"]["status"], "valid");
        assert_eq!(
            manifest["express"]["content_hash"],
            crate::express::content_hash("SCHEMA m '1.0.0'; END_SCHEMA;")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn journal_round_trip() {
        let dir = std::env::temp_dir().join(format!("unidpp-registry-test-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut store = Store::open(Some(&path)).unwrap();
            store
                .register_item(profile_item("p", "0.9.0", "2026-01-01T00:00:00Z"))
                .unwrap();
            store
                .supersede(
                    "p",
                    "0.9.0",
                    successor("1.0.0", "2026-07-01T00:00:00Z", "consolidated edition"),
                    Some(serde_json::json!({"profile_id": "p", "version": "1.0.0"})),
                )
                .unwrap();
            let binding = ApplicabilityBinding {
                id: 0,
                subject: "gtin:06901234000016".into(),
                profile_item: "p".into(),
                register: Some("unidpp-dev".into()),
                profile_version: Some("1.0.0".into()),
                effective_from: Some(ts("1996-01-01T00:00:00Z")),
                effective_until: None,
                registered_at: Some(ts("2026-05-01T00:00:00Z")),
                retroactive: true,
            };
            store.bind(binding).unwrap();
        }
        let store = Store::open(Some(&path)).unwrap();
        assert_eq!(store.log_len(), 3);
        let item = store.item("p").unwrap();
        assert_eq!(item.versions.len(), 2);
        assert_eq!(item.version("0.9.0").unwrap().status, Status::Superseded);
        assert_eq!(item.manifest.as_ref().unwrap()["version"], "1.0.0");
        assert_eq!(store.bindings_for("gtin:06901234000016").len(), 1);
        assert_eq!(store.bindings_for("gtin:06901234000016")[0].id, 1);
        let _ = std::fs::remove_file(&path);
    }
}
