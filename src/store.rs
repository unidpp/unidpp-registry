//! Registry store: items keyed by identifier, applicability bindings,
//! and the append-only audit log of every registry mutation. The
//! optional JSONL journal persists the audit log and is replayed on
//! start — the log *is* the storage (nothing is edited in place;
//! lifecycle transitions are appended operations, mirroring the
//! resolver's I4 doctrine and the Ruby model's immutable versions).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde_json::{json, Value};

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
        let seq = obj.get("seq").and_then(Value::as_u64).ok_or("missing `seq`")?;
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
            _ => return Err("unknown `op`".to_string()),
        };
        Ok(AuditRecord { seq, recorded_at, op })
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
/// applicability bindings, the audit log, and the JSONL journal.
pub struct Store {
    items: HashMap<String, Item>,
    bindings: Vec<ApplicabilityBinding>,
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
            store.journal = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            );
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
        }
    }

    // -- reads ----------------------------------------------------------

    pub fn item(&self, identifier: &str) -> Option<&Item> {
        self.items.get(identifier)
    }

    /// Items filtered by item class and/or register.
    pub fn items_filtered(
        &self,
        class: Option<ItemClass>,
        register: Option<&str>,
    ) -> Vec<&Item> {
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
        self.bindings.iter().filter(|b| b.subject == subject).collect()
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
            .register_item(profile_item("eu-espr-textiles", "1.0.0", "2026-10-18T00:00:00Z"))
            .unwrap();
        assert!(store.item("eu-espr-textiles").is_some());
        assert!(store.item("nope").is_none());
        assert_eq!(store.log_len(), 1);
        // duplicate registration conflicts
        let err = store
            .register_item(profile_item("eu-espr-textiles", "2.0.0", "2027-01-01T00:00:00Z"))
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
        assert_eq!(
            item.window_until(old),
            Some(ts("2026-07-01T00:00:00Z"))
        );
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
            .supersede("p", "0.9.0", successor("1.0.0", "2026-07-01T00:00:00Z", "r"), None)
            .unwrap();
        // unknown target
        assert!(matches!(
            store.supersede("p", "9.9.9", successor("2.0.0", "2027-01-01T00:00:00Z", "r"), None),
            Err(StoreError::Invalid(_))
        ));
        // already-superseded target
        assert!(matches!(
            store.supersede("p", "0.9.0", successor("2.0.0", "2027-01-01T00:00:00Z", "r"), None),
            Err(StoreError::Invalid(_))
        ));
        // duplicate version number
        assert!(matches!(
            store.supersede("p", "1.0.0", successor("1.0.0", "2027-01-01T00:00:00Z", "r"), None),
            Err(StoreError::Conflict(_))
        ));
        // window start before the superseded version's window start
        assert!(matches!(
            store.supersede("p", "1.0.0", successor("2.0.0", "2026-06-01T00:00:00Z", "r"), None),
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
