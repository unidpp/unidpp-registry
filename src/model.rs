//! Registry model: ISO 19135 items, item versions and applicability
//! bindings — the Rust mirror of unidpp-rb's `Unidpp::Registry`
//! (`Item` / `ItemVersion` / `ApplicabilityBinding`; the read-only
//! Ruby `Client` maps onto this service's HTTP surface, and its
//! queries onto the semantics implemented here).
//!
//! Doctrine (from the Ruby reference, kept verbatim in spirit):
//! - one item = the single definition (I2 — single definition, many
//!   constraints) of a data element, profile, crypto suite, transform,
//!   trust anchor or unit; item references are (register, item,
//!   version) — seam S4: version pinning at the profile↔registry join;
//! - versions are immutable once registered; status and supersession
//!   links express the lifecycle (valid / superseded / retired);
//! - an open `effective_until` is *derived* from the successor's
//!   `effective_from` when absent (`window_until`);
//! - applicability is dated binding, not new identity (source
//!   invariant 9): a retroactive binding legally backdates — it
//!   applies from its `effective_from` even though registered later —
//!   while a non-retroactive one cannot impose obligations for times
//!   before `registered_at`.
//!
//! Wire shapes mirror the Ruby lutaml-model JSON mappings (`render_nil:
//! false` → absent-when-None), with one documented derived addition:
//! each rendered version carries `window_end` (the resolved effective
//! window end; ignored on input).

use std::fmt;

use serde_json::{json, Map, Value};

use crate::time::Timestamp;

// ---------------------------------------------------------------------------
// Item class (subregister)
// ---------------------------------------------------------------------------

/// The item classes (subregisters) a register holds. Mirrors Ruby
/// `Item::ITEM_CLASSES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemClass {
    DataElement,
    Profile,
    CryptoSuite,
    Transform,
    TrustAnchor,
    Unit,
    /// A deposited EXPRESS (or CDDAL) semantic model: source text +
    /// content hash + expressir validation status (item 58 / T-08).
    /// Deposited through the dedicated `POST /models` surface.
    Model,
    /// A mapping between items of two registers, itself a registered
    /// item (item 57 / T-07, ISO 19135 harmonization).
    CrossRegisterMapping,
}

impl ItemClass {
    pub const ALL: [ItemClass; 8] = [
        ItemClass::DataElement,
        ItemClass::Profile,
        ItemClass::CryptoSuite,
        ItemClass::Transform,
        ItemClass::TrustAnchor,
        ItemClass::Unit,
        ItemClass::Model,
        ItemClass::CrossRegisterMapping,
    ];

    /// Canonical (singular) class name, as stored on the item.
    pub fn as_str(self) -> &'static str {
        match self {
            ItemClass::DataElement => "data-element",
            ItemClass::Profile => "profile",
            ItemClass::CryptoSuite => "crypto-suite",
            ItemClass::Transform => "transform",
            ItemClass::TrustAnchor => "trust-anchor",
            ItemClass::Unit => "unit",
            ItemClass::Model => "model",
            ItemClass::CrossRegisterMapping => "cross-register-mapping",
        }
    }

    /// Plural class name — the subregister path segment
    /// (`/data-elements`, `/profiles`, …).
    pub fn plural(self) -> &'static str {
        match self {
            ItemClass::DataElement => "data-elements",
            ItemClass::Profile => "profiles",
            ItemClass::CryptoSuite => "crypto-suites",
            ItemClass::Transform => "transforms",
            ItemClass::TrustAnchor => "trust-anchors",
            ItemClass::Unit => "units",
            ItemClass::Model => "models",
            ItemClass::CrossRegisterMapping => "cross-register-mappings",
        }
    }

    /// Parses a class name in singular or plural form. Underscore
    /// spellings (`cross_register_mapping`) normalize to the
    /// canonical hyphen form.
    pub fn parse(input: &str) -> Option<ItemClass> {
        let t = input.trim().replace('_', "-");
        ItemClass::ALL
            .into_iter()
            .find(|c| c.as_str() == t || c.plural() == t)
    }

    /// Comma-separated canonical class list (error messages).
    pub fn help() -> String {
        ItemClass::ALL
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for ItemClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Lifecycle status
// ---------------------------------------------------------------------------

/// ISO 19135 item lifecycle status. Mirrors Ruby
/// `ItemVersion::STATUSES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Valid,
    Superseded,
    Retired,
}

impl Status {
    pub const VALUES: [Status; 3] = [Status::Valid, Status::Superseded, Status::Retired];

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Valid => "valid",
            Status::Superseded => "superseded",
            Status::Retired => "retired",
        }
    }

    pub fn parse(input: &str) -> Option<Status> {
        Status::VALUES
            .into_iter()
            .find(|s| s.as_str() == input.trim())
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Item version
// ---------------------------------------------------------------------------

/// One version of a registry item with its ISO 19135 lifecycle status.
/// Versions are immutable once registered; status and supersession
/// links express the lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemVersion {
    pub version: String,
    pub status: Status,
    /// Effective window of this version. An open `effective_until` is
    /// derived from the successor's `effective_from` when absent (see
    /// [`Item::window_until`]).
    pub effective_from: Option<Timestamp>,
    pub effective_until: Option<Timestamp>,
    pub registered_at: Option<Timestamp>,
    pub superseded_by_version: Option<String>,
    pub notes: Option<String>,
}

impl ItemVersion {
    /// Was this version in force at `t`, given the resolved window end
    /// (explicit or derived from the successor)? Half-open window
    /// `[from, until)` — Ruby `ItemVersion#in_force_at?` parity.
    pub fn in_force_at(&self, t: Timestamp, until: Option<Timestamp>) -> bool {
        if let Some(from) = self.effective_from {
            if t < from {
                return false;
            }
        }
        if let Some(u) = until {
            if t >= u {
                return false;
            }
        }
        true
    }

    /// Wire form (Ruby `ItemVersion` JSON mapping, plus the derived
    /// `window_end`). `window_end` is derived at render time and
    /// ignored by [`ItemVersion::from_json`].
    pub fn to_json(&self, window_end: Option<Timestamp>) -> Value {
        let mut m = Map::new();
        m.insert("version".into(), json!(self.version));
        m.insert("status".into(), json!(self.status.as_str()));
        if let Some(t) = self.effective_from {
            m.insert("effective_from".into(), json!(t.to_string()));
        }
        if let Some(t) = self.effective_until {
            m.insert("effective_until".into(), json!(t.to_string()));
        }
        if let Some(t) = self.registered_at {
            m.insert("registered_at".into(), json!(t.to_string()));
        }
        if let Some(s) = &self.superseded_by_version {
            m.insert("superseded_by_version".into(), json!(s));
        }
        if let Some(s) = &self.notes {
            m.insert("notes".into(), json!(s));
        }
        if let Some(t) = window_end {
            m.insert("window_end".into(), json!(t.to_string()));
        }
        Value::Object(m)
    }

    /// Parses the canonical wire form (journal replay).
    pub fn from_json(v: &Value) -> Result<ItemVersion, String> {
        let obj = v.as_object().ok_or("item version must be an object")?;
        let get_str = |k: &str| -> Result<Option<String>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
                Some(_) => Err(format!("`{k}` must be a non-empty string")),
            }
        };
        let ts = |k: &str| -> Result<Option<Timestamp>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Timestamp::parse(s).map(Some).map_err(|e| e.to_string()),
                Some(_) => Err(format!("`{k}` must be an RFC 3339 string")),
            }
        };
        Ok(ItemVersion {
            version: get_str("version")?.ok_or("missing `version`")?,
            status: Status::parse(
                obj.get("status")
                    .and_then(Value::as_str)
                    .ok_or("missing/invalid `status`")?,
            )
            .ok_or("invalid `status`")?,
            effective_from: ts("effective_from")?,
            effective_until: ts("effective_until")?,
            registered_at: ts("registered_at")?,
            superseded_by_version: get_str("superseded_by_version")?,
            notes: get_str("notes")?,
        })
    }
}

// ---------------------------------------------------------------------------
// Item
// ---------------------------------------------------------------------------

/// A registry item: the single definition of a data element, profile,
/// crypto suite, transform, trust anchor or unit. Profile items may
/// embed a manifest, version-pinned to one of the item's versions
/// (seam S4); the manifest is carried as an opaque JSON object whose
/// `version` key (when present) must reference a registered version.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub identifier: String,
    pub register: String,
    pub item_class: ItemClass,
    pub title: String,
    /// ISO 19135 submitting organization for this item.
    pub submitting_organization: Option<String>,
    pub versions: Vec<ItemVersion>,
    pub manifest: Option<Value>,
}

impl Item {
    pub fn version(&self, number: &str) -> Option<&ItemVersion> {
        self.versions.iter().find(|v| v.version == number)
    }

    /// Mutable version lookup (lifecycle transitions in the store).
    pub fn version_mut(&mut self, number: &str) -> Option<&mut ItemVersion> {
        self.versions.iter_mut().find(|v| v.version == number)
    }

    /// Versions in registration order (by `effective_from`, then
    /// version) — Ruby `Item#ordered_versions`.
    pub fn ordered_versions(&self) -> Vec<&ItemVersion> {
        let mut vs: Vec<&ItemVersion> = self.versions.iter().collect();
        vs.sort_by_key(|v| {
            (
                v.effective_from.map(|t| t.secs).unwrap_or(i64::MIN),
                v.version.clone(),
            )
        });
        vs
    }

    /// The version currently in force: latest effective version with
    /// status `valid`, else the latest not retired — Ruby
    /// `Item#current_version`.
    pub fn current_version(&self) -> Option<&ItemVersion> {
        let ordered = self.ordered_versions();
        let mut reversed = ordered.into_iter().rev();
        reversed
            .find(|v| v.status == Status::Valid)
            .or_else(|| reversed.find(|v| v.status != Status::Retired))
    }

    /// Resolved effective window end: explicit `effective_until`, else
    /// the successor's `effective_from`, else open — Ruby
    /// `Item#window_until`.
    pub fn window_until(&self, v: &ItemVersion) -> Option<Timestamp> {
        if v.effective_until.is_some() {
            return v.effective_until;
        }
        v.superseded_by_version
            .as_deref()
            .and_then(|n| self.version(n))
            .and_then(|s| s.effective_from)
    }

    /// The version in force at time `t` (point-in-time registry state)
    /// — Ruby `Item#in_force_at`.
    pub fn in_force_at(&self, t: Timestamp) -> Option<&ItemVersion> {
        self.ordered_versions()
            .into_iter()
            .rfind(|v| v.in_force_at(t, self.window_until(v)))
    }

    /// Follows supersession links from the earliest version (or from
    /// `from`, when given) to the terminal version — Ruby
    /// `Item#supersession_chain`. Errors on unknown start versions and
    /// broken/cyclic links.
    pub fn supersession_chain(&self, from: Option<&str>) -> Result<Vec<&ItemVersion>, String> {
        let start = match from {
            Some(n) => self
                .version(n)
                .ok_or_else(|| format!("item `{}` has no version `{}`", self.identifier, n))?,
            None => *self
                .ordered_versions()
                .first()
                .ok_or_else(|| format!("item `{}` has no versions", self.identifier))?,
        };
        let mut chain = vec![start];
        while let Some(next) = chain
            .last()
            .and_then(|v| v.superseded_by_version.as_deref())
        {
            let nv = self.version(next).ok_or_else(|| {
                format!(
                    "item `{}` has no version `{next}` (broken supersession link)",
                    self.identifier
                )
            })?;
            if chain.iter().any(|v| v.version == nv.version) {
                return Err(format!(
                    "supersession cycle at version `{}` of item `{}`",
                    nv.version, self.identifier
                ));
            }
            chain.push(nv);
        }
        Ok(chain)
    }

    /// Seam S4 discipline: an embedded manifest must be pinned to a
    /// version of this item (a manifest without a `version` key is
    /// unpinned).
    pub fn manifest_version_pinned(&self) -> bool {
        let Some(m) = &self.manifest else {
            return true;
        };
        match m.get("version").and_then(Value::as_str) {
            None => false,
            Some(pinned) => self.version(pinned).is_some(),
        }
    }

    /// Wire form (Ruby `Item` JSON mapping; versions carry the derived
    /// `window_end`).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("identifier".into(), json!(self.identifier));
        m.insert("register".into(), json!(self.register));
        m.insert("item_class".into(), json!(self.item_class.as_str()));
        m.insert("title".into(), json!(self.title));
        if let Some(s) = &self.submitting_organization {
            m.insert("submitting_organization".into(), json!(s));
        }
        m.insert(
            "versions".into(),
            Value::Array(
                self.ordered_versions()
                    .into_iter()
                    .map(|v| v.to_json(self.window_until(v)))
                    .collect(),
            ),
        );
        if let Some(man) = &self.manifest {
            m.insert("manifest".into(), man.clone());
        }
        Value::Object(m)
    }

    /// Parses the canonical wire form (journal replay).
    pub fn from_json(v: &Value) -> Result<Item, String> {
        let obj = v.as_object().ok_or("item must be an object")?;
        let req = |k: &str| -> Result<String, String> {
            obj.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("missing `{k}`"))
        };
        let versions = match obj.get("versions") {
            Some(Value::Array(a)) => a
                .iter()
                .map(ItemVersion::from_json)
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("missing `versions` array".into()),
        };
        let class_str = req("item_class")?;
        let item_class = ItemClass::parse(&class_str)
            .ok_or_else(|| format!("unknown `item_class` `{class_str}`"))?;
        Ok(Item {
            identifier: req("identifier")?,
            register: req("register")?,
            item_class,
            title: req("title")?,
            submitting_organization: obj
                .get("submitting_organization")
                .and_then(Value::as_str)
                .map(str::to_string),
            versions,
            manifest: obj.get("manifest").filter(|m| !m.is_null()).cloned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Applicability binding
// ---------------------------------------------------------------------------

/// Applicability binding (source invariant 9): profile-set growth is
/// dated binding, not new identity. Adding a profile to an existing
/// subject is a registry applicability event with an effective window
/// and a retroactivity flag; manifest history is
/// as-of-reconstructable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicabilityBinding {
    /// Sequential binding id (assigned by the store).
    pub id: u64,
    /// Canonical product/type identity (request field `product_type`).
    pub subject: String,
    /// Registry item identifier of the profile (request field
    /// `profile_id`).
    pub profile_item: String,
    /// Register holding the profile.
    pub register: Option<String>,
    /// Optional pin to one version of the profile item.
    pub profile_version: Option<String>,
    pub effective_from: Option<Timestamp>,
    pub effective_until: Option<Timestamp>,
    pub registered_at: Option<Timestamp>,
    pub retroactive: bool,
}

impl ApplicabilityBinding {
    /// Legal as-of semantics: retroactive bindings apply from their
    /// `effective_from` even when registered later; non-retroactive
    /// ones only from `registered_at` — Ruby
    /// `ApplicabilityBinding#applies_at?`.
    pub fn applies_at(&self, t: Timestamp) -> bool {
        if let Some(from) = self.effective_from {
            if t < from {
                return false;
            }
        }
        if let Some(until) = self.effective_until {
            if t >= until {
                return false;
            }
        }
        if !self.retroactive {
            if let Some(r) = self.registered_at {
                if t < r {
                    return false;
                }
            }
        }
        true
    }

    /// Wire form (Ruby `ApplicabilityBinding` JSON mapping, plus the
    /// store-assigned `id`).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert("subject".into(), json!(self.subject));
        m.insert("profile_item".into(), json!(self.profile_item));
        if let Some(s) = &self.register {
            m.insert("register".into(), json!(s));
        }
        if let Some(s) = &self.profile_version {
            m.insert("profile_version".into(), json!(s));
        }
        if let Some(t) = self.effective_from {
            m.insert("effective_from".into(), json!(t.to_string()));
        }
        if let Some(t) = self.effective_until {
            m.insert("effective_until".into(), json!(t.to_string()));
        }
        if let Some(t) = self.registered_at {
            m.insert("registered_at".into(), json!(t.to_string()));
        }
        m.insert("retroactive".into(), json!(self.retroactive));
        Value::Object(m)
    }

    /// Parses the canonical wire form (journal replay).
    pub fn from_json(v: &Value) -> Result<ApplicabilityBinding, String> {
        let obj = v.as_object().ok_or("binding must be an object")?;
        let req = |k: &str| -> Result<String, String> {
            obj.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("missing `{k}`"))
        };
        let opt_str = |k: &str| -> Result<Option<String>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
                Some(_) => Err(format!("`{k}` must be a non-empty string")),
            }
        };
        let ts = |k: &str| -> Result<Option<Timestamp>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Timestamp::parse(s).map(Some).map_err(|e| e.to_string()),
                Some(_) => Err(format!("`{k}` must be an RFC 3339 string")),
            }
        };
        Ok(ApplicabilityBinding {
            id: obj.get("id").and_then(Value::as_u64).unwrap_or(0),
            subject: req("subject")?,
            profile_item: req("profile_item")?,
            register: opt_str("register")?,
            profile_version: opt_str("profile_version")?,
            effective_from: ts("effective_from")?,
            effective_until: ts("effective_until")?,
            registered_at: ts("registered_at")?,
            retroactive: obj
                .get("retroactive")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    fn version(number: &str, from: &str, until: Option<&str>) -> ItemVersion {
        ItemVersion {
            version: number.to_string(),
            status: Status::Valid,
            effective_from: Some(ts(from)),
            effective_until: until.map(ts),
            registered_at: Some(ts("2026-09-01T00:00:00Z")),
            superseded_by_version: None,
            notes: None,
        }
    }

    /// The Ruby spec fixture shape: eu-espr-textiles with a superseded
    /// 0.9.0 (explicit window) and a valid 1.0.0.
    fn eu_espr() -> Item {
        let mut v09 = version(
            "0.9.0",
            "2026-10-18T00:00:00Z",
            Some("2027-10-18T00:00:00Z"),
        );
        v09.status = Status::Superseded;
        v09.superseded_by_version = Some("1.0.0".into());
        v09.notes = Some("first delegated-act edition".into());
        let mut v10 = version("1.0.0", "2027-10-18T00:00:00Z", None);
        v10.notes = Some("consolidated edition".into());
        Item {
            identifier: "eu-espr-textiles".into(),
            register: "unidpp-dev".into(),
            item_class: ItemClass::Profile,
            title: "EU ESPR textiles jurisdiction profile".into(),
            submitting_organization: Some("CEN-CLC/JTC 24".into()),
            versions: vec![v09, v10],
            manifest: None,
        }
    }

    #[test]
    fn item_class_parses_singular_and_plural() {
        assert_eq!(ItemClass::parse("profile"), Some(ItemClass::Profile));
        assert_eq!(
            ItemClass::parse("crypto-suites"),
            Some(ItemClass::CryptoSuite)
        );
        assert_eq!(ItemClass::parse(" unit "), Some(ItemClass::Unit));
        assert_eq!(ItemClass::parse("bogus"), None);
        assert_eq!(ItemClass::Profile.plural(), "profiles");
        assert_eq!(ItemClass::TrustAnchor.as_str(), "trust-anchor");
        // the v3 classes, in hyphen and underscore spellings, both
        // numbers
        assert_eq!(ItemClass::parse("model"), Some(ItemClass::Model));
        assert_eq!(ItemClass::parse("models"), Some(ItemClass::Model));
        assert_eq!(
            ItemClass::parse("cross-register-mapping"),
            Some(ItemClass::CrossRegisterMapping)
        );
        assert_eq!(
            ItemClass::parse("cross_register_mapping"),
            Some(ItemClass::CrossRegisterMapping)
        );
        assert_eq!(
            ItemClass::parse("cross-register-mappings"),
            Some(ItemClass::CrossRegisterMapping)
        );
        assert_eq!(ItemClass::Model.plural(), "models");
        assert_eq!(
            ItemClass::CrossRegisterMapping.plural(),
            "cross-register-mappings"
        );
        assert_eq!(ItemClass::ALL.len(), 8);
    }

    #[test]
    fn explicit_window_end_is_preferred_over_derived() {
        let item = eu_espr();
        let v09 = item.version("0.9.0").unwrap();
        // explicit effective_until wins over the successor's from
        assert_eq!(item.window_until(v09), Some(ts("2027-10-18T00:00:00Z")));
    }

    #[test]
    fn derived_window_end_comes_from_the_successor() {
        let mut v1 = version("1.0.0", "2018-06-01T00:00:00Z", None);
        v1.status = Status::Superseded;
        v1.superseded_by_version = Some("2.0.0".into());
        let v2 = version("2.0.0", "2021-06-01T00:00:00Z", None);
        let item = Item {
            identifier: "historic-vehicle".into(),
            register: "unidpp-dev".into(),
            item_class: ItemClass::Profile,
            title: "Historic vehicle profile".into(),
            submitting_organization: None,
            versions: vec![v1, v2],
            manifest: None,
        };
        assert_eq!(
            item.window_until(item.version("1.0.0").unwrap()),
            Some(ts("2021-06-01T00:00:00Z"))
        );
        assert_eq!(item.window_until(item.version("2.0.0").unwrap()), None);
    }

    #[test]
    fn in_force_at_point_in_time() {
        let item = eu_espr();
        assert_eq!(item.in_force_at(ts("2020-01-01T00:00:00Z")), None);
        assert_eq!(
            item.in_force_at(ts("2027-06-01T00:00:00Z"))
                .unwrap()
                .version,
            "0.9.0"
        );
        assert_eq!(
            item.in_force_at(ts("2028-01-01T00:00:00Z"))
                .unwrap()
                .version,
            "1.0.0"
        );
        // half-open window: at the boundary instant the successor rules
        assert_eq!(
            item.in_force_at(ts("2027-10-18T00:00:00Z"))
                .unwrap()
                .version,
            "1.0.0"
        );
    }

    #[test]
    fn current_version_prefers_valid() {
        let item = eu_espr();
        assert_eq!(item.current_version().unwrap().version, "1.0.0");
    }

    #[test]
    fn supersession_chain_whole_and_from_middle() {
        let mut item = eu_espr();
        let mut v2 = version("2.0.0", "2028-10-18T00:00:00Z", None);
        item.version_mut("1.0.0").unwrap().superseded_by_version = Some("2.0.0".into());
        v2.notes = Some("third edition".into());
        item.versions.push(v2);
        let chain = item.supersession_chain(None).unwrap();
        let versions: Vec<&str> = chain.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(versions, vec!["0.9.0", "1.0.0", "2.0.0"]);
        let statuses: Vec<&str> = chain.iter().map(|v| v.status.as_str()).collect();
        assert_eq!(statuses, vec!["superseded", "valid", "valid"]);
        let from_middle = item.supersession_chain(Some("1.0.0")).unwrap();
        assert_eq!(from_middle.len(), 2);
        // unknown start and broken links error
        assert!(item.supersession_chain(Some("9.9.9")).is_err());
        let mut broken = item.clone();
        broken.versions[2].superseded_by_version = Some("9.9.9".into());
        assert!(broken.supersession_chain(None).is_err());
    }

    #[test]
    fn manifest_version_pinning() {
        let mut item = eu_espr();
        assert!(item.manifest_version_pinned(), "no manifest is pinned");
        item.manifest = Some(json!({"profile_id": "eu-espr-textiles", "version": "1.0.0"}));
        assert!(item.manifest_version_pinned());
        item.manifest = Some(json!({"version": "99.0.0"}));
        assert!(!item.manifest_version_pinned());
        item.manifest = Some(json!({"profile_id": "x"}));
        assert!(
            !item.manifest_version_pinned(),
            "no version key is unpinned"
        );
    }

    #[test]
    fn binding_retroactivity_semantics() {
        let mut b = ApplicabilityBinding {
            id: 0,
            subject: "gtin:06901234000016".into(),
            profile_item: "historic-vehicle".into(),
            register: Some("unidpp-dev".into()),
            profile_version: None,
            effective_from: Some(ts("1996-01-01T00:00:00Z")),
            effective_until: None,
            registered_at: Some(ts("2026-05-01T00:00:00Z")),
            retroactive: true,
        };
        // retroactive: applies from effective_from even before registered_at
        assert!(b.applies_at(ts("2005-06-01T00:00:00Z")));
        assert!(!b.applies_at(ts("1995-12-31T23:59:59Z")));
        // non-retroactive: cannot impose obligations before registered_at
        b.retroactive = false;
        assert!(!b.applies_at(ts("2005-06-01T00:00:00Z")));
        assert!(b.applies_at(ts("2027-01-01T00:00:00Z")));
        // effective_until is exclusive
        b.effective_until = Some(ts("2027-01-01T00:00:00Z"));
        assert!(!b.applies_at(ts("2027-01-01T00:00:00Z")));
        assert!(b.applies_at(ts("2026-12-31T23:59:59Z")));
    }

    #[test]
    fn json_round_trip_item_and_binding() {
        let item = eu_espr();
        let round = Item::from_json(&item.to_json()).unwrap();
        assert_eq!(round, item);
        let binding = ApplicabilityBinding {
            id: 7,
            subject: "gtin:06901234000016".into(),
            profile_item: "eu-espr-textiles".into(),
            register: None,
            profile_version: Some("1.0.0".into()),
            effective_from: Some(ts("2026-10-18T00:00:00Z")),
            effective_until: None,
            registered_at: Some(ts("2026-09-01T00:00:00Z")),
            retroactive: false,
        };
        assert_eq!(
            ApplicabilityBinding::from_json(&binding.to_json()).unwrap(),
            binding
        );
        // the derived window_end is ignored on parse
        let mut v = item.to_json();
        v["versions"][0]["window_end"] = json!("1999-01-01T00:00:00Z");
        assert_eq!(Item::from_json(&v).unwrap(), item);
    }
}
