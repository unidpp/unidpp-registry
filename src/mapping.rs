//! Cross-register mappings as registered items (T-07 / item 57,
//! ISO 19135 harmonization): a mapping between items of two
//! registers is itself a register item, with referential integrity
//! validated at intake — both ends must exist.
//!
//! Manifest shape:
//!
//! ```json
//! {
//!   "version": "1.0.0",
//!   "source": {"register": "gb-std", "item": "gb-4943-1", "version": "2022"},
//!   "target": {"register": "iec", "item": "iec-62368-1", "version": null},
//!   "mapping_type": "equivalent",
//!   "attester": "CQC-pattern notified body",
//!   "evidence_ref": "https://example/mapping-evidence"
//! }
//! ```
//!
//! `mapping_type` is the harmonization relation:
//! `equivalent` | `narrower` | `broader` | `related`. The
//! GB 4943.1-2022 ↔ IEC 62368-1 equivalence is the first instance
//! of this class (the pilot's `equiv-gb4943-iec62368` transform
//! item is its predecessor).

use serde_json::{json, Value};

use crate::model::{Item, ItemClass};
use crate::schema::SchemaError;
use crate::store::Store;

/// Harmonization relations (ISO 19135-style mapping types).
pub const MAPPING_TYPES: [&str; 4] = ["equivalent", "narrower", "broader", "related"];

/// The item class this module governs.
pub const ITEM_CLASS: ItemClass = ItemClass::CrossRegisterMapping;

/// A reference to one end of a mapping: a (register, item, version)
/// triple. `register` and `version` are optional qualifiers; `item`
/// is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    pub register: Option<String>,
    pub item: String,
    pub version: Option<String>,
}

/// A cross-register mapping manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossRegisterMapping {
    pub source: ItemRef,
    pub target: ItemRef,
    pub mapping_type: String,
    pub attester: Option<String>,
    pub evidence_ref: Option<String>,
}

/// The generated JSON Schema (draft 2020-12) for the mapping
/// manifest.
pub fn cross_register_mapping_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://unidpp.org/schemas/cross-register-mapping/v1",
        "title": "UniDPP cross-register mapping",
        "description": "A mapping between items of two registers, itself a registered item \
    (ISO 19135 harmonization). Both ends are validated for referential integrity at intake.",
        "type": "object",
        "required": ["version", "source", "target", "mapping_type"],
        "properties": {
            "version": {"type": "string", "minLength": 1},
            "source": {"$ref": "#/$defs/item_ref"},
            "target": {"$ref": "#/$defs/item_ref"},
            "mapping_type": {"type": "string", "enum": MAPPING_TYPES.to_vec()},
            "attester": {"type": "string", "minLength": 1},
            "evidence_ref": {"type": "string", "minLength": 1}
        },
        "additionalProperties": true,
        "$defs": {
            "item_ref": {
                "type": "object",
                "required": ["item"],
                "properties": {
                    "register": {"type": "string", "minLength": 1},
                    "item": {"type": "string", "minLength": 1},
                    "version": {"type": "string", "minLength": 1}
                },
                "additionalProperties": true
            }
        }
    })
}

/// Schema-level validation of a mapping manifest.
pub fn validate_manifest(manifest: &Value) -> Result<(), Vec<SchemaError>> {
    crate::schema::validate(&cross_register_mapping_schema(), manifest)
}

/// Typed parse of a schema-valid mapping manifest.
pub fn parse(manifest: &Value) -> Result<CrossRegisterMapping, String> {
    let obj = manifest
        .as_object()
        .ok_or("mapping manifest must be an object")?;
    let req = |k: &str| -> Result<String, String> {
        obj.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("mapping manifest missing `{k}`"))
    };
    let opt = |k: &str| -> Result<Option<String>, String> {
        match obj.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
            Some(_) => Err(format!("`{k}` must be a non-empty string")),
        }
    };
    let item_ref = |side: &str| -> Result<ItemRef, String> {
        let v = obj
            .get(side)
            .ok_or_else(|| format!("mapping manifest missing `{side}`"))?;
        let o = v
            .as_object()
            .ok_or_else(|| format!("`{side}` must be an object"))?;
        let inner_opt = |k: &str| -> Result<Option<String>, String> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
                Some(_) => Err(format!("`{side}.{k}` must be a non-empty string")),
            }
        };
        let item = o
            .get("item")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("`{side}.item` is required"))?
            .to_string();
        Ok(ItemRef {
            register: inner_opt("register")?,
            item,
            version: inner_opt("version")?,
        })
    };
    Ok(CrossRegisterMapping {
        source: item_ref("source")?,
        target: item_ref("target")?,
        mapping_type: req("mapping_type")?,
        attester: opt("attester")?,
        evidence_ref: opt("evidence_ref")?,
    })
}

/// Referential integrity: both ends of the mapping must resolve to
/// registered items (register attribute matching when given, version
/// existing when pinned). Pure over the store — no mutation.
pub fn integrity_errors(mapping: &CrossRegisterMapping, store: &Store) -> Vec<SchemaError> {
    let mut errors = Vec::new();
    for (side, r) in [("source", &mapping.source), ("target", &mapping.target)] {
        let Some(found) = store.item(&r.item) else {
            errors.push(SchemaError {
                path: format!("{side}.item"),
                message: format!(
                    "dangling reference: no registry item `{}` (cross-register mappings must reference items that exist)",
                    r.item
                ),
            });
            continue;
        };
        if let Some(claimed) = &r.register {
            if *claimed != found.register {
                errors.push(SchemaError {
                    path: format!("{side}.register"),
                    message: format!(
                        "item `{}` belongs to register `{}`, not `{claimed}`",
                        r.item, found.register
                    ),
                });
            }
        }
        if let Some(v) = &r.version {
            if found.version(v).is_none() {
                errors.push(SchemaError {
                    path: format!("{side}.version"),
                    message: format!("item `{}` has no version `{v}`", r.item),
                });
            }
        }
    }
    errors
}

/// Does this item's manifest match a lookup filter? `item` matches
/// either direction; `source`/`target` match the named side.
pub fn matches_query(
    item: &Item,
    lookup_item: Option<&str>,
    source: Option<&str>,
    target: Option<&str>,
) -> bool {
    if item.item_class != ITEM_CLASS {
        return false;
    }
    let Some(manifest) = &item.manifest else {
        return false;
    };
    let side_item = |side: &str| {
        manifest
            .get(side)
            .and_then(Value::as_object)
            .and_then(|o| o.get("item"))
            .and_then(Value::as_str)
    };
    if let Some(want) = lookup_item {
        if side_item("source") != Some(want) && side_item("target") != Some(want) {
            return false;
        }
    }
    if let Some(want) = source {
        if side_item("source") != Some(want) {
            return false;
        }
    }
    if let Some(want) = target {
        if side_item("target") != Some(want) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Item, ItemClass, ItemVersion, Status};
    use crate::store::Store;
    use serde_json::json;

    fn ts(s: &str) -> crate::time::Timestamp {
        crate::time::Timestamp::parse(s).unwrap()
    }

    fn item(id: &str, register: &str, class: ItemClass) -> Item {
        Item {
            identifier: id.to_string(),
            register: register.to_string(),
            item_class: class,
            title: format!("{id} title"),
            submitting_organization: None,
            versions: vec![ItemVersion {
                version: "1.0.0".to_string(),
                status: Status::Valid,
                effective_from: Some(ts("2026-01-01T00:00:00Z")),
                effective_until: None,
                registered_at: Some(ts("2026-01-01T00:00:00Z")),
                superseded_by_version: None,
                notes: None,
            }],
            manifest: None,
        }
    }

    fn mapping_manifest() -> Value {
        json!({
            "version": "1.0.0",
            "source": {"register": "gb-std", "item": "gb-4943-1", "version": "1.0.0"},
            "target": {"register": "iec", "item": "iec-62368-1"},
            "mapping_type": "equivalent",
            "attester": "CQC-pattern notified body",
            "evidence_ref": "https://example/evidence"
        })
    }

    #[test]
    fn schema_and_parse_round_trip() {
        let doc = mapping_manifest();
        assert!(validate_manifest(&doc).is_ok());
        let m = parse(&doc).unwrap();
        assert_eq!(m.source.item, "gb-4943-1");
        assert_eq!(m.source.version.as_deref(), Some("1.0.0"));
        assert_eq!(m.target.register.as_deref(), Some("iec"));
        assert_eq!(m.mapping_type, "equivalent");
        assert_eq!(m.attester.as_deref(), Some("CQC-pattern notified body"));
    }

    #[test]
    fn schema_rejects_malformed_mappings_with_paths() {
        let mut doc = mapping_manifest();
        doc["mapping_type"] = json!("same-ish");
        let e = validate_manifest(&doc).unwrap_err();
        assert_eq!(e[0].path, "mapping_type");
        let mut doc = mapping_manifest();
        doc["source"] = json!({"register": "gb-std"});
        let e = validate_manifest(&doc).unwrap_err();
        assert!(e
            .iter()
            .any(|x| x.path == "source" && x.message.contains("`item` is missing")));
        let mut doc = mapping_manifest();
        doc.as_object_mut().unwrap().remove("target");
        let e = validate_manifest(&doc).unwrap_err();
        assert!(e
            .iter()
            .any(|x| x.path.is_empty() && x.message.contains("`target` is missing")));
    }

    #[test]
    fn integrity_catches_dangling_references() {
        let mut store = Store::open(None).unwrap();
        store
            .register_item(item("gb-4943-1", "gb-std", ItemClass::DataElement))
            .unwrap();
        let m = parse(&mapping_manifest()).unwrap();
        // target does not exist
        let e = integrity_errors(&m, &store);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].path, "target.item");
        assert!(e[0].message.contains("dangling"));
        // both ends exist → clean
        store
            .register_item(item("iec-62368-1", "iec", ItemClass::DataElement))
            .unwrap();
        assert!(integrity_errors(&m, &store).is_empty());
    }

    #[test]
    fn integrity_catches_register_and_version_mismatches() {
        let mut store = Store::open(None).unwrap();
        store
            .register_item(item("gb-4943-1", "gb-std", ItemClass::DataElement))
            .unwrap();
        store
            .register_item(item("iec-62368-1", "iec", ItemClass::DataElement))
            .unwrap();
        // wrong register claim
        let mut doc = mapping_manifest();
        doc["target"]["register"] = json!("cen");
        let e = integrity_errors(&parse(&doc).unwrap(), &store);
        assert_eq!(e[0].path, "target.register");
        // unregistered version pin
        let mut doc = mapping_manifest();
        doc["source"]["version"] = json!("9.9.9");
        let e = integrity_errors(&parse(&doc).unwrap(), &store);
        assert_eq!(e[0].path, "source.version");
        // unpinned version (absent) is fine
        let mut doc = mapping_manifest();
        doc["source"].as_object_mut().unwrap().remove("version");
        assert!(integrity_errors(&parse(&doc).unwrap(), &store).is_empty());
    }

    #[test]
    fn lookup_matches_either_direction() {
        let mut store = Store::open(None).unwrap();
        store
            .register_item(item("gb-4943-1", "gb-std", ItemClass::DataElement))
            .unwrap();
        let mut m = item("map-gb-iec", "unidpp-dev", ITEM_CLASS);
        m.manifest = Some(mapping_manifest());
        // by either side
        assert!(matches_query(&m, Some("gb-4943-1"), None, None));
        assert!(matches_query(&m, Some("iec-62368-1"), None, None));
        assert!(!matches_query(&m, Some("other"), None, None));
        // by named side
        assert!(matches_query(&m, None, Some("gb-4943-1"), None));
        assert!(matches_query(&m, None, None, Some("iec-62368-1")));
        assert!(!matches_query(&m, None, Some("iec-62368-1"), None));
        // combined
        assert!(matches_query(
            &m,
            None,
            Some("gb-4943-1"),
            Some("iec-62368-1")
        ));
        // other classes never match
        let not_a_mapping = item("x", "unidpp-dev", ItemClass::Transform);
        assert!(!matches_query(
            &not_a_mapping,
            Some("gb-4943-1"),
            None,
            None
        ));
    }
}
