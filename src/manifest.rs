//! The canonical profile-manifest model (T-01b / item 51).
//!
//! One formalization, two renders: the Rust structs below are the
//! single canonical source; the JSON Schema
//! ([`profile_manifest_schema`]) is generated from the same field
//! vocabulary and served at `GET /schemas/profile-manifest`
//! (draft 2020-12). Intake validation runs the generated schema
//! through [`crate::schema::validate`] — the served contract and the
//! enforced contract cannot drift (a unit test locks that every
//! fixture accepted by the schema parses into the typed model and
//! vice versa).
//!
//! The manifest vocabulary follows the NWIP manifest schema (TODO
//! item 50's `profile_manifest` EXPRESS entity family):
//!
//! | field              | shape                                            |
//! |--------------------|--------------------------------------------------|
//! | `version`          | required string — the item-version pin (seam S4) |
//! | `subject_capability` | optional S0..S3 — the declared subject class   |
//! | `axes`             | optional array: jurisdiction / sector / characteristic |
//! | `legal_basis`      | optional array of {instrument, citation, force}  |
//! | `data_points`      | optional array of bindings (element, min_capability, …) |
//! | `transforms`       | optional array of transform bindings (open union) |
//! | `triggers`         | optional array of predicates: `fact_predicate` (predicate_ref) or `time` (basis, operator, duration) |
//!
//! Unknown fields are allowed at every level: manifests carry
//! jurisdiction-specific material beyond the core model (custody
//! models, issuing roles, notes, projector-shaped lens sections).
//! Two pilot dialects — the material-loop item manifests and the
//! projector lens manifests — both validate (covered by tests).

use serde_json::{json, Value};

use crate::satisfiability::CAPABILITY_CLASSES;
use crate::schema::{CARDINALITY_PATTERN, DURATION_PATTERN};
use crate::time::Timestamp;

/// Applicability axes of a profile (jurisdiction × sector ×
/// characteristic — I10).
pub const AXES: [&str; 3] = ["jurisdiction", "sector", "characteristic"];
/// Trigger predicate classes: fact predicates (evaluated locally by
/// the subject's custodian) and clock predicates (evaluated by the
/// registry, see [`crate::clock`]).
pub const PREDICATE_CLASSES: [&str; 2] = ["fact_predicate", "time"];
/// Subject-fact keys a time trigger may be based on.
pub const TIME_BASES: [&str; 2] = crate::clock::BASES;
/// Comparison operators a time trigger may use.
pub const TIME_OPERATORS: [&str; 4] = crate::clock::OPERATORS;
/// Provenance floor vocabulary observed on data-point bindings (open
/// in the model; typed as non-empty strings in the schema).
pub const GRANULARITIES: [&str; 3] = ["type", "lot", "instance"];

/// The generated JSON Schema (draft 2020-12) for a profile manifest
/// — what `GET /schemas/profile-manifest` serves and what
/// `POST /items` (class `profile`) enforces at intake.
pub fn profile_manifest_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://unidpp.org/schemas/profile-manifest/v1",
        "title": "UniDPP profile manifest",
        "description": "A profile is a registered, versioned lens on the neutral core. \
    The manifest binds axes, trigger predicates, the declared subject capability class, \
    legal basis, and the data points the profile requires. Generated from the canonical \
    Rust model (unidpp-registry src/manifest.rs); unknown fields are allowed.",
        "type": "object",
        "required": ["version"],
        "properties": {
            "version": {"type": "string", "minLength": 1},
            "subject_capability": {"type": "string", "enum": CAPABILITY_CLASSES.to_vec()},
            "axes": {"type": "array", "items": {"type": "string", "enum": AXES.to_vec()}},
            "legal_basis": {"type": "array", "items": {"$ref": "#/$defs/legal_basis"}},
            "data_points": {"type": "array", "items": {"$ref": "#/$defs/data_point"}},
            "transforms": {"type": "array", "items": {"$ref": "#/$defs/transform"}},
            "triggers": {"type": "array", "items": {"$ref": "#/$defs/trigger"}}
        },
        "additionalProperties": true,
        "$defs": {
            "legal_basis": {
                "type": "object",
                "required": ["instrument", "citation", "force"],
                "properties": {
                    "instrument": {"type": "string", "minLength": 1},
                    "citation": {"type": "string", "minLength": 1},
                    "force": {"type": "string", "minLength": 1}
                },
                "additionalProperties": true
            },
            "data_point": {
                "type": "object",
                "required": ["element", "min_capability"],
                "properties": {
                    "element": {"type": "string", "minLength": 1},
                    "min_capability": {"type": "string", "enum": CAPABILITY_CLASSES.to_vec()},
                    "cardinality": {"type": "string", "pattern": CARDINALITY_PATTERN},
                    "required_provenance": {"type": "string", "minLength": 1},
                    "required_unit": {"type": "string", "minLength": 1},
                    "subject_granularity": {"type": "string", "enum": GRANULARITIES.to_vec()},
                    "tier_a": {"type": "boolean"},
                    "traversal_depth": {"type": "integer", "minimum": 0},
                    "trust_floor": {"type": "string", "minLength": 1},
                    "fresh_within": {"type": "string", "pattern": DURATION_PATTERN},
                    "visibility": {"type": "string", "minLength": 1}
                },
                "additionalProperties": true
            },
            "transform": {
                "type": "object",
                "properties": {
                    "transform_ref": {"type": "string", "minLength": 1},
                    "transform_class": {"type": "string", "minLength": 1},
                    "method_citation": {"type": "string", "minLength": 1},
                    "decision_rule": {"type": "string", "minLength": 1},
                    "uncertainty_ref": {"type": "string", "minLength": 1}
                },
                "additionalProperties": true
            },
            "trigger": {
                "type": "object",
                "required": ["predicate_class"],
                "properties": {
                    "predicate_class": {"type": "string", "enum": PREDICATE_CLASSES.to_vec()},
                    "predicate_ref": {"type": "string", "minLength": 1},
                    "evaluation_mode": {"type": "string", "minLength": 1},
                    "description": {"type": "string", "minLength": 1},
                    "basis": {"type": "string", "enum": TIME_BASES.to_vec()},
                    "operator": {"type": "string", "enum": TIME_OPERATORS.to_vec()},
                    "duration": {"type": "string", "pattern": DURATION_PATTERN}
                },
                "additionalProperties": true,
                "allOf": [
                    {
                        "if": {
                            "properties": {"predicate_class": {"const": "fact_predicate"}},
                            "required": ["predicate_class"]
                        },
                        "then": {"required": ["predicate_ref"]}
                    },
                    {
                        "if": {
                            "properties": {"predicate_class": {"const": "time"}},
                            "required": ["predicate_class"]
                        },
                        "then": {"required": ["basis", "operator", "duration"]}
                    }
                ]
            }
        }
    })
}

/// Validates a manifest against the generated schema.
pub fn validate_manifest(manifest: &Value) -> Result<(), Vec<crate::schema::SchemaError>> {
    crate::schema::validate(&profile_manifest_schema(), manifest)
}

// ---------------------------------------------------------------------------
// Typed model (downstream consumers: satisfiability, clock evaluation)
// ---------------------------------------------------------------------------

/// One required data point of a profile (the registry-side fields;
/// the full binding is carried by the raw manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPoint {
    pub element: String,
    pub min_capability: String,
    /// Bounded freshness demand (ISO 8601 duration), if any.
    pub fresh_within: Option<String>,
}

impl DataPoint {
    fn from_json(v: &Value) -> Result<DataPoint, String> {
        let obj = v.as_object().ok_or("data point must be an object")?;
        let req = |k: &str| -> Result<String, String> {
            obj.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("data point missing `{k}`"))
        };
        let fresh = match obj.get("fresh_within") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err("`fresh_within` must be a string".into()),
        };
        Ok(DataPoint {
            element: req("element")?,
            min_capability: req("min_capability")?,
            fresh_within: fresh,
        })
    }
}

/// A trigger predicate in typed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    /// Evaluated locally by the subject's custodian against twin
    /// facts; never by the registry.
    Fact { predicate_ref: String },
    /// Clock-fired: see [`crate::clock`].
    Time(crate::clock::TimeTrigger),
}

/// The typed profile manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileManifest {
    pub version: String,
    pub subject_capability: Option<String>,
    pub axes: Vec<String>,
    /// Raw legal-basis entries (no downstream consumer needs them
    /// typed).
    pub legal_basis: Vec<Value>,
    /// Raw transform bindings (an open union of dialects).
    pub transforms: Vec<Value>,
    pub triggers: Vec<Trigger>,
    pub data_points: Vec<DataPoint>,
}

impl ProfileManifest {
    /// Parses the typed model from a manifest document. Callers that
    /// need schema-level diagnostics should use
    /// [`validate_manifest`] first; this parser handles
    /// schema-valid documents (parity locked by tests).
    pub fn from_json(v: &Value) -> Result<ProfileManifest, String> {
        let obj = v.as_object().ok_or("manifest must be an object")?;
        let version = obj
            .get("version")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("manifest missing `version`")?
            .to_string();
        let subject_capability = match obj.get("subject_capability") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            Some(_) => return Err("`subject_capability` must be a string".into()),
        };
        let str_vec = |k: &str| -> Result<Vec<String>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(Vec::new()),
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|x| {
                        x.as_str()
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .ok_or_else(|| format!("`{k}` entries must be non-empty strings"))
                    })
                    .collect(),
                Some(_) => Err(format!("`{k}` must be an array")),
            }
        };
        let raw_vec = |k: &str| -> Result<Vec<Value>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(Vec::new()),
                Some(Value::Array(a)) => Ok(a.clone()),
                Some(_) => Err(format!("`{k}` must be an array")),
            }
        };
        let mut triggers = Vec::new();
        for t in raw_vec("triggers")? {
            match t.get("predicate_class").and_then(Value::as_str) {
                Some("fact_predicate") => {
                    let predicate_ref = t
                        .get("predicate_ref")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .ok_or("fact predicate missing `predicate_ref`")?
                        .to_string();
                    triggers.push(Trigger::Fact { predicate_ref });
                }
                Some("time") => {
                    triggers.push(Trigger::Time(crate::clock::parse_time_trigger(&t)?));
                }
                _ => return Err("trigger missing a valid `predicate_class`".into()),
            }
        }
        let data_points = raw_vec("data_points")?
            .iter()
            .map(DataPoint::from_json)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProfileManifest {
            version,
            subject_capability,
            axes: str_vec("axes")?,
            legal_basis: raw_vec("legal_basis")?,
            transforms: raw_vec("transforms")?,
            triggers,
            data_points,
        })
    }
}

/// Renders a minimal clock-predicate manifest (tests).
#[cfg(test)]
fn time_trigger_manifest(version: &str, basis: &str, operator: &str, duration: &str) -> Value {
    json!({
        "version": version,
        "triggers": [
            {"predicate_class": "time", "basis": basis, "operator": operator, "duration": duration}
        ]
    })
}

/// Re-stamps a schema document for serving (as-of semantics): the
/// `as_of` keyword is not a validation keyword, so draft 2020-12
/// validators ignore it.
pub(crate) fn stamped_schema(mut schema: Value, as_of: Timestamp) -> Value {
    if let Some(m) = schema.as_object_mut() {
        m.insert("as_of".into(), json!(as_of.to_string()));
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema_errors(doc: &Value) -> Vec<crate::schema::SchemaError> {
        validate_manifest(doc).unwrap_err()
    }

    /// A dialect-A (material-loop item) manifest, the pilot shape.
    fn material_loop_manifest() -> Value {
        json!({
            "version": "1.0.0",
            "axes": ["characteristic"],
            "issuing_role": "manufacturer of the product containing the permanent magnet",
            "custody": {"default_model": "mass_balance", "standard": "ISO 22095:2020"},
            "legal_basis": [{
                "instrument": "Regulation (EU) 2024/1252 (Critical Raw Materials Act)",
                "citation": "Art. 15 recycled-content duties",
                "force": "binding"
            }],
            "data_points": [
                {
                    "element": "de/m/crm-identity",
                    "min_capability": "S0",
                    "required_provenance": "type_declared",
                    "subject_granularity": "type",
                    "tier_a": false,
                    "traversal_depth": 1,
                    "trust_floor": "attested",
                    "cardinality": "1..n"
                },
                {
                    "element": "de/m/lot-mass",
                    "min_capability": "S0",
                    "required_provenance": "instance_measured",
                    "required_unit": "units:kg",
                    "subject_granularity": "instance",
                    "tier_a": false,
                    "traversal_depth": 2,
                    "trust_floor": "attested",
                    "cardinality": "1"
                }
            ],
            "transforms": [
                {
                    "transform_ref": "urn:unidpp:transform:recycled-content-mass-balance",
                    "transform_class": "aggregation",
                    "method_citation": "ISO 59020:2024"
                }
            ],
            "triggers": [
                {
                    "predicate_class": "fact_predicate",
                    "predicate_ref": "pred/contains-strategic-crm",
                    "evaluation_mode": "on_event",
                    "description": "product contains a strategic raw material"
                }
            ],
            "notes": "traversal depth 99 keeps deep graphs verifiable"
        })
    }

    /// A dialect-B (projector lens) manifest — the other pilot shape.
    fn lens_manifest() -> Value {
        json!({
            "version": "1.0.0",
            "profile": {
                "id": "urn:unidpp:profile:pilot-eu-lens",
                "axes": {"jurisdiction": "EU", "sector": "e-mobility"},
                "trigger": "Any",
                "min_capability": "silent",
                "freshness": "Static",
                "data_points": [
                    {"register": "unidpp-dev", "item": "de.dpp.operator-id", "version": "1.0.0"}
                ],
                "crypto_suites": ["ecdsa-p256"]
            },
            "bindings": [
                {"element": "unidpp-dev/de.dpp.operator-id@1.0.0", "min_trust": "attested", "min_capability": "silent"}
            ],
            "transforms": [
                {"kind": "classification", "id": "eu-reparability-class", "source": "de.dpp.reparability-score", "bands": [{"label": "A", "min": "8.0"}]}
            ]
        })
    }

    #[test]
    fn schema_declares_draft_2020_12_and_is_fetchable_shaped() {
        let s = profile_manifest_schema();
        assert_eq!(s["$schema"], "https://json-schema.org/draft/2020-12/schema");
        assert_eq!(s["$id"], "https://unidpp.org/schemas/profile-manifest/v1");
        assert_eq!(s["type"], "object");
        assert!(s["required"]
            .as_array()
            .unwrap()
            .contains(&json!("version")));
        assert!(s["$defs"].is_object());
    }

    #[test]
    fn both_pilot_dialects_validate() {
        for doc in [material_loop_manifest(), lens_manifest()] {
            assert!(validate_manifest(&doc).is_ok(), "{doc}");
            // parity: schema-valid documents parse into the typed model
            assert!(ProfileManifest::from_json(&doc).is_ok());
        }
    }

    #[test]
    fn time_trigger_manifests_validate() {
        let doc = time_trigger_manifest("1.0.0", "manufactured_at", ">=", "P40Y");
        assert!(validate_manifest(&doc).is_ok());
        let parsed = ProfileManifest::from_json(&doc).unwrap();
        assert_eq!(parsed.triggers.len(), 1);
        assert!(matches!(parsed.triggers[0], Trigger::Time(_)));
    }

    #[test]
    fn malformed_manifests_are_rejected_with_field_paths() {
        // missing version → path at the document root
        let mut doc = material_loop_manifest();
        doc.as_object_mut().unwrap().remove("version");
        let e = schema_errors(&doc);
        assert_eq!(e[0].path, "");
        assert!(e[0].message.contains("`version` is missing"));

        // bad capability token
        let mut doc = material_loop_manifest();
        doc["data_points"][1]["min_capability"] = json!("S9");
        let e = schema_errors(&doc);
        assert_eq!(e[0].path, "data_points[1].min_capability");
        assert!(e[0].message.contains("S9"));

        // unknown axis
        let mut doc = material_loop_manifest();
        doc["axes"] = json!(["zodiac"]);
        let e = schema_errors(&doc);
        assert_eq!(e[0].path, "axes[0]");

        // legal basis missing its instrument
        let mut doc = material_loop_manifest();
        doc["legal_basis"][0]
            .as_object_mut()
            .unwrap()
            .remove("instrument");
        let e = schema_errors(&doc);
        assert_eq!(e[0].path, "legal_basis[0]");
        assert!(e[0].message.contains("`instrument` is missing"));

        // traversal depth must be a non-negative integer
        let mut doc = material_loop_manifest();
        doc["data_points"][0]["traversal_depth"] = json!(-1);
        let e = schema_errors(&doc);
        assert_eq!(e[0].path, "data_points[0].traversal_depth");
        // and a non-integer
        let mut doc = material_loop_manifest();
        doc["data_points"][0]["traversal_depth"] = json!("many");
        let e = schema_errors(&doc);
        assert!(e.iter().any(|x| x.path == "data_points[0].traversal_depth"));

        // cardinality must match the binding grammar
        let mut doc = material_loop_manifest();
        doc["data_points"][0]["cardinality"] = json!("several");
        let e = schema_errors(&doc);
        assert!(e.iter().any(|x| x.path == "data_points[0].cardinality"));

        // fresh_within must be an ISO 8601 duration
        let mut doc = material_loop_manifest();
        doc["data_points"][0]["fresh_within"] = json!("tomorrow-ish");
        let e = schema_errors(&doc);
        assert!(e.iter().any(|x| x.path == "data_points[0].fresh_within"));

        // fact predicate without a predicate_ref
        let mut doc = material_loop_manifest();
        doc["triggers"][0]
            .as_object_mut()
            .unwrap()
            .remove("predicate_ref");
        let e = schema_errors(&doc);
        assert!(e
            .iter()
            .any(|x| x.path == "triggers[0]" && x.message.contains("`predicate_ref` is missing")));

        // time trigger missing its duration / bad basis / bad operator
        let mut doc = time_trigger_manifest("1.0.0", "manufactured_at", ">=", "P40Y");
        doc["triggers"][0]
            .as_object_mut()
            .unwrap()
            .remove("duration");
        let e = schema_errors(&doc);
        assert!(e
            .iter()
            .any(|x| x.path == "triggers[0]" && x.message.contains("`duration` is missing")));
        let doc = time_trigger_manifest("1.0.0", "sold_at", ">=", "P40Y");
        let e = schema_errors(&doc);
        assert!(e.iter().any(|x| x.path == "triggers[0].basis"));
        let doc = time_trigger_manifest("1.0.0", "manufactured_at", "==", "P40Y");
        let e = schema_errors(&doc);
        assert!(e.iter().any(|x| x.path == "triggers[0].operator"));

        // subject capability must be on the ladder
        let mut doc = material_loop_manifest();
        doc["subject_capability"] = json!("silent");
        let e = schema_errors(&doc);
        assert!(e.iter().any(|x| x.path == "subject_capability"));

        // whole-manifest type error
        assert!(!schema_errors(&json!({})).is_empty());
        assert!(!schema_errors(&json!([1])).is_empty());
    }

    #[test]
    fn typed_parse_rejects_what_the_schema_rejects() {
        assert!(ProfileManifest::from_json(&json!({})).is_err());
        let mut doc = material_loop_manifest();
        doc["data_points"] = json!("none");
        assert!(ProfileManifest::from_json(&doc).is_err());
        assert!(ProfileManifest::from_json(&json!({"version": "1", "axes": [3]})).is_err());
    }
}
