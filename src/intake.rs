//! The intake validator chain: class-scoped checks run when an item
//! (or a superseding version carrying a new manifest) enters the
//! register. Each check is a small pure implementation of the
//! [`IntakeCheck`] trait, registered once in [`default_chain`] —
//! adding a new check means adding a type, never editing a handler
//! (OCP); each check owns exactly one concern (MECE).
//!
//! | check | class | concern |
//! |---|---|---|
//! | [`ProfileManifestSchemaCheck`] | profile | the manifest conforms to the generated JSON Schema (item 51) |
//! | [`ProfileSatisfiabilityCheck`] | profile | capability demands are servable by the declared subject class (item 71) |
//! | [`CrossRegisterMappingCheck`] | cross-register-mapping | manifest shape + referential integrity of both ends (item 57) |
//!
//! Errors reject the intake (HTTP 400 with the field paths);
//! warnings (only the satisfiability check emits them, under
//! `strict = false`) ride along with the 201.

use crate::express::ValidationStatus;
use crate::manifest;
use crate::mapping;
use crate::model::{Item, ItemClass};
use crate::satisfiability;
use crate::store::Store;

/// Everything a check may need about the intake. The store borrow
/// is read-only: integrity checks look, they never mutate.
pub struct IntakeContext<'a> {
    pub store: &'a Store,
    /// When false, hard failures become warnings (the
    /// satisfiability check's warning-only mode, item 71).
    pub strict: bool,
}

/// A rejection: where in the request document, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakeError {
    pub check: &'static str,
    pub path: String,
    pub message: String,
}

/// A warning: the item is registered, with this note attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakeWarning {
    pub check: &'static str,
    pub path: String,
    pub message: String,
}

impl From<IntakeWarning> for serde_json::Value {
    fn from(w: IntakeWarning) -> serde_json::Value {
        serde_json::json!({"check": w.check, "path": w.path, "message": w.message})
    }
}

/// One class-scoped intake check.
pub trait IntakeCheck: Sync {
    /// Stable name (surfaced in errors/warnings).
    fn name(&self) -> &'static str;
    /// The item class this check governs; `None` runs for every
    /// class.
    fn class(&self) -> Option<ItemClass>;
    /// `Err` rejects the intake; `Ok(warnings)` registers the item
    /// carrying the warnings.
    fn check(
        &self,
        item: &Item,
        ctx: &IntakeContext,
    ) -> Result<Vec<IntakeWarning>, Vec<IntakeError>>;
}

/// The registered chain. New checks are appended here.
pub fn default_chain() -> Vec<Box<dyn IntakeCheck>> {
    vec![
        Box::new(ProfileManifestSchemaCheck),
        Box::new(ProfileSatisfiabilityCheck),
        Box::new(CrossRegisterMappingCheck),
    ]
}

/// Runs the chain for the item's class, in registration order. The
/// first failing check's errors are returned (rejections are
/// immediate — a manifest that fails its schema is not also run
/// through satisfiability).
pub fn run(
    chain: &[Box<dyn IntakeCheck>],
    item: &Item,
    ctx: &IntakeContext,
) -> Result<Vec<IntakeWarning>, Vec<IntakeError>> {
    let mut warnings = Vec::new();
    for c in chain {
        if let Some(class) = c.class() {
            if item.item_class != class {
                continue;
            }
        }
        let mut w = c.check(item, ctx)?;
        warnings.append(&mut w);
    }
    Ok(warnings)
}

// ---------------------------------------------------------------------------
// Item 51 — profile manifest conforms to the generated JSON Schema
// ---------------------------------------------------------------------------

pub struct ProfileManifestSchemaCheck;

impl IntakeCheck for ProfileManifestSchemaCheck {
    fn name(&self) -> &'static str {
        "profile-manifest-schema"
    }

    fn class(&self) -> Option<ItemClass> {
        Some(ItemClass::Profile)
    }

    fn check(
        &self,
        item: &Item,
        _ctx: &IntakeContext,
    ) -> Result<Vec<IntakeWarning>, Vec<IntakeError>> {
        let Some(m) = &item.manifest else {
            return Ok(Vec::new()); // a profile without a manifest is pin-checked elsewhere
        };
        manifest::validate_manifest(m).map_err(|errors| {
            errors
                .into_iter()
                .map(|e| IntakeError {
                    check: self.name(),
                    path: e.path,
                    message: e.message,
                })
                .collect::<Vec<_>>()
        })?;
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Item 71 — capability demands must be satisfiable
// ---------------------------------------------------------------------------

pub struct ProfileSatisfiabilityCheck;

impl IntakeCheck for ProfileSatisfiabilityCheck {
    fn name(&self) -> &'static str {
        "profile-satisfiability"
    }

    fn class(&self) -> Option<ItemClass> {
        Some(ItemClass::Profile)
    }

    fn check(
        &self,
        item: &Item,
        ctx: &IntakeContext,
    ) -> Result<Vec<IntakeWarning>, Vec<IntakeError>> {
        let Some(m) = &item.manifest else {
            return Ok(Vec::new());
        };
        let parsed = manifest::ProfileManifest::from_json(m).map_err(|e| {
            vec![IntakeError {
                check: self.name(),
                path: String::new(),
                message: e,
            }]
        })?;
        match satisfiability::check(&parsed) {
            Ok(()) => Ok(Vec::new()),
            Err(violations) => {
                let notes: Vec<IntakeWarning> = violations
                    .into_iter()
                    .map(|v| IntakeWarning {
                        check: self.name(),
                        path: v.path,
                        message: v.message,
                    })
                    .collect();
                if ctx.strict {
                    Err(notes
                        .into_iter()
                        .map(|w| IntakeError {
                            check: w.check,
                            path: w.path,
                            message: w.message,
                        })
                        .collect())
                } else {
                    Ok(notes)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Item 57 — cross-register mapping: shape + referential integrity
// ---------------------------------------------------------------------------

pub struct CrossRegisterMappingCheck;

impl IntakeCheck for CrossRegisterMappingCheck {
    fn name(&self) -> &'static str {
        "cross-register-mapping-integrity"
    }

    fn class(&self) -> Option<ItemClass> {
        Some(ItemClass::CrossRegisterMapping)
    }

    fn check(
        &self,
        item: &Item,
        ctx: &IntakeContext,
    ) -> Result<Vec<IntakeWarning>, Vec<IntakeError>> {
        let Some(m) = &item.manifest else {
            return Err(vec![IntakeError {
                check: self.name(),
                path: String::new(),
                message:
                    "a cross-register mapping requires a manifest (source, target, mapping_type)"
                        .to_string(),
            }]);
        };
        let to_errors = |errors: Vec<crate::schema::SchemaError>| -> Vec<IntakeError> {
            errors
                .into_iter()
                .map(|e| IntakeError {
                    check: self.name(),
                    path: e.path,
                    message: e.message,
                })
                .collect()
        };
        mapping::validate_manifest(m).map_err(to_errors)?;
        let parsed = mapping::parse(m).map_err(|e| {
            vec![IntakeError {
                check: self.name(),
                path: String::new(),
                message: e,
            }]
        })?;
        mapping::integrity_errors(&parsed, ctx.store)
            .into_iter()
            .map(|e| IntakeError {
                check: self.name(),
                path: e.path,
                message: e.message,
            })
            .collect::<Vec<_>>()
            .into_result()
    }
}

/// Small helper: an empty error list is Ok (warnings are not a
/// concept for this check).
trait IntoResult {
    fn into_result(self) -> Result<Vec<IntakeWarning>, Vec<IntakeError>>;
}

impl IntoResult for Vec<IntakeError> {
    fn into_result(self) -> Result<Vec<IntakeWarning>, Vec<IntakeError>> {
        if self.is_empty() {
            Ok(Vec::new())
        } else {
            Err(self)
        }
    }
}

// ---------------------------------------------------------------------------
// Item 58 — model deposits: validation status carried on the item
// ---------------------------------------------------------------------------

/// Reads a model item's validation status from its manifest
/// (admin views; `ValidationStatus::Pending` when unreadable).
pub fn model_validation_status(item: &Item) -> ValidationStatus {
    item.manifest
        .as_ref()
        .and_then(|m| crate::express::deposit_from_manifest(m).ok())
        .map(|d| d.validation.status)
        .unwrap_or(ValidationStatus::Pending)
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

    fn item(id: &str, class: ItemClass, manifest: Option<serde_json::Value>) -> Item {
        Item {
            identifier: id.to_string(),
            register: "unidpp-dev".to_string(),
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
            manifest,
        }
    }

    #[test]
    fn chain_is_class_scoped() {
        let store = Store::open(None).unwrap();
        let ctx = IntakeContext {
            store: &store,
            strict: true,
        };
        // a unit item with a manifest that would fail the profile
        // schema is not the profile check's concern
        let unit = item(
            "unit-kwh",
            ItemClass::Unit,
            Some(json!({"min_capability": "S9"})),
        );
        assert!(run(&default_chain(), &unit, &ctx).is_ok());
        // a profile with the same manifest is rejected
        let profile = item(
            "p",
            ItemClass::Profile,
            Some(json!({"data_points": [{"min_capability": "S9"}]})),
        );
        let e = run(&default_chain(), &profile, &ctx).unwrap_err();
        assert!(e.iter().all(|x| x.check == "profile-manifest-schema"));
        assert!(e.iter().any(|x| x.path.contains("min_capability")));
    }

    #[test]
    fn strict_mode_downgrades_satisfiability_to_a_warning() {
        let store = Store::open(None).unwrap();
        let manifest = json!({
            "version": "1.0.0",
            "subject_capability": "S0",
            "data_points": [{"element": "de/x", "min_capability": "S3"}]
        });
        let profile = item("p", ItemClass::Profile, Some(manifest));
        let strict = IntakeContext {
            store: &store,
            strict: true,
        };
        let e = run(&default_chain(), &profile, &strict).unwrap_err();
        assert!(e.iter().any(|x| x.check == "profile-satisfiability"));
        let lenient = IntakeContext {
            store: &store,
            strict: false,
        };
        let w = run(&default_chain(), &profile, &lenient).unwrap();
        assert!(w
            .iter()
            .any(|x| x.check == "profile-satisfiability"
                && x.path == "data_points[0].min_capability"));
    }

    #[test]
    fn mapping_check_validates_integrity_against_the_store() {
        let mut store = Store::open(None).unwrap();
        let source = item("gb-4943-1", ItemClass::DataElement, None);
        store.register_item(source.clone()).unwrap();
        let ctx = IntakeContext {
            store: &store,
            strict: true,
        };
        let good = item(
            "map-1",
            ItemClass::CrossRegisterMapping,
            Some(json!({
                "version": "1.0.0",
                "source": {"register": "unidpp-dev", "item": "gb-4943-1", "version": "1.0.0"},
                "target": {"register": "unidpp-dev", "item": "gb-4943-1"},
                "mapping_type": "related"
            })),
        );
        assert!(run(&default_chain(), &good, &ctx).is_ok());
        let dangling = item(
            "map-2",
            ItemClass::CrossRegisterMapping,
            Some(json!({
                "version": "1.0.0",
                "source": {"item": "gb-4943-1"},
                "target": {"item": "iec-62368-1"},
                "mapping_type": "equivalent"
            })),
        );
        let e = run(&default_chain(), &dangling, &ctx).unwrap_err();
        assert!(e
            .iter()
            .any(|x| x.check == "cross-register-mapping-integrity" && x.path == "target.item"));
        // a mapping without a manifest is rejected outright
        let bare = item("map-3", ItemClass::CrossRegisterMapping, None);
        assert!(run(&default_chain(), &bare, &ctx).is_err());
    }

    #[test]
    fn model_validation_status_helper() {
        let rec = crate::express::ValidationRecord {
            status: ValidationStatus::Pending,
            tool: "expressir".into(),
            detail: None,
        };
        let m = item(
            "m",
            ItemClass::Model,
            Some(crate::express::model_manifest(
                "1.0.0",
                "SCHEMA m '1'; END_SCHEMA;",
                &rec,
            )),
        );
        assert_eq!(model_validation_status(&m), ValidationStatus::Pending);
        assert_eq!(
            model_validation_status(&item("m2", ItemClass::Model, None)),
            ValidationStatus::Pending
        );
    }
}
