//! The class descriptor and the instance intake (R10 B1 + B2): the
//! build half of the extensibility gap register's G6 and G3.
//!
//! **B1 — the class descriptor.** An author-defined passport class
//! declares its machine-checkable shape as a registered, SIGNED item
//! of class `class-descriptor`: the identifier names the class, and
//! the manifest carries
//!
//! - `features`: the dotted fact paths with one of the four canonical
//!   value kinds (clause 5's closed set: string, decimal, boolean,
//!   list), required/optional, and — where the feature surfaces one —
//!   a declared vocabulary (string features) or a unit reference
//!   (decimal features, resolving against the registered units),
//! - `capability_classes`: the S0–S3 classes that may carry the class,
//! - `rule_references`: the rule ids the class relies on (G4's seam:
//!   present, uninterpreted at B1),
//!
//! plus the same signed form a profile manifest carries (issuer
//! class, issuing node, a signature slot with a value — the
//! cryptographic reading stays the trust service's).
//!
//! **B2 — the instance intake.** An item of an author-defined class
//! (class `instance`) carries `instance_of` (the descriptor's
//! identifier) and the twin-fact map as `features`. The check
//! resolves the descriptor point-in-time (like every registry read)
//! and validates: every required feature present, every present
//! declared feature's value kind matching the descriptor, vocabulary
//! members in range, the descriptor's unit references resolving
//! against the registered units. A refusal names the failing feature
//! path and the descriptor rule it broke. Facts outside the
//! descriptor are the open map (clause 5's extensibility surface) —
//! they ride, unvalidated. The negative fixtures a class author
//! relies on: missing-required, wrong-kind, out-of-vocabulary,
//! unresolved-unit, unknown-class.

use serde_json::Value;

use crate::intake::{IntakeCheck, IntakeContext, IntakeError, IntakeWarning};
use crate::model::{Item, ItemClass};

/// The four canonical value kinds (clause 5's closed set).
const FACT_KINDS: [&str; 4] = ["string", "decimal", "boolean", "list"];

/// The capability classes that may carry a class (S0–S3).
const CAPABILITY_CLASSES: [&str; 4] = ["silent", "passive-auth", "logged-contact", "connected"];

/// The descriptor's signed form reuses the profile's authority
/// typology (the five issuer classes).
const ISSUER_CLASSES: [&str; 5] = ["law", "treaty", "consensus", "declaration", "attestation"];

/// A declared feature of a class descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureSpec {
    /// The dotted fact path (the open map's key, clause 5).
    pub path: String,
    /// One of the four canonical kinds.
    pub kind: String,
    pub required: bool,
    /// The closed vocabulary a string feature draws from.
    pub vocabulary: Option<Vec<String>>,
    /// The unit reference a decimal feature carries (resolving
    /// against the registered units at instance intake).
    pub unit: Option<String>,
}

/// Parses the descriptor's `features` array into specs.
pub fn parse_features(manifest: &Value) -> Result<Vec<FeatureSpec>, Vec<IntakeError>> {
    let mut errors = Vec::new();
    let mut specs = Vec::new();
    let Some(features) = manifest.get("features").and_then(|v| v.as_array()) else {
        return Err(vec![IntakeError {
            check: "class-descriptor-manifest",
            path: "manifest.features".into(),
            message: "the descriptor declares its features as an array of feature specs".into(),
        }]);
    };
    for (index, feature) in features.iter().enumerate() {
        let at = format!("manifest.features[{index}]");
        let path = feature
            .get("path")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let Some(path) = path else {
            errors.push(IntakeError {
                check: "class-descriptor-manifest",
                path: format!("{at}.path"),
                message: "every feature names its dotted fact path".into(),
            });
            continue;
        };
        if !valid_fact_path(&path) {
            errors.push(IntakeError {
                check: "class-descriptor-manifest",
                path: format!("{at}.path"),
                message: format!(
                    "`{path}` is not a fact path: dotted segments, no leading, trailing or doubled dots"
                ),
            });
        }
        let kind = feature.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if !FACT_KINDS.contains(&kind) {
            errors.push(IntakeError {
                check: "class-descriptor-manifest",
                path: format!("{at}.kind"),
                message: format!(
                    "`{kind}` is not a value kind (the closed set: {})",
                    FACT_KINDS.join(", ")
                ),
            });
        }
        let vocabulary: Option<Vec<String>> = feature
            .get("vocabulary")
            .and_then(|v| v.as_array())
            .map(|list| {
                list.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            });
        let unit = feature
            .get("unit")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        if vocabulary.is_some() && kind != "string" {
            errors.push(IntakeError {
                check: "class-descriptor-manifest",
                path: format!("{at}.vocabulary"),
                message: "a vocabulary declares the range of a STRING feature".into(),
            });
        }
        if unit.is_some() && kind != "decimal" {
            errors.push(IntakeError {
                check: "class-descriptor-manifest",
                path: format!("{at}.unit"),
                message: "a unit reference declares the unit of a DECIMAL feature".into(),
            });
        }
        if let Some(vocabulary) = &vocabulary {
            if vocabulary.is_empty() {
                errors.push(IntakeError {
                    check: "class-descriptor-manifest",
                    path: format!("{at}.vocabulary"),
                    message:
                        "a declared vocabulary states its members (an empty one declares nothing)"
                            .into(),
                });
            }
        }
        if let Some(unit) = &unit {
            if unit.trim().is_empty() {
                errors.push(IntakeError {
                    check: "class-descriptor-manifest",
                    path: format!("{at}.unit"),
                    message: "the unit reference is empty".into(),
                });
            }
        }
        specs.push(FeatureSpec {
            path,
            kind: kind.to_string(),
            required: feature
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            vocabulary,
            unit,
        });
    }
    // Duplicate paths: one fact path, one declaration.
    let mut seen: Vec<&str> = Vec::new();
    for spec in &specs {
        if seen.contains(&spec.path.as_str()) {
            errors.push(IntakeError {
                check: "class-descriptor-manifest",
                path: format!("manifest.features[{}]", spec.path),
                message: format!("the fact path `{}` is declared twice", spec.path),
            });
        }
        seen.push(&spec.path);
    }
    if errors.is_empty() {
        Ok(specs)
    } else {
        Err(errors)
    }
}

/// The fact-path shape: dotted, non-empty segments, no leading,
/// trailing or doubled dots.
fn valid_fact_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let segments: Vec<&str> = path.split('.').collect();
    segments.iter().all(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// B1 — the class descriptor registers only in its SIGNED form
// ---------------------------------------------------------------------------

/// The descriptor's signed form: the same discipline a profile
/// manifest carries (the FORM is intake's; the cryptographic reading
/// is the trust service's).
pub struct ClassDescriptorSignatureCheck;

impl IntakeCheck for ClassDescriptorSignatureCheck {
    fn name(&self) -> &'static str {
        "class-descriptor-signature-required"
    }

    fn class(&self) -> Option<ItemClass> {
        Some(ItemClass::ClassDescriptor)
    }

    fn check(
        &self,
        item: &Item,
        _ctx: &IntakeContext,
    ) -> Result<Vec<IntakeWarning>, Vec<IntakeError>> {
        let Some(m) = &item.manifest else {
            return Err(vec![IntakeError {
                check: self.name(),
                path: "manifest".into(),
                message: "a class descriptor registers its SIGNED manifest (issuer_class, issuer, signature) — no manifest given".into(),
            }]);
        };
        let mut errors = Vec::new();
        match m.get("issuer_class").and_then(|v| v.as_str()) {
            Some(token) if ISSUER_CLASSES.contains(&token) => {}
            Some(other) => errors.push(IntakeError {
                check: self.name(),
                path: "manifest.issuer_class".into(),
                message: format!(
                    "`{other}` is not an issuer class (one of {})",
                    ISSUER_CLASSES.join(", ")
                ),
            }),
            None => errors.push(IntakeError {
                check: self.name(),
                path: "manifest.issuer_class".into(),
                message: "class descriptors are signed by their issuer: the manifest must state its issuer_class (law | treaty | consensus | declaration | attestation)".into(),
            }),
        }
        match m.get("issuer").and_then(|v| v.as_str()) {
            Some(issuer) if !issuer.trim().is_empty() => {}
            _ => errors.push(IntakeError {
                check: self.name(),
                path: "manifest.issuer".into(),
                message: "the issuing node's id is required (the signer of record)".into(),
            }),
        }
        let signature_filled = m
            .get("signature")
            .and_then(|v| v.get("signature"))
            .map(|v| v.as_str().map(|s| !s.trim().is_empty()).unwrap_or(false))
            .unwrap_or(false);
        if !signature_filled {
            errors.push(IntakeError {
                check: self.name(),
                path: "manifest.signature".into(),
                message: "class descriptors register only in their SIGNED form: a signature slot with a signature value is required (the cryptographic reading is the trust service's)".into(),
            });
        }
        if errors.is_empty() {
            Ok(Vec::new())
        } else {
            Err(errors)
        }
    }
}

// ---------------------------------------------------------------------------
// B1 — the descriptor's shape: features, capabilities, rule refs
// ---------------------------------------------------------------------------

pub struct ClassDescriptorManifestCheck;

impl IntakeCheck for ClassDescriptorManifestCheck {
    fn name(&self) -> &'static str {
        "class-descriptor-manifest"
    }

    fn class(&self) -> Option<ItemClass> {
        Some(ItemClass::ClassDescriptor)
    }

    fn check(
        &self,
        item: &Item,
        _ctx: &IntakeContext,
    ) -> Result<Vec<IntakeWarning>, Vec<IntakeError>> {
        let Some(m) = &item.manifest else {
            return Err(vec![IntakeError {
                check: self.name(),
                path: "manifest".into(),
                message: "a class descriptor carries a manifest".into(),
            }]);
        };
        let mut errors = Vec::new();
        // The identifier names the author's class.
        match m.get("class_id").and_then(|v| v.as_str()) {
            Some(class_id) if class_id == item.identifier => {}
            Some(other) => errors.push(IntakeError {
                check: self.name(),
                path: "manifest.class_id".into(),
                message: format!(
                    "the descriptor's class_id `{other}` must name the item itself (`{}`): the identifier IS the class",
                    item.identifier
                ),
            }),
            None => errors.push(IntakeError {
                check: self.name(),
                path: "manifest.class_id".into(),
                message: "the descriptor states its class_id (the identifier names the class)".into(),
            }),
        }
        // The features (the shape half of B1; parsing reports its own
        // paths).
        let features = match parse_features(m) {
            Ok(features) => features,
            Err(mut feature_errors) => {
                errors.append(&mut feature_errors);
                Vec::new()
            }
        };
        if features.is_empty() && errors.is_empty() {
            errors.push(IntakeError {
                check: self.name(),
                path: "manifest.features".into(),
                message: "a class descriptor declares at least one feature".into(),
            });
        }
        // The capability classes that may carry the class.
        match m.get("capability_classes").and_then(|v| v.as_array()) {
            Some(classes) => {
                if classes.is_empty() {
                    errors.push(IntakeError {
                        check: self.name(),
                        path: "manifest.capability_classes".into(),
                        message: "the descriptor states at least one capability class (S0–S3)"
                            .into(),
                    });
                }
                for (index, class) in classes.iter().enumerate() {
                    let token = class.as_str().unwrap_or("");
                    if !CAPABILITY_CLASSES.contains(&token) {
                        errors.push(IntakeError {
                            check: self.name(),
                            path: format!("manifest.capability_classes[{index}]"),
                            message: format!(
                                "`{token}` is not a capability class (one of {})",
                                CAPABILITY_CLASSES.join(", ")
                            ),
                        });
                    }
                }
            }
            None => errors.push(IntakeError {
                check: self.name(),
                path: "manifest.capability_classes".into(),
                message: "the descriptor states the capability classes that may carry it".into(),
            }),
        }
        // The rule references (G4's seam: present, uninterpreted).
        match m.get("rule_references").and_then(|v| v.as_array()) {
            Some(rules) => {
                for (index, rule) in rules.iter().enumerate() {
                    let token = rule.as_str().unwrap_or("");
                    if token.trim().is_empty() {
                        errors.push(IntakeError {
                            check: self.name(),
                            path: format!("manifest.rule_references[{index}]"),
                            message: "a rule reference is a non-empty rule id".into(),
                        });
                    }
                }
            }
            None => errors.push(IntakeError {
                check: self.name(),
                path: "manifest.rule_references".into(),
                message: "the descriptor states the rule references it relies on (an empty array declares none)".into(),
            }),
        }
        if errors.is_empty() {
            Ok(Vec::new())
        } else {
            Err(errors)
        }
    }
}

// ---------------------------------------------------------------------------
// B2 — the instance against its descriptor
// ---------------------------------------------------------------------------

pub struct InstanceAgainstClassCheck;

/// The kind a fact value presents as (the reading side of the four
/// canonical kinds).
fn value_kind(value: &Value) -> Option<&'static str> {
    match value {
        Value::String(_) => Some("string"),
        Value::Bool(_) => Some("boolean"),
        Value::Array(list) if list.iter().all(|v| v.is_string()) => Some("list"),
        Value::Number(_) => Some("decimal"),
        _ => None,
    }
}

impl IntakeCheck for InstanceAgainstClassCheck {
    fn name(&self) -> &'static str {
        "instance-against-class"
    }

    fn class(&self) -> Option<ItemClass> {
        Some(ItemClass::Instance)
    }

    fn check(
        &self,
        item: &Item,
        ctx: &IntakeContext,
    ) -> Result<Vec<IntakeWarning>, Vec<IntakeError>> {
        let Some(m) = &item.manifest else {
            return Err(vec![IntakeError {
                check: self.name(),
                path: "manifest".into(),
                message: "an instance carries a manifest (instance_of, features)".into(),
            }]);
        };
        let class_id = m
            .get("instance_of")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let Some(class_id) = class_id else {
            return Err(vec![IntakeError {
                check: self.name(),
                path: "manifest.instance_of".into(),
                message:
                    "the instance states the class it instantiates (the descriptor's identifier)"
                        .into(),
            }]);
        };
        // The descriptor resolves (point-in-time, like every registry
        // read); anything else is the unknown-class refusal.
        let Some(descriptor) = ctx.store.item(class_id) else {
            return Err(vec![IntakeError {
                check: self.name(),
                path: "manifest.instance_of".into(),
                message: format!(
                    "unknown class `{class_id}`: no registered class descriptor names it"
                ),
            }]);
        };
        if descriptor.item_class != ItemClass::ClassDescriptor {
            return Err(vec![IntakeError {
                check: self.name(),
                path: "manifest.instance_of".into(),
                message: format!(
                    "`{class_id}` is registered as a {}, not a class descriptor",
                    descriptor.item_class
                ),
            }]);
        }
        let Some(descriptor_manifest) = &descriptor.manifest else {
            return Err(vec![IntakeError {
                check: self.name(),
                path: "manifest.instance_of".into(),
                message: format!("the class descriptor `{class_id}` carries no manifest"),
            }]);
        };
        let specs = parse_features(descriptor_manifest).map_err(|errors| {
            errors
                .into_iter()
                .map(|e| IntakeError {
                    check: self.name(),
                    path: format!("manifest.instance_of ({})", e.path),
                    message: format!(
                        "the class descriptor `{class_id}` itself does not parse: {}",
                        e.message
                    ),
                })
                .collect::<Vec<_>>()
        })?;
        let features = m.get("features").cloned().unwrap_or(Value::Null);
        let mut errors = Vec::new();
        for spec in &specs {
            let fact = features.get(&spec.path);
            match fact {
                None | Some(Value::Null) => {
                    if spec.required {
                        errors.push(IntakeError {
                            check: self.name(),
                            path: format!("manifest.features.{}", spec.path),
                            message: format!(
                                "the class `{class_id}` declares `{}` required; the instance states no fact at that path (missing-required)",
                                spec.path
                            ),
                        });
                    }
                }
                Some(value) => {
                    // The kind must match the descriptor's declaration.
                    let presented = value_kind(value);
                    if presented != Some(spec.kind.as_str()) {
                        errors.push(IntakeError {
                            check: self.name(),
                            path: format!("manifest.features.{}", spec.path),
                            message: format!(
                                "the fact at `{}` presents as {:?}; the class `{class_id}` declares `{}` (wrong-kind)",
                                spec.path,
                                presented.unwrap_or("neither string, decimal, boolean nor a list of strings"),
                                spec.kind
                            ),
                        });
                        continue;
                    }
                    // Vocabulary members in range.
                    if let Some(vocabulary) = &spec.vocabulary {
                        let member = value.as_str().unwrap_or_default();
                        if !vocabulary.iter().any(|v| v == member) {
                            errors.push(IntakeError {
                                check: self.name(),
                                path: format!("manifest.features.{}", spec.path),
                                message: format!(
                                    "`{member}` is outside the vocabulary the class `{class_id}` declares for `{}` (out-of-vocabulary; members: {})",
                                    spec.path,
                                    vocabulary.join(", ")
                                ),
                            });
                        }
                    }
                }
            }
        }
        // The descriptor's unit references resolve against the
        // registered units.
        for spec in &specs {
            let Some(unit) = &spec.unit else { continue };
            match ctx.store.item(unit) {
                Some(unit_item) if unit_item.item_class == ItemClass::Unit => {}
                Some(other) => errors.push(IntakeError {
                    check: self.name(),
                    path: format!("manifest.features.{}", spec.path),
                    message: format!(
                        "the class `{class_id}` declares unit `{unit}` for `{}`, but that identifier registers as a {} (unresolved-unit)",
                        spec.path, other.item_class
                    ),
                }),
                None => errors.push(IntakeError {
                    check: self.name(),
                    path: format!("manifest.features.{}", spec.path),
                    message: format!(
                        "the class `{class_id}` declares unit `{unit}` for `{}`, but no registered unit names it (unresolved-unit)",
                        spec.path
                    ),
                }),
            }
        }
        if errors.is_empty() {
            Ok(Vec::new())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intake::{default_chain, run, IntakeContext};
    use crate::model::Item;
    use crate::store::Store;
    use serde_json::json;

    fn ctx<'a>(store: &'a Store) -> IntakeContext<'a> {
        IntakeContext {
            store,
            strict: true,
        }
    }

    fn item(class: ItemClass, identifier: &str, manifest: Value) -> Item {
        Item {
            identifier: identifier.to_string(),
            register: "unidpp-registry".to_string(),
            item_class: class,
            title: identifier.to_string(),
            submitting_organization: None,
            versions: Vec::new(),
            manifest: Some(manifest),
        }
    }

    fn signed_descriptor(class_id: &str, features: Value) -> Value {
        json!({
            "class_id": class_id,
            "issuer_class": "consensus",
            "issuer": "urn:unidpp:actor:consortium",
            "signature": {"signature": "dGVzdC1zaWduYXR1cmU"},
            "features": features,
            "capability_classes": ["silent", "logged-contact"],
            "rule_references": ["rule.pressure-range"]
        })
    }

    fn tyre_features() -> Value {
        json!([
            {"path": "tyre.pressure-bar", "kind": "decimal", "required": true, "unit": "bar"},
            {"path": "tyre.season", "kind": "string", "required": true,
             "vocabulary": ["summer", "winter", "all-season"]},
            {"path": "tyre.runflat", "kind": "boolean", "required": false},
            {"path": "tyre.sizes", "kind": "list", "required": false}
        ])
    }

    fn store_with_descriptor() -> Store {
        store_with_descriptor_and_unit(true)
    }

    /// The descriptor's store, with the bar unit registered or left
    /// out (the unresolved-unit fixture).
    fn store_with_descriptor_and_unit(with_unit: bool) -> Store {
        let mut store = Store::open(None).expect("in-memory store");
        let descriptor = item(
            ItemClass::ClassDescriptor,
            "tyre-e8",
            signed_descriptor("tyre-e8", tyre_features()),
        );
        let chain = default_descriptor_chain();
        run(&chain, &descriptor, &ctx(&store)).expect("the descriptor passes its own chain");
        store.register_item(descriptor).expect("registered");
        if with_unit {
            store
                .register_item(item(
                    ItemClass::Unit,
                    "bar",
                    json!({"name": "bar", "symbol": "bar"}),
                ))
                .expect("unit registered");
        }
        store
    }

    #[test]
    fn the_descriptor_registers_signed_and_shaped() {
        let store = Store::open(None).unwrap();
        let descriptor = item(
            ItemClass::ClassDescriptor,
            "tyre-e8",
            signed_descriptor("tyre-e8", tyre_features()),
        );
        let chain = default_descriptor_chain();
        assert!(run(&chain, &descriptor, &ctx(&store)).is_ok());
    }

    #[test]
    fn an_unsigned_descriptor_refuses() {
        let store = Store::open(None).unwrap();
        let mut unsigned = signed_descriptor("tyre-e8", tyre_features());
        unsigned["signature"] = json!({"signature": ""});
        let descriptor = item(ItemClass::ClassDescriptor, "tyre-e8", unsigned);
        let errors = run(&default_descriptor_chain(), &descriptor, &ctx(&store)).unwrap_err();
        assert!(errors.iter().any(|e| e.path == "manifest.signature"));
    }

    #[test]
    fn a_mismatched_class_id_refuses() {
        let store = Store::open(None).unwrap();
        let descriptor = item(
            ItemClass::ClassDescriptor,
            "tyre-e8",
            signed_descriptor("some-other-class", tyre_features()),
        );
        let errors = run(&default_descriptor_chain(), &descriptor, &ctx(&store)).unwrap_err();
        assert!(errors.iter().any(|e| e.path == "manifest.class_id"));
    }

    #[test]
    fn a_fifth_value_kind_refuses() {
        let store = Store::open(None).unwrap();
        let features = json!([
            {"path": "tyre.geometry", "kind": "polygon", "required": false}
        ]);
        let descriptor = item(
            ItemClass::ClassDescriptor,
            "tyre-e8",
            signed_descriptor("tyre-e8", features),
        );
        let errors = run(&default_descriptor_chain(), &descriptor, &ctx(&store)).unwrap_err();
        assert!(errors.iter().any(|e| e.path == "manifest.features[0].kind"));
    }

    #[test]
    fn a_vocabulary_on_a_boolean_feature_refuses() {
        let store = Store::open(None).unwrap();
        let features = json!([
            {"path": "tyre.runflat", "kind": "boolean", "required": false,
             "vocabulary": ["yes", "no"]}
        ]);
        let descriptor = item(
            ItemClass::ClassDescriptor,
            "tyre-e8",
            signed_descriptor("tyre-e8", features),
        );
        let errors = run(&default_descriptor_chain(), &descriptor, &ctx(&store)).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.path == "manifest.features[0].vocabulary"));
    }

    #[test]
    fn a_duplicate_fact_path_refuses() {
        let store = Store::open(None).unwrap();
        let features = json!([
            {"path": "tyre.season", "kind": "string", "required": true},
            {"path": "tyre.season", "kind": "string", "required": false}
        ]);
        let descriptor = item(
            ItemClass::ClassDescriptor,
            "tyre-e8",
            signed_descriptor("tyre-e8", features),
        );
        let errors = run(&default_descriptor_chain(), &descriptor, &ctx(&store)).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("declared twice")));
    }

    fn instance(features: Value, class_id: &str) -> Item {
        item(
            ItemClass::Instance,
            "instance-tyre-0001",
            json!({
                "instance_of": class_id,
                "features": features
            }),
        )
    }

    fn conforming_instance() -> Item {
        instance(
            json!({
                "tyre.pressure-bar": 2.3,
                "tyre.season": "winter",
                "tyre.runflat": true,
                "tyre.sizes": ["205/55R16", "225/45R17"],
                "tyre.open-fact": "rides unvalidated (the open map)"
            }),
            "tyre-e8",
        )
    }

    #[test]
    fn the_conforming_instance_registers() {
        let store = store_with_descriptor();
        let warnings = run(&default_chain(), &conforming_instance(), &ctx(&store));
        assert!(warnings.is_ok());
    }

    #[test]
    fn a_missing_required_feature_refuses() {
        let store = store_with_descriptor();
        let mut features = json!({"tyre.season": "winter"});
        features["tyre.pressure-bar"] = Value::Null;
        let errors = run(
            &default_chain(),
            &instance(features, "tyre-e8"),
            &ctx(&store),
        )
        .unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.path == "manifest.features.tyre.pressure-bar"
                && e.message.contains("missing-required")));
    }

    #[test]
    fn a_wrong_kind_refuses() {
        let store = store_with_descriptor();
        let features = json!({
            "tyre.pressure-bar": 2.3,
            "tyre.season": true
        });
        let errors = run(
            &default_chain(),
            &instance(features, "tyre-e8"),
            &ctx(&store),
        )
        .unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.path == "manifest.features.tyre.season"
                    && e.message.contains("wrong-kind"))
        );
    }

    #[test]
    fn an_out_of_vocabulary_member_refuses() {
        let store = store_with_descriptor();
        let features = json!({
            "tyre.pressure-bar": 2.3,
            "tyre.season": "competitive"
        });
        let errors = run(
            &default_chain(),
            &instance(features, "tyre-e8"),
            &ctx(&store),
        )
        .unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("out-of-vocabulary")));
    }

    #[test]
    fn an_unresolvable_unit_refuses() {
        let store = store_with_descriptor_and_unit(false);
        let errors = run(&default_chain(), &conforming_instance(), &ctx(&store)).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("unresolved-unit")));
    }

    #[test]
    fn an_unknown_class_refuses() {
        let store = store_with_descriptor();
        let errors = run(
            &default_chain(),
            &instance(json!({"x": 1}), "no-such-class"),
            &ctx(&store),
        )
        .unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("unknown class")));
    }

    fn default_descriptor_chain() -> Vec<Box<dyn IntakeCheck>> {
        vec![
            Box::new(ClassDescriptorSignatureCheck),
            Box::new(ClassDescriptorManifestCheck),
        ]
    }
}
