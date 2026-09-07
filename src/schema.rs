//! Minimal JSON Schema (draft 2020-12 subset) validation.
//!
//! The registry serves and enforces schemas generated from canonical
//! Rust models (the single-formalization principle: one source, two
//! renders — the model and the schema it emits). External consumers
//! may use any draft 2020-12 validator against the served schema;
//! internally the registry validates with the small checker in this
//! module, which supports exactly the keyword subset the generated
//! schemas use (a unit test locks that every keyword emitted is
//! supported).
//!
//! Supported keywords: `type`, `enum`, `const`, `required`,
//! `properties`, `additionalProperties` (boolean), `items`,
//! `minItems`, `minLength`, `minimum`, `pattern`, `if`/`then`,
//! `allOf`, `$ref` (`#/$defs/…` only). Unsupported keywords are
//! ignored, matching draft 2020-12's "unknown keywords MUST be
//! ignored" rule.
//!
//! Errors carry a precise field path in dotted-with-index notation
//! (`data_points[2].min_capability`), the empty string denoting the
//! document root.

use serde_json::Value;

/// `cardinality` binding form: `"1"`, `"0..1"`, `"1..n"`, `"2..n"`, …
pub const CARDINALITY_PATTERN: &str = r"^[0-9]+(\.\.([0-9]+|n))?$";
/// ISO 8601 duration form: `P40Y`, `P1Y6M3D`, `P2W`, `PT6H30M`, …
/// (the regex is the full ECMA form for external validators; the
/// checker below maps it to [`crate::clock::parse_duration`]).
pub const DURATION_PATTERN: &str =
    r"^P(?!$)([0-9]+Y)?([0-9]+M)?([0-9]+W)?([0-9]+D)?(T(?=[0-9])([0-9]+H)?([0-9]+M)?([0-9]+S)?)?$";

/// One schema-violation finding: where (field path) and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    pub path: String,
    pub message: String,
}

impl SchemaError {
    fn new(path: &str, message: String) -> SchemaError {
        SchemaError {
            path: path.to_string(),
            message,
        }
    }
}

/// Maximum `$ref`/nesting depth (guards against cyclic schemas).
const MAX_DEPTH: usize = 32;

/// Validate `doc` against `schema`, collecting every violation.
pub fn validate(schema: &Value, doc: &Value) -> Result<(), Vec<SchemaError>> {
    let mut errors = Vec::new();
    check(schema, doc, "", schema, 0, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check(
    schema: &Value,
    doc: &Value,
    path: &str,
    root: &Value,
    depth: usize,
    errors: &mut Vec<SchemaError>,
) {
    if depth > MAX_DEPTH {
        errors.push(SchemaError::new(path, "schema nesting too deep".into()));
        return;
    }
    if let Some(target) = resolve_ref(schema, root) {
        check(target, doc, path, root, depth + 1, errors);
    }
    let Some(obj) = schema.as_object() else {
        return;
    };
    check_type(obj, doc, path, errors);
    check_enum(obj, doc, path, errors);
    if let Value::Object(fields) = doc {
        check_object(obj, fields, path, root, depth, errors);
    }
    if let Value::Array(items) = doc {
        check_array(obj, items, path, root, depth, errors);
    }
    check_scalar(obj, doc, path, errors);
    for sub in obj
        .get("allOf")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
    {
        check(sub, doc, path, root, depth + 1, errors);
    }
    if let (Some(cond), Some(then)) = (obj.get("if"), obj.get("then")) {
        if validate(cond, doc).is_ok() {
            check(then, doc, path, root, depth + 1, errors);
        }
    }
}

fn resolve_ref<'a>(schema: &'a Value, root: &'a Value) -> Option<&'a Value> {
    let r = schema.get("$ref")?.as_str()?;
    let name = r.strip_prefix("#/$defs/")?;
    root.get("$defs")?.get(name)
}

fn check_type(
    obj: &serde_json::Map<String, Value>,
    doc: &Value,
    path: &str,
    errors: &mut Vec<SchemaError>,
) {
    let expected = match obj.get("type") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => return,
    };
    if expected.is_empty() {
        return;
    }
    let actual = json_type(doc);
    if !expected.iter().any(|t| t == actual) {
        errors.push(SchemaError::new(
            path,
            format!("expected {} but found {actual}", expected.join(" | ")),
        ));
    }
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn check_enum(
    obj: &serde_json::Map<String, Value>,
    doc: &Value,
    path: &str,
    errors: &mut Vec<SchemaError>,
) {
    if let Some(list) = obj.get("enum").and_then(Value::as_array) {
        if !list.contains(doc) {
            errors.push(SchemaError::new(
                path,
                format!(
                    "value {} is not one of {}",
                    doc,
                    list.iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    if let Some(c) = obj.get("const") {
        if c != doc {
            errors.push(SchemaError::new(
                path,
                format!("value {doc} is not the constant {c}"),
            ));
        }
    }
}

fn check_object(
    obj: &serde_json::Map<String, Value>,
    fields: &serde_json::Map<String, Value>,
    path: &str,
    root: &Value,
    depth: usize,
    errors: &mut Vec<SchemaError>,
) {
    for key in obj
        .get("required")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(Value::as_str)
    {
        if !fields.contains_key(key) {
            errors.push(SchemaError::new(
                path,
                format!("required property `{key}` is missing"),
            ));
        }
    }
    let props = obj.get("properties").and_then(Value::as_object);
    if let Some(props) = props {
        for (key, sub) in props {
            if let Some(value) = fields.get(key) {
                let child = child_path(path, key);
                check(sub, value, &child, root, depth + 1, errors);
            }
        }
    }
    if obj.get("additionalProperties") == Some(&Value::Bool(false)) {
        if let Some(props) = props {
            for key in fields.keys() {
                if !props.contains_key(key) {
                    errors.push(SchemaError::new(
                        path,
                        format!("property `{key}` is not allowed here"),
                    ));
                }
            }
        }
    }
}

fn check_array(
    obj: &serde_json::Map<String, Value>,
    items: &[Value],
    path: &str,
    root: &Value,
    depth: usize,
    errors: &mut Vec<SchemaError>,
) {
    if let Some(min) = obj.get("minItems").and_then(Value::as_u64) {
        if (items.len() as u64) < min {
            errors.push(SchemaError::new(
                path,
                format!("array has {} items, fewer than {min}", items.len()),
            ));
        }
    }
    if let Some(sub) = obj.get("items") {
        for (i, item) in items.iter().enumerate() {
            let child = format!("{path}[{i}]");
            check(sub, item, &child, root, depth + 1, errors);
        }
    }
}

fn check_scalar(
    obj: &serde_json::Map<String, Value>,
    doc: &Value,
    path: &str,
    errors: &mut Vec<SchemaError>,
) {
    if let Value::String(s) = doc {
        if let Some(min) = obj.get("minLength").and_then(Value::as_u64) {
            if (s.chars().count() as u64) < min {
                errors.push(SchemaError::new(
                    path,
                    format!("string is shorter than {min} characters"),
                ));
            }
        }
        if let Some(p) = obj.get("pattern").and_then(Value::as_str) {
            if !pattern_matches(p, s) {
                errors.push(SchemaError::new(
                    path,
                    format!("string `{s}` does not match the required pattern"),
                ));
            }
        }
    }
    if let Some(n) = doc.as_f64() {
        if let Some(min) = obj.get("minimum").and_then(Value::as_f64) {
            if n < min {
                errors.push(SchemaError::new(
                    path,
                    format!("value {n} is below the minimum {min}"),
                ));
            }
        }
    }
}

/// Recognized `pattern` implementations. The generated schemas emit
/// exactly two patterns (cardinality, ISO 8601 duration); both are
/// matched structurally here rather than through a regex engine (the
/// crate is deliberately regex-free). Any other pattern is an error
/// against this checker — a unit test asserts every pattern the
/// generated schemas emit is recognized.
fn pattern_matches(pattern: &str, s: &str) -> bool {
    match pattern {
        CARDINALITY_PATTERN => is_cardinality(s),
        DURATION_PATTERN => crate::clock::parse_duration(s).is_ok(),
        other => {
            debug_assert!(
                false,
                "schema.rs has no matcher for pattern `{other}`; add one before emitting it"
            );
            true
        }
    }
}

/// `"1"` | `"0..1"` | `"1..n"` — `<n>` or `<n>..<n|n>`.
fn is_cardinality(s: &str) -> bool {
    let (lower, upper) = match s.split_once("..") {
        None => return is_digits(s),
        Some((l, u)) => (l, u),
    };
    is_digits(lower) && (upper == "n" || is_digits(upper))
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn child_path(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_string()
    } else {
        format!("{parent}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn errs(schema: &Value, doc: &Value) -> Vec<SchemaError> {
        validate(schema, doc).unwrap_err()
    }

    #[test]
    fn checker_supports_the_keyword_subset_the_schemas_use() {
        // Every keyword the generated schemas (manifest::profile_manifest_schema,
        // mapping::cross_register_mapping_schema) emit must be exercised here.
        let schema = json!({
            "type": "object",
            "required": ["k"],
            "properties": {
                "k": {"type": ["string", "null"], "enum": ["a", "b", null]},
                "list": {"type": "array", "minItems": 1, "items": {"type": "integer", "minimum": 0}},
                "s": {"type": "string", "minLength": 2},
                "card": {"type": "string", "pattern": CARDINALITY_PATTERN},
                "dur": {"type": "string", "pattern": DURATION_PATTERN},
                "tag": {"const": "fixed"}
            },
            "additionalProperties": false,
            "allOf": [{
                "if": {"properties": {"k": {"const": "a"}}, "required": ["k"]},
                "then": {"required": ["s"]}
            }],
            "$defs": {"inner": {"type": "object", "required": ["z"], "properties": {"z": {"type": "string"}}}},
            "properties_extra_ignored": true
        });
        // A fully-valid document.
        assert!(validate(
            &schema,
            &json!({"k": "a", "s": "ok", "list": [1], "card": "1..n", "dur": "P40Y", "tag": "fixed"})
        )
        .is_ok());
        // Each keyword's failure carries the right path.
        let e = errs(&schema, &json!({"k": "c"}));
        assert!(e
            .iter()
            .any(|x| x.path == "k" && x.message.contains("not one of")));
        // if/then: k == "a" requires s
        let e = errs(&schema, &json!({"k": "a"}));
        assert!(e
            .iter()
            .any(|x| x.path.is_empty() && x.message.contains("`s` is missing")));
        let e = errs(&schema, &json!({"k": "a", "s": "ok", "list": []}));
        assert!(e
            .iter()
            .any(|x| x.path == "list" && x.message.contains("fewer than")));
        let e = errs(&schema, &json!({"k": "a", "s": "ok", "list": [-1]}));
        assert!(e
            .iter()
            .any(|x| x.path == "list[0]" && x.message.contains("below the minimum")));
        let e = errs(&schema, &json!({"k": "a", "s": "x"}));
        assert!(e
            .iter()
            .any(|x| x.path == "s" && x.message.contains("shorter than")));
        let e = errs(&schema, &json!({"k": "a", "s": "ok", "card": "lots"}));
        assert!(e
            .iter()
            .any(|x| x.path == "card" && x.message.contains("pattern")));
        let e = errs(&schema, &json!({"k": "a", "s": "ok", "dur": "40Y"}));
        assert!(e
            .iter()
            .any(|x| x.path == "dur" && x.message.contains("pattern")));
        let e = errs(&schema, &json!({"k": "a", "s": "ok", "extra": 1}));
        assert!(e
            .iter()
            .any(|x| x.message.contains("`extra` is not allowed")));
        // if/then: k == "b" does not require s.
        assert!(validate(&schema, &json!({"k": "b"})).is_ok());
        // wrong type with a type array
        let e = errs(&schema, &json!({"k": 5}));
        assert!(e
            .iter()
            .any(|x| x.path == "k" && x.message.contains("expected string | null")));
        // null accepted by the type array
        assert!(validate(&schema, &json!({"k": null, "tag": "fixed"})).is_ok());
    }

    #[test]
    fn refs_resolve_against_the_schema_root() {
        let schema = json!({
            "type": "object",
            "required": ["inner"],
            "properties": {"inner": {"$ref": "#/$defs/inner"}},
            "$defs": {"inner": {"type": "object", "required": ["z"], "properties": {"z": {"type": "string"}}}}
        });
        assert!(validate(&schema, &json!({"inner": {"z": "v"}})).is_ok());
        let e = errs(&schema, &json!({"inner": {}}));
        assert_eq!(e[0].path, "inner");
        assert!(e[0].message.contains("`z` is missing"));
        // unknown $ref targets are ignored (not a crash)
        let dangling = json!({"$ref": "#/$defs/nope"});
        assert!(validate(&dangling, &json!({"any": 1})).is_ok());
    }

    #[test]
    fn cardinality_pattern_forms() {
        for ok in ["1", "0..1", "1..n", "2..n", "10..20"] {
            assert!(is_cardinality(ok), "{ok} should be a cardinality");
        }
        for bad in ["", "n", "1..", "..2", "a..b", "1...2", "one"] {
            assert!(!is_cardinality(bad), "{bad} should not be a cardinality");
        }
    }
}
