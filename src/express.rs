//! EXPRESS model deposits (T-08 / item 58): whole semantic models
//! exchanged as registered, checksummed artifacts.
//!
//! `POST /models` accepts an EXPRESS source text plus metadata,
//! computes the content hash (SHA-256 over the exact deposited
//! bytes), stores the model as a `model` item, and validates the
//! source with expressir (external Ruby CLI, `expressir validate
//! load`, run as a subprocess — document the dependency: `gem
//! install expressir`, binary on PATH). When expressir is not
//! available the model is stored with `validation.status = pending`
//! and can be validated later via `POST /models/{id}/validate`.
//!
//! A model item's manifest:
//!
//! ```json
//! {
//!   "version": "1.0.0",
//!   "express": {
//!     "source": "SCHEMA m '1.0'; END_SCHEMA;",
//!     "content_hash": "sha256:<64 hex>",
//!     "validation": {"status": "valid", "tool": "expressir 2.4.0", "detail": null}
//!   }
//! }
//! ```

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The external validator binary (documented dependency: `gem
/// install expressir`; must be on PATH).
pub const EXPRESSIR_BIN: &str = "expressir";

/// Validation state of a deposited model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    /// expressir not available at validation time; re-run
    /// `POST /models/{id}/validate`.
    Pending,
    /// expressir accepted the source.
    Valid,
    /// expressir rejected the source (parse error or schema
    /// violation).
    Invalid,
}

impl ValidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ValidationStatus::Pending => "pending",
            ValidationStatus::Valid => "valid",
            ValidationStatus::Invalid => "invalid",
        }
    }

    pub fn parse(s: &str) -> Option<ValidationStatus> {
        match s.trim() {
            "pending" => Some(ValidationStatus::Pending),
            "valid" => Some(ValidationStatus::Valid),
            "invalid" => Some(ValidationStatus::Invalid),
            _ => None,
        }
    }
}

/// The validation record stored on a model item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationRecord {
    pub status: ValidationStatus,
    pub tool: String,
    pub detail: Option<String>,
}

impl ValidationRecord {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("status".into(), json!(self.status.as_str()));
        m.insert("tool".into(), json!(self.tool));
        if let Some(d) = &self.detail {
            m.insert("detail".into(), json!(d));
        }
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Result<ValidationRecord, String> {
        let obj = v.as_object().ok_or("validation record must be an object")?;
        let status = obj
            .get("status")
            .and_then(Value::as_str)
            .and_then(ValidationStatus::parse)
            .ok_or("invalid `validation.status`")?;
        let tool = obj
            .get("tool")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let detail = obj
            .get("detail")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(ValidationRecord {
            status,
            tool,
            detail,
        })
    }
}

/// Content hash of a deposit: `sha256:` + lowercase hex over the
/// exact deposited bytes. Retrieval may pin this hash (`GET
/// /models/{id}?hash=…`, mismatch → 409).
pub fn content_hash(source: &str) -> String {
    let digest = Sha256::digest(source.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Is the expressir binary reachable? (Used to pick assertions in
/// tests and to explain pending statuses.)
pub fn expressir_available() -> bool {
    std::process::Command::new(EXPRESSIR_BIN)
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Runs expressir over the source (temp file, subprocess).
///
/// - exit 0 → `Valid`;
/// - nonzero exit → `Invalid` with the last meaningful stderr/stdout
///   line as detail (expressir exits nonzero for parse failures and
///   for load-validation findings such as a missing schema version
///   string);
/// - binary missing → `Pending` (the degrade path).
pub fn validate_with_expressir(source: &str) -> ValidationRecord {
    let path = std::env::temp_dir().join(format!(
        "unidpp-registry-express-{}-{}.exp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let write = std::fs::write(&path, source);
    let outcome = match write {
        Err(e) => Some(ValidationRecord {
            status: ValidationStatus::Pending,
            tool: "filesystem".to_string(),
            detail: Some(format!("could not stage the source for validation: {e}")),
        }),
        Ok(()) => match run_expressir(&path) {
            Ok(output) if output.status.success() => Some(ValidationRecord {
                status: ValidationStatus::Valid,
                tool: EXPRESSIR_BIN.to_string(),
                detail: None,
            }),
            Ok(output) => Some(ValidationRecord {
                status: ValidationStatus::Invalid,
                tool: EXPRESSIR_BIN.to_string(),
                detail: Some(last_meaningful_line(&output)),
            }),
            Err(_) => None,
        },
    };
    let _ = std::fs::remove_file(&path);
    outcome.unwrap_or(ValidationRecord {
        status: ValidationStatus::Pending,
        tool: EXPRESSIR_BIN.to_string(),
        detail: Some(format!(
            "`{EXPR}` is not available (gem install expressir)",
            EXPR = EXPRESSIR_BIN
        )),
    })
}

fn run_expressir(path: &std::path::Path) -> std::io::Result<std::process::Output> {
    std::process::Command::new(EXPRESSIR_BIN)
        .arg("validate")
        .arg("load")
        .arg(path)
        .output()
}

/// The tail of the validator output, compacted (the Ruby CLI prints
/// a backtrace; the last frame names the failure).
fn last_meaningful_line(output: &std::process::Output) -> String {
    let text = String::from_utf8_lossy(&output.stderr);
    let line = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("expressir rejected the source");
    let mut detail: String = line.chars().take(300).collect();
    if text.lines().count() > 1 && detail.len() == 300 {
        detail.push('…');
    }
    detail
}

/// Builds a model item's manifest (seam-S4 version pin included).
pub fn model_manifest(version: &str, source: &str, validation: &ValidationRecord) -> Value {
    json!({
        "version": version,
        "express": {
            "source": source,
            "content_hash": content_hash(source),
            "validation": validation.to_json(),
        }
    })
}

/// Reads the express section of a model item's manifest.
pub struct ModelDeposit {
    pub source: String,
    pub content_hash: String,
    pub validation: ValidationRecord,
}

pub fn deposit_from_manifest(manifest: &Value) -> Result<ModelDeposit, String> {
    let x = manifest
        .get("express")
        .ok_or("model manifest missing `express`")?;
    let source = x
        .get("source")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("model manifest missing `express.source`")?
        .to_string();
    let content_hash = x
        .get("content_hash")
        .and_then(Value::as_str)
        .ok_or("model manifest missing `express.content_hash`")?
        .to_string();
    let validation = x
        .get("validation")
        .ok_or_else(|| "model manifest missing `express.validation`".to_string())
        .and_then(ValidationRecord::from_json)?;
    Ok(ModelDeposit {
        source,
        content_hash,
        validation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SOURCE: &str = "SCHEMA unidpp_registry_min '1.0.0';\nEND_SCHEMA;\n";
    const INVALID_SOURCE: &str = "SCHEMA unidpp registry broken;\n";

    #[test]
    fn content_hash_pins_the_exact_bytes() {
        let h = content_hash(VALID_SOURCE);
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), "sha256:".len() + 64);
        assert_eq!(content_hash(VALID_SOURCE), h, "deterministic");
        assert_ne!(
            content_hash(&VALID_SOURCE.replace('m', "M")),
            h,
            "byte-sensitive"
        );
    }

    #[test]
    fn validation_record_round_trips() {
        let r = ValidationRecord {
            status: ValidationStatus::Pending,
            tool: "expressir".into(),
            detail: Some("not available".into()),
        };
        assert_eq!(ValidationRecord::from_json(&r.to_json()).unwrap(), r);
        assert_eq!(r.to_json()["status"], "pending");
        for s in ["pending", "valid", "invalid"] {
            assert_eq!(ValidationStatus::parse(s).unwrap().as_str(), s);
        }
        assert!(ValidationStatus::parse("nope").is_none());
    }

    #[test]
    fn expressir_validation_of_a_minimal_schema() {
        // When expressir is installed, a versioned minimal schema
        // validates and a syntactically broken one is invalid; when
        // it is not installed, both come back pending (the degrade
        // path). A *valid* schema is never reported invalid, and an
        // invalid one is never reported valid.
        if expressir_available() {
            assert_eq!(
                validate_with_expressir(VALID_SOURCE).status,
                ValidationStatus::Valid
            );
            assert_eq!(
                validate_with_expressir(INVALID_SOURCE).status,
                ValidationStatus::Invalid
            );
            let bad = validate_with_expressir(INVALID_SOURCE);
            assert!(bad.detail.is_some());
        } else {
            assert_eq!(
                validate_with_expressir(VALID_SOURCE).status,
                ValidationStatus::Pending
            );
            assert_eq!(
                validate_with_expressir(INVALID_SOURCE).status,
                ValidationStatus::Pending
            );
        }
    }

    #[test]
    fn the_vendored_unidpp_core_schema_validates_or_degrades() {
        let source = include_str!("../assets/unidpp-core.express");
        let rec = validate_with_expressir(source);
        assert_ne!(
            rec.status,
            ValidationStatus::Invalid,
            "the vendored UNIDPP_CORE schema must validate (or be pending when expressir is absent)"
        );
    }

    #[test]
    fn manifest_round_trip() {
        let rec = ValidationRecord {
            status: ValidationStatus::Valid,
            tool: "expressir".into(),
            detail: None,
        };
        let m = model_manifest("1.0.0", VALID_SOURCE, &rec);
        assert_eq!(m["version"], "1.0.0");
        let d = deposit_from_manifest(&m).unwrap();
        assert_eq!(d.source, VALID_SOURCE);
        assert_eq!(d.content_hash, content_hash(VALID_SOURCE));
        assert_eq!(d.validation, rec);
        assert!(deposit_from_manifest(&json!({"version": "1"})).is_err());
    }
}
