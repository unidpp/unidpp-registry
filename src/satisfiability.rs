//! Profile satisfiability (T-23): capability-class constraints of a
//! profile manifest, as a pure function — no IO, no store access.
//!
//! Subject capability classes (I8: twin testimonial by default,
//! sensorial by exception):
//!
//! | class | name           | serves                                    |
//! |-------|----------------|-------------------------------------------|
//! | S0    | silent         | testimony-only (no connectivity, no keys) |
//! | S1    | passive-auth   | NFC chip / PUF / IEC 61406 identity link  |
//! | S2    | logged-contact | dumps on physical read, no comms          |
//! | S3    | connected      | full edge segments                        |
//!
//! The normative rule: a profile demanding live freshness from an S0
//! product is an unsatisfiable profile. Concretely, a manifest whose
//! declared subject capability class cannot serve a data point's
//! demands — `min_capability` above the declared class, or a bounded
//! `fresh_within` on an S0/S1 subject — is rejected at intake
//! (strict) or warned about (`strict = false`).

/// The capability-class ladder, weakest to strongest.
pub const CAPABILITY_CLASSES: [&str; 4] = ["S0", "S1", "S2", "S3"];

/// Rank on the capability ladder (S0 = 0 … S3 = 3); `None` when the
/// token is not a capability class.
pub fn capability_rank(class: &str) -> Option<u8> {
    CAPABILITY_CLASSES
        .iter()
        .position(|c| *c == class)
        .map(|p| p as u8)
}

/// Does `actual` meet or exceed `required`? (Ladder semantics.)
pub fn satisfies(required: &str, actual: &str) -> bool {
    match (capability_rank(required), capability_rank(actual)) {
        (Some(r), Some(a)) => a >= r,
        _ => false,
    }
}

/// One satisfiability violation: the offending data point (field
/// path into the manifest) and why it cannot be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub message: String,
}

use crate::manifest::ProfileManifest;

/// Checks a parsed profile manifest for unsatisfiable capability
/// demands. Ok(()) when every data point is servable by the declared
/// subject capability class (or none is declared — an undeclared
/// class is not checkable, and passes).
pub fn check(manifest: &ProfileManifest) -> Result<(), Vec<Violation>> {
    let Some(subject) = manifest.subject_capability.as_deref() else {
        return Ok(());
    };
    let Some(subject_rank) = capability_rank(subject) else {
        return Ok(()); // unknown tokens are the schema check's problem
    };
    let mut violations = Vec::new();
    for (i, dp) in manifest.data_points.iter().enumerate() {
        let path = format!("data_points[{i}].min_capability");
        if let Some(demanded) = capability_rank(&dp.min_capability) {
            if demanded > subject_rank {
                violations.push(Violation {
                    path,
                    message: format!(
                        "data point `{}` demands capability `{}` but the profile's declared subject capability class is `{}` — unsatisfiable",
                        dp.element, dp.min_capability, subject
                    ),
                });
            }
        }
        if let Some(fresh) = dp.fresh_within.as_deref() {
            if !fresh.is_empty() && subject_rank <= 1 {
                violations.push(Violation {
                    path: format!("data_points[{i}].fresh_within"),
                    message: format!(
                        "data point `{}` demands freshness within `{fresh}` but an `{subject}` subject (silent/passive-auth) cannot serve bounded freshness — unsatisfiable",
                        dp.element
                    ),
                });
            }
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{DataPoint, ProfileManifest};

    fn manifest(subject: Option<&str>, dps: Vec<DataPoint>) -> ProfileManifest {
        ProfileManifest {
            version: "1.0.0".into(),
            subject_capability: subject.map(str::to_string),
            axes: vec![],
            legal_basis: vec![],
            transforms: vec![],
            triggers: vec![],
            data_points: dps,
        }
    }

    fn dp(element: &str, min_capability: &str) -> DataPoint {
        DataPoint {
            element: element.into(),
            min_capability: min_capability.into(),
            fresh_within: None,
        }
    }

    #[test]
    fn ladder_orders_and_satisfies() {
        assert!(satisfies("S0", "S3"));
        assert!(satisfies("S2", "S2"));
        assert!(!satisfies("S3", "S0"));
        assert!(!satisfies("S1", "S0"));
        assert_eq!(capability_rank("S3"), Some(3));
        assert_eq!(capability_rank("X"), None);
        assert_eq!(CAPABILITY_CLASSES.len(), 4);
    }

    #[test]
    fn s3_demand_on_s0_is_rejected_with_the_field_path() {
        let m = manifest(Some("S0"), vec![dp("de/m/x", "S3")]);
        let v = check(&m).unwrap_err();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].path, "data_points[0].min_capability");
        assert!(v[0].message.contains("S3"));
        assert!(v[0].message.contains("S0"));
    }

    #[test]
    fn s3_demand_on_s3_passes() {
        let m = manifest(Some("S3"), vec![dp("de/m/x", "S3")]);
        assert!(check(&m).is_ok());
        // and every weaker demand too
        let m = manifest(Some("S2"), vec![dp("de/m/x", "S0"), dp("de/m/y", "S2")]);
        assert!(check(&m).is_ok());
    }

    #[test]
    fn bounded_freshness_is_unsatisfiable_below_s2() {
        let mut d = dp("de/m/co2", "S0");
        d.fresh_within = Some("P1D".into());
        let v = check(&manifest(Some("S0"), vec![d])).unwrap_err();
        assert_eq!(v[0].path, "data_points[0].fresh_within");
        assert!(v[0].message.contains("P1D"));
        // S1 also cannot serve bounded freshness
        let mut d = dp("de/m/co2", "S0");
        d.fresh_within = Some("PT12H".into());
        assert!(check(&manifest(Some("S1"), vec![d])).is_err());
        // S2 can (logged-contact dumps on read)
        let mut d = dp("de/m/co2", "S2");
        d.fresh_within = Some("P1D".into());
        assert!(check(&manifest(Some("S2"), vec![d])).is_ok());
    }

    #[test]
    fn undeclared_subject_class_is_not_checkable() {
        let m = manifest(None, vec![dp("de/m/x", "S3")]);
        assert!(check(&m).is_ok());
    }

    #[test]
    fn every_offending_data_point_is_reported() {
        let mut a = dp("de/m/a", "S2");
        a.fresh_within = Some("P1D".into());
        let m = manifest(Some("S0"), vec![dp("de/m/ok", "S0"), a, dp("de/m/c", "S3")]);
        let v = check(&m).unwrap_err();
        let paths: Vec<&str> = v.iter().map(|x| x.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                // the S2 demand and the bounded freshness are both
                // unsatisfiable on the S0 subject
                "data_points[1].min_capability",
                "data_points[1].fresh_within",
                "data_points[2].min_capability"
            ]
        );
    }
}
