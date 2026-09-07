//! Clock predicates (T-02): time-based applicability triggers.
//!
//! A profile's trigger may be clock-fired — it fires on the passage
//! of time alone, with no human declaring the event. The doctrinal
//! case is the antique vehicle: at T = 2002, a subject manufactured
//! in 1962 crosses a `manufactured_at + P40Y >= now` threshold and
//! the historic-vehicle profile binds.
//!
//! Trigger shape (one entry of the manifest's `triggers` array):
//!
//! ```json
//! {"predicate_class": "time", "basis": "manufactured_at",
//!  "operator": ">=", "duration": "P40Y"}
//! ```
//!
//! - `basis` names a subject fact holding an RFC 3339 instant
//!   (`manufactured_at` | `first_registered_at`);
//! - `duration` is an ISO 8601 duration added to the basis instant,
//!   calendar-aware (a month added to January 31 lands on the last
//!   day of February, not March 3);
//! - the comparison is evaluated at the query instant: the predicate
//!   is satisfied iff `at <operator> basis + duration`.
//!
//! The module is pure — no IO, no store access. The applicability
//! endpoint feeds it the request's `subject_facts` and the query
//! instant; the binding-store's as-of machinery decides the rest.
//! Fact predicates (`predicate_class: "fact_predicate"`) are
//! evaluated locally by the subject's custodian, never by the
//! registry — the registry evaluates only what the passage of time
//! makes computable.

use serde_json::Value;

use crate::time::{civil_from_days, days_from_civil, days_in_month, Timestamp};

/// Fact keys a time predicate may use as its basis (T-02).
pub const BASES: [&str; 2] = ["manufactured_at", "first_registered_at"];
/// Comparison operators a time predicate may use.
pub const OPERATORS: [&str; 4] = [">=", ">", "<=", "<"];

const SECS_PER_DAY: i64 = 86_400;

/// An ISO 8601 duration, normalized into calendar months plus
/// absolute seconds (`P40Y` → 480 months; `P2W` → 14 days).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duration {
    pub months: i64,
    pub seconds: i64,
}

impl Duration {
    pub const ZERO: Duration = Duration {
        months: 0,
        seconds: 0,
    };
}

/// Parses an ISO 8601 duration (`P[nY][nM][nW][nD][T[nH][nM][nS]]`,
/// at least one component required). Strict: uppercase designators
/// only, ASCII digits only, components in calendar order.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let err =
        || format!("invalid ISO 8601 duration `{input}` (expected e.g. P40Y, P1Y6M3D, PT6H30M)");
    let s = input.strip_prefix('P').ok_or_else(err)?;
    let (date_part, time_part) = match s.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    let mut months: i64 = 0;
    let mut seconds: i64 = 0;
    let mut seen = false;
    let mut rest = date_part;
    for (unit, apply) in [
        (b'Y', Apply::Years),
        (b'M', Apply::Months),
        (b'W', Apply::Weeks),
        (b'D', Apply::Days),
    ] {
        if let Some((n, used)) = take_component(rest, unit).map_err(|_| err())? {
            match apply {
                Apply::Years => months += n * 12,
                Apply::Months => months += n,
                Apply::Weeks => seconds += n * 7 * SECS_PER_DAY,
                Apply::Days => seconds += n * SECS_PER_DAY,
            }
            rest = &rest[used..];
            seen = true;
        }
    }
    if !rest.is_empty() {
        return Err(err());
    }
    if let Some(t) = time_part {
        let mut trest = t;
        for (unit, secs_per) in [(b'H', 3_600i64), (b'M', 60), (b'S', 1)] {
            if let Some((n, used)) = take_component(trest, unit).map_err(|_| err())? {
                seconds += n * secs_per;
                trest = &trest[used..];
                seen = true;
            }
        }
        if !trest.is_empty() || t.is_empty() {
            return Err(err());
        }
    }
    if !seen || date_part.is_empty() && time_part.is_none() {
        return Err(err());
    }
    Ok(Duration { months, seconds })
}

enum Apply {
    Years,
    Months,
    Weeks,
    Days,
}

/// Takes one `<digits><unit>` component from the front of `s` when
/// present. Byte-based (panic-free on non-ASCII input).
fn take_component(s: &str, unit: u8) -> Result<Option<(i64, usize)>, String> {
    let b = s.as_bytes();
    let n = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 || n >= b.len() || b[n] != unit {
        return Ok(None);
    }
    let value: i64 = s[..n]
        .parse()
        .map_err(|_| "duration component overflows".to_string())?;
    Ok(Some((value, n + 1)))
}

/// Adds a duration to a timestamp, calendar-aware: year/month
/// components are applied in the civil calendar (day clamped to the
/// target month's last day), day/time components in absolute
/// seconds.
pub fn add_duration(t: Timestamp, d: &Duration) -> Timestamp {
    if d.months == 0 {
        return Timestamp {
            secs: t.secs + d.seconds,
        };
    }
    let days = t.secs.div_euclid(SECS_PER_DAY);
    let time_of_day = t.secs.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let total = year * 12 + (month as i64 - 1) + d.months;
    let new_year = total.div_euclid(12);
    let new_month = (total.rem_euclid(12) + 1) as u32;
    let last = i64::from(days_in_month(new_year, new_month));
    let new_day = (i64::from(day)).min(last) as u32;
    Timestamp {
        secs: days_from_civil(new_year, new_month, new_day) * SECS_PER_DAY
            + time_of_day
            + d.seconds,
    }
}

/// A parsed time trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeTrigger {
    pub basis: String,
    pub operator: String,
    pub duration: Duration,
    pub duration_raw: String,
}

/// Parses one trigger object (`{predicate_class: "time", basis,
/// operator, duration}`) into a [`TimeTrigger`].
pub fn parse_time_trigger(trigger: &Value) -> Result<TimeTrigger, String> {
    let obj = trigger
        .as_object()
        .ok_or("time trigger must be an object")?;
    let get = |k: &str| -> Result<String, String> {
        obj.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("time trigger missing `{k}`"))
    };
    let basis = get("basis")?;
    if !BASES.contains(&basis.as_str()) {
        return Err(format!(
            "time trigger `basis` `{basis}` is not one of {}",
            BASES.join(", ")
        ));
    }
    let operator = get("operator")?;
    if !OPERATORS.contains(&operator.as_str()) {
        return Err(format!(
            "time trigger `operator` `{operator}` is not one of {}",
            OPERATORS.join(", ")
        ));
    }
    let duration_raw = get("duration")?;
    let duration = parse_duration(&duration_raw)?;
    Ok(TimeTrigger {
        basis,
        operator,
        duration,
        duration_raw,
    })
}

/// The result of evaluating one time trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockEvaluation {
    /// The instant the trigger's threshold sits at (`basis +
    /// duration`).
    pub threshold: Timestamp,
    /// Whether the predicate holds at the query instant.
    pub satisfied: bool,
}

/// Evaluates a time trigger against the subject facts at instant
/// `at`. The basis fact must be present and parse as an RFC 3339
/// timestamp; a missing or unparseable fact is an error (the caller
/// decides whether that means "does not bind" or a 400).
pub fn evaluate(
    trigger: &TimeTrigger,
    facts: &Value,
    at: Timestamp,
) -> Result<ClockEvaluation, String> {
    let raw = facts
        .get(trigger.basis.as_str())
        .and_then(Value::as_str)
        .ok_or_else(|| format!("subject facts missing the `{}` basis", trigger.basis))?;
    let basis =
        Timestamp::parse(raw).map_err(|e| format!("subject fact `{}`: {e}", trigger.basis))?;
    let threshold = add_duration(basis, &trigger.duration);
    let satisfied = match trigger.operator.as_str() {
        ">=" => at >= threshold,
        ">" => at > threshold,
        "<=" => at <= threshold,
        "<" => at < threshold,
        other => return Err(format!("unsupported operator `{other}`")),
    };
    Ok(ClockEvaluation {
        threshold,
        satisfied,
    })
}

/// Collects the time triggers of a profile manifest, with their
/// indices in the manifest's `triggers` array. Triggers with another
/// `predicate_class` are skipped (fact predicates are the
/// custodian's concern, not the registry's).
pub fn time_triggers(manifest: &Value) -> Result<Vec<(usize, TimeTrigger)>, String> {
    let mut out = Vec::new();
    let Some(triggers) = manifest.get("triggers").and_then(Value::as_array) else {
        return Ok(out);
    };
    for (i, t) in triggers.iter().enumerate() {
        if t.get("predicate_class").and_then(Value::as_str) == Some("time") {
            out.push((i, parse_time_trigger(t)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    #[test]
    fn duration_forms_parse() {
        let d = parse_duration("P40Y").unwrap();
        assert_eq!(
            d,
            Duration {
                months: 480,
                seconds: 0
            }
        );
        let d = parse_duration("P1Y6M3D").unwrap();
        assert_eq!(
            d,
            Duration {
                months: 18,
                seconds: 3 * SECS_PER_DAY
            }
        );
        let d = parse_duration("P2W").unwrap();
        assert_eq!(d.seconds, 14 * SECS_PER_DAY);
        let d = parse_duration("PT6H30M").unwrap();
        assert_eq!(d.seconds, 6 * 3_600 + 30 * 60);
        let d = parse_duration("PT90S").unwrap();
        assert_eq!(d.seconds, 90);
        let d = parse_duration("P0D").unwrap();
        assert_eq!(d, Duration::ZERO);
        let d = parse_duration("P1Y2M3DT4H5M6S").unwrap();
        assert_eq!(d.months, 14);
        assert_eq!(d.seconds, 3 * 86_400 + 4 * 3_600 + 5 * 60 + 6);
    }

    #[test]
    fn duration_rejects_malformed() {
        for bad in [
            "", "40Y", "P", "PX", "P1.5Y", "PT", "P1H", "T1H", "P1YX", "P-1Y", "P1y", "P1YT",
            "PT1M30",
        ] {
            assert!(parse_duration(bad).is_err(), "`{bad}` should not parse");
        }
    }

    #[test]
    fn add_duration_is_calendar_aware() {
        // the antique case: 1962-05-04 + 40 years
        assert_eq!(
            add_duration(
                ts("1962-05-04T00:00:00Z"),
                &Duration {
                    months: 480,
                    seconds: 0
                }
            ),
            ts("2002-05-04T00:00:00Z")
        );
        // month-end clamping, non-leap and leap
        assert_eq!(
            add_duration(
                ts("2026-01-31T12:00:00Z"),
                &Duration {
                    months: 1,
                    seconds: 0
                }
            ),
            ts("2026-02-28T12:00:00Z")
        );
        assert_eq!(
            add_duration(
                ts("2024-01-31T00:00:00Z"),
                &Duration {
                    months: 1,
                    seconds: 0
                }
            ),
            ts("2024-02-29T00:00:00Z")
        );
        // year rollover with clamping (Feb 29 + 1 year)
        assert_eq!(
            add_duration(
                ts("2024-02-29T00:00:00Z"),
                &Duration {
                    months: 12,
                    seconds: 0
                }
            ),
            ts("2025-02-28T00:00:00Z")
        );
        // absolute seconds keep the time of day
        assert_eq!(
            add_duration(
                ts("2000-01-01T00:00:00Z"),
                &Duration {
                    months: 0,
                    seconds: 86_400 + 3_600
                }
            ),
            ts("2000-01-02T01:00:00Z")
        );
        // months and seconds compose
        let d = parse_duration("P1M1DT1H").unwrap();
        assert_eq!(
            add_duration(ts("2026-03-15T10:00:00Z"), &d),
            ts("2026-04-16T11:00:00Z")
        );
        // negative results stay on the proleptic calendar
        assert_eq!(
            add_duration(
                ts("1962-05-04T00:00:00Z"),
                &Duration {
                    months: -12,
                    seconds: 0
                }
            ),
            ts("1961-05-04T00:00:00Z")
        );
    }

    fn antique(fact: &str, at: &str) -> Result<ClockEvaluation, String> {
        let t = parse_time_trigger(&json!({
            "predicate_class": "time", "basis": "manufactured_at",
            "operator": ">=", "duration": "P40Y"
        }))
        .unwrap();
        evaluate(&t, &json!({ "manufactured_at": fact }), ts(at))
    }

    #[test]
    fn antique_threshold_boundary() {
        // threshold = 1962-05-04 + P40Y = 2002-05-04
        let e = antique("1962-05-04T00:00:00Z", "2002-05-04T00:00:00Z").unwrap();
        assert_eq!(e.threshold, ts("2002-05-04T00:00:00Z"));
        assert!(e.satisfied, ">= is inclusive at the threshold instant");
        assert!(
            !antique("1962-05-04T00:00:00Z", "2002-05-03T23:59:59Z")
                .unwrap()
                .satisfied
        );
        assert!(
            !antique("1962-05-04T00:00:00Z", "2001-06-01T00:00:00Z")
                .unwrap()
                .satisfied
        );
        assert!(
            antique("1962-05-04T00:00:00Z", "2003-01-01T00:00:00Z")
                .unwrap()
                .satisfied
        );
    }

    #[test]
    fn operators_evaluate_against_the_threshold() {
        let eval = |op: &str, at: &str| -> bool {
            let t = parse_time_trigger(&json!({
                "predicate_class": "time", "basis": "first_registered_at",
                "operator": op, "duration": "P30D"
            }))
            .unwrap();
            evaluate(
                &t,
                &json!({ "first_registered_at": "2026-01-01T00:00:00Z" }),
                ts(at),
            )
            .unwrap()
            .satisfied
        };
        assert!(eval(">", "2026-01-31T00:00:01Z"));
        assert!(!eval(">", "2026-01-31T00:00:00Z"), "> is exclusive");
        assert!(eval("<=", "2026-01-31T00:00:00Z"));
        assert!(!eval("<", "2026-01-31T00:00:00Z"), "< is exclusive");
        assert!(
            eval("<", "2026-01-02T00:00:00Z"),
            "before the threshold, < holds"
        );
        assert!(
            !eval("<", "2026-02-01T00:00:00Z"),
            "after the threshold, < fails"
        );
    }

    #[test]
    fn missing_or_bad_fact_is_an_error() {
        let t = parse_time_trigger(&json!({
            "predicate_class": "time", "basis": "manufactured_at",
            "operator": ">=", "duration": "P40Y"
        }))
        .unwrap();
        let e = evaluate(&t, &json!({}), ts("2026-01-01T00:00:00Z")).unwrap_err();
        assert!(e.contains("missing the `manufactured_at` basis"));
        let e = evaluate(
            &t,
            &json!({ "manufactured_at": "not-a-date" }),
            ts("2026-01-01T00:00:00Z"),
        )
        .unwrap_err();
        assert!(e.contains("subject fact"));
    }

    #[test]
    fn malformed_time_triggers_are_rejected_at_parse() {
        for bad in [
            json!({}),
            json!({ "predicate_class": "time" }),
            json!({ "predicate_class": "time", "basis": "sold_at", "operator": ">=", "duration": "P1Y" }),
            json!({ "predicate_class": "time", "basis": "manufactured_at", "operator": "==", "duration": "P1Y" }),
            json!({ "predicate_class": "time", "basis": "manufactured_at", "operator": ">=", "duration": "40Y" }),
        ] {
            assert!(parse_time_trigger(&bad).is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn time_triggers_collected_from_a_manifest() {
        let manifest = json!({
            "version": "1.0.0",
            "triggers": [
                { "predicate_class": "fact_predicate", "predicate_ref": "pred/x" },
                { "predicate_class": "time", "basis": "manufactured_at", "operator": ">=", "duration": "P40Y" }
            ]
        });
        let got = time_triggers(&manifest).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, 1, "only the time trigger, at its index");
        assert_eq!(got[0].1.duration_raw, "P40Y");
        assert!(time_triggers(&json!({ "version": "1.0.0" }))
            .unwrap()
            .is_empty());
        let broken = json!({ "triggers": [ { "predicate_class": "time" } ] });
        assert!(time_triggers(&broken).is_err());
    }
}
