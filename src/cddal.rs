//! CDDAL: the canonical plain-text serialization of registry items
//! (T-06 / item 83).
//!
//! Exchange between semantic-registry hosts uses CDDAL — the
//! IEC 61360 / ISO/IEC 62656 dictionary plain-text form (OpenCDD's
//! grammar as the reference) — so that two mirrors of the same item
//! version produce byte-identical canonical forms and cross-host
//! comparison reduces to hashing. This module lands the **canonical
//! subset** the registry's item model exercises:
//!
//! - one `TERM` block per item, fields in a fixed canonical order,
//!   LF line endings, two-space field indent;
//! - item identity (`identifier`, IRDI when the manifest carries
//!   one, `register`, `class`), the dictionary slots (`name`,
//!   `definition`), the data-element representation and unit (from
//!   the manifest), and the resolved version (`version`, `status`,
//!   effective window start, registration stamp) — the same
//!   resolution rule as the JSON view (`in_force_at` with `at=`,
//!   else the current registered version);
//! - values are single logical lines; `\`, LF and CR are escaped
//!   (`\\`, `\n`, `\r`) so every model value round-trips;
//! - no serving metadata: the `as_of` stamp rides in the `x-as-of`
//!   header only, never the body — two reads of the same state are
//!   byte-identical.
//!
//! [`parse`] reads the form back into [`TermEntry`] — the CDDAL
//! projection of the item model — proving the canonicalization
//! round trip ([`TermEntry::of`] → [`render`] → [`parse`] →
//! equality).
//!
//! ## Coverage boundary (honest scope)
//!
//! A full OpenCDD grammar is out of scope. Not serialized: the full
//! version history and supersession chains (only the resolved
//! version is emitted — history stays in the JSON form), the
//! embedded manifests beyond the named keys (`irdi`, `name`,
//! `representation`, `unit`/`required_unit`/`unit_ref`, `symbol`),
//! applicability bindings, the discovery layer (C3/C4/C5), and
//! signed descriptor bodies. JSON remains the full-fidelity form;
//! CDDAL is the canonical exchange projection of the dictionary
//! slots. Negotiation applies to the collection reads (`GET /items`
//! and the subregister listings); single-item reads stay JSON.

use std::fmt::Write as _;

use crate::model::{Item, ItemClass, Status};
use crate::time::Timestamp;
use serde_json::Value;

/// The media type of the canonical plain-text form.
pub const MEDIA_TYPE: &str = "text/cddal";

/// The warning header set when an unknown `Accept` falls back to
/// JSON.
pub const FALLBACK_HEADER: &str = "x-content-negotiation";

/// The warning value: "served JSON although nothing in `Accept` was
/// servable".
pub const FALLBACK_VALUE: &str = "unknown-accept-fallback";

/// The field keys, in canonical order (the order [`render`] emits
/// and the closed set [`parse`] accepts).
pub const FIELDS: [&str; 13] = [
    "irdi",
    "register",
    "class",
    "name",
    "definition",
    "submitting_organization",
    "representation",
    "unit",
    "unit_symbol",
    "version",
    "status",
    "effective_from",
    "registered_at",
];

// ---------------------------------------------------------------------------
// The term entry (the CDDAL projection of an item)
// ---------------------------------------------------------------------------

/// The resolved version carried by a term block (RFC 3339 stamps in
/// canonical display form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionEntry {
    pub version: String,
    pub status: String,
    pub effective_from: Option<String>,
    pub registered_at: Option<String>,
}

/// One dictionary term block: the CDDAL projection of a registry
/// item. Built from the item model ([`TermEntry::of`]) — never
/// assembled per endpoint — and the target of [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermEntry {
    pub identifier: String,
    /// IRDI (IEC IRDS form) when the item's manifest carries one.
    pub irdi: Option<String>,
    pub register: String,
    /// Canonical item-class name (`ItemClass::as_str`).
    pub item_class: String,
    /// The dictionary name: the manifest's `name` when present,
    /// else the 19135 definition slot (the model has one title
    /// slot serving both roles).
    pub name: String,
    /// The 19135 definition slot (the item title).
    pub definition: String,
    pub submitting_organization: Option<String>,
    /// Data elements: the raw representation notation (`an..35`).
    pub representation: Option<String>,
    /// Data elements: the unit reference.
    pub unit: Option<String>,
    /// Units: the unit symbol.
    pub unit_symbol: Option<String>,
    /// The resolved version (`in_force_at` with `at`, else the
    /// current registered version); `None` when nothing is in
    /// force and no current version exists.
    pub version: Option<VersionEntry>,
}

impl TermEntry {
    /// Projects an item into its CDDAL term entry, resolving the
    /// version exactly like the JSON view: with `at`, the version
    /// in force at that instant; without, the current registered
    /// version.
    pub fn of(item: &Item, at: Option<Timestamp>) -> TermEntry {
        let manifest = item.manifest.as_ref();
        let mstr = |keys: &[&str]| -> Option<String> {
            manifest.and_then(|m| {
                keys.iter().find_map(|k| {
                    m.get(*k)
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                })
            })
        };
        // Class-scoped manifest slots (MECE: each class reads only
        // the keys its manifests carry).
        let (representation, unit, unit_symbol) = match item.item_class {
            ItemClass::DataElement => (
                mstr(&["representation"]),
                mstr(&["unit", "required_unit", "unit_ref"]),
                None,
            ),
            ItemClass::Unit => (None, None, mstr(&["symbol"])),
            _ => (None, None, None),
        };
        let resolved = match at {
            Some(t) => item.in_force_at(t),
            None => item.current_version(),
        };
        TermEntry {
            identifier: item.identifier.clone(),
            irdi: mstr(&["irdi"]),
            register: item.register.clone(),
            item_class: item.item_class.as_str().to_string(),
            name: mstr(&["name"]).unwrap_or_else(|| item.title.clone()),
            definition: item.title.clone(),
            submitting_organization: item.submitting_organization.clone(),
            representation,
            unit,
            unit_symbol,
            version: resolved.map(|v| VersionEntry {
                version: v.version.clone(),
                status: v.status.as_str().to_string(),
                effective_from: v.effective_from.map(|t| t.to_string()),
                registered_at: v.registered_at.map(|t| t.to_string()),
            }),
        }
    }

    /// Appends the canonical block for this entry (`TERM …` line,
    /// present fields in [`FIELDS`] order, `END` line).
    pub fn render_into(&self, out: &mut String) {
        let _ = writeln!(out, "TERM {}", self.identifier);
        if let Some(v) = &self.irdi {
            write_field(out, "irdi", v);
        }
        write_field(out, "register", &self.register);
        write_field(out, "class", &self.item_class);
        write_field(out, "name", &self.name);
        write_field(out, "definition", &self.definition);
        if let Some(v) = &self.submitting_organization {
            write_field(out, "submitting_organization", v);
        }
        if let Some(v) = &self.representation {
            write_field(out, "representation", v);
        }
        if let Some(v) = &self.unit {
            write_field(out, "unit", v);
        }
        if let Some(v) = &self.unit_symbol {
            write_field(out, "unit_symbol", v);
        }
        if let Some(v) = &self.version {
            write_field(out, "version", &v.version);
            write_field(out, "status", &v.status);
            if let Some(t) = &v.effective_from {
                write_field(out, "effective_from", t);
            }
            if let Some(t) = &v.registered_at {
                write_field(out, "registered_at", t);
            }
        }
        out.push_str("END\n");
    }
}

/// Renders a whole document (blocks in the given order — the store
/// serves them identifier-sorted, so the byte form is canonical).
pub fn render(entries: &[TermEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        e.render_into(&mut out);
    }
    out
}

// ---------------------------------------------------------------------------
// Canonical value escaping (single-line fields)
// ---------------------------------------------------------------------------

fn write_field(out: &mut String, key: &str, value: &str) {
    out.push_str("  ");
    out.push_str(key);
    out.push_str(": ");
    escape_value(value, out);
    out.push('\n');
}

fn escape_value(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
}

fn unescape_value(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some(other) => {
                    return Err(format!("invalid escape `\\{other}`"));
                }
                None => return Err("trailing escape at end of value".into()),
            },
            _ => out.push(c),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parser (the canonicalization proof's read side)
// ---------------------------------------------------------------------------

/// A block under construction (fields collected in document order;
/// order and duplicates are validated when the block closes).
struct RawTerm {
    identifier: String,
    fields: Vec<(String, String)>,
}

fn take_field(fields: &mut Vec<(String, String)>, key: &str) -> Option<String> {
    fields
        .iter()
        .position(|(k, _)| k == key)
        .map(|i| fields.remove(i).1)
}

/// Required-field extraction with the canonical error shape.
fn required_field(
    fields: &mut Vec<(String, String)>,
    key: &str,
    identifier: &str,
    line: usize,
) -> Result<String, String> {
    take_field(fields, key).ok_or_else(|| {
        format!("line {line}: term `{identifier}` is missing required field `{key}`")
    })
}

/// Optional RFC 3339 stamp extraction (canonical display form).
fn optional_stamp(
    fields: &mut Vec<(String, String)>,
    key: &str,
    identifier: &str,
    line: usize,
) -> Result<Option<String>, String> {
    match take_field(fields, key) {
        None => Ok(None),
        Some(raw) => Timestamp::parse(&raw)
            .map(|t| Some(t.to_string()))
            .map_err(|_| {
                format!("line {line}: term `{identifier}` field `{key}` is not RFC 3339: `{raw}`")
            }),
    }
}

impl RawTerm {
    /// Validates and assembles the collected fields into a term
    /// entry (`line` is the block's `END` line, for error paths).
    fn into_entry(self, line: usize) -> Result<TermEntry, String> {
        let mut fields = self.fields;
        let identifier = self.identifier;
        let item_class = required_field(&mut fields, "class", &identifier, line)?;
        if ItemClass::parse(&item_class).is_none() {
            return Err(format!(
                "line {line}: term `{identifier}` has unknown item class `{item_class}`"
            ));
        }
        let version = match take_field(&mut fields, "version") {
            Some(version) => {
                let status = take_field(&mut fields, "status").ok_or_else(|| {
                    format!("line {line}: term `{identifier}` has `version` without `status`")
                })?;
                if Status::parse(&status).is_none() {
                    return Err(format!(
                        "line {line}: term `{identifier}` has unknown status `{status}`"
                    ));
                }
                Some(VersionEntry {
                    version,
                    status,
                    effective_from: optional_stamp(
                        &mut fields,
                        "effective_from",
                        &identifier,
                        line,
                    )?,
                    registered_at: optional_stamp(&mut fields, "registered_at", &identifier, line)?,
                })
            }
            None => {
                if fields.iter().any(|(k, _)| {
                    matches!(k.as_str(), "status" | "effective_from" | "registered_at")
                }) {
                    return Err(format!(
                        "line {line}: term `{identifier}` has version fields without `version`"
                    ));
                }
                None
            }
        };
        let register = required_field(&mut fields, "register", &identifier, line)?;
        let name = required_field(&mut fields, "name", &identifier, line)?;
        let definition = required_field(&mut fields, "definition", &identifier, line)?;
        let irdi = take_field(&mut fields, "irdi");
        let submitting_organization = take_field(&mut fields, "submitting_organization");
        let representation = take_field(&mut fields, "representation");
        let unit = take_field(&mut fields, "unit");
        let unit_symbol = take_field(&mut fields, "unit_symbol");
        Ok(TermEntry {
            identifier,
            irdi,
            register,
            item_class,
            name,
            definition,
            submitting_organization,
            representation,
            unit,
            unit_symbol,
            version,
        })
    }
}

/// Splits a field body (`key: value`, the two-space indent already
/// stripped) at the first colon. Values may themselves contain
/// colons; keys are from the closed [`FIELDS`] set.
fn split_field(body: &str) -> Option<(&str, &str)> {
    let (key, rest) = body.split_once(':')?;
    let value = rest.strip_prefix(' ')?;
    Some((key, value))
}

/// Parses a CDDAL document back into term entries. Strict by
/// design (register admission runs canonicalization round-trip as a
/// gate): unknown or duplicate fields, blank lines inside blocks,
/// unterminated blocks, empty values and invalid escapes are
/// errors, each naming the line.
pub fn parse(text: &str) -> Result<Vec<TermEntry>, String> {
    let mut entries = Vec::new();
    let mut current: Option<RawTerm> = None;
    for (i, line) in text.split('\n').enumerate() {
        let n = i + 1;
        if line.is_empty() {
            if current.is_some() {
                return Err(format!("line {n}: blank line inside a term block"));
            }
            continue;
        }
        if let Some(id) = line.strip_prefix("TERM ") {
            if current.is_some() {
                return Err(format!("line {n}: TERM inside a term block (missing END?)"));
            }
            if id.is_empty() || id.chars().any(char::is_whitespace) {
                return Err(format!(
                    "line {n}: term identifier must be a non-empty token without whitespace"
                ));
            }
            current = Some(RawTerm {
                identifier: id.to_string(),
                fields: Vec::new(),
            });
            continue;
        }
        if line == "END" {
            let raw = current
                .take()
                .ok_or_else(|| format!("line {n}: END without a term block"))?;
            entries.push(raw.into_entry(n)?);
            continue;
        }
        let Some(body) = line.strip_prefix("  ") else {
            return Err(format!(
                "line {n}: not a term-block line (expected `TERM <id>`, `  <field>: <value>` or `END`)"
            ));
        };
        let (key, raw_value) =
            split_field(body).ok_or_else(|| format!("line {n}: field line has no `key: value`"))?;
        if !FIELDS.contains(&key) {
            return Err(format!("line {n}: unknown field `{key}`"));
        }
        let value = unescape_value(raw_value).map_err(|e| format!("line {n}: {e}"))?;
        if value.is_empty() {
            return Err(format!("line {n}: field `{key}` has an empty value"));
        }
        let raw = current
            .as_mut()
            .ok_or_else(|| format!("line {n}: field outside a term block"))?;
        if raw.fields.iter().any(|(k, _)| k == key) {
            return Err(format!("line {n}: duplicate field `{key}`"));
        }
        raw.fields.push((key.to_string(), value));
    }
    if current.is_some() {
        return Err("unterminated term block at end of document".to_string());
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Content negotiation
// ---------------------------------------------------------------------------

/// What a request's `Accept` header resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Representation {
    Json,
    Cddal,
}

/// Negotiates the response representation from an `Accept` header
/// value. Rules (deliberately minimal, documented in the README):
///
/// - absent or empty `Accept` → JSON, no warning (the default);
/// - any listed entry whose media type (before `;`) is
///   `text/cddal` → CDDAL (q-values are not weighted; a listed
///   CDDAL entry wins);
/// - otherwise, an entry that JSON serves (`application/json`,
///   `*/*`) → JSON, no warning;
/// - otherwise (nothing in the list is servable) → JSON **with**
///   the [`FALLBACK_HEADER`] warning, so callers can detect the
///   silent degradation.
pub fn negotiate(accept: Option<&str>) -> (Representation, bool) {
    let Some(header) = accept.map(str::trim).filter(|h| !h.is_empty()) else {
        return (Representation::Json, false);
    };
    let mut json_satisfies = false;
    for entry in header.split(',') {
        let media_type = entry
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match media_type.as_str() {
            "text/cddal" => return (Representation::Cddal, false),
            "application/json" | "*/*" => json_satisfies = true,
            _ => {}
        }
    }
    (Representation::Json, !json_satisfies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Item, ItemClass, ItemVersion, Status};
    use serde_json::json;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    fn version(number: &str, from: &str, status: Status) -> ItemVersion {
        ItemVersion {
            version: number.to_string(),
            status,
            effective_from: Some(ts(from)),
            effective_until: None,
            registered_at: Some(ts("2026-09-01T00:00:00Z")),
            superseded_by_version: None,
            notes: None,
        }
    }

    fn item(id: &str, register: &str, class: ItemClass, manifest: Option<Value>) -> Item {
        Item {
            identifier: id.to_string(),
            register: register.to_string(),
            item_class: class,
            title: format!("{id} definition"),
            submitting_organization: Some("submitting org".to_string()),
            versions: vec![version("1.0.0", "2026-01-01T00:00:00Z", Status::Valid)],
            manifest,
        }
    }

    fn round_trip(item: &Item) -> TermEntry {
        let entry = TermEntry::of(item, None);
        let parsed = parse(&render(std::slice::from_ref(&entry))).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], entry, "round trip of `{}`", item.identifier);
        entry
    }

    #[test]
    fn round_trips_every_item_class() {
        // Data element: UNTDED-shaped manifest (representation) plus
        // a unit reference.
        let data_element = item(
            "urn:untded:de:1000",
            "untded",
            ItemClass::DataElement,
            Some(json!({
                "version": "1.0.0",
                "name": "Document name",
                "tag": 1000,
                "representation": "an..35"
            })),
        );
        let entry = round_trip(&data_element);
        assert_eq!(entry.name, "Document name");
        assert_eq!(entry.representation.as_deref(), Some("an..35"));
        // Unit reference via the closed key set.
        let with_unit = item(
            "de/lot-mass",
            "unidpp-dev",
            ItemClass::DataElement,
            Some(json!({"version": "1.0.0", "required_unit": "units:kg"})),
        );
        assert_eq!(round_trip(&with_unit).unit.as_deref(), Some("units:kg"));

        // Unit: UnitsML-shaped manifest (symbol).
        let unit = item(
            "unitsml:u:kilowatt_hour",
            "unitsml",
            ItemClass::Unit,
            Some(json!({
                "version": "1.0.0",
                "name": "kilowatt hour",
                "symbol": "kW·h",
                "quantity_kind": "energy"
            })),
        );
        let entry = round_trip(&unit);
        assert_eq!(entry.unit_symbol.as_deref(), Some("kW·h"));
        assert_eq!(entry.representation, None, "units carry no representation");

        // Profile / crypto suite / transform / trust anchor: bare
        // items and manifest-bearing ones.
        round_trip(&item(
            "eu-espr-textiles",
            "unidpp-dev",
            ItemClass::Profile,
            None,
        ));
        round_trip(&item(
            "eu-espr-textiles",
            "unidpp-dev",
            ItemClass::Profile,
            Some(json!({"version": "1.0.0", "subject_capability": "S2"})),
        ));
        round_trip(&item("ed25519", "unidpp-dev", ItemClass::CryptoSuite, None));
        round_trip(&item(
            "recycled-mass-balance",
            "unidpp-dev",
            ItemClass::Transform,
            None,
        ));
        round_trip(&item("ta-nist", "unidpp-dev", ItemClass::TrustAnchor, None));

        // Model: the EXPRESS-deposit manifest is not in the CDDAL
        // subset — identity, slots and version still round-trip.
        round_trip(&item(
            "unidpp-core-express",
            "unidpp-seed",
            ItemClass::Model,
            Some(json!({"version": "0.1.0", "express": {"source": "SCHEMA x;"}})),
        ));

        // Cross-register mapping: the mapping manifest stays in
        // JSON; the mapping item's own dictionary slots round-trip.
        round_trip(&item(
            "urn:unidpp:map:gb4943-iec62368",
            "unidpp",
            ItemClass::CrossRegisterMapping,
            Some(json!({
                "version": "1.0.0",
                "source": {"register": "gb-std", "item": "gb-4943-1"},
                "target": {"register": "iec", "item": "iec-62368-1"},
                "mapping_type": "equivalent"
            })),
        ));

        // An item with an IRDI.
        let irdi = item(
            "de-crm-identity",
            "unidpp-dev",
            ItemClass::DataElement,
            Some(json!({"version": "1.0.0", "irdi": "0173-1#01-AAB000#001"})),
        );
        assert_eq!(
            round_trip(&irdi).irdi.as_deref(),
            Some("0173-1#01-AAB000#001")
        );
    }

    #[test]
    fn canonical_form_is_exact_bytes() {
        let mut element = item(
            "urn:untded:de:1000",
            "untded",
            ItemClass::DataElement,
            Some(json!({"version": "1.0.0", "name": "Document name", "representation": "an..35"})),
        );
        element.submitting_organization = None;
        element.versions[0].effective_from = None;
        let entry = TermEntry::of(&element, None);
        let expected = concat!(
            "TERM urn:untded:de:1000\n",
            "  register: untded\n",
            "  class: data-element\n",
            "  name: Document name\n",
            "  definition: urn:untded:de:1000 definition\n",
            "  representation: an..35\n",
            "  version: 1.0.0\n",
            "  status: valid\n",
            "  registered_at: 2026-09-01T00:00:00Z\n",
            "END\n",
        );
        assert_eq!(render(std::slice::from_ref(&entry)), expected);
        // Byte-determinism: two renders of the same entry are
        // byte-identical.
        assert_eq!(
            render(std::slice::from_ref(&entry)),
            render(std::slice::from_ref(&entry))
        );
    }

    #[test]
    fn values_with_escapable_characters_round_trip() {
        let mut tricky = item(
            "tricky",
            "unidpp-dev",
            ItemClass::DataElement,
            Some(json!({"version": "1.0.0", "name": "back\\slash and\nnewline and\rcr"})),
        );
        tricky.title = "definition: with: colons and \\ backslash".to_string();
        let entry = TermEntry::of(&tricky, None);
        assert_eq!(entry.name, "back\\slash and\nnewline and\rcr");
        let parsed = parse(&render(std::slice::from_ref(&entry))).unwrap();
        assert_eq!(parsed[0], entry);
    }

    #[test]
    fn version_resolution_matches_the_json_view_rule() {
        let mut v1 = version("1.0.0", "2026-01-01T00:00:00Z", Status::Superseded);
        v1.superseded_by_version = Some("2.0.0".into());
        let v2 = version("2.0.0", "2028-01-01T00:00:00Z", Status::Valid);
        let mut item = item("windows", "unidpp-dev", ItemClass::Profile, None);
        item.versions = vec![v1, v2];

        // before any window: nothing in force
        let entry = TermEntry::of(&item, Some(ts("2025-06-01T00:00:00Z")));
        assert_eq!(entry.version, None);
        // during 1.0.0's window
        let entry = TermEntry::of(&item, Some(ts("2027-06-01T00:00:00Z")));
        assert_eq!(entry.version.as_ref().unwrap().version, "1.0.0");
        assert_eq!(entry.version.as_ref().unwrap().status, "superseded");
        // after 2.0.0 takes over
        let entry = TermEntry::of(&item, Some(ts("2029-01-01T00:00:00Z")));
        assert_eq!(entry.version.as_ref().unwrap().version, "2.0.0");
        // no `at`: current registered version (2.0.0 is valid)
        let entry = TermEntry::of(&item, None);
        assert_eq!(entry.version.as_ref().unwrap().version, "2.0.0");
        // all of them round-trip, including the version-less form
        for at in [
            Some(ts("2025-06-01T00:00:00Z")),
            Some(ts("2027-06-01T00:00:00Z")),
            None,
        ] {
            let entry = TermEntry::of(&item, at);
            assert_eq!(
                parse(&render(std::slice::from_ref(&entry))).unwrap()[0],
                entry
            );
        }
    }

    #[test]
    fn document_with_many_entries_round_trips_in_order() {
        let items = [
            item(
                "b-second",
                "unidpp-dev",
                ItemClass::Unit,
                Some(json!({"symbol": "s"})),
            ),
            item(
                "a-first",
                "untded",
                ItemClass::DataElement,
                Some(json!({"name": "n"})),
            ),
            item("c-third", "unidpp-dev", ItemClass::Profile, None),
        ];
        let entries: Vec<TermEntry> = items.iter().map(|i| TermEntry::of(i, None)).collect();
        assert_eq!(parse(&render(&entries)).unwrap(), entries);
    }

    #[test]
    fn parser_rejects_malformed_documents() {
        // unknown field
        assert!(parse(
            "TERM x\n  register: r\n  class: unit\n  name: n\n  definition: d\n  bogus: 1\nEND\n"
        )
        .unwrap_err()
        .contains("unknown field `bogus`"));
        // duplicate field
        assert!(parse("TERM x\n  register: r\n  register: r2\n  class: unit\n  name: n\n  definition: d\nEND\n")
            .unwrap_err()
            .contains("duplicate field `register`"));
        // missing required field
        assert!(
            parse("TERM x\n  register: r\n  class: unit\n  name: n\nEND\n")
                .unwrap_err()
                .contains("missing required field `definition`")
        );
        // unterminated block (with and without trailing newline —
        // the trailing newline surfaces as the blank-line error,
        // the more precise diagnostic)
        assert!(parse("TERM x\n  register: r\n")
            .unwrap_err()
            .contains("blank line inside"));
        assert!(parse("TERM x\n  register: r")
            .unwrap_err()
            .contains("unterminated"));
        // END without TERM
        assert!(parse("END\n")
            .unwrap_err()
            .contains("END without a term block"));
        // field outside a block
        assert!(parse("  register: r\n")
            .unwrap_err()
            .contains("outside a term block"));
        // blank line inside a block
        assert!(parse("TERM x\n\nEND\n")
            .unwrap_err()
            .contains("blank line inside"));
        // empty value
        assert!(parse("TERM x\n  register: \nEND\n")
            .unwrap_err()
            .contains("empty value"));
        // invalid escape
        assert!(parse("TERM x\n  register: r\\q\nEND\n")
            .unwrap_err()
            .contains("invalid escape"));
        // unknown item class
        assert!(
            parse("TERM x\n  register: r\n  class: gadget\n  name: n\n  definition: d\nEND\n")
                .unwrap_err()
                .contains("unknown item class `gadget`")
        );
        // unknown status
        assert!(parse("TERM x\n  register: r\n  class: unit\n  name: n\n  definition: d\n  version: 1\n  status: draft\nEND\n")
            .unwrap_err()
            .contains("unknown status `draft`"));
        // status without version
        assert!(parse("TERM x\n  register: r\n  class: unit\n  name: n\n  definition: d\n  status: valid\nEND\n")
            .unwrap_err()
            .contains("without `version`"));
        // non-RFC 3339 stamp
        assert!(parse("TERM x\n  register: r\n  class: unit\n  name: n\n  definition: d\n  version: 1\n  status: valid\n  effective_from: Yesterday\nEND\n")
            .unwrap_err()
            .contains("not RFC 3339"));
        // TERM inside a block
        assert!(parse("TERM x\nTERM y\nEND\n")
            .unwrap_err()
            .contains("TERM inside a term block"));
        // garbage line
        assert!(parse("hello\n")
            .unwrap_err()
            .contains("not a term-block line"));
        // empty document is fine
        assert_eq!(parse("").unwrap(), Vec::<TermEntry>::new());
        assert_eq!(parse("\n\n").unwrap(), Vec::<TermEntry>::new());
    }

    #[test]
    fn negotiation_matrix() {
        use Representation::*;
        // absent / empty → JSON, silent
        assert_eq!(negotiate(None), (Json, false));
        assert_eq!(negotiate(Some("  ")), (Json, false));
        // default-ish forms → JSON, silent
        assert_eq!(negotiate(Some("*/*")), (Json, false));
        assert_eq!(negotiate(Some("application/json")), (Json, false));
        assert_eq!(negotiate(Some("APPLICATION/JSON")), (Json, false));
        assert_eq!(
            negotiate(Some("application/json;q=0.9, text/plain;q=0.1")),
            (Json, false)
        );
        // CDDAL, alone and in lists, with parameters, any case
        assert_eq!(negotiate(Some("text/cddal")), (Cddal, false));
        assert_eq!(negotiate(Some("TEXT/CDDAL")), (Cddal, false));
        assert_eq!(negotiate(Some("text/cddal; charset=utf-8")), (Cddal, false));
        assert_eq!(
            negotiate(Some("application/json, text/cddal;q=0.5")),
            (Cddal, false)
        );
        // unknown types → JSON + fallback warning
        assert_eq!(negotiate(Some("application/ld+json")), (Json, true));
        assert_eq!(negotiate(Some("application/xml")), (Json, true));
        assert_eq!(negotiate(Some("text/plain")), (Json, true));
        assert_eq!(
            negotiate(Some("application/yaml, application/xml")),
            (Json, true)
        );
        // a known type alongside unknown ones stays silent
        assert_eq!(
            negotiate(Some("application/xml, application/json")),
            (Json, false)
        );
    }
}
