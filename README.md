# unidpp-registry

Part of UniDPP (github.com/unidpp) — part of UniDPP
`10-remaining-tasks-definitive.md` items 12 (registry service) and 32
(registry v2: the discovery registry): a running **ISO 19135 registry
service** (item registration, versioned supersession,
point-in-time resolution, applicability bindings) that the issuer and
resolver both consume, extended with the **discovery registry** —
signed C3 service descriptors, C4 protocol bindings and C5
verification mechanisms per operator-model §1. License: Apache-2.0.

The model mirrors the Ruby reference
`unidpp-rb/lib/unidpp/registry` (`Item` / `ItemVersion` /
`ApplicabilityBinding`; the read-only Ruby `Client` maps onto this
service's HTTP surface); the server conventions mirror
`unidpp-resolver` (axum, as-of stamps, append-only log, Bearer-guarded
admin, ephemeral-port integration tests).

## Storage choice

**In-memory model + JSONL append-only journal** (no SQLite, no
rusqlite). Rationale:

- The audit log is already a *required* feature — and it is exactly
 the journal. Every mutation is an appended audit record carrying its
 full payload (`register-item` carries the whole item, `supersede-
 version` carries the successor version, `bind-applicability` the
 binding), so the log replays losslessly into state on start. One
 mechanism, two guarantees: durability and auditability. This is the
 resolver's proven `Store` pattern (I4 doctrine: nothing edited in
 place).
- Registry content is small (hundreds of items, thousands of
 bindings) and read-heavy; the working set fits in memory trivially,
 and versions are immutable per version — perfectly cacheable.
- No C toolchain, no database dependency, no migrations: the
 dependency set stays at axum + tokio + serde_json (the
 dependency-light house doctrine).
- Trade-off (accepted, documented): the journal is not a queryable
 index, and concurrent instances cannot share a journal file. A
 single-instance registry service with a fronting proxy (the the UniDPP design framework
 L6 pattern) is the deployment unit; if multi-writer scale is ever
 needed, the `Store` boundary is where SQLite would slot in — the
 model and API would not change.

Set `UNIDPP_REGISTRY_STATE_FILE` to persist (unset = in-memory, for
tests and dev).

## Semantics (Ruby parity)

- **One item = one definition** of a data element, profile, crypto
 suite, transform, trust anchor or unit. Item references are
 (register, item, version).
- **Versions are immutable once registered**; status and supersession
 links express the lifecycle (`valid` / `superseded` / `retired`).
- **Supersession**: registering a new version transitions the old one
 to `superseded` and links it to its successor. The old version's
 open effective-window end is **derived** from the successor's
 `effective_from` (`window_end`; an explicit `effective_until`
 always wins).
- **Point-in-time**: `?at=T` returns the version in force at `T`
 (half-open window `[from, until)`, `until` explicit-or-derived).
 Without `at`, the **current registered version** is returned — the
 Ruby `Client#version_of` default (latest `valid` version, even if
 its window has not started yet), *not* "in force at wall-clock now".
- **Applicability is dated binding, not new identity** (source
 invariant 9). A **retroactive** binding legally backdates — it
 applies from its `effective_from` even though registered later
 (end-of-waste style re-qualification). A non-retroactive binding
 cannot impose obligations for times before `registered_at`.
 `registered_at` is always the server stamp; it cannot be set through
 the API.
- **Subregisters are item classes**: `/data-elements`, `/profiles`,
 `/crypto-suites`, `/transforms`, `/trust-anchors`, `/units` expose
 the same endpoints, class-scoped (an item of another class 404s
 there; `class` is pinned by the mount point).
- **As-of stamps on all responses**: `x-as-of` header everywhere plus
 an `as_of` field in JSON bodies.
- **Append-only audit log**: every mutation is a sequence-numbered
 record; `GET /admin/log` reads it, the JSONL journal persists it.

## Endpoints

Public (reads):

| Endpoint | Meaning |
|---|---|
| `GET /` | discovery document (endpoints, classes, subregisters, conventions) |
| `GET /healthz` | liveness |
| `GET /items?class=&register=&at=` | list items (class/register scoped), each with its resolved version |
| `GET /items` / `GET /{subregister}` with `Accept: text/cddal` | the same collection reads in the canonical CDDAL plain-text dictionary form (see "CDDAL serialization"); JSON is the default and the fallback |
| `GET /items/{id}?at=&register=` | the item + the version in force at `at` (null before its first window); without `at` the current registered version |
| `GET /items/{id}/supersession?from=` | the supersession chain (to the terminal version) |
| `GET /applicability?product_type=&at=&subject_facts=` | which profiles applied to the product type at `at`; with `subject_facts` (a URL-encoded JSON object) clock predicates on the bound profiles are evaluated at `at` (entries whose triggers cannot fire yet are excluded; time-triggered bindings without facts are listed under `unresolved`) |
| `GET /schemas/profile-manifest` | the profile-manifest JSON Schema (draft 2020-12), generated from the canonical Rust model; as-of stamped |
| `GET /models?register=&at=` | deposited EXPRESS models, with validation status |
| `GET /models/{id}?at=&hash=` | a deposit's source, content hash and validation status; with `hash=` retrieval is pinned (mismatch → 409) |
| `GET /cross-register-mappings?item=&source=&target=&register=&at=` | mappings by referenced item — `item` matches either end, `source`/`target` the named end |

Admin (Bearer `UNIDPP_REGISTRY_ADMIN_TOKEN` when set; open in dev mode):

| Endpoint | Body | Meaning |
|---|---|---|
| `POST /items` | `{register_id, item_id, class, definition, version, status?, effective_from?, effective_until?, submitting_organization?, manifest?, strict?}` | register a new item with its first version (`status` must be `valid` when given); class `profile` manifests are validated against the served JSON Schema and checked for satisfiability, class `cross-register-mapping` manifests for referential integrity — rejections carry the field path (`strict=false` downgrades satisfiability failures to warnings) |
| `POST /items/{id}/versions` | `{version, reason, effective_from?, effective_until?, supersede_version?, manifest?, strict?}` | supersede: new version + reason; the old (default: current valid) transitions to `superseded` with derived window end; a new manifest passes the same intake checks |
| `POST /applicability` | `{profile_id, product_type, effective_from?, effective_until?, retroactive?, register?, profile_version?}` | dated applicability binding (profile item must exist, class `profile`) |
| `POST /applicability` | `{product_type, at?, subject_facts}` | *evaluation* form (no `profile_id`): same clock-predicate evaluation as the GET |
| `POST /models` | `{register_id, item_id, definition, version, source, effective_from?, submitting_organization?}` | deposit an EXPRESS model: content hash over the exact bytes + expressir validation; `invalid` sources are rejected, absent expressir stores `pending` |
| `POST /models/{id}/validate` | — | re-run expressir validation over the stored source (the `pending` → `valid`/`invalid` path) and record the outcome |
| `GET /admin/log?limit=&offset=` | — | the append-only audit log |

Each subregister mounts the same surface class-scoped:
`POST/GET /{subregister}`, `GET /{subregister}/{id}`,
`POST /{subregister}/{id}/versions`,
`GET /{subregister}/{id}/supersession` — where `{subregister}` is one
of `data-elements`, `profiles`, `crypto-suites`, `transforms`,
`trust-anchors`, `units`, `cross-register-mappings` (the `models`
subregister has the dedicated `/models` surface above).

## CDDAL serialization (T-06)

Exchange between semantic-registry hosts uses **CDDAL** — the
IEC 61360 / ISO/IEC 62656 dictionary plain-text form (OpenCDD's
grammar as the reference) — with a normative canonicalization rule:
two mirrors of the same item set serve byte-identical forms, so
cross-host comparison and audit reduce to hashing. The collection
reads (`GET /items` and every subregister listing) honour `Accept:
text/cddal` with this canonical form (`src/cddal.rs`); the model is
the single source — the serializer walks the item model, and a
strict parser reads the form back into the same projection (the
canonicalization round trip, proven by tests).

One `TERM` block per item, fields in a fixed canonical order:

```text
TERM urn:untded:de:1000
  register: untded
  class: data-element
  name: Document name
  definition: The name of the document.
  submitting_organization: UNTDED 2005 (ECE/TRADE/362)
  representation: an..35
  version: 1.0.0
  status: valid
  effective_from: 2005-01-01T00:00:00Z
  registered_at: 2026-09-07T00:00:00Z
END
```

Canonicalization rules: LF line endings; `TERM <identifier>` …
`END`; present fields in the order `irdi, register, class, name,
definition, submitting_organization, representation, unit,
unit_symbol, version, status, effective_from, registered_at`
(two-space indent, `key: value`); items in the store's canonical
listing order (identifier-sorted); values are single logical lines
with `\`, LF and CR escaped (`\\`, `\n`, `\r`); the version is the
*resolved* one (`in_force_at` with `?at=`, else the current
registered version — the same rule as the JSON view); **no serving
metadata in the body** — the as-of stamp rides in the `x-as-of`
header only, so two reads of the same state are byte-identical.
Dictionary slots come from the item model plus the class-scoped
manifest keys: `irdi` and `name` (any class); `representation`
(data elements, the raw `an..35`-style notation); `unit`
(data elements: `unit` / `required_unit` / `unit_ref`); `unit_symbol`
(units).

Negotiation: absent `Accept`, or one listing a servable type
(`application/json`, `*/*`), serves JSON silently; a listed
`text/cddal` (parameters and case tolerated, q-values not weighted)
serves CDDAL; an `Accept` listing **nothing** servable (e.g.
`application/xml`) falls back to JSON with the warning header
`x-content-negotiation: unknown-accept-fallback`, so callers can
detect the silent degradation.

**Coverage boundary (honest scope):** a full OpenCDD grammar is out
of scope. Not serialized: the version history and supersession
chains (only the resolved version is emitted — history stays in the
JSON form), manifests beyond the named keys above (profile
manifests, EXPRESS deposit bodies, mapping manifests stay JSON-only),
applicability bindings, and the discovery layer (C3/C4/C5
descriptors). JSON remains the full-fidelity form; CDDAL is the
canonical exchange projection of the dictionary slots.
Single-item reads (`GET /items/{id}`) stay JSON.

## v3 intake checks and clock predicates

`POST /items` runs a chain of class-scoped intake checks (each a
pure function on the manifest; extend by implementing
`IntakeCheck`, not by editing handlers):

| Check | Class | Rule |
|---|---|---|
| `profile-manifest-schema` | profile | the manifest validates against the served JSON Schema (draft 2020-12, generated from `src/manifest.rs` — one source, two renders) |
| `profile-satisfiability` | profile | data points demanding `min_capability` above the declared `subject_capability`, or bounded `fresh_within` on an S0/S1 subject, are unsatisfiable (I8 ladder: S0 silent, S1 passive-auth, S2 logged-contact, S3 connected) — reject, or warn with `strict=false` |
| `cross-register-mapping-integrity` | cross-register-mapping | both ends of `{source, target}` must resolve to registered items (register attribute matching, version pins existing) |

Clock predicates (`{predicate_class: "time", basis:
"manufactured_at"|"first_registered_at", operator: ">="|">"|"<="|"<",
duration: "P40Y"}`) are evaluated by the applicability endpoint at
the query instant: the predicate fires once `at <operator> basis +
duration` (calendar-aware ISO 8601 duration arithmetic). The
doctrinal case: manufactured 1962-05-04, `P40Y` → the historic
vehicle profile binds from 2002-05-04. Fact predicates remain the
subject custodian's concern — the registry evaluates only what the
passage of time alone makes computable.

**expressir dependency** (EXPRESS validation): `gem install
expressir`, binary on `PATH` (validated with expressir 2.4.0; the
CLI is invoked as `expressir validate load <temp-file>`). Without
it, model deposits are stored with `validation.status = "pending"`
and can be validated later via `POST /models/{id}/validate`. The
serving binary deposits the vendored UniDPP EXPRESS core schema
(`assets/unidpp-core.express`, sourced from unidpp-express) as its
first model item on start (idempotent; disable with
`UNIDPP_REGISTRY_SEED_EXPRESS=0`).

## Discovery registry (v2) — C3 / C4 / C5

The discovery layer registers *descriptors of services and shapes*
(never records of things — I12): who serves what (C3), in which wire
grammar (C4), verified by which mechanism (C5). Descriptors are
**versioned** (the same supersession discipline as 19135 items, with
derived window ends) and **signed** by the operator key (Ed25519).

| Endpoint | Meaning |
|---|---|
| `POST /services` | register a signed C3 service descriptor (`{identifier, version, effective_from?, effective_until?, body, signature}`) |
| `GET /services?class=&jurisdiction=&at=` | list services, class/jurisdiction filtered, point-in-time |
| `GET /services/{id}?at=` | one descriptor; `version` is null before its first window |
| `POST /services/{id}/versions` | supersede with a new signed version (`{version, effective_from?, body, signature, supersede_version?}`) |
| `GET /services/{id}/supersession?from=` | the supersession chain |
| `POST /protocol-bindings` | register a signed C4 binding (`{identifier, version, body, signature}`) |
| `GET /protocol-bindings`, `GET /protocol-bindings/{id}` | list / fetch |
| `POST /verification-mechanisms` | register a signed C5 mechanism (`{identifier, body, signature}`) |
| `GET /verification-mechanisms`, `GET /verification-mechanisms/{id}` | list / fetch |
| `POST /admin/seed` | idempotently populate the seed dataset |

### Schemas (canonical wire forms)

**C3 service body** (signed as a whole, minus the `signature` member):

```json
{
 "identifier": "issuer-de-1",
 "operator": {"id": "op-…", "key_id": "k-…", "public_key": "<64 hex>", "algorithm": "ed25519"},
 "class": "issuer",
 "endpoints": [{"uri": "https://issuer.example/", "protocol_binding_ref": "pb-tier-a-binary"}],
 "protocol_binding_ref": "pb-tier-a-binary",
 "jurisdiction": "DE",
 "residency_class": "eu",
 "status": "active",
 "succession_pointer": null
}
```

Service classes: `issuer`, `registry`, `resolver`, `trust`, `log`,
`archive`, `gateway`, `marketplace-gate`, `edge`. Service statuses:
`active`, `superseded`, `suspended`, `succeeded` (`succeeded` is the
"succession pointer in effect" state — clients follow the pointer).

**C4 protocol-binding body**: `{identifier, description, version,
grammar_ref, media_types[], conformance_suite_ref?, operator}`.

**C5 verification-mechanism body**: `{identifier, suite,
agility_status, trust_framework?, trust_list_endpoint?,
master_list_ref?, verdict_grammar_ref?, operator}`.

### Signature convention

The signature is **Ed25519 over the canonical JSON of the descriptor
body** (serde_json byte form, with any `signature` member removed
before signing). The operator id is content-derived from the public
key (`op-` + 16 hex of `H(b"op" ‖ public_key)`), so an operator id
pins exactly one key — the registry rejects bodies whose `operator.id`
does not match the derived id. The signature block is
`{"key_id": "k-…", "algorithm": "ed25519", "value": "<128 hex>"}`,
and `key_id` must match the content-derived key id of the operator's
public key (catches cross-key forgeries).

The **seeded dev keyring** holds the operators UniDPP itself runs
(`unidpp-registry`, `unidpp-issuer`, `unidpp-resolver`,
`unidpp-trust`, `unidpp-log`, `unidpp-archive`,
`unidpp-cli-verifier`, `unidpp-edge`), keys derived as
`H("UNIDPP-DISCOVERY/OPERATOR-SEED" ‖ label)` — the same scheme as
signatif's `KeyPair::seeded`. Signatures are verified at intake only;
journal replay re-applies stored records. Production replaces the
keyring with an external trust list (the seam is
`AppState::keyring`).

### Seed dataset (`POST /admin/seed`)

- **8 C3 services** — UniDPP's own: registry, issuer, resolver,
 trust, log, archive, CLI-class verifier, edge (self-hosted; UniDPP
 is its own first customer — the reference deployment).
- **5 C4 protocol bindings** — EN 18222 REST, GS1 Digital Link,
 GB/T 33993, UNTP VC profile, Tier-A binary.
- **3 C5 verification mechanisms** — SM2/SM3/SM4 (active), FIPS 186-4
 (active), FIPS 204 ML-DSA-65 (migration).
- **10 C1 units** — the SI base units (m, kg, s, A, K, mol, cd) plus
 kWh, MJ, J, each with an ISO 80000 citation in the manifest
 (UnitsML-style; submitter ISO/TC 12). Served through the existing
 `GET /units` subregister.

All seed records go through the same audit log + journal as any other
mutation; the endpoint is idempotent per process.

### Example session (discovery)

```sh
# Seed, then discover all trust-class services
curl -s -XPOST localhost:8090/admin/seed
curl -s 'localhost:8090/services?class=trust'
# → one service, its endpoints, protocol binding ref, jurisdiction

# Point-in-time: what did the trust service look like before v2?
curl -s 'localhost:8090/services/unidpp-trust-v1?at=2026-01-01T00:00:00Z'

# Fetch the binding named by a service descriptor
curl -s 'localhost:8090/protocol-bindings/pb-tier-a-binary'
```

### Example session

```sh
curl -s -XPOST localhost:8090/items -H 'content-type: application/json' -d '{
 "register_id": "unidpp-dev", "item_id": "eu-espr-textiles",
 "class": "profile", "definition": "EU ESPR textiles jurisdiction profile",
 "version": "0.9.0", "effective_from": "2026-10-18T00:00:00Z" }'

curl -s -XPOST localhost:8090/items/eu-espr-textiles/versions \
 -H 'content-type: application/json' \
 -d '{"version": "1.0.0", "reason": "consolidated edition",
 "effective_from": "2027-10-18T00:00:00Z"}'

curl -s 'localhost:8090/items/eu-espr-textiles?at=2027-06-01T00:00:00Z'
# → "version": {"version": "0.9.0", "status": "superseded", ...,
# "superseded_by_version": "1.0.0",
# "window_end": "2027-10-18T00:00:00Z"}

curl -s -XPOST localhost:8090/applicability -H 'content-type: application/json' -d '{
 "profile_id": "eu-espr-textiles", "product_type": "gtin:06901234000016",
 "effective_from": "1996-01-01T00:00:00Z", "retroactive": true }'

curl -s 'localhost:8090/applicability?product_type=gtin:06901234000016&at=2020-01-01T00:00:00Z'
# → the retroactive binding applies even though it was registered in 2026
```

## Field-name mapping (Ruby wire ↔ API requests)

| Request field | Model field (wire) |
|---|---|
| `register_id` | `register` (item attribute) |
| `item_id` | `identifier` |
| `class` | `item_class` (singular; plural accepted) |
| `definition` | `title` (the 19135 name/definition slot) |
| `profile_id` | `profile_item` |
| `product_type` | `subject` (canonical product/type identity) |

Response bodies use the Ruby wire shapes (`render_nil: false` —
absent when None), plus: `version` (resolved), `as_of`, `audit_seq`
(on mutations), `id` (on bindings) and `window_end` (derived,
rendered on every version, ignored on input).

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `UNIDPP_REGISTRY_BIND` | `127.0.0.1:8090` | listen address |
| `UNIDPP_REGISTRY_ADMIN_TOKEN` | unset (open) | Bearer token for mutations, `/admin/*` and `/admin/seed` |
| `UNIDPP_REGISTRY_STATE_FILE` | unset (in-memory) | JSONL journal for the audit log (replayed on start) |
| `UNIDPP_REGISTRY_SEED_ON_DEMAND` | `1` | when `0`, `POST /admin/seed` refuses |

## Build & test

```
cargo build # zero warnings
cargo test # 75 unit + 24 integration tests, zero warnings
cargo clippy # clean
```

Unit tests cover the model semantics (derived vs. explicit window
ends, point-in-time resolution, current-version preference,
supersession chains whole/from-middle/broken, manifest version
pinning, retroactivity), the store (lifecycle transitions,
validation failures, journal round trip), and the discovery layer
(service classes, keyring determinism, signature verify + tamper
rejection, operator-id pinning, service windows and supersession
chains, descriptor JSON round trips, body-shape validation).
Integration tests speak real HTTP against servers spawned on
ephemeral ports: register → supersede → as-of queries
before/during/after windows, supersession chains, retroactive
applicability (including the `registered_at` gate and
`effective_until` closure), subregisters class-scoped, admin auth
(401 wrong/absent token), the append-only audit log (order,
monotonic seq, payloads), journal replay across restarts — and the
discovery paths: signed service registration (tampered and
unknown-operator rejections), class/jurisdiction filters, service
supersession with as-of windows, protocol bindings and verification
mechanisms (register/list/get/duplicate/missing fields), the seed
dataset (counts, contents, units with ISO 80000 citations, audit-log
coverage), discovery journal replay across restarts, and admin auth
on all new mutation endpoints — and the CDDAL paths: JSON default,
`text/cddal` served with the right content type, the
canonicalization round trip over HTTP (the served form parses back
into the term entries projected from the registered items),
byte-determinism across two calls, and the unknown-Accept fallback
header.

## Deviations from the Ruby reference (documented)

- Identifiers are **unique per service instance** (keyed by
 `identifier`); the register is an item attribute, not a key. A
 FERIN-style federation runs one service per register — registers
 federate as siblings, none is the universal envelope. `?register=`
 scopes lookups; re-registering an existing identifier is a 409.
- Register governance metadata (`Register`'s owner/manager/control
 body) has no endpoint here — it is static deployment metadata in
 the Ruby `FileStore` fixtures; add a `GET /register` endpoint if a
 deployment needs to publish it.
- The service **writes** (register/supersede/bind); the Ruby
 `Store`/`FileStore`/`Client` are read-only consumers — the Ruby
 `FileStore` remains the offline-mirror format, and the wire shapes
 here are compatible with it.
- Manifests are carried as opaque JSON objects; the seam-S4 pinning
 rule is enforced at the boundary (a manifest `version` key must
 reference a registered version of the item; a manifest without a
 `version` key is rejected at registration and unpinned after
 supersede).
- `retired` status exists in the model and wire forms, but no
 endpoint sets it yet (19135 retirement by the control body is a
 future admin operation; the state machine already accepts it).
- A superseding version's `effective_from` must not precede the
 superseded version's window start (the Ruby model tolerates
 out-of-order windows by sorting; the service rejects them to keep
 chain integrity).
