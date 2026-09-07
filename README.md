# unidpp-registry

Part of UniDPP (github.com/unidpp) — implements TODO.impl
`10-remaining-tasks-definitive.md` item 12: a running **ISO 19135
registry service** (item registration, versioned supersession,
point-in-time resolution, applicability bindings) that the issuer and
resolver both consume. License: Apache-2.0.

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
  single-instance registry service with a fronting proxy (the PLAN.md
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
| `GET /items/{id}?at=&register=` | the item + the version in force at `at` (null before its first window); without `at` the current registered version |
| `GET /items/{id}/supersession?from=` | the supersession chain (to the terminal version) |
| `GET /applicability?product_type=&at=` | which profiles applied to the product type at `at` |

Admin (Bearer `UNIDPP_REGISTRY_ADMIN_TOKEN` when set; open in dev mode):

| Endpoint | Body | Meaning |
|---|---|---|
| `POST /items` | `{register_id, item_id, class, definition, version, status?, effective_from?, effective_until?, submitting_organization?, manifest?}` | register a new item with its first version (`status` must be `valid` when given) |
| `POST /items/{id}/versions` | `{version, reason, effective_from?, effective_until?, supersede_version?, manifest?}` | supersede: new version + reason; the old (default: current valid) transitions to `superseded` with derived window end |
| `POST /applicability` | `{profile_id, product_type, effective_from?, effective_until?, retroactive?, register?, profile_version?}` | dated applicability binding (profile item must exist, class `profile`) |
| `GET /admin/log?limit=&offset=` | — | the append-only audit log |

Each subregister mounts the same surface class-scoped:
`POST/GET /{subregister}`, `GET /{subregister}/{id}`,
`POST /{subregister}/{id}/versions`,
`GET /{subregister}/{id}/supersession` — where `{subregister}` is one
of `data-elements`, `profiles`, `crypto-suites`, `transforms`,
`trust-anchors`, `units`.

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
#               "superseded_by_version": "1.0.0",
#               "window_end": "2027-10-18T00:00:00Z"}

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
| `UNIDPP_REGISTRY_ADMIN_TOKEN` | unset (open) | Bearer token for mutations and `/admin/log` |
| `UNIDPP_REGISTRY_STATE_FILE` | unset (in-memory) | JSONL journal for the audit log (replayed on start) |

## Build & test

```
cargo build   # zero warnings
cargo test    # 17 unit + 7 integration tests, zero warnings
```

Unit tests cover the model semantics (derived vs. explicit window
ends, point-in-time resolution, current-version preference,
supersession chains whole/from-middle/broken, manifest version
pinning, retroactivity) and the store (lifecycle transitions,
validation failures, journal round trip). Integration tests speak
real HTTP against servers spawned on ephemeral ports: register →
supersede → as-of queries before/during/after windows, supersession
chains, retroactive applicability (including the `registered_at`
gate and `effective_until` closure), subregisters class-scoped,
admin auth (401 wrong/absent token), the append-only audit log
(order, monotonic seq, payloads) and journal replay across restarts.

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
