# `keys-engine` query surface

This doc describes every method, type, and predicate variant a frontend
will use to read or reveal data from the engine. Stubs landed in Phase 1
task 1.5; implementations land in Phase 3.

The shapes here are the **stable public API** of `keys-engine` for the
duration of the SQLite migration project. Adding fields and methods is
non-breaking; renaming, removing, or changing semantics is breaking.

## Methods

All methods live on `impl Engine`. Stubs panic with
`unimplemented!("task X.Y")`; the `X.Y` matches the implementing task in
the migration tracker.

| Method | Implements in | Notes |
|---|---|---|
| `list_entries(group: Option<Uuid>, page: Pagination) -> Vec<EntrySummary>` | 3.1 | Paginated. `group = None` → global. |
| `entry(uuid: Uuid) -> Option<EntryFull>` | 3.1 | `Ok(None)` if not found. |
| `entry_count(group: Option<Uuid>) -> u64` | 3.1 | Cheap count, no rows fetched. |
| `group_tree() -> Vec<GroupNode>` | 3.2 | Flat list; tree built by caller. Siblings ordered by `sort_order`. |
| `group_parent_uuid(child: Uuid) -> Option<Uuid>` | 6.17-C | `None` for the root group; `NotFound` for unknown UUID. Cheap single-row `SELECT`. |
| `is_descendant_of(group: Uuid, ancestor: Uuid) -> bool` | 6.17-C | Walks `parent_uuid` up from `group`. **Not inclusive** — a group is not its own descendant. Capped at 1024 hops to defang malformed cycles. |
| `group_uuids_in_subtree(root: Uuid) -> Vec<Uuid>` | — | Recursive-CTE descent; **root-inclusive** counterpart to `is_descendant_of`. Ancestry-derived, so correct the instant a group is re-parented (never consults the per-entry `is_recycled` flag). `NotFound` for an unknown root — never an empty sentinel. |
| `entry_uuids_in_subtree(root: Uuid) -> Vec<Uuid>` | — | Every entry anywhere under `root` (root included) in one join. Same ancestry-derived membership as `group_uuids_in_subtree`; empty `Vec` for an existing empty subtree, `NotFound` for an unknown root. |
| `reorder_group(uuid: Uuid, new_position: u32) -> ()` | 6.8 | Move `uuid` within its parent's child list. Emits `ChangeEvent::GroupsReordered`. |
| `search(query: &str, page: Pagination) -> Vec<EntrySummary>` | 3.3 | FTS5-backed. |
| `search_by_service(identifier: &str, limit: usize) -> Vec<EntrySummary>` | 7.2 | AutoFill lookup. Tiered host match — see below. |
| `smart_folder_entries(folder_id: i64, page: Pagination) -> Vec<EntrySummary>` | 3.8 | Compiles predicate → SQL → runs. |
| `smart_folder_count(folder_id: i64) -> u64` | 3.8 | Badge-count variant. |
| `reveal_password(uuid: Uuid) -> SecretString` | 3.4 | Fetches wrapped blob; AEAD-opens. |
| `reveal_custom_field(uuid: Uuid, field_name: &str) -> SecretString` | 3.4 | Same path; arbitrary field name. |
| `reveal_history_field(uuid: Uuid, history_index: u32, field_name: &str) -> SecretString` | 3.4 | Historic snapshot variant. |
| `attachment_bytes(uuid: Uuid, attachment_name: &str) -> Vec<u8>` | 3.1 | Raw blob fetch. |
| `history(uuid: Uuid) -> Vec<HistoricEntry>` | 3.1 | Oldest-first ordering. |
| `delete_history_at(entry_uuid: Uuid, history_index: u32) -> ()` | 6.17-H follow-up | Remove a single history snapshot. Renumbers surviving snapshots to stay dense (`0..N`). Does **not** bump `entry.modified_at` (bookkeeping, not a content edit). Emits `EntriesUpdated`. Mirrors legacy `Vault::delete_history_at` semantics. |
| `restore_entry_from_history(entry_uuid: Uuid, history_index: u32) -> ()` | 6.17-I unblock | Restore the entry to the state captured at `history_index`, **preserving** the snapshot in the history list and appending the pre-restore live state as a new snapshot at the tail. Bumps `entry.modified_at = now()`; restores `created_at`/`accessed_at`/`last_used_at`/`expires_at` verbatim from the snapshot; recomputes derived columns (`password_strength_bucket`, `password_entropy`, `password_fingerprint`, `url_host`, `has_totp`). Replaces tags, attachments (via `sha256_hex`), custom fields, and protected fields wholesale. Inline-trims oldest snapshots to honour `meta.history_max_items`. Emits `EntriesUpdated`. Mirrors legacy `Vault::restore_entry_from_history` under `HistoryPolicy::Snapshot`. |
| `export_entry(entry_uuid: Uuid) -> PortableEntry` | 6.17-F | Serialise an entry into an in-process carrier (every field, every protected slot revealed, every attachment's bytes, plus custom-icon PNG when present) suitable for cross-database move via `import_entry`. Read-only. |
| `import_entry(portable: PortableEntry, target_group_uuid: Uuid) -> Uuid` | 6.17-F | Consume a carrier; insert as a brand new entry under `target_group_uuid` (fresh UUID + `now` timestamps). Rehomes custom icons via SHA-256 dedup into the target's pool. Emits `EntriesAdded`. |
| `database_metadata() -> DatabaseMetadata` | 6.17-I-3c | Read-only Info-tab payload: `generator` (from `meta.generator`), `cipher_display` (from `meta.kdbx_cipher_oid`), `kdf_display` (from `meta.kdbx_kdf_parameters` / `meta.kdbx_transform_rounds`), `attachment_total_count` + `attachment_total_bytes` (from `attachment_blob`). Outer-header facts are written at ingest time; for engines created pre-6.17-I-3c, cipher / KDF render as `"Unknown"` / `"Unknown KDF"` until the next ingest refreshes them. Attachment pool stats match the legacy `Vault::attachmentPoolStats` (one row per distinct content-addressed payload). Backs the Keys-Mac `DatabaseEditorView` properties pane — final retirement of `DatabaseDocument.ffiVault`. |
| `kdbx_state_signature() -> Option<KdbxStateSignature>` | post-migration | `(mtime_ms, byte_count)` of the KDBX file whose contents the engine's SQLite mirror currently corresponds to. Recorded automatically by `save_to_kdbx`; frontends call `record_kdbx_state_signature(path)` after `ingest_from_kdbx`. Persisted in `setting`, survives close+reopen. Used by Keys-Mac on unlock to skip re-ingest (the 1–4s wall-clock dominator on big vaults) when SQLite is already in sync with the on-disk KDBX. Distinct from `last_self_write` because that one is consume-on-match for file-watcher self-write suppression — sharing would let an ingest's signature swallow a real subsequent external-change event. |
| `record_kdbx_state_signature(path: &Path) -> ()` | post-migration | Stat `path`, persist the resulting `(mtime_ms, byte_count)` as the signature corresponding to the engine's current SQLite state, and settle the persistence watermark (`persisted_seq = mutation_seq`) in the same transaction — one fact, "mirror and file now correspond". Call after a successful `ingest_from_kdbx`. `save_to_kdbx` records the same correspondence automatically (using the seq snapshotted at save start). |
| `persistence_state() -> PersistenceState` | migration 0012 | The watermark pair `{ mutation_seq, persisted_seq }` plus `is_dirty()` — "does the KDBX still owe a write?", answered by the engine instead of per-call-site frontend convention. `mutation_seq` is bumped by AFTER-triggers inside every projected-content mutation's transaction; `persisted_seq` advances at each mirror↔disk correspondence point (save / ingest+signature / rebuild / digest-equal reconcile). Persisted in `setting`, so an unsaved mutation reads back dirty across close+reopen — the crash-recovery flush signal. Frontend save orchestrators flush iff dirty (debounced, plus lifecycle edges). |
| `reconcile_with_disk_park_conflicts(...)` correspondence note | ARC C | On `Applied { needs_write_back: false }` (digest-proven convergence) the engine records the kdbx-state signature and settles the watermark itself — the disk file already holds everything, and a flush would rewrite identical bytes (mtime churn, the reconcile ping-pong seed). `NoChange` never settles: it only proves nothing was adopted; the mirror may still hold local edits the disk lacks. Disk-path only — the peer-transport twin (`ingest_peer_from_kdbx`) digests against a fetched blob, not the vault file. The FFI `sync_with_disk` verb packages the whole open-time gate (signature check → skip / ingest / reconcile → internal persist iff advanced past disk) and returns `FreshIngest` / `UpToDate` / `NoChange` / `Applied { wrote_back }`. |

Every method returns `Result<_, EngineError>`.

## Types

### `Pagination`

`{ offset: u64, limit: u64 }`. `Pagination::all()` constructs
`{ 0, u64::MAX }` for "every row"; the SQL layer maps the max-limit
sentinel onto SQLite's "no limit" convention.

### `EntrySummary`

Lightweight row for list / sidebar / AutoFill UIs:

| field | type | source |
|---|---|---|
| `uuid` | `Uuid` | `entry.uuid` |
| `group_uuid` | `Uuid` | `entry.group_uuid` |
| `title` | `String` | `entry.title` |
| `username` | `String` | `entry.username` |
| `url` | `String` | `entry.url` |
| `url_host` | `String` | `entry.url_host` |
| `notes` | `String` | `entry.notes` |
| `created_at` | `i64` ms | `entry.created_at` |
| `modified_at` | `i64` ms | `entry.modified_at` |
| `accessed_at` | `i64` ms | `entry.accessed_at` |
| `last_used_at` | `Option<i64>` ms | `entry.last_used_at` |
| `password_strength_bucket` | `Option<StrengthBucket>` | `entry.password_strength_bucket` |
| `password_entropy` | `Option<f64>` bits | `entry.password_entropy` |
| `attachment_count` | `u32` | `COUNT(entry_attachment)` |
| `icon` | `IconRef` | `entry.icon_index` or `entry.icon_custom_uuid` |

### `EntryFull`

Superset of `EntrySummary` plus:

| field | type | notes |
|---|---|---|
| `expires_at` | `Option<i64>` ms | `None` = no expiry |
| `is_recycled` | `bool` | |
| `custom_fields` | `Vec<CustomFieldRef>` | name + `is_protected` only; reveal for values |
| `tags` | `Vec<String>` | joined through `entry_tag` |
| `attachments` | `Vec<AttachmentRef>` | name + size; bytes via `attachment_bytes` |
| `history_count` | `u32` | for paging the history view |

Note: `EntryFull` does **not** repeat `attachment_count` from
`EntrySummary`; callers either use `attachments.len()` or
`history_count` for analogous needs.

### `GroupNode`

Flat tree node:

| field | type |
|---|---|
| `uuid` | `Uuid` |
| `parent_uuid` | `Option<Uuid>` (`None` for root) |
| `name` | `String` |
| `icon` | `IconRef` |
| `entry_count_direct` | `u32` |
| `is_recycle_bin` | `bool` |
| `sort_order` | `u32` (position within parent's child list) |

### `ChangeEvent::GroupsReordered(Vec<Uuid>)`

Emitted by `reorder_group`. Carries every sibling under the affected
parent in their new `sort_order` order — observers can either re-fetch
`group_tree` or splice the list directly. Cross-parent moves still go
through `ChangeEvent::GroupsMoved` via `move_group`.

### `HistoricEntry`

Mirrors `EntryFull`'s structural shape minus things that don't exist
in a snapshot (`uuid`, `group_uuid`, `is_recycled`, `history_count`)
and minus protected-field plaintext. Protected values still come back
via `reveal_history_field(uuid, history_index, field_name)`.

| field | type | notes |
|---|---|---|
| `history_index` | `u32` | 0 = oldest |
| `title` | `String` | |
| `username` | `String` | |
| `url` | `String` | |
| `url_host` | `String` | parsed at snapshot time |
| `notes` | `String` | |
| `icon` | `IconRef` | snapshot-time icon |
| `created_at` | `i64` ms | |
| `modified_at` | `i64` ms | |
| `accessed_at` | `i64` ms | |
| `last_used_at` | `Option<i64>` ms | mirrors `accessed_at` proxy |
| `expires_at` | `Option<i64>` ms | |
| `password_strength_bucket` | `Option<StrengthBucket>` | computed at ingest |
| `password_entropy` | `Option<f64>` | bits |
| `custom_fields` | `Vec<CustomFieldRef>` | name + `is_protected`, sorted by name |
| `tags` | `Vec<String>` | |
| `attachments` | `Vec<AttachmentRef>` | metadata only; bytes via `attachment_bytes` |

### `StrengthBucket`

`#[repr(u8)]` enum, weakest → strongest:

`VeryWeak (0)`, `Weak (1)`, `Reasonable (2)`, `Strong (3)`, `VeryStrong (4)`.

Stored as the discriminant in `entry.password_strength_bucket`. Bucket
names mirror Swift's existing `PasswordStrength` enum so the Phase 6
Swift adapter is a direct mapping. No upstream Rust source exists today.

### `IconRef`

```rust
enum IconRef {
    Builtin(u32),       // index into KeePass's built-in icon set
    Custom(Uuid),       // reference to a custom icon blob
}
```

Custom-icon blob retrieval is exposed via `Engine::custom_icon_bytes`
(Phase 6.17-D). Pair it with `Engine::add_custom_icon` (SHA-256
content-hash dedup, returns the icon's UUID) and
`Engine::clear_entry_custom_icon` (nulls an entry's `icon_custom_uuid`,
leaves the pool blob in place — orphan icons are reaped by save-path
GC, matching legacy `Vault` semantics).

### Last-access stamps

Two engine methods write the `last_used_at` column without bumping
`modified_at` (mirroring legacy `Vault` semantics):

- `Engine::touch_entry(uuid)` — read-touch flow (AutoFill fulfilment,
  in-app reveal). Bumps `last_used_at` to now. Emits the dedicated
  `ChangeEvent::EntryTouched { uuid }` event rather than the heavier
  `EntriesUpdated`, so listeners that don't care about Recently-Used
  ordering can ignore the high-volume AutoFill traffic without
  re-rendering full entry detail.
- `Engine::clear_entry_last_access(uuid)` — user-driven explicit
  reset from the entry detail editor. Sets `last_used_at` back to
  NULL. Emits `ChangeEvent::EntriesUpdated(vec![uuid])` because this
  is a view-affecting user gesture.

Both return `EngineError::NotFound { entity: "entry" }` for an
unknown uuid.

### `CustomFieldRef` / `AttachmentRef`

```rust
struct CustomFieldRef { name: String, is_protected: bool }
struct AttachmentRef  { name: String, size: u64 }
```

### `PortableEntry` / `PortableAttachment`

In-process carrier for cross-database entry moves, produced by
`Engine::export_entry` and consumed by `Engine::import_entry`. The flow
is `source.export_entry(uuid)` → `target.import_entry(carrier, group)` →
`source.delete_entry(uuid)`. The carrier is **not** `Serialize` /
`Deserialize`: it holds revealed protected-field plaintext in
`SecretString`s that zero on drop, so dropping the carrier wipes
secrets even if the import path errors out mid-write.

```rust
struct PortableEntry {
    title: String,
    username: String,
    url: String,
    notes: String,
    icon: IconRef,
    tags: Vec<String>,
    created_at: Option<i64>,
    modified_at: Option<i64>,
    accessed_at: Option<i64>,
    last_used_at: Option<i64>,
    expires_at: Option<i64>,
    password: SecretString,
    protected_fields: Vec<(String, SecretString)>,
    custom_fields: Vec<(String, String)>,
    attachments: Vec<PortableAttachment>,
    custom_icon_png: Option<Vec<u8>>,
}

struct PortableAttachment {
    name: String,
    bytes: Vec<u8>,
    mime: Option<String>,
}
```

History is **not** ferried — `import_entry` mints a brand new entry and
the source's history snapshots describe edits that happened in a
different database. Timestamps on the carrier are retained for future
preservation paths; today's import stamps `now` for
`created_at`/`modified_at`/`accessed_at` (matching `create_entry`) and
preserves `expires_at` only.

Custom-icon ferrying: when the source entry references a custom icon,
the PNG bytes ride in `custom_icon_png` so the target can
content-hash-dedup them into its own `meta_custom_icon` pool —
yielding either an existing UUID (cache hit) or a freshly minted one
(cache miss). A carrier with `IconRef::Custom` but a `None`
`custom_icon_png` is rejected with `EngineError::NotFound { entity:
"custom_icon" }`.

## Predicate AST

Lives in `keys-engine::predicate`. See module doc comments for the full
variant set. JSON encoding is tagged-union, `snake_case`:

```json
{
    "type": "and",
    "predicates": [
        { "type": "tag_equals", "tag": "banking" },
        { "type": "modified_within", "duration": 604800 }
    ]
}
```

### Variants (initial set)

- Logical: `And { predicates }`, `Or { predicates }`, `Not { predicate }`.
- Field substring: `TitleContains { substring }`, `UrlContains { substring }`, `UsernameContains { substring }`.
- URL host equality: `UrlHostEquals { host }`.
- Tag: `TagEquals { tag }`, `TagHasAny { tags }`, `TagHasAll { tags }`.
- Time: `ModifiedWithin { duration }`, `ModifiedBefore { timestamp_ms }`, `Expired`, `ExpiringWithin { duration }`.
- Strength: `StrengthBelow { bucket }`, `EntropyBelow { bits }`.
- Other: `Duplicates`, `Group { uuid }`.
- Catch-all: `Unknown` (see versioning).

`#[non_exhaustive]` on the enum so adding variants is non-breaking for
exhaustive `match` users in other crates (once they add a wildcard arm).

### Versioning (mirrors `SQLITE_MIGRATION.md` rules)

1. Every variant has a stable `"type"` discriminator.
2. Producers are additive-only. New variants and new optional fields
   are non-breaking; renaming / removing / making-required is a wire
   break.
3. Decoders are tolerant: unknown `type` discriminators map to
   `Predicate::Unknown`. Phase 3.9 wires that into a per-folder
   `evaluable: false` marker and preserves the raw JSON via a custom
   `Deserialize` impl (today's `#[serde(other)]` unit-variant form
   discards the unknown payload).
4. Folder documents carry a top-level `version` integer for emergency
   wholesale restructures.

### `Duration` encoding

`ModifiedWithin` and `ExpiringWithin` encode their `Duration` as **integer
seconds** in JSON, not the default `(secs, nanos)` tuple. Smart-folder
durations are coarse-grained (days / weeks) — nanosecond precision is
noise — and the integer form survives any JSON consumer.

## `search_by_service` matching tiers

Backs the AutoFill extension's per-domain lookup. Given a service
identifier (bare host like `google.com`, or a full URL like
`https://accounts.google.com/signin?...`), the engine extracts a host
candidate and matches entries in three tiers, most-specific first:

1. **Exact host** — case-insensitive equality with `entry.url_host`
   (which is lowercased at ingest).
2. **eTLD+1** — the identifier's host is reduced to its registrable
   domain (e.g. `accounts.google.com` → `google.com`,
   `news.bbc.co.uk` → `bbc.co.uk`). Entries whose `url_host` either
   equals that domain or ends in `.<domain>` match. Catches both the
   "saved at apex, identifier is subdomain" and "saved on subdomain,
   identifier is apex" cases.
3. **Substring** — the identifier appears anywhere inside
   `entry.url` (case-insensitive `LIKE %id%`). Last-resort tier for
   entries whose URL didn't parse and therefore have an empty
   `url_host`.

Recycled entries are excluded. Results are deduplicated by entry uuid
(best tier wins), ordered by tier ascending, then `last_used_at DESC
NULLS LAST`, then `modified_at DESC`. The caller-supplied `limit`
caps the row count.

The eTLD+1 reduction is intentionally **not** backed by the full
Public Suffix List in v1 — a hand-curated list of two-label suffixes
(`co.uk`, `com.au`, `co.nz`, …) covers the common AutoFill cases
without the 200 KB `publicsuffix` dependency. The fallback when a
suffix isn't listed is a too-aggressive eTLD+1 (e.g. `co.uk` itself);
the exact-host tier and substring tier still function, so the worst
case is "an irrelevant entry gets ranked below the relevant one"
rather than "nothing matches".

## Decisions deferred to later tasks

- AutoFill consumer of `Engine::touch_entry` (Phase 7.7) — the
  write path itself landed in Phase 6.17-E.
- `NotEvaluable` error variant for unknown-predicate folders (Phase 3.9).
- Tolerant decoder that preserves unknown-predicate raw JSON (Phase 3.9).
