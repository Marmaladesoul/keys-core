# `keys-engine` query surface

This doc describes every method, type, and predicate variant a frontend
will use to read or reveal data from the engine. Stubs landed in Phase 1
task 1.5; implementations land in Phase 3.

The shapes here are the **stable public API** of `keys-engine` for the
duration of the SQLite migration project. Adding fields and methods is
non-breaking; renaming, removing, or changing semantics is breaking.

Cross-reference: `_localdocs/SQLITE_MIGRATION.md` Phase 3 tasks 3.1–3.9.

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

### `CustomFieldRef` / `AttachmentRef`

```rust
struct CustomFieldRef { name: String, is_protected: bool }
struct AttachmentRef  { name: String, size: u64 }
```

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

- `last_used_at` write path from AutoFill (Phase 7.7).
- `NotEvaluable` error variant for unknown-predicate folders (Phase 3.9).
- Tolerant decoder that preserves unknown-predicate raw JSON (Phase 3.9).
