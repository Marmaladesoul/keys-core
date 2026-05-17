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
| `group_tree() -> Vec<GroupNode>` | 3.2 | Flat list; tree built by caller. |
| `search(query: &str, page: Pagination) -> Vec<EntrySummary>` | 3.3 | FTS5-backed. |
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
| `modified_at` | `i64` ms | `entry.modified_at` |
| `last_used_at` | `Option<i64>` ms | `entry.last_used_at` |
| `password_strength_bucket` | `Option<StrengthBucket>` | `entry.password_strength_bucket` |
| `password_entropy` | `Option<f64>` bits | `entry.password_entropy` |
| `attachment_count` | `u32` | `COUNT(entry_attachment)` |
| `icon` | `IconRef` | `entry.icon_index` or `entry.icon_custom_uuid` |

### `EntryFull`

Superset of `EntrySummary` plus:

| field | type | notes |
|---|---|---|
| `notes` | `String` | |
| `created_at` | `i64` ms | |
| `accessed_at` | `i64` ms | |
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

Custom-icon blob retrieval (`Engine::custom_icon_bytes`) is intentionally
**not** part of this Phase 1 surface — frontends rendering custom icons
will get a dedicated query method in Phase 3+.

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

## Decisions deferred to later tasks

- Custom-icon blob retrieval (no method yet).
- `last_used_at` write path from AutoFill (Phase 7.7).
- `NotEvaluable` error variant for unknown-predicate folders (Phase 3.9).
- Tolerant decoder that preserves unknown-predicate raw JSON (Phase 3.9).
