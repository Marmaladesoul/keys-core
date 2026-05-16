# `keys-engine` schema reference

The engine owns a SQLCipher-encrypted SQLite file. This doc describes
every table, column, index, trigger and virtual table in the v1
schema. The authoritative DDL lives in
`src/migrations/0001_initial_schema.sql`.

## Conventions

- **Identifiers.** UUIDs are stored as `TEXT` — KDBX-canonical
  lowercase hyphenated form. Auto-increment surrogate keys
  (`tag.id`, `smart_folder.id`) are `INTEGER PRIMARY KEY AUTOINCREMENT`
  because rusqlite's UNIQUE-with-rowid optimisation isn't needed here
  and the explicit auto-increment guarantees ids don't get recycled
  after delete.
- **Timestamps.** `INTEGER` milliseconds since the Unix epoch (UTC).
  Matches the FFI millis-since-epoch convention; no timezone surprises.
- **Strings.** `TEXT NOT NULL DEFAULT ''` for text fields KDBX models
  as "always present, possibly empty". Avoids null-vs-empty footguns
  in query layer.
- **Foreign keys.** Declared on every parent-child relationship. The
  engine sets `PRAGMA foreign_keys = ON` immediately after the
  SQLCipher key handshake.
- **Migrations.** `schema_version` (single row, INTEGER PRIMARY KEY)
  records the highest applied migration. The migration runner refuses
  to open a database whose recorded version exceeds the binary's
  max-known version — older binaries don't touch newer schemas.

## Tables

### `schema_version`

| column   | type    | notes                              |
|----------|---------|------------------------------------|
| version  | INTEGER | PK; highest applied migration ver. |

Internal. Created by the migration runner, not by migration 0001. One
row per applied migration; `MAX(version)` is the current schema
version.

### `group`

| column            | type    | notes                                       |
|-------------------|---------|---------------------------------------------|
| uuid              | TEXT    | PRIMARY KEY                                 |
| parent_uuid       | TEXT    | NULL = root; FK to `group(uuid)`            |
| name              | TEXT    | NOT NULL                                    |
| icon_index        | INTEGER | Standard KDBX icon                          |
| icon_custom_uuid  | TEXT    | Custom icon ref                             |
| notes             | TEXT    | NOT NULL DEFAULT ''                         |
| created_at        | INTEGER | ms since epoch                              |
| modified_at       | INTEGER | ms since epoch                              |
| expires_at        | INTEGER | NULL = no expiry                            |
| is_recycle_bin    | INTEGER | bool; KDBX has exactly one recycle bin      |

Index: `idx_group_parent_uuid (parent_uuid)` — for tree walks and
"children of group X" listings.

Quoted identifier (`"group"`) because `GROUP` is a SQL reserved word.

### `entry`

| column                     | type    | notes                                          |
|----------------------------|---------|------------------------------------------------|
| uuid                       | TEXT    | PRIMARY KEY                                    |
| group_uuid                 | TEXT    | FK to `group(uuid)`                            |
| title                      | TEXT    | NOT NULL DEFAULT ''                            |
| username                   | TEXT    | NOT NULL DEFAULT ''                            |
| url                        | TEXT    | NOT NULL DEFAULT ''                            |
| url_host                   | TEXT    | Parsed host of `url`; AutoFill lookup column   |
| notes                      | TEXT    | NOT NULL DEFAULT ''                            |
| icon_index                 | INTEGER |                                                |
| icon_custom_uuid           | TEXT    |                                                |
| created_at                 | INTEGER | ms since epoch                                 |
| modified_at                | INTEGER | ms since epoch                                 |
| accessed_at                | INTEGER | ms since epoch                                 |
| last_used_at               | INTEGER | NULL until first use; AutoFill ordering        |
| expires_at                 | INTEGER | NULL = no expiry                               |
| password_strength_bucket   | INTEGER | Derived from Password on every mutation        |
| password_entropy           | REAL    | Bits of entropy                                |
| password_fingerprint       | BLOB    | HMAC-SHA-256 for duplicate detection           |
| is_recycled                | INTEGER | bool                                           |

Indices:

- `idx_entry_group_uuid` — "entries in group X" listing.
- `idx_entry_url_host` — AutoFill service-identifier lookup. The most
  perf-critical index in the schema.
- `idx_entry_last_used_at` — AutoFill ordering ("most recently used
  first") and the "Recently Used" smart folder.
- `idx_entry_password_strength_bucket` — "weak password" smart folder.
- `idx_entry_password_fingerprint` — duplicate-password detection
  smart folder.

The `password_*` columns ship empty in migration 0001. Phase 2 task
2.1 lands the fingerprint key; Phase 2 task 2.3 (ingest) fills the
columns on every entry write.

### `entry_protected`

| column        | type | notes                                |
|---------------|------|--------------------------------------|
| entry_uuid    | TEXT | FK to `entry(uuid)` ON DELETE CASCADE |
| field_name    | TEXT | `'Password'` for the canonical slot   |
| wrapped_blob  | BLOB | AES-GCM ciphertext (nonce \|\| ct \|\| tag) |

Primary key `(entry_uuid, field_name)`. Cascade-delete: removing an
entry removes its protected payloads, no orphans.

The blob format is decided by the field-protector implementation
(Phase 2.3). Schema treats it as opaque.

### `entry_custom_field`

| column      | type | notes                                |
|-------------|------|--------------------------------------|
| entry_uuid  | TEXT | FK to `entry(uuid)` ON DELETE CASCADE |
| field_name  | TEXT | non-protected slot name              |
| value       | TEXT | plaintext value                      |

Primary key `(entry_uuid, field_name)`. Holds the **non-protected**
custom fields KDBX entries can carry — protected ones still live in
`entry_protected` under their AES-GCM wrap. The two tables are
mutually exclusive on `(entry_uuid, field_name)`. Landed in migration
0002.

Index: `idx_entry_custom_field_entry_uuid (entry_uuid)` for the
"all custom fields for entry X" lookup.

### `entry_attachment`

| column           | type | notes                                       |
|------------------|------|---------------------------------------------|
| entry_uuid       | TEXT | FK to `entry(uuid)` ON DELETE CASCADE       |
| attachment_name  | TEXT |                                             |
| blob_sha256      | BLOB | FK to `attachment_blob(sha256)`             |

Primary key `(entry_uuid, attachment_name)`. Index on `blob_sha256`
for the "which entries reference this blob?" reverse lookup that
attachment-blob garbage collection will need.

### `entry_history`

| column         | type    | notes                                        |
|----------------|---------|----------------------------------------------|
| entry_uuid     | TEXT    | FK to `entry(uuid)` ON DELETE CASCADE        |
| history_index  | INTEGER | 0 = oldest                                   |
| snapshot_json  | TEXT    | Serialised historic entry                    |

Primary key `(entry_uuid, history_index)`. History is rarely read
(detail-pane "Show history" only) and never queried into; JSON keeps
schema migrations cheap.

Protected fields inside the JSON — the canonical `password` slot and any
`custom_fields` entry with `protected: true` — carry base64-encoded
AES-GCM-sealed bytes (`nonce(12) || ciphertext || tag(16)`), sealed
under the same session key as `entry_protected.wrapped_blob`. The JSON
never contains protected plaintext at rest. Non-protected custom fields
keep their plaintext in `value`; the `protected` boolean disambiguates.
`reveal_history_field` and projection unwrap on read.

### `attachment_blob`

| column | type    | notes                                   |
|--------|---------|-----------------------------------------|
| sha256 | BLOB    | PRIMARY KEY; content-addressed dedup    |
| bytes  | BLOB    | NOT NULL                                |
| size   | INTEGER | NOT NULL; denormalised `length(bytes)`  |

`size` is denormalised so attachment-list views don't page-fault the
blob just to display its byte count.

### `tag`

| column | type    | notes                                        |
|--------|---------|----------------------------------------------|
| id     | INTEGER | PRIMARY KEY AUTOINCREMENT                    |
| name   | TEXT    | NOT NULL UNIQUE                              |

Surrogate id over name keeps the join table compact. AUTOINCREMENT is
explicit so deleted ids never recycle (important when external code
caches `tag_id` across mutations).

### `entry_tag`

| column     | type    | notes                                            |
|------------|---------|--------------------------------------------------|
| entry_uuid | TEXT    | FK to `entry(uuid)` ON DELETE CASCADE            |
| tag_id     | INTEGER | FK to `tag(id)` ON DELETE CASCADE                |

Primary key `(entry_uuid, tag_id)`. Index on `tag_id` for "entries
with tag X" queries.

### `smart_folder`

| column          | type    | notes                                          |
|-----------------|---------|------------------------------------------------|
| id              | INTEGER | PRIMARY KEY AUTOINCREMENT                      |
| name            | TEXT    | NOT NULL                                       |
| predicate_json  | TEXT    | NOT NULL; serialised predicate tree            |
| version         | INTEGER | NOT NULL DEFAULT 1; emergency escape hatch     |
| evaluable       | INTEGER | NOT NULL DEFAULT 1; 0 means unknown predicate  |
| created_at      | INTEGER | ms since epoch                                 |
| modified_at     | INTEGER | ms since epoch                                 |

`evaluable=0` marks predicate trees the current binary couldn't
decode (per the tolerant-decoder rule in
`SQLITE_MIGRATION.md`). Preserved verbatim so a newer binary can read
them; not run by this one.

### `setting`

| column | type | notes      |
|--------|------|------------|
| key    | TEXT | PRIMARY KEY |
| value  | BLOB | NOT NULL   |

Generic KV. Reserved keys:

- `fingerprint_key` — 32 random bytes, encrypted under SQLCipher (same
  key as the rest of the file; the protection is at rest). Used to
  HMAC password plaintexts for `entry.password_fingerprint`.
- `last_saved_kdbx_bytes` — raw KDBX bytes of the most recent
  [`Engine::save_to_kdbx`] write, the common ancestor for an
  external-change 3-way merge. Stored uncompressed: SQLCipher already
  encrypts the row at rest, and KDBX is already internally compressed,
  so an extra gzip layer would save <5% at the cost of an extra moving
  part. Written atomically with the on-disk save in task 2.5; read
  back by task 4.6 and fed into [`keepass_core::kdbx::Kdbx::open`] for
  3-way merge.
- `meta.recycle_bin_enabled` — 1-byte BLOB (`[0]` / `[1]`) carrying
  `Meta::recycle_bin_enabled` verbatim. Written by ingest, read by
  projection. Lets the schema represent the "enabled=true, no bin
  group yet" intermediate state KeePassXC emits — the `is_recycle_bin`
  column on `group` alone can only express `enabled` when a bin group
  already exists. Legacy DBs without this row fall back to the
  derived "does a bin group exist?" behaviour.
- **`meta.*` family** (migration 0003) — every scalar field of
  `keepass_core::model::Meta`. The list:
  - `meta.generator`, `meta.database_name`, `meta.database_description`,
    `meta.default_username`, `meta.color`, `meta.header_hash`
    — utf-8 string bytes.
  - `meta.database_name_changed`, `meta.database_description_changed`,
    `meta.default_username_changed`, `meta.recycle_bin_changed`,
    `meta.settings_changed`, `meta.master_key_changed` — little-endian
    `i64` milliseconds since the Unix epoch. Absent row ≡ `None`.
  - `meta.master_key_change_rec`, `meta.master_key_change_force`,
    `meta.history_max_size` — little-endian `i64`.
  - `meta.history_max_items` — little-endian `i32`.
  - `meta.maintenance_history_days` — little-endian `u32`.
  - `meta.memory_protection` — single byte; bits 0..=4 encode
    `protect_title`, `protect_username`, `protect_password`,
    `protect_url`, `protect_notes` respectively.
  - `meta.unknown_xml` — JSON array of
    `{ "tag": "...", "raw_xml": "<base64>" }` records. Captures the
    `<UnknownElement>` round-trip pool verbatim.

## Meta-owned tables (migration 0003)

### `meta_custom_icon`

| column           | type    | notes               |
|------------------|---------|---------------------|
| uuid             | TEXT    | PRIMARY KEY         |
| name             | TEXT    | NOT NULL DEFAULT '' |
| bytes            | BLOB    | NOT NULL            |
| last_modified_at | INTEGER | nullable; ms epoch  |

Pool of custom entry / group icons. Indexed by uuid (the primary key).

### `meta_custom_data`

| column           | type    | notes               |
|------------------|---------|---------------------|
| key              | TEXT    | PRIMARY KEY         |
| value            | TEXT    | NOT NULL            |
| last_modified_at | INTEGER | nullable; ms epoch  |

Free-form key/value strings preserved verbatim for round-trip.

### `meta_deleted_object`

| column     | type    | notes              |
|------------|---------|--------------------|
| uuid       | TEXT    | PRIMARY KEY        |
| deleted_at | INTEGER | nullable; ms epoch |

Tombstones for deleted entries / groups, recorded for future
sync/merge work. Indexed on `deleted_at` for
"what got deleted recently?" queries.

## FTS5 virtual table

```sql
CREATE VIRTUAL TABLE entry_fts USING fts5(
    title, username, url, notes,
    content='entry',
    content_rowid='rowid',
    tokenize='porter unicode61'
);
```

- **`content='entry'`** — external-content index. FTS5 stores the
  inverted index but reads source text from `entry` on demand. Saves
  storage; requires triggers to keep the index in sync.
- **`tokenize='porter unicode61'`** — Porter stemming over Unicode
  normalisation. Adequate for v1 Latin-script content; non-Latin
  scripts (CJK, Thai) get word-level matching at best. Revisit if a
  user reports a search-quality issue with non-Latin entries.

### Sync triggers

FTS5 external-content tables do NOT auto-sync. Three triggers maintain
consistency:

- `entry_ai` AFTER INSERT — inserts new entry's text into the FTS
  index.
- `entry_au` AFTER UPDATE — uses the FTS5 `'delete'` command to remove
  the old row's contribution, then re-inserts the new row.
- `entry_ad` AFTER DELETE — removes the entry's contribution.

The `'delete'` command shape is the FTS5-prescribed pattern for
external-content tables — see the FTS5 docs section "External Content
and Contentless Tables".

## What's NOT in v1

Deliberate omissions for later migrations:

- No `view_state` / `window_state` tables — frontend-state storage
  stays a Swift concern for now (`UserDefaults` on macOS).
- No `recent_search` history.
- No `audit_log` of mutations.

Each can land in a later migration when there's a concrete consumer.
