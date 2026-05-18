-- Migration 0001: initial schema.
--
-- Creates every table the engine needs in v1, plus the FTS5 mirror of
-- entry text columns. All timestamps are INTEGER milliseconds since the
-- Unix epoch (UTC). Foreign keys are declared on every parent-child
-- relationship; the engine enables `PRAGMA foreign_keys = ON` after the
-- key handshake so SQLite actually enforces them.
--
-- See `crates/keys-engine/docs/schema.md` for column-by-column rationale.

-- Groups. Forms a tree via parent_uuid; the root group has parent_uuid
-- NULL. `is_recycle_bin` marks the special recycle-bin group (KDBX has
-- exactly one). Self-referential FK; we don't cascade — group deletion
-- is an explicit operation handled by the engine.
CREATE TABLE "group" (
    uuid             TEXT    PRIMARY KEY,
    parent_uuid      TEXT    REFERENCES "group"(uuid),
    name             TEXT    NOT NULL,
    icon_index       INTEGER,
    icon_custom_uuid TEXT,
    notes            TEXT    NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    modified_at      INTEGER NOT NULL,
    expires_at       INTEGER,
    is_recycle_bin   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_group_parent_uuid ON "group"(parent_uuid);

-- Entries. The bulk of the schema. `url_host` is the parsed host of
-- `url`, pre-extracted for AutoFill's indexed lookup. `password_*`
-- columns are derived from the protected Password field on every
-- mutation (Phase 2 wires them up; the columns ship empty until then).
-- `password_fingerprint` is HMAC-SHA-256(plaintext, fingerprint_key) for
-- duplicate detection without decrypt.
CREATE TABLE entry (
    uuid                     TEXT    PRIMARY KEY,
    group_uuid               TEXT    NOT NULL REFERENCES "group"(uuid),
    title                    TEXT    NOT NULL DEFAULT '',
    username                 TEXT    NOT NULL DEFAULT '',
    url                      TEXT    NOT NULL DEFAULT '',
    url_host                 TEXT    NOT NULL DEFAULT '',
    notes                    TEXT    NOT NULL DEFAULT '',
    icon_index               INTEGER,
    icon_custom_uuid         TEXT,
    created_at               INTEGER NOT NULL,
    modified_at              INTEGER NOT NULL,
    accessed_at              INTEGER NOT NULL,
    last_used_at             INTEGER,
    expires_at               INTEGER,
    password_strength_bucket INTEGER,
    password_entropy         REAL,
    password_fingerprint     BLOB,
    is_recycled              INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_entry_group_uuid               ON entry(group_uuid);
CREATE INDEX idx_entry_url_host                 ON entry(url_host);
CREATE INDEX idx_entry_last_used_at             ON entry(last_used_at);
CREATE INDEX idx_entry_password_strength_bucket ON entry(password_strength_bucket);
CREATE INDEX idx_entry_password_fingerprint     ON entry(password_fingerprint);

-- Wrapped protected fields. One row per protected slot per entry. The
-- canonical Password field uses field_name='Password'; arbitrary custom
-- protected fields use their KDBX field name. `wrapped_blob` is AES-GCM
-- ciphertext (nonce || ct || tag) under the session key from the field
-- protector callback. Phase 2 fills the blobs.
CREATE TABLE entry_protected (
    entry_uuid   TEXT NOT NULL REFERENCES entry(uuid) ON DELETE CASCADE,
    field_name   TEXT NOT NULL,
    wrapped_blob BLOB NOT NULL,
    PRIMARY KEY (entry_uuid, field_name)
);

-- Attachment links. Dedup'd via content-addressed `attachment_blob`.
-- A single blob can be referenced by many (entry, name) pairs without
-- duplicating bytes.
CREATE TABLE entry_attachment (
    entry_uuid      TEXT NOT NULL REFERENCES entry(uuid) ON DELETE CASCADE,
    attachment_name TEXT NOT NULL,
    blob_sha256     BLOB NOT NULL REFERENCES attachment_blob(sha256),
    PRIMARY KEY (entry_uuid, attachment_name)
);

CREATE INDEX idx_entry_attachment_blob_sha256 ON entry_attachment(blob_sha256);

-- Historic entry snapshots. KDBX stores N prior versions per entry;
-- we keep them as opaque JSON blobs since history is rarely read and
-- never queried into. `history_index` 0 is oldest.
CREATE TABLE entry_history (
    entry_uuid     TEXT    NOT NULL REFERENCES entry(uuid) ON DELETE CASCADE,
    history_index  INTEGER NOT NULL,
    snapshot_json  TEXT    NOT NULL,
    PRIMARY KEY (entry_uuid, history_index)
);

-- Content-addressed attachment storage. Same bytes referenced by N
-- entries take O(1) storage. `size` is denormalised from
-- `length(bytes)` for cheap listing without page-faulting the blob.
CREATE TABLE attachment_blob (
    sha256 BLOB    PRIMARY KEY,
    bytes  BLOB    NOT NULL,
    size   INTEGER NOT NULL
);

-- Tags. Normalised: a single string per tag, joined to entries via
-- `entry_tag`. Avoids the parse-string-column dance the Swift side has
-- to do today.
CREATE TABLE tag (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT    NOT NULL UNIQUE
);

CREATE TABLE entry_tag (
    entry_uuid TEXT    NOT NULL REFERENCES entry(uuid) ON DELETE CASCADE,
    tag_id     INTEGER NOT NULL REFERENCES tag(id)     ON DELETE CASCADE,
    PRIMARY KEY (entry_uuid, tag_id)
);

CREATE INDEX idx_entry_tag_tag_id ON entry_tag(tag_id);

-- User-defined smart folders. `predicate_json` is the serialised
-- predicate tree (see predicate-versioning rules in
-- SQLITE_MIGRATION.md). `evaluable=0` marks predicates the current
-- binary couldn't decode — they're preserved verbatim so a newer
-- binary can read them, but not run.
CREATE TABLE smart_folder (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL,
    predicate_json TEXT    NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    evaluable      INTEGER NOT NULL DEFAULT 1,
    created_at     INTEGER NOT NULL,
    modified_at    INTEGER NOT NULL
);

-- Generic KV settings. Reserved keys:
--   * fingerprint_key       — 32 random bytes (encrypted under SQLCipher)
--                             used to HMAC password plaintexts for the
--                             duplicate-detection column on `entry`.
--   * last_saved_kdbx_bytes — raw KDBX bytes of the most recent
--                             save_to_kdbx write; common ancestor for
--                             3-way external-change merge (task 4.4).
--                             Uncompressed: SQLCipher already encrypts
--                             at rest and KDBX is internally compressed.
CREATE TABLE setting (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- Entry text search is plain LIKE-based substring matching across
-- `title`, `username`, `url`, `notes`, and tag names — see
-- `reads::search`. No FTS5 index: prefix-only matching surprised
-- users (typing `a` did not find `Marmalade`), and on the entry
-- counts this app deals with (<10k) a `LIKE %x%` scan is fast enough.
