-- Migration 0003: persist `Meta` so SQLite is a complete vault
-- representation (not just an index over a KDBX file).
--
-- Before this migration, only `Meta::recycle_bin_enabled` /
-- `Meta::recycle_bin_uuid` (the recycle-bin pair) survived ingest;
-- every other field was carried forward at save time by copying from
-- the live `Kdbx<Unlocked>` handle. That made the engine dependent on
-- a live KDBX handle being available at save time and meant Meta
-- couldn't survive `close → reopen` without the original handle.
--
-- This migration adds:
--
--   * Three tables (`meta_custom_icon`, `meta_custom_data`,
--     `meta_deleted_object`) for the list-shaped Meta fields.
--   * A bunch of new `setting` row keys for the scalar Meta fields:
--       meta.generator                       TEXT (utf-8 bytes)
--       meta.database_name                   TEXT (utf-8 bytes)
--       meta.database_description            TEXT (utf-8 bytes)
--       meta.database_name_changed           INTEGER ms since epoch
--       meta.database_description_changed    INTEGER ms since epoch
--       meta.default_username                TEXT
--       meta.default_username_changed        INTEGER ms since epoch
--       meta.recycle_bin_changed             INTEGER ms since epoch
--       meta.settings_changed                INTEGER ms since epoch
--       meta.master_key_changed              INTEGER ms since epoch
--       meta.master_key_change_rec           i64 little-endian (8 bytes)
--       meta.master_key_change_force         i64 little-endian (8 bytes)
--       meta.history_max_items               i32 little-endian (4 bytes)
--       meta.history_max_size                i64 little-endian (8 bytes)
--       meta.maintenance_history_days        u32 little-endian (4 bytes)
--       meta.color                           TEXT
--       meta.header_hash                     TEXT
--       meta.memory_protection               1-byte bitfield
--                                              bit 0 protect_title
--                                              bit 1 protect_username
--                                              bit 2 protect_password
--                                              bit 3 protect_url
--                                              bit 4 protect_notes
--       meta.unknown_xml                     JSON array (utf-8 text bytes)
--                                              [{tag: "...", raw_xml: "<b64>"}, ...]
--
-- See `crates/keys-engine/docs/schema.md` for the column-by-column
-- rationale.

-- Pool of custom entry/group icons referenced by
-- `Entry::custom_icon_uuid` / `Group::custom_icon_uuid`.
CREATE TABLE meta_custom_icon (
    uuid             TEXT    NOT NULL PRIMARY KEY,
    name             TEXT    NOT NULL DEFAULT '',
    bytes            BLOB    NOT NULL,
    last_modified_at INTEGER
);

-- Free-form plugin/client key-value strings preserved verbatim for
-- round-trip.
CREATE TABLE meta_custom_data (
    key              TEXT    NOT NULL PRIMARY KEY,
    value            TEXT    NOT NULL,
    last_modified_at INTEGER
);

-- Tombstones for deleted entries or groups, recorded for sync/merge.
CREATE TABLE meta_deleted_object (
    uuid       TEXT    NOT NULL PRIMARY KEY,
    deleted_at INTEGER
);

CREATE INDEX idx_meta_deleted_object_deleted_at
    ON meta_deleted_object(deleted_at);
