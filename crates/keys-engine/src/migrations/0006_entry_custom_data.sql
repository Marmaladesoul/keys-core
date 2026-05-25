-- Migration 0006: per-entry custom_data persistence.
--
-- KDBX models each `<Entry>` as carrying its own `<CustomData>` block —
-- arbitrary `(key, value, last-modified)` triples used by plugins and
-- the Keys-side extensions defined under the `keys.*` namespace (e.g.
-- `keys.history_tombstones.v1`, the parked-conflict marker carried on
-- history records). Prior to this migration the engine's SQLite mirror
-- dropped those values on ingest, which is fine for entries but wrong
-- for anything that needs to survive a reconcile→project→save cycle.
--
-- This table mirrors the structure of `meta_custom_data` (migration
-- 0003) one level down — keyed by `(entry_uuid, key)`. Values are
-- opaque TEXT and round-trip verbatim through projection.
--
-- History-record-level custom_data lives inside the
-- `entry_history.snapshot_json` blob — adding it there is a JSON-shape
-- extension (backwards-compatible: old rows surface an empty list), not
-- a schema change, so no DDL here.
CREATE TABLE entry_custom_data (
    entry_uuid       TEXT NOT NULL REFERENCES entry(uuid) ON DELETE CASCADE,
    key              TEXT NOT NULL,
    value            TEXT NOT NULL,
    last_modified_at INTEGER,
    PRIMARY KEY (entry_uuid, key)
);

CREATE INDEX idx_entry_custom_data_key ON entry_custom_data(key);
