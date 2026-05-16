-- Migration 0002: non-protected custom fields.
--
-- v1 had no place for non-protected custom fields, so ingest silently
-- dropped them. This migration adds `entry_custom_field` — one row
-- per (entry, name) — so the round-trip preserves them. Protected
-- custom fields still live in `entry_protected`; the two tables are
-- mutually exclusive on field_name.
--
-- See `crates/keys-engine/docs/schema.md` for column rationale.

CREATE TABLE entry_custom_field (
    entry_uuid TEXT NOT NULL REFERENCES entry(uuid) ON DELETE CASCADE,
    field_name TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (entry_uuid, field_name)
);

CREATE INDEX idx_entry_custom_field_entry_uuid ON entry_custom_field(entry_uuid);
