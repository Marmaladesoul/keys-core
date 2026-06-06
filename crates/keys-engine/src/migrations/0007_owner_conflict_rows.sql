-- Migration 0007: owner-tagged conflict rows (multi-peer sync store).
--
-- Phase 2 of the multi-peer owner-rows rearchitecture
-- (_project-management/sync-multipeer-store.md §9). The model keeps each
-- peer's divergent value as an extra OWNER-keyed row and derives conflicts
-- lazily, instead of eagerly merging every peer into one canonical vault.
--
-- These tables are a PARALLEL set, deliberately NOT an `owner` column bolted
-- onto the live `entry` table: the local side IS the existing `entry`
-- projection (owner = "me", implicit), so leaving it untouched means
-- projection.rs and every existing query keep working byte-identically and
-- simply never see peer rows. A `conflict_*` row exists ONLY for an entry a
-- peer genuinely conflicts on (both sides moved off the shared ancestor);
-- the non-conflicting majority is compared at ingest and discarded.
--
-- Lifetime: these rows are LOCAL-ONLY (they never cross the wire — the
-- secret-safety rule) and are re-derivable (the next peer pull re-runs
-- classify). They are intentionally NOT in `clear_vault_tables` and do NOT
-- FK-cascade off the local `entry(uuid)`: a peer row may reference an entry
-- whose local mirror is later wiped + rebuilt by a KDBX-divergent re-ingest,
-- and must survive that. `ingest_peer` refreshes them per (owner, entry) on
-- every pull (delete-then-insert), so they never accumulate stale snapshots.
--
-- Secret-safety: `conflict_entry_protected.wrapped_blob` is AES-GCM-sealed
-- under the same session key the live `entry_protected` rows use — never
-- plaintext. Only the encrypted-at-rest SQLCipher page protects it; it is
-- never serialised into the KDBX or sent to a peer.
--
-- Scope (Phase 2): the columns the resolver needs to render "theirs" for the
-- field/icon picker — user-facing standard fields + icon + timestamps on
-- `conflict_entry`, sealed Password / protected custom fields on
-- `conflict_entry_protected`, non-protected custom fields on
-- `conflict_entry_custom_field`. Engine-internal derived columns
-- (url_host, password_strength_bucket, fingerprint, has_totp, …) are omitted
-- — peer rows are never queried for those. Peer attachments, history,
-- custom_data and group placement are deferred to the Phase-5 content-pool /
-- tombstone work; `group_uuid` is carried nullable for that future use.

CREATE TABLE conflict_entry (
    owner            TEXT    NOT NULL,
    entry_uuid       TEXT    NOT NULL,
    group_uuid       TEXT,
    title            TEXT    NOT NULL DEFAULT '',
    username         TEXT    NOT NULL DEFAULT '',
    url              TEXT    NOT NULL DEFAULT '',
    notes            TEXT    NOT NULL DEFAULT '',
    icon_index       INTEGER NOT NULL DEFAULT 0,
    icon_custom_uuid TEXT,
    created_at       INTEGER,
    modified_at      INTEGER,
    accessed_at      INTEGER,
    expires_at       INTEGER,
    PRIMARY KEY (owner, entry_uuid)
);

-- Backs the "any uuid with at least one peer row" badge query (Phase 3).
CREATE INDEX idx_conflict_entry_uuid ON conflict_entry(entry_uuid);

CREATE TABLE conflict_entry_protected (
    owner        TEXT NOT NULL,
    entry_uuid   TEXT NOT NULL,
    field_name   TEXT NOT NULL,
    wrapped_blob BLOB NOT NULL,
    PRIMARY KEY (owner, entry_uuid, field_name),
    FOREIGN KEY (owner, entry_uuid)
        REFERENCES conflict_entry(owner, entry_uuid) ON DELETE CASCADE
);

CREATE TABLE conflict_entry_custom_field (
    owner      TEXT NOT NULL,
    entry_uuid TEXT NOT NULL,
    field_name TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (owner, entry_uuid, field_name),
    FOREIGN KEY (owner, entry_uuid)
        REFERENCES conflict_entry(owner, entry_uuid) ON DELETE CASCADE
);
