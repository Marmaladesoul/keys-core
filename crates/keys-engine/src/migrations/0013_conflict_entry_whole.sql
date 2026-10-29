-- Migration 0013: a held conflict's peer row stores the peer's whole entry.
--
-- The resolver rebuilds "theirs" from the peer row and merges local against
-- it, so every facet the row drops is a facet that merge decides wrongly.
-- 0007 stored the entry facet by facet (standard fields, protected and
-- plain custom fields) and 0009 bolted attachments on; tags, `<CustomData>`
-- (the tag / attachment / history tombstones among it) and `<History>` were
-- still missing. Without history the rebuilt entry shares no ancestor with
-- local, so the tag merge falls back to a union and neither side's
-- deletions since the fork are honoured; without tags the history record of
-- a rejected peer version is unfaithful.
--
-- The row is now ONE record per (owner, entry): the peer entry and each of
-- its history versions in the `entry_history.snapshot_json` record shape
-- (see `conflict_rows::PeerEntryIo`). A future facet rides in that shape
-- instead of needing another table. Protected values (the password and
-- protected custom fields) are AES-GCM-sealed under the session key, as in
-- `entry_protected` and `entry_history`; attachment bytes are referenced by
-- SHA-256 into the shared `attachment_blob` pool, never inlined.
--
-- `conflict_entry_blob_ref` lists every pool sha the record references
-- (the live version's attachments and its history's). It is the blob-pool
-- GC's reference root for parked conflicts: a peer's divergent bytes exist
-- only in the pool until the conflict resolves or dissolves.
--
-- Existing parked rows are DROPPED, not converted: re-sealing them needs
-- the session key, which SQL doesn't have, and the engine carries no
-- one-off upgrade code. A row parked from a peer replica with its own store
-- re-parks on the next ingest from that peer, which still holds the version
-- live. A row parked from the vault FILE (an external writer of the same
-- KDBX) is different: once local saves over the file, the row is the only
-- copy of that writer's version. Resolve every held conflict before
-- upgrading. Local's own versions are untouched by the drop.
--
-- Lifetime and secret posture otherwise match 0007 (local-only, refreshed
-- per pull, not in `clear_vault_tables`, no FK to the live `entry`).

DROP TABLE conflict_entry_attachment;
DROP TABLE conflict_entry_protected;
DROP TABLE conflict_entry_custom_field;
DROP TABLE conflict_entry;

CREATE TABLE conflict_entry (
    owner      TEXT NOT NULL,
    entry_uuid TEXT NOT NULL,
    entry_json TEXT NOT NULL,
    PRIMARY KEY (owner, entry_uuid)
);

-- Backs the "any uuid with at least one peer row" badge query.
CREATE INDEX idx_conflict_entry_uuid ON conflict_entry(entry_uuid);

CREATE TABLE conflict_entry_blob_ref (
    owner       TEXT NOT NULL,
    entry_uuid  TEXT NOT NULL,
    blob_sha256 BLOB NOT NULL,
    PRIMARY KEY (owner, entry_uuid, blob_sha256),
    FOREIGN KEY (owner, entry_uuid)
        REFERENCES conflict_entry(owner, entry_uuid) ON DELETE CASCADE
);
