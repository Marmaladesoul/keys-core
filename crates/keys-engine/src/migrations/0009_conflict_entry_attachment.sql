-- Migration 0009: peer attachment state on conflict rows (keyhole Finding #7).
--
-- The resolver's "theirs" is reconstructed from the conflict_* rows. Without
-- attachment state the rebuilt remote entry carried no attachments, the
-- local-vs-theirs merge read that as "remote removed every attachment", and
-- a choose-remote resolution wiped the local attachment links —
-- data-loss-adjacent (the bytes survived unreferenced in the pool and in the
-- pre-resolve history snapshot, but the live entry lost them and replicas
-- diverged).
--
-- Bytes are NOT duplicated here: at park time they land content-addressed in
-- the shared `attachment_blob` pool (INSERT OR IGNORE) and this table
-- references them by sha — the same shape as the live `entry_attachment`
-- link table. Lifetime / secret posture matches the other conflict_* tables
-- (local-only, re-derivable, refreshed per pull); attachment bytes are not
-- sealed, matching `attachment_blob`.
--
-- NOTE for the upcoming blob-pool GC (5c remainder): this table is a
-- reference root — a blob referenced only by a parked conflict must survive
-- GC until the conflict resolves or dissolves.

CREATE TABLE conflict_entry_attachment (
    owner           TEXT NOT NULL,
    entry_uuid      TEXT NOT NULL,
    attachment_name TEXT NOT NULL,
    blob_sha256     BLOB NOT NULL,
    PRIMARY KEY (owner, entry_uuid, attachment_name),
    FOREIGN KEY (owner, entry_uuid)
        REFERENCES conflict_entry(owner, entry_uuid) ON DELETE CASCADE
);
