-- Migration 0012: the persistence watermark — engine-owned dirty truth.
--
-- Mutations persist to the SQLite mirror synchronously; the KDBX
-- projection (`save_to_kdbx`) is a separate, caller-triggered step.
-- Whether the KDBX write is still *owed* was, until now, a per-call-site
-- convention in every frontend. This migration moves that truth into
-- the engine as a monotonic watermark pair in `setting`:
--
--   persistence.mutation_seq    bumped whenever vault CONTENT changes
--   persistence.persisted_seq   the mutation_seq captured at the start
--                               of the last successful persist /
--                               correspondence point (save, ingest,
--                               rebuild)
--
-- Dirty  =  mutation_seq > persisted_seq.
--
-- A watermark pair rather than a boolean: a mutation landing while a
-- persist is in flight stays strictly greater than the sequence the
-- persist captured at its start, so it can never be masked by that
-- persist's completion. Both rows persist in `setting`, so a process
-- crash after a mutation but before a save leaves the mirror visibly
-- dirty on reopen — the orchestrator flushes instead of the KDBX
-- silently lagging until the next unrelated save.
--
-- The bump is enforced by AFTER-triggers on every table whose rows
-- project into the KDBX, so it happens inside the same transaction as
-- the row write and cannot be forgotten by a new mutation entry point.
--
-- Trigger coverage (kept honest by the `trigger_coverage_is_complete`
-- test in tests/persistence_watermark.rs — a future migration adding a
-- projected table must add its three triggers or that test fails):
--
--   INCLUDED — projected vault content:
--     entry, entry_attachment, entry_custom_data, entry_custom_field,
--     entry_history, entry_protected, entry_tag, "group",
--     meta_custom_data, meta_custom_icon, meta_deleted_object, tag,
--     and `setting` rows whose key is 'meta.%' (the scalar Meta fields
--     live there since migration 0003).
--
--   EXCLUDED — not projected content:
--     setting (all non-meta keys: the watermark itself, kdbx-state
--       signatures, fingerprint key — bumping on these would re-dirty
--       every save),
--     attachment_blob (content-addressed pool; rows are only reachable
--       via entry_attachment links, which DO bump. The save-time blob
--       GC deletes unreferenced pool rows — bumping there would
--       re-dirty the mirror on every save, an infinite save loop),
--     conflict_entry / conflict_entry_* (mirror-local parked-conflict
--       copies; the projected conflict *marker* lands in
--       entry_custom_data, which bumps),
--     smart_folder (mirror-local; never projected or ingested),
--     schema_version (migration bookkeeping).
--
-- Recursion safety: the bump UPDATE targets a `setting` row whose key
-- ('persistence.mutation_seq') never matches the meta-trigger's
-- `LIKE 'meta.%'` WHEN clause, so the trigger set cannot re-fire
-- itself regardless of the recursive_triggers pragma.

-- Seed the watermark. A brand-new mirror starts settled at 0/0 — the
-- migration runs at open, before any content exists. An EXISTING
-- mirror (any ingested vault has at least its root "group" row) is
-- seeded DIRTY (1/0): whether its content actually diverges from the
-- KDBX is unknowable at migration time, and the two failure
-- directions are asymmetric — a false "dirty" costs one harmless
-- save at the next flush, while a false "clean" on a mirror holding
-- a genuinely-unsaved mutation loses that mutation the next time the
-- mirror is rebuilt from disk. The next real correspondence point
-- (save or ingest+signature) settles it.
INSERT OR IGNORE INTO setting(key, value)
SELECT 'persistence.mutation_seq',
       CASE WHEN EXISTS(SELECT 1 FROM "group") THEN 1 ELSE 0 END;
INSERT OR IGNORE INTO setting(key, value) VALUES ('persistence.persisted_seq', 0);

-- entry
CREATE TRIGGER mutation_seq_entry_insert AFTER INSERT ON entry
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_update AFTER UPDATE ON entry
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_delete AFTER DELETE ON entry
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- entry_attachment
CREATE TRIGGER mutation_seq_entry_attachment_insert AFTER INSERT ON entry_attachment
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_attachment_update AFTER UPDATE ON entry_attachment
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_attachment_delete AFTER DELETE ON entry_attachment
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- entry_custom_data
CREATE TRIGGER mutation_seq_entry_custom_data_insert AFTER INSERT ON entry_custom_data
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_custom_data_update AFTER UPDATE ON entry_custom_data
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_custom_data_delete AFTER DELETE ON entry_custom_data
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- entry_custom_field
CREATE TRIGGER mutation_seq_entry_custom_field_insert AFTER INSERT ON entry_custom_field
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_custom_field_update AFTER UPDATE ON entry_custom_field
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_custom_field_delete AFTER DELETE ON entry_custom_field
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- entry_history
CREATE TRIGGER mutation_seq_entry_history_insert AFTER INSERT ON entry_history
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_history_update AFTER UPDATE ON entry_history
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_history_delete AFTER DELETE ON entry_history
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- entry_protected
CREATE TRIGGER mutation_seq_entry_protected_insert AFTER INSERT ON entry_protected
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_protected_update AFTER UPDATE ON entry_protected
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_protected_delete AFTER DELETE ON entry_protected
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- entry_tag
CREATE TRIGGER mutation_seq_entry_tag_insert AFTER INSERT ON entry_tag
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_tag_update AFTER UPDATE ON entry_tag
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_entry_tag_delete AFTER DELETE ON entry_tag
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- "group" (quoted — SQL keyword)
CREATE TRIGGER mutation_seq_group_insert AFTER INSERT ON "group"
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_group_update AFTER UPDATE ON "group"
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_group_delete AFTER DELETE ON "group"
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- meta_custom_data
CREATE TRIGGER mutation_seq_meta_custom_data_insert AFTER INSERT ON meta_custom_data
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_meta_custom_data_update AFTER UPDATE ON meta_custom_data
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_meta_custom_data_delete AFTER DELETE ON meta_custom_data
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- meta_custom_icon
CREATE TRIGGER mutation_seq_meta_custom_icon_insert AFTER INSERT ON meta_custom_icon
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_meta_custom_icon_update AFTER UPDATE ON meta_custom_icon
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_meta_custom_icon_delete AFTER DELETE ON meta_custom_icon
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- meta_deleted_object
CREATE TRIGGER mutation_seq_meta_deleted_object_insert AFTER INSERT ON meta_deleted_object
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_meta_deleted_object_update AFTER UPDATE ON meta_deleted_object
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_meta_deleted_object_delete AFTER DELETE ON meta_deleted_object
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- tag
CREATE TRIGGER mutation_seq_tag_insert AFTER INSERT ON tag
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_tag_update AFTER UPDATE ON tag
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_tag_delete AFTER DELETE ON tag
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;

-- setting: ONLY the scalar Meta rows (key 'meta.%') are projected
-- content. The WHEN clause keeps the watermark's own row writes (and
-- signature/fingerprint writes) from bumping.
CREATE TRIGGER mutation_seq_setting_meta_insert AFTER INSERT ON setting
WHEN NEW.key LIKE 'meta.%'
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_setting_meta_update AFTER UPDATE ON setting
WHEN NEW.key LIKE 'meta.%'
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
CREATE TRIGGER mutation_seq_setting_meta_delete AFTER DELETE ON setting
WHEN OLD.key LIKE 'meta.%'
BEGIN UPDATE setting SET value = value + 1 WHERE key = 'persistence.mutation_seq'; END;
