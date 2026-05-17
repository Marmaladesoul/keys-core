-- Migration 0004: persistent sibling-group ordering.
--
-- Adds a `sort_order` column to `"group"` so the engine can preserve
-- per-parent positional order of sibling groups across save/load and
-- expose a `reorder_group` mutation for drag-reorder UI. KDBX itself
-- carries an ordered list of children per group; before this column
-- the engine projected groups back to KDBX in alphabetical-by-name
-- order, which clobbered any manual ordering the user had applied.
--
-- Existing rows default to `sort_order = 0`. Until the next ingest
-- (which writes the correct positional order), all siblings share
-- the default value and the secondary `name ASC` sort in
-- `group_tree` keeps the order stable.

ALTER TABLE "group" ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_group_parent_sort ON "group"(parent_uuid, sort_order);
