-- KDBX 4.1 <PreviousParentGroup>: the group an entry was last moved
-- out of. Mirrored so (a) the element round-trips through
-- ingest → mirror → projection instead of being silently stripped
-- from saved files, and (b) restore_entry can return a recycled
-- entry to where it actually lived instead of leaving it in the bin.
-- NULL = never moved / not recorded (pre-4.1 files, older rows).
ALTER TABLE entry ADD COLUMN previous_parent_uuid TEXT NULL;
