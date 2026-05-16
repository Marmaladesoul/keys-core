# Round-trip invariants

What does `kdbx → ingest → SQLite → save → reopen` preserve, and what does it lose? This doc enumerates every `Vault` field surface that the Phase 2 pipeline touches, and classifies each one as **strict**, **tolerant**, **lost-but-preserved-from-source**, or **known-defect**.

Source of truth for the assertion is the `vault_round_trip_eq` helper in `tests/round_trip.rs`.

## Strict — must match exactly

| Surface | Notes |
|---|---|
| Group hierarchy (parent/child shape) | Reconstructed from `(group.uuid, group.parent_uuid)` rows. |
| `GroupId` / `EntryId` UUIDs | Stored verbatim as `TEXT` columns. |
| `Group::name` | |
| `Entry::title`, `username`, `url`, `notes` | Plain string columns. |
| `Entry::password` (revealed plaintext) | Wrapped under the session key in `entry_protected.wrapped_blob`, AES-GCM-opened on projection. |
| Protected `CustomField::value` | Same wrap path as `password`, keyed on `field_name`. |
| `Entry::tags` (as a **set**) | Dedup-and-sort happens on ingest. Order is not preserved; the set is. |
| Attachment `(name, SHA-256 of bytes)` | Bytes are content-addressed in `attachment_blob`; `ref_id` is **not** stable across a round-trip (the projection assigns fresh ref-ids walking the entry list). |
| `Entry::history` length + per-snapshot plaintext shape | Snapshots are serialised to JSON in `entry_history.snapshot_json` and deserialised back. The JSON columns reproduce title/username/url/notes/password/tags/custom_fields/timestamps. |
| `Meta::recycle_bin_uuid` | Persisted via the `is_recycle_bin` column on `group`. |

## Tolerant — compared after normalisation

| Surface | Normalisation |
|---|---|
| All timestamps | Truncated to whole seconds before comparison. KDBX serialisation drops sub-second precision (`<Times>` carry ISO-8601 strings without milliseconds), so anything finer than 1 s can't round-trip through the on-disk format. |
| `None` vs `Some(epoch)` timestamps | Treated equivalent. The v1 schema declares `created_at` / `modified_at` / `accessed_at` `NOT NULL`, so a source-side `None` becomes `Some(0)` after ingest+projection. Both forms compare equal to each other and to a "no information" baseline. |
| `Entry::tags` order | Compared as `HashSet`, not `Vec`. Projection sorts tags alphabetically; the source vault may carry any order. |

## Lost-but-preserved-from-source — not in the v1 schema, but preserved on save

These `Meta` fields aren't persisted in the SQLite mirror. The save path (`save.rs::splice_preserving_meta`) carries them across by copying `kdbx.vault().meta` onto the projected vault before serialising, so they **do** survive a single round-trip — but only because the live kdbx handle still has them. After a `close → reopen` of the engine without the original kdbx handle (which doesn't happen in this test), they'd be regenerated as default by the next save.

- `Meta::database_name`
- `Meta::generator`
- `Meta::history_max_items`, `history_max_size`
- `Meta::custom_icons`
- `Meta::custom_data`
- `Meta::memory_protection`
- `Meta::unknown_xml`
- `Vault::deleted_objects`
- All other non-recycle-bin `Meta` fields

The round-trip test helper doesn't re-check these, because a strict comparison would only verify that `kdbx.vault().meta` equals `kdbx.vault().meta` — the splice carries them verbatim. A future schema migration that persists `Meta` would let these graduate to **strict**.

## Known-defect — recognised data loss in v1 schema

| Surface | Loss | Path to fix |
|---|---|---|
| `Meta::recycle_bin_enabled` when `recycle_bin_uuid IS NULL` | Lost — the schema derives `enabled` from "does a bin group exist?". A KDBX file that says "enabled=true, no bin yet" round-trips as "enabled=false". | Persist the flag explicitly in the `setting` table. Cheap, can land alongside the other phase-2 hygiene work. |
| `Binary::protected` flag | Lost — every attachment projects as `protected = false`. KeePassXC's default for attachments is unprotected, so this matters only for hand-rolled / legacy vaults. | Add a `protected INTEGER NOT NULL DEFAULT 0` column to `attachment_blob` or `entry_attachment`. |
| Attachment `ref_id` stability | Not preserved across round-trips. Compared by `(name, sha256)` instead. | Not a defect — `ref_id` is an internal index into `Vault::binaries`, not a content identifier. |

## Adding new fields

When the schema grows (new column, new table, new projection), update the equality helper in the same PR:

1. If the field is preserved losslessly → add a strict comparison.
2. If the field is preserved with tolerance → add normalisation + comparison, document the rule here.
3. If the field is intentionally dropped → add to the "Known-defect" table with the rationale and the path to fix it later.
