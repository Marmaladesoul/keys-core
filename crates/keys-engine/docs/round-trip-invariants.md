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
| `Entry::history` length + per-snapshot revealed shape | Snapshots are serialised to JSON in `entry_history.snapshot_json` and deserialised back. Protected fields (the canonical `password` slot and any `custom_field` with `protected: true`) are AES-GCM-sealed under the session key and base64-encoded *inside* the JSON — same wire format as `entry_protected.wrapped_blob`. Projection unwraps them on the way out, so the reloaded `Entry::history` carries plaintext that matches the source vault. Comparisons run against the revealed plaintext, never the JSON bytes. |
| `Meta::recycle_bin_uuid` | Persisted via the `is_recycle_bin` column on `group`. |
| `Meta::recycle_bin_enabled` | Persisted explicitly in the `setting` table under key `meta.recycle_bin_enabled` (1-byte BLOB). Round-trips cleanly even when `recycle_bin_uuid IS NULL`. Legacy DBs without the row fall back to `recycle_bin_uuid.is_some()`. |
| `Meta::generator`, `database_name`, `database_description`, `default_username`, `color`, `header_hash` | Persisted as utf-8 bytes in `setting` rows keyed `meta.*` (migration 0003). |
| `Meta::history_max_items`, `history_max_size`, `maintenance_history_days`, `master_key_change_rec`, `master_key_change_force` | Persisted as little-endian fixed-width ints in `setting` rows keyed `meta.*` (migration 0003). |
| `Meta::memory_protection` | Five booleans packed into a single byte in the `meta.memory_protection` setting row (migration 0003). |
| `Meta::custom_icons` | One row per icon in the `meta_custom_icon` table — `(uuid, name, bytes, last_modified_at)`. Compared as a set keyed by uuid in the round-trip harness because save-time order is not guaranteed (migration 0003). |
| `Meta::custom_data` | One row per item in `meta_custom_data` — `(key, value, last_modified_at)` (migration 0003). |
| `Meta::*_changed` timestamps (`database_name_changed`, `database_description_changed`, `default_username_changed`, `recycle_bin_changed`, `settings_changed`, `master_key_changed`) | Persisted as little-endian `i64` ms-since-epoch in `setting` rows (migration 0003). Compared at second precision per the timestamp rules below. |
| `Vault::deleted_objects` | Tombstone rows in `meta_deleted_object` — `(uuid, deleted_at)` (migration 0003). Compared as a set keyed by uuid. |

## Tolerant — compared after normalisation

| Surface | Normalisation |
|---|---|
| All timestamps | Truncated to whole seconds before comparison. KDBX serialisation drops sub-second precision (`<Times>` carry ISO-8601 strings without milliseconds), so anything finer than 1 s can't round-trip through the on-disk format. |
| `None` vs `Some(epoch)` timestamps | Treated equivalent. The v1 schema declares `created_at` / `modified_at` / `accessed_at` `NOT NULL`, so a source-side `None` becomes `Some(0)` after ingest+projection. Both forms compare equal to each other and to a "no information" baseline. |
| `Entry::tags` order | Compared as `HashSet`, not `Vec`. Projection sorts tags alphabetically; the source vault may carry any order. |

## Lost-but-preserved-from-source — historical

This section listed `Meta` fields that the v1 schema didn't persist; `save.rs::splice_preserving_meta` used to carry them forward by copying from the live `Kdbx<Unlocked>` handle. Migration 0003 (the meta-into-sqlite work) graduated every one of those fields to **strict**, and `splice_preserving_meta` has been retired. SQLite is now a complete representation of the vault — the engine can reconstitute a KDBX file without any input from a live `Kdbx` handle.

`Meta::unknown_xml` is persisted (as a JSON list of `(tag, base64(raw_xml))` records in the `meta.unknown_xml` setting row) but compared by **count only** in the round-trip harness because `quick-xml` is free to re-emit attribute ordering / whitespace / empty-element shorthand differently on each pass. The SQLite-only round-trip is byte-exact; only the kdbx → save → reopen path is tolerant on this field.

## Known-defect — recognised data loss in v1 schema

| Surface | Loss | Path to fix |
|---|---|---|
| `Binary::protected` flag | Lost — every attachment projects as `protected = false`. KeePassXC's default for attachments is unprotected, so this matters only for hand-rolled / legacy vaults. | Add a `protected INTEGER NOT NULL DEFAULT 0` column to `attachment_blob` or `entry_attachment`. |
| Attachment `ref_id` stability | Not preserved across round-trips. Compared by `(name, sha256)` instead. | Not a defect — `ref_id` is an internal index into `Vault::binaries`, not a content identifier. |

## Adding new fields

When the schema grows (new column, new table, new projection), update the equality helper in the same PR:

1. If the field is preserved losslessly → add a strict comparison.
2. If the field is preserved with tolerance → add normalisation + comparison, document the rule here.
3. If the field is intentionally dropped → add to the "Known-defect" table with the rationale and the path to fix it later.
