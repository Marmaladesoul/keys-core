# Predicate versioning rules

Smart-folder predicate JSON must survive cross-version, cross-device sync.
Four rules govern the on-the-wire shape; together they let any device safely
ignore variants and fields it doesn't recognise without dropping data or
corrupting a peer.

These rules are normative. They are duplicated verbatim from the project
tracker (`_localdocs/SQLITE_MIGRATION.md` → "Predicate versioning rules")
so that anyone adding a predicate variant or persisting a folder can read
the discipline next to the code it constrains.

## The four rules

1. **Predicates are tagged unions.** Every node has a `type` discriminator
   and a fixed set of fields. Example: `{"type": "tag_equals", "tag":
   "banking"}`.

2. **Producers are additive-only.** Adding a new predicate type or a new
   optional field to an existing type is fine — old decoders ignore unknown
   fields. **Renaming a field, removing a field, or making an old field
   required is a breaking change and is forbidden.** If a wholesale
   restructure becomes necessary, introduce a NEW `type` discriminator and
   keep the old one supported in perpetuity. The "deprecated types" list
   grows; the schema doesn't break.

3. **Decoders are tolerant.** Unknown `type` discriminator → mark the
   predicate (and its enclosing folder) as `evaluable: false`. Preserve the
   raw JSON so a future-version decoder can read it. Do not crash, do not
   silently drop.

4. **Top-level `version` field as emergency escape hatch.** Each folder
   document carries `"version": 1` by default. Reserved for the case where
   Rule 2 has to be violated despite best efforts — at which point write
   an explicit v1 → vN migration. Probably never used if Rule 2 is
   followed.

## Storage shape decision

Per Rule 4 the folder document carries a top-level `version`. In KeysCore
the storage layer realises this as **two columns on `smart_folder`** rather
than a JSON envelope:

| Column           | Type    | Purpose                                                  |
|------------------|---------|----------------------------------------------------------|
| `predicate_json` | `TEXT`  | Bare `Predicate` JSON — the `{"type": …, …}` object.     |
| `version`        | `INT`   | Document version. Defaults to `1`. Bump only per Rule 4. |

This is **option A** in the task brief: predicate JSON stays as a bare
tagged-union object; the `version` field is a sibling DB column instead of
a wrapping `{"version": N, "predicate": {…}}` envelope. The reasons:

- No data migration required — Phase 3.5 already shipped the two-column
  layout.
- Simpler call sites: `serde_json::to_string(predicate)` and
  `serde_json::from_str::<Predicate>` round-trip without an envelope
  intermediary.
- The `version` column **is** the emergency escape hatch from Rule 4. If
  Rule 2 ever has to be violated, bump the column and write a v1 → vN
  migration.

If predicate JSON is ever serialised **outside** the database (e.g. shared
between users via export, or piped over an IPC boundary that doesn't carry
the sibling column), wrap it in
`{"version": N, "predicate": {…}}` at the boundary. The on-disk shape
stays unchanged.

## How each rule lands in code

| Rule | Where                                                                 |
|------|-----------------------------------------------------------------------|
| 1    | `Predicate` enum (`crates/keys-engine/src/predicate.rs`) plus the private `KnownPredicate` mirror with `#[serde(tag = "type", rename_all = "snake_case")]`. |
| 2    | No `#[serde(deny_unknown_fields)]` anywhere on `Predicate` or its mirror — serde's default is to ignore unknown fields. Verified by `old_decoder_ignores_new_field_on_existing_type` in `tests/predicate_versioning.rs`. |
| 3    | `Predicate::Unknown(serde_json::Value)` catch-all + the hand-rolled `Deserialize` impl in `predicate.rs` that maps unknown discriminators to it. `Predicate::is_evaluable` recurses; smart-folder writes persist the result in the `evaluable` column. |
| 4    | `smart_folder.version` column, surfaced as `SmartFolder::version: u32`. New folders default to `1`. |

## Discipline checklist for adding a new predicate variant

1. Add the variant to `Predicate` enum with full serde annotations (via
   the private `KnownPredicate` mirror).
2. Update `KNOWN_TYPE_DISCRIMINATORS` in `predicate.rs` with the
   `snake_case` discriminator string.
3. Add the SQL mapping in `predicate_sql::compile`.
4. Add a JSON round-trip unit test (covered by
   `every_known_variant_round_trips`).
5. Add an SQL-execution e2e test in `tests/predicate_sql_e2e.rs`.
6. (Optional) Add a built-in folder using it in `predicate_builtin.rs`.
7. Update `docs/query-surface.md` and this versioning doc.

## Discipline checklist for adding a field to an existing variant

1. Add the field as `Option<T>` or with `#[serde(default)]` — **never
   required**.
2. Ensure old payloads without the field still deserialise — covered by
   the `old_decoder_ignores_new_field_on_existing_type` pattern.
3. Add a round-trip test asserting the old shape still produces the right
   (default-equipped) variant.
4. If the field is meaningful to evaluation, update
   `predicate_sql::compile` to use it when present and to behave
   identically to the old shape when absent.

## Forbidden changes

- Renaming a field on an existing `type`.
- Removing a field from an existing `type`.
- Changing a field's type (e.g. `String` → `Vec<String>`).
- Making a previously-optional field required.
- Adding `#[serde(deny_unknown_fields)]` to `Predicate` or `KnownPredicate`.

If one of these is genuinely unavoidable, use Rule 4: bump `version`,
write a `v1 → vN` migration, and document the break here.
