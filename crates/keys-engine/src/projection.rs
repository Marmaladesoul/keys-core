//! `SQLite` → `Vault` projection — the reverse of [`crate::ingest`].
//!
//! Reconstructs a [`keepass_core::model::Vault`] from the engine's
//! `SQLite` mirror. Used by the upcoming serialise path (task 2.5) and
//! by the round-trip property tests (task 2.7). Read-only: every query
//! runs inside a single immediate transaction so the projected vault
//! reflects a consistent point-in-time snapshot, but nothing is
//! written.
//!
//! Mapping invariants (must stay in lock-step with
//! [`crate::ingest`]):
//!
//! * Groups round-trip via `(uuid, parent_uuid)`; the root group is the
//!   single row with `parent_uuid IS NULL`.
//! * Entries attach to their `group_uuid` parent.
//! * `entry_protected.field_name = 'Password'` becomes
//!   [`keepass_core::model::Entry::password`] (plaintext).
//! * Other `entry_protected` rows become protected
//!   [`keepass_core::model::CustomField`]s with `protected = true`.
//! * `entry_history.snapshot_json` is the
//!   `crate::ingest::HistorySnapshot` shape; protected fields inside the
//!   JSON are base64-encoded AES-GCM-sealed bytes (same wire format as
//!   `entry_protected.wrapped_blob`) and get unwrapped under the session
//!   key on the way out, producing a plaintext [`Entry`] used as the
//!   history record.
//! * Attachments materialise as fresh [`Vault::binaries`] entries — one
//!   per unique SHA-256, with `Attachment::ref_id` pointing into the
//!   new pool. The original `Binary::protected` flag is **not**
//!   preserved (the schema has no column for it); we project everything
//!   as `protected = false`, which matches `KeePassXC`'s default for
//!   non-encrypted attachment payloads.
//! * `entry.url_host` is engine-internal (an indexed lookup column);
//!   it does **not** surface on the projected vault.
//! * `entry.is_recycled` is implied by group membership in the
//!   projection — entries inside (or under) the recycle-bin group are
//!   recycled. The column is read for cross-checks in tests but not
//!   set on the model.
//! * Non-protected custom fields live in `entry_custom_field`
//!   (migration 0002). They project back as
//!   [`keepass_core::model::CustomField`]s with `protected = false`,
//!   alongside the protected fields recovered from `entry_protected`.

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};
use keepass_core::model::{
    Attachment, Binary, CustomDataItem, CustomField, Entry, EntryId, Group, GroupId, Timestamps,
    Vault,
};
use keepass_core::protector::{FieldProtector, SessionKey, open_with_key};
use rusqlite::Connection;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{EngineError, ProjectionError};
use crate::meta;

/// Canonical KDBX field name for an entry's password slot — must match
/// [`crate::ingest`]'s constant of the same name.
const PASSWORD_FIELD: &str = "Password";

/// Top-level projection entry point. Runs every read inside a single
/// immediate transaction so the snapshot is consistent.
#[allow(clippy::too_many_lines)]
pub(crate) fn project(
    conn: &Connection,
    protector: &dyn FieldProtector,
) -> Result<Vault, EngineError> {
    let session_key = protector
        .acquire_session_key()
        .map_err(|e| EngineError::Projection(ProjectionError::SessionKey(e.to_string())))?;

    // Read-only — we don't open a transaction. SQLite serialises
    // statements per-connection so individual reads see a consistent
    // page state, and the engine holds the only handle. If we ever
    // grow concurrent writers we'll want a deferred read transaction
    // here; for now any added ceremony is dead weight.

    // 1. Groups: load all rows, build a tree.
    let group_rows = load_group_rows(conn)?;
    let (mut root, recycle_bin_uuid) = build_group_tree(group_rows)?;

    // 2. Entries: load every entry row with its derived columns.
    let entry_rows = load_entry_rows(conn)?;

    // 3. Side tables: protected blobs, attachments (joined with blobs),
    //    tags (joined), history snapshots. Batch one query per table.
    let protected = load_protected(conn)?;
    let non_protected = load_non_protected_custom_fields(conn)?;
    let attachments = load_attachments(conn)?;
    let tags = load_tags(conn)?;
    let history = load_history(conn)?;
    let entry_custom_data = load_entry_custom_data(conn)?;

    // 4. Materialise the binary pool. We assign a fresh ref_id per
    //    distinct attachment blob, populated lazily as we walk entries
    //    so the pool order is deterministic relative to walk order.
    let mut binary_pool: Vec<Binary> = Vec::new();
    let mut sha_to_ref: HashMap<[u8; 32], u32> = HashMap::new();

    // 5. Assemble entries with their side-table data attached, keyed by
    //    group_uuid so we can hang them off the tree in step 6.
    let mut entries_by_group: HashMap<Uuid, Vec<Entry>> = HashMap::new();
    for row in entry_rows {
        let entry_uuid = row.uuid;
        let mut entry = build_entry_from_row(&row);

        // Protected fields.
        if let Some(rows) = protected.get(&entry_uuid) {
            for (field_name, wrapped) in rows {
                let plaintext = open_with_key(&session_key, wrapped).map_err(|e| {
                    EngineError::Projection(ProjectionError::Unwrap(format!(
                        "entry {entry_uuid} field {field_name}: {e}",
                    )))
                })?;
                let plaintext_str = String::from_utf8(plaintext).map_err(|e| {
                    EngineError::Projection(ProjectionError::Unwrap(format!(
                        "entry {entry_uuid} field {field_name}: non-utf8 plaintext: {e}",
                    )))
                })?;
                if field_name == PASSWORD_FIELD {
                    entry.password = plaintext_str;
                } else {
                    entry.custom_fields.push(CustomField::new(
                        field_name.clone(),
                        plaintext_str,
                        true,
                    ));
                }
            }
        }

        // Non-protected custom fields (migration 0002).
        if let Some(rows) = non_protected.get(&entry_uuid) {
            for (field_name, value) in rows {
                entry.custom_fields.push(CustomField::new(
                    field_name.clone(),
                    value.clone(),
                    false,
                ));
            }
        }

        // Attachments → bind into the binary pool.
        if let Some(rows) = attachments.get(&entry_uuid) {
            for att in rows {
                let ref_id = if let Some(id) = sha_to_ref.get(&att.sha256) {
                    *id
                } else {
                    let id = u32::try_from(binary_pool.len()).map_err(|_| {
                        EngineError::Projection(ProjectionError::SchemaInvariant(
                            "binary pool exceeded u32::MAX".into(),
                        ))
                    })?;
                    binary_pool.push(Binary::new(att.bytes.clone(), false));
                    sha_to_ref.insert(att.sha256, id);
                    id
                };
                entry
                    .attachments
                    .push(Attachment::new(att.name.clone(), ref_id));
            }
        }

        // Tags.
        if let Some(rows) = tags.get(&entry_uuid) {
            entry.tags.clone_from(rows);
        }

        // Per-entry `<CustomData>` (migration 0006). Round-trips
        // Keys-namespaced extensions like `keys.history_tombstones.v1`
        // that need to survive a reconcile→project→save cycle.
        if let Some(rows) = entry_custom_data.get(&entry_uuid) {
            for (key, value, last_modified_ms) in rows {
                entry.custom_data.push(CustomDataItem::new(
                    key.clone(),
                    value.clone(),
                    last_modified_ms.and_then(ms_to_dt),
                ));
            }
        }

        // History. Protected snapshot fields (password + protected
        // custom fields) carry base64-encoded AES-GCM-sealed bytes —
        // unwrap them under the session key on the way out so the
        // projected `Entry::history` carries plaintext, the same shape
        // a fresh-from-KDBX `Vault` would carry.
        if let Some(rows) = history.get(&entry_uuid) {
            // rows is sorted oldest-first by history_index.
            for snap in rows {
                entry
                    .history
                    .push(snapshot_to_entry(entry_uuid, snap, &session_key)?);
            }
        }

        entries_by_group
            .entry(row.group_uuid)
            .or_default()
            .push(entry);
    }

    attach_entries_to_tree(&mut root, &mut entries_by_group);

    let mut vault = Vault::empty(root.id);
    vault.root = root;
    vault.binaries = binary_pool;

    // Reconstitute the full `Meta` block from the persisted
    // setting rows + `meta_*` companion tables (migration 0003). The
    // engine no longer needs a live `Kdbx<Unlocked>` handle to round-trip
    // `Meta` faithfully; SQLite is the source of truth.
    meta::read_meta_into(conn, &mut vault.meta)?;
    vault.meta.recycle_bin_uuid = recycle_bin_uuid;
    // Prefer the explicit `meta.recycle_bin_enabled` setting row written
    // by ingest. Legacy DBs predating that row fall back to the derived
    // "does a bin group exist?" behaviour. The setting captures the
    // "enabled=true, no bin yet" intermediate state KeePassXC emits.
    vault.meta.recycle_bin_enabled =
        load_recycle_bin_enabled(conn)?.unwrap_or_else(|| recycle_bin_uuid.is_some());

    vault.deleted_objects = meta::read_deleted_objects(conn)?;

    Ok(vault)
}

// ───────────────────────── group tree ─────────────────────────

struct GroupRow {
    uuid: Uuid,
    parent_uuid: Option<Uuid>,
    name: String,
    icon_index: Option<i64>,
    icon_custom_uuid: Option<Uuid>,
    notes: String,
    created_at: i64,
    modified_at: i64,
    expires_at: Option<i64>,
    is_recycle_bin: bool,
    /// Persisted sibling order. Not consumed by `build_subtree` —
    /// child ordering is fixed at query time by the `ORDER BY` clause
    /// in [`load_group_rows`]. Kept on the row for completeness /
    /// future read paths that want positional metadata.
    #[allow(dead_code)]
    sort_order: u32,
}

/// Read the explicit `meta.recycle_bin_enabled` setting row written by
/// ingest. Returns `Ok(None)` when no row exists — callers fall back to
/// the derived "does a bin group exist?" behaviour for legacy DBs. The
/// value is stored as a 1-byte BLOB (`[0]` / `[1]`); any other shape is
/// treated as `None` so a corrupt row doesn't poison the projection.
fn load_recycle_bin_enabled(conn: &Connection) -> Result<Option<bool>, EngineError> {
    let result: Result<Vec<u8>, rusqlite::Error> = conn.query_row(
        "SELECT value FROM setting WHERE key = 'meta.recycle_bin_enabled'",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    );
    match result {
        Ok(bytes) if bytes.len() == 1 => Ok(Some(bytes[0] != 0)),
        Ok(_) | Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(EngineError::Sqlite(err)),
    }
}

fn load_group_rows(conn: &Connection) -> Result<Vec<GroupRow>, EngineError> {
    // Order by `sort_order, name, uuid` so the build_subtree pass below
    // emits children in the persisted positional order. The
    // `parent_uuid` column ordering is only used by `build_group_tree`
    // to bucket rows by parent — the iteration order over rows there
    // is what determines child order on the projected `Vault`.
    let mut stmt = conn.prepare(
        "SELECT uuid, parent_uuid, name, icon_index, icon_custom_uuid, notes, \
                created_at, modified_at, expires_at, is_recycle_bin, sort_order \
         FROM \"group\" \
         ORDER BY sort_order ASC, name ASC, uuid ASC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let sort_order_i64: i64 = row.get(10)?;
            Ok(GroupRow {
                uuid: parse_uuid_col(row, 0)?,
                parent_uuid: row
                    .get::<_, Option<String>>(1)?
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                name: row.get(2)?,
                icon_index: row.get(3)?,
                icon_custom_uuid: row
                    .get::<_, Option<String>>(4)?
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                notes: row.get(5)?,
                created_at: row.get(6)?,
                modified_at: row.get(7)?,
                expires_at: row.get(8)?,
                is_recycle_bin: row.get::<_, i64>(9)? != 0,
                sort_order: crate::reads::u32_from_db_column(sort_order_i64, 10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Assemble groups into a tree. Returns `(root, recycle_bin_uuid)`.
fn build_group_tree(rows: Vec<GroupRow>) -> Result<(Group, Option<GroupId>), EngineError> {
    // Identify the root: parent_uuid IS NULL.
    let mut by_uuid: HashMap<Uuid, GroupRow> = HashMap::new();
    let mut children_of: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    let mut root_uuid: Option<Uuid> = None;
    let mut recycle_bin_uuid: Option<Uuid> = None;

    for row in rows {
        if row.is_recycle_bin {
            recycle_bin_uuid = Some(row.uuid);
        }
        match row.parent_uuid {
            None => {
                if let Some(existing) = root_uuid {
                    return Err(EngineError::Projection(ProjectionError::SchemaInvariant(
                        format!("multiple root groups: {existing} and {}", row.uuid),
                    )));
                }
                root_uuid = Some(row.uuid);
            }
            Some(p) => {
                children_of.entry(p).or_default().push(row.uuid);
            }
        }
        by_uuid.insert(row.uuid, row);
    }

    let root_uuid = root_uuid.ok_or_else(|| {
        EngineError::Projection(ProjectionError::SchemaInvariant(
            "no root group (no row with parent_uuid NULL)".into(),
        ))
    })?;

    let root = build_subtree(root_uuid, &mut by_uuid, &children_of)?;
    Ok((root, recycle_bin_uuid.map(GroupId)))
}

fn build_subtree(
    uuid: Uuid,
    by_uuid: &mut HashMap<Uuid, GroupRow>,
    children_of: &HashMap<Uuid, Vec<Uuid>>,
) -> Result<Group, EngineError> {
    let row = by_uuid.remove(&uuid).ok_or_else(|| {
        EngineError::Projection(ProjectionError::SchemaInvariant(format!(
            "group {uuid} referenced as parent but no row found",
        )))
    })?;
    let mut group = Group::empty(GroupId(row.uuid));
    group.name = row.name;
    group.notes = row.notes;
    // Saturating, not corruption-class: ingest bounded `icon_index` into
    // `u32` at write time, so a value outside that range here would be
    // an ingest invariant violation. `debug_assert!` so CI catches it;
    // production falls back to the default icon rather than aborting a
    // projection.
    let icon_idx = row.icon_index.unwrap_or(0);
    debug_assert!(
        (0..=i64::from(u32::MAX)).contains(&icon_idx),
        "group icon_index {icon_idx} out of u32 range — ingest invariant violated",
    );
    group.icon_id = u32::try_from(icon_idx).unwrap_or(0);
    group.custom_icon_uuid = row.icon_custom_uuid;
    group.times = build_times(
        row.created_at,
        row.modified_at,
        row.modified_at,
        row.expires_at,
    );

    if let Some(child_ids) = children_of.get(&uuid) {
        for child_uuid in child_ids {
            group
                .groups
                .push(build_subtree(*child_uuid, by_uuid, children_of)?);
        }
    }
    Ok(group)
}

fn attach_entries_to_tree(group: &mut Group, entries_by_group: &mut HashMap<Uuid, Vec<Entry>>) {
    if let Some(es) = entries_by_group.remove(&group.id.0) {
        group.entries = es;
    }
    for child in &mut group.groups {
        attach_entries_to_tree(child, entries_by_group);
    }
}

// ───────────────────────── entries ─────────────────────────

struct EntryRow {
    uuid: Uuid,
    group_uuid: Uuid,
    title: String,
    username: String,
    url: String,
    notes: String,
    icon_index: Option<i64>,
    icon_custom_uuid: Option<Uuid>,
    created_at: i64,
    modified_at: i64,
    accessed_at: i64,
    expires_at: Option<i64>,
    previous_parent_uuid: Option<Uuid>,
}

fn load_entry_rows(conn: &Connection) -> Result<Vec<EntryRow>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT uuid, group_uuid, title, username, url, notes, \
                icon_index, icon_custom_uuid, \
                created_at, modified_at, accessed_at, expires_at, \
                previous_parent_uuid \
         FROM entry",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(EntryRow {
                uuid: parse_uuid_col(row, 0)?,
                group_uuid: parse_uuid_col(row, 1)?,
                title: row.get(2)?,
                username: row.get(3)?,
                url: row.get(4)?,
                notes: row.get(5)?,
                icon_index: row.get(6)?,
                icon_custom_uuid: row
                    .get::<_, Option<String>>(7)?
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                created_at: row.get(8)?,
                modified_at: row.get(9)?,
                accessed_at: row.get(10)?,
                expires_at: row.get(11)?,
                previous_parent_uuid: row
                    .get::<_, Option<String>>(12)?
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            12,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn build_entry_from_row(row: &EntryRow) -> Entry {
    let mut entry = Entry::empty(EntryId(row.uuid));
    entry.title.clone_from(&row.title);
    entry.username.clone_from(&row.username);
    entry.url.clone_from(&row.url);
    entry.notes.clone_from(&row.notes);
    // See group-side note in `build_subtree` — saturating with a
    // `debug_assert!` rather than surfacing a typed error, because
    // ingest bounded this into `u32` at write time.
    let icon_idx = row.icon_index.unwrap_or(0);
    debug_assert!(
        (0..=i64::from(u32::MAX)).contains(&icon_idx),
        "entry icon_index {icon_idx} out of u32 range — ingest invariant violated",
    );
    entry.icon_id = u32::try_from(icon_idx).unwrap_or(0);
    entry.custom_icon_uuid = row.icon_custom_uuid;
    entry.previous_parent_group = row.previous_parent_uuid.map(GroupId);
    entry.times = build_times(
        row.created_at,
        row.modified_at,
        row.accessed_at,
        row.expires_at,
    );
    entry
}

// ───────────────────────── side tables ─────────────────────────

type ProtectedRows = HashMap<Uuid, Vec<(String, Vec<u8>)>>;

fn load_protected(conn: &Connection) -> Result<ProtectedRows, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT entry_uuid, field_name, wrapped_blob FROM entry_protected ORDER BY entry_uuid, field_name",
    )?;
    let mut out: HashMap<Uuid, Vec<(String, Vec<u8>)>> = HashMap::new();
    let rows = stmt.query_map([], |row| {
        Ok((
            parse_uuid_col(row, 0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for r in rows {
        let (uuid, name, blob) = r?;
        out.entry(uuid).or_default().push((name, blob));
    }
    Ok(out)
}

type NonProtectedCustomFieldRows = HashMap<Uuid, Vec<(String, String)>>;

fn load_non_protected_custom_fields(
    conn: &Connection,
) -> Result<NonProtectedCustomFieldRows, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT entry_uuid, field_name, value FROM entry_custom_field \
         ORDER BY entry_uuid, field_name",
    )?;
    let mut out: NonProtectedCustomFieldRows = HashMap::new();
    let rows = stmt.query_map([], |row| {
        Ok((
            parse_uuid_col(row, 0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for r in rows {
        let (uuid, name, value) = r?;
        out.entry(uuid).or_default().push((name, value));
    }
    Ok(out)
}

struct AttachmentRow {
    name: String,
    sha256: [u8; 32],
    bytes: Vec<u8>,
}

fn load_attachments(conn: &Connection) -> Result<HashMap<Uuid, Vec<AttachmentRow>>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT ea.entry_uuid, ea.attachment_name, ea.blob_sha256, ab.bytes \
         FROM entry_attachment ea \
         JOIN attachment_blob ab ON ab.sha256 = ea.blob_sha256 \
         ORDER BY ea.entry_uuid, ea.attachment_name",
    )?;
    let mut out: HashMap<Uuid, Vec<AttachmentRow>> = HashMap::new();
    let rows = stmt.query_map([], |row| {
        let entry_uuid = parse_uuid_col(row, 0)?;
        let name: String = row.get(1)?;
        let sha_bytes: Vec<u8> = row.get(2)?;
        let bytes: Vec<u8> = row.get(3)?;
        Ok((entry_uuid, name, sha_bytes, bytes))
    })?;
    for r in rows {
        let (entry_uuid, name, sha_vec, bytes) = r?;
        let sha: [u8; 32] = sha_vec.as_slice().try_into().map_err(|_| {
            EngineError::Projection(ProjectionError::SchemaInvariant(format!(
                "attachment_blob.sha256 not 32 bytes for entry {entry_uuid}",
            )))
        })?;
        out.entry(entry_uuid).or_default().push(AttachmentRow {
            name,
            sha256: sha,
            bytes,
        });
    }
    Ok(out)
}

fn load_tags(conn: &Connection) -> Result<HashMap<Uuid, Vec<String>>, EngineError> {
    // Order by tag.name so projection is deterministic. Ingest doesn't
    // promise to preserve original tag order; sorted alphabetical is
    // the only stable choice that survives upsert ordering.
    let mut stmt = conn.prepare(
        "SELECT et.entry_uuid, t.name FROM entry_tag et \
         JOIN tag t ON t.id = et.tag_id \
         ORDER BY et.entry_uuid, t.name",
    )?;
    let mut out: HashMap<Uuid, Vec<String>> = HashMap::new();
    let rows = stmt.query_map([], |row| {
        Ok((parse_uuid_col(row, 0)?, row.get::<_, String>(1)?))
    })?;
    for r in rows {
        let (uuid, name) = r?;
        out.entry(uuid).or_default().push(name);
    }
    Ok(out)
}

type EntryCustomDataRows = HashMap<Uuid, Vec<(String, String, Option<i64>)>>;

fn load_entry_custom_data(conn: &Connection) -> Result<EntryCustomDataRows, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT entry_uuid, key, value, last_modified_at FROM entry_custom_data \
         ORDER BY entry_uuid, key",
    )?;
    let mut out: EntryCustomDataRows = HashMap::new();
    let rows = stmt.query_map([], |row| {
        Ok((
            parse_uuid_col(row, 0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<i64>>(3)?,
        ))
    })?;
    for r in rows {
        let (uuid, key, value, last_mod) = r?;
        out.entry(uuid).or_default().push((key, value, last_mod));
    }
    Ok(out)
}

fn load_history(conn: &Connection) -> Result<HashMap<Uuid, Vec<HistorySnapshot>>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT entry_uuid, snapshot_json FROM entry_history ORDER BY entry_uuid, history_index",
    )?;
    let mut out: HashMap<Uuid, Vec<HistorySnapshot>> = HashMap::new();
    let rows = stmt.query_map([], |row| {
        Ok((parse_uuid_col(row, 0)?, row.get::<_, String>(1)?))
    })?;
    for r in rows {
        let (uuid, json) = r?;
        let snap: HistorySnapshot = serde_json::from_str(&json)
            .map_err(|e| EngineError::Projection(ProjectionError::Json(e)))?;
        out.entry(uuid).or_default().push(snap);
    }
    Ok(out)
}

// ───────────────────────── history shape ─────────────────────────

/// Deserialise side of the shape written by
/// `crate::ingest::HistorySnapshot`.
#[derive(Deserialize)]
struct HistorySnapshot {
    title: String,
    username: String,
    url: String,
    notes: String,
    password: String,
    tags: Vec<String>,
    created_at: i64,
    modified_at: i64,
    accessed_at: i64,
    expires_at: Option<i64>,
    custom_fields: HashMap<String, HistoryCustomField>,
    /// Per-record `<CustomData>`. Pre-shape rows (history JSON written
    /// before migration 0006 shipped) deserialise as an empty list.
    #[serde(default)]
    custom_data: Vec<HistoryCustomDataItem>,
}

#[derive(Deserialize)]
struct HistoryCustomField {
    value: String,
    protected: bool,
}

#[derive(Deserialize)]
struct HistoryCustomDataItem {
    key: String,
    value: String,
    #[serde(default)]
    last_modified_at: Option<i64>,
}

fn snapshot_to_entry(
    entry_uuid: Uuid,
    snap: &HistorySnapshot,
    session_key: &SessionKey,
) -> Result<Entry, EngineError> {
    // History snapshots reuse the live entry's uuid in KeePass — they
    // are *prior versions of the same record*, not new records — so
    // we propagate the same UUID into the snapshot Entry.
    let mut e = Entry::empty(EntryId(entry_uuid));
    e.title.clone_from(&snap.title);
    e.username.clone_from(&snap.username);
    e.url.clone_from(&snap.url);
    e.notes.clone_from(&snap.notes);
    e.password = unwrap_b64_field(entry_uuid, "Password", &snap.password, session_key)?;
    e.tags.clone_from(&snap.tags);
    e.times = build_times(
        snap.created_at,
        snap.modified_at,
        snap.accessed_at,
        snap.expires_at,
    );
    for (k, v) in &snap.custom_fields {
        let plaintext = if v.protected {
            unwrap_b64_field(entry_uuid, k, &v.value, session_key)?
        } else {
            v.value.clone()
        };
        e.custom_fields
            .push(CustomField::new(k.clone(), plaintext, v.protected));
    }
    // Per-record `<CustomData>` (migration 0006 extended the JSON
    // shape). Carries the parked-conflict marker
    // (`keys.field_conflict.v1`) for the resolver UI to key off.
    for cd in &snap.custom_data {
        e.custom_data.push(CustomDataItem::new(
            cd.key.clone(),
            cd.value.clone(),
            cd.last_modified_at.and_then(ms_to_dt),
        ));
    }
    // History entries themselves carry no nested history, no
    // attachments — those aren't part of the snapshot JSON.
    Ok(e)
}

/// Base64-decode + AES-GCM-open a wrapped history field. Errors bubble
/// up as [`ProjectionError::Unwrap`] with enough context to identify the
/// failing entry + field name.
fn unwrap_b64_field(
    entry_uuid: Uuid,
    field_name: &str,
    b64: &str,
    session_key: &SessionKey,
) -> Result<String, EngineError> {
    use base64::Engine as _;
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| {
            EngineError::Projection(ProjectionError::Unwrap(format!(
                "entry {entry_uuid} history field {field_name}: base64 decode: {e}",
            )))
        })?;
    let plaintext = open_with_key(session_key, &wrapped).map_err(|e| {
        EngineError::Projection(ProjectionError::Unwrap(format!(
            "entry {entry_uuid} history field {field_name}: {e}",
        )))
    })?;
    String::from_utf8(plaintext).map_err(|e| {
        EngineError::Projection(ProjectionError::Unwrap(format!(
            "entry {entry_uuid} history field {field_name}: non-utf8 plaintext: {e}",
        )))
    })
}

// ───────────────────────── helpers ─────────────────────────

fn parse_uuid_col(row: &rusqlite::Row<'_>, idx: usize) -> Result<Uuid, rusqlite::Error> {
    let s: String = row.get(idx)?;
    Uuid::parse_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn ms_to_dt(ms: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_millis_opt(ms).single()
}

/// Build a [`Timestamps`] from the columns we persist. Schema-wise
/// `created_at` and `modified_at` are NOT NULL — we mirror their value
/// straight into `Some(...)`. The `expires` bool is `true` iff
/// `expires_at` is `Some`. `last_access_time` mirrors `accessed_at`.
/// `location_changed` is not persisted; left `None`.
fn build_times(
    created_at: i64,
    modified_at: i64,
    accessed_at: i64,
    expires_at: Option<i64>,
) -> Timestamps {
    let mut t = Timestamps::default();
    t.creation_time = ms_to_dt(created_at);
    t.last_modification_time = ms_to_dt(modified_at);
    t.last_access_time = ms_to_dt(accessed_at);
    t.expiry_time = expires_at.and_then(ms_to_dt);
    t.expires = expires_at.is_some();
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_times_marks_expires_when_expires_at_set() {
        let t = build_times(1_000, 2_000, 3_000, Some(4_000));
        assert!(t.expires);
        assert_eq!(t.expiry_time, ms_to_dt(4_000));
        assert_eq!(t.creation_time, ms_to_dt(1_000));
    }

    #[test]
    fn build_times_marks_no_expiry_when_none() {
        let t = build_times(1_000, 2_000, 3_000, None);
        assert!(!t.expires);
        assert!(t.expiry_time.is_none());
    }
}
