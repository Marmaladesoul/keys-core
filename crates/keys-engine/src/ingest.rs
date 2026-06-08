//! `KDBX` → `SQLite` ingest path.
//!
//! Walks an unlocked [`Kdbx`] in-memory tree and INSERTs the entire
//! contents into the engine's `SQLite` mirror in a single transaction.
//! Idempotent: every call DELETEs the vault tables before writing, so
//! re-ingest produces the same final state regardless of what was
//! there. Schema (migrations, settings) is preserved.
//!
//! Subsequent tasks (Phase 2.4 projection, 2.5 serialise) close the
//! round-trip. Mutation semantics — single-row edits without rewriting
//! every table — land in Phase 4.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{Entry, Group, GroupId, Vault};
use keepass_core::protector::{FieldProtector, SessionKey, seal_with_key};
use keepass_merge::{Classification, Granularity, classify, parse_conflict_resolutions};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{EngineError, IngestError};
use crate::fingerprint;
use crate::meta;
use crate::strength;
use crate::totp;

/// Canonical KDBX field name for an entry's password slot.
///
/// Used both as the `field_name` value for `entry_protected` rows
/// carrying the canonical password and as the historic-snapshot JSON
/// key.
const PASSWORD_FIELD: &str = "Password";

/// Outcome of an ingest pass. Captured uuids let the engine fire a
/// single combined `GroupsAdded` + `EntriesAdded` pair of events after
/// the transaction commits.
#[derive(Debug, Default)]
pub(crate) struct IngestOutcome {
    pub group_uuids: Vec<Uuid>,
    pub entry_uuids: Vec<Uuid>,
}

/// Top-level ingest entry point. Holds a single transaction across the
/// entire walk so a failure rolls back cleanly.
pub(crate) fn ingest(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    kdbx: &Kdbx<Unlocked>,
) -> Result<IngestOutcome, EngineError> {
    // Unwrap the in-memory wrap layer once: every Entry from this
    // Vault carries plaintext in `password` and `custom_fields[i].value`
    // for the duration of the call. Drop it as soon as the walk is
    // done.
    let vault = kdbx
        .vault_with_unwrapped_protected()
        .map_err(|e| EngineError::Ingest(IngestError::Kdbx(e.to_string())))?;
    let header = kdbx.outer_header();
    let cipher_id = *header.cipher_id.0.as_bytes();
    let kdf_params = header.kdf_parameters.as_deref().map(<[u8]>::to_vec);
    let transform_rounds = header.transform_rounds;
    ingest_vault_with_header(
        conn,
        fingerprint_key,
        protector,
        &vault,
        Some(&HeaderFacts {
            cipher_id,
            kdf_params,
            transform_rounds,
        }),
    )
}

/// Outer-header facts the engine persists into `meta.*` setting rows
/// so it doesn't have to hold a live [`Kdbx`] handle to surface them
/// via [`crate::Engine::database_metadata`].
struct HeaderFacts {
    cipher_id: [u8; 16],
    kdf_params: Option<Vec<u8>>,
    transform_rounds: Option<u64>,
}

/// Re-ingest a pre-unwrapped [`Vault`] without going through a
/// [`Kdbx`] envelope. Used by paths that have already mutated the
/// in-memory vault (e.g. `clear_parked_conflict_marker`) and don't
/// want to round-trip through KDBX encrypt + decrypt just to feed
/// `ingest`.
///
/// The outer-header facts (cipher / KDF / transform-rounds) carried
/// in `meta.*` setting rows are left as the existing ingest wrote
/// them; the database envelope hasn't changed, only its decoded
/// content.
pub(crate) fn ingest_vault(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    vault: &Vault,
) -> Result<IngestOutcome, EngineError> {
    ingest_vault_with_header(conn, fingerprint_key, protector, vault, None)
}

fn ingest_vault_with_header(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    vault: &Vault,
    header_facts: Option<&HeaderFacts>,
) -> Result<IngestOutcome, EngineError> {
    // One session-key fetch per ingest call. Same discipline as the
    // keepass-core wrap pass.
    let session_key = protector
        .acquire_session_key()
        .map_err(|e| EngineError::Ingest(IngestError::SessionKey(e.to_string())))?;

    let recycle_bin_uuid = vault.meta.recycle_bin_uuid;
    let recycle_bin_enabled = vault.meta.recycle_bin_enabled;

    let tx = conn.transaction()?;
    clear_vault_tables(&tx)?;
    meta::clear_meta_tables(&tx)?;

    // Persist the full `Meta` block and `Vault::deleted_objects`. After
    // this, SQLite is a complete representation of the vault — the save
    // path no longer has to splice anything from a live `Kdbx` handle.
    meta::write_meta(&tx, &vault.meta)?;
    meta::write_deleted_objects(&tx, &vault.deleted_objects)?;

    // Persist the three outer-header facts the engine's
    // `database_metadata` accessor needs to render the Info-tab cipher /
    // KDF strings. Not part of `Meta` (they live on the encrypted
    // envelope, not the XML payload), but persisted as `meta.*` setting
    // rows so the engine doesn't have to hold a live `Kdbx` handle to
    // surface them.
    //
    // Header-facts are absent on the [`ingest_vault`] code path —
    // that path mutates the in-memory vault without re-wrapping the
    // envelope, so the existing rows (written by the originating
    // ingest call) remain accurate.
    if let Some(facts) = header_facts {
        meta::write_kdbx_outer_header_facts(
            &tx,
            facts.cipher_id,
            facts.kdf_params.as_deref(),
            facts.transform_rounds,
        )?;
    }

    // Persist `Meta::recycle_bin_enabled` explicitly. The `is_recycle_bin`
    // column on `group` can only tell us "enabled" when a bin group
    // already exists; KeePassXC happily ships vaults with
    // `enabled=true, recycle_bin_uuid=None` (the bin group is lazily
    // created on first soft-delete), and without this row that state
    // would round-trip as `enabled=false`. Projection consults this row
    // first and falls back to the derived behaviour for legacy DBs
    // without it. Encoded as a 1-byte BLOB (`[0]` / `[1]`) to match the
    // `setting.value BLOB` convention already used by `fingerprint_key`.
    let enabled_blob: [u8; 1] = [u8::from(recycle_bin_enabled)];
    tx.execute(
        "INSERT OR REPLACE INTO setting(key, value) VALUES ('meta.recycle_bin_enabled', ?1)",
        params![&enabled_blob[..]],
    )?;

    let mut outcome = IngestOutcome::default();

    // Walk groups first so entries' FK references resolve. The root
    // group has no parent and therefore no meaningful sibling
    // position; we record it with `sort_order = 0` for consistency.
    walk_groups(&tx, &vault.root, None, 0, recycle_bin_uuid, &mut outcome)?;

    // Index the binary pool by ref_id so attachment lookups are O(1).
    // KDBX `ref_id` is the index into `Vault::binaries`.
    let binaries: Vec<&[u8]> = vault.binaries.iter().map(|b| b.data.as_slice()).collect();

    walk_entries(
        &tx,
        vault,
        &vault.root,
        recycle_bin_uuid,
        false,
        fingerprint_key,
        &session_key,
        &binaries,
        &mut outcome,
    )?;

    tx.commit()?;
    Ok(outcome)
}

/// `DELETE FROM` every vault-content table. Schema and migration rows
/// stay. Order respects foreign-key references — children before
/// parents.
fn clear_vault_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
    // Child tables first.
    conn.execute("DELETE FROM entry_tag", [])?;
    conn.execute("DELETE FROM entry_attachment", [])?;
    conn.execute("DELETE FROM entry_history", [])?;
    conn.execute("DELETE FROM entry_protected", [])?;
    conn.execute("DELETE FROM entry_custom_field", [])?;
    conn.execute("DELETE FROM entry_custom_data", [])?;
    conn.execute("DELETE FROM entry", [])?;
    conn.execute("DELETE FROM tag", [])?;
    conn.execute("DELETE FROM attachment_blob", [])?;
    // Group goes last; entries FK to it.
    conn.execute("DELETE FROM \"group\"", [])?;
    Ok(())
}

/// Recursive group walk. `parent_uuid = None` for the root group.
///
/// `sort_order` is the position of `group` within its parent's
/// `groups` vec. KDBX XML stores child groups positionally; we
/// preserve that order so a user's manual drag-reorder survives
/// save/load.
fn walk_groups(
    conn: &Connection,
    group: &Group,
    parent_uuid: Option<Uuid>,
    sort_order: u32,
    recycle_bin_uuid: Option<GroupId>,
    outcome: &mut IngestOutcome,
) -> Result<(), rusqlite::Error> {
    let uuid_str = group.id.0.to_string();
    let parent_str = parent_uuid.as_ref().map(Uuid::to_string);
    let is_recycle_bin = recycle_bin_uuid.is_some_and(|rb| rb == group.id);

    conn.execute(
        "INSERT INTO \"group\" (\
            uuid, parent_uuid, name, icon_index, icon_custom_uuid, notes, \
            created_at, modified_at, expires_at, is_recycle_bin, sort_order\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            uuid_str,
            parent_str,
            group.name,
            i64::from(group.icon_id),
            group.custom_icon_uuid.map(|u| u.to_string()),
            group.notes,
            dt_to_ms(group.times.creation_time),
            dt_to_ms(group.times.last_modification_time),
            expiry_ms(&group.times),
            i64::from(is_recycle_bin),
            i64::from(sort_order),
        ],
    )?;

    outcome.group_uuids.push(group.id.0);
    for (idx, child) in group.groups.iter().enumerate() {
        let child_pos = u32::try_from(idx).unwrap_or(u32::MAX);
        walk_groups(
            conn,
            child,
            Some(group.id.0),
            child_pos,
            recycle_bin_uuid,
            outcome,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_entries(
    conn: &Connection,
    vault: &Vault,
    group: &Group,
    recycle_bin_uuid: Option<GroupId>,
    is_under_recycle_bin: bool,
    fingerprint_key: &[u8; 32],
    session_key: &SessionKey,
    binaries: &[&[u8]],
    outcome: &mut IngestOutcome,
) -> Result<(), EngineError> {
    let group_is_recycle_bin = recycle_bin_uuid.is_some_and(|rb| rb == group.id);
    let in_recycle_bin = is_under_recycle_bin || group_is_recycle_bin;

    for entry in &group.entries {
        insert_entry(
            conn,
            vault,
            entry,
            group.id,
            in_recycle_bin,
            fingerprint_key,
            session_key,
            binaries,
        )?;
        outcome.entry_uuids.push(entry.id.0);
    }

    for child in &group.groups {
        walk_entries(
            conn,
            vault,
            child,
            recycle_bin_uuid,
            in_recycle_bin,
            fingerprint_key,
            session_key,
            binaries,
            outcome,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn insert_entry(
    conn: &Connection,
    vault: &Vault,
    entry: &Entry,
    group_id: GroupId,
    is_recycled: bool,
    fingerprint_key: &[u8; 32],
    session_key: &SessionKey,
    binaries: &[&[u8]],
) -> Result<(), EngineError> {
    let entry_uuid = entry.id.0.to_string();
    let group_uuid = group_id.0.to_string();

    // Pull canonical Password plaintext off the entry. Empty string
    // when the entry has no password (KDBX models that as the empty
    // value, so we keep that semantics through to SQLite).
    let password_plain = entry.password.as_bytes();
    let strength_result = strength::strength(&entry.password);
    let bucket = strength_result.bucket as u8;
    let entropy = strength_result.entropy_bits;
    let pw_fingerprint: [u8; 32] = if entry.password.is_empty() {
        // No password → no meaningful fingerprint. Leaving the column
        // NULL preserves "duplicate detection ignores empty passwords",
        // which matches the Swift StrengthCache behaviour.
        [0u8; 32]
    } else {
        fingerprint::fingerprint(fingerprint_key, password_plain)
    };
    let pw_fingerprint_param: Option<&[u8]> = if entry.password.is_empty() {
        None
    } else {
        Some(&pw_fingerprint)
    };

    let url_host = parse_host(&entry.url);
    let has_totp = totp::url_is_otpauth(&entry.url)
        || entry
            .custom_fields
            .iter()
            .any(|cf| totp::is_totp_field(&cf.key));

    let created_at = dt_to_ms_required(entry.times.creation_time);
    let modified_at = dt_to_ms_required(entry.times.last_modification_time);
    let accessed_at = dt_to_ms_required(entry.times.last_access_time);
    // `last_used_at` doesn't have a dedicated KDBX field. The
    // accessed-time on an entry is the closest proxy — clients update
    // it on AutoFill / copy-password — so we mirror that into
    // `last_used_at` whenever it's non-default. A zero / missing
    // accessed-time means "never used" → NULL column.
    let last_used_at: Option<i64> = entry.times.last_access_time.map(|d| d.timestamp_millis());

    conn.execute(
        "INSERT INTO entry (\
            uuid, group_uuid, title, username, url, url_host, notes, \
            icon_index, icon_custom_uuid, created_at, modified_at, \
            accessed_at, last_used_at, expires_at, \
            password_strength_bucket, password_entropy, password_fingerprint, \
            is_recycled, has_totp\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        params![
            entry_uuid,
            group_uuid,
            entry.title,
            entry.username,
            entry.url,
            url_host,
            entry.notes,
            i64::from(entry.icon_id),
            entry.custom_icon_uuid.map(|u| u.to_string()),
            created_at,
            modified_at,
            accessed_at,
            last_used_at,
            expiry_ms(&entry.times),
            i64::from(bucket),
            entropy,
            pw_fingerprint_param,
            i64::from(is_recycled),
            i64::from(has_totp),
        ],
    )?;

    // Canonical Password slot. Always written (even empty) so the
    // reveal path has a deterministic row to look up.
    let wrapped_password = seal_with_key(session_key, password_plain)
        .map_err(|e| EngineError::Ingest(IngestError::Wrap(e.to_string())))?;
    conn.execute(
        "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
         VALUES (?1, ?2, ?3)",
        params![entry_uuid, PASSWORD_FIELD, wrapped_password],
    )?;

    // Custom fields. Protected ones go into entry_protected; non-
    // protected ones go into entry_custom_field (migration 0002). A
    // custom field accidentally named "Password" is dropped rather
    // than colliding with the canonical Password slot.
    for cf in &entry.custom_fields {
        if cf.protected {
            // Avoid colliding with the canonical Password slot if a
            // custom field happens to be named "Password" — extremely
            // unlikely but easy to handle by skipping.
            if cf.key == PASSWORD_FIELD {
                continue;
            }
            let wrapped = seal_with_key(session_key, cf.value.as_bytes())
                .map_err(|e| EngineError::Ingest(IngestError::Wrap(e.to_string())))?;
            conn.execute(
                "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
                 VALUES (?1, ?2, ?3)",
                params![entry_uuid, cf.key, wrapped],
            )?;
        } else {
            insert_non_protected_custom_field(conn, &entry_uuid, &cf.key, &cf.value)?;
        }
    }

    // Per-entry `<CustomData>`. Migration 0006. Each `(key, value)`
    // pair round-trips verbatim — needed for Keys-namespaced
    // extensions like `keys.history_tombstones.v1` that must survive a
    // reconcile→project→save cycle.
    for cd in &entry.custom_data {
        conn.execute(
            "INSERT INTO entry_custom_data (entry_uuid, key, value, last_modified_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                entry_uuid,
                cd.key,
                cd.value,
                cd.last_modified.map(|d| d.timestamp_millis()),
            ],
        )?;
    }

    // Tags. `Entry::tags` is already a deduplicated Vec<String> per
    // the keepass-core decoder; we still trim and skip empties for
    // safety against hand-rolled vaults.
    for raw in &entry.tags {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        let tag_id = upsert_tag(conn, name)?;
        conn.execute(
            "INSERT OR IGNORE INTO entry_tag (entry_uuid, tag_id) VALUES (?1, ?2)",
            params![entry_uuid, tag_id],
        )?;
    }

    // Attachments. Resolve ref_id → bytes via the binary pool index.
    for att in &entry.attachments {
        let Some(bytes) = binaries.get(att.ref_id as usize).copied() else {
            // Dangling ref_id — skip rather than fail. A future audit
            // task can decide if this should be a hard error.
            continue;
        };
        insert_attachment(conn, &entry_uuid, &att.name, bytes)?;
    }

    // History snapshots. KDBX stores oldest-first in `Entry::history`
    // (per the decoder doc); we use the slice index as
    // `history_index` directly.
    for (idx, hist) in entry.history.iter().enumerate() {
        let snapshot = HistorySnapshot::from_entry(hist, session_key, binaries)?;
        let json = serde_json::to_string(&snapshot)
            .map_err(|e| EngineError::Ingest(IngestError::Json(e)))?;
        conn.execute(
            "INSERT INTO entry_history (entry_uuid, history_index, snapshot_json) \
             VALUES (?1, ?2, ?3)",
            params![entry_uuid, i64::try_from(idx).unwrap_or(i64::MAX), json],
        )?;
    }

    // Suppress unused warnings for vault when history snapshots don't
    // need to consult the meta — keeps the parameter list a single
    // shape across future revisions.
    let _ = vault;

    Ok(())
}

/// Insert (or no-op) a tag name and return its row id.
fn upsert_tag(conn: &Connection, name: &str) -> Result<i64, rusqlite::Error> {
    conn.execute(
        "INSERT OR IGNORE INTO tag (name) VALUES (?1)",
        params![name],
    )?;
    conn.query_row("SELECT id FROM tag WHERE name = ?1", params![name], |r| {
        r.get::<_, i64>(0)
    })
}

/// Insert an attachment blob (content-addressed by SHA-256) plus its
/// `entry_attachment` link row.
fn insert_attachment(
    conn: &Connection,
    entry_uuid: &str,
    attachment_name: &str,
    bytes: &[u8],
) -> Result<(), rusqlite::Error> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sha = hasher.finalize();
    let sha_bytes: &[u8] = sha.as_slice();
    let size_i64 = i64::try_from(bytes.len()).unwrap_or(i64::MAX);

    conn.execute(
        "INSERT OR IGNORE INTO attachment_blob (sha256, bytes, size) VALUES (?1, ?2, ?3)",
        params![sha_bytes, bytes, size_i64],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO entry_attachment (entry_uuid, attachment_name, blob_sha256) \
         VALUES (?1, ?2, ?3)",
        params![entry_uuid, attachment_name, sha_bytes],
    )?;
    Ok(())
}

/// Persist a single non-protected custom field via the
/// `entry_custom_field` table (migration 0002). Values are stored as
/// `TEXT` — the KDBX wire format models custom fields as XML strings,
/// so TEXT is the natural fit and keeps direct-SQL inspection readable.
fn insert_non_protected_custom_field(
    conn: &Connection,
    entry_uuid: &str,
    field_name: &str,
    value: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO entry_custom_field (entry_uuid, field_name, value) \
         VALUES (?1, ?2, ?3)",
        params![entry_uuid, field_name, value],
    )?;
    Ok(())
}

/// Parse the host out of a URL. Lowercased for the indexed
/// `url_host` column (`AutoFill` lookups are case-insensitive).
/// Returns the empty string when the input isn't a parseable URL or
/// has no host — matching the schema's "NOT NULL DEFAULT ''"
/// expectation rather than introducing a NULL.
fn parse_host(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    match url::Url::parse(url) {
        Ok(parsed) => parsed
            .host_str()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

fn dt_to_ms(dt: Option<DateTime<Utc>>) -> i64 {
    dt.map_or(0, |d| d.timestamp_millis())
}

fn dt_to_ms_required(dt: Option<DateTime<Utc>>) -> i64 {
    dt_to_ms(dt)
}

fn expiry_ms(times: &keepass_core::model::Timestamps) -> Option<i64> {
    if times.expires {
        times.expiry_time.map(|d| d.timestamp_millis())
    } else {
        None
    }
}

/// JSON shape stored in `entry_history.snapshot_json`.
///
/// Protected fields (the canonical `password` slot and any custom field
/// with `protected: true`) are AES-GCM-sealed under the same session
/// key used for the live `entry_protected.wrapped_blob` rows, then
/// base64-encoded so the bytes round-trip through `TEXT`. This keeps
/// history symmetric with live entries — plaintext never appears in
/// DB-stored JSON. Non-protected custom fields keep their plaintext in
/// `value`; the `protected` flag tells the reveal/projection side
/// which interpretation applies.
///
/// Wire shape (per snapshot):
///
/// ```json
/// {
///   "title": "...", "username": "...", "url": "...",
///   "url_host": "...", "notes": "...",
///   "password": "<base64(nonce|ct|tag)>",
///   "tags": [...],
///   "created_at": ..., "modified_at": ..., "accessed_at": ...,
///   "last_used_at": ..., "expires_at": ...,
///   "icon_index": 0, "icon_custom_uuid": null,
///   "password_strength_bucket": 3, "password_entropy": 42.5,
///   "attachments": [
///     { "name": "doc.txt", "size": 1234, "sha256_hex": "<hex>" }
///   ],
///   "custom_fields": {
///     "Token":   { "value": "<base64(nonce|ct|tag)>", "protected": true  },
///     "Website": { "value": "example.com",            "protected": false }
///   }
/// }
/// ```
///
/// Backwards compat: every field added after the initial shipped shape
/// is `#[serde(default)]` on the read side ([`HistorySnapshotRead`]) so
/// older JSON deserialises cleanly; on the write side every newly-
/// snapshotted history row carries the full payload.
#[derive(Serialize)]
struct HistorySnapshot<'a> {
    title: &'a str,
    username: &'a str,
    url: &'a str,
    url_host: String,
    notes: &'a str,
    /// Base64 of `seal_with_key(session_key, password_plaintext)`.
    password: String,
    tags: &'a [String],
    created_at: i64,
    modified_at: i64,
    accessed_at: i64,
    last_used_at: Option<i64>,
    expires_at: Option<i64>,
    icon_index: u32,
    icon_custom_uuid: Option<String>,
    password_strength_bucket: Option<u8>,
    password_entropy: Option<f64>,
    attachments: Vec<HistoryAttachment<'a>>,
    custom_fields: HashMap<&'a str, HistoryCustomField>,
    /// Per-record `<CustomData>`. Round-trips the parked-conflict
    /// marker (`keys.field_conflict.v1`) and any other client-specific
    /// metadata attached to a history snapshot. Pre-shape rows
    /// deserialise as an empty list via `#[serde(default)]` on the
    /// read side.
    custom_data: Vec<HistoryCustomDataItem<'a>>,
}

#[derive(Serialize)]
struct HistoryAttachment<'a> {
    name: &'a str,
    size: u64,
    /// Hex-encoded SHA-256 of the attachment bytes. Lets the read side
    /// resolve a snapshot's attachment to the content-addressed blob in
    /// `attachment_blob` without relying on the live `entry_attachment`
    /// link row (which may have been overwritten by a later edit).
    ///
    /// Newly added field — older `snapshot_json` rows have no
    /// `sha256_hex`, so the read-side mirror marks it `#[serde(default)]`.
    /// Pre-widening rows surface an empty string here; lookups against
    /// `attachment_blob` skip those, and the caller sees `NotFound`.
    sha256_hex: String,
}

#[derive(Serialize)]
struct HistoryCustomDataItem<'a> {
    key: &'a str,
    value: &'a str,
    /// Milliseconds since the Unix epoch (UTC). `None` matches the
    /// keepass-core model when KDBX3 writers omit `<LastModificationTime>`.
    last_modified_at: Option<i64>,
}

#[derive(Serialize)]
struct HistoryCustomField {
    /// For `protected = true`, base64 of `seal_with_key(...)`; for
    /// `protected = false`, the plaintext value.
    value: String,
    protected: bool,
}

impl<'a> HistorySnapshot<'a> {
    fn from_entry(
        entry: &'a Entry,
        session_key: &SessionKey,
        binaries: &[&[u8]],
    ) -> Result<Self, EngineError> {
        let mut custom_fields: HashMap<&'a str, HistoryCustomField> = HashMap::new();
        for cf in &entry.custom_fields {
            let value = if cf.protected {
                let wrapped = seal_with_key(session_key, cf.value.as_bytes())
                    .map_err(|e| EngineError::Ingest(IngestError::Wrap(e.to_string())))?;
                b64_encode(&wrapped)
            } else {
                cf.value.clone()
            };
            custom_fields.insert(
                cf.key.as_str(),
                HistoryCustomField {
                    value,
                    protected: cf.protected,
                },
            );
        }
        let wrapped_password = seal_with_key(session_key, entry.password.as_bytes())
            .map_err(|e| EngineError::Ingest(IngestError::Wrap(e.to_string())))?;
        let strength_result = strength::strength(&entry.password);
        let (bucket, entropy) = if entry.password.is_empty() {
            (None, None)
        } else {
            (
                Some(strength_result.bucket as u8),
                Some(strength_result.entropy_bits),
            )
        };
        let attachments: Vec<HistoryAttachment<'a>> = entry
            .attachments
            .iter()
            .map(|att| {
                let bytes = binaries.get(att.ref_id as usize).copied().unwrap_or(&[]);
                let size = u64::try_from(bytes.len()).unwrap_or(0);
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                let sha = hasher.finalize();
                let sha256_hex = sha.iter().fold(String::with_capacity(64), |mut acc, b| {
                    use std::fmt::Write as _;
                    let _ = write!(&mut acc, "{b:02x}");
                    acc
                });
                HistoryAttachment {
                    name: att.name.as_str(),
                    size,
                    sha256_hex,
                }
            })
            .collect();
        Ok(Self {
            title: &entry.title,
            username: &entry.username,
            url: &entry.url,
            url_host: parse_host(&entry.url),
            notes: &entry.notes,
            password: b64_encode(&wrapped_password),
            tags: &entry.tags,
            created_at: dt_to_ms_required(entry.times.creation_time),
            modified_at: dt_to_ms_required(entry.times.last_modification_time),
            accessed_at: dt_to_ms_required(entry.times.last_access_time),
            last_used_at: entry.times.last_access_time.map(|d| d.timestamp_millis()),
            expires_at: expiry_ms(&entry.times),
            icon_index: entry.icon_id,
            icon_custom_uuid: entry.custom_icon_uuid.map(|u| u.to_string()),
            password_strength_bucket: bucket,
            password_entropy: entropy,
            attachments,
            custom_fields,
            custom_data: entry
                .custom_data
                .iter()
                .map(|cd| HistoryCustomDataItem {
                    key: cd.key.as_str(),
                    value: cd.value.as_str(),
                    last_modified_at: cd.last_modified.map(|d| d.timestamp_millis()),
                })
                .collect(),
        })
    }
}

/// Standard base64 with padding — matches what `reveal` and `projection`
/// pass to the decoder. No URL-safe variant; the bytes live inside a JSON
/// string, never in a URL.
fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ───────────────────────────────────────────────────────────────────────────
// Owner-tagged peer ingest — the multi-peer owner-rows store (Phase 2).
//
// `ingest_peer` is the lazy-conflict counterpart to the eager-merge reconcile
// path. For each entry a peer holds that we also hold, it runs the
// keepass-merge `classify` brain (item granularity) and:
//   - InSync     → nothing diverged; clear any stale row for this (owner, entry).
//   - AutoMerged → advance our local entry to the merged value; clear the row.
//   - Conflict   → keep our local value (hold-open) and store the peer's value
//                  as an `owner`-keyed `conflict_*` row for the resolver.
//
// Phase 5b adds cross-peer DELETE reconciliation, applied symmetrically against
// each side's `<DeletedObjects>` tombstones (per sync-merge-strategies §4):
//   - A peer entry we don't hold but *did* delete is only resurrected if the
//     peer's copy post-dates our tombstone (edit-wins); otherwise it stays
//     deleted (no zombie).
//   - A local entry the peer no longer holds is removed when the peer
//     tombstoned it and we hadn't edited since; kept (edit-wins) otherwise.
//   - Both sides' tombstones are unioned (grow-only, earliest deletion time
//     wins) so deletions propagate onward — never against a uuid that is still
//     a live local object (a live record must not carry its own tombstone).
//
// It is purely additive: it writes only the `conflict_*` tables, the advanced /
// resurrected / removed local entries, and `meta_deleted_object`; it never
// calls `clear_vault_tables`. As of Phase 4 this is the live sync reconcile's
// ingest path (`reconcile::reconcile_with_disk_park_conflicts`).
// ───────────────────────────────────────────────────────────────────────────

/// Outcome of an `ingest_peer` pass.
///
/// The buckets let the caller decide save-vs-no-save (the loop-safety
/// contract): a non-empty [`Self::auto_merged`], [`Self::added`], **or**
/// [`Self::deleted`] means the local side changed and must be persisted; pure
/// conflicts / in-sync advance nothing locally, so no save (and thus no
/// fresh-nonce re-push) is needed.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct IngestPeerOutcome {
    /// Entries where the peer genuinely conflicts — a `conflict_*` row was
    /// written/refreshed for this `owner`. The badge candidates.
    pub conflicted: Vec<Uuid>,
    /// Entries advanced to a merged value (one-sided / non-overlapping peer
    /// edits), or restored from our own tombstone because the peer's copy
    /// post-dates our deletion (edit-wins resurrection, Phase 5b). The local
    /// side changed → the caller must persist.
    pub auto_merged: Vec<Uuid>,
    /// Peer-only entries the peer added that we didn't hold — inserted locally
    /// (present beats absent; an add is unambiguous). Includes edit-wins
    /// resurrections of entries we had deleted (the peer's copy is newer than
    /// our tombstone). The local side changed → the caller must persist.
    pub added: Vec<Uuid>,
    /// Local entries removed because the peer tombstoned them and we hadn't
    /// edited since (cross-peer delete propagation, Phase 5b). The local side
    /// changed → the caller must persist.
    pub deleted: Vec<Uuid>,
    /// Count of entries the peer agreed on outright — nothing written.
    pub in_sync: usize,
}

/// Ingest one peer's vault as owner-tagged conflict rows. See the module
/// section header for the per-entry classification. `local` is the engine's
/// projected vault (the source of truth for our side); `peer` is the peer
/// KDBX with protected fields unwrapped to plaintext for the call's duration.
/// `owner` is an opaque peer/device identifier the sync layer supplies; it is
/// the conflict-row key, so the same string must be used across that peer's
/// pulls for the refresh-in-place semantics to hold.
pub(crate) fn ingest_peer(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    owner: &str,
    local: &Vault,
    peer: &Vault,
) -> Result<IngestPeerOutcome, EngineError> {
    // One session-key fetch per call — same discipline as `ingest`.
    let session_key = protector
        .acquire_session_key()
        .map_err(|e| EngineError::Ingest(IngestError::SessionKey(e.to_string())))?;

    let local_by_uuid = index_entries(&local.root);
    let local_bin_refs: Vec<&[u8]> = local.binaries.iter().map(|b| b.data.as_slice()).collect();
    let peer_bin_refs: Vec<&[u8]> = peer.binaries.iter().map(|b| b.data.as_slice()).collect();

    // Cross-peer resolution adoption (design §5.3): a side carrying a
    // `keys.conflict_resolutions.v1` record for an entry has decided that
    // conflict. Presence-asymmetry tells us which side resolved — the record
    // travels with the resolver's vault, so the first sync after a resolution
    // has it on exactly one side.
    let peer_resolved = resolution_times(&peer.meta.custom_data);
    let local_resolved = resolution_times(&local.meta.custom_data);

    // Tombstone maps (Phase 5b). Deduplicated per uuid with the earliest
    // deletion time winning — the grow-only `<DeletedObjects>` merge rule.
    let peer_tomb = tombstone_map(&peer.deleted_objects);
    let local_tomb = tombstone_map(&local.deleted_objects);
    // Uuids the peer still holds live, so the local-side delete pass can tell a
    // shared entry from one the peer dropped.
    let peer_uuids: HashSet<Uuid> = collect_entries(&peer.root).iter().map(|e| e.id.0).collect();

    let mut outcome = IngestPeerOutcome::default();
    let tx = conn.transaction()?;

    for (peer_entry, peer_parent) in collect_entries_with_parent(&peer.root) {
        let uuid = peer_entry.id.0;
        let uuid_str = uuid.to_string();
        let Some(local_entry) = local_by_uuid.get(&uuid) else {
            // The peer holds an entry we don't. Either a peer-side ADD (we've
            // never seen it) or a RESURRECTION candidate (we deleted it). The
            // Phase 5b tombstone guard stops a stale peer from zombie-ing an
            // entry we intentionally deleted: re-add only when the peer's copy
            // post-dates our tombstone (edit-wins).
            if let Some(&our_deleted_at) = local_tomb.get(&uuid) {
                if !live_edit_wins(peer_entry.times.last_modification_time, our_deleted_at) {
                    // Our deletion is at least as recent as the peer's copy →
                    // keep it deleted, don't re-add. The peer learns our
                    // tombstone (it rides in our projection) and converges.
                    continue;
                }
                // Peer edited strictly after our delete → edit wins: resurrect.
                // Scrub our tombstone first so the restored entry never coexists
                // with it (a live entry + matching tombstone is re-deleted by
                // other KDBX clients — sync-merge-strategies §4).
                remove_tombstone(&tx, &uuid_str)?;
            }
            // Insert under the peer's parent group if we hold it, else the local
            // root (group-structure reconciliation — renames / moves / recycle
            // bin — is Phase 5d).
            let group_id = if group_exists(&tx, peer_parent)? {
                peer_parent
            } else {
                local.root.id
            };
            insert_entry(
                &tx,
                peer,
                peer_entry,
                group_id,
                false,
                fingerprint_key,
                &session_key,
                &peer_bin_refs,
            )?;
            outcome.added.push(uuid);
            continue;
        };
        match classify(
            local_entry,
            peer_entry,
            &local.binaries,
            &peer.binaries,
            // Field granularity: non-overlapping edits (different fields on each
            // side) auto-merge instead of parking the whole entry; only a
            // same-field clash is a held conflict. (Was Item — park any
            // divergence — the conservative choice while the sync transport was
            // unproven. Flip back to Granularity::Item if field auto-merge
            // misbehaves.)
            Granularity::Field,
        ) {
            Classification::InSync => {
                clear_conflict_rows(&tx, owner, &uuid_str)?;
                outcome.in_sync += 1;
            }
            Classification::AutoMerged { merged } => {
                advance_local_entry(
                    &tx,
                    local,
                    &merged,
                    fingerprint_key,
                    &session_key,
                    &local_bin_refs,
                )?;
                clear_conflict_rows(&tx, owner, &uuid_str)?;
                outcome.auto_merged.push(uuid);
            }
            Classification::Conflict { conflict } => {
                // Cross-peer resolution adoption (Phase 5a) before hold-open.
                // A resolution record is keyed by entry uuid, not by the resolved
                // values, so it must only settle the *one* divergence it was made
                // for. An edit on either side *after* the relevant `resolved_at`
                // is fresh intent that re-opens the conflict (design §5.3):
                //   - local edit after the PEER resolved  → don't adopt theirs;
                //   - peer  edit after WE   resolved      → don't suppress ours.
                // Missing the second guard let a stale local record permanently
                // mute every future conflict on that entry — and asymmetrically,
                // since only the resolver's vault carries the record (it no-ops
                // while the peer parks). Soak bug: a re-edited, previously-resolved
                // entry surfaced a conflict on one side only.
                let peer_resolved_at = peer_resolved.get(&uuid).copied();
                let local_resolved_at = local_resolved.get(&uuid).copied();
                let local_mtime = local_entry.times.last_modification_time;
                let peer_mtime = peer_entry.times.last_modification_time;
                let local_supersedes_peer = edited_after(local_mtime, peer_resolved_at);
                let peer_edited_since_local_res = edited_after(peer_mtime, local_resolved_at);
                let local_resolution_holds =
                    local_resolved_at.is_some() && !peer_edited_since_local_res;

                clear_conflict_rows(&tx, owner, &uuid_str)?;
                if local_resolution_holds {
                    // We resolved this exact conflict and the peer hasn't edited
                    // since → keep our value and leave the badge clear; the peer
                    // adopts our synced resolution record on its pull. Re-holding
                    // here would re-badge a conflict we already settled (the bug
                    // that made resolve-on-one fail to clear-on-all). Local
                    // unchanged → no save.
                } else if peer_resolved_at.is_some() && !local_supersedes_peer {
                    // The peer resolved this entry and we haven't (and our copy
                    // isn't a newer edit) → adopt the peer's chosen value:
                    // resolve-on-one ⇒ clears-on-all.
                    advance_local_entry(
                        &tx,
                        peer,
                        &conflict.remote,
                        fingerprint_key,
                        &session_key,
                        &peer_bin_refs,
                    )?;
                    outcome.auto_merged.push(uuid);
                } else {
                    // Genuine unresolved conflict (or our edit superseded the
                    // peer's resolution) → hold open: leave the local entry
                    // untouched and store the peer's value (the resolver's
                    // "theirs"), refreshed in place.
                    //
                    // KNOWN LIMITATION (deferred to Phase 5, by design —
                    // classify's scope is standard + custom fields + icon): the
                    // peer's NON-conflicting facets riding alongside this held
                    // conflict (tags, attachments, group placement) are neither
                    // folded onto local nor captured in the peer row. They are
                    // not lost (the peer keeps them); they reach this side once
                    // the conflict converges or Phase 5 (content pools / groups)
                    // lands. The eager-merge path folded them immediately —
                    // the accepted behavioural narrowing of the switch.
                    insert_conflict_entry(&tx, owner, &conflict.remote, &session_key)?;
                    outcome.conflicted.push(uuid);
                }
            }
            // `Classification` is `#[non_exhaustive]`; a future verdict variant
            // must be handled explicitly above. Until one exists, conservatively
            // do nothing for this entry — never silently advance (and thus
            // overwrite) the local side on a verdict we don't understand.
            _ => {}
        }
    }

    // Cross-peer DELETE propagation + tombstone union (Phase 5b, direction 1).
    reconcile_peer_deletes(&tx, &local_by_uuid, &peer_uuids, &peer_tomb, &mut outcome)?;

    tx.commit()?;
    Ok(outcome)
}

/// Phase 5b direction-1: reconcile local entries the peer no longer holds
/// against the peer's tombstones, then union both sides' `<DeletedObjects>`.
/// Mutates the local mirror inside `tx` and records propagated deletes in
/// `outcome.deleted`. See the module section header for the full rule set.
fn reconcile_peer_deletes(
    tx: &Connection,
    local_by_uuid: &HashMap<Uuid, &Entry>,
    peer_uuids: &HashSet<Uuid>,
    peer_tomb: &HashMap<Uuid, Option<DateTime<Utc>>>,
    outcome: &mut IngestPeerOutcome,
) -> Result<(), EngineError> {
    // A local entry the peer no longer holds may have been deleted there:
    //   - peer tombstoned it + we didn't edit after → propagate the delete
    //     (remove locally; the tombstone is unioned in below). A local change →
    //     drives the save.
    //   - peer tombstoned it + we edited after       → edit-vs-delete: keep
    //     local. The conservative default for a password manager — never
    //     silently drop a live edit. No surfaced conflict: the case is rare and
    //     the peer resurrects on its own pull of our still-present entry, so the
    //     two sides still converge (the edit wins everywhere).
    //   - no peer tombstone                          → the peer simply hasn't
    //     seen our add yet; keep it.
    for (uuid, local_entry) in local_by_uuid {
        if peer_uuids.contains(uuid) {
            continue; // present on both → handled by the classify walk above.
        }
        let Some(&peer_deleted_at) = peer_tomb.get(uuid) else {
            continue; // the peer never had it (our local-only add) → keep.
        };
        if live_edit_wins(local_entry.times.last_modification_time, peer_deleted_at) {
            continue; // edit wins → keep local (the union below skips its tombstone).
        }
        delete_local_entry(tx, &uuid.to_string())?;
        outcome.deleted.push(*uuid);
    }

    // Fold the peer's `<DeletedObjects>` into ours so deletions propagate
    // onward (grow-only set, earliest deletion time wins). Skip any uuid still
    // backing a live local object (entry or group): a live record must never
    // carry its own tombstone, or other KDBX clients re-delete it.
    for (uuid, deleted_at) in peer_tomb {
        let uuid_str = uuid.to_string();
        if entry_exists(tx, &uuid_str)? || group_exists(tx, GroupId(*uuid))? {
            continue;
        }
        union_tombstone(tx, &uuid_str, *deleted_at)?;
    }
    Ok(())
}

/// Depth-first collection of every entry under `root` (read-only — the
/// write-side counterpart is [`walk_entries`]).
fn collect_entries(root: &Group) -> Vec<&Entry> {
    fn walk<'a>(group: &'a Group, out: &mut Vec<&'a Entry>) {
        out.extend(group.entries.iter());
        for child in &group.groups {
            walk(child, out);
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

/// Depth-first collection of every entry under `root` paired with its parent
/// group id — the peer-side walk for `ingest_peer`, which needs the parent so
/// a peer-only add lands under the right group.
fn collect_entries_with_parent(root: &Group) -> Vec<(&Entry, GroupId)> {
    fn walk<'a>(group: &'a Group, out: &mut Vec<(&'a Entry, GroupId)>) {
        for entry in &group.entries {
            out.push((entry, group.id));
        }
        for child in &group.groups {
            walk(child, out);
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

/// Latest `keys.conflict_resolutions.v1` `resolved_at` per entry, parsed from a
/// vault Meta's `custom_data`. Used by `ingest_peer` for cross-peer adoption:
/// a side that carries a resolution record for an entry has *decided* that
/// conflict. A parse failure degrades to "no resolutions" (a corrupt record
/// must not block ingest).
fn resolution_times(
    custom_data: &[keepass_core::model::CustomDataItem],
) -> HashMap<Uuid, DateTime<Utc>> {
    let mut out: HashMap<Uuid, DateTime<Utc>> = HashMap::new();
    for record in parse_conflict_resolutions(custom_data).unwrap_or_default() {
        out.entry(record.entry)
            .and_modify(|t| {
                if record.resolved_at > *t {
                    *t = record.resolved_at;
                }
            })
            .or_insert(record.resolved_at);
    }
    out
}

/// Was `mtime` recorded strictly after `resolved_at`? `false` when either is
/// absent — supersession (an edit re-opening a resolved conflict) requires a
/// known, strictly-later edit; a missing timestamp is never treated as fresher.
fn edited_after(mtime: Option<DateTime<Utc>>, resolved_at: Option<DateTime<Utc>>) -> bool {
    matches!((mtime, resolved_at), (Some(m), Some(r)) if m > r)
}

/// Does the local mirror already hold the group `group_id`?
fn group_exists(tx: &Connection, group_id: GroupId) -> Result<bool, rusqlite::Error> {
    tx.query_row(
        "SELECT 1 FROM \"group\" WHERE uuid = ?1",
        params![group_id.0.to_string()],
        |_| Ok(()),
    )
    .optional()
    .map(|row| row.is_some())
}

/// `entry-uuid → &Entry` index for the local side, so the per-peer walk can
/// pair each peer entry with our own in O(1).
fn index_entries(root: &Group) -> HashMap<Uuid, &Entry> {
    collect_entries(root)
        .into_iter()
        .map(|e| (e.id.0, e))
        .collect()
}

/// Advance the local mirror's entry to `merged` (an auto-merge result).
///
/// `merged` keeps the entry's existing group and recycle state (classify
/// never moves entries), so we read those from the current row, drop the
/// entry (its child rows cascade), and re-insert via the canonical
/// [`insert_entry`] so every derived column / sealed field / history row is
/// rebuilt exactly as a normal ingest would. `merged`'s attachments and
/// history are inherited from local, so they index into the local binary
/// pool (`binaries`).
fn advance_local_entry(
    tx: &Connection,
    local_vault: &Vault,
    merged: &Entry,
    fingerprint_key: &[u8; 32],
    session_key: &SessionKey,
    binaries: &[&[u8]],
) -> Result<(), EngineError> {
    let uuid_str = merged.id.0.to_string();
    let (group_uuid_str, is_recycled): (String, bool) = tx.query_row(
        "SELECT group_uuid, is_recycled FROM entry WHERE uuid = ?1",
        params![uuid_str],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)),
    )?;
    let group_id =
        GroupId(Uuid::parse_str(&group_uuid_str).map_err(|e| {
            EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?);
    // Child tables (entry_protected/attachment/history/tag/custom_field/
    // custom_data) cascade off entry(uuid) ON DELETE — same posture as
    // `mutations::delete_entry`.
    tx.execute("DELETE FROM entry WHERE uuid = ?1", params![uuid_str])?;
    insert_entry(
        tx,
        local_vault,
        merged,
        group_id,
        is_recycled,
        fingerprint_key,
        session_key,
        binaries,
    )?;
    Ok(())
}

/// Write the peer's value as an `owner`-keyed `conflict_*` row set (the
/// resolver's "theirs"). Mirrors [`insert_entry`]'s field walk but targets
/// the parallel conflict tables and omits the engine-internal derived
/// columns / history / tags / attachments (out of Phase-2 scope). Protected
/// fields are sealed under the same session key the live rows use — never
/// stored as plaintext.
fn insert_conflict_entry(
    tx: &Connection,
    owner: &str,
    entry: &Entry,
    session_key: &SessionKey,
) -> Result<(), EngineError> {
    let uuid = entry.id.0.to_string();
    tx.execute(
        "INSERT INTO conflict_entry (\
            owner, entry_uuid, group_uuid, title, username, url, notes, \
            icon_index, icon_custom_uuid, created_at, modified_at, accessed_at, expires_at\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            owner,
            uuid,
            // group placement is Phase-5 group reconciliation.
            Option::<String>::None,
            entry.title,
            entry.username,
            entry.url,
            entry.notes,
            i64::from(entry.icon_id),
            entry.custom_icon_uuid.map(|u| u.to_string()),
            dt_to_ms_required(entry.times.creation_time),
            dt_to_ms_required(entry.times.last_modification_time),
            dt_to_ms_required(entry.times.last_access_time),
            expiry_ms(&entry.times),
        ],
    )?;

    // Canonical Password slot, always sealed (even empty) for symmetry with
    // the live `entry_protected` row.
    let wrapped_password = seal_with_key(session_key, entry.password.as_bytes())
        .map_err(|e| EngineError::Ingest(IngestError::Wrap(e.to_string())))?;
    tx.execute(
        "INSERT INTO conflict_entry_protected (owner, entry_uuid, field_name, wrapped_blob) \
         VALUES (?1, ?2, ?3, ?4)",
        params![owner, uuid, PASSWORD_FIELD, wrapped_password],
    )?;

    for cf in &entry.custom_fields {
        if cf.protected {
            // Mirror `insert_entry`: a custom field named "Password" would
            // collide with the canonical slot, so skip it.
            if cf.key == PASSWORD_FIELD {
                continue;
            }
            let wrapped = seal_with_key(session_key, cf.value.as_bytes())
                .map_err(|e| EngineError::Ingest(IngestError::Wrap(e.to_string())))?;
            tx.execute(
                "INSERT INTO conflict_entry_protected (owner, entry_uuid, field_name, wrapped_blob) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![owner, uuid, cf.key, wrapped],
            )?;
        } else {
            tx.execute(
                "INSERT INTO conflict_entry_custom_field (owner, entry_uuid, field_name, value) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![owner, uuid, cf.key, cf.value],
            )?;
        }
    }

    Ok(())
}

/// Drop the `conflict_*` rows for one `(owner, entry)`. Explicit child
/// deletes (don't rely on the FK-cascade pragma being on), parent last.
fn clear_conflict_rows(
    tx: &Connection,
    owner: &str,
    entry_uuid: &str,
) -> Result<(), rusqlite::Error> {
    tx.execute(
        "DELETE FROM conflict_entry_protected WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, entry_uuid],
    )?;
    tx.execute(
        "DELETE FROM conflict_entry_custom_field WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, entry_uuid],
    )?;
    tx.execute(
        "DELETE FROM conflict_entry WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, entry_uuid],
    )?;
    Ok(())
}

// ── Phase 5b: cross-peer delete / tombstone helpers ─────────────────────────

/// Does a live edit beat a tombstone? The single rule behind both directions of
/// the Phase 5b edit-vs-delete reconciliation, applied symmetrically:
///
/// - **Direction 1** (our live entry vs the peer's tombstone): keep our entry
///   iff the edit wins; otherwise propagate the peer's delete.
/// - **Direction 2** (the peer's live entry vs our tombstone): resurrect the
///   peer's entry iff its edit wins; otherwise keep the entry deleted.
///
/// Conservative for a password manager — never drop a live edit without proof
/// the deletion is at least as recent:
/// - both times known → the edit wins iff *strictly* newer than the deletion
///   (ties go to the delete — "we didn't edit *after* it");
/// - deletion time unknown → the edit wins (can't justify dropping live data
///   against an undated tombstone);
/// - edit time unknown but the deletion is dated → the delete wins.
fn live_edit_wins(edit: Option<DateTime<Utc>>, delete: Option<DateTime<Utc>>) -> bool {
    match (edit, delete) {
        (Some(e), Some(d)) => e > d,
        (_, None) => true,
        (None, Some(_)) => false,
    }
}

/// Index a vault's `<DeletedObjects>` by uuid. On a duplicate uuid the
/// **earliest** deletion time wins (grow-only-set provenance), preferring a
/// known time over `None`.
fn tombstone_map(
    deleted: &[keepass_core::model::DeletedObject],
) -> HashMap<Uuid, Option<DateTime<Utc>>> {
    let mut out: HashMap<Uuid, Option<DateTime<Utc>>> = HashMap::new();
    for t in deleted {
        out.entry(t.uuid)
            .and_modify(|cur| *cur = earliest(*cur, t.deleted_at))
            .or_insert(t.deleted_at);
    }
    out
}

/// The earlier of two optional deletion times, preferring a known time over an
/// undated (`None`) one.
fn earliest(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

/// Does the local mirror still hold a live entry `uuid`?
fn entry_exists(tx: &Connection, uuid: &str) -> Result<bool, rusqlite::Error> {
    tx.query_row("SELECT 1 FROM entry WHERE uuid = ?1", params![uuid], |_| {
        Ok(())
    })
    .optional()
    .map(|row| row.is_some())
}

/// Remove an entry from the local mirror (Phase 5b delete propagation). Child
/// rows cascade off `entry(uuid) ON DELETE`; the orphan-tag sweep mirrors
/// `mutations::delete_entry` so a tag whose last referencing entry just went
/// away doesn't linger.
fn delete_local_entry(tx: &Connection, uuid: &str) -> Result<(), rusqlite::Error> {
    tx.execute("DELETE FROM entry WHERE uuid = ?1", params![uuid])?;
    tx.execute(
        "DELETE FROM tag WHERE id NOT IN (SELECT DISTINCT tag_id FROM entry_tag)",
        [],
    )?;
    Ok(())
}

/// Drop a `<DeletedObjects>` tombstone for `uuid` from the local mirror. Used on
/// edit-wins resurrection — a restored live entry must never coexist with its
/// own tombstone (cross-client re-delete hazard).
fn remove_tombstone(tx: &Connection, uuid: &str) -> Result<(), rusqlite::Error> {
    tx.execute(
        "DELETE FROM meta_deleted_object WHERE uuid = ?1",
        params![uuid],
    )?;
    Ok(())
}

/// Union one peer tombstone into the local mirror's `<DeletedObjects>`, keeping
/// the **earliest** deletion time on a uuid collision (grow-only set). The
/// caller guarantees `uuid` is not a live local object.
fn union_tombstone(
    tx: &Connection,
    uuid: &str,
    deleted_at: Option<DateTime<Utc>>,
) -> Result<(), rusqlite::Error> {
    let new_ms = deleted_at.map(|d| d.timestamp_millis());
    let existing: Option<Option<i64>> = tx
        .query_row(
            "SELECT deleted_at FROM meta_deleted_object WHERE uuid = ?1",
            params![uuid],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?;
    match existing {
        None => {
            tx.execute(
                "INSERT INTO meta_deleted_object (uuid, deleted_at) VALUES (?1, ?2)",
                params![uuid, new_ms],
            )?;
        }
        Some(existing_ms) => {
            let merged = earliest_ms(existing_ms, new_ms);
            if merged != existing_ms {
                tx.execute(
                    "UPDATE meta_deleted_object SET deleted_at = ?2 WHERE uuid = ?1",
                    params![uuid, merged],
                )?;
            }
        }
    }
    Ok(())
}

/// The earlier of two optional epoch-millis deletion times, preferring a known
/// time over an undated (`None`) one.
fn earliest_ms(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_lowercases() {
        assert_eq!(
            parse_host("https://Login.Example.COM/path"),
            "login.example.com"
        );
    }

    #[test]
    fn parse_host_empty_for_unparseable() {
        assert_eq!(parse_host(""), "");
        assert_eq!(parse_host("not a url"), "");
        // Schemeless input is not a URL per RFC 3986; url crate refuses.
        assert_eq!(parse_host("example.com"), "");
    }
}

#[cfg(test)]
mod ingest_peer_tests {
    //! Owner-tagged peer ingest (Phase 2). In-memory migrated connection +
    //! hand-built vaults (explicit `<History>` so classify finds the LCA, the
    //! same posture as the keepass-merge `classify` unit tests) + raw-SQL
    //! inspection of the `conflict_*` rows. Logic-level — the real-KDBX
    //! history-identity soak is the Phase-4 gate.

    use super::{IngestPeerOutcome, ingest_peer, ingest_vault};
    use crate::migrations;
    use keepass_core::model::{
        CustomField, DeletedObject, Entry, EntryId, GroupId, Timestamps, Vault,
    };
    use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey, open_with_key};
    use keepass_merge::{ConflictKind, ConflictResolution, add_conflict_resolution};
    use rusqlite::{Connection, params};
    use uuid::Uuid;

    const FP_KEY: [u8; 32] = [0x11; 32];
    const SK: [u8; 32] = [0x9c; 32];

    #[derive(Debug)]
    struct TestProtector;
    impl FieldProtector for TestProtector {
        fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
            Ok(SessionKey::from_bytes(SK))
        }
    }

    fn mem_conn() -> Connection {
        let mut c = Connection::open_in_memory().expect("open in-memory db");
        migrations::apply_pending(&mut c).expect("apply migrations");
        // Mirror production (`Engine::open`): cascade child rows on entry delete
        // so `delete_local_entry` behaves the same here as on a live engine.
        c.execute_batch("PRAGMA foreign_keys = ON")
            .expect("enable foreign keys");
        c
    }

    fn ts(secs: i64) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0);
        t
    }

    /// An entry sharing uuid `id` whose CURRENT `(title, password)` is
    /// `current` and whose `<History>` holds one ancestor snapshot `base`
    /// stamped `base_secs` — the LCA the local + peer forks share. `current
    /// == base` models an untouched side (current is the LCA).
    fn forked(id: Uuid, base: (&str, &str), base_secs: i64, current: (&str, &str)) -> Entry {
        let mut snap = Entry::empty(EntryId(id));
        snap.title = base.0.into();
        snap.password = base.1.into();
        snap.times = ts(base_secs);

        let mut e = Entry::empty(EntryId(id));
        e.title = current.0.into();
        e.password = current.1.into();
        e.history = vec![snap];
        e
    }

    /// Like [`forked`] but the diverging facet is a non-protected custom
    /// field `note` (base value vs current value).
    fn forked_note(id: Uuid, base_note: &str, base_secs: i64, current_note: &str) -> Entry {
        let mut snap = Entry::empty(EntryId(id));
        snap.custom_fields = vec![CustomField::new("note", base_note, false)];
        snap.times = ts(base_secs);

        let mut e = Entry::empty(EntryId(id));
        e.custom_fields = vec![CustomField::new("note", current_note, false)];
        e.history = vec![snap];
        e
    }

    fn vault_of(entries: Vec<Entry>) -> Vault {
        let mut v = Vault::empty(GroupId(Uuid::new_v4()));
        v.root.entries = entries;
        v
    }

    /// Stamp a `keys.conflict_resolutions.v1` record for `entry`'s `field` onto
    /// the vault's Meta — i.e. "this side resolved that conflict".
    fn with_resolution(mut v: Vault, entry: Uuid, field: &str, resolved_secs: i64) -> Vault {
        let at = chrono::DateTime::<chrono::Utc>::from_timestamp(resolved_secs, 0).expect("ts");
        let record = ConflictResolution::new(
            entry,
            ConflictKind::Field,
            Some(field.to_string()),
            at,
            None,
        );
        add_conflict_resolution(&mut v.meta.custom_data, &record).expect("add resolution record");
        v
    }

    /// A plain entry with uuid `id`, `title`, and a `last_modification_time` of
    /// `mtime_secs` — the knob the Phase 5b delete reconciliation compares
    /// against a tombstone. No `<History>`: the delete path never calls
    /// `classify`.
    fn entry_at(id: Uuid, title: &str, mtime_secs: i64) -> Entry {
        let mut e = Entry::empty(EntryId(id));
        e.title = title.into();
        e.times = ts(mtime_secs);
        e
    }

    /// A `<DeletedObjects>` tombstone for `id` stamped at `secs`.
    fn tombstone(id: Uuid, secs: i64) -> DeletedObject {
        DeletedObject::new(
            id,
            Some(chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).expect("ts")),
        )
    }

    /// [`vault_of`] plus `<DeletedObjects>` tombstones.
    fn vault_with_tombstones(entries: Vec<Entry>, tombs: Vec<DeletedObject>) -> Vault {
        let mut v = vault_of(entries);
        v.deleted_objects = tombs;
        v
    }

    /// Count `meta_deleted_object` rows for `uuid` (0 or 1).
    fn tombstone_rows(conn: &Connection, uuid: Uuid) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM meta_deleted_object WHERE uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count tombstones")
    }

    /// Seed the local mirror from `local`.
    fn seeded(local: &Vault) -> Connection {
        let mut conn = mem_conn();
        ingest_vault(&mut conn, &FP_KEY, &TestProtector, local).expect("seed local");
        conn
    }

    fn peer_into(
        conn: &mut Connection,
        owner: &str,
        local: &Vault,
        peer: &Vault,
    ) -> IngestPeerOutcome {
        ingest_peer(conn, &FP_KEY, &TestProtector, owner, local, peer).expect("ingest_peer")
    }

    /// Seed `local`, ingest one `peer` as `owner`, return (conn, outcome).
    fn run(local: &Vault, owner: &str, peer: &Vault) -> (Connection, IngestPeerOutcome) {
        let mut conn = seeded(local);
        let outcome = peer_into(&mut conn, owner, local, peer);
        (conn, outcome)
    }

    fn conflict_rows_for(conn: &Connection, uuid: Uuid) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM conflict_entry WHERE entry_uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count conflict rows")
    }

    fn local_entry_exists(conn: &Connection, uuid: Uuid) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM entry WHERE uuid = ?1",
            params![uuid.to_string()],
            |r| r.get::<_, i64>(0),
        )
        .expect("count entry")
            > 0
    }

    fn local_title(conn: &Connection, uuid: Uuid) -> String {
        conn.query_row(
            "SELECT title FROM entry WHERE uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("local title")
    }

    /// Decrypt a sealed `conflict_entry_protected` field for assertions.
    fn peer_protected(conn: &Connection, owner: &str, uuid: Uuid, field: &str) -> Vec<u8> {
        let wrapped: Vec<u8> = conn
            .query_row(
                "SELECT wrapped_blob FROM conflict_entry_protected \
                 WHERE owner = ?1 AND entry_uuid = ?2 AND field_name = ?3",
                params![owner, uuid.to_string(), field],
                |r| r.get(0),
            )
            .expect("protected row");
        open_with_key(&SessionKey::from_bytes(SK), &wrapped).expect("unseal")
    }

    #[test]
    fn in_sync_peer_writes_nothing() {
        let id = Uuid::new_v4();
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "p0"))]);
        let peer = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "p0"))]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(outcome.in_sync, 1);
        assert!(outcome.conflicted.is_empty());
        assert!(outcome.auto_merged.is_empty());
        assert_eq!(conflict_rows_for(&conn, id), 0);
    }

    #[test]
    fn one_sided_peer_edit_advances_local() {
        let id = Uuid::new_v4();
        // Local untouched (current == LCA); peer changed the title.
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "p0"))]);
        let peer = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T-PEER", "p0"))]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(outcome.auto_merged, vec![id]);
        assert!(outcome.conflicted.is_empty());
        assert_eq!(
            local_title(&conn, id),
            "T-PEER",
            "peer's edit adopted locally"
        );
        assert_eq!(
            conflict_rows_for(&conn, id),
            0,
            "auto-merge stores no peer row"
        );
    }

    #[test]
    fn both_sided_same_field_holds_local_and_stores_peer_row() {
        let id = Uuid::new_v4();
        // Both moved Password off the LCA, differently → genuine conflict.
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "p-MINE"))]);
        let peer = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "p-THEIRS"))]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(outcome.conflicted, vec![id]);
        assert!(
            outcome.auto_merged.is_empty(),
            "hold-open: local not advanced"
        );
        assert_eq!(conflict_rows_for(&conn, id), 1);
        // Local untouched; peer's password stored (sealed) as theirs.
        assert_eq!(local_title(&conn, id), "T");
        assert_eq!(peer_protected(&conn, "peerB", id, "Password"), b"p-THEIRS");
    }

    #[test]
    fn field_granularity_different_fields_auto_merge() {
        let id = Uuid::new_v4();
        // Local changed Title, peer changed Password — disjoint fields. Under
        // field granularity (what ingest now uses) these non-overlapping edits
        // auto-merge into one combined entry; no conflict is parked. (Item
        // granularity, the prior choice, would have parked the whole entry.)
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T-MINE", "p0"))]);
        let peer = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "p-PEER"))]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(outcome.auto_merged, vec![id]);
        assert!(
            outcome.conflicted.is_empty(),
            "disjoint-field edits auto-merge, no conflict parked"
        );
        assert_eq!(conflict_rows_for(&conn, id), 0);
        // Local advanced to the combined entry — local's title edit survives
        // (peer's password edit rides in too, from the LCA-unchanged side).
        assert_eq!(local_title(&conn, id), "T-MINE");
    }

    #[test]
    fn peer_password_is_sealed_not_plaintext() {
        let id = Uuid::new_v4();
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "mine"))]);
        let peer = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "theirs"))]);
        let (conn, _) = run(&local, "peerB", &peer);
        let wrapped: Vec<u8> = conn
            .query_row(
                "SELECT wrapped_blob FROM conflict_entry_protected \
                 WHERE owner = 'peerB' AND entry_uuid = ?1 AND field_name = 'Password'",
                params![id.to_string()],
                |r| r.get(0),
            )
            .expect("protected row");
        assert_ne!(
            wrapped.as_slice(),
            b"theirs",
            "stored sealed, not plaintext"
        );
        // AES-GCM: 12-byte nonce + ciphertext(=plaintext len) + 16-byte tag.
        assert_eq!(wrapped.len(), 12 + "theirs".len() + 16);
        // ...and it round-trips back to the peer value under the session key.
        assert_eq!(peer_protected(&conn, "peerB", id, "Password"), b"theirs");
    }

    #[test]
    fn repull_refreshes_peer_row_in_place() {
        let id = Uuid::new_v4();
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "mine"))]);
        let mut conn = seeded(&local);

        let peer_v1 = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "theirs-1"))]);
        peer_into(&mut conn, "peerB", &local, &peer_v1);
        assert_eq!(peer_protected(&conn, "peerB", id, "Password"), b"theirs-1");

        // Same peer pulls again with a newer value → one row, refreshed.
        let peer_v2 = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "theirs-2"))]);
        peer_into(&mut conn, "peerB", &local, &peer_v2);
        let owner_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM conflict_entry WHERE owner = 'peerB' AND entry_uuid = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(owner_rows, 1, "refresh in place, no accumulation");
        assert_eq!(peer_protected(&conn, "peerB", id, "Password"), b"theirs-2");
    }

    #[test]
    fn multiple_peers_store_distinct_rows() {
        let id = Uuid::new_v4();
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "mine"))]);
        let mut conn = seeded(&local);

        peer_into(
            &mut conn,
            "peerB",
            &local,
            &vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "from-B"))]),
        );
        peer_into(
            &mut conn,
            "peerC",
            &local,
            &vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "from-C"))]),
        );

        assert_eq!(
            conflict_rows_for(&conn, id),
            2,
            "one row per peer — native multi-peer"
        );
        assert_eq!(peer_protected(&conn, "peerB", id, "Password"), b"from-B");
        assert_eq!(peer_protected(&conn, "peerC", id, "Password"), b"from-C");
    }

    #[test]
    fn peer_only_entry_is_added_locally() {
        let local_id = Uuid::new_v4();
        let peer_only_id = Uuid::new_v4();
        let local = vault_of(vec![forked(local_id, ("T", "p0"), 1000, ("T", "p0"))]);
        // Peer carries an extra entry we've never seen — a peer-side add.
        let peer = vault_of(vec![
            forked(local_id, ("T", "p0"), 1000, ("T", "p0")),
            forked(peer_only_id, ("X", "x0"), 1000, ("New", "x0")),
        ]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        // An add is unambiguous (present beats absent): taken locally, not a
        // conflict. Only deletes wait for the Phase-5 tombstone story.
        assert_eq!(outcome.added, vec![peer_only_id]);
        assert!(outcome.conflicted.is_empty());
        assert_eq!(
            conflict_rows_for(&conn, peer_only_id),
            0,
            "an add is not a conflict"
        );
        assert!(
            local_entry_exists(&conn, peer_only_id),
            "peer-only entry inserted into the local mirror"
        );
        assert_eq!(local_title(&conn, peer_only_id), "New");
    }

    #[test]
    fn conflict_then_reagreement_clears_row() {
        let id = Uuid::new_v4();
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "mine"))]);
        let mut conn = seeded(&local);

        // Round 1: genuine conflict → row stored.
        peer_into(
            &mut conn,
            "peerB",
            &local,
            &vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "theirs"))]),
        );
        assert_eq!(conflict_rows_for(&conn, id), 1);

        // Round 2: the peer now matches our current value → InSync → cleared.
        peer_into(
            &mut conn,
            "peerB",
            &local,
            &vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "mine"))]),
        );
        assert_eq!(
            conflict_rows_for(&conn, id),
            0,
            "re-agreement clears the badge for free"
        );
    }

    #[test]
    fn non_protected_custom_field_conflict_stores_peer_value() {
        let id = Uuid::new_v4();
        let local = vault_of(vec![forked_note(id, "n0", 1000, "A")]);
        let peer = vault_of(vec![forked_note(id, "n0", 1000, "B")]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(outcome.conflicted, vec![id]);
        let stored: String = conn
            .query_row(
                "SELECT value FROM conflict_entry_custom_field \
                 WHERE owner = 'peerB' AND entry_uuid = ?1 AND field_name = 'note'",
                params![id.to_string()],
                |r| r.get(0),
            )
            .expect("custom field row");
        assert_eq!(
            stored, "B",
            "peer's non-protected custom field stored as theirs"
        );
    }

    #[test]
    fn no_shared_ancestor_falls_back_to_conflict() {
        let id = Uuid::new_v4();
        // Disjoint history mtimes ⇒ no shared snapshot; a both-present field
        // that differs parks conservatively (the same fallback classify uses).
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T", "mine"))]);
        let peer = vault_of(vec![forked(id, ("X", "x0"), 9999, ("T", "theirs"))]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(outcome.conflicted, vec![id]);
        assert_eq!(conflict_rows_for(&conn, id), 1);
    }

    #[test]
    fn peer_resolution_record_is_adopted() {
        let id = Uuid::new_v4();
        // Both edited Title (a conflict); the peer carries a resolution record
        // ⇒ the peer resolved it ⇒ we adopt the peer's value (resolve-on-one
        // clears-on-all), not hold.
        let local = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T-MINE", "p0"))]);
        let peer = with_resolution(
            vault_of(vec![forked(id, ("T", "p0"), 1000, ("T-THEIRS", "p0"))]),
            id,
            "Title",
            2000,
        );
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(outcome.auto_merged, vec![id], "peer's resolution adopted");
        assert!(outcome.conflicted.is_empty());
        assert_eq!(conflict_rows_for(&conn, id), 0, "badge clears on adopt");
        assert_eq!(
            local_title(&conn, id),
            "T-THEIRS",
            "local advanced to the peer's resolved value"
        );
    }

    #[test]
    fn local_resolution_is_not_re_held() {
        let id = Uuid::new_v4();
        // We resolved Title locally; the peer hasn't adopted yet (values still
        // differ). We must keep our value with the badge clear — re-holding
        // would re-badge a conflict we already settled.
        let local = with_resolution(
            vault_of(vec![forked(id, ("T", "p0"), 1000, ("T-MINE", "p0"))]),
            id,
            "Title",
            2000,
        );
        let peer = vault_of(vec![forked(id, ("T", "p0"), 1000, ("T-THEIRS", "p0"))]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert!(
            outcome.conflicted.is_empty(),
            "we already resolved → don't re-hold"
        );
        assert!(
            outcome.auto_merged.is_empty(),
            "local keeps its value, no advance"
        );
        assert_eq!(conflict_rows_for(&conn, id), 0, "badge stays clear");
        assert_eq!(
            local_title(&conn, id),
            "T-MINE",
            "local keeps its chosen value"
        );
    }

    #[test]
    fn stale_local_resolution_reopens_on_fresh_peer_edit() {
        let id = Uuid::new_v4();
        // We resolved Title at t=2000. THEN the peer made a *fresh* edit
        // (mtime 3000) producing a new divergence the old record never covered.
        // The stale resolution must NOT suppress it — a genuine new conflict is
        // parked. Regression: a once-resolved entry permanently muted every
        // future conflict, and only on the resolver's side (the other peer,
        // lacking the record, parked) — the soak asymmetry on re-edited entries.
        let local = with_resolution(
            vault_of(vec![forked(id, ("T", "p0"), 1000, ("T-MINE", "p0"))]),
            id,
            "Title",
            2000,
        );
        let mut peer_entry = forked(id, ("T", "p0"), 1000, ("T-THEIRS-NEW", "p0"));
        peer_entry.times = ts(3000); // peer edited AFTER our resolution
        let peer = vault_of(vec![peer_entry]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(
            outcome.conflicted,
            vec![id],
            "fresh peer edit after our resolution re-opens the conflict"
        );
        assert!(
            outcome.auto_merged.is_empty(),
            "re-opened conflict holds open, no silent adopt"
        );
        assert_eq!(conflict_rows_for(&conn, id), 1);
    }

    #[test]
    fn local_resolution_still_holds_when_peer_edit_predates_it() {
        let id = Uuid::new_v4();
        // Boundary: the peer's diverging value predates our resolution (mtime
        // 1500 < resolved 2000) — it's the conflict we already settled, not a
        // fresh one. Must still suppress (resolve-on-one stays cleared-on-all).
        let local = with_resolution(
            vault_of(vec![forked(id, ("T", "p0"), 1000, ("T-MINE", "p0"))]),
            id,
            "Title",
            2000,
        );
        let mut peer_entry = forked(id, ("T", "p0"), 1000, ("T-THEIRS", "p0"));
        peer_entry.times = ts(1500); // peer's value predates our resolution
        let peer = vault_of(vec![peer_entry]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert!(
            outcome.conflicted.is_empty(),
            "pre-resolution peer value is the settled conflict → no re-hold"
        );
        assert_eq!(conflict_rows_for(&conn, id), 0, "badge stays clear");
        assert_eq!(local_title(&conn, id), "T-MINE", "local keeps its value");
    }

    // ── Phase 5b: cross-peer deletes / tombstones ──────────────────────────

    #[test]
    fn peer_tombstone_propagates_delete() {
        let id = Uuid::new_v4();
        // Local last edited X at t=1000; the peer deleted it later at t=2000.
        let local = vault_of(vec![entry_at(id, "X", 1000)]);
        let peer = vault_with_tombstones(vec![], vec![tombstone(id, 2000)]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(outcome.deleted, vec![id], "peer delete propagated");
        assert!(outcome.auto_merged.is_empty());
        assert!(outcome.conflicted.is_empty());
        assert!(!local_entry_exists(&conn, id), "entry removed locally");
        assert_eq!(
            tombstone_rows(&conn, id),
            1,
            "tombstone unioned for onward propagation"
        );
    }

    #[test]
    fn edit_vs_delete_keeps_local_edit() {
        let id = Uuid::new_v4();
        // We edited X at t=3000; the peer deleted it earlier at t=2000 → the
        // edit wins (conservative: never silently drop a live edit).
        let local = vault_of(vec![entry_at(id, "X-edited", 3000)]);
        let peer = vault_with_tombstones(vec![], vec![tombstone(id, 2000)]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert!(outcome.deleted.is_empty(), "edit wins → not deleted");
        assert!(local_entry_exists(&conn, id), "local edit kept");
        assert_eq!(local_title(&conn, id), "X-edited");
        assert_eq!(
            tombstone_rows(&conn, id),
            0,
            "no tombstone against a live entry (cross-client re-delete hazard)"
        );
    }

    #[test]
    fn local_only_add_absent_on_peer_is_kept() {
        let id = Uuid::new_v4();
        // We added X; the peer simply hasn't seen it (no tombstone) → keep it.
        let local = vault_of(vec![entry_at(id, "X", 1000)]);
        let peer = vault_of(vec![]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert!(outcome.deleted.is_empty(), "no tombstone → not a delete");
        assert!(local_entry_exists(&conn, id), "local-only add kept");
        assert_eq!(tombstone_rows(&conn, id), 0);
    }

    #[test]
    fn orphan_tombstone_is_unioned() {
        let absent = Uuid::new_v4();
        // Neither side holds `absent` live; the peer carries its tombstone. We
        // adopt it so the deletion keeps propagating, without touching an entry.
        let local = vault_of(vec![]);
        let peer = vault_with_tombstones(vec![], vec![tombstone(absent, 4000)]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert!(outcome.deleted.is_empty());
        assert!(outcome.added.is_empty());
        assert!(outcome.auto_merged.is_empty());
        assert_eq!(tombstone_rows(&conn, absent), 1, "orphan tombstone unioned");
    }

    #[test]
    fn stale_peer_does_not_resurrect_deleted_entry() {
        let id = Uuid::new_v4();
        // We deleted X at t=3000. The peer still has a stale copy edited at
        // t=2000 (before our delete) → it must NOT come back (no zombie).
        let local = vault_with_tombstones(vec![], vec![tombstone(id, 3000)]);
        let peer = vault_of(vec![entry_at(id, "X-stale", 2000)]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert!(outcome.added.is_empty(), "stale peer copy not resurrected");
        assert!(!local_entry_exists(&conn, id), "entry stays deleted");
        assert_eq!(tombstone_rows(&conn, id), 1, "our tombstone is retained");
    }

    #[test]
    fn peer_edit_after_delete_resurrects_entry() {
        let id = Uuid::new_v4();
        // We deleted X at t=2000. The peer edited it later at t=3000 → edit
        // wins: X comes back and our tombstone is scrubbed.
        let local = vault_with_tombstones(vec![], vec![tombstone(id, 2000)]);
        let peer = vault_of(vec![entry_at(id, "X-revived", 3000)]);
        let (conn, outcome) = run(&local, "peerB", &peer);
        assert_eq!(
            outcome.added,
            vec![id],
            "peer's newer edit resurrects the entry"
        );
        assert!(local_entry_exists(&conn, id));
        assert_eq!(local_title(&conn, id), "X-revived");
        assert_eq!(
            tombstone_rows(&conn, id),
            0,
            "tombstone scrubbed on resurrection (never live entry + tombstone)"
        );
    }
}
