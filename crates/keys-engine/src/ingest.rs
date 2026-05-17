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

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{Entry, Group, GroupId, Vault};
use keepass_core::protector::{FieldProtector, SessionKey, seal_with_key};
use rusqlite::{Connection, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{EngineError, IngestError};
use crate::fingerprint;
use crate::meta;
use crate::strength;

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

    // Walk groups first so entries' FK references resolve.
    walk_groups(&tx, &vault.root, None, recycle_bin_uuid, &mut outcome)?;

    // Index the binary pool by ref_id so attachment lookups are O(1).
    // KDBX `ref_id` is the index into `Vault::binaries`.
    let binaries: Vec<&[u8]> = vault.binaries.iter().map(|b| b.data.as_slice()).collect();

    walk_entries(
        &tx,
        &vault,
        &vault.root,
        recycle_bin_uuid,
        false,
        fingerprint_key,
        &session_key,
        &binaries,
        &mut outcome,
    )?;

    tx.commit()?;
    drop(vault);
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
    conn.execute("DELETE FROM entry", [])?;
    conn.execute("DELETE FROM tag", [])?;
    conn.execute("DELETE FROM attachment_blob", [])?;
    // Group goes last; entries FK to it.
    conn.execute("DELETE FROM \"group\"", [])?;
    Ok(())
}

/// Recursive group walk. `parent_uuid = None` for the root group.
fn walk_groups(
    conn: &Connection,
    group: &Group,
    parent_uuid: Option<Uuid>,
    recycle_bin_uuid: Option<GroupId>,
    outcome: &mut IngestOutcome,
) -> Result<(), rusqlite::Error> {
    let uuid_str = group.id.0.to_string();
    let parent_str = parent_uuid.as_ref().map(Uuid::to_string);
    let is_recycle_bin = recycle_bin_uuid.is_some_and(|rb| rb == group.id);

    conn.execute(
        "INSERT INTO \"group\" (\
            uuid, parent_uuid, name, icon_index, icon_custom_uuid, notes, \
            created_at, modified_at, expires_at, is_recycle_bin\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
        ],
    )?;

    outcome.group_uuids.push(group.id.0);
    for child in &group.groups {
        walk_groups(conn, child, Some(group.id.0), recycle_bin_uuid, outcome)?;
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
            is_recycled\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
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
