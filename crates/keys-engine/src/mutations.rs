//! Per-row mutation API.
//!
//! Phase 4.1 lands the engine-side mutation surface. Every mutation
//! runs inside a single `SQLite` transaction, refreshes the relevant
//! `modified_at`, and maintains derived columns (`url_host`,
//! `password_strength_bucket`, `password_entropy`,
//! `password_fingerprint`) when protected fields change.
//!
//! Event emission for the Phase 4.3 change-bus lives on
//! [`crate::Engine`] — the mutation functions here return the small
//! outcome structs the engine needs to construct events (previous group
//! for a deleted entry, the cascade list for a recursive group delete,
//! etc.), and the engine fires events after the commit returns.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use keepass_core::protector::{FieldProtector, SessionKey, seal_with_key};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::EngineError;
use crate::fingerprint;
use crate::model::{EntryUpdate, GroupUpdate, IconRef, NewEntryFields, NewGroupFields};
use crate::strength;

/// Canonical KDBX field name for the password slot. Must match
/// [`crate::ingest`]'s `PASSWORD_FIELD`.
const PASSWORD_FIELD: &str = "Password";

/// Outcome of [`delete_entry`] — carries the pre-delete group so the
/// engine can populate an [`crate::events::EntryDeletionInfo`].
#[derive(Debug)]
pub(crate) struct DeleteEntryOutcome {
    pub previous_group: Uuid,
}

/// Outcome of [`move_entry`] — carries both endpoints so the engine can
/// populate an [`crate::events::EntryMove`].
#[derive(Debug)]
pub(crate) struct MoveEntryOutcome {
    pub from_group: Uuid,
    pub to_group: Uuid,
}

/// Outcome of [`move_group`] — carries both endpoints.
#[derive(Debug)]
pub(crate) struct MoveGroupOutcome {
    pub from_parent: Uuid,
    pub to_parent: Uuid,
}

/// Outcome of [`delete_group`] — carries the full cascade so the engine
/// can fold a single combined `GroupsDeleted` + `EntriesDeleted` pair
/// of events.
#[derive(Debug, Default)]
pub(crate) struct DeleteGroupOutcome {
    /// Every group removed by the cascade, paired with the parent it
    /// had immediately before deletion.
    pub deleted_groups: Vec<(Uuid, Option<Uuid>)>,
    /// Every entry removed by the cascade, paired with the group it
    /// was in immediately before deletion.
    pub deleted_entries: Vec<(Uuid, Uuid)>,
}

/// Wall-clock `now` in ms since the Unix epoch. Saturates on platform
/// edge cases rather than panicking — a mutation should never abort
/// because the host clock is set to 1969.
pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Acquire one session key for the duration of a single mutation.
fn session_key(protector: &dyn FieldProtector) -> Result<SessionKey, EngineError> {
    protector
        .acquire_session_key()
        .map_err(|e| EngineError::SessionKey(e.to_string()))
}

fn wrap(session: &SessionKey, plaintext: &[u8]) -> Result<Vec<u8>, EngineError> {
    seal_with_key(session, plaintext).map_err(|e| EngineError::Wrap(e.to_string()))
}

/// Parse the host out of a URL. Lowercased to match `idx_entry_url_host`.
/// Mirror of `ingest::parse_host`.
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

fn icon_parts(icon: &IconRef) -> (Option<i64>, Option<String>) {
    match icon {
        IconRef::Builtin(idx) => (Some(i64::from(*idx)), None),
        IconRef::Custom(uuid) => (None, Some(uuid.to_string())),
    }
}

/// `true` if a row exists in `entry` with the given uuid.
fn entry_exists(tx: &Transaction<'_>, uuid: &str) -> Result<bool, EngineError> {
    let n: i64 = tx.query_row(
        "SELECT COUNT(*) FROM entry WHERE uuid = ?1",
        params![uuid],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// `true` if a row exists in `"group"` with the given uuid.
fn group_exists(tx: &Transaction<'_>, uuid: &str) -> Result<bool, EngineError> {
    let n: i64 = tx.query_row(
        "SELECT COUNT(*) FROM \"group\" WHERE uuid = ?1",
        params![uuid],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Look up the recycle bin group uuid, if one exists.
fn recycle_bin_uuid(tx: &Transaction<'_>) -> Result<Option<String>, EngineError> {
    let row = tx
        .query_row(
            "SELECT uuid FROM \"group\" WHERE is_recycle_bin = 1 LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    Ok(row)
}

/// Insert (or no-op) a tag name and return its row id.
fn upsert_tag(tx: &Transaction<'_>, name: &str) -> Result<i64, EngineError> {
    tx.execute(
        "INSERT OR IGNORE INTO tag (name) VALUES (?1)",
        params![name],
    )?;
    let id: i64 = tx.query_row("SELECT id FROM tag WHERE name = ?1", params![name], |r| {
        r.get(0)
    })?;
    Ok(id)
}

/// Compute strength + fingerprint columns for a password plaintext.
fn password_columns(plaintext: &str, fingerprint_key: &[u8; 32]) -> (u8, f64, Option<[u8; 32]>) {
    let s = strength::strength(plaintext);
    let fp = if plaintext.is_empty() {
        None
    } else {
        Some(fingerprint::fingerprint(
            fingerprint_key,
            plaintext.as_bytes(),
        ))
    };
    (s.bucket as u8, s.entropy_bits, fp)
}

// ── Entry mutations ────────────────────────────────────────────────────

#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
pub(crate) fn create_entry(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    group_uuid: Uuid,
    fields: NewEntryFields,
) -> Result<Uuid, EngineError> {
    let session = session_key(protector)?;
    let entry_uuid = Uuid::new_v4();
    let now = now_ms();
    let group_uuid_str = group_uuid.to_string();
    let entry_uuid_str = entry_uuid.to_string();

    let tx = conn.transaction()?;

    if !group_exists(&tx, &group_uuid_str)? {
        return Err(EngineError::NotFound { entity: "group" });
    }

    let pw_plain = fields.password.expose_secret();
    let (bucket, entropy, fp) = password_columns(pw_plain, fingerprint_key);
    let fp_param: Option<&[u8]> = fp.as_ref().map(|b| &b[..]);
    let url_host = parse_host(&fields.url);
    let (icon_index, icon_custom_uuid) = icon_parts(&fields.icon);

    tx.execute(
        "INSERT INTO entry (\
            uuid, group_uuid, title, username, url, url_host, notes, \
            icon_index, icon_custom_uuid, created_at, modified_at, \
            accessed_at, last_used_at, expires_at, \
            password_strength_bucket, password_entropy, password_fingerprint, \
            is_recycled\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, 0)",
        params![
            entry_uuid_str,
            group_uuid_str,
            fields.title,
            fields.username,
            fields.url,
            url_host,
            fields.notes,
            icon_index,
            icon_custom_uuid,
            now,
            now,
            now,
            Option::<i64>::None,
            Option::<i64>::None,
            i64::from(bucket),
            entropy,
            fp_param,
        ],
    )?;

    // Canonical Password slot — always written.
    let wrapped_pw = wrap(&session, pw_plain.as_bytes())?;
    tx.execute(
        "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
         VALUES (?1, ?2, ?3)",
        params![entry_uuid_str, PASSWORD_FIELD, wrapped_pw],
    )?;

    for cf in &fields.custom_fields {
        if cf.protected {
            if cf.name == PASSWORD_FIELD {
                // Avoid colliding with the canonical Password slot; same
                // policy as ingest.
                continue;
            }
            let wrapped = wrap(&session, cf.value.expose_secret().as_bytes())?;
            tx.execute(
                "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
                 VALUES (?1, ?2, ?3)",
                params![entry_uuid_str, cf.name, wrapped],
            )?;
        } else {
            tx.execute(
                "INSERT INTO entry_custom_field (entry_uuid, field_name, value) \
                 VALUES (?1, ?2, ?3)",
                params![entry_uuid_str, cf.name, cf.value.expose_secret()],
            )?;
        }
    }

    insert_tags(&tx, &entry_uuid_str, &fields.tags)?;

    tx.commit()?;
    Ok(entry_uuid)
}

fn insert_tags(tx: &Transaction<'_>, entry_uuid: &str, tags: &[String]) -> Result<(), EngineError> {
    let mut seen: HashSet<String> = HashSet::new();
    for raw in tags {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        if !seen.insert(name.to_owned()) {
            continue;
        }
        let id = upsert_tag(tx, name)?;
        tx.execute(
            "INSERT OR IGNORE INTO entry_tag (entry_uuid, tag_id) VALUES (?1, ?2)",
            params![entry_uuid, id],
        )?;
    }
    Ok(())
}

pub(crate) fn update_entry(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    uuid: Uuid,
    update: EntryUpdate,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }

    if let Some(title) = update.title {
        tx.execute(
            "UPDATE entry SET title = ?1 WHERE uuid = ?2",
            params![title, uuid_str],
        )?;
    }
    if let Some(username) = update.username {
        tx.execute(
            "UPDATE entry SET username = ?1 WHERE uuid = ?2",
            params![username, uuid_str],
        )?;
    }
    if let Some(url) = update.url {
        let host = parse_host(&url);
        tx.execute(
            "UPDATE entry SET url = ?1, url_host = ?2 WHERE uuid = ?3",
            params![url, host, uuid_str],
        )?;
    }
    if let Some(notes) = update.notes {
        tx.execute(
            "UPDATE entry SET notes = ?1 WHERE uuid = ?2",
            params![notes, uuid_str],
        )?;
    }
    if let Some(icon) = update.icon {
        let (idx, custom) = icon_parts(&icon);
        tx.execute(
            "UPDATE entry SET icon_index = ?1, icon_custom_uuid = ?2 WHERE uuid = ?3",
            params![idx, custom, uuid_str],
        )?;
    }
    if let Some(expiry) = update.expires_at {
        tx.execute(
            "UPDATE entry SET expires_at = ?1 WHERE uuid = ?2",
            params![expiry, uuid_str],
        )?;
    }

    if let Some(password) = update.password {
        let session = session_key(protector)?;
        let plain = password.expose_secret();
        let (bucket, entropy, fp) = password_columns(plain, fingerprint_key);
        let fp_param: Option<&[u8]> = fp.as_ref().map(|b| &b[..]);
        let wrapped = wrap(&session, plain.as_bytes())?;

        tx.execute(
            "UPDATE entry SET \
                password_strength_bucket = ?1, \
                password_entropy = ?2, \
                password_fingerprint = ?3 \
             WHERE uuid = ?4",
            params![i64::from(bucket), entropy, fp_param, uuid_str],
        )?;
        tx.execute(
            "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(entry_uuid, field_name) DO UPDATE SET wrapped_blob = excluded.wrapped_blob",
            params![uuid_str, PASSWORD_FIELD, wrapped],
        )?;
    }

    bump_modified(&tx, &uuid_str)?;
    tx.commit()?;
    Ok(())
}

fn bump_modified(tx: &Transaction<'_>, uuid: &str) -> Result<(), EngineError> {
    tx.execute(
        "UPDATE entry SET modified_at = ?1 WHERE uuid = ?2",
        params![now_ms(), uuid],
    )?;
    Ok(())
}

pub(crate) fn recycle_entry(conn: &mut Connection, uuid: Uuid) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    let now = now_ms();
    if let Some(bin) = recycle_bin_uuid(&tx)? {
        tx.execute(
            "UPDATE entry SET is_recycled = 1, group_uuid = ?1, modified_at = ?2 \
             WHERE uuid = ?3",
            params![bin, now, uuid_str],
        )?;
    } else {
        tx.execute(
            "UPDATE entry SET is_recycled = 1, modified_at = ?1 WHERE uuid = ?2",
            params![now, uuid_str],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn restore_entry(conn: &mut Connection, uuid: Uuid) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    tx.execute(
        "UPDATE entry SET is_recycled = 0, modified_at = ?1 WHERE uuid = ?2",
        params![now_ms(), uuid_str],
    )?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn delete_entry(
    conn: &mut Connection,
    uuid: Uuid,
) -> Result<DeleteEntryOutcome, EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    let previous_group_str: String = match tx
        .query_row(
            "SELECT group_uuid FROM entry WHERE uuid = ?1",
            params![uuid_str],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        Some(g) => g,
        None => return Err(EngineError::NotFound { entity: "entry" }),
    };
    let previous_group = Uuid::parse_str(&previous_group_str)
        .map_err(|e| EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))))?;
    tx.execute("DELETE FROM entry WHERE uuid = ?1", params![uuid_str])?;
    tx.commit()?;
    Ok(DeleteEntryOutcome { previous_group })
}

pub(crate) fn move_entry(
    conn: &mut Connection,
    uuid: Uuid,
    new_group_uuid: Uuid,
) -> Result<MoveEntryOutcome, EngineError> {
    let uuid_str = uuid.to_string();
    let group_str = new_group_uuid.to_string();
    let tx = conn.transaction()?;
    let previous_group_str: String = match tx
        .query_row(
            "SELECT group_uuid FROM entry WHERE uuid = ?1",
            params![uuid_str],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        Some(g) => g,
        None => return Err(EngineError::NotFound { entity: "entry" }),
    };
    if !group_exists(&tx, &group_str)? {
        return Err(EngineError::NotFound { entity: "group" });
    }
    let from_group = Uuid::parse_str(&previous_group_str)
        .map_err(|e| EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))))?;
    tx.execute(
        "UPDATE entry SET group_uuid = ?1, modified_at = ?2 WHERE uuid = ?3",
        params![group_str, now_ms(), uuid_str],
    )?;
    tx.commit()?;
    Ok(MoveEntryOutcome {
        from_group,
        to_group: new_group_uuid,
    })
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn set_protected_field(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    uuid: Uuid,
    field_name: &str,
    plaintext: SecretString,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let session = session_key(protector)?;
    let wrapped = wrap(&session, plaintext.expose_secret().as_bytes())?;

    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    tx.execute(
        "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(entry_uuid, field_name) DO UPDATE SET wrapped_blob = excluded.wrapped_blob",
        params![uuid_str, field_name, wrapped],
    )?;

    if field_name == PASSWORD_FIELD {
        let plain = plaintext.expose_secret();
        let (bucket, entropy, fp) = password_columns(plain, fingerprint_key);
        let fp_param: Option<&[u8]> = fp.as_ref().map(|b| &b[..]);
        tx.execute(
            "UPDATE entry SET \
                password_strength_bucket = ?1, \
                password_entropy = ?2, \
                password_fingerprint = ?3 \
             WHERE uuid = ?4",
            params![i64::from(bucket), entropy, fp_param, uuid_str],
        )?;
    }

    bump_modified(&tx, &uuid_str)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn set_non_protected_custom_field(
    conn: &mut Connection,
    uuid: Uuid,
    field_name: &str,
    value: &str,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    tx.execute(
        "INSERT INTO entry_custom_field (entry_uuid, field_name, value) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(entry_uuid, field_name) DO UPDATE SET value = excluded.value",
        params![uuid_str, field_name, value],
    )?;
    bump_modified(&tx, &uuid_str)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn remove_custom_field(
    conn: &mut Connection,
    uuid: Uuid,
    field_name: &str,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    // Refuse to delete the canonical Password slot via this method —
    // it would leave the reveal path with no row to read. Callers that
    // really want to "clear" the password should set it to empty via
    // `set_protected_field`.
    if field_name == PASSWORD_FIELD {
        return Err(EngineError::NotFound {
            entity: "custom_field",
        });
    }
    tx.execute(
        "DELETE FROM entry_protected WHERE entry_uuid = ?1 AND field_name = ?2",
        params![uuid_str, field_name],
    )?;
    tx.execute(
        "DELETE FROM entry_custom_field WHERE entry_uuid = ?1 AND field_name = ?2",
        params![uuid_str, field_name],
    )?;
    bump_modified(&tx, &uuid_str)?;
    tx.commit()?;
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn set_tags(
    conn: &mut Connection,
    uuid: Uuid,
    tags: Vec<String>,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    tx.execute(
        "DELETE FROM entry_tag WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    insert_tags(&tx, &uuid_str, &tags)?;
    bump_modified(&tx, &uuid_str)?;
    tx.commit()?;
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn attach_file(
    conn: &mut Connection,
    uuid: Uuid,
    name: &str,
    bytes: Vec<u8>,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha = hasher.finalize();
    let sha_bytes: &[u8] = sha.as_slice();
    let size_i64 = i64::try_from(bytes.len()).unwrap_or(i64::MAX);

    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    tx.execute(
        "INSERT OR IGNORE INTO attachment_blob (sha256, bytes, size) VALUES (?1, ?2, ?3)",
        params![sha_bytes, bytes, size_i64],
    )?;
    tx.execute(
        "INSERT INTO entry_attachment (entry_uuid, attachment_name, blob_sha256) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(entry_uuid, attachment_name) DO UPDATE SET blob_sha256 = excluded.blob_sha256",
        params![uuid_str, name, sha_bytes],
    )?;
    bump_modified(&tx, &uuid_str)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn remove_attachment(
    conn: &mut Connection,
    uuid: Uuid,
    name: &str,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    // Don't GC `attachment_blob` rows here; blobs are shared by SHA and
    // GC is a separate concern.
    tx.execute(
        "DELETE FROM entry_attachment WHERE entry_uuid = ?1 AND attachment_name = ?2",
        params![uuid_str, name],
    )?;
    bump_modified(&tx, &uuid_str)?;
    tx.commit()?;
    Ok(())
}

// ── Group mutations ────────────────────────────────────────────────────

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn create_group(
    conn: &mut Connection,
    parent_uuid: Uuid,
    fields: NewGroupFields,
) -> Result<Uuid, EngineError> {
    let parent_str = parent_uuid.to_string();
    let new_uuid = Uuid::new_v4();
    let new_uuid_str = new_uuid.to_string();
    let now = now_ms();
    let (icon_index, icon_custom_uuid) = icon_parts(&fields.icon);

    let tx = conn.transaction()?;
    if !group_exists(&tx, &parent_str)? {
        return Err(EngineError::NotFound { entity: "group" });
    }
    tx.execute(
        "INSERT INTO \"group\" (\
            uuid, parent_uuid, name, icon_index, icon_custom_uuid, notes, \
            created_at, modified_at, expires_at, is_recycle_bin\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, 0)",
        params![
            new_uuid_str,
            parent_str,
            fields.name,
            icon_index,
            icon_custom_uuid,
            fields.notes,
            now,
            now,
        ],
    )?;
    tx.commit()?;
    Ok(new_uuid)
}

pub(crate) fn update_group(
    conn: &mut Connection,
    uuid: Uuid,
    update: GroupUpdate,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !group_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "group" });
    }
    if let Some(name) = update.name {
        tx.execute(
            "UPDATE \"group\" SET name = ?1 WHERE uuid = ?2",
            params![name, uuid_str],
        )?;
    }
    if let Some(notes) = update.notes {
        tx.execute(
            "UPDATE \"group\" SET notes = ?1 WHERE uuid = ?2",
            params![notes, uuid_str],
        )?;
    }
    if let Some(icon) = update.icon {
        let (idx, custom) = icon_parts(&icon);
        tx.execute(
            "UPDATE \"group\" SET icon_index = ?1, icon_custom_uuid = ?2 WHERE uuid = ?3",
            params![idx, custom, uuid_str],
        )?;
    }
    if let Some(expiry) = update.expires_at {
        tx.execute(
            "UPDATE \"group\" SET expires_at = ?1 WHERE uuid = ?2",
            params![expiry, uuid_str],
        )?;
    }
    tx.execute(
        "UPDATE \"group\" SET modified_at = ?1 WHERE uuid = ?2",
        params![now_ms(), uuid_str],
    )?;
    tx.commit()?;
    Ok(())
}

/// Soft-recycle a group.
///
/// Moves the group under the database's recycle bin group, if one
/// exists. Errors with [`EngineError::NotFound`] (`entity =
/// "recycle_bin"`) when the database has no bin yet — the engine
/// deliberately does not auto-create a bin; that's a frontend decision.
///
/// Direct child entries of the group remain untouched; they're
/// implicitly recycled by sitting under a recycled-ancestor branch.
/// Read paths that need to surface "is this row in the bin?" should
/// walk ancestors or consult the entry's `is_recycled` column for
/// entries moved into the bin directly.
pub(crate) fn recycle_group(conn: &mut Connection, uuid: Uuid) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !group_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "group" });
    }
    let Some(bin) = recycle_bin_uuid(&tx)? else {
        return Err(EngineError::NotFound {
            entity: "recycle_bin",
        });
    };
    if bin == uuid_str {
        // Refuse to recycle the bin itself.
        return Err(EngineError::CycleDetected);
    }
    tx.execute(
        "UPDATE \"group\" SET parent_uuid = ?1, modified_at = ?2 WHERE uuid = ?3",
        params![bin, now_ms(), uuid_str],
    )?;
    tx.commit()?;
    Ok(())
}

/// Counterpart to [`recycle_group`]. Moves the group under
/// `new_parent_uuid`. KDBX itself doesn't track the original location
/// for restore, so the caller supplies a destination.
pub(crate) fn restore_group(
    conn: &mut Connection,
    uuid: Uuid,
    new_parent_uuid: Uuid,
) -> Result<MoveGroupOutcome, EngineError> {
    move_group(conn, uuid, new_parent_uuid)
}

/// Hard-delete a group and every descendant group / entry.
///
/// The schema's group self-FK does not declare `ON DELETE CASCADE`, and
/// `entry.group_uuid` references `"group"(uuid)` without cascade either,
/// so we recursively delete children manually. Entry child tables
/// (`entry_protected`, `entry_attachment`, `entry_custom_field`,
/// `entry_history`, `entry_tag`) cascade off `entry`.
pub(crate) fn delete_group(
    conn: &mut Connection,
    uuid: Uuid,
) -> Result<DeleteGroupOutcome, EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    // Pull the target group's parent up front so the outcome carries the
    // pre-delete attachment point. `parent_uuid` is NULL only for the
    // root group.
    let previous_parent_str: Option<String> = match tx
        .query_row(
            "SELECT parent_uuid FROM \"group\" WHERE uuid = ?1",
            params![uuid_str],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
    {
        Some(p) => p,
        None => return Err(EngineError::NotFound { entity: "group" }),
    };
    let previous_parent = match previous_parent_str {
        Some(s) => Some(Uuid::parse_str(&s).map_err(|e| {
            EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?),
        None => None,
    };

    let mut outcome = DeleteGroupOutcome::default();
    delete_group_recursive(&tx, &uuid_str, previous_parent, &mut outcome)?;
    tx.commit()?;
    Ok(outcome)
}

fn delete_group_recursive(
    tx: &Transaction<'_>,
    uuid: &str,
    parent_uuid: Option<Uuid>,
    outcome: &mut DeleteGroupOutcome,
) -> Result<(), EngineError> {
    let self_uuid = Uuid::parse_str(uuid)
        .map_err(|e| EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))))?;

    // Children first so the cascade order is leaves-up.
    let children: Vec<String> = {
        let mut stmt = tx.prepare("SELECT uuid FROM \"group\" WHERE parent_uuid = ?1")?;
        stmt.query_map(params![uuid], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for child in children {
        delete_group_recursive(tx, &child, Some(self_uuid), outcome)?;
    }

    // Direct child entries — collect uuids first for the event.
    let child_entries: Vec<String> = {
        let mut stmt = tx.prepare("SELECT uuid FROM entry WHERE group_uuid = ?1")?;
        stmt.query_map(params![uuid], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for entry_uuid_str in child_entries {
        let entry_uuid = Uuid::parse_str(&entry_uuid_str).map_err(|e| {
            EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?;
        outcome.deleted_entries.push((entry_uuid, self_uuid));
    }

    tx.execute("DELETE FROM entry WHERE group_uuid = ?1", params![uuid])?;
    tx.execute("DELETE FROM \"group\" WHERE uuid = ?1", params![uuid])?;
    outcome.deleted_groups.push((self_uuid, parent_uuid));
    Ok(())
}

pub(crate) fn move_group(
    conn: &mut Connection,
    uuid: Uuid,
    new_parent_uuid: Uuid,
) -> Result<MoveGroupOutcome, EngineError> {
    let uuid_str = uuid.to_string();
    let new_parent_str = new_parent_uuid.to_string();

    if uuid_str == new_parent_str {
        return Err(EngineError::CycleDetected);
    }
    let tx = conn.transaction()?;
    let previous_parent_str: Option<String> = match tx
        .query_row(
            "SELECT parent_uuid FROM \"group\" WHERE uuid = ?1",
            params![uuid_str],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
    {
        Some(p) => p,
        None => return Err(EngineError::NotFound { entity: "group" }),
    };
    if !group_exists(&tx, &new_parent_str)? {
        return Err(EngineError::NotFound { entity: "group" });
    }
    let from_parent = match previous_parent_str {
        Some(s) => Uuid::parse_str(&s).map_err(|e| {
            EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?,
        // Root has no parent — we still need a sentinel. Use the
        // moved group's own uuid; callers shouldn't be moving the root
        // anyway, so this branch is degenerate. The cycle check below
        // will also catch the self-move.
        None => uuid,
    };

    // Walk up from new_parent; if we hit `uuid`, it's a cycle.
    let mut cursor: Option<String> = Some(new_parent_str.clone());
    while let Some(cur) = cursor {
        if cur == uuid_str {
            return Err(EngineError::CycleDetected);
        }
        cursor = tx
            .query_row(
                "SELECT parent_uuid FROM \"group\" WHERE uuid = ?1",
                params![cur],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
    }

    tx.execute(
        "UPDATE \"group\" SET parent_uuid = ?1, modified_at = ?2 WHERE uuid = ?3",
        params![new_parent_str, now_ms(), uuid_str],
    )?;
    tx.commit()?;
    Ok(MoveGroupOutcome {
        from_parent,
        to_parent: new_parent_uuid,
    })
}
