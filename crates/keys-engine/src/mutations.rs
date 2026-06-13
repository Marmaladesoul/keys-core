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

use std::collections::HashMap;

use keepass_core::protector::{FieldProtector, SessionKey, open_with_key, seal_with_key};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{EngineError, RevealError};
use crate::fingerprint;
use crate::model::{EntrySave, EntryUpdate, GroupUpdate, IconRef, NewEntryFields, NewGroupFields};
use crate::strength;
use crate::totp;

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

/// Outcome of [`reorder_group`] — carries the full ordered list of
/// sibling uuids under the affected parent so the engine can publish
/// a `GroupsReordered` event covering every row whose `sort_order`
/// just changed.
#[derive(Debug)]
pub(crate) struct ReorderGroupOutcome {
    /// All siblings under the target's parent (including the target
    /// itself) in their new `sort_order` order, lowest first.
    pub siblings_in_order: Vec<Uuid>,
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
fn recycle_bin_uuid(tx: &Connection) -> Result<Option<String>, EngineError> {
    let row = tx
        .query_row(
            "SELECT uuid FROM \"group\" WHERE is_recycle_bin = 1 LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    Ok(row)
}

/// Garbage-collect `tag` rows that no `entry_tag` row references.
///
/// Must be called inside the same transaction as a mutation that may
/// have removed the last `entry_tag` referencing a tag (i.e. `set_tags`,
/// `delete_entry`, and the `delete_group` cascade). Keeping the GC in
/// the same transaction means it can never desync from the mutation
/// that caused the orphan.
fn gc_orphan_tags(tx: &Transaction<'_>) -> Result<(), EngineError> {
    tx.execute(
        "DELETE FROM tag WHERE id NOT IN (SELECT DISTINCT tag_id FROM entry_tag)",
        [],
    )?;
    Ok(())
}

/// Garbage-collect `attachment_blob` rows nothing references — the
/// mirror-side twin of keepass-core's save-time `gc_binaries_pool` for
/// the KDBX file. Without it the pool only ever grew: remove/replace
/// left blobs in place by design (content-addressed rows are shared),
/// and deleting an entry cascaded away the links and history that
/// referenced its blobs while the bytes lingered forever.
///
/// Reference roots, all of which must survive:
/// - live `entry_attachment` links;
/// - `conflict_entry_attachment` rows — a parked conflict's divergent
///   peer bytes exist ONLY in the pool until the conflict resolves
///   (keyhole Finding #7);
/// - history-snapshot attachments (`entry_history.snapshot_json`,
///   shas stored hex). Malformed JSON and pre-widening rows (empty
///   hex) skip, matching the read side's posture.
///
/// Runs at save time ([`crate::save::save`]), transactionally, so the
/// collected set can never desync from the state being serialised.
pub(crate) fn gc_attachment_blobs(conn: &mut Connection) -> Result<u64, EngineError> {
    /// The one slice of `snapshot_json` the GC needs; serde ignores the
    /// snapshot's other fields.
    #[derive(Deserialize)]
    struct SnapshotAttachmentsOnly {
        #[serde(default)]
        attachments: Vec<HistoryAttachmentIo>,
    }

    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS gc_attachment_roots (sha BLOB PRIMARY KEY); \
         DELETE FROM gc_attachment_roots;",
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO gc_attachment_roots \
             SELECT blob_sha256 FROM entry_attachment",
        [],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO gc_attachment_roots \
             SELECT blob_sha256 FROM conflict_entry_attachment",
        [],
    )?;

    // History roots. Only the attachment list is needed; serde ignores
    // the snapshot's other fields.
    {
        let mut read = tx.prepare("SELECT snapshot_json FROM entry_history")?;
        let mut write =
            tx.prepare("INSERT OR IGNORE INTO gc_attachment_roots (sha) VALUES (?1)")?;
        let rows = read.query_map([], |r| r.get::<_, String>(0))?;
        for json in rows {
            let Ok(snap) = serde_json::from_str::<SnapshotAttachmentsOnly>(&json?) else {
                continue;
            };
            for att in snap.attachments {
                if let Some(sha) = hex_decode32(&att.sha256_hex) {
                    write.execute(params![sha.as_slice()])?;
                }
            }
        }
    }

    let removed = tx.execute(
        "DELETE FROM attachment_blob \
         WHERE sha256 NOT IN (SELECT sha FROM gc_attachment_roots)",
        [],
    )?;
    tx.commit()?;
    Ok(removed as u64)
}

/// Decode a 64-char lowercase/uppercase hex string into 32 bytes.
/// `None` on any malformation — the GC treats an undecodable root as
/// absent rather than failing the save.
fn hex_decode32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Record a `<DeletedObjects>` tombstone for `uuid` so the deletion propagates
/// cross-peer (Phase 5b). Without it a peer that still holds the object can't
/// tell "deleted here" from "never seen there" and would resurrect it on the
/// next owner-rows ingest. `INSERT OR REPLACE` stays idempotent (a live object
/// shouldn't already carry a tombstone, but re-deletion mustn't error). Shared
/// by `delete_entry` and the `delete_group` cascade so *every* removed entry
/// and group leaves a tombstone.
fn record_tombstone(tx: &Connection, uuid: &str, now: i64) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT OR REPLACE INTO meta_deleted_object (uuid, deleted_at) VALUES (?1, ?2)",
        params![uuid, now],
    )?;
    Ok(())
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

/// Push a snapshot of the **current live** state of `uuid_str` onto
/// `entry_history` at the next dense `history_index`, then prune the
/// history list against the vault's `meta.history_max_items` /
/// `meta.history_max_size` budgets.
///
/// This is the single funnel every content-mutating entry function
/// routes through. The convention is "call as the first action inside
/// the mutation's transaction, before any UPDATE/DELETE/INSERT touches
/// the entry" — that way the captured snapshot's `modified_at` is the
/// pre-edit value, and the mutation that follows is free to bump
/// `modified_at` to now via [`bump_modified`].
///
/// Pruning explicitly **skips** any existing snapshot whose JSON
/// `custom_data` carries the [`FIELD_CONFLICT_CUSTOM_DATA_KEY`] marker
/// — those records are pinned by the conflict-resolver UI and silently
/// evicting them would recreate the original "lost ancestor" bug class.
/// Concretely: with 11 marker-tagged snapshots and `history_max_items =
/// 10`, all 11 markers stay and zero unmarked records remain.
fn push_history_snapshot(tx: &Transaction<'_>, uuid_str: &str) -> Result<(), EngineError> {
    let snap = build_live_snapshot(tx, uuid_str)?;
    let json =
        serde_json::to_string(&snap).map_err(|e| EngineError::Reveal(RevealError::Json(e)))?;
    let max_idx: Option<i64> = tx
        .query_row(
            "SELECT MAX(history_index) FROM entry_history WHERE entry_uuid = ?1",
            params![uuid_str],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let next_idx = max_idx.map_or(0, |i| i + 1);
    tx.execute(
        "INSERT INTO entry_history (entry_uuid, history_index, snapshot_json) \
         VALUES (?1, ?2, ?3)",
        params![uuid_str, next_idx, json],
    )?;
    prune_history(tx, uuid_str)?;
    Ok(())
}

/// Prune `entry_history` for `uuid_str` to honour
/// `meta.history_max_items` and `meta.history_max_size`. Records carrying
/// the *legacy* parked-conflict marker
/// ([`crate::reconcile::FIELD_CONFLICT_CUSTOM_DATA_KEY`]) are always
/// retained so a cleanup pass can still find and tombstone them — the
/// hold-open redesign no longer writes the marker, but old vaults may
/// still hold one. See [`crate::reconcile::clear_parked_conflict_marker`].
///
/// Re-packs `history_index` into a dense `0..N` afterwards.
#[allow(clippy::too_many_lines)]
fn prune_history(tx: &Transaction<'_>, uuid_str: &str) -> Result<(), EngineError> {
    /// Large offset used by the dense `0..N` re-pack to avoid
    /// transient PK collisions while shifting indices.
    const SHIFT: i64 = 1_000_000_000;

    #[derive(Clone)]
    struct Row {
        history_index: i64,
        size_bytes: i64,
        is_marker: bool,
    }

    let max_items = crate::meta::read_history_max_items(tx)?;
    let max_size = crate::meta::read_history_max_size(tx)?;

    // Load all rows oldest-first with their byte size and marker flag.
    let rows: Vec<Row> = {
        let mut stmt = tx.prepare(
            "SELECT history_index, length(snapshot_json), snapshot_json \
             FROM entry_history WHERE entry_uuid = ?1 \
             ORDER BY history_index ASC",
        )?;
        let mapped = stmt.query_map(params![uuid_str], |r| {
            let idx: i64 = r.get(0)?;
            let size: i64 = r.get(1)?;
            let json: String = r.get(2)?;
            Ok((idx, size, json))
        })?;
        let mut out = Vec::new();
        for r in mapped {
            let (idx, size, json) = r?;
            // Parse just enough to detect the marker. A failed parse is
            // treated as "no marker" — defensive: a pre-shape row or a
            // corrupt blob shouldn't pin itself.
            let is_marker = serde_json::from_str::<HistorySnapshotIo>(&json).is_ok_and(|s| {
                s.custom_data
                    .iter()
                    .any(|cd| cd.key == crate::reconcile::FIELD_CONFLICT_CUSTOM_DATA_KEY)
            });
            out.push(Row {
                history_index: idx,
                size_bytes: size,
                is_marker,
            });
        }
        out
    };
    if rows.is_empty() {
        return Ok(());
    }

    // Identify which rows to drop. Strategy: walk the candidates
    // (unmarked rows) oldest-first, evicting just enough to bring the
    // surviving list under both budgets. Markers are never candidates.
    let mut survive_marker: Vec<bool> = vec![true; rows.len()]; // initially keep all
    let total_marker_size: i64 = rows
        .iter()
        .filter(|r| r.is_marker)
        .map(|r| r.size_bytes)
        .sum();
    let marker_count: i32 =
        i32::try_from(rows.iter().filter(|r| r.is_marker).count()).unwrap_or(i32::MAX);

    // Items budget: count of surviving non-marker rows + marker_count
    // must be <= max_items. Negative max_items disables the items
    // budget (matches keepass-core convention).
    let items_cap = if max_items < 0 {
        i32::MAX
    } else {
        // Non-marker rows we may keep:
        (max_items - marker_count).max(0)
    };
    // Size budget: surviving total bytes must be <= max_size.
    // Negative max_size disables. If markers alone exceed the budget,
    // we can't do anything about it — we still retain them.
    let size_cap_remaining: i64 = if max_size < 0 {
        i64::MAX
    } else {
        (max_size - total_marker_size).max(0)
    };

    // Walk newest-first picking unmarked rows to keep, evicting the
    // rest. Keep at most `items_cap` unmarked rows, and keep adding
    // their sizes only while we stay under `size_cap_remaining`.
    let mut kept_unmarked: i32 = 0;
    let mut kept_size: i64 = 0;
    for i in (0..rows.len()).rev() {
        if rows[i].is_marker {
            continue;
        }
        let next_kept_size = kept_size.saturating_add(rows[i].size_bytes);
        if kept_unmarked < items_cap && next_kept_size <= size_cap_remaining {
            kept_unmarked += 1;
            kept_size = next_kept_size;
        } else {
            survive_marker[i] = false;
        }
    }

    // Apply: delete dropped rows, then re-pack indices on survivors.
    let to_delete: Vec<i64> = rows
        .iter()
        .enumerate()
        .filter_map(|(i, r)| (!survive_marker[i]).then_some(r.history_index))
        .collect();
    if to_delete.is_empty() {
        return Ok(());
    }
    for idx in &to_delete {
        tx.execute(
            "DELETE FROM entry_history WHERE entry_uuid = ?1 AND history_index = ?2",
            params![uuid_str, idx],
        )?;
    }
    // Re-pack survivors to a dense `0..N` ordered by their original
    // history_index. Two-step rename via a large offset avoids transient
    // PK collisions: shift everything way up, then back down to the new
    // dense indices.
    tx.execute(
        "UPDATE entry_history SET history_index = history_index + ?1 \
         WHERE entry_uuid = ?2",
        params![SHIFT, uuid_str],
    )?;
    let survivor_indices: Vec<i64> = rows
        .iter()
        .enumerate()
        .filter_map(|(i, r)| survive_marker[i].then_some(r.history_index + SHIFT))
        .collect();
    for (new_idx, old_shifted) in survivor_indices.iter().enumerate() {
        let new_idx_i64 = i64::try_from(new_idx).unwrap_or(i64::MAX);
        tx.execute(
            "UPDATE entry_history SET history_index = ?1 \
             WHERE entry_uuid = ?2 AND history_index = ?3",
            params![new_idx_i64, uuid_str, old_shifted],
        )?;
    }
    Ok(())
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
    now: i64,
    new_uuid: Uuid,
) -> Result<Uuid, EngineError> {
    let session = session_key(protector)?;
    let entry_uuid = new_uuid;
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
    let has_totp = totp::url_is_otpauth(&fields.url)
        || fields
            .custom_fields
            .iter()
            .any(|cf| totp::is_totp_field(&cf.name));

    tx.execute(
        "INSERT INTO entry (\
            uuid, group_uuid, title, username, url, url_host, notes, \
            icon_index, icon_custom_uuid, created_at, modified_at, \
            accessed_at, last_used_at, expires_at, \
            password_strength_bucket, password_entropy, password_fingerprint, \
            is_recycled, has_totp\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, 0, ?18)",
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
            i64::from(has_totp),
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
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }

    // One history snapshot per logical edit — capture pre-edit state
    // before any field mutates. See [`push_history_snapshot`] for the
    // invariant.
    push_history_snapshot(&tx, &uuid_str)?;

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
    let mut url_changed = false;
    if let Some(url) = update.url {
        let host = parse_host(&url);
        tx.execute(
            "UPDATE entry SET url = ?1, url_host = ?2 WHERE uuid = ?3",
            params![url, host, uuid_str],
        )?;
        url_changed = true;
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

    if url_changed {
        recompute_has_totp(&tx, &uuid_str)?;
    }
    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

/// Apply the full desired state of an entry in ONE transaction with
/// EXACTLY ONE history snapshot.
///
/// This is the engine's single funnel for the entry editor's "Save".
/// It replaces the old Swift-orchestrated sequence of per-field
/// mutations (`update_entry` + `set_tags` + per-field
/// `set_*_custom_field` + `remove_custom_field` …) — each of which
/// pushed its OWN `push_history_snapshot` — so one logical save now
/// archives exactly one `<History>` record regardless of custom-field
/// count.
///
/// Behaviour:
/// - Takes a single [`push_history_snapshot`] of the pre-save state up
///   front, then writes the new columns directly. It does NOT call any
///   of the per-field archiving mutations (they'd each re-archive).
/// - Standard fields (title/username/url/notes/password), icon, expiry,
///   strength/fingerprint columns and `url_host` are overwritten.
/// - The canonical Password slot is always re-wrapped under a fresh
///   session key.
/// - The custom-field set is applied as a **replace-all**: every
///   `entry_protected` (except the canonical Password slot, re-written
///   here) and `entry_custom_field` row is dropped and re-inserted from
///   `save.custom_fields`. Fields absent from the set are therefore
///   removed — this retires the editor's explicit removal bookkeeping.
/// - Tags are applied with set-semantics (delete-all + re-insert + GC).
/// - `has_totp` is recomputed from the final URL + field set.
///
/// **Idempotency.** Every call is treated as a user-initiated save: it
/// unconditionally archives ONE snapshot and bumps `modified_at`. It
/// does NOT diff against the current state, so re-saving identical
/// state still archives exactly one snapshot. This is the deliberate
/// "one snapshot per save" contract (chosen over a dedup heuristic) so
/// the invariant stays simple and predictable across clients.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
pub(crate) fn save_entry(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    uuid: Uuid,
    save: EntrySave,
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let session = session_key(protector)?;
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }

    // One snapshot of the pre-save state, captured before any field
    // mutates — see [`push_history_snapshot`] for the invariant.
    push_history_snapshot(&tx, &uuid_str)?;

    // ── Standard columns + derived password columns ──
    let url_host = parse_host(&save.url);
    let (icon_index, icon_custom_uuid) = icon_parts(&save.icon);
    let pw_plain = save.password.expose_secret();
    let (bucket, entropy, fp) = password_columns(pw_plain, fingerprint_key);
    let fp_param: Option<&[u8]> = fp.as_ref().map(|b| &b[..]);
    tx.execute(
        "UPDATE entry SET \
            title = ?1, username = ?2, url = ?3, url_host = ?4, notes = ?5, \
            icon_index = ?6, icon_custom_uuid = ?7, expires_at = ?8, \
            password_strength_bucket = ?9, password_entropy = ?10, \
            password_fingerprint = ?11 \
         WHERE uuid = ?12",
        params![
            save.title,
            save.username,
            save.url,
            url_host,
            save.notes,
            icon_index,
            icon_custom_uuid,
            save.expires_at,
            i64::from(bucket),
            entropy,
            fp_param,
            uuid_str,
        ],
    )?;

    // ── Custom fields: replace-all ──
    // Drop every protected + non-protected row, then re-write the
    // canonical Password slot followed by the desired custom-field set.
    tx.execute(
        "DELETE FROM entry_protected WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    tx.execute(
        "DELETE FROM entry_custom_field WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    let wrapped_pw = wrap(&session, pw_plain.as_bytes())?;
    tx.execute(
        "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
         VALUES (?1, ?2, ?3)",
        params![uuid_str, PASSWORD_FIELD, wrapped_pw],
    )?;
    for cf in &save.custom_fields {
        if cf.protected {
            if cf.name == PASSWORD_FIELD {
                // Never shadow the canonical Password slot — matches the
                // ingest / `create_entry` policy.
                continue;
            }
            let wrapped = wrap(&session, cf.value.expose_secret().as_bytes())?;
            tx.execute(
                "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(entry_uuid, field_name) DO UPDATE SET wrapped_blob = excluded.wrapped_blob",
                params![uuid_str, cf.name, wrapped],
            )?;
        } else {
            tx.execute(
                "INSERT INTO entry_custom_field (entry_uuid, field_name, value) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(entry_uuid, field_name) DO UPDATE SET value = excluded.value",
                params![uuid_str, cf.name, cf.value.expose_secret()],
            )?;
        }
    }

    // ── Tags: set-semantics ──
    tx.execute(
        "DELETE FROM entry_tag WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    insert_tags(&tx, &uuid_str, &save.tags)?;
    gc_orphan_tags(&tx)?;

    // ── Derived bit + modified stamp ──
    recompute_has_totp(&tx, &uuid_str)?;
    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

fn bump_modified(tx: &Transaction<'_>, uuid: &str, now: i64) -> Result<(), EngineError> {
    tx.execute(
        "UPDATE entry SET modified_at = ?1 WHERE uuid = ?2",
        params![now, uuid],
    )?;
    Ok(())
}

/// Recompute `entry.has_totp` for a single entry from its current
/// URL and custom-field set. Call after any mutation that can flip
/// the bit: protected-field add/remove, non-protected-field
/// add/remove, or URL change. See [`crate::totp`] for the detection
/// convention.
fn recompute_has_totp(tx: &Transaction<'_>, uuid: &str) -> Result<(), EngineError> {
    // Read current URL + field names, then write the recomputed bit
    // in one UPDATE. Doing it Rust-side (rather than a compound SQL
    // expression) keeps the detection rule in one place — the
    // [`crate::totp`] helpers — so the migration backfill, ingest,
    // and live mutations all derive `has_totp` from the same source
    // of truth.
    let url: String = tx.query_row(
        "SELECT url FROM entry WHERE uuid = ?1",
        params![uuid],
        |r| r.get(0),
    )?;
    let mut has = totp::url_is_otpauth(&url);
    if !has {
        let mut stmt = tx.prepare(
            "SELECT field_name FROM entry_protected WHERE entry_uuid = ?1 \
             UNION ALL \
             SELECT field_name FROM entry_custom_field WHERE entry_uuid = ?1",
        )?;
        let mut rows = stmt.query(params![uuid])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            if totp::is_totp_field(&name) {
                has = true;
                break;
            }
        }
    }
    tx.execute(
        "UPDATE entry SET has_totp = ?1 WHERE uuid = ?2",
        params![i64::from(has), uuid],
    )?;
    Ok(())
}

/// Clear `entry.icon_custom_uuid` for a single entry, returning the
/// entry to its built-in icon (`icon_index`, which is left unchanged —
/// it's the orthogonal fallback slot per KDBX semantics, see
/// `keepass_core::model::entry_editor::EntryEditor::set_custom_icon`).
///
/// Does **not** touch `meta_custom_icon`: the blob may still be
/// referenced by other entries or groups. The Phase 5 "save-path GC
/// silently resets dangling refs" invariant means a stale ref would
/// be a no-op at save time anyway, but the engine's stricter model
/// prefers to clear the column explicitly so projection round-trips
/// match.
pub(crate) fn clear_entry_custom_icon(
    conn: &mut Connection,
    uuid: Uuid,
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    push_history_snapshot(&tx, &uuid_str)?;
    tx.execute(
        "UPDATE entry SET icon_custom_uuid = NULL WHERE uuid = ?1",
        params![uuid_str],
    )?;
    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

/// Link a fetched favicon to an entry as its custom icon WITHOUT
/// archiving a history snapshot or bumping `modified_at`. A favicon is
/// automatic cosmetic enrichment, not a user edit — it must not clutter
/// the entry's `<History>` or move its "last modified" time. (The
/// user-driven icon picker goes through [`update_entry`], which *does*
/// archive + bump, because hand-choosing an icon IS a real edit.)
/// `icon_index` is left untouched — the orthogonal built-in fallback
/// slot per KDBX semantics.
pub(crate) fn link_entry_custom_icon(
    conn: &mut Connection,
    uuid: Uuid,
    icon_uuid: Uuid,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    tx.execute(
        "UPDATE entry SET icon_custom_uuid = ?1 WHERE uuid = ?2",
        params![icon_uuid.to_string(), uuid_str],
    )?;
    tx.commit()?;
    Ok(())
}

/// Bump `entry.last_used_at` to now. Mirrors the legacy
/// `Vault::touch_entry` contract: nothing else on the entry changes
/// (no `modified_at` bump, no history snapshot), so the touch reads
/// as a benign last-access stamp rather than a real edit. The engine
/// emits [`crate::ChangeEvent::EntryTouched`] for this rather than
/// [`crate::ChangeEvent::EntriesUpdated`].
pub(crate) fn touch_entry(conn: &mut Connection, uuid: Uuid, now: i64) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    tx.execute(
        "UPDATE entry SET last_used_at = ?1 WHERE uuid = ?2",
        params![now, uuid_str],
    )?;
    tx.commit()?;
    Ok(())
}

/// Set `entry.last_used_at` back to NULL. User-driven explicit clear
/// from the entry-detail editor (e.g. "this `AutoFill` match shouldn't
/// have shown up in recents"). Like [`touch_entry`], does NOT bump
/// `modified_at`.
pub(crate) fn clear_entry_last_access(
    conn: &mut Connection,
    uuid: Uuid,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    tx.execute(
        "UPDATE entry SET last_used_at = NULL WHERE uuid = ?1",
        params![uuid_str],
    )?;
    tx.commit()?;
    Ok(())
}

/// Configure the recycle-bin policy. Mirrors
/// `keepass_core::Kdbx::set_recycle_bin`: writes both `enabled` and
/// the bin-group designation atomically, in a single transaction.
///
/// `group_uuid = Some(uuid)` designates that group as the bin (and
/// clears the flag on any previously-designated bin — the schema
/// permits only one bin per vault). `group_uuid = None` clears the
/// bin designation entirely.
///
/// Returns [`EngineError::NotFound`] (`entity = "group"`) if
/// `group_uuid` is Some but no matching group row exists. The check
/// runs inside the transaction so a concurrent delete can't slip
/// between validation and the flag write.
pub(crate) fn set_recycle_bin(
    conn: &mut Connection,
    enabled: bool,
    group_uuid: Option<Uuid>,
) -> Result<(), EngineError> {
    let tx = conn.transaction()?;
    if let Some(uuid) = group_uuid {
        let uuid_str = uuid.to_string();
        if !group_exists(&tx, &uuid_str)? {
            return Err(EngineError::NotFound { entity: "group" });
        }
        crate::meta::write_recycle_bin_group(&tx, &uuid_str)?;
    } else {
        crate::meta::clear_recycle_bin_group(&tx)?;
    }
    crate::meta::write_recycle_bin_enabled(&tx, enabled)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn recycle_entry(
    conn: &mut Connection,
    uuid: Uuid,
    now: i64,
    bin_uuid: Uuid,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }

    // Recycling an entry that is already in the bin subtree is a no-op.
    // Without this guard a double-recycle would clobber
    // `previous_parent_uuid` with the bin itself, permanently losing the
    // entry's true origin — `restore_entry` would then "restore" it INTO
    // the Trash. (Adversarial-review catch on the 0008 work.)
    let current_group: String = tx.query_row(
        "SELECT group_uuid FROM entry WHERE uuid = ?1",
        params![uuid_str],
        |r| r.get(0),
    )?;
    if group_in_bin_subtree(&tx, &current_group)? {
        tx.commit()?;
        return Ok(());
    }

    // Resolve the bin group, lazily creating it when the vault has the
    // recycle bin *enabled* but no bin group exists yet. This mirrors
    // keepass-core's `Kdbx::recycle_entry` / `find_or_create_recycle_bin`
    // (the canonical KDBX model) and the contract the rest of this module
    // already assumes — see `meta::clear_recycle_bin_group`, whose docs
    // state "recycle_entry will lazily create one". Without this, the
    // first recycle on any enabled-but-binless vault (a fresh vault, or
    // one created by keepassxc-cli) silently *permanently* deleted the
    // entry under a "Move to Trash" label.
    let bin = match recycle_bin_uuid(&tx)? {
        Some(bin) => Some(bin),
        None if crate::meta::read_recycle_bin_enabled(&tx)? => {
            Some(create_recycle_bin_group(&tx, now, bin_uuid)?)
        }
        None => None,
    };

    if let Some(bin) = bin {
        // Record where the entry came from (KDBX 4.1
        // <PreviousParentGroup>) so restore can put it back.
        tx.execute(
            "UPDATE entry SET is_recycled = 1, previous_parent_uuid = group_uuid, \
             group_uuid = ?1, modified_at = ?2, location_changed_at = ?2 \
             WHERE uuid = ?3",
            params![bin, now, uuid_str],
        )?;
    } else {
        // Recycle bin genuinely disabled and none exists. KeePass semantics
        // make a delete here *permanent*: a soft `is_recycled` flag has no
        // KDBX representation without a bin group, so it would neither
        // persist nor sync nor be emptyable — the entry would strand
        // (deleted in the UI, untouched on disk + on peers). Hard-delete +
        // tombstone instead, so the removal persists and propagates to
        // peers (Phase 5b). Child rows cascade on entry delete.
        tx.execute("DELETE FROM entry WHERE uuid = ?1", params![uuid_str])?;
        gc_orphan_tags(&tx)?;
        record_tombstone(&tx, &uuid_str, now)?;
    }
    tx.commit()?;
    Ok(())
}

/// Create the canonical "Recycle Bin" group at the vault root, flag it as
/// the bin, and record it in meta (enabled + designation). Returns the new
/// group UUID. Mirrors keepass-core's `find_or_create_recycle_bin` — same
/// name and icon (43) — so a bin created here is indistinguishable from one
/// the model layer would mint, and projects/syncs identically.
fn create_recycle_bin_group(
    tx: &Transaction<'_>,
    now: i64,
    bin_uuid: Uuid,
) -> Result<String, EngineError> {
    let root_uuid: String = tx.query_row(
        "SELECT uuid FROM \"group\" WHERE parent_uuid IS NULL LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    let new_uuid = bin_uuid.to_string();
    let next_sort_order: i64 = tx.query_row(
        "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM \"group\" WHERE parent_uuid = ?1",
        params![root_uuid],
        |r| r.get(0),
    )?;
    // is_recycle_bin starts 0 here; `write_recycle_bin_group` sets it to 1
    // (and clears the flag on any prior bin — the one-bin invariant).
    tx.execute(
        "INSERT INTO \"group\" (\
            uuid, parent_uuid, name, icon_index, icon_custom_uuid, notes, \
            created_at, modified_at, expires_at, is_recycle_bin, sort_order\
         ) VALUES (?1, ?2, 'Recycle Bin', 43, NULL, '', ?3, ?3, NULL, 0, ?4)",
        params![new_uuid, root_uuid, now, next_sort_order],
    )?;
    crate::meta::write_recycle_bin_group(tx, &new_uuid)?;
    crate::meta::write_recycle_bin_enabled(tx, true)?;
    Ok(new_uuid)
}

/// Ensure a recycle bin group exists when the bin is enabled but none is
/// present. Idempotent: a no-op when a bin already exists or the bin is
/// disabled. Returns the bin's uuid if one exists/was created, else `None`.
///
/// Called when a vault is first added so Keys never carries an
/// enabled-but-binless vault into normal use — fixing the bin's uuid up
/// front (before sync) avoids two peers each lazily minting their own bin.
/// `recycle_entry`'s lazy-create remains the last-ditch safety net.
pub(crate) fn ensure_recycle_bin(
    conn: &mut Connection,
    now: i64,
    bin_uuid: Uuid,
) -> Result<Option<String>, EngineError> {
    let tx = conn.transaction()?;
    let bin = match recycle_bin_uuid(&tx)? {
        Some(bin) => Some(bin),
        None if crate::meta::read_recycle_bin_enabled(&tx)? => {
            Some(create_recycle_bin_group(&tx, now, bin_uuid)?)
        }
        None => None,
    };
    tx.commit()?;
    Ok(bin)
}

/// Restore a recycled entry: clear `is_recycled` AND move it out of
/// the bin group — back to its recorded previous parent
/// (KDBX 4.1 `<PreviousParentGroup>`, written by `recycle_entry`) when
/// that group still exists, else to the vault root. Restore is itself
/// a relocation, so the bin becomes the new previous parent. Matches
/// `KeePassXC`'s restore semantics.
///
/// Found by keyhole's `restore-leaves-bin.sh`: the original
/// implementation only cleared the flag, leaving a "restored" entry
/// still sitting in the Trash for every group-scoped view and every
/// other KDBX client.
pub(crate) fn restore_entry(
    conn: &mut Connection,
    uuid: Uuid,
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }

    let (current_group, previous): (String, Option<String>) = tx.query_row(
        "SELECT group_uuid, previous_parent_uuid FROM entry WHERE uuid = ?1",
        params![uuid_str],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    if !group_in_bin_subtree(&tx, &current_group)? {
        // Not in the Trash. Restoring a live entry must not relocate it
        // (an earlier draft would have bounced it to its previous parent
        // or even the root — adversarial-review catch). Clear a stale
        // `is_recycled` flag if one survives from an older mirror, but
        // leave the entry where it lives.
        tx.execute(
            "UPDATE entry SET is_recycled = 0 WHERE uuid = ?1 AND is_recycled = 1",
            params![uuid_str],
        )?;
        tx.commit()?;
        return Ok(());
    }

    // Destination: the recorded previous parent (KDBX 4.1
    // <PreviousParentGroup>, written by recycle_entry) when it still
    // exists AND is not itself in the Trash subtree — restoring "back"
    // into the bin is no restore at all. Otherwise the vault root, the
    // one group guaranteed to exist (KeePassXC does the same).
    let destination = match previous {
        Some(prev) if group_exists(&tx, &prev)? && !group_in_bin_subtree(&tx, &prev)? => prev,
        _ => tx.query_row(
            "SELECT uuid FROM \"group\" WHERE parent_uuid IS NULL LIMIT 1",
            [],
            |r| r.get(0),
        )?,
    };
    tx.execute(
        "UPDATE entry SET is_recycled = 0, previous_parent_uuid = group_uuid, \
         group_uuid = ?1, modified_at = ?2, location_changed_at = ?2 WHERE uuid = ?3",
        params![destination, now, uuid_str],
    )?;
    tx.commit()?;
    Ok(())
}

/// Is `group_uuid` the recycle bin or anywhere inside its subtree?
/// Walks the parent chain; the depth guard makes a corrupt (cyclic)
/// parent graph terminate rather than spin.
pub(crate) fn group_in_bin_subtree(tx: &Connection, group_uuid: &str) -> Result<bool, EngineError> {
    let Some(bin) = recycle_bin_uuid(tx)? else {
        return Ok(false);
    };
    let mut cur = Some(group_uuid.to_owned());
    for _ in 0..10_000 {
        let Some(g) = cur else { return Ok(false) };
        if g == bin {
            return Ok(true);
        }
        cur = tx
            .query_row(
                "SELECT parent_uuid FROM \"group\" WHERE uuid = ?1",
                params![g],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
    }
    debug_assert!(false, "group parent chain exceeded 10k — cycle?");
    Ok(false)
}

pub(crate) fn delete_entry(
    conn: &mut Connection,
    uuid: Uuid,
    now: i64,
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
    gc_orphan_tags(&tx)?;
    record_tombstone(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(DeleteEntryOutcome { previous_group })
}

pub(crate) fn move_entry(
    conn: &mut Connection,
    uuid: Uuid,
    new_group_uuid: Uuid,
    now: i64,
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
    // Any relocation records the source group (KDBX 4.1
    // <PreviousParentGroup>), matching KeePassXC's behaviour on move.
    // `is_recycled` follows the destination: a move into the Trash
    // subtree IS a recycle, a move out IS a restore — leaving the flag
    // stale would lie to every flag-scoped read until the next ingest
    // re-derived it from ancestry. (Adversarial-review catch.)
    let dest_in_bin = group_in_bin_subtree(&tx, &group_str)?;
    // Stamp <LocationChanged> (5d sync LWW key) — a move is a location
    // event, distinct from a content edit. `modified_at` is also
    // bumped (pre-existing behaviour); the content hash is unchanged by
    // a pure move, so field merge is unaffected either way.
    tx.execute(
        "UPDATE entry SET previous_parent_uuid = group_uuid, group_uuid = ?1, \
         is_recycled = ?2, modified_at = ?3, location_changed_at = ?3 WHERE uuid = ?4",
        params![group_str, i64::from(dest_in_bin), now, uuid_str],
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
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let session = session_key(protector)?;
    let wrapped = wrap(&session, plaintext.expose_secret().as_bytes())?;

    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    push_history_snapshot(&tx, &uuid_str)?;
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
    } else if totp::is_totp_field(field_name) {
        // Adding/replacing a recognised TOTP-bearing protected field
        // flips `has_totp` on. Recompute rather than blindly setting
        // to 1 so the helper stays the single source of truth.
        recompute_has_totp(&tx, &uuid_str)?;
    }

    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn set_non_protected_custom_field(
    conn: &mut Connection,
    uuid: Uuid,
    field_name: &str,
    value: &str,
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    push_history_snapshot(&tx, &uuid_str)?;
    tx.execute(
        "INSERT INTO entry_custom_field (entry_uuid, field_name, value) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(entry_uuid, field_name) DO UPDATE SET value = excluded.value",
        params![uuid_str, field_name, value],
    )?;
    if totp::is_totp_field(field_name) {
        recompute_has_totp(&tx, &uuid_str)?;
    }
    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn remove_custom_field(
    conn: &mut Connection,
    uuid: Uuid,
    field_name: &str,
    now: i64,
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
    push_history_snapshot(&tx, &uuid_str)?;
    tx.execute(
        "DELETE FROM entry_protected WHERE entry_uuid = ?1 AND field_name = ?2",
        params![uuid_str, field_name],
    )?;
    tx.execute(
        "DELETE FROM entry_custom_field WHERE entry_uuid = ?1 AND field_name = ?2",
        params![uuid_str, field_name],
    )?;
    if totp::is_totp_field(field_name) {
        recompute_has_totp(&tx, &uuid_str)?;
    }
    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn set_tags(
    conn: &mut Connection,
    uuid: Uuid,
    tags: Vec<String>,
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    // Compare current vs requested as a normalised, deduped set.
    // A no-op set (same logical contents) must NOT push history —
    // user intent didn't change anything KDBX-observable.
    let mut current: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT t.name FROM entry_tag et \
             JOIN tag t ON t.id = et.tag_id \
             WHERE et.entry_uuid = ?1",
        )?;
        let rows = stmt.query_map(params![uuid_str], |r| r.get::<_, String>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    current.sort();
    current.dedup();
    let mut normalised_new: Vec<String> = tags
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    normalised_new.sort();
    normalised_new.dedup();
    let changed = current != normalised_new;
    if changed {
        push_history_snapshot(&tx, &uuid_str)?;
    }
    tx.execute(
        "DELETE FROM entry_tag WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    insert_tags(&tx, &uuid_str, &tags)?;
    if changed {
        bump_modified(&tx, &uuid_str, now)?;
    }
    gc_orphan_tags(&tx)?;
    tx.commit()?;
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn attach_file(
    conn: &mut Connection,
    uuid: Uuid,
    name: &str,
    bytes: Vec<u8>,
    now: i64,
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
    push_history_snapshot(&tx, &uuid_str)?;
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
    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

/// Delete a single history snapshot from an entry.
///
/// Removes the row at `(entry_uuid, history_index)` from `entry_history`
/// and re-numbers the surviving snapshots so `history_index` stays a
/// dense `0..N` sequence (matching what [`crate::ingest`] writes on a
/// fresh load and what the [`crate::reads::history`] reader expects).
///
/// Deleting a history snapshot is bookkeeping, not a content edit on the
/// live entry — `entry.modified_at` is **not** bumped, mirroring the
/// legacy `Vault::delete_history_at` semantics
/// (`HistoryPolicy::NoSnapshot` in `keepass_core`).
///
/// # Errors
///
/// - [`EngineError::NotFound`] (`entity = "entry"`) if the entry uuid
///   isn't in `entry`.
/// - [`EngineError::NotFound`] (`entity = "history_snapshot"`) if the
///   index is outside `0..N` for that entry's history.
pub(crate) fn delete_history_at(
    conn: &mut Connection,
    uuid: Uuid,
    history_index: u32,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    let removed = tx.execute(
        "DELETE FROM entry_history \
         WHERE entry_uuid = ?1 AND history_index = ?2",
        params![uuid_str, i64::from(history_index)],
    )?;
    if removed == 0 {
        return Err(EngineError::NotFound {
            entity: "history_snapshot",
        });
    }
    // Re-pack `history_index` so the remaining rows stay dense. Shift
    // every row whose index sat above the deleted slot down by one. The
    // PRIMARY KEY on `(entry_uuid, history_index)` makes this a no-op
    // for empty-tail deletes (nothing matched the WHERE) and a
    // single-pass renumber otherwise.
    tx.execute(
        "UPDATE entry_history \
         SET history_index = history_index - 1 \
         WHERE entry_uuid = ?1 AND history_index > ?2",
        params![uuid_str, i64::from(history_index)],
    )?;
    tx.commit()?;
    Ok(())
}

/// Restore an entry to the state captured in one of its history
/// snapshots, preserving the snapshot in the history list and pushing
/// the pre-restore live state as a brand new snapshot at the tail.
///
/// Mirrors the legacy `Vault::restore_entry_from_history` /
/// `keepass_core::Kdbx::restore_entry_from_history` contract under
/// `HistoryPolicy::Snapshot`:
///
/// * Snapshot at `history_index` is **cloned** out (not consumed); the
///   list grows by one and the targeted snapshot stays put.
/// * A fresh snapshot capturing the **pre-restore live entry** is
///   appended at the tail (`history_index = old_max + 1`). Future
///   undoes can return to that pre-restore state.
/// * The live `entry` row is overwritten field-by-field from the
///   snapshot (title, username, url, notes, icon, tags, attachments,
///   custom fields, protected fields, timestamps).
/// * `modified_at` is bumped to `now()` — the restore is a real
///   content edit. `created_at`, `accessed_at`, `last_used_at`,
///   `expires_at` are restored verbatim from the snapshot.
/// * Derived columns are recomputed from the restored content:
///   `password_strength_bucket`, `password_entropy`,
///   `password_fingerprint`, `url_host`, `has_totp`.
/// * Optional inline `history_max_items` trim drops oldest snapshots
///   first (matching `keepass_core::truncate_history`'s item-budget
///   pass). `history_max_size` is left to the next round-trip through
///   keepass-core's save path — the engine doesn't model serialised
///   byte budgets here.
///
/// Protected-field wrapping reuses the bytes already in the snapshot
/// JSON: those blobs were sealed under the engine's session key at
/// ingest time, and the current `entry_protected` rows are sealed
/// under that same key, so a verbatim copy keeps the cipher chain
/// intact. The password plaintext is briefly unwrapped (held in a
/// `Zeroizing` buffer that wipes on drop) only to compute the new
/// `password_fingerprint` HMAC, which needs plaintext bytes.
///
/// # Errors
///
/// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry with
///   that uuid exists.
/// - [`EngineError::NotFound`] (`entity = "history_snapshot"`) if
///   `history_index` is outside `0..N` for that entry's history.
/// - [`EngineError::Reveal`] / [`EngineError::Wrap`] /
///   [`EngineError::SessionKey`] on protector failure.
/// - [`EngineError::Sqlite`] on storage failure.
#[allow(clippy::too_many_lines)]
pub(crate) fn restore_entry_from_history(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    uuid: Uuid,
    history_index: u32,
    history_max_items: i32,
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let session = session_key(protector)?;
    let tx = conn.transaction()?;

    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }

    // ── 1. Load the target snapshot JSON ─────────────────────────────
    let target_json: Option<String> = tx
        .query_row(
            "SELECT snapshot_json FROM entry_history \
             WHERE entry_uuid = ?1 AND history_index = ?2",
            params![uuid_str, i64::from(history_index)],
            |r| r.get(0),
        )
        .optional()?;
    let Some(target_json) = target_json else {
        return Err(EngineError::NotFound {
            entity: "history_snapshot",
        });
    };
    let snap: HistorySnapshotIo = serde_json::from_str(&target_json)
        .map_err(|e| EngineError::Reveal(RevealError::Json(e)))?;

    // ── 2. Capture pre-restore live state as a new snapshot ──────────
    let pre_restore = build_live_snapshot(&tx, &uuid_str)?;
    let pre_restore_json = serde_json::to_string(&pre_restore)
        .map_err(|e| EngineError::Reveal(RevealError::Json(e)))?;

    // ── 3. Unwrap snapshot password to recompute derived columns ─────
    let wrapped_pw_bytes =
        b64_decode(&snap.password).map_err(|e| EngineError::Reveal(RevealError::Unwrap(e)))?;
    let pw_plain = open_with_key(&session, &wrapped_pw_bytes)
        .map(Zeroizing::new)
        .map_err(|e| EngineError::Reveal(RevealError::Unwrap(e.to_string())))?;
    let pw_plain_str = std::str::from_utf8(&pw_plain).map_err(|e| {
        EngineError::Reveal(RevealError::Unwrap(format!("non-utf8 plaintext: {e}")))
    })?;
    let (bucket, entropy, fp) = password_columns(pw_plain_str, fingerprint_key);
    let fp_param: Option<&[u8]> = fp.as_ref().map(|b| &b[..]);

    // ── 4. Overwrite the live entry row ──────────────────────────────
    let url_host = parse_host(&snap.url);
    let icon_index_i64 = snap.icon_index.map(i64::from);
    tx.execute(
        "UPDATE entry SET \
            title = ?1, username = ?2, url = ?3, url_host = ?4, notes = ?5, \
            icon_index = ?6, icon_custom_uuid = ?7, \
            created_at = ?8, modified_at = ?9, accessed_at = ?10, \
            last_used_at = ?11, expires_at = ?12, \
            password_strength_bucket = ?13, password_entropy = ?14, password_fingerprint = ?15 \
         WHERE uuid = ?16",
        params![
            snap.title,
            snap.username,
            snap.url,
            url_host,
            snap.notes,
            icon_index_i64,
            snap.icon_custom_uuid,
            snap.created_at,
            now,
            snap.accessed_at,
            snap.last_used_at,
            snap.expires_at,
            i64::from(bucket),
            entropy,
            fp_param,
            uuid_str,
        ],
    )?;

    // ── 5. Replace entry_protected with the snapshot's set ───────────
    tx.execute(
        "DELETE FROM entry_protected WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    // Canonical Password slot — wrapped bytes copied verbatim from the
    // snapshot (sealed under the same session key as live entries).
    tx.execute(
        "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
         VALUES (?1, ?2, ?3)",
        params![uuid_str, PASSWORD_FIELD, wrapped_pw_bytes],
    )?;
    drop(pw_plain);
    drop(session);

    // ── 6. Replace entry_custom_field + protected custom fields ──────
    tx.execute(
        "DELETE FROM entry_custom_field WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    for (name, cf) in &snap.custom_fields {
        if name == PASSWORD_FIELD {
            // Mirrors ingest / create_entry policy: never duplicate the
            // canonical Password slot via a custom-field row.
            continue;
        }
        if cf.protected {
            let bytes =
                b64_decode(&cf.value).map_err(|e| EngineError::Reveal(RevealError::Unwrap(e)))?;
            tx.execute(
                "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
                 VALUES (?1, ?2, ?3)",
                params![uuid_str, name, bytes],
            )?;
        } else {
            tx.execute(
                "INSERT INTO entry_custom_field (entry_uuid, field_name, value) \
                 VALUES (?1, ?2, ?3)",
                params![uuid_str, name, cf.value],
            )?;
        }
    }

    // ── 7. Replace entry_attachment links via sha256_hex resolution ──
    tx.execute(
        "DELETE FROM entry_attachment WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    for att in &snap.attachments {
        if att.sha256_hex.is_empty() {
            // Pre-widening snapshot row — bytes can't be resolved.
            // Skip rather than insert a dangling row.
            continue;
        }
        let Some(sha_bytes) = hex_to_bytes(&att.sha256_hex) else {
            continue;
        };
        // Confirm the blob still lives in attachment_blob. Skip if it
        // was GC'd out from under us — the alternative is a FK violation
        // that aborts the whole restore.
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM attachment_blob WHERE sha256 = ?1",
                params![sha_bytes],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !exists {
            continue;
        }
        tx.execute(
            "INSERT INTO entry_attachment (entry_uuid, attachment_name, blob_sha256) \
             VALUES (?1, ?2, ?3)",
            params![uuid_str, att.name, sha_bytes],
        )?;
    }

    // ── 8. Replace entry_tag set ─────────────────────────────────────
    tx.execute(
        "DELETE FROM entry_tag WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    insert_tags(&tx, &uuid_str, &snap.tags)?;

    // ── 9. Recompute has_totp from the freshly restored state ────────
    recompute_has_totp(&tx, &uuid_str)?;

    // ── 10. Append pre-restore snapshot at the tail ──────────────────
    let max_idx: Option<i64> = tx
        .query_row(
            "SELECT MAX(history_index) FROM entry_history WHERE entry_uuid = ?1",
            params![uuid_str],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let next_idx = max_idx.map_or(0, |i| i + 1);
    tx.execute(
        "INSERT INTO entry_history (entry_uuid, history_index, snapshot_json) \
         VALUES (?1, ?2, ?3)",
        params![uuid_str, next_idx, pre_restore_json],
    )?;

    // ── 11. Trim oldest snapshots if history_max_items is exceeded ───
    // Matches the item-count budget pass in
    // `keepass_core::truncate_history`. Size budget is intentionally
    // left to the next save/round-trip — modelling serialised XML
    // bytes from inside the engine duplicates keepass-core's logic
    // and is brittle in the face of format changes.
    if history_max_items >= 0 {
        let cap = i64::from(history_max_items);
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM entry_history WHERE entry_uuid = ?1",
            params![uuid_str],
            |r| r.get(0),
        )?;
        if count > cap {
            let to_drop = count - cap;
            // Drop the `to_drop` rows with the lowest history_index,
            // then renumber survivors to a dense `0..N`.
            tx.execute(
                "DELETE FROM entry_history \
                 WHERE rowid IN ( \
                    SELECT rowid FROM entry_history \
                    WHERE entry_uuid = ?1 \
                    ORDER BY history_index ASC \
                    LIMIT ?2 \
                 )",
                params![uuid_str, to_drop],
            )?;
            // Re-pack remaining indices. Single pass: shift every
            // surviving row's index down by `to_drop`. Safe even when
            // the shift produces a transient PK collision because the
            // shift order is monotonic (smallest index moves to 0).
            tx.execute(
                "UPDATE entry_history \
                 SET history_index = history_index - ?2 \
                 WHERE entry_uuid = ?1",
                params![uuid_str, to_drop],
            )?;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Build a `HistorySnapshotIo` from the **current live** state of an
/// entry — mirrors `crate::ingest::HistorySnapshot::from_entry` but
/// reads from SQL rather than an in-memory `Entry`. Used by
/// [`restore_entry_from_history`] to capture the pre-restore state as
/// a brand new history row.
///
/// Protected-field wrapped bytes (the canonical `Password` slot and any
/// custom protected field) are copied verbatim from `entry_protected`
/// and re-encoded as base64 — they were already sealed under the
/// engine's session key, and the new history JSON inherits that
/// cipher chain, so no unwrap/re-wrap is needed here.
#[allow(clippy::too_many_lines)]
fn build_live_snapshot(
    tx: &Transaction<'_>,
    uuid_str: &str,
) -> Result<HistorySnapshotIo, EngineError> {
    // Scalar columns on `entry`.
    #[allow(clippy::type_complexity)]
    let row: (
        String,
        String,
        String,
        String,
        String,
        Option<i64>,
        Option<String>,
        i64,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<f64>,
    ) = tx.query_row(
        "SELECT title, username, url, url_host, notes, \
                icon_index, icon_custom_uuid, \
                created_at, modified_at, accessed_at, last_used_at, expires_at, \
                password_strength_bucket, password_entropy \
         FROM entry WHERE uuid = ?1",
        params![uuid_str],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
                r.get(11)?,
                r.get(12)?,
                r.get(13)?,
            ))
        },
    )?;
    let (
        title,
        username,
        url,
        url_host,
        notes,
        icon_index,
        icon_custom_uuid,
        created_at,
        modified_at,
        accessed_at,
        last_used_at,
        expires_at,
        password_strength_bucket,
        password_entropy,
    ) = row;

    // Protected fields → wrapped-blob bytes, b64-encoded into JSON.
    let mut password_b64 = String::new();
    let mut custom_fields: HashMap<String, HistoryCustomFieldIo> = HashMap::new();
    {
        let mut stmt = tx.prepare(
            "SELECT field_name, wrapped_blob FROM entry_protected WHERE entry_uuid = ?1",
        )?;
        let mut rows = stmt.query(params![uuid_str])?;
        while let Some(r) = rows.next()? {
            let name: String = r.get(0)?;
            let blob: Vec<u8> = r.get(1)?;
            if name == PASSWORD_FIELD {
                password_b64 = b64_encode(&blob);
            } else {
                custom_fields.insert(
                    name,
                    HistoryCustomFieldIo {
                        value: b64_encode(&blob),
                        protected: true,
                    },
                );
            }
        }
    }

    // Non-protected custom fields → plaintext.
    {
        let mut stmt =
            tx.prepare("SELECT field_name, value FROM entry_custom_field WHERE entry_uuid = ?1")?;
        let mut rows = stmt.query(params![uuid_str])?;
        while let Some(r) = rows.next()? {
            let name: String = r.get(0)?;
            let value: String = r.get(1)?;
            custom_fields.insert(
                name,
                HistoryCustomFieldIo {
                    value,
                    protected: false,
                },
            );
        }
    }

    // Tags.
    let mut tags: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT t.name FROM entry_tag et \
             JOIN tag t ON t.id = et.tag_id \
             WHERE et.entry_uuid = ?1 \
             ORDER BY t.name ASC",
        )?;
        let rows = stmt.query_map(params![uuid_str], |r| r.get::<_, String>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    // Defensive: dedupe in case ingest somehow allowed duplicates.
    tags.sort();
    tags.dedup();

    // Attachments → resolve size + sha256 via the content-addressed blob.
    let attachments: Vec<HistoryAttachmentIo> = {
        let mut stmt = tx.prepare(
            "SELECT ea.attachment_name, ab.sha256, ab.size \
             FROM entry_attachment ea \
             JOIN attachment_blob ab ON ab.sha256 = ea.blob_sha256 \
             WHERE ea.entry_uuid = ?1",
        )?;
        let rows = stmt.query_map(params![uuid_str], |r| {
            let name: String = r.get(0)?;
            let sha: Vec<u8> = r.get(1)?;
            let size: i64 = r.get(2)?;
            Ok((name, sha, size))
        })?;
        rows.filter_map(Result::ok)
            .map(|(name, sha, size)| HistoryAttachmentIo {
                name,
                size: u64::try_from(size).unwrap_or(0),
                sha256_hex: bytes_to_hex(&sha),
            })
            .collect()
    };

    // Per-entry CustomData rows (migration 0006). Captured so the
    // pushed snapshot can carry `keys.field_conflict.v1` markers and
    // other Keys-namespaced metadata round-trip through the history.
    let custom_data: Vec<HistoryCustomDataIo> = {
        let mut stmt = tx.prepare(
            "SELECT key, value, last_modified_at FROM entry_custom_data \
             WHERE entry_uuid = ?1 ORDER BY key ASC",
        )?;
        let rows = stmt.query_map(params![uuid_str], |r| {
            Ok(HistoryCustomDataIo {
                key: r.get(0)?,
                value: r.get(1)?,
                last_modified_at: r.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    Ok(HistorySnapshotIo {
        title,
        username,
        url,
        url_host,
        notes,
        password: password_b64,
        tags,
        created_at,
        modified_at,
        accessed_at,
        last_used_at,
        expires_at,
        icon_index: icon_index.map(|i| u32::try_from(i).unwrap_or(0)),
        icon_custom_uuid,
        password_strength_bucket: password_strength_bucket.map(|i| u8::try_from(i).unwrap_or(0)),
        password_entropy,
        attachments,
        custom_fields,
        custom_data,
    })
}

/// Round-trip shape for `entry_history.snapshot_json`. Symmetric with
/// the write-side `crate::ingest::HistorySnapshot` and the read-side
/// `crate::reads::HistorySnapshotRead` — kept private here because
/// [`restore_entry_from_history`] needs both ends in one place.
#[derive(Serialize, Deserialize, Default)]
struct HistoryCustomDataIo {
    key: String,
    value: String,
    #[serde(default)]
    last_modified_at: Option<i64>,
}

#[derive(Serialize, Deserialize)]
struct HistorySnapshotIo {
    title: String,
    username: String,
    url: String,
    #[serde(default)]
    url_host: String,
    #[serde(default)]
    notes: String,
    /// Base64 of the AES-GCM-sealed password under the engine's session
    /// key. Empty string only for pre-widening snapshots that predated
    /// the canonical password slot — restore copies verbatim into
    /// `entry_protected`, so an empty value means "no password row",
    /// not "empty-string password" (the seal of an empty string would
    /// still be a non-empty base64 blob).
    #[serde(default)]
    password: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    modified_at: i64,
    #[serde(default)]
    accessed_at: i64,
    #[serde(default)]
    last_used_at: Option<i64>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    icon_index: Option<u32>,
    #[serde(default)]
    icon_custom_uuid: Option<String>,
    #[serde(default)]
    password_strength_bucket: Option<u8>,
    #[serde(default)]
    password_entropy: Option<f64>,
    #[serde(default)]
    attachments: Vec<HistoryAttachmentIo>,
    #[serde(default)]
    custom_fields: HashMap<String, HistoryCustomFieldIo>,
    /// Per-record `<CustomData>` — round-trips the
    /// `keys.field_conflict.v1` marker and any other history-pinned
    /// metadata. See `crate::ingest::HistorySnapshot.custom_data`.
    #[serde(default)]
    custom_data: Vec<HistoryCustomDataIo>,
}

#[derive(Serialize, Deserialize)]
struct HistoryAttachmentIo {
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    sha256_hex: String,
}

#[derive(Serialize, Deserialize)]
struct HistoryCustomFieldIo {
    value: String,
    #[serde(default)]
    protected: bool,
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(&mut acc, "{b:02x}");
            acc
        })
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Add or replace an attachment on an entry: the blob lands in the
/// content-addressed pool (`attachment_blob`, dedup'd by SHA-256, same
/// shape ingest writes) and the per-entry link row is upserted by
/// name. History snapshots before the change, like every entry
/// mutation. Blob GC stays a separate concern, mirroring
/// [`remove_attachment`].
pub(crate) fn set_attachment(
    conn: &mut Connection,
    uuid: Uuid,
    name: &str,
    bytes: &[u8],
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    push_history_snapshot(&tx, &uuid_str)?;

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sha = hasher.finalize();
    let sha_bytes: &[u8] = sha.as_slice();
    let size_i64 = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    tx.execute(
        "INSERT OR IGNORE INTO attachment_blob (sha256, bytes, size) VALUES (?1, ?2, ?3)",
        params![sha_bytes, bytes, size_i64],
    )?;
    // Upsert the link: replacing an attachment's bytes under the same
    // name re-points the link row at the new blob.
    tx.execute(
        "INSERT INTO entry_attachment (entry_uuid, attachment_name, blob_sha256) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(entry_uuid, attachment_name) DO UPDATE SET blob_sha256 = excluded.blob_sha256",
        params![uuid_str, name, sha_bytes],
    )?;
    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn remove_attachment(
    conn: &mut Connection,
    uuid: Uuid,
    name: &str,
    now: i64,
) -> Result<(), EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;
    if !entry_exists(&tx, &uuid_str)? {
        return Err(EngineError::NotFound { entity: "entry" });
    }
    push_history_snapshot(&tx, &uuid_str)?;
    // Don't GC `attachment_blob` rows here; blobs are shared by SHA and
    // GC is a separate concern.
    tx.execute(
        "DELETE FROM entry_attachment WHERE entry_uuid = ?1 AND attachment_name = ?2",
        params![uuid_str, name],
    )?;
    bump_modified(&tx, &uuid_str, now)?;
    tx.commit()?;
    Ok(())
}

// ── Group mutations ────────────────────────────────────────────────────

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn create_group(
    conn: &mut Connection,
    parent_uuid: Uuid,
    fields: NewGroupFields,
    now: i64,
    new_uuid: Uuid,
) -> Result<Uuid, EngineError> {
    let parent_str = parent_uuid.to_string();
    let new_uuid_str = new_uuid.to_string();
    let (icon_index, icon_custom_uuid) = icon_parts(&fields.icon);

    let tx = conn.transaction()?;
    if !group_exists(&tx, &parent_str)? {
        return Err(EngineError::NotFound { entity: "group" });
    }
    // Append after the parent's existing children. `MAX(sort_order)`
    // is NULL on an empty parent — COALESCE-to-(-1) gives us 0 for
    // the first child and `max + 1` thereafter.
    let next_sort_order: i64 = tx.query_row(
        "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM \"group\" WHERE parent_uuid = ?1",
        params![parent_str],
        |r| r.get(0),
    )?;
    tx.execute(
        "INSERT INTO \"group\" (\
            uuid, parent_uuid, name, icon_index, icon_custom_uuid, notes, \
            created_at, modified_at, expires_at, is_recycle_bin, sort_order\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, 0, ?9)",
        params![
            new_uuid_str,
            parent_str,
            fields.name,
            icon_index,
            icon_custom_uuid,
            fields.notes,
            now,
            now,
            next_sort_order,
        ],
    )?;
    tx.commit()?;
    Ok(new_uuid)
}

pub(crate) fn update_group(
    conn: &mut Connection,
    uuid: Uuid,
    update: GroupUpdate,
    now: i64,
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
        params![now, uuid_str],
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
pub(crate) fn recycle_group(
    conn: &mut Connection,
    uuid: Uuid,
    now: i64,
) -> Result<(), EngineError> {
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
        params![bin, now, uuid_str],
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
    now: i64,
) -> Result<MoveGroupOutcome, EngineError> {
    move_group(conn, uuid, new_parent_uuid, now)
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
    now: i64,
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
    delete_group_recursive(&tx, &uuid_str, previous_parent, &mut outcome, now)?;
    // The recursive cascade may have deleted entries that were the
    // last referencers of one or more tag rows. Sweep here once at the
    // end of the cascade rather than per recursive frame — every
    // `entry_tag` row affected by the cascade has already been removed
    // (cascade from `entry`), so a single pass cleans the lot.
    gc_orphan_tags(&tx)?;
    tx.commit()?;
    Ok(outcome)
}

fn delete_group_recursive(
    tx: &Transaction<'_>,
    uuid: &str,
    parent_uuid: Option<Uuid>,
    outcome: &mut DeleteGroupOutcome,
    now: i64,
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
        delete_group_recursive(tx, &child, Some(self_uuid), outcome, now)?;
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
        // Each cascade-deleted entry needs its own `<DeletedObjects>` tombstone
        // (Phase 5b) — the owner-rows ingest reconciles deletes per entry uuid,
        // so without this a peer would resurrect these entries (re-parented to
        // root) on the next sync.
        record_tombstone(tx, &entry_uuid_str, now)?;
    }

    tx.execute("DELETE FROM entry WHERE group_uuid = ?1", params![uuid])?;
    tx.execute("DELETE FROM \"group\" WHERE uuid = ?1", params![uuid])?;
    outcome.deleted_groups.push((self_uuid, parent_uuid));
    // Tombstone the group itself too (kdbx-native `<DeletedObjects>` covers
    // entries *and* groups — sync-merge-strategies §4). Consuming group
    // tombstones to remove a peer's live group is Phase 5d; recording them now
    // is forward-compatible and stops the group resurrecting later.
    record_tombstone(tx, uuid, now)?;
    Ok(())
}

pub(crate) fn move_group(
    conn: &mut Connection,
    uuid: Uuid,
    new_parent_uuid: Uuid,
    now: i64,
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

    // Append at the end of the new parent's children. `MAX(sort_order)`
    // is NULL when the destination is empty; COALESCE-to-(-1) makes the
    // first child land at 0.
    let next_sort_order: i64 = tx.query_row(
        "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM \"group\" WHERE parent_uuid = ?1",
        params![new_parent_str],
        |r| r.get(0),
    )?;
    // Stamp <LocationChanged> (5d group re-parent LWW key) as well as
    // modified_at — a move is a location event distinct from a metadata
    // edit, so the two facets carry independent LWW stamps (mirrors
    // entry move).
    tx.execute(
        "UPDATE \"group\" \
         SET parent_uuid = ?1, sort_order = ?2, modified_at = ?3, location_changed_at = ?3 \
         WHERE uuid = ?4",
        params![new_parent_str, next_sort_order, now, uuid_str],
    )?;
    tx.commit()?;
    Ok(MoveGroupOutcome {
        from_parent,
        to_parent: new_parent_uuid,
    })
}

/// Reorder `uuid` within its current parent's child list. `new_position`
/// is the 0-based final index in the parent's sibling sequence; values
/// past the last index clamp to the end.
///
/// Returns the full ordered list of sibling uuids under the parent so
/// the engine can publish a [`crate::events::ChangeEvent::GroupsReordered`]
/// event covering every row whose `sort_order` changed.
///
/// Strategy: pull all sibling uuids ordered by current `sort_order`,
/// remove the target from its old slot, splice it at `new_position`,
/// then rewrite every sibling's `sort_order` as its new index.
/// Renumbering everything is the simplest correct approach and is
/// trivially cheap — a single parent rarely holds more than a few
/// dozen direct children.
///
/// Cross-parent moves go through [`move_group`] instead; this method
/// refuses to alter parentage.
pub(crate) fn reorder_group(
    conn: &mut Connection,
    uuid: Uuid,
    new_position: u32,
    now: i64,
) -> Result<ReorderGroupOutcome, EngineError> {
    let uuid_str = uuid.to_string();
    let tx = conn.transaction()?;

    // Look up the target group + its parent. The root group has
    // `parent_uuid IS NULL` and cannot be reordered (it has no siblings
    // by construction); we reject that case as a no-op error rather
    // than silently doing nothing.
    let parent_str: Option<String> = match tx
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
    let Some(parent_str) = parent_str else {
        // The root group has no siblings — reordering it is degenerate.
        // Treat as not-found rather than introducing a new error
        // variant; the FFI layer maps that cleanly to a foreign error
        // and the surface stays minimal.
        return Err(EngineError::NotFound { entity: "group" });
    };

    // Pull current sibling order (ascending by sort_order, with the
    // same tie-breakers as `group_tree` so the read and write paths
    // agree on order when sort_order values collide).
    let mut siblings: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT uuid FROM \"group\" \
             WHERE parent_uuid = ?1 \
             ORDER BY sort_order ASC, name ASC, uuid ASC",
        )?;
        stmt.query_map(params![parent_str], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };

    // Splice the target into its new position. Position values past
    // the end clamp to "last" — drag-reorder UIs often pass
    // `siblings.len()` to mean "put it at the end".
    let Some(current_idx) = siblings.iter().position(|s| s == &uuid_str) else {
        // The row exists (we read its parent above) but isn't under
        // its own parent in the sibling list — impossible without
        // schema corruption. Surface as not-found rather than panicking.
        return Err(EngineError::NotFound { entity: "group" });
    };
    let target = siblings.remove(current_idx);
    let clamped = (new_position as usize).min(siblings.len());
    siblings.insert(clamped, target);

    // Rewrite every sibling's sort_order to its new index. A single
    // statement per row keeps the SQL trivial; bulk-update via a CTE
    // would be cleverer but not measurably faster at these row counts.
    for (idx, sibling_uuid) in siblings.iter().enumerate() {
        let pos = i64::try_from(idx).unwrap_or(i64::MAX);
        tx.execute(
            "UPDATE \"group\" SET sort_order = ?1 WHERE uuid = ?2",
            params![pos, sibling_uuid],
        )?;
    }
    // Bump modified_at only on the row the user actually moved; the
    // other siblings keep their original modified_at because their
    // logical contents didn't change.
    tx.execute(
        "UPDATE \"group\" SET modified_at = ?1 WHERE uuid = ?2",
        params![now, uuid_str],
    )?;
    tx.commit()?;

    let siblings_in_order = siblings
        .into_iter()
        .map(|s| {
            Uuid::parse_str(&s).map_err(|e| {
                EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ReorderGroupOutcome { siblings_in_order })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Spin up a minimal `SQLite` DB with the engine's schema and a single
    /// group + entry row so we can hand-craft history rows for prune
    /// tests without going through the full Engine wiring.
    fn bare_db_with_entry() -> (Connection, String) {
        let mut conn = Connection::open_in_memory().expect("in-memory db");
        crate::migrations::apply_pending(&mut conn).expect("migrate");
        let root = Uuid::new_v4().to_string();
        let entry = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO \"group\" (uuid, parent_uuid, name, created_at, modified_at) \
             VALUES (?1, NULL, 'r', 0, 0)",
            params![root],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entry (uuid, group_uuid, created_at, modified_at, accessed_at) \
             VALUES (?1, ?2, 0, 0, 0)",
            params![entry, root],
        )
        .unwrap();
        // The canonical Password slot row is part of the engine's
        // baseline invariant — create_entry always inserts one. We
        // include it here so `build_live_snapshot` could be called
        // (none of these prune tests need it, but the invariant is
        // preserved).
        conn.execute(
            "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
             VALUES (?1, 'Password', X'')",
            params![entry],
        )
        .unwrap();
        (conn, entry)
    }

    /// Insert a hand-crafted history row at `index`. Marker rows carry
    /// a `keys.field_conflict.v1` `custom_data` entry; unmarked rows
    /// have an empty list.
    fn insert_history_row(conn: &Connection, entry_uuid: &str, index: i64, marker: bool) {
        let cd = if marker {
            r#"[{"key":"keys.field_conflict.v1","value":"x"}]"#
        } else {
            "[]"
        };
        let json = format!(
            r#"{{"title":"row-{index}","username":"","url":"","modified_at":{index},"custom_data":{cd}}}"#
        );
        conn.execute(
            "INSERT INTO entry_history (entry_uuid, history_index, snapshot_json) \
             VALUES (?1, ?2, ?3)",
            params![entry_uuid, index, json],
        )
        .unwrap();
    }

    /// CRITICAL invariant: pruning must NEVER evict a marker-tagged
    /// snapshot, even when their count exceeds `history_max_items`. The
    /// brief's worked example: 11 markers + 0 unmarked, cap = 10 →
    /// retain all 11 markers, evict 0 unmarked.
    #[test]
    fn prune_history_keeps_all_markers_even_above_cap() {
        let (mut conn, entry) = bare_db_with_entry();
        // 5 marker-tagged + 2 unmarked, cap = 3.
        crate::meta::write_history_max_items(&conn, 3).unwrap();
        crate::meta::write_history_max_size(&conn, -1).unwrap();
        for i in 0..5 {
            insert_history_row(&conn, &entry, i, true);
        }
        for i in 5..7 {
            insert_history_row(&conn, &entry, i, false);
        }
        let tx = conn.transaction().unwrap();
        prune_history(&tx, &entry).unwrap();
        tx.commit().unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entry_history WHERE entry_uuid = ?1",
                params![entry],
                |r| r.get(0),
            )
            .unwrap();
        // All 5 markers retained; 0 unmarked (cap=3, markers consume 5
        // — non-marker quota is max(3 - 5, 0) = 0).
        assert_eq!(count, 5, "5 markers retained + 0 unmarked");

        // Verify each surviving row carries the marker.
        let mut stmt = conn
            .prepare("SELECT snapshot_json FROM entry_history WHERE entry_uuid = ?1")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map(params![entry], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for json in &rows {
            assert!(
                json.contains("keys.field_conflict.v1"),
                "surviving row must be a marker; got {json}",
            );
        }
    }

    /// Pruning re-packs `history_index` into a dense `0..N` after
    /// eviction.
    #[test]
    fn prune_history_repacks_indices_densely() {
        let (mut conn, entry) = bare_db_with_entry();
        crate::meta::write_history_max_items(&conn, 2).unwrap();
        crate::meta::write_history_max_size(&conn, -1).unwrap();
        for i in 0..5 {
            insert_history_row(&conn, &entry, i, false);
        }
        let tx = conn.transaction().unwrap();
        prune_history(&tx, &entry).unwrap();
        tx.commit().unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT history_index FROM entry_history WHERE entry_uuid = ?1 \
                 ORDER BY history_index ASC",
            )
            .unwrap();
        let idxs: Vec<i64> = stmt
            .query_map(params![entry], |r| r.get::<_, i64>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(idxs, vec![0, 1], "re-packed to dense 0..N");
    }

    /// One blob per root class plus a genuine orphan: the sweep must
    /// reap exactly the orphan and spare live links, history-snapshot
    /// shas, and parked-conflict rows (the Finding-#7 GC root).
    #[test]
    fn gc_attachment_blobs_reaps_only_unrooted() {
        let (mut conn, entry) = bare_db_with_entry();
        let put_blob = |conn: &Connection, byte: u8| -> [u8; 32] {
            let sha = [byte; 32];
            conn.execute(
                "INSERT INTO attachment_blob (sha256, bytes, size) VALUES (?1, x'00', 1)",
                params![sha.as_slice()],
            )
            .unwrap();
            sha
        };
        let live = put_blob(&conn, 1);
        let hist = put_blob(&conn, 2);
        let parked = put_blob(&conn, 3);
        let orphan = put_blob(&conn, 4);

        conn.execute(
            "INSERT INTO entry_attachment (entry_uuid, attachment_name, blob_sha256) \
             VALUES (?1, 'live.txt', ?2)",
            params![entry, live.as_slice()],
        )
        .unwrap();
        let hist_hex = hist.iter().fold(String::with_capacity(64), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        let json = format!(
            r#"{{"title":"t","username":"","url":"","attachments":[{{"name":"h.txt","size":1,"sha256_hex":"{hist_hex}"}}]}}"#
        );
        conn.execute(
            "INSERT INTO entry_history (entry_uuid, history_index, snapshot_json) \
             VALUES (?1, 0, ?2)",
            params![entry, json],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO conflict_entry (owner, entry_uuid, title, username, url, notes, icon_index) \
             VALUES ('peer', ?1, '', '', '', '', 0)",
            params![entry],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO conflict_entry_attachment (owner, entry_uuid, attachment_name, blob_sha256) \
             VALUES ('peer', ?1, 'parked.txt', ?2)",
            params![entry, parked.as_slice()],
        )
        .unwrap();

        let removed = gc_attachment_blobs(&mut conn).expect("gc");
        assert_eq!(removed, 1, "exactly the orphan is reaped");
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM attachment_blob", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 3, "live + history + parked roots survive");
        let orphan_left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM attachment_blob WHERE sha256 = ?1",
                params![orphan.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphan_left, 0, "the orphan is the one that went");
    }
}
