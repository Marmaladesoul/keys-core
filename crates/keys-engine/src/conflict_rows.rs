//! Read-side primitives for the owner-tagged conflict rows of the
//! multi-peer owner-rows store.
//!
//! Phase 2 ([`crate::ingest::ingest_peer`]) WRITES the `conflict_*` rows;
//! this module READS them back — the badge query (which entries have a peer
//! row) and reconstruction of a peer's ("theirs") [`Entry`] from its sealed
//! rows. These are the building blocks Phase 4 wires into the badge FFI and
//! the resolver-payload rebuild, replacing the legacy `held_conflicts` kv +
//! the single-blob theirs-stash. As of Phase 4 they are on the live path:
//! `conflict_owners_for` / `reconstruct_peer_entry` rebuild the resolver's
//! "theirs", and `drop_conflict_rows` clears the badge on resolve / dismiss.

use keepass_core::model::{CustomField, Entry, EntryId, Timestamps};
use keepass_core::protector::{SessionKey, open_with_key};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::error::{EngineError, ProjectionError};
use crate::util::PASSWORD_FIELD;

/// Every entry UUID that has at least one stored peer conflict row — the
/// owner-rows badge query, replacing the `held_conflicts` JSON-array kv.
pub(crate) fn parked_conflict_uuids(conn: &Connection) -> Result<Vec<Uuid>, EngineError> {
    let mut stmt =
        conn.prepare("SELECT DISTINCT entry_uuid FROM conflict_entry ORDER BY entry_uuid")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        // A malformed uuid string can't have been written by `ingest_peer`
        // (it stringifies a real `Uuid`); skip rather than fail the badge.
        if let Ok(uuid) = Uuid::parse_str(&r?) {
            out.push(uuid);
        }
    }
    Ok(out)
}

/// The distinct owner ids holding a conflict row for `uuid` — one per peer
/// (native multi-peer: an entry can carry several owners' divergent values).
pub(crate) fn conflict_owners_for(
    conn: &Connection,
    uuid: Uuid,
) -> Result<Vec<String>, EngineError> {
    let mut stmt =
        conn.prepare("SELECT owner FROM conflict_entry WHERE entry_uuid = ?1 ORDER BY owner")?;
    let rows = stmt.query_map(params![uuid.to_string()], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// One side's reconstructed conflict-entry columns, before unsealing.
struct ConflictEntryRow {
    title: String,
    username: String,
    url: String,
    notes: String,
    icon_index: i64,
    icon_custom_uuid: Option<String>,
    created_at: Option<i64>,
    modified_at: Option<i64>,
    accessed_at: Option<i64>,
    expires_at: Option<i64>,
}

/// A peer's ("theirs") entry rebuilt from its conflict rows, plus its
/// attachment bytes.
///
/// [`Entry::attachments`] is a `(name, ref_id)` reference into a vault's
/// binary pool, and reconstruction has no vault — so `entry` carries no
/// attachments; they ride alongside as named bytes for the caller to bind
/// into whatever pool backs the synthetic "theirs" vault
/// (`reconcile::held_conflict_payload`).
pub(crate) struct ReconstructedPeerEntry {
    pub(crate) entry: Entry,
    /// `(attachment name, bytes)`, name-sorted; resolved from the shared
    /// `attachment_blob` pool at read time.
    pub(crate) attachments: Vec<(String, Vec<u8>)>,
}

/// Reconstruct one peer's ("theirs") [`Entry`] from its conflict rows — the
/// inverse of `ingest::insert_conflict_entry`. Protected fields are unsealed
/// with `session_key`, so the result carries plaintext in `password` /
/// `custom_fields[].value`, matching the post-unwrap shape the resolver's
/// reveal path expects.
///
/// Attachments come back as named bytes (Finding #7 — without them the
/// rebuilt "theirs" read as "remote removed every attachment" and a
/// choose-remote resolution wiped the local links). A sha with no pool blob
/// (a future GC) skips, matching the history-snapshot posture.
///
/// `<History>` is not stored, so the reconstructed entry carries none: a held
/// conflict re-derives through the no-shared-ancestor path, where every
/// divergent field surfaces — exactly the item-granularity picker the
/// resolver wants. Returns `None` when no `conflict_entry` row exists for
/// `(owner, uuid)`.
pub(crate) fn reconstruct_peer_entry(
    conn: &Connection,
    owner: &str,
    uuid: Uuid,
    session_key: &SessionKey,
) -> Result<Option<ReconstructedPeerEntry>, EngineError> {
    let uuid_str = uuid.to_string();
    let base = conn
        .query_row(
            "SELECT title, username, url, notes, icon_index, icon_custom_uuid, \
                    created_at, modified_at, accessed_at, expires_at \
             FROM conflict_entry WHERE owner = ?1 AND entry_uuid = ?2",
            params![owner, uuid_str],
            |r| {
                Ok(ConflictEntryRow {
                    title: r.get(0)?,
                    username: r.get(1)?,
                    url: r.get(2)?,
                    notes: r.get(3)?,
                    icon_index: r.get(4)?,
                    icon_custom_uuid: r.get(5)?,
                    created_at: r.get(6)?,
                    modified_at: r.get(7)?,
                    accessed_at: r.get(8)?,
                    expires_at: r.get(9)?,
                })
            },
        )
        .optional()?;
    let Some(base) = base else {
        return Ok(None);
    };

    let mut entry = Entry::empty(EntryId(uuid));
    // Borrows / Copy reads of `base` first, then move the owned String
    // fields last (avoids a borrow-after-partial-move on `reconstruct_times`).
    entry.icon_id = u32::try_from(base.icon_index).unwrap_or(0);
    entry.custom_icon_uuid = base
        .icon_custom_uuid
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok());
    entry.times = reconstruct_times(&base);
    entry.title = base.title;
    entry.username = base.username;
    entry.url = base.url;
    entry.notes = base.notes;

    // Protected fields: canonical Password + any protected custom fields.
    let mut stmt = conn.prepare(
        "SELECT field_name, wrapped_blob FROM conflict_entry_protected \
         WHERE owner = ?1 AND entry_uuid = ?2 ORDER BY field_name",
    )?;
    let protected = stmt.query_map(params![owner, uuid_str], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    for row in protected {
        let (field_name, wrapped) = row?;
        let plaintext = open_with_key(session_key, &wrapped).map_err(|e| {
            EngineError::Projection(ProjectionError::Unwrap(format!(
                "conflict {owner}/{uuid} field {field_name}: {e}"
            )))
        })?;
        let value = String::from_utf8(plaintext).map_err(|e| {
            EngineError::Projection(ProjectionError::Unwrap(format!(
                "conflict {owner}/{uuid} field {field_name}: non-utf8 plaintext: {e}"
            )))
        })?;
        if field_name == PASSWORD_FIELD {
            entry.password = value;
        } else {
            entry
                .custom_fields
                .push(CustomField::new(field_name, value, true));
        }
    }

    // Non-protected custom fields.
    let mut stmt = conn.prepare(
        "SELECT field_name, value FROM conflict_entry_custom_field \
         WHERE owner = ?1 AND entry_uuid = ?2 ORDER BY field_name",
    )?;
    let custom = stmt.query_map(params![owner, uuid_str], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    for row in custom {
        let (field_name, value) = row?;
        entry
            .custom_fields
            .push(CustomField::new(field_name, value, false));
    }

    // Attachments: resolve each row's sha through the shared blob pool.
    // The INNER JOIN drops a sha whose blob is gone (a future GC) — skip,
    // don't fail the rebuild.
    let mut stmt = conn.prepare(
        "SELECT a.attachment_name, b.bytes \
         FROM conflict_entry_attachment a \
         JOIN attachment_blob b ON b.sha256 = a.blob_sha256 \
         WHERE a.owner = ?1 AND a.entry_uuid = ?2 ORDER BY a.attachment_name",
    )?;
    let att_rows = stmt.query_map(params![owner, uuid_str], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    let mut attachments = Vec::new();
    for row in att_rows {
        attachments.push(row?);
    }

    Ok(Some(ReconstructedPeerEntry { entry, attachments }))
}

/// Drop every owner's conflict rows for one `entry_uuid` (across all peers),
/// returning the number of `conflict_entry` parent rows removed. Used by the
/// resolve / dismiss paths to clear an entry from the badge once its conflict
/// has converged locally — the owner-rows replacement for the legacy
/// `held_conflicts` kv read-modify-write.
///
/// Child tables are deleted explicitly (parent last) rather than relying on
/// the FK `ON DELETE CASCADE` pragma being enabled, matching
/// `ingest::clear_conflict_rows`'s posture.
pub(crate) fn drop_conflict_rows(conn: &Connection, entry_uuid: Uuid) -> Result<u32, EngineError> {
    let uuid_str = entry_uuid.to_string();
    conn.execute(
        "DELETE FROM conflict_entry_protected WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    conn.execute(
        "DELETE FROM conflict_entry_custom_field WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    conn.execute(
        "DELETE FROM conflict_entry_attachment WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    let removed = conn.execute(
        "DELETE FROM conflict_entry WHERE entry_uuid = ?1",
        params![uuid_str],
    )?;
    Ok(u32::try_from(removed).unwrap_or(u32::MAX))
}

/// Drop ONE owner's conflict rows for `entry_uuid`, leaving any other
/// owners' rows intact. The owner-scoped counterpart to
/// [`drop_conflict_rows`], for dissolve-reconciliation: when a local
/// edit / sync converges the entry to *one* peer's value, only that
/// peer's parked row has dissolved — other peers may still genuinely
/// diverge and must stay badged (the multi-peer over-clear the
/// Finding #10 review caught). Mirrors `ingest::clear_conflict_rows`'s
/// `WHERE owner = ?1 AND entry_uuid = ?2` shape.
pub(crate) fn drop_conflict_rows_for_owner(
    conn: &Connection,
    owner: &str,
    entry_uuid: Uuid,
) -> Result<(), EngineError> {
    let uuid_str = entry_uuid.to_string();
    conn.execute(
        "DELETE FROM conflict_entry_protected WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, uuid_str],
    )?;
    conn.execute(
        "DELETE FROM conflict_entry_custom_field WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, uuid_str],
    )?;
    conn.execute(
        "DELETE FROM conflict_entry_attachment WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, uuid_str],
    )?;
    conn.execute(
        "DELETE FROM conflict_entry WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, uuid_str],
    )?;
    Ok(())
}

fn reconstruct_times(row: &ConflictEntryRow) -> Timestamps {
    let ms = |o: Option<i64>| o.and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis);
    let mut t = Timestamps::default();
    t.creation_time = ms(row.created_at);
    t.last_modification_time = ms(row.modified_at);
    t.last_access_time = ms(row.accessed_at);
    if let Some(expiry) = ms(row.expires_at) {
        t.expires = true;
        t.expiry_time = Some(expiry);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations;
    use keepass_core::protector::seal_with_key;

    const SK: [u8; 32] = [0x9c; 32];

    fn mem_conn() -> Connection {
        let mut c = Connection::open_in_memory().expect("open in-memory db");
        migrations::apply_pending(&mut c).expect("apply migrations");
        c
    }

    fn sk() -> SessionKey {
        SessionKey::from_bytes(SK)
    }

    /// Insert a peer conflict row directly (the shape `ingest::insert_conflict_entry`
    /// writes), sealing protected fields under the test session key.
    fn insert_peer(
        conn: &Connection,
        owner: &str,
        uuid: Uuid,
        title: &str,
        password: &str,
        cf: &[(&str, &str, bool)],
    ) {
        conn.execute(
            "INSERT INTO conflict_entry (owner, entry_uuid, title, username, url, notes, icon_index) \
             VALUES (?1, ?2, ?3, '', '', '', 0)",
            params![owner, uuid.to_string(), title],
        )
        .expect("insert conflict_entry");
        let wp = seal_with_key(&sk(), password.as_bytes()).expect("seal pw");
        conn.execute(
            "INSERT INTO conflict_entry_protected (owner, entry_uuid, field_name, wrapped_blob) \
             VALUES (?1, ?2, 'Password', ?3)",
            params![owner, uuid.to_string(), wp],
        )
        .expect("insert protected pw");
        for (key, value, protected) in cf {
            if *protected {
                let w = seal_with_key(&sk(), value.as_bytes()).expect("seal cf");
                conn.execute(
                    "INSERT INTO conflict_entry_protected (owner, entry_uuid, field_name, wrapped_blob) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![owner, uuid.to_string(), key, w],
                )
                .expect("insert protected cf");
            } else {
                conn.execute(
                    "INSERT INTO conflict_entry_custom_field (owner, entry_uuid, field_name, value) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![owner, uuid.to_string(), key, value],
                )
                .expect("insert custom field");
            }
        }
    }

    #[test]
    fn badge_query_returns_distinct_uuids() {
        let conn = mem_conn();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // Two peers conflict on `a`; one peer on `b`.
        insert_peer(&conn, "peerB", a, "A", "x", &[]);
        insert_peer(&conn, "peerC", a, "A", "y", &[]);
        insert_peer(&conn, "peerB", b, "B", "z", &[]);
        let mut uuids = parked_conflict_uuids(&conn).expect("query");
        uuids.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(uuids, expected, "distinct entry uuids, not per-owner rows");
    }

    #[test]
    fn owners_for_lists_each_peer() {
        let conn = mem_conn();
        let id = Uuid::new_v4();
        insert_peer(&conn, "peerB", id, "A", "x", &[]);
        insert_peer(&conn, "peerC", id, "A", "y", &[]);
        let owners = conflict_owners_for(&conn, id).expect("owners");
        assert_eq!(owners, vec!["peerB".to_string(), "peerC".to_string()]);
    }

    #[test]
    fn drop_for_owner_is_owner_scoped() {
        // Two peers conflict on the same entry; dropping one owner's rows
        // must leave the other owner's rows (and badge) intact — the
        // owner-granular clear that prevents the multi-peer over-clear
        // (Finding #10 review). A custom field + protected pw per owner
        // exercises the child-table deletes too.
        let conn = mem_conn();
        let id = Uuid::new_v4();
        insert_peer(&conn, "peerB", id, "A", "pwB", &[("cf", "vB", false)]);
        insert_peer(&conn, "peerC", id, "A", "pwC", &[("cf", "vC", true)]);
        assert_eq!(conflict_owners_for(&conn, id).unwrap().len(), 2);

        drop_conflict_rows_for_owner(&conn, "peerB", id).expect("drop peerB");

        // peerB gone from every table; peerC fully intact.
        assert_eq!(
            conflict_owners_for(&conn, id).unwrap(),
            vec!["peerC".to_string()],
            "only the dropped owner is removed"
        );
        let n_prot: i64 = conn
            .query_row(
                "SELECT count(*) FROM conflict_entry_protected WHERE owner = 'peerB' AND entry_uuid = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_prot, 0, "peerB protected rows gone");
        let n_cf_c: i64 = conn
            .query_row(
                "SELECT count(*) FROM conflict_entry_protected WHERE owner = 'peerC' AND entry_uuid = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_cf_c, 2, "peerC pw + protected cf intact");
        // The entry is still badged (peerC still conflicts).
        assert_eq!(parked_conflict_uuids(&conn).unwrap(), vec![id]);

        // Owner-agnostic drop then clears the remainder.
        drop_conflict_rows(&conn, id).expect("drop all");
        assert!(parked_conflict_uuids(&conn).unwrap().is_empty());
    }

    #[test]
    fn reconstruct_round_trips_fields_and_unseals_secrets() {
        let conn = mem_conn();
        let id = Uuid::new_v4();
        insert_peer(
            &conn,
            "peerB",
            id,
            "Acme",
            "s3cret",
            &[("TOTP", "seed", true), ("note", "hello", false)],
        );
        let reconstructed = reconstruct_peer_entry(&conn, "peerB", id, &sk())
            .expect("reconstruct")
            .expect("entry present");
        let entry = reconstructed.entry;
        assert!(
            reconstructed.attachments.is_empty(),
            "no attachment rows stored, none reconstructed"
        );
        assert_eq!(entry.id.0, id);
        assert_eq!(entry.title, "Acme");
        assert_eq!(entry.password, "s3cret", "password unsealed");
        let totp = entry
            .custom_fields
            .iter()
            .find(|f| f.key == "TOTP")
            .expect("totp");
        assert_eq!(totp.value, "seed");
        assert!(totp.protected, "protected bit reconstructed");
        let note = entry
            .custom_fields
            .iter()
            .find(|f| f.key == "note")
            .expect("note");
        assert_eq!(note.value, "hello");
        assert!(!note.protected);
    }

    #[test]
    fn reconstruct_returns_attachment_bytes_from_pool() {
        let conn = mem_conn();
        let id = Uuid::new_v4();
        insert_peer(&conn, "peerB", id, "Acme", "pw", &[]);
        // Pool blob + conflict link, the shape `insert_conflict_entry`
        // writes (sha content-addresses the bytes).
        let bytes = b"attachment-bytes".to_vec();
        let sha: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&bytes);
            h.finalize().into()
        };
        conn.execute(
            "INSERT INTO attachment_blob (sha256, bytes, size) VALUES (?1, ?2, ?3)",
            params![
                sha.as_slice(),
                bytes,
                i64::try_from(bytes.len()).expect("test bytes fit")
            ],
        )
        .expect("insert blob");
        conn.execute(
            "INSERT INTO conflict_entry_attachment \
                 (owner, entry_uuid, attachment_name, blob_sha256) \
             VALUES (?1, ?2, 'doc.txt', ?3)",
            params!["peerB", id.to_string(), sha.as_slice()],
        )
        .expect("insert conflict attachment");
        // A second link whose blob is absent (GC'd) must skip, not fail.
        conn.execute(
            "INSERT INTO conflict_entry_attachment \
                 (owner, entry_uuid, attachment_name, blob_sha256) \
             VALUES (?1, ?2, 'gone.txt', x'00')",
            params!["peerB", id.to_string()],
        )
        .expect("insert dangling conflict attachment");

        let reconstructed = reconstruct_peer_entry(&conn, "peerB", id, &sk())
            .expect("reconstruct")
            .expect("entry present");
        assert_eq!(
            reconstructed.attachments,
            vec![("doc.txt".to_string(), b"attachment-bytes".to_vec())],
            "stored attachment comes back; dangling sha skips"
        );
        assert!(
            reconstructed.entry.attachments.is_empty(),
            "ref binding is the caller's job — the entry itself carries none"
        );
    }

    #[test]
    fn drop_clears_attachment_rows_too() {
        let conn = mem_conn();
        let id = Uuid::new_v4();
        insert_peer(&conn, "peerB", id, "Acme", "pw", &[]);
        conn.execute(
            "INSERT INTO conflict_entry_attachment \
                 (owner, entry_uuid, attachment_name, blob_sha256) \
             VALUES ('peerB', ?1, 'doc.txt', x'aa')",
            params![id.to_string()],
        )
        .expect("insert conflict attachment");
        drop_conflict_rows(&conn, id).expect("drop");
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM conflict_entry_attachment WHERE entry_uuid = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(left, 0, "attachment rows dropped with the conflict");
    }

    #[test]
    fn reconstruct_unknown_entry_returns_none() {
        let conn = mem_conn();
        assert!(
            reconstruct_peer_entry(&conn, "peerB", Uuid::new_v4(), &sk())
                .expect("reconstruct")
                .is_none()
        );
    }
}
