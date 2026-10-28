//! The owner-tagged conflict rows of the multi-peer owner-rows store.
//!
//! A held conflict keeps the peer's version as an owner-keyed
//! `conflict_entry` row: [`write_peer_entry`] writes it
//! ([`crate::ingest::ingest_peer`]'s hold-open arm), and
//! [`reconstruct_peer_entry`] rebuilds it as the resolver's "theirs" — the
//! only writer and the only reader of the record, so the two can't drift.
//! The rest is the badge query (which entries have a peer row), the owner
//! listing, and the drops that clear the badge on resolve, dismiss or
//! dissolve.

use std::collections::{HashMap, HashSet};

use keepass_core::model::{Binary, Entry};
use keepass_core::protector::SessionKey;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{EngineError, IngestError, ProjectionError};
use crate::history_snapshot::HistorySnapshotIo;
use crate::ingest::store_attachment_blobs;
use crate::projection::snapshot_to_entry;

/// The `conflict_entry.entry_json` record: a peer's whole entry, as the
/// history-snapshot records [`HistorySnapshotIo`] already defines — the live
/// version plus each `<History>` version, oldest first.
///
/// Reusing the snapshot shape means a peer row carries every facet the
/// mirror keeps for a version (fields, protected values sealed under the
/// session key, tags, icon, times, `<CustomData>`, attachments by sha), and
/// a facet added to that shape reaches peer rows with no further change.
/// The entry's location (group, `<LocationChanged>`, previous parent) is not
/// part of it: location reconciles apart from the content verdict, and the
/// resolver splices "theirs" into local's placement.
///
/// The snapshot's derived fields (`url_host`, password strength) ride along
/// unread: the rebuild reads only what [`snapshot_to_entry`] restores.
///
/// The record is local-only and re-derivable (the next ingest from the peer
/// rewrites it), so the shape carries no back-compat defaults.
#[derive(Serialize, Deserialize)]
struct PeerEntryIo {
    entry: HistorySnapshotIo,
    history: Vec<HistorySnapshotIo>,
}

/// Store `entry` — a peer's version, in full — as `owner`'s conflict row
/// (the resolver's "theirs"). The caller clears any previous row for
/// `(owner, entry)` first.
///
/// `binaries` is the peer vault's binary pool, which the entry's (and its
/// history's) attachment `ref_id`s index. The bytes are content-addressed
/// into the shared `attachment_blob` pool and each sha is listed in
/// `conflict_entry_blob_ref`, the blob GC's root for parked conflicts. A
/// dangling `ref_id` stores no bytes, so that attachment rebuilds absent —
/// the posture of every other attachment walk in ingest.
pub(crate) fn write_peer_entry(
    conn: &Connection,
    owner: &str,
    entry: &Entry,
    session_key: &SessionKey,
    binaries: &[&[u8]],
) -> Result<(), EngineError> {
    let record = PeerEntryIo {
        entry: HistorySnapshotIo::from_entry(entry, session_key, binaries)?,
        history: entry
            .history
            .iter()
            .map(|h| HistorySnapshotIo::from_entry(h, session_key, binaries))
            .collect::<Result<_, _>>()?,
    };
    let json =
        serde_json::to_string(&record).map_err(|e| EngineError::Ingest(IngestError::Json(e)))?;
    let uuid = entry.id.0.to_string();
    conn.execute(
        "INSERT INTO conflict_entry (owner, entry_uuid, entry_json) VALUES (?1, ?2, ?3)",
        params![owner, uuid, json],
    )?;

    let attachments = entry
        .attachments
        .iter()
        .chain(entry.history.iter().flat_map(|h| &h.attachments));
    for sha in store_attachment_blobs(conn, attachments, binaries)? {
        conn.execute(
            "INSERT OR IGNORE INTO conflict_entry_blob_ref (owner, entry_uuid, blob_sha256) \
             VALUES (?1, ?2, ?3)",
            params![owner, uuid, sha.as_slice()],
        )?;
    }
    Ok(())
}

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

/// Rebuild one peer's ("theirs") [`Entry`] from its conflict row — the
/// inverse of [`write_peer_entry`], returning the peer's entry exactly as
/// the mirror would hold it: fields, tags, icon, times, `<CustomData>`,
/// attachments and `<History>`. Protected values come back unsealed with
/// `session_key`, the post-unwrap shape the resolver's reveal path expects.
///
/// Attachments (the live version's and its history's) bind into
/// `binary_pool` — the binary pool of the vault the caller splices the
/// entry into. A blob that pool already holds is reused, so only divergent
/// peer bytes grow it. A sha whose blob is gone (a future GC) skips, the
/// history-snapshot posture.
///
/// Returns `None` when no `conflict_entry` row exists for `(owner, uuid)`.
pub(crate) fn reconstruct_peer_entry(
    conn: &Connection,
    owner: &str,
    uuid: Uuid,
    session_key: &SessionKey,
    binary_pool: &mut Vec<Binary>,
) -> Result<Option<Entry>, EngineError> {
    let json: Option<String> = conn
        .query_row(
            "SELECT entry_json FROM conflict_entry WHERE owner = ?1 AND entry_uuid = ?2",
            params![owner, uuid.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let record: PeerEntryIo = serde_json::from_str(&json)
        .map_err(|e| EngineError::Projection(ProjectionError::Json(e)))?;

    // Seed with the caller's pool so bytes it already holds are reused.
    // Only binaries whose length matches an attachment the record
    // references can be one of them, so only those are hashed.
    let sizes: HashSet<u64> = std::iter::once(&record.entry)
        .chain(&record.history)
        .flat_map(|snap| snap.attachments.iter().map(|a| a.size))
        .collect();
    let mut sha_to_ref: HashMap<[u8; 32], u32> = HashMap::new();
    for (idx, bin) in binary_pool.iter().enumerate() {
        if !u64::try_from(bin.data.len()).is_ok_and(|n| sizes.contains(&n)) {
            continue;
        }
        let idx = u32::try_from(idx).map_err(|_| {
            EngineError::Projection(ProjectionError::SchemaInvariant(
                "binary pool exceeded u32::MAX".into(),
            ))
        })?;
        sha_to_ref
            .entry(Sha256::digest(&bin.data).into())
            .or_insert(idx);
    }
    let mut rebuild = |snap: &HistorySnapshotIo| {
        snapshot_to_entry(uuid, snap, session_key, conn, binary_pool, &mut sha_to_ref)
    };
    let mut entry = rebuild(&record.entry)?;
    entry.history = record
        .history
        .iter()
        .map(&mut rebuild)
        .collect::<Result<_, _>>()?;
    Ok(Some(entry))
}

/// Drop every owner's conflict rows for one `entry_uuid` (across all peers),
/// returning the number of `conflict_entry` rows removed. Used by the
/// resolve / dismiss paths to clear an entry from the badge once its conflict
/// has converged locally — the owner-rows replacement for the legacy
/// `held_conflicts` kv read-modify-write.
///
/// The blob-ref child rows are deleted explicitly (parent last) rather than
/// relying on the FK `ON DELETE CASCADE` pragma being enabled.
pub(crate) fn drop_conflict_rows(conn: &Connection, entry_uuid: Uuid) -> Result<u32, EngineError> {
    let uuid_str = entry_uuid.to_string();
    conn.execute(
        "DELETE FROM conflict_entry_blob_ref WHERE entry_uuid = ?1",
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
/// [`drop_conflict_rows`]: ingest refreshes an owner's row through it, and
/// dissolve-reconciliation uses it when a local edit / sync converges the
/// entry to *one* peer's value — only that peer's parked row has dissolved;
/// other peers may still genuinely diverge and must stay badged (the
/// multi-peer over-clear the Finding #10 review caught).
pub(crate) fn drop_conflict_rows_for_owner(
    conn: &Connection,
    owner: &str,
    entry_uuid: Uuid,
) -> Result<(), EngineError> {
    let uuid_str = entry_uuid.to_string();
    conn.execute(
        "DELETE FROM conflict_entry_blob_ref WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, uuid_str],
    )?;
    conn.execute(
        "DELETE FROM conflict_entry WHERE owner = ?1 AND entry_uuid = ?2",
        params![owner, uuid_str],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations;
    use chrono::{DateTime, Utc};
    use keepass_core::model::{Attachment, CustomDataItem, CustomField, EntryId, Timestamps};

    const SK: [u8; 32] = [0x9c; 32];

    fn mem_conn() -> Connection {
        let mut c = Connection::open_in_memory().expect("open in-memory db");
        migrations::apply_pending(&mut c).expect("apply migrations");
        c
    }

    fn sk() -> SessionKey {
        SessionKey::from_bytes(SK)
    }

    fn at(secs: i64) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(secs, 0)
    }

    /// A minimal peer version: `title` plus a password.
    fn simple(uuid: Uuid, title: &str, password: &str) -> Entry {
        let mut e = Entry::empty(EntryId(uuid));
        e.title = title.into();
        e.password = password.into();
        e
    }

    /// Park `entry` as `owner`'s row through the real writer.
    fn park(conn: &Connection, owner: &str, entry: &Entry, binaries: &[&[u8]]) {
        write_peer_entry(conn, owner, entry, &sk(), binaries).expect("write peer entry");
    }

    fn rebuild(conn: &Connection, owner: &str, uuid: Uuid, pool: &mut Vec<Binary>) -> Entry {
        reconstruct_peer_entry(conn, owner, uuid, &sk(), pool)
            .expect("reconstruct")
            .expect("peer row present")
    }

    /// One comparable record per version (live first, then history): the
    /// version with its history detached, custom fields sorted (the snapshot
    /// shape keys them by name), and its attachments resolved to
    /// `(name, bytes)` through `pool`, since the two sides' `ref_id`s index
    /// different pools.
    type Comparable = Vec<(Entry, Vec<(String, Vec<u8>)>)>;
    fn comparable(e: &Entry, pool: &[&[u8]]) -> Comparable {
        std::iter::once(e)
            .chain(&e.history)
            .map(|v| {
                let mut v = v.clone();
                v.history.clear();
                v.custom_fields.sort_by(|a, b| a.key.cmp(&b.key));
                let atts = v
                    .attachments
                    .drain(..)
                    .map(|a| (a.name, pool[a.ref_id as usize].to_vec()))
                    .collect();
                (v, atts)
            })
            .collect()
    }

    fn blob_refs(conn: &Connection, owner: &str, uuid: Uuid) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM conflict_entry_blob_ref WHERE owner = ?1 AND entry_uuid = ?2",
            params![owner, uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count blob refs")
    }

    #[test]
    fn badge_query_returns_distinct_uuids() {
        let conn = mem_conn();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // Two peers conflict on `a`; one peer on `b`.
        park(&conn, "peerB", &simple(a, "A", "x"), &[]);
        park(&conn, "peerC", &simple(a, "A", "y"), &[]);
        park(&conn, "peerB", &simple(b, "B", "z"), &[]);
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
        park(&conn, "peerB", &simple(id, "A", "x"), &[]);
        park(&conn, "peerC", &simple(id, "A", "y"), &[]);
        let owners = conflict_owners_for(&conn, id).expect("owners");
        assert_eq!(owners, vec!["peerB".to_string(), "peerC".to_string()]);
    }

    /// The peer row rebuilds the peer's entry exactly — every facet the
    /// mirror keeps, `<History>` included — so the resolver merges against
    /// the same entry the peer holds.
    #[test]
    fn reconstruct_round_trips_the_whole_entry() {
        let conn = mem_conn();
        let id = Uuid::new_v4();
        let pool: Vec<&[u8]> = vec![b"live-bytes", b"history-only-bytes", b"shared-bytes"];

        let version = |title: &str, tags: &[&str], mtime: i64| {
            let mut e = simple(id, title, &format!("pw-{title}"));
            e.username = format!("user-{title}");
            e.url = "https://example.com/login".into();
            e.notes = format!("notes-{title}");
            e.tags = tags.iter().map(|t| (*t).to_string()).collect();
            e.icon_id = 7;
            e.custom_icon_uuid = Some(Uuid::from_u128(0x00C0_FFEE));
            e.custom_fields = vec![
                CustomField::new("TOTP", format!("seed-{title}"), true),
                CustomField::new("note", format!("plain-{title}"), false),
            ];
            e.custom_data = vec![CustomDataItem::new(
                "keys.tag_state.v1".to_string(),
                format!("{{\"remove\":\"{title}\"}}"),
                at(mtime),
            )];
            let mut t = Timestamps::default();
            t.creation_time = at(1_000);
            t.last_modification_time = at(mtime);
            t.last_access_time = at(mtime + 1);
            e.times = t;
            e
        };
        let mut v1 = version("v1", &["alpha", "beta"], 2_000);
        v1.attachments = vec![
            Attachment::new("old.txt", 1),
            Attachment::new("shared.txt", 2),
        ];
        let mut v2 = version("v2", &["alpha"], 3_000);
        v2.times.expires = true;
        v2.times.expiry_time = at(9_000);
        let mut peer = version("live", &["alpha", "gamma"], 4_000);
        peer.attachments = vec![
            Attachment::new("doc.txt", 0),
            Attachment::new("shared.txt", 2),
        ];
        peer.history = vec![v1, v2];

        park(&conn, "peerB", &peer, &pool);
        let mut rebuilt_pool = Vec::new();
        let rebuilt = rebuild(&conn, "peerB", id, &mut rebuilt_pool);

        let rebuilt_bytes: Vec<&[u8]> = rebuilt_pool.iter().map(|b| b.data.as_slice()).collect();
        assert_eq!(
            comparable(&rebuilt, &rebuilt_bytes),
            comparable(&peer, &pool),
            "every version rebuilds exactly"
        );
        assert_eq!(
            rebuilt_pool.len(),
            3,
            "a sha shared across versions binds once"
        );
        assert_eq!(
            blob_refs(&conn, "peerB", id),
            3,
            "every version's bytes are GC-rooted"
        );
    }

    #[test]
    fn protected_values_are_sealed_at_rest() {
        let conn = mem_conn();
        let id = Uuid::new_v4();
        let mut peer = simple(id, "Acme", "s3cret-live");
        peer.custom_fields = vec![CustomField::new("TOTP", "s3cret-seed", true)];
        peer.history = vec![simple(id, "Acme", "s3cret-old")];
        park(&conn, "peerB", &peer, &[]);
        let json: String = conn
            .query_row("SELECT entry_json FROM conflict_entry", [], |r| r.get(0))
            .expect("row");
        assert!(!json.contains("s3cret"), "no protected plaintext at rest");
        let rebuilt = rebuild(&conn, "peerB", id, &mut Vec::new());
        assert_eq!(rebuilt.password, "s3cret-live");
        assert_eq!(rebuilt.custom_fields[0].value, "s3cret-seed");
        assert_eq!(rebuilt.history[0].password, "s3cret-old");
    }

    /// Bytes the caller's pool already holds are reused; a sha whose blob is
    /// gone skips rather than failing the rebuild.
    #[test]
    fn reconstruct_reuses_pool_bytes_and_skips_missing_blobs() {
        let conn = mem_conn();
        let id = Uuid::new_v4();
        let mut peer = simple(id, "Acme", "pw");
        peer.attachments = vec![
            Attachment::new("doc.txt", 0),
            Attachment::new("gone.txt", 1),
        ];
        park(&conn, "peerB", &peer, &[b"doc-bytes", b"gone-bytes"]);
        conn.execute(
            "DELETE FROM attachment_blob WHERE bytes = ?1",
            params![b"gone-bytes".as_slice()],
        )
        .expect("drop one blob");

        let mut pool = vec![
            Binary::new(b"unrelated".to_vec(), false),
            Binary::new(b"doc-bytes".to_vec(), false),
        ];
        let rebuilt = rebuild(&conn, "peerB", id, &mut pool);
        assert_eq!(pool.len(), 2, "known bytes reuse the pool's binary");
        assert_eq!(
            rebuilt.attachments,
            vec![Attachment::new("doc.txt", 1)],
            "the missing blob skips"
        );
    }

    /// A dangling `ref_id` is skipped, not recorded as the sha of empty
    /// bytes — which would resolve against any zero-byte blob and rebuild
    /// as a present, empty attachment.
    #[test]
    fn dangling_attachment_ref_rebuilds_absent() {
        let conn = mem_conn();
        let id = Uuid::new_v4();
        let mut peer = simple(id, "Acme", "pw");
        peer.attachments = vec![Attachment::new("phantom.txt", 5)];
        park(&conn, "peerB", &peer, &[]);

        let mut pool = vec![Binary::new(Vec::new(), false)];
        let rebuilt = rebuild(&conn, "peerB", id, &mut pool);
        assert!(
            rebuilt.attachments.is_empty(),
            "got {:?}",
            rebuilt.attachments
        );
    }

    #[test]
    fn drop_for_owner_is_owner_scoped() {
        // Two peers conflict on the same entry; dropping one owner's rows
        // must leave the other owner's rows (and badge) intact — the
        // owner-granular clear that prevents the multi-peer over-clear
        // (Finding #10 review).
        let conn = mem_conn();
        let id = Uuid::new_v4();
        let mut peer = simple(id, "A", "pw");
        peer.attachments = vec![Attachment::new("doc.txt", 0)];
        park(&conn, "peerB", &peer, &[b"bytes-B"]);
        park(&conn, "peerC", &peer, &[b"bytes-C"]);

        drop_conflict_rows_for_owner(&conn, "peerB", id).expect("drop peerB");

        assert_eq!(
            conflict_owners_for(&conn, id).unwrap(),
            vec!["peerC".to_string()],
            "only the dropped owner is removed"
        );
        assert_eq!(blob_refs(&conn, "peerB", id), 0, "peerB's GC roots gone");
        assert_eq!(blob_refs(&conn, "peerC", id), 1, "peerC's GC roots intact");
        assert_eq!(parked_conflict_uuids(&conn).unwrap(), vec![id]);

        // Owner-agnostic drop then clears the remainder.
        drop_conflict_rows(&conn, id).expect("drop all");
        assert!(parked_conflict_uuids(&conn).unwrap().is_empty());
        assert_eq!(blob_refs(&conn, "peerC", id), 0, "blob refs dropped too");
    }

    #[test]
    fn reconstruct_unknown_entry_returns_none() {
        let conn = mem_conn();
        assert!(
            reconstruct_peer_entry(&conn, "peerB", Uuid::new_v4(), &sk(), &mut Vec::new())
                .expect("reconstruct")
                .is_none()
        );
    }
}
