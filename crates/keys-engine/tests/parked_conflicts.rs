//! Integration tests for slice 5b — non-blocking reconcile via
//! [`keys_engine::Engine::reconcile_with_disk_park_conflicts`] plus
//! the marker-clearing surfaces
//! ([`Engine::entries_with_parked_conflict`] /
//! [`Engine::clear_parked_conflict_marker`]).
//!
//! Mirrors the fixture posture of `external_change_merge.rs`
//! (`FixedKey` + `FixedProtector` + seeded one-entry vault) so the two
//! test files exercise the same code path with different merge modes.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewEntry;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError, ParkConflictsResult};

// ── Fixtures (duplicated from external_change_merge.rs intentionally —
//    `tests/` files can't share helpers without a shared `common` mod,
//    and the existing test posture is to inline). ──

#[derive(Debug)]
struct FixedKey([u8; 32]);

impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

#[derive(Debug, Clone)]
struct FixedProtector([u8; 32]);

impl FieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes(self.0))
    }
}

const SESSION_KEY_BYTES: [u8; 32] = [0x9c; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];
const PASSWORD: &[u8] = b"pw";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(PASSWORD)
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), "test", Some(protector())).expect("create")
}

fn reopen_kdbx(path: &std::path::Path) -> Kdbx<Unlocked> {
    Kdbx::open(path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock kdbx")
}

struct Fixture {
    _dir: tempfile::TempDir,
    kdbx_path: std::path::PathBuf,
    engine: Engine,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed"))
        .expect("seed entry");
    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("initial save");
    let kdbx_reread = reopen_kdbx(&kdbx_path);
    engine
        .ingest_from_kdbx(&kdbx_reread)
        .expect("re-ingest from disk");
    Fixture {
        _dir: dir,
        kdbx_path,
        engine,
    }
}

// ── Tests ──

/// Trivial sanity: a clean reconcile with no actual divergence
/// returns `NoChange` from the park-conflicts surface too.
#[test]
fn park_conflicts_no_change_when_in_sync() {
    let mut f = fixture();
    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(matches!(result, ParkConflictsResult::NoChange));
}

/// Adds-only on disk apply through the park-conflicts variant the
/// same as the legacy variant: non-conflicting changes land, parked
/// summary is empty.
#[test]
fn park_conflicts_applies_non_conflicting_external_add() {
    let mut f = fixture();

    let mut external = reopen_kdbx(&f.kdbx_path);
    let root = external.vault().root.id;
    let new_id = external
        .add_entry(root, NewEntry::new("from-disk"))
        .expect("add external");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");

    match result {
        ParkConflictsResult::Applied { applied, parked } => {
            assert_eq!(applied.entries_added, 1, "one entry added");
            assert!(
                parked.entries_with_parked_conflict.is_empty(),
                "no conflicts to park",
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }

    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    assert!(summaries.iter().any(|s| s.uuid == new_id.0));
}

/// The headline test: a same-entry conflict on disk + locally lands
/// non-blocking. The merge applies via park-conflicts, the entry's
/// uuid surfaces in `entries_with_parked_conflict`, and the entry's
/// history has gained a record carrying the
/// `keys.field_conflict.v1` marker.
#[test]
fn park_conflicts_parks_field_conflict_into_history_with_marker() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    // Local edit via the engine.
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rename".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    // Concurrent disk edit via keepass-core.
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| {
                e.set_title("disk-rename");
            },
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    // Park-conflicts: applies successfully, parks the conflict.
    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    match result {
        ParkConflictsResult::Applied { parked, .. } => {
            assert_eq!(parked.entries_with_parked_conflict.len(), 1, "one parked");
            assert_eq!(
                parked.entries_with_parked_conflict[0],
                seed_uuid.to_string()
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }

    // Local current-state preserved.
    let after = f.engine.entry(seed_uuid).expect("entry").expect("present");
    assert_eq!(after.title, "local-rename");

    // The marker shows up in the marker query.
    let with_marker = f.engine.entries_with_parked_conflict().expect("query");
    assert_eq!(with_marker, vec![seed_uuid]);

    // The history list contains a snapshot tagged with the marker.
    let history = f.engine.history(seed_uuid).expect("history");
    let marker_snapshots: Vec<_> = history
        .iter()
        .filter(|h| {
            h.custom_data
                .iter()
                .any(|cd| cd.key == keepass_merge::FIELD_CONFLICT_CUSTOM_DATA_KEY)
        })
        .collect();
    assert_eq!(marker_snapshots.len(), 1, "exactly one parked snapshot");
    assert_eq!(marker_snapshots[0].title, "disk-rename");
}

/// `clear_parked_conflict_marker` tombstones the marker history
/// record: it disappears from history, the marker query no longer
/// surfaces the entry, and the entry's `custom_data` carries a
/// `keys.history_tombstones.v1` row so the cleanup propagates across
/// sync.
#[test]
fn clear_parked_conflict_marker_removes_marker_and_writes_tombstone() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rename".into()),
                ..Default::default()
            },
        )
        .expect("local edit");
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| e.set_title("disk-rename"),
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    f.engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
    );

    // Clear the marker.
    let cleared = f
        .engine
        .clear_parked_conflict_marker(seed_uuid, chrono::Utc::now())
        .expect("clear");
    assert_eq!(cleared, 1, "one marker cleared");

    // No more entries flagged.
    assert!(
        f.engine
            .entries_with_parked_conflict()
            .expect("query")
            .is_empty(),
        "no parked conflicts after clear",
    );

    // The marker history record is gone.
    let history = f.engine.history(seed_uuid).expect("history");
    assert!(
        !history.iter().any(|h| h
            .custom_data
            .iter()
            .any(|cd| { cd.key == keepass_merge::FIELD_CONFLICT_CUSTOM_DATA_KEY })),
        "marker-bearing history record removed",
    );

    // The tombstone landed on the live entry's custom_data —
    // visible via the projection.
    let full = f.engine.entry(seed_uuid).expect("entry").expect("present");
    assert!(
        full.custom_data
            .iter()
            .any(|cd| cd.key == keepass_merge::TOMBSTONE_CUSTOM_DATA_KEY),
        "tombstone written to entry custom_data — got {:?}",
        full.custom_data
            .iter()
            .map(|cd| &cd.key)
            .collect::<Vec<_>>(),
    );
}

/// Regression test for Bug #1 — `vaults_equivalent` short-circuited
/// reconcile on content-only edits (password/tags/custom fields/
/// attachments/custom icon), so a password edit on one Mac never
/// propagated to a peer. The fix replaces the field-content comparator
/// with a byte-equivalence check against the engine's last-saved
/// baseline. If the disk bytes differ from the baseline, the merge
/// runs unconditionally; identical content produces empty buckets that
/// the apply path treats as a no-op.
#[test]
fn two_engine_one_sided_password_edit_propagates() {
    use secrecy::{ExposeSecret, SecretString};

    let dir = tempfile::tempdir().expect("tempdir");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed")).expect("seed");

    // Engine A: ingests, saves the kdbx to disk.
    let db_a = dir.path().join("a.db");
    let mut engine_a =
        Engine::open(&db_a, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open a");
    engine_a.ingest_from_kdbx(&kdbx).expect("a ingest");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a save");

    // Engine B: reads the kdbx A wrote, ingests, then re-ingests after
    // re-reading from disk so its baseline equals the disk bytes.
    let kdbx_b_view = reopen_kdbx(&kdbx_path);
    let db_b = dir.path().join("b.db");
    let mut engine_b =
        Engine::open(&db_b, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open b");
    engine_b.ingest_from_kdbx(&kdbx_b_view).expect("b ingest");
    // Run an initial reconcile so B picks up the current disk bytes as
    // its baseline. (Without this, B's `last_saved_kdbx_bytes` is None
    // and the short-circuit falls through anyway, but we want to
    // exercise the post-baseline path.)
    let _ = engine_b
        .reconcile_with_disk_park_conflicts(&kdbx_path, &composite(), chrono::Utc::now())
        .expect("b initial reconcile");

    let seed_uuid = engine_a
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // A edits ONLY the password — the kind of edit `vaults_equivalent`
    // used to ignore (it only compared title/username/url/notes).
    engine_a
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                password: Some(SecretString::from("new-secret-pw".to_string())),
                ..Default::default()
            },
        )
        .expect("a edit pw");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a save 2");

    // B reconciles — must see the password edit, not NoChange.
    let result = engine_b
        .reconcile_with_disk_park_conflicts(&kdbx_path, &composite(), chrono::Utc::now())
        .expect("b reconcile");
    match result {
        ParkConflictsResult::Applied { .. } => {
            // The merge ran. Whether the change lands in
            // `entries_updated` or via the park path is incidental for
            // Bug #1 — what matters is that the short-circuit didn't
            // swallow it. The password assertion below proves the
            // edit actually reached B.
        }
        ParkConflictsResult::NoChange => {
            panic!("password-only edit was lost (Bug #1 — vaults_equivalent ignored password)")
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Verify the password actually landed in B's projection.
    let revealed = engine_b.reveal_password(seed_uuid).expect("reveal");
    assert_eq!(revealed.expose_secret(), "new-secret-pw");
}

/// Clearing an entry with no markers is a clean no-op.
#[test]
fn clear_parked_conflict_marker_no_op_on_clean_entry() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    let cleared = f
        .engine
        .clear_parked_conflict_marker(seed_uuid, chrono::Utc::now())
        .expect("clear");
    assert_eq!(cleared, 0);
}

/// Bug #2 regression: a one-sided engine edit on Mac-A must reconcile
/// cleanly on Mac-B without parking a conflict. Before the fix the
/// engine's mutations didn't push a history snapshot of the pre-edit
/// state, so the projected kdbx had empty `<History>` for the edited
/// entry — the peer's merger then had no common ancestor and fell back
/// to parking. After the fix, A's save carries the pre-edit snapshot
/// and the merger adopts the change as a clean update.
#[test]
fn two_engine_one_sided_title_edit_updates_without_parking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed"))
        .expect("seed entry");

    // Mac-A engine: owns the kdbx, will edit and save.
    let db_a = dir.path().join("a.db");
    let mut engine_a =
        Engine::open(&db_a, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open a");
    engine_a.ingest_from_kdbx(&kdbx).expect("a ingest");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a initial save");

    // Mac-B engine: ingests from the same disk file.
    let kdbx_b_view = reopen_kdbx(&kdbx_path);
    let db_b = dir.path().join("b.db");
    let mut engine_b =
        Engine::open(&db_b, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open b");
    engine_b.ingest_from_kdbx(&kdbx_b_view).expect("b ingest");

    let summaries = engine_a
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    // Mac-A: edit the title via the engine, save to disk.
    engine_a
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("edited-on-A".into()),
                ..Default::default()
            },
        )
        .expect("a edit");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a save");

    // Mac-B: reconcile against the updated disk. No conflict should be parked.
    let result = engine_b
        .reconcile_with_disk_park_conflicts(&kdbx_path, &composite(), chrono::Utc::now())
        .expect("b reconcile");

    match result {
        ParkConflictsResult::Applied { applied, parked } => {
            assert!(
                parked.entries_with_parked_conflict.is_empty(),
                "B should not park; got: {:?}",
                parked.entries_with_parked_conflict
            );
            assert_eq!(
                applied.entries_updated, 1,
                "B should adopt A's edit as a clean update"
            );
        }
        other => panic!("expected Applied with one update, got {other:?}"),
    }

    let after = engine_b.entry(seed_uuid).expect("entry").expect("present");
    assert_eq!(after.title, "edited-on-A");
}
