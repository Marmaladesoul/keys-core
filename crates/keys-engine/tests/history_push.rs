//! Bug #2 regression suite — every content-mutating entry path must
//! push exactly one history snapshot of the pre-edit state, and the
//! prune pass must respect `keys.field_conflict.v1` markers.
//!
//! Tests run against the public `Engine` surface so they exercise the
//! same enforcement funnel a real caller would hit.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewEntry;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EntryUpdate, KeyProvider, KeyProviderError};
use secrecy::SecretString;

// ── fixtures (same pattern as parked_conflicts.rs) ──────────────────

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

const SESSION_KEY_BYTES: [u8; 32] = [0xa1; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}
fn composite() -> CompositeKey {
    CompositeKey::from_password(b"pw")
}
fn fresh_kdbx() -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), "t", Some(protector())).expect("create")
}

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
    seed_uuid: uuid::Uuid,
}

fn seed_with_password(password: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("seed").password(SecretString::new(password.to_owned().into())),
        )
        .expect("seed");
    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    Fixture {
        _dir: dir,
        engine,
        seed_uuid: id.0,
    }
}

fn fixture() -> Fixture {
    seed_with_password("orig-pw")
}

// ── single-snapshot tests ───────────────────────────────────────────

#[test]
fn title_only_edit_pushes_exactly_one_snapshot() {
    let mut f = fixture();
    f.engine
        .update_entry(
            f.seed_uuid,
            EntryUpdate {
                title: Some("renamed".into()),
                ..Default::default()
            },
        )
        .expect("update");
    let history = f.engine.history(f.seed_uuid).expect("history");
    assert_eq!(history.len(), 1, "exactly one snapshot");
    assert_eq!(history[0].title, "seed", "pre-edit title captured");
}

#[test]
fn password_only_edit_pushes_one_snapshot_with_preedit_state() {
    let mut f = seed_with_password("orig-pw");
    let live_before = f
        .engine
        .entry(f.seed_uuid)
        .expect("entry")
        .expect("present");
    let mtime_before = live_before.modified_at;

    // ensure clock can advance at least a millisecond between edit
    // operations so the bumped mtime is observably newer.
    std::thread::sleep(std::time::Duration::from_millis(2));

    f.engine
        .update_entry(
            f.seed_uuid,
            EntryUpdate {
                password: Some(SecretString::new("new-pw".to_owned().into())),
                ..Default::default()
            },
        )
        .expect("password edit");

    let history = f.engine.history(f.seed_uuid).expect("history");
    assert_eq!(history.len(), 1, "exactly one snapshot");
    assert_eq!(
        history[0].modified_at, mtime_before,
        "snapshot mtime is pre-edit",
    );

    let live_after = f
        .engine
        .entry(f.seed_uuid)
        .expect("entry")
        .expect("present");
    assert!(
        live_after.modified_at > mtime_before,
        "live mtime advanced ({} <= {})",
        live_after.modified_at,
        mtime_before,
    );
}

#[test]
fn multi_field_edit_pushes_exactly_one_snapshot() {
    let mut f = fixture();
    f.engine
        .update_entry(
            f.seed_uuid,
            EntryUpdate {
                title: Some("t".into()),
                url: Some("https://example.com".into()),
                notes: Some("n".into()),
                ..Default::default()
            },
        )
        .expect("update");
    let history = f.engine.history(f.seed_uuid).expect("history");
    assert_eq!(history.len(), 1, "one snapshot per logical edit");
}

#[test]
fn tag_change_pushes_one_snapshot() {
    let mut f = fixture();
    f.engine
        .set_tags(f.seed_uuid, vec!["work".into()])
        .expect("set tags");
    let history = f.engine.history(f.seed_uuid).expect("history");
    assert_eq!(history.len(), 1);
}

#[test]
fn tag_noop_pushes_zero_snapshots() {
    let mut f = fixture();
    f.engine
        .set_tags(f.seed_uuid, vec!["work".into(), "secure".into()])
        .expect("initial set");
    let before = f.engine.history(f.seed_uuid).expect("history").len();
    // Re-set the same tags (different order, with duplicates, extra
    // whitespace — all normalise to the same set).
    f.engine
        .set_tags(
            f.seed_uuid,
            vec!["secure".into(), "  work  ".into(), "work".into()],
        )
        .expect("noop set");
    let after = f.engine.history(f.seed_uuid).expect("history").len();
    assert_eq!(before, after, "no-op tag set must not push history");
}

#[test]
fn custom_field_add_then_delete_pushes_two_snapshots() {
    let mut f = fixture();
    f.engine
        .set_non_protected_custom_field(f.seed_uuid, "Website", "example.com")
        .expect("add cf");
    let after_add = f.engine.history(f.seed_uuid).expect("h").len();
    assert_eq!(after_add, 1);
    f.engine
        .remove_custom_field(f.seed_uuid, "Website")
        .expect("rm cf");
    let after_del = f.engine.history(f.seed_uuid).expect("h").len();
    assert_eq!(after_del, 2);
}

#[test]
fn touch_entry_pushes_zero_snapshots() {
    let mut f = fixture();
    f.engine.touch_entry(f.seed_uuid).expect("touch");
    let history = f.engine.history(f.seed_uuid).expect("history");
    assert_eq!(history.len(), 0, "touch is not a content edit");
}

#[test]
fn two_consecutive_edits_push_two_snapshots_in_order() {
    let mut f = fixture();
    f.engine
        .update_entry(
            f.seed_uuid,
            EntryUpdate {
                title: Some("v1".into()),
                ..Default::default()
            },
        )
        .expect("e1");
    std::thread::sleep(std::time::Duration::from_millis(2));
    f.engine
        .update_entry(
            f.seed_uuid,
            EntryUpdate {
                title: Some("v2".into()),
                ..Default::default()
            },
        )
        .expect("e2");
    let history = f.engine.history(f.seed_uuid).expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].title, "seed", "oldest first");
    assert_eq!(history[1].title, "v1");
    assert!(
        history[0].modified_at <= history[1].modified_at,
        "snapshots ordered by mtime",
    );
}

// ── pruning tests ───────────────────────────────────────────────────

#[test]
fn prune_respects_history_max_items() {
    let mut f = fixture();
    f.engine.set_history_max_items(3).expect("cap");
    for i in 0..5 {
        f.engine
            .update_entry(
                f.seed_uuid,
                EntryUpdate {
                    title: Some(format!("v{i}")),
                    ..Default::default()
                },
            )
            .expect("update");
    }
    let history = f.engine.history(f.seed_uuid).expect("history");
    assert_eq!(history.len(), 3, "trimmed to cap");
    // The kept records are the three most recent: snapshots taken
    // just before "v2", "v3", and "v4" — i.e. their pre-edit titles
    // were "v1", "v2", "v3".
    assert_eq!(history[0].title, "v1");
    assert_eq!(history[1].title, "v2");
    assert_eq!(history[2].title, "v3");
}

#[test]
fn prune_respects_history_max_size() {
    let mut f = fixture();
    // Very small size budget — 1 KiB. Any single sizeable edit will
    // saturate it, forcing eviction.
    f.engine.set_history_max_size(1024).expect("cap");
    let big_notes = "x".repeat(2000);
    for _ in 0..3 {
        f.engine
            .update_entry(
                f.seed_uuid,
                EntryUpdate {
                    notes: Some(big_notes.clone()),
                    ..Default::default()
                },
            )
            .expect("update");
    }
    let history = f.engine.history(f.seed_uuid).expect("history");
    assert!(
        history.len() < 3,
        "size budget evicted some snapshots ({} kept)",
        history.len()
    );
}

#[test]
fn round_trip_history_via_kdbx() {
    let mut f = fixture();
    let dir = tempfile::tempdir().expect("td");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("placeholder"))
        .expect("ph");

    f.engine
        .update_entry(
            f.seed_uuid,
            EntryUpdate {
                title: Some("e1".into()),
                ..Default::default()
            },
        )
        .expect("e1");
    std::thread::sleep(std::time::Duration::from_millis(2));
    f.engine
        .update_entry(
            f.seed_uuid,
            EntryUpdate {
                title: Some("e2".into()),
                ..Default::default()
            },
        )
        .expect("e2");

    // Save through the engine's own ingest-projected kdbx — go through
    // a fresh shell to project onto.
    let mut shell = fresh_kdbx();
    f.engine
        .save_to_kdbx(&kdbx_path, &mut shell, None)
        .expect("save");

    // Reopen via a fresh engine and verify history is intact + ordered.
    let dir2 = tempfile::tempdir().expect("td2");
    let mut engine2 = Engine::open(
        &dir2.path().join("k2.db"),
        &FixedKey(DB_KEY_BYTES),
        protector(),
        None,
    )
    .expect("open2");
    let kdbx2 = Kdbx::open(&kdbx_path)
        .expect("open kdbx")
        .read_header()
        .expect("hdr")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock");
    engine2.ingest_from_kdbx(&kdbx2).expect("ingest2");
    let history2 = engine2.history(f.seed_uuid).expect("history2");
    assert_eq!(history2.len(), 2);
    assert_eq!(history2[0].title, "seed");
    assert_eq!(history2[1].title, "e1");
}
