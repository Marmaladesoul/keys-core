//! Integration tests for [`Engine::restore_entry_from_history`]
//! (6.17-I final unblock — preservation semantics matching legacy
//! `Vault::restore_entry_from_history` under `HistoryPolicy::Snapshot`).

use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomFieldValue, HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    ChangeEvent, DataChangeObserver, DbKey, Engine, EngineError, KeyProvider, KeyProviderError,
    Pagination, StrengthBucket,
};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

// ── test wiring (same shape as tests/history_mutations.rs) ─────────────

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

const SESSION_KEY_BYTES: [u8; 32] = [0x6c; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

#[derive(Default, Debug)]
struct CaptureObserver {
    events: Mutex<Vec<ChangeEvent>>,
}

impl CaptureObserver {
    fn snapshot(&self) -> Vec<ChangeEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl DataChangeObserver for CaptureObserver {
    fn on_event(&self, event: ChangeEvent) {
        self.events.lock().unwrap().push(event);
    }
}

/// Engine pre-populated with one entry that has three history snapshots:
/// snap 0 = "v0", snap 1 = "v1", snap 2 = "v2"; live entry = "v3".
fn engine_with_history() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("v0")).expect("add");
    for label in ["v1", "v2", "v3"] {
        let owned = label.to_owned();
        kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
            e.set_title(&owned);
        })
        .expect("edit");
    }
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, id.0, dir)
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn restore_clones_snapshot_and_pushes_pre_restore_to_tail() {
    let (mut engine, id, _dir) = engine_with_history();

    // Sanity baseline.
    let before = engine.history(id).expect("history");
    assert_eq!(before.len(), 3);
    assert_eq!(before[0].title, "v0");
    assert_eq!(before[1].title, "v1");
    assert_eq!(before[2].title, "v2");
    let live_before = engine.entry(id).expect("entry").expect("present");
    assert_eq!(live_before.title, "v3");
    let modified_before = live_before.modified_at;

    // Sleep 2ms so the post-restore modified_at is strictly greater
    // even on coarse-resolution clocks.
    std::thread::sleep(std::time::Duration::from_millis(2));

    engine.restore_entry_from_history(id, 0).expect("restore");

    // Live entry now reflects snap 0 ("v0").
    let live_after = engine.entry(id).expect("entry").expect("present");
    assert_eq!(live_after.title, "v0");
    assert!(
        live_after.modified_at > modified_before,
        "modified_at must bump on restore: before={}, after={}",
        modified_before,
        live_after.modified_at,
    );

    // History list grew by one: snap 0 (v0) preserved, then v1, v2, and
    // the pre-restore live state ("v3") appended at index 3.
    let after = engine.history(id).expect("history");
    assert_eq!(after.len(), 4, "history must grow by one on restore");
    assert_eq!(after[0].history_index, 0);
    assert_eq!(after[0].title, "v0", "targeted snapshot must be preserved");
    assert_eq!(after[1].history_index, 1);
    assert_eq!(after[1].title, "v1");
    assert_eq!(after[2].history_index, 2);
    assert_eq!(after[2].title, "v2");
    assert_eq!(after[3].history_index, 3);
    assert_eq!(
        after[3].title, "v3",
        "pre-restore live state must be the new tail snapshot",
    );
}

#[test]
fn restore_emits_entries_updated() {
    let (mut engine, id, _dir) = engine_with_history();
    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    engine.restore_entry_from_history(id, 1).expect("restore");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1, "expected one event, got {events:?}");
    match &events[0] {
        ChangeEvent::EntriesUpdated(v) => assert_eq!(v, &vec![id]),
        other => panic!("expected EntriesUpdated([{id}]), got {other:?}"),
    }
}

#[test]
fn restore_unknown_entry_returns_not_found_entry() {
    let (mut engine, _id, _dir) = engine_with_history();
    let err = engine
        .restore_entry_from_history(Uuid::new_v4(), 0)
        .expect_err("missing entry should error");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "entry"),
        other => panic!("expected NotFound entry, got {other:?}"),
    }
}

#[test]
fn restore_oob_index_returns_not_found_history_snapshot() {
    let (mut engine, id, _dir) = engine_with_history();
    let err = engine
        .restore_entry_from_history(id, 99)
        .expect_err("OOB index should error");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "history_snapshot"),
        other => panic!("expected NotFound history_snapshot, got {other:?}"),
    }
    // History is untouched after the failed restore.
    let history = engine.history(id).expect("history");
    assert_eq!(history.len(), 3);
}

#[test]
fn restore_unwraps_protected_password_field() {
    // Build a vault where the historic snapshot carries one password
    // and the live entry carries a different one. After restore, the
    // reveal path on the live entry should hand back the historic
    // password.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("acct").password(SecretString::from("history-secret")),
        )
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("live-secret"));
    })
    .expect("edit");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    // Pre-restore: live reveals "live-secret".
    let live_pw = engine.reveal_password(id.0).expect("reveal live");
    assert_eq!(live_pw.expose_secret(), "live-secret");

    engine.restore_entry_from_history(id.0, 0).expect("restore");

    let restored_pw = engine.reveal_password(id.0).expect("reveal restored");
    assert_eq!(restored_pw.expose_secret(), "history-secret");
}

#[test]
fn restore_protected_custom_field_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("acct")).expect("add");
    // First edit sets the historic value; we use Snapshot so the
    // snapshot captures the state PRIOR to this edit (no Token field
    // at all). So instead build: add → set Token=history → snapshot →
    // set Token=live → snapshot. Then history[1] carries "history".
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("history-token")),
        );
    })
    .expect("set history token");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("live-token")),
        );
    })
    .expect("set live token");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    assert_eq!(
        engine
            .reveal_custom_field(id.0, "Token")
            .expect("live token")
            .expose_secret(),
        "live-token",
    );

    // History order: [0] = no Token, [1] = "history-token".
    engine.restore_entry_from_history(id.0, 1).expect("restore");

    assert_eq!(
        engine
            .reveal_custom_field(id.0, "Token")
            .expect("restored token")
            .expose_secret(),
        "history-token",
    );
}

#[test]
fn restore_recomputes_password_strength_bucket() {
    // History snapshot carries a strong password; live entry carries a
    // weak one. After restore, `password_strength_bucket` should
    // reflect the strong password.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let strong = "c0rrect-horse-battery-staple-78xz!!Q";
    let weak = "a";
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("acct").password(SecretString::from(strong)),
        )
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from(weak));
    })
    .expect("weaken");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let live_before = engine.entry(id.0).expect("entry").expect("present");
    let weak_bucket = live_before
        .password_strength_bucket
        .expect("bucket present");
    assert!(
        matches!(weak_bucket, StrengthBucket::VeryWeak | StrengthBucket::Weak),
        "weak password expected in low buckets, got {weak_bucket:?}",
    );

    engine.restore_entry_from_history(id.0, 0).expect("restore");

    let live_after = engine.entry(id.0).expect("entry").expect("present");
    let strong_bucket = live_after.password_strength_bucket.expect("bucket present");
    assert!(
        strong_bucket > weak_bucket,
        "restoring strong password should raise the bucket: \
         before={weak_bucket:?}, after={strong_bucket:?}",
    );
    assert!(
        matches!(
            strong_bucket,
            StrengthBucket::Strong | StrengthBucket::VeryStrong,
        ),
        "strong password expected in upper buckets, got {strong_bucket:?}",
    );
}

#[test]
fn restore_flips_has_totp_when_snapshot_carries_totp_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("acct")).expect("add");
    // History[0] captures the no-TOTP state. Then we add the TOTP
    // field with Snapshot, so history[1] carries the TOTP field.
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_custom_field(
            "otp",
            CustomFieldValue::Protected(SecretString::from(
                "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Example",
            )),
        );
    })
    .expect("add otp");
    // Final edit removes the TOTP field — live has no TOTP, history[1]
    // is the snapshot of the otp-bearing state.
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.remove_custom_field("otp");
    })
    .expect("remove otp");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let live_before = engine
        .list_entries(None, Pagination::all())
        .expect("entries")
        .into_iter()
        .find(|e| e.uuid == id.0)
        .expect("entry summary");
    assert!(!live_before.has_totp, "live entry must not carry TOTP");

    // Restore the otp-bearing snapshot (history index 1).
    engine.restore_entry_from_history(id.0, 1).expect("restore");

    let live_after = engine
        .list_entries(None, Pagination::all())
        .expect("entries")
        .into_iter()
        .find(|e| e.uuid == id.0)
        .expect("entry summary");
    assert!(
        live_after.has_totp,
        "restoring a snapshot with a TOTP field must flip has_totp on",
    );
}

#[test]
fn restore_preserves_targeted_snapshot_in_list() {
    // Explicit cross-check of the preservation invariant against the
    // legacy `keepass_core::Kdbx::restore_entry_from_history` semantics:
    // the snapshot at `history_index` must still be present after the
    // restore call, at its original index.
    let (mut engine, id, _dir) = engine_with_history();
    let before = engine.history(id).expect("history");
    let target = before[1].clone();
    assert_eq!(target.title, "v1");

    engine.restore_entry_from_history(id, 1).expect("restore");

    let after = engine.history(id).expect("history");
    // Index 1 is still "v1" — the snapshot was cloned out, not consumed.
    assert_eq!(after[1].history_index, 1);
    assert_eq!(after[1].title, "v1");
}

#[test]
fn restore_trims_oldest_when_history_max_items_exceeded() {
    let (mut engine, id, _dir) = engine_with_history();
    // After this restore the list would be 4 entries long. Force a
    // cap of 3 so the oldest (the original snap 0 = "v0") is trimmed.
    engine.set_history_max_items(3).expect("cap");

    engine.restore_entry_from_history(id, 2).expect("restore");

    let after = engine.history(id).expect("history");
    assert_eq!(
        after.len(),
        3,
        "history must be trimmed to history_max_items"
    );
    // Oldest dropped. Surviving rows are dense 0..N.
    assert_eq!(after[0].history_index, 0);
    assert_eq!(after[0].title, "v1");
    assert_eq!(after[1].history_index, 1);
    assert_eq!(after[1].title, "v2");
    assert_eq!(after[2].history_index, 2);
    // The pre-restore "v3" became the new tail snapshot.
    assert_eq!(after[2].title, "v3");
}
