//! Integration tests for the [`FileWatcher`] trait and the
//! [`NotifyFileWatcher`] default impl — Phase 4 task 4.5.
//!
//! Notify-backed tests are inherently timing-flaky because filesystem
//! events are asynchronous. Tests use a short polling loop with a
//! generous timeout rather than fixed sleeps; if the timeout fires the
//! test fails with a clear message.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, DisconnectReason, Engine, FileWatcher, FileWatcherEvent, FileWatcherObserver,
    KeyProvider, KeyProviderError, NotifyFileWatcher, VaultState,
};

// ────────────────────────────────────────────────────────────────────────
// Test fixtures.
// ────────────────────────────────────────────────────────────────────────

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

const DB_KEY_BYTES: [u8; 32] = [0x42; 32];
const SESSION_KEY_BYTES: [u8; 32] = [0x9c; 32];

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

/// Capture observer that records every event it receives.
#[derive(Debug, Default)]
struct CaptureObserver {
    events: Mutex<Vec<FileWatcherEvent>>,
}

impl FileWatcherObserver for CaptureObserver {
    fn on_event(&self, event: FileWatcherEvent) {
        self.events.lock().unwrap().push(event);
    }
}

impl CaptureObserver {
    fn snapshot(&self) -> Vec<FileWatcherEvent> {
        self.events.lock().unwrap().clone()
    }
}

/// Synthetic file watcher whose events are driven by the test itself.
/// Useful for asserting engine-side filtering / state-transition logic
/// without relying on the OS to deliver real fs events.
#[derive(Debug, Default)]
struct ManualFileWatcher {
    observer: Mutex<Option<Arc<dyn FileWatcherObserver>>>,
}

impl ManualFileWatcher {
    fn fire(&self, event: FileWatcherEvent) {
        let guard = self.observer.lock().unwrap();
        if let Some(obs) = guard.as_ref() {
            obs.on_event(event);
        }
    }
}

impl FileWatcher for ManualFileWatcher {
    fn set_observer(&self, observer: Option<Arc<dyn FileWatcherObserver>>) {
        *self.observer.lock().unwrap() = observer;
    }
}

/// Poll `cond` every 25ms for up to `timeout`. Returns true if it ever
/// became true. Used in place of fixed sleeps to keep notify-backed
/// tests reliable on slow CI runners.
fn poll_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) -> bool {
    let start = Instant::now();
    loop {
        if cond() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

const EVENT_TIMEOUT: Duration = Duration::from_secs(4);

// ────────────────────────────────────────────────────────────────────────
// NotifyFileWatcher behavioural tests.
// ────────────────────────────────────────────────────────────────────────

#[test]
fn notify_watcher_fires_on_external_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.kdbx");
    std::fs::write(&path, b"initial").expect("seed file");

    let watcher = NotifyFileWatcher::new(path.clone()).expect("watcher");
    let observer = Arc::new(CaptureObserver::default());
    watcher.set_observer(Some(observer.clone()));

    // Give the watcher a moment to register before the write so we
    // don't race the platform watcher startup.
    std::thread::sleep(Duration::from_millis(150));

    std::fs::write(&path, b"externally modified").expect("external write");

    let saw_change = poll_until(EVENT_TIMEOUT, || {
        observer
            .snapshot()
            .iter()
            .any(|e| matches!(e, FileWatcherEvent::ContentChanged { .. }))
    });
    assert!(
        saw_change,
        "expected ContentChanged within timeout, got {:?}",
        observer.snapshot()
    );
}

#[test]
fn notify_watcher_fires_on_unavailable_after_remove() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.kdbx");
    std::fs::write(&path, b"initial").expect("seed file");

    let watcher = NotifyFileWatcher::new(path.clone()).expect("watcher");
    let observer = Arc::new(CaptureObserver::default());
    watcher.set_observer(Some(observer.clone()));

    std::thread::sleep(Duration::from_millis(150));

    std::fs::remove_file(&path).expect("remove");

    let saw = poll_until(EVENT_TIMEOUT, || {
        observer
            .snapshot()
            .iter()
            .any(|e| matches!(e, FileWatcherEvent::Unavailable { .. }))
    });
    assert!(
        saw,
        "expected Unavailable within timeout, got {:?}",
        observer.snapshot()
    );
}

#[test]
fn notify_watcher_fires_on_available_after_recreate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.kdbx");
    std::fs::write(&path, b"initial").expect("seed file");

    let watcher = NotifyFileWatcher::new(path.clone()).expect("watcher");
    let observer = Arc::new(CaptureObserver::default());
    watcher.set_observer(Some(observer.clone()));

    std::thread::sleep(Duration::from_millis(150));

    std::fs::remove_file(&path).expect("remove");
    // Wait until the watcher has acknowledged the removal — only then
    // does a Create map to Available rather than ContentChanged.
    let saw_remove = poll_until(EVENT_TIMEOUT, || {
        observer
            .snapshot()
            .iter()
            .any(|e| matches!(e, FileWatcherEvent::Unavailable { .. }))
    });
    assert!(saw_remove, "expected Unavailable before recreate");

    std::fs::write(&path, b"recreated").expect("recreate");

    let saw_available = poll_until(EVENT_TIMEOUT, || {
        observer
            .snapshot()
            .iter()
            .any(|e| matches!(e, FileWatcherEvent::Available))
    });
    assert!(
        saw_available,
        "expected Available after recreate, got {:?}",
        observer.snapshot()
    );
}

// ────────────────────────────────────────────────────────────────────────
// Engine-side integration tests (synthetic watcher).
// ────────────────────────────────────────────────────────────────────────

#[test]
fn self_write_signature_suppresses_engine_reconcile_callback() {
    // Open an engine with a manual file watcher. Save once to populate
    // the self-write signature, then fire a synthetic ContentChanged
    // event with the same path; the engine-side filter should consume
    // the signature and suppress the reconcile call.

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let manual: Arc<ManualFileWatcher> = Arc::new(ManualFileWatcher::default());
    let manual_dyn: Arc<dyn FileWatcher> = manual.clone();
    // The engine's SQLite handle lives at `db_path`; the watcher's
    // target is the KDBX at `kdbx_path` (that's what gets written via
    // save_to_kdbx and what an external editor would touch). The
    // engine's internal observer stats `kdbx_path` when filtering
    // ContentChanged events. Engine::open takes the SQLite path; we
    // pass the kdbx path via the watcher's target_path coupling below.
    let mut engine = Engine::open(
        &db_path,
        &FixedKey(DB_KEY_BYTES),
        protector(),
        Some(manual_dyn),
    )
    .expect("open engine");

    // Ingest from + save to a kdbx file at `kdbx_path`. Use a fresh
    // empty kdbx so the save path materialises the file.
    let composite = keepass_core::CompositeKey::from_password(b"pw");
    let mut kdbx = keepass_core::kdbx::Kdbx::create_empty_v4_with_protector(
        &composite,
        "test",
        Some(protector()),
    )
    .expect("create empty kdbx");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save");

    assert!(
        engine.last_self_write().is_some(),
        "save_to_kdbx should record a self-write signature"
    );
    assert_eq!(engine.pending_reconcile_calls_for_test(), 0);

    // Fire a synthetic ContentChanged that carries (mtime, size)
    // matching the just-recorded signature. The engine observer sees
    // them match and suppresses the reconcile call.
    let sig = engine.last_self_write().expect("signature recorded");
    manual.fire(FileWatcherEvent::ContentChanged {
        mtime: Some(sig.mtime),
        size: Some(sig.size),
    });

    assert_eq!(
        engine.pending_reconcile_calls_for_test(),
        0,
        "self-write signature should suppress reconcile call"
    );
    assert!(
        engine.last_self_write().is_none(),
        "signature should be consumed by the observer"
    );

    // A second ContentChanged (no signature now) should pass through.
    manual.fire(FileWatcherEvent::ContentChanged {
        mtime: Some(sig.mtime),
        size: Some(sig.size),
    });
    assert_eq!(engine.pending_reconcile_calls_for_test(), 1);
}

#[test]
fn engine_state_transitions_on_unavailable_and_available() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");

    let manual: Arc<ManualFileWatcher> = Arc::new(ManualFileWatcher::default());
    let manual_dyn: Arc<dyn FileWatcher> = manual.clone();
    let engine = Engine::open(
        &db_path,
        &FixedKey(DB_KEY_BYTES),
        protector(),
        Some(manual_dyn),
    )
    .expect("open engine");

    assert_eq!(engine.state(), VaultState::Active);

    manual.fire(FileWatcherEvent::Unavailable {
        reason: "deleted by user".to_owned(),
    });

    match engine.state() {
        VaultState::Disconnected {
            reason: DisconnectReason::FileUnreadable(msg),
        } => assert!(msg.contains("deleted"), "unexpected reason: {msg}"),
        other => panic!("expected Disconnected/FileUnreadable, got {other:?}"),
    }

    manual.fire(FileWatcherEvent::Available);
    assert_eq!(engine.state(), VaultState::Active);
}

#[test]
fn engine_open_without_file_watcher_works() {
    // Smoke-test: passing None for file_watcher should leave every
    // existing path (ingest, save) untouched.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    assert_eq!(engine.state(), VaultState::Active);
    assert!(engine.file_watcher().is_none());

    let composite = keepass_core::CompositeKey::from_password(b"pw");
    let mut kdbx = keepass_core::kdbx::Kdbx::create_empty_v4_with_protector(
        &composite,
        "test",
        Some(protector()),
    )
    .expect("create");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save");
    assert!(engine.last_self_write().is_some());
}

#[test]
fn drop_engine_terminates_watcher_thread() {
    // The NotifyFileWatcher exposes a test-only sentinel thread whose
    // only job is to outlive the watcher; when the watcher is dropped
    // (i.e. its observer Mutex's last Arc is gone), the sentinel
    // exits. If `Engine::drop` correctly drops the watcher we hold,
    // joining the sentinel will succeed within a small timeout.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.kdbx");
    std::fs::write(&path, b"seed").expect("seed");

    let watcher = Arc::new(NotifyFileWatcher::new(path.clone()).expect("watcher"));
    let sentinel = watcher.take_sentinel_for_test().expect("sentinel handle");

    // Drop our reference; nothing else holds the watcher.
    drop(watcher);

    // Sentinel polls every 20ms; allow generously for CI.
    let join_result = std::thread::spawn(move || sentinel.join())
        .join()
        .expect("join wrapper");
    assert!(
        join_result.is_ok(),
        "sentinel thread should join cleanly after watcher drop"
    );
}
