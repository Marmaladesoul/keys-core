//! Integration tests for the reveal surface (task 3.4):
//! [`Engine::reveal_password`], [`Engine::reveal_custom_field`],
//! [`Engine::reveal_history_field`].
//!
//! Same wiring shape as `entry_reads.rs`: build an in-memory KDBX via
//! `keepass_core::Kdbx::create_empty_v4_with_protector`, ingest into a
//! fresh engine, then assert on the reveal response.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomFieldValue, HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EngineError, KeyProvider, KeyProviderError, RevealError};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

// ── test wiring ────────────────────────────────────────────────────────

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

/// Counts `acquire_session_key` calls so tests can assert reveals
/// don't cache the key.
#[derive(Debug)]
struct CountingFieldProtector {
    bytes: [u8; 32],
    calls: AtomicUsize,
}

impl CountingFieldProtector {
    fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl FieldProtector for CountingFieldProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SessionKey::from_bytes(self.bytes))
    }
}

const SESSION_KEY_BYTES: [u8; 32] = [0x9c; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector()).expect("open engine")
}

fn open_engine_with(path: &std::path::Path, p: Arc<dyn FieldProtector>) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), p).expect("open engine")
}

fn assert_not_found(err: &EngineError, expected_entity: &str) {
    match err {
        EngineError::NotFound { entity } => assert_eq!(*entity, expected_entity),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

// ── reveal_password ────────────────────────────────────────────────────

#[test]
fn reveal_password_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("acme").password(SecretString::from("hunter2")),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let revealed = engine.reveal_password(id.0).expect("reveal");
    assert_eq!(revealed.expose_secret(), "hunter2");
}

#[test]
fn reveal_password_returns_not_found_for_missing_uuid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine.reveal_password(Uuid::new_v4()).expect_err("missing");
    assert_not_found(&err, "password");
}

#[test]
fn reveal_password_returns_not_found_when_entry_has_no_password_row() {
    // Ingest writes a Password row unconditionally (even for empty
    // passwords), so the only way to land here is to delete the row
    // out of band. We do that via direct SQL to simulate corruption /
    // an external writer. The contract is documented on
    // `reveal_password`: missing row → NotFound, empty plaintext →
    // Ok(empty SecretString).
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(root, NewEntry::new("empty-pw"))
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    // Sanity: with the row in place we get Ok("").
    let revealed = engine.reveal_password(id.0).expect("reveal empty");
    assert_eq!(revealed.expose_secret(), "");

    // Now drop the row and re-open to surface NotFound.
    engine.close().expect("close");
    {
        let conn = rusqlite::Connection::open(&path).expect("open raw");
        let mut hex = String::with_capacity(64);
        for b in DB_KEY_BYTES {
            use std::fmt::Write;
            write!(&mut hex, "{b:02x}").expect("hex write");
        }
        conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
            .expect("apply key");
        conn.execute(
            "DELETE FROM entry_protected WHERE entry_uuid = ?1 AND field_name = 'Password'",
            rusqlite::params![id.0.to_string()],
        )
        .expect("delete row");
    }

    let engine = open_engine(&path);
    let err = engine.reveal_password(id.0).expect_err("missing");
    assert_not_found(&err, "password");
}

// ── reveal_custom_field ────────────────────────────────────────────────

#[test]
fn reveal_custom_field_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("api")).expect("add");
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "API Key",
            CustomFieldValue::Protected(SecretString::from("abc123")),
        );
    })
    .expect("set cf");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let revealed = engine
        .reveal_custom_field(id.0, "API Key")
        .expect("reveal cf");
    assert_eq!(revealed.expose_secret(), "abc123");
}

#[test]
fn reveal_custom_field_returns_not_found_for_missing_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("no-cf")).expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine
        .reveal_custom_field(id.0, "Nonexistent")
        .expect_err("missing");
    assert_not_found(&err, "custom_field");
}

#[test]
fn reveal_custom_field_routes_password_through_canonical_row() {
    // Documented behaviour: asking reveal_custom_field for the
    // canonical "Password" name returns the same value as
    // reveal_password.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("acme").password(SecretString::from("hunter2")),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let via_pw = engine.reveal_password(id.0).expect("reveal pw");
    let via_cf = engine
        .reveal_custom_field(id.0, "Password")
        .expect("reveal cf");
    assert_eq!(via_pw.expose_secret(), via_cf.expose_secret());
}

// ── reveal_history_field ───────────────────────────────────────────────

fn entry_with_history(kdbx: &mut Kdbx<Unlocked>) -> keepass_core::model::EntryId {
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("rotated").password(SecretString::from("old-password")),
        )
        .expect("add");
    // Snapshot the current state, then change the password.
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("new-password"));
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("new-token")),
        );
    })
    .expect("rotate");
    id
}

#[test]
fn reveal_history_field_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let id = entry_with_history(&mut kdbx);

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let revealed = engine
        .reveal_history_field(id.0, 0, "Password")
        .expect("reveal history pw");
    assert_eq!(revealed.expose_secret(), "old-password");
}

#[test]
fn reveal_history_field_returns_not_found_for_missing_history_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let id = entry_with_history(&mut kdbx);

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine
        .reveal_history_field(id.0, 42, "Password")
        .expect_err("missing snap");
    assert_not_found(&err, "history_snapshot");
}

#[test]
fn reveal_history_field_returns_not_found_for_missing_field_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let id = entry_with_history(&mut kdbx);

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine
        .reveal_history_field(id.0, 0, "Nonexistent")
        .expect_err("missing field");
    assert_not_found(&err, "history_field");
}

// ── session-key discipline ─────────────────────────────────────────────

#[test]
fn reveal_uses_freshly_acquired_session_key() {
    // Live-reveal paths must hit `acquire_session_key` exactly once per
    // call — no caching, no double-fetch. History reveal of a protected
    // field (password / protected custom field) hits it exactly once
    // too, now that history JSON wraps protected fields symmetrically
    // with live entries.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("acme").password(SecretString::from("hunter2")),
        )
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("tok")),
        );
    })
    .expect("set cf");
    // History snapshot for the history-reveal assertion.
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("acme v2");
    })
    .expect("snapshot");

    // Ingest under the regular (Arc) protector — the ingest pass
    // calling acquire_session_key on its own protector clone doesn't
    // affect the counter we install on the engine below.
    let counting = Arc::new(CountingFieldProtector::new(SESSION_KEY_BYTES));
    {
        let mut engine = open_engine_with(&path, counting.clone());
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        // Ingest fetches once; reset our expectations from that point.
        let baseline = counting.calls();
        assert!(baseline >= 1, "ingest should fetch at least once");

        let _ = engine.reveal_password(id.0).expect("reveal pw");
        assert_eq!(
            counting.calls(),
            baseline + 1,
            "reveal_password must acquire exactly one fresh session key"
        );

        let _ = engine
            .reveal_custom_field(id.0, "Token")
            .expect("reveal cf");
        assert_eq!(
            counting.calls(),
            baseline + 2,
            "reveal_custom_field must acquire exactly one fresh session key"
        );

        // History reveal of the password slot now unwraps under the
        // session key — exactly one fetch, matching the live path.
        let _ = engine
            .reveal_history_field(id.0, 0, "Password")
            .expect("reveal history");
        assert_eq!(
            counting.calls(),
            baseline + 3,
            "reveal_history_field (protected) must acquire exactly one fresh session key"
        );
    }
}

// ── perf ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "perf benchmark — run with --ignored to confirm <5ms reveal"]
fn reveal_password_perf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("perf").password(SecretString::from("hunter2-perf")),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    // Warm.
    let _ = engine.reveal_password(id.0).expect("warm");

    let start = std::time::Instant::now();
    let _ = engine.reveal_password(id.0).expect("reveal");
    let elapsed = start.elapsed();
    eprintln!("reveal_password took {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(5),
        "reveal_password must complete in <5ms, took {elapsed:?}",
    );
}

// Touch RevealError so it appears in the public API surface test even
// when the happy paths don't exercise it.
#[test]
fn reveal_error_variants_are_public() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RevealError>();
}
