//! Phase 2 deferred follow-up — history JSON wrap.
//!
//! Verifies that protected fields inside `entry_history.snapshot_json`
//! are AES-GCM-sealed under the session key (base64-encoded), not
//! stored as inline plaintext. Restores symmetry with the live
//! `entry_protected.wrapped_blob` rows: plaintext never appears in
//! DB-stored JSON for history snapshots either.

use std::fmt::Write as _;
use std::sync::Arc;

use base64::Engine as _;
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomFieldValue, HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use secrecy::{ExposeSecret, SecretString};

// ── test wiring (same shape as tests/reveal.rs) ────────────────────────

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

const SESSION_KEY_BYTES: [u8; 32] = [0x7a; 32];
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

/// Open the `SQLCipher` DB with raw rusqlite for direct inspection of
/// `entry_history.snapshot_json`. Mirrors the pattern already used in
/// `tests/reveal.rs::reveal_password_returns_not_found_when_entry_has_no_password_row`.
fn open_raw(path: &std::path::Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("open raw");
    let mut hex = String::with_capacity(64);
    for b in DB_KEY_BYTES {
        write!(&mut hex, "{b:02x}").expect("hex write");
    }
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
        .expect("apply key");
    conn
}

fn fetch_history_json(path: &std::path::Path, entry_uuid: &str, history_index: i64) -> String {
    let conn = open_raw(path);
    conn.query_row(
        "SELECT snapshot_json FROM entry_history \
         WHERE entry_uuid = ?1 AND history_index = ?2",
        rusqlite::params![entry_uuid, history_index],
        |r| r.get::<_, String>(0),
    )
    .expect("fetch snapshot_json")
}

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64 decode")
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn history_snapshot_password_is_wrapped_in_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("rotated").password(SecretString::from("ancient")),
        )
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("modern"));
    })
    .expect("rotate");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let json = fetch_history_json(&path, &id.0.to_string(), 0);
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let pw_b64 = parsed
        .get("password")
        .and_then(|v| v.as_str())
        .expect("password field is a string");

    // Must NOT be the plaintext.
    assert_ne!(pw_b64, "ancient", "history password leaked as plaintext");

    // Must decode to AES-GCM wire shape: nonce(12) + ct + tag(16).
    // "ancient" is 7 bytes, so the wrapped blob is at least 12+7+16 = 35.
    let wrapped = b64_decode(pw_b64);
    assert!(
        wrapped.len() >= 12 + 16 + "ancient".len(),
        "wrapped blob too short: {} bytes",
        wrapped.len()
    );
}

#[test]
fn reveal_history_field_unwraps_password() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("rotated").password(SecretString::from("old-pw")),
        )
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("new-pw"));
    })
    .expect("rotate");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let revealed = engine
        .reveal_history_field(id.0, 0, "Password")
        .expect("reveal");
    assert_eq!(revealed.expose_secret(), "old-pw");
}

#[test]
fn reveal_history_field_unwraps_protected_custom_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("api")).expect("add");
    // Set the protected custom field as the *current* state, then
    // snapshot, then mutate the field so the snapshot we read back
    // carries the "old-token" version.
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("old-token")),
        );
    })
    .expect("set old token");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("new-token")),
        );
    })
    .expect("rotate");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let revealed = engine
        .reveal_history_field(id.0, 0, "Token")
        .expect("reveal token");
    assert_eq!(revealed.expose_secret(), "old-token");
}

#[test]
fn reveal_history_field_returns_plaintext_for_non_protected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("site")).expect("add");
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field("Website", CustomFieldValue::Plain("example.com".into()));
    })
    .expect("set old website");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_custom_field("Website", CustomFieldValue::Plain("example.org".into()));
    })
    .expect("rotate");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let revealed = engine
        .reveal_history_field(id.0, 0, "Website")
        .expect("reveal website");
    assert_eq!(revealed.expose_secret(), "example.com");
}

#[test]
fn history_round_trip_through_kdbx_preserves_protected_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("rotated").password(SecretString::from("ancient")),
        )
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("modern"));
    })
    .expect("rotate");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    // Save engine → KDBX on disk; reopen the KDBX; re-ingest; reveal.
    let kdbx_path = dir.path().join("out.kdbx");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save_to_kdbx");

    let reopened = Kdbx::open(&kdbx_path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&CompositeKey::from_password(b"pw"), Some(protector()))
        .expect("unlock");

    let dir2 = tempfile::tempdir().expect("tempdir2");
    let path2 = dir2.path().join("keys2.db");
    let mut engine2 = open_engine(&path2);
    engine2.ingest_from_kdbx(&reopened).expect("re-ingest");

    let revealed = engine2
        .reveal_history_field(id.0, 0, "Password")
        .expect("reveal history through round-trip");
    assert_eq!(revealed.expose_secret(), "ancient");
}

#[test]
fn history_no_plaintext_in_json_at_rest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("rotated").password(SecretString::from("ancient")),
        )
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("ancient-token")),
        );
    })
    .expect("set protected cf");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("modern"));
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("modern-token")),
        );
    })
    .expect("rotate");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let json = fetch_history_json(&path, &id.0.to_string(), 0);
    assert!(
        !json.contains("ancient"),
        "plaintext leaked into snapshot_json: {json}"
    );
    assert!(
        !json.contains("ancient-token"),
        "protected custom field plaintext leaked into snapshot_json: {json}"
    );
}
