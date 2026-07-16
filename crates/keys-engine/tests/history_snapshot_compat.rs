//! Cross-reader compatibility pin for the `entry_history.snapshot_json`
//! wire format.
//!
//! `snapshot_json` is persisted and long-lived: rows written by every
//! build the engine has shipped are still sitting in users' mirrors.
//! Four separate code paths read them — the history list, the
//! per-field reveal, restore, and the KDBX projection (i.e. save) — and
//! each one must tolerate a row written before a given field existed.
//!
//! These tests take a **genuine** snapshot the current writer produced
//! and strip the fields that were added after the format first shipped,
//! standing in for a row an older build wrote. Stripping a real row
//! rather than hand-writing JSON keeps the sealed password authentic,
//! so the readers do real work. Every reader is then driven across it.
//!
//! A reader that forgets a `#[serde(default)]` fails here rather than
//! in the field, where the symptom is "this one operation errors on
//! this one vault" long after the field was added — and only on the
//! path that forgot.
//!
//! Scope: this pins the *shape* layer. What a consumer then does with a
//! value it considers unusable (e.g. the projection rejecting a
//! snapshot that carries no sealed password at all) is that consumer's
//! policy, and deliberately fails closed.

use std::fmt::Write as _;
use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomFieldValue, HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use secrecy::{ExposeSecret, SecretString};

// ── test wiring (same shape as tests/history_wrap.rs) ──────────────────

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

/// Keys that did **not** exist in the initially-shipped snapshot shape.
/// Removing all of them from a modern row yields the oldest row the
/// format admits that still carries a usable password.
const FIELDS_ADDED_AFTER_THE_INITIAL_SHAPE: &[&str] = &[
    "url_host",
    "notes",
    "tags",
    "created_at",
    "modified_at",
    "accessed_at",
    "last_used_at",
    "expires_at",
    "icon_index",
    "icon_custom_uuid",
    "password_strength_bucket",
    "password_entropy",
    "attachments",
    "custom_fields",
    "custom_data",
];

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

/// A vault whose entry carries one history snapshot, rotated from
/// `ancient-pw` to `modern-pw` and holding a protected custom field.
fn vault_with_one_snapshot(
    dir: &std::path::Path,
) -> (std::path::PathBuf, Kdbx<Unlocked>, uuid::Uuid) {
    let path = dir.join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("rotated")
                .password(SecretString::from("ancient-pw"))
                .username("old-user")
                .url("https://old.example.com/"),
        )
        .expect("add");
    // Seed the protected custom field without snapshotting, so the one
    // snapshot this vault carries is the rotation below.
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("t0ken")),
        );
    })
    .expect("seed token");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("modern-pw"));
    })
    .expect("rotate");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    (path, kdbx, id.0)
}

/// Rewrite the entry's snapshot 0 as an older build would have written
/// it: the real row minus every field added since the format shipped.
/// Returns the stripped JSON for assertions.
fn age_the_snapshot(path: &std::path::Path, id: uuid::Uuid) -> serde_json::Value {
    let conn = open_raw(path);
    let json: String = conn
        .query_row(
            "SELECT snapshot_json FROM entry_history \
             WHERE entry_uuid = ?1 AND history_index = 0",
            rusqlite::params![id.to_string()],
            |r| r.get(0),
        )
        .expect("fetch snapshot_json");

    let mut v: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let obj = v.as_object_mut().expect("snapshot is a JSON object");
    for field in FIELDS_ADDED_AFTER_THE_INITIAL_SHAPE {
        obj.remove(*field);
    }
    // Sanity: the aged row must still carry a real sealed password, or
    // this fixture isn't testing what it claims to.
    assert!(
        obj.get("password")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|p| !p.is_empty()),
        "aged fixture lost its sealed password"
    );

    let aged = serde_json::to_string(&v).expect("serialise");
    let rows = conn
        .execute(
            "UPDATE entry_history SET snapshot_json = ?1 \
             WHERE entry_uuid = ?2 AND history_index = 0",
            rusqlite::params![aged, id.to_string()],
        )
        .expect("overwrite snapshot_json");
    assert_eq!(rows, 1, "expected exactly one history row to rewrite");
    v
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn the_aged_fixture_really_is_missing_the_later_fields() {
    // Guards the other tests: if the writer ever stops emitting one of
    // these, the fixture silently stops aging the row and the tests
    // below turn into no-ops.
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, _kdbx, id) = vault_with_one_snapshot(dir.path());

    let conn = open_raw(&path);
    let json: String = conn
        .query_row(
            "SELECT snapshot_json FROM entry_history \
             WHERE entry_uuid = ?1 AND history_index = 0",
            rusqlite::params![id.to_string()],
            |r| r.get(0),
        )
        .expect("fetch");
    let modern: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let modern = modern.as_object().expect("object");

    for field in FIELDS_ADDED_AFTER_THE_INITIAL_SHAPE {
        assert!(
            modern.contains_key(*field),
            "the writer no longer emits `{field}` — update this fixture's field list"
        );
    }
    drop(conn);

    let aged = age_the_snapshot(&path, id);
    let aged = aged.as_object().expect("object");
    for field in FIELDS_ADDED_AFTER_THE_INITIAL_SHAPE {
        assert!(!aged.contains_key(*field), "`{field}` survived aging");
    }
    assert!(
        aged.contains_key("title"),
        "aging must keep the initial shape"
    );
}

#[test]
fn history_list_reads_an_aged_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, _kdbx, id) = vault_with_one_snapshot(dir.path());
    age_the_snapshot(&path, id);

    let engine = open_engine(&path);
    let history = engine.history(id).expect("history must read an aged row");

    assert_eq!(history.len(), 1);
    assert_eq!(history[0].title, "rotated");
    // Fields the row predates surface as defaults, not an error.
    assert!(history[0].tags.is_empty());
    assert!(history[0].custom_fields.is_empty());
}

#[test]
fn projection_reads_an_aged_snapshot() {
    // The projection path is the KDBX *save* path and was the strictest
    // of the four readers: it required `notes`, `tags`, `created_at`,
    // `accessed_at`, `expires_at` and `custom_fields` outright, so an
    // aged row hard-errored here while every other path read it happily.
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, mut kdbx, id) = vault_with_one_snapshot(dir.path());
    age_the_snapshot(&path, id);
    let kdbx_path = dir.path().join("out.kdbx");

    let mut engine = open_engine(&path);
    let result = engine.save_to_kdbx(&kdbx_path, &mut kdbx, None);

    assert!(
        result.is_ok(),
        "saving a vault holding an aged history row must not fail: {:?}",
        result.err()
    );
}

#[test]
fn reveal_reads_the_password_out_of_an_aged_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, _kdbx, id) = vault_with_one_snapshot(dir.path());
    age_the_snapshot(&path, id);

    let engine = open_engine(&path);
    let revealed = engine
        .reveal_history_field(id, 0, "Password")
        .expect("reveal must read an aged row");

    assert_eq!(
        revealed.expose_secret(),
        "ancient-pw",
        "the aged snapshot must still yield its pre-edit password"
    );
}

#[test]
fn restore_from_an_aged_snapshot_applies_its_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, _kdbx, id) = vault_with_one_snapshot(dir.path());
    age_the_snapshot(&path, id);

    let mut engine = open_engine(&path);
    engine
        .restore_entry_from_history(id, 0)
        .expect("restore must read an aged row");

    let entry = engine.entry(id).expect("entry").expect("entry exists");
    assert_eq!(entry.title, "rotated");
    let password = engine
        .reveal_password(id)
        .expect("reveal restored password");
    assert_eq!(
        password.expose_secret(),
        "ancient-pw",
        "restore must bring back the snapshot's password"
    );
}

#[test]
fn a_modern_snapshot_still_round_trips_through_every_reader() {
    // The other direction: a row the current writer produced reads back
    // with its values intact, and projects without error.
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, mut kdbx, id) = vault_with_one_snapshot(dir.path());

    let mut engine = open_engine(&path);

    let history = engine.history(id).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].title, "rotated");
    assert_eq!(history[0].username, "old-user");

    let revealed = engine
        .reveal_history_field(id, 0, "Password")
        .expect("reveal the snapshotted password");
    assert_eq!(revealed.expose_secret(), "ancient-pw");

    let token = engine
        .reveal_history_field(id, 0, "Token")
        .expect("reveal the snapshotted protected custom field");
    assert_eq!(token.expose_secret(), "t0ken");

    let kdbx_path = dir.path().join("out.kdbx");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("projection of a modern snapshot");
}
