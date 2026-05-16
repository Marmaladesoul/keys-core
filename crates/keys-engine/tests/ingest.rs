//! Integration tests for [`Engine::ingest_from_kdbx`] (task 2.3).
//!
//! These exercise the `KDBX` → `SQLite` walk against vaults built in
//! memory via `keepass_core::Kdbx::create_empty_v4_with_protector` +
//! editor methods, so the tests run without any KDF cost or fixture
//! files on disk. Each test focuses on one observable side-effect of
//! ingest (groups land, entries land with the right derived columns,
//! protected fields are wrapped, tags / attachments / history get
//! their rows).

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{
    Attachment, Binary, CustomFieldValue, HistoryPolicy, NewEntry, NewGroup,
};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use rusqlite::{Connection, params};
use secrecy::SecretString;

/// Test `SQLCipher` key provider — fixed 32 bytes per test.
#[derive(Debug)]
struct FixedKey([u8; 32]);

impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

/// Test session-key provider. Returns a fixed 32-byte key so wrap /
/// unwrap is deterministic across the test surface.
#[derive(Debug, Clone)]
struct FixedProtector([u8; 32]);

impl FieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes(self.0))
    }
}

const SESSION_KEY_BYTES: [u8; 32] = [0x9c; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn protector_concrete() -> FixedProtector {
    FixedProtector(SESSION_KEY_BYTES)
}

/// Hex literal for the `PRAGMA key = "x'…'"` raw open that several
/// tests below use to peek into the `SQLCipher` database directly.
fn db_key_hex() -> String {
    let mut s = String::with_capacity(64);
    for b in &DB_KEY_BYTES {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").expect("hex");
    }
    s
}

fn raw_open(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\"", db_key_hex()))
        .expect("apply key");
    conn
}

/// Build a fresh KDBX with the supplied protector. No KDF cost
/// because `create_empty_v4_with_protector` initialises the in-memory
/// state directly.
fn fresh_kdbx(protector: Arc<dyn FieldProtector>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector)).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

fn row_count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .expect("count")
}

#[test]
fn ingest_empty_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx(protector());

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    // create_empty_v4_with_protector ships with a single root group.
    assert_eq!(row_count(&raw, "\"group\""), 1);
    assert_eq!(row_count(&raw, "entry"), 0);
    assert_eq!(row_count(&raw, "entry_protected"), 0);
    assert_eq!(row_count(&raw, "entry_history"), 0);
    assert_eq!(row_count(&raw, "entry_attachment"), 0);
    assert_eq!(row_count(&raw, "entry_tag"), 0);
    assert_eq!(row_count(&raw, "tag"), 0);
    assert_eq!(row_count(&raw, "attachment_blob"), 0);
}

#[test]
fn ingest_simple_vault_fills_derived_columns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;

    let plaintext_pw = "Tr0ub4dor&3";
    let entry_id = kdbx
        .add_entry(
            root,
            NewEntry::new("acme")
                .username("alice")
                .url("https://login.example.com/path")
                .notes("hello")
                .password(SecretString::from(plaintext_pw)),
        )
        .expect("add entry");

    let engine = open_engine(&path);
    let expected_fingerprint = engine.fingerprint(plaintext_pw.as_bytes());
    let expected_strength = engine.strength(plaintext_pw);
    let mut engine = engine;
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    assert_eq!(row_count(&raw, "entry"), 1);
    let (title, username, url, host, bucket, entropy, fp): (
        String,
        String,
        String,
        String,
        i64,
        f64,
        Vec<u8>,
    ) = raw
        .query_row(
            "SELECT title, username, url, url_host, password_strength_bucket, password_entropy, \
             password_fingerprint FROM entry WHERE uuid = ?1",
            params![entry_id.0.to_string()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, f64>(5)?,
                    r.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .expect("read row");

    assert_eq!(title, "acme");
    assert_eq!(username, "alice");
    assert_eq!(url, "https://login.example.com/path");
    assert_eq!(host, "login.example.com");
    assert_eq!(bucket, expected_strength.bucket as i64);
    assert!((entropy - expected_strength.entropy_bits).abs() < 1e-6);
    assert_eq!(fp, expected_fingerprint);

    // Protected blob round-trips through unwrap with the same session key.
    let wrapped: Vec<u8> = raw
        .query_row(
            "SELECT wrapped_blob FROM entry_protected WHERE entry_uuid = ?1 AND field_name = 'Password'",
            params![entry_id.0.to_string()],
            |r| r.get(0),
        )
        .expect("wrapped blob");
    let opened = unwrap_blob(&protector_concrete(), &wrapped);
    assert_eq!(opened, plaintext_pw.as_bytes());
}

#[test]
fn ingest_with_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(root, NewEntry::new("v0").password(SecretString::from("p0")))
        .expect("add");

    // Each edit pushes a history snapshot of the prior state.
    for title in ["v1", "v2", "v3"] {
        kdbx.edit_entry(entry_id, HistoryPolicy::Snapshot, |e| {
            e.set_title(title);
        })
        .expect("edit");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    let count: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM entry_history WHERE entry_uuid = ?1",
            params![entry_id.0.to_string()],
            |r| r.get(0),
        )
        .expect("count history");
    assert_eq!(count, 3, "three prior versions retained");
}

#[test]
fn ingest_with_attachments_dedups_by_sha256() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());

    // Build the binary pool: one shared blob + one unique blob.
    let shared = Binary::new(b"shared bytes".to_vec(), false);
    let other = Binary::new(b"different bytes".to_vec(), false);
    {
        let mut vault = kdbx.vault().clone();
        vault.binaries.push(shared.clone());
        vault.binaries.push(other.clone());
        kdbx.replace_vault(vault);
    }

    let root = kdbx.vault().root.id;
    let entry_a = kdbx.add_entry(root, NewEntry::new("a")).expect("add a");
    let entry_b = kdbx.add_entry(root, NewEntry::new("b")).expect("add b");
    {
        // Attach both binaries to entry_a; just the shared one to entry_b.
        let mut vault = kdbx.vault().clone();
        for entry in &mut vault.root.entries {
            if entry.id == entry_a {
                entry.attachments.push(Attachment::new("shared.txt", 0));
                entry.attachments.push(Attachment::new("solo.txt", 1));
            } else if entry.id == entry_b {
                entry.attachments.push(Attachment::new("shared.txt", 0));
            }
        }
        kdbx.replace_vault(vault);
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    // 3 attachment links total (a:shared, a:solo, b:shared).
    assert_eq!(row_count(&raw, "entry_attachment"), 3);
    // 2 distinct blobs (shared dedups).
    assert_eq!(row_count(&raw, "attachment_blob"), 2);
}

#[test]
fn ingest_with_tags_splits_and_links() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let _entry_id = kdbx
        .add_entry(
            root,
            NewEntry::new("tagged")
                .password(SecretString::from("pw"))
                .tags(vec!["banking".into(), "personal".into(), "email".into()]),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    assert_eq!(row_count(&raw, "tag"), 3);
    assert_eq!(row_count(&raw, "entry_tag"), 3);

    let names: Vec<String> = raw
        .prepare("SELECT name FROM tag ORDER BY name")
        .expect("prepare")
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("collect");
    assert_eq!(names, vec!["banking", "email", "personal"]);
}

#[test]
fn ingest_with_custom_fields_routes_protected_to_entry_protected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(
            root,
            NewEntry::new("api keys").password(SecretString::from("pw")),
        )
        .expect("add");
    kdbx.edit_entry(entry_id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("secret-token")),
        );
        e.set_custom_field("Note", CustomFieldValue::Plain("public-note".into()));
    })
    .expect("edit");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    // Password + Token (protected). Non-protected "Note" is deferred (v1).
    let proto_count: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM entry_protected WHERE entry_uuid = ?1",
            params![entry_id.0.to_string()],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(proto_count, 2);

    let names: Vec<String> = raw
        .prepare("SELECT field_name FROM entry_protected WHERE entry_uuid = ?1 ORDER BY field_name")
        .expect("prepare")
        .query_map(params![entry_id.0.to_string()], |r| r.get::<_, String>(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("collect");
    assert_eq!(names, vec!["Password", "Token"]);
}

#[test]
fn ingest_with_url_host_extraction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(
            root,
            NewEntry::new("with url").url("https://Login.Example.com/some/path?q=1"),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    let host: String = raw
        .query_row(
            "SELECT url_host FROM entry WHERE uuid = ?1",
            params![entry_id.0.to_string()],
            |r| r.get(0),
        )
        .expect("read host");
    assert_eq!(host, "login.example.com");
}

#[test]
fn ingest_marks_recycle_bin_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let bin_id = kdbx
        .add_group(root, NewGroup::new("Recycle Bin"))
        .expect("add bin");
    kdbx.set_recycle_bin(true, Some(bin_id));

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    let flag: i64 = raw
        .query_row(
            "SELECT is_recycle_bin FROM \"group\" WHERE uuid = ?1",
            params![bin_id.0.to_string()],
            |r| r.get(0),
        )
        .expect("read flag");
    assert_eq!(flag, 1, "recycle-bin group must be flagged");
}

#[test]
fn ingest_marks_recycled_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let bin_id = kdbx
        .add_group(root, NewGroup::new("Recycle Bin"))
        .expect("add bin");
    kdbx.set_recycle_bin(true, Some(bin_id));
    let entry_id = kdbx
        .add_entry(bin_id, NewEntry::new("trash"))
        .expect("add entry in bin");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    let recycled: i64 = raw
        .query_row(
            "SELECT is_recycled FROM entry WHERE uuid = ?1",
            params![entry_id.0.to_string()],
            |r| r.get(0),
        )
        .expect("read recycled flag");
    assert_eq!(recycled, 1);
}

#[test]
fn ingest_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("a").password(SecretString::from("pw")))
        .expect("add a");
    kdbx.add_entry(root, NewEntry::new("b").password(SecretString::from("pw")))
        .expect("add b");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("first ingest");
    engine.ingest_from_kdbx(&kdbx).expect("second ingest");
    engine.ingest_from_kdbx(&kdbx).expect("third ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    assert_eq!(row_count(&raw, "entry"), 2, "no duplicate entries");
    // 2 entries × 1 Password slot each = 2 protected rows.
    assert_eq!(row_count(&raw, "entry_protected"), 2);
}

#[test]
fn ingest_round_trip_password_unwraps_under_same_session_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let pw = "correct horse battery staple";
    let entry_id = kdbx
        .add_entry(root, NewEntry::new("t").password(SecretString::from(pw)))
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let raw = raw_open(&path);
    let wrapped: Vec<u8> = raw
        .query_row(
            "SELECT wrapped_blob FROM entry_protected WHERE entry_uuid = ?1 AND field_name = 'Password'",
            params![entry_id.0.to_string()],
            |r| r.get(0),
        )
        .expect("blob");
    let opened = unwrap_blob(&protector_concrete(), &wrapped);
    assert_eq!(opened, pw.as_bytes());
}

#[test]
#[ignore = "perf benchmark — run with --ignored on Apple Silicon to confirm <2s ingest"]
fn ingest_perf_877_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    for i in 0..877 {
        kdbx.add_entry(
            root,
            NewEntry::new(format!("entry {i}"))
                .username(format!("user{i}"))
                .url(format!("https://host{i}.example.com"))
                .password(SecretString::from(format!("pw-{i}-{}", "x".repeat(16)))),
        )
        .expect("add");
    }

    let start = std::time::Instant::now();
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");
    let elapsed = start.elapsed();
    eprintln!("877-entry ingest took {elapsed:?}");
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "877-entry ingest must complete in <2s, took {elapsed:?}",
    );
}

// --------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------

/// In-process AES-GCM unwrap mirroring the ingest path's seal format
/// (nonce(12) || ciphertext || tag(16)). Lets tests assert the stored
/// blob is recoverable under the same session key without depending
/// on a public unwrap helper from the engine.
fn unwrap_blob(protector: &FixedProtector, wrapped: &[u8]) -> Vec<u8> {
    use aes_gcm::Aes256Gcm;
    use aes_gcm::aead::{Aead, KeyInit};
    let key = protector.acquire_session_key().expect("session key");
    assert!(wrapped.len() >= 12 + 16, "wrapped blob too short");
    let (nonce_bytes, ct) = wrapped.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).expect("cipher");
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).expect("decrypt")
}
