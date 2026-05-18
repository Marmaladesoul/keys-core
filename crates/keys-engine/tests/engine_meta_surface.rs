//! Tests for the Phase 6.17-B meta-surface engine APIs.
//!
//! Six methods land here: `recycle_bin_uuid`, `recycle_bin_enabled`,
//! `history_max_items`, `history_max_size`, plus setters for the two
//! history caps. They back the Keys-Mac downstream slice that retires
//! the in-memory `Vault` meta shim.

use std::path::Path;
use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{Group, GroupId};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{ChangeEvent, DataChangeObserver, DbKey, Engine, KeyProvider, KeyProviderError};
use rusqlite::Connection;
use uuid::Uuid;

// ─────────────────────── infrastructure ───────────────────────

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
const COMPOSITE_PW: &[u8] = b"engine-meta-surface-tests";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(COMPOSITE_PW)
}

fn fresh_kdbx(name: &str) -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), name, Some(protector())).expect("create")
}

fn db_key_hex() -> String {
    let mut s = String::with_capacity(64);
    for b in &DB_KEY_BYTES {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").expect("hex");
    }
    s
}

fn raw_open(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\"", db_key_hex()))
        .expect("apply key");
    conn
}

fn open_engine(path: &Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("engine open")
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

// ─────────────────────── recycle_bin_uuid ───────────────────────

#[test]
fn recycle_bin_uuid_is_none_when_no_bin_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("no-bin");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert_eq!(engine.recycle_bin_uuid().expect("read"), None);
}

#[test]
fn recycle_bin_uuid_returns_bin_group_uuid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");

    // Build a kdbx with a bin group and point Meta at it.
    let mut kdbx = fresh_kdbx("with-bin");
    let bin_id = GroupId(Uuid::new_v4());
    let mut bin = Group::empty(bin_id);
    bin.name = "Recycle Bin".into();
    let mut vault = kdbx.vault().clone();
    vault.root.groups.push(bin);
    vault.meta.recycle_bin_uuid = Some(bin_id);
    vault.meta.recycle_bin_enabled = true;
    kdbx.replace_vault(vault);

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let got = engine.recycle_bin_uuid().expect("read");
    assert_eq!(got, Some(bin_id.0.to_string()));
}

// ─────────────────────── recycle_bin_enabled ───────────────────────

#[test]
fn recycle_bin_enabled_reads_setting_row_true() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("enabled-true");
    let mut vault = kdbx.vault().clone();
    vault.meta.recycle_bin_enabled = true;
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert!(engine.recycle_bin_enabled().expect("read"));
}

#[test]
fn recycle_bin_enabled_reads_setting_row_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("enabled-false");
    let mut vault = kdbx.vault().clone();
    vault.meta.recycle_bin_enabled = false;
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert!(!engine.recycle_bin_enabled().expect("read"));
}

#[test]
fn recycle_bin_enabled_falls_back_when_setting_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("legacy-no-setting");
    {
        let mut engine = open_engine(&path);
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine.close().expect("close");
    }
    // Delete the setting row to simulate a pre-fix legacy DB.
    let conn = raw_open(&path);
    conn.execute(
        "DELETE FROM setting WHERE key = 'meta.recycle_bin_enabled'",
        [],
    )
    .expect("delete");
    drop(conn);

    let engine = open_engine(&path);
    // No bin group exists -> fallback says false.
    assert!(!engine.recycle_bin_enabled().expect("read"));
}

// ─────────────────────── history_max_items / size getters ───────────────────────

#[test]
fn history_max_items_reads_persisted_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("hmi");
    let mut vault = kdbx.vault().clone();
    vault.meta.history_max_items = 42;
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert_eq!(engine.history_max_items().expect("read"), 42);
}

#[test]
fn history_max_size_reads_persisted_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("hms");
    let mut vault = kdbx.vault().clone();
    vault.meta.history_max_size = 12_345_678;
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert_eq!(engine.history_max_size().expect("read"), 12_345_678);
}

// ─────────────────────── setters ───────────────────────

// ─────────────────────── set_recycle_bin ───────────────────────

/// Build a kdbx with a single extra group under root, return the
/// engine + that group's uuid.
fn engine_with_extra_group(path: &Path, name: &str) -> (Engine, Uuid) {
    let mut kdbx = fresh_kdbx(name);
    let extra = Uuid::new_v4();
    let mut vault = kdbx.vault().clone();
    let mut g = Group::empty(GroupId(extra));
    g.name = "Extra".into();
    vault.root.groups.push(g);
    kdbx.replace_vault(vault);
    let mut engine = open_engine(path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, extra)
}

#[test]
fn set_recycle_bin_designates_group_and_enables() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let (mut engine, extra) = engine_with_extra_group(&path, "designate");

    engine.set_recycle_bin(true, Some(extra)).expect("set bin");
    assert_eq!(
        engine.recycle_bin_uuid().expect("read uuid"),
        Some(extra.to_string())
    );
    assert!(engine.recycle_bin_enabled().expect("read enabled"));
}

#[test]
fn set_recycle_bin_enabled_no_group_clears_designation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let (mut engine, extra) = engine_with_extra_group(&path, "enabled-no-group");

    // First designate a bin...
    engine.set_recycle_bin(true, Some(extra)).expect("set bin");
    assert_eq!(
        engine.recycle_bin_uuid().expect("read"),
        Some(extra.to_string())
    );

    // ...then pass enabled=true with no group. Mirrors keepass-core:
    // the designation is cleared, enabled is left true. `recycle_entry`
    // will lazily create a bin on the next soft-delete.
    engine.set_recycle_bin(true, None).expect("clear bin");
    assert_eq!(engine.recycle_bin_uuid().expect("read"), None);
    assert!(engine.recycle_bin_enabled().expect("read enabled"));
}

#[test]
fn set_recycle_bin_disabled_clears_designation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let (mut engine, extra) = engine_with_extra_group(&path, "disable");

    engine.set_recycle_bin(true, Some(extra)).expect("set");
    engine.set_recycle_bin(false, None).expect("disable");

    assert!(!engine.recycle_bin_enabled().expect("read enabled"));
    assert_eq!(engine.recycle_bin_uuid().expect("read uuid"), None);
}

#[test]
fn set_recycle_bin_unknown_group_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("unknown");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let bogus = Uuid::new_v4();
    let err = engine
        .set_recycle_bin(true, Some(bogus))
        .expect_err("should fail");
    match err {
        keys_engine::EngineError::NotFound { entity } => assert_eq!(entity, "group"),
        other => panic!("expected NotFound, got {other:?}"),
    }

    // And nothing should have been persisted.
    assert!(!engine.recycle_bin_enabled().expect("read"));
    assert_eq!(engine.recycle_bin_uuid().expect("read"), None);
}

#[test]
fn set_recycle_bin_round_trips_close_and_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let (mut engine, extra) = engine_with_extra_group(&path, "round-trip");

    engine.set_recycle_bin(true, Some(extra)).expect("set");
    engine.close().expect("close");

    let engine = open_engine(&path);
    assert_eq!(
        engine.recycle_bin_uuid().expect("read"),
        Some(extra.to_string())
    );
    assert!(engine.recycle_bin_enabled().expect("read"));
}

#[test]
fn set_recycle_bin_emits_meta_updated_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let (mut engine, extra) = engine_with_extra_group(&path, "emit");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());
    engine.set_recycle_bin(true, Some(extra)).expect("set");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::MetaUpdated { keys } => {
            assert!(keys.contains(&"meta.recycle_bin_enabled".to_string()));
            assert!(keys.contains(&"meta.recycle_bin_uuid".to_string()));
        }
        other => panic!("expected MetaUpdated, got {other:?}"),
    }
}

#[test]
fn set_recycle_bin_swaps_designation_atomically() {
    // Exclusivity invariant: at most one group has is_recycle_bin = 1.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("swap");
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut vault = kdbx.vault().clone();
    let mut g1 = Group::empty(GroupId(first));
    g1.name = "Bin A".into();
    let mut g2 = Group::empty(GroupId(second));
    g2.name = "Bin B".into();
    vault.root.groups.push(g1);
    vault.root.groups.push(g2);
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    engine.set_recycle_bin(true, Some(first)).expect("first");
    assert_eq!(
        engine.recycle_bin_uuid().expect("read"),
        Some(first.to_string())
    );
    engine.set_recycle_bin(true, Some(second)).expect("swap");
    assert_eq!(
        engine.recycle_bin_uuid().expect("read"),
        Some(second.to_string()),
        "designation should have moved to second"
    );
}

#[test]
fn set_history_max_items_persists_and_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("set-hmi");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    engine.set_history_max_items(7).expect("set");
    assert_eq!(engine.history_max_items().expect("read"), 7);

    // Survives a close-and-reopen.
    engine.close().expect("close");
    let engine = open_engine(&path);
    assert_eq!(engine.history_max_items().expect("reread"), 7);
}

#[test]
fn set_history_max_size_persists_and_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("set-hms");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    engine.set_history_max_size(999_999).expect("set");
    assert_eq!(engine.history_max_size().expect("read"), 999_999);

    engine.close().expect("close");
    let engine = open_engine(&path);
    assert_eq!(engine.history_max_size().expect("reread"), 999_999);
}

#[test]
fn set_history_max_items_emits_meta_updated_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("emit-hmi");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());
    engine.set_history_max_items(15).expect("set");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::MetaUpdated { keys } => {
            assert_eq!(keys, &vec!["meta.history_max_items".to_string()]);
        }
        other => panic!("expected MetaUpdated, got {other:?}"),
    }
}

// ─────────────────────── database_metadata ───────────────────────

#[test]
fn database_metadata_reports_generator_from_meta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("gen");
    let mut vault = kdbx.vault().clone();
    vault.meta.generator = "Keys".into();
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let md = engine.database_metadata().expect("read");
    assert_eq!(md.generator, "Keys");
}

#[test]
fn database_metadata_generator_empty_when_meta_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("no-gen");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let md = engine.database_metadata().expect("read");
    // `Meta::default().generator` is empty.
    assert_eq!(md.generator, "");
}

#[test]
fn database_metadata_reports_aes_cipher_for_fresh_v4_vault() {
    // `create_empty_v4` always uses AES-256-CBC as the outer cipher.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("cipher");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let md = engine.database_metadata().expect("read");
    assert_eq!(md.cipher_display, "AES-256-CBC");
}

#[test]
fn database_metadata_reports_argon2d_kdf_for_fresh_v4_vault() {
    // `create_empty_v4` defaults: Argon2d, 64 MiB, 2 iter, 8 parallelism.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("kdf");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let md = engine.database_metadata().expect("read");
    assert_eq!(
        md.kdf_display,
        "Argon2d (64 MB \u{00B7} 2 iter \u{00B7} 8 threads)"
    );
}

#[test]
fn database_metadata_attachment_pool_starts_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("att-empty");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let md = engine.database_metadata().expect("read");
    assert_eq!(md.attachment_total_count, 0);
    assert_eq!(md.attachment_total_bytes, 0);
}

#[test]
fn database_metadata_counts_attachment_pool_dedup() {
    use keepass_core::model::{Attachment, Binary, Entry, EntryId};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("att-dedup");

    // Two entries, three attachment references — two of them share
    // bytes so the pool dedupes to two distinct blobs.
    let mut vault = kdbx.vault().clone();
    let shared_bytes = vec![0x11u8; 100];
    let unique_bytes = vec![0x22u8; 250];

    // ref_id 0: shared; ref_id 1: unique.
    vault
        .binaries
        .push(Binary::new(shared_bytes.clone(), false));
    vault
        .binaries
        .push(Binary::new(unique_bytes.clone(), false));

    let e1_id = EntryId(Uuid::new_v4());
    let mut e1 = Entry::empty(e1_id);
    e1.title = "one".into();
    e1.attachments.push(Attachment::new("shared.txt", 0));
    e1.attachments.push(Attachment::new("unique.txt", 1));
    let e2_id = EntryId(Uuid::new_v4());
    let mut e2 = Entry::empty(e2_id);
    e2.title = "two".into();
    // Same payload as e1's first attachment — content-addressed dedup
    // should keep the pool at two rows total.
    e2.attachments.push(Attachment::new("shared.txt", 0));
    vault.root.entries.push(e1);
    vault.root.entries.push(e2);
    kdbx.replace_vault(vault);

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let md = engine.database_metadata().expect("read");
    assert_eq!(md.attachment_total_count, 2);
    assert_eq!(
        md.attachment_total_bytes,
        (shared_bytes.len() + unique_bytes.len()) as u64
    );
}

#[test]
fn database_metadata_round_trips_close_and_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("round-trip");
    let mut vault = kdbx.vault().clone();
    vault.meta.generator = "Keys".into();
    kdbx.replace_vault(vault);

    {
        let mut engine = open_engine(&path);
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine.close().expect("close");
    }
    let engine = open_engine(&path);
    let md = engine.database_metadata().expect("read");
    assert_eq!(md.generator, "Keys");
    assert_eq!(md.cipher_display, "AES-256-CBC");
    assert_eq!(
        md.kdf_display,
        "Argon2d (64 MB \u{00B7} 2 iter \u{00B7} 8 threads)"
    );
}

#[test]
fn database_metadata_unknown_displays_when_outer_header_rows_absent() {
    // A pre-Phase-6.17-I-3c engine wouldn't have the cipher / KDF rows
    // written. Simulate by deleting them after ingest.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("legacy");
    {
        let mut engine = open_engine(&path);
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine.close().expect("close");
    }
    let conn = raw_open(&path);
    conn.execute(
        "DELETE FROM setting WHERE key IN \
         ('meta.kdbx_cipher_oid', 'meta.kdbx_kdf_parameters', 'meta.kdbx_transform_rounds')",
        [],
    )
    .expect("delete");
    drop(conn);

    let engine = open_engine(&path);
    let md = engine.database_metadata().expect("read");
    assert_eq!(md.cipher_display, "Unknown");
    assert_eq!(md.kdf_display, "Unknown KDF");
}

#[test]
fn set_history_max_size_emits_meta_updated_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("emit-hms");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());
    engine.set_history_max_size(2 * 1024 * 1024).expect("set");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::MetaUpdated { keys } => {
            assert_eq!(keys, &vec!["meta.history_max_size".to_string()]);
        }
        other => panic!("expected MetaUpdated, got {other:?}"),
    }
}
