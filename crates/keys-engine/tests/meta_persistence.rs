//! Tests for migration 0003 — full `Meta` persistence + vault state
//! machine.
//!
//! Before this migration, the engine persisted only the recycle-bin
//! pair on `Meta`; every other field was carried forward at save time
//! by copying from the live `Kdbx<Unlocked>` handle. This test file
//! locks down the new "`SQLite` is the source of truth" contract.

use std::path::Path;
use std::sync::Arc;

use chrono::TimeZone;
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomDataItem, CustomIcon, DeletedObject, MemoryProtection, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, DisconnectReason, Engine, KeyProvider, KeyProviderError, VaultState};
use rusqlite::Connection;
use secrecy::SecretString;
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
const COMPOSITE_PW: &[u8] = b"meta-persistence-tests";

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

/// Open the engine's `SQLCipher` file directly to peek at tables
/// without going through the `Engine` API.
fn raw_open(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\"", db_key_hex()))
        .expect("apply key");
    conn
}

/// Build a kdbx with every Meta field populated to a non-default,
/// distinct value. Used by the broad round-trip / projection tests.
fn kdbx_with_full_meta() -> Kdbx<Unlocked> {
    let mut kdbx = fresh_kdbx("full-meta-source");
    let mut vault = kdbx.vault().clone();

    vault.meta.generator = "MetaTestGenerator".into();
    vault.meta.database_name = "Personal Vault".into();
    vault.meta.database_description = "A description with utf-8: ✓ 🦀".into();
    vault.meta.default_username = "alice@example.com".into();
    vault.meta.database_name_changed = Some(dt(1_700_000_000));
    vault.meta.database_description_changed = Some(dt(1_700_000_001));
    vault.meta.default_username_changed = Some(dt(1_700_000_002));
    vault.meta.recycle_bin_changed = Some(dt(1_700_000_003));
    vault.meta.settings_changed = Some(dt(1_700_000_004));
    vault.meta.master_key_changed = Some(dt(1_700_000_005));
    vault.meta.master_key_change_rec = 90;
    vault.meta.master_key_change_force = 365;
    vault.meta.history_max_items = 25;
    vault.meta.history_max_size = 12 * 1024 * 1024;
    vault.meta.maintenance_history_days = 90;
    vault.meta.color = "#ff8800".into();
    vault.meta.header_hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    vault.meta.memory_protection = {
        let mut mp = MemoryProtection::default();
        mp.protect_title = true;
        mp.protect_username = true;
        mp.protect_password = true;
        mp.protect_url = false;
        mp.protect_notes = true;
        mp
    };
    vault.meta.custom_icons = vec![
        CustomIcon::new(
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            b"\x89PNG\r\n\x1a\nfake-icon-bytes-1".to_vec(),
            "Coffee".into(),
            Some(dt(1_700_001_000)),
        ),
        CustomIcon::new(
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            b"\x89PNG\r\n\x1a\nfake-icon-bytes-2".to_vec(),
            "Server".into(),
            None,
        ),
    ];
    vault.meta.custom_data = vec![
        CustomDataItem::new(
            "KPXC_DECRYPTION_TIME_PREFERENCE".into(),
            "1000".into(),
            Some(dt(1_700_002_000)),
        ),
        CustomDataItem::new("PluginVendor".into(), "vendor-value".into(), None),
    ];
    vault.deleted_objects = vec![
        DeletedObject::new(
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            Some(dt(1_700_003_000)),
        ),
        DeletedObject::new(
            Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap(),
            Some(dt(1_700_003_001)),
        ),
    ];

    kdbx.replace_vault(vault);

    // Add entries that reference the custom icons so keepass-core's
    // save-time `gc_custom_icons_pool` doesn't strip them.
    let root = kdbx.vault().root.id;
    let icon_a = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let icon_b = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
    let e1 = kdbx
        .add_entry(
            root,
            NewEntry::new("uses-icon-a").password(SecretString::from("p1")),
        )
        .expect("entry 1");
    let e2 = kdbx
        .add_entry(
            root,
            NewEntry::new("uses-icon-b").password(SecretString::from("p2")),
        )
        .expect("entry 2");

    let mut vault = kdbx.vault().clone();
    for entry in &mut vault.root.entries {
        if entry.id == e1 {
            entry.custom_icon_uuid = Some(icon_a);
        } else if entry.id == e2 {
            entry.custom_icon_uuid = Some(icon_b);
        }
    }
    kdbx.replace_vault(vault);

    kdbx
}

fn dt(secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc.timestamp_opt(secs, 0).single().expect("dt")
}

// ─────────────────────── schema tests ───────────────────────

#[test]
fn migration_0003_creates_tables() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector())
        .expect("engine open")
        .close()
        .expect("close");

    let conn = raw_open(&engine_path);
    for table in [
        "meta_custom_icon",
        "meta_custom_data",
        "meta_deleted_object",
    ] {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |r| r.get(0),
            )
            .expect("query");
        assert_eq!(n, 1, "table {table} must exist");
    }
}

// ─────────────────────── ingest tests ───────────────────────

fn ingested_engine(kdbx: &Kdbx<Unlocked>, engine_path: &Path) -> Engine {
    let mut engine =
        Engine::open(engine_path, &FixedKey(DB_KEY_BYTES), protector()).expect("engine open");
    engine.ingest_from_kdbx(kdbx).expect("ingest");
    engine
}

fn read_setting_text(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM setting WHERE key = ?1", [key], |row| {
        row.get::<_, Vec<u8>>(0)
    })
    .ok()
    .and_then(|b| String::from_utf8(b).ok())
}

#[test]
fn ingest_persists_database_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("dbname-test");
    let mut vault = kdbx.vault().clone();
    vault.meta.database_name = "Personal Vault".into();
    kdbx.replace_vault(vault);

    let engine = ingested_engine(&kdbx, &engine_path);
    engine.close().expect("close");

    let conn = raw_open(&engine_path);
    assert_eq!(
        read_setting_text(&conn, "meta.database_name").as_deref(),
        Some("Personal Vault"),
    );
}

#[test]
fn ingest_persists_generator_string() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("gen-test");
    let mut vault = kdbx.vault().clone();
    vault.meta.generator = "KeePassXC".into();
    kdbx.replace_vault(vault);

    let engine = ingested_engine(&kdbx, &engine_path);
    engine.close().expect("close");

    let conn = raw_open(&engine_path);
    assert_eq!(
        read_setting_text(&conn, "meta.generator").as_deref(),
        Some("KeePassXC"),
    );
}

#[test]
fn ingest_persists_custom_icons() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("icons-test");
    let mut vault = kdbx.vault().clone();
    let uuid_a = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
    let uuid_b = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
    vault.meta.custom_icons = vec![
        CustomIcon::new(uuid_a, b"icon-bytes-aaaa".to_vec(), "A".into(), None),
        CustomIcon::new(
            uuid_b,
            b"icon-bytes-bbbb".to_vec(),
            "B".into(),
            Some(dt(42)),
        ),
    ];
    kdbx.replace_vault(vault);

    let engine = ingested_engine(&kdbx, &engine_path);
    engine.close().expect("close");

    let conn = raw_open(&engine_path);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM meta_custom_icon", [], |r| r.get(0))
        .expect("count");
    assert_eq!(count, 2, "two icon rows expected");

    let bytes_a: Vec<u8> = conn
        .query_row(
            "SELECT bytes FROM meta_custom_icon WHERE uuid = ?1",
            [uuid_a.to_string()],
            |r| r.get(0),
        )
        .expect("a bytes");
    assert_eq!(bytes_a, b"icon-bytes-aaaa");
}

#[test]
fn ingest_persists_custom_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("cdata-test");
    let mut vault = kdbx.vault().clone();
    vault.meta.custom_data = vec![
        CustomDataItem::new("k1".into(), "v1".into(), None),
        CustomDataItem::new("k2".into(), "v2".into(), Some(dt(99))),
    ];
    kdbx.replace_vault(vault);

    let engine = ingested_engine(&kdbx, &engine_path);
    engine.close().expect("close");

    let conn = raw_open(&engine_path);
    let v1: String = conn
        .query_row(
            "SELECT value FROM meta_custom_data WHERE key = 'k1'",
            [],
            |r| r.get(0),
        )
        .expect("k1");
    let v2: String = conn
        .query_row(
            "SELECT value FROM meta_custom_data WHERE key = 'k2'",
            [],
            |r| r.get(0),
        )
        .expect("k2");
    assert_eq!(v1, "v1");
    assert_eq!(v2, "v2");
}

#[test]
fn ingest_persists_deleted_objects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("tomb-test");
    let mut vault = kdbx.vault().clone();
    vault.deleted_objects = (0..3)
        .map(|i| {
            DeletedObject::new(
                Uuid::parse_str(&format!("00000000-0000-0000-0000-00000000000{i}")).unwrap(),
                Some(dt(1_000 + i64::from(i))),
            )
        })
        .collect();
    kdbx.replace_vault(vault);

    let engine = ingested_engine(&kdbx, &engine_path);
    engine.close().expect("close");

    let conn = raw_open(&engine_path);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM meta_deleted_object", [], |r| r.get(0))
        .expect("count");
    assert_eq!(count, 3);
}

// ─────────────────────── projection tests ───────────────────────

#[test]
fn projection_reconstitutes_full_meta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let kdbx = kdbx_with_full_meta();
    let source_vault = kdbx
        .vault_with_unwrapped_protected()
        .expect("source unwrap");

    let engine = ingested_engine(&kdbx, &engine_path);
    let projected = engine.project_to_vault().expect("project");

    assert_eq!(projected.meta.generator, source_vault.meta.generator);
    assert_eq!(
        projected.meta.database_name,
        source_vault.meta.database_name
    );
    assert_eq!(
        projected.meta.database_description,
        source_vault.meta.database_description
    );
    assert_eq!(
        projected.meta.default_username,
        source_vault.meta.default_username
    );
    assert_eq!(projected.meta.color, source_vault.meta.color);
    assert_eq!(projected.meta.header_hash, source_vault.meta.header_hash);
    assert_eq!(
        projected.meta.memory_protection,
        source_vault.meta.memory_protection
    );
    assert_eq!(
        projected.meta.history_max_items,
        source_vault.meta.history_max_items
    );
    assert_eq!(
        projected.meta.history_max_size,
        source_vault.meta.history_max_size
    );
    assert_eq!(
        projected.meta.maintenance_history_days,
        source_vault.meta.maintenance_history_days
    );
    assert_eq!(
        projected.meta.master_key_change_rec,
        source_vault.meta.master_key_change_rec
    );
    assert_eq!(
        projected.meta.master_key_change_force,
        source_vault.meta.master_key_change_force
    );
    assert_eq!(
        projected.meta.database_name_changed,
        source_vault.meta.database_name_changed
    );
    assert_eq!(
        projected.meta.master_key_changed,
        source_vault.meta.master_key_changed
    );

    // Custom icons compared as a set.
    assert_eq!(
        projected.meta.custom_icons.len(),
        source_vault.meta.custom_icons.len(),
    );
    for src_icon in &source_vault.meta.custom_icons {
        let dst = projected
            .meta
            .custom_icons
            .iter()
            .find(|i| i.uuid == src_icon.uuid)
            .expect("icon present");
        assert_eq!(dst.data, src_icon.data);
        assert_eq!(dst.name, src_icon.name);
        assert_eq!(dst.last_modified, src_icon.last_modified);
    }

    // Custom data compared as a set.
    assert_eq!(
        projected.meta.custom_data.len(),
        source_vault.meta.custom_data.len(),
    );
    for src_item in &source_vault.meta.custom_data {
        let dst = projected
            .meta
            .custom_data
            .iter()
            .find(|i| i.key == src_item.key)
            .expect("custom-data present");
        assert_eq!(dst.value, src_item.value);
        assert_eq!(dst.last_modified, src_item.last_modified);
    }

    // Deleted objects compared as a set.
    assert_eq!(
        projected.deleted_objects.len(),
        source_vault.deleted_objects.len()
    );
    for src_obj in &source_vault.deleted_objects {
        let dst = projected
            .deleted_objects
            .iter()
            .find(|o| o.uuid == src_obj.uuid)
            .expect("tombstone present");
        assert_eq!(dst.deleted_at, src_obj.deleted_at);
    }
}

#[test]
fn round_trip_preserves_full_meta() {
    // Ingest → save → reopen → check Meta survives.
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let kdbx_path = dir.path().join("round.kdbx");

    let kdbx = kdbx_with_full_meta();
    let source_meta = kdbx.vault().meta.clone();

    let mut engine = ingested_engine(&kdbx, &engine_path);
    let mut kdbx = kdbx;
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx)
        .expect("save_to_kdbx");
    drop(engine);
    drop(kdbx);

    let reopened = Kdbx::open(&kdbx_path)
        .expect("open from disk")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock");
    let reopened_meta = &reopened.vault().meta;

    assert_eq!(reopened_meta.database_name, source_meta.database_name);
    assert_eq!(reopened_meta.generator, source_meta.generator);
    assert_eq!(reopened_meta.default_username, source_meta.default_username);
    assert_eq!(
        reopened_meta.history_max_items,
        source_meta.history_max_items
    );
    assert_eq!(reopened_meta.history_max_size, source_meta.history_max_size);
    assert_eq!(
        reopened_meta.memory_protection,
        source_meta.memory_protection
    );
    assert_eq!(reopened_meta.color, source_meta.color);
    assert_eq!(
        reopened_meta.custom_icons.len(),
        source_meta.custom_icons.len()
    );
    assert_eq!(
        reopened_meta.custom_data.len(),
        source_meta.custom_data.len()
    );
}

#[test]
fn save_to_kdbx_without_live_handle_preserves_meta() {
    // The killer test. Ingest from a rich Meta source, close the engine,
    // reopen it (zero info from the original `Kdbx` handle survives in
    // memory), then save through a freshly-synthesised empty `Kdbx` —
    // whose Meta is the keepass-core default. If `splice_preserving_meta`
    // were still pulling Meta from the handle, every persisted field
    // would be reset to default in the saved KDBX. After this PR, the
    // projection feeds the full Meta from SQLite onto the fresh handle
    // before save.
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let kdbx_path = dir.path().join("rebuilt.kdbx");

    let source_kdbx = kdbx_with_full_meta();
    let source_meta = source_kdbx.vault().meta.clone();

    // Ingest, then drop both handles entirely.
    {
        let engine = ingested_engine(&source_kdbx, &engine_path);
        engine.close().expect("close");
    }
    drop(source_kdbx);

    // Reopen the engine (in-memory state = none) and synthesise a
    // fresh empty kdbx whose Meta is default.
    let mut engine =
        Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector()).expect("reopen engine");
    let mut fresh_kdbx =
        Kdbx::create_empty_v4_with_protector(&composite(), "blank", Some(protector()))
            .expect("fresh kdbx");
    // Sanity: the fresh kdbx's meta is the keepass-core default.
    assert_ne!(
        fresh_kdbx.vault().meta.database_name,
        source_meta.database_name
    );

    engine
        .save_to_kdbx(&kdbx_path, &mut fresh_kdbx)
        .expect("save_to_kdbx via fresh handle");

    drop(engine);
    drop(fresh_kdbx);

    // Reopen from disk; Meta must match the original source, not the
    // fresh handle's defaults.
    let reopened = Kdbx::open(&kdbx_path)
        .expect("open")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock");
    let reopened_meta = &reopened.vault().meta;

    assert_eq!(
        reopened_meta.database_name, source_meta.database_name,
        "database_name came from SQLite, not the (empty) live handle"
    );
    assert_eq!(reopened_meta.generator, source_meta.generator);
    assert_eq!(
        reopened_meta.history_max_items,
        source_meta.history_max_items
    );
    assert_eq!(
        reopened_meta.memory_protection,
        source_meta.memory_protection
    );
    assert_eq!(
        reopened_meta.custom_icons.len(),
        source_meta.custom_icons.len()
    );
    assert_eq!(
        reopened_meta.custom_data.len(),
        source_meta.custom_data.len()
    );
}

// ─────────────────────── vault state tests ───────────────────────

#[test]
fn state_is_active_on_fresh_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let engine =
        Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector()).expect("engine open");
    assert_eq!(engine.state(), VaultState::Active);
}

#[test]
fn state_enum_variants_match_design() {
    // Sanity: confirm the four variants exist and the Disconnected
    // payload carries a DisconnectReason. The match is exhaustive at
    // the surface we own; `#[non_exhaustive]` means callers see the
    // wildcard arm.
    let states = [
        VaultState::Active,
        VaultState::Disconnected {
            reason: DisconnectReason::FileMissing,
        },
        VaultState::Disconnected {
            reason: DisconnectReason::FileUnreadable("perm denied".into()),
        },
        VaultState::Disconnected {
            reason: DisconnectReason::NetworkUnavailable,
        },
        VaultState::Disconnected {
            reason: DisconnectReason::Other("eg".into()),
        },
        VaultState::ReadOnly,
        VaultState::Error,
    ];
    for s in &states {
        // Equality on Clone — exercise PartialEq + Clone derive at
        // least once.
        assert_eq!(s, &s.clone());
    }
}
