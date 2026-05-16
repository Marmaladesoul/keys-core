//! End-to-end tests for built-in smart folders (task 3.7).
//!
//! Confirms that every builtin predicate compiles cleanly and that
//! the compiled SQL returns the right entries against a curated KDBX
//! vault.

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{HistoryPolicy, NewEntry, NewGroup};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::predicate::Predicate;
use keys_engine::predicate_builtin::{
    BUILTIN_SMART_FOLDERS, BuiltinSmartFolderKind, EXPIRING_SOON_WINDOW, RECENTLY_MODIFIED_WINDOW,
    expired, expiring_soon, recently_modified, recycle_bin_contents, weak_password,
};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError, compile_predicate};
use secrecy::SecretString;

// ── shared test wiring (mirrors predicate_sql_e2e.rs) ──────────────────

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

// ── unit-ish tests ─────────────────────────────────────────────────────

#[test]
fn weak_password_predicate_is_evaluable() {
    assert!(weak_password().is_evaluable());
}

#[test]
fn recently_modified_is_within_30_days() {
    let Predicate::ModifiedWithin { duration } = recently_modified() else {
        panic!("expected ModifiedWithin");
    };
    assert_eq!(duration, RECENTLY_MODIFIED_WINDOW);
    assert_eq!(duration.as_secs(), 30 * 24 * 60 * 60);
}

#[test]
fn expiring_soon_is_within_7_days() {
    let Predicate::ExpiringWithin { duration } = expiring_soon() else {
        panic!("expected ExpiringWithin");
    };
    assert_eq!(duration, EXPIRING_SOON_WINDOW);
    assert_eq!(duration.as_secs(), 7 * 24 * 60 * 60);
}

#[test]
fn builtin_folders_have_unique_stable_ids() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for f in BUILTIN_SMART_FOLDERS {
        assert!(seen.insert(f.id), "duplicate id: {}", f.id);
    }
}

#[test]
fn all_builtin_predicates_compile_without_error() {
    let now_ms: i64 = 1_700_000_000_000;
    for folder in BUILTIN_SMART_FOLDERS {
        match folder.kind {
            BuiltinSmartFolderKind::AllEntries | BuiltinSmartFolderKind::RecycleBin => {
                // AllEntries has no predicate (special-cased to the
                // unfiltered list path); RecycleBin requires the
                // vault's recycle-bin UUID, supplied at evaluation
                // time. Cover RecycleBin separately with a real UUID.
                assert!(
                    folder.kind.predicate().is_none(),
                    "{} kind should not return a predicate",
                    folder.id,
                );
            }
            _ => {
                let p = folder
                    .kind
                    .predicate()
                    .unwrap_or_else(|| panic!("{} should have a predicate", folder.id));
                compile_predicate(&p, now_ms)
                    .unwrap_or_else(|e| panic!("{} failed to compile: {e}", folder.id));
            }
        }
    }

    // And the parameterised one separately.
    compile_predicate(&recycle_bin_contents(uuid::Uuid::nil()), now_ms)
        .expect("recycle_bin_contents compiles");
}

#[test]
fn expired_predicate_compiles_to_valid_sql() {
    let now_ms: i64 = 1_700_000_000_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let in_past = kdbx.add_entry(root, NewEntry::new("past")).expect("add");
    kdbx.edit_entry(in_past, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(Utc.timestamp_millis_opt(now_ms - 1_000_000).unwrap()));
    })
    .expect("set expiry past");
    let _no_expiry = kdbx.add_entry(root, NewEntry::new("none")).expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let got = engine
        .compiled_predicate_uuids_for_test(&expired(), now_ms)
        .expect("compile + run");
    assert_eq!(got, vec![in_past.0]);
}

#[test]
fn expiring_soon_finds_entries_within_7_days() {
    let now_ms: i64 = 1_700_000_000_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let in_3d = kdbx.add_entry(root, NewEntry::new("in-3d")).expect("add");
    let in_10d = kdbx.add_entry(root, NewEntry::new("in-10d")).expect("add");
    let already_expired = kdbx.add_entry(root, NewEntry::new("already")).expect("add");
    let no_expiry = kdbx.add_entry(root, NewEntry::new("none")).expect("add");

    let day_ms: i64 = 86_400_000;
    kdbx.edit_entry(in_3d, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(Utc.timestamp_millis_opt(now_ms + 3 * day_ms).unwrap()));
    })
    .expect("3d");
    kdbx.edit_entry(in_10d, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(
            Utc.timestamp_millis_opt(now_ms + 10 * day_ms).unwrap(),
        ));
    })
    .expect("10d");
    kdbx.edit_entry(already_expired, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(Utc.timestamp_millis_opt(now_ms - day_ms).unwrap()));
    })
    .expect("past");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let got = engine
        .compiled_predicate_uuids_for_test(&expiring_soon(), now_ms)
        .expect("run");
    assert_eq!(got, vec![in_3d.0]);
    let _ = (in_10d, already_expired, no_expiry);
}

#[test]
fn weak_password_finds_only_weak_entries() {
    let now_ms: i64 = 1_700_000_000_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let very_weak = kdbx
        .add_entry(root, NewEntry::new("vw").password(SecretString::from("a")))
        .expect("add");
    let strong = kdbx
        .add_entry(
            root,
            NewEntry::new("st").password(SecretString::from("Tr0ub4dor&3-correct-horse-battery!")),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let got = engine
        .compiled_predicate_uuids_for_test(&weak_password(), now_ms)
        .expect("run");
    assert!(got.contains(&very_weak.0), "very-weak should match");
    assert!(!got.contains(&strong.0), "strong must not match");
}

#[test]
fn recycle_bin_contents_finds_recycled_entries() {
    let now_ms: i64 = 1_700_000_000_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    // Use a regular group as the stand-in "recycle bin" — the predicate
    // just resolves to `Predicate::Group { uuid }`, so any group works
    // for proving the SQL filter routes the way we expect.
    let bin = kdbx
        .add_group(root, NewGroup::new("Recycle Bin"))
        .expect("add bin");
    let recycled = kdbx
        .add_entry(bin, NewEntry::new("recycled"))
        .expect("add recycled");
    let live = kdbx
        .add_entry(root, NewEntry::new("live"))
        .expect("add live");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let p = recycle_bin_contents(bin.0);
    let got = engine
        .compiled_predicate_uuids_for_test(&p, now_ms)
        .expect("run");
    assert_eq!(got, vec![recycled.0]);
    let _ = live;
}
