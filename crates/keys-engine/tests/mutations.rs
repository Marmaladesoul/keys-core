//! Integration tests for the Phase 4.1 mutation API.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, EntryUpdate, GroupUpdate, IconRef, KeyProvider, KeyProviderError,
    NewCustomField, NewEntryFields, NewGroupFields, Pagination,
};
use rusqlite::{Connection, params};
use secrecy::{ExposeSecret as _, SecretString};
use uuid::Uuid;

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

fn fresh_kdbx(protector: Arc<dyn FieldProtector>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector)).expect("create")
}

/// Build an engine with a fresh empty vault ingested. Returns
/// `(engine, root_group_uuid, tempdir)`. `TempDir` is kept alive so
/// the database file isn't deleted out from under the engine.
fn engine_with_empty_vault() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx(protector());
    let root_uuid = kdbx.vault().root.id.0;
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, root_uuid, dir)
}

/// Trivial [`NewEntryFields`] for tests that don't care about most fields.
fn new_entry(title: &str, password: &str) -> NewEntryFields {
    NewEntryFields {
        title: title.into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from(password),
        icon: IconRef::Builtin(0),
        custom_fields: Vec::new(),
        tags: Vec::new(),
    }
}

fn raw_open(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    let mut hex = String::with_capacity(64);
    for b in &DB_KEY_BYTES {
        use std::fmt::Write as _;
        write!(&mut hex, "{b:02x}").expect("hex");
    }
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
        .expect("apply key");
    conn
}

// ── create_entry ───────────────────────────────────────────────────────

#[test]
fn create_entry_inserts_row_with_derived_columns() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut fields = new_entry("acme", "Tr0ub4dor&3");
    fields.url = "https://Login.Example.COM/path".into();
    fields.username = "alice".into();
    let uuid = engine.create_entry(root, fields).expect("create");
    let entry = engine.entry(uuid).expect("entry").expect("found");
    assert_eq!(entry.title, "acme");
    assert_eq!(entry.username, "alice");
    assert_eq!(entry.url_host, "login.example.com");
    assert!(entry.password_strength_bucket.is_some());
    assert!(entry.password_entropy.is_some_and(|e| e > 0.0));
    assert!(!entry.is_recycled);
}

#[test]
fn create_entry_unknown_group_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let err = engine
        .create_entry(Uuid::new_v4(), new_entry("x", "p"))
        .unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "group" }
    ));
}

#[test]
fn create_entry_persists_protected_password_blob() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("acme", "secret123"))
        .expect("create");
    let path = dir.path().join("keys.db");
    engine.close().expect("close");
    let raw = raw_open(&path);
    let n: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM entry_protected WHERE entry_uuid = ?1 AND field_name = 'Password'",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 1);
}

#[test]
fn create_entry_with_custom_fields_and_tags() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut fields = new_entry("acme", "pw");
    fields.custom_fields = vec![
        NewCustomField {
            name: "Token".into(),
            value: SecretString::from("abc"),
            protected: true,
        },
        NewCustomField {
            name: "Website".into(),
            value: SecretString::from("example.com"),
            protected: false,
        },
    ];
    fields.tags = vec!["work".into(), "work".into(), "  ".into(), "team".into()];
    let uuid = engine.create_entry(root, fields).expect("create");
    let entry = engine.entry(uuid).expect("entry").expect("found");
    let names: Vec<&str> = entry
        .custom_fields
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(names, vec!["Token", "Website"]);
    let mut tags = entry.tags.clone();
    tags.sort();
    assert_eq!(tags, vec!["team".to_owned(), "work".to_owned()]);
}

#[test]
fn create_then_list_returns_new_entry() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("acme", "pw"))
        .expect("create");
    let summaries = engine
        .list_entries(Some(root), Pagination::all())
        .expect("list");
    assert!(summaries.iter().any(|s| s.uuid == uuid));
}

// ── update_entry ───────────────────────────────────────────────────────

#[test]
fn update_entry_changes_fields_and_refreshes_modified() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("old", "pw"))
        .expect("create");
    let before = engine.entry(uuid).unwrap().unwrap().modified_at;
    // Sleep 2 ms to make modified_at change visibly.
    std::thread::sleep(std::time::Duration::from_millis(2));
    engine
        .update_entry(
            uuid,
            EntryUpdate {
                title: Some("new".into()),
                url: Some("https://NEW.Example.com/".into()),
                ..Default::default()
            },
        )
        .expect("update");
    let entry = engine.entry(uuid).unwrap().unwrap();
    assert_eq!(entry.title, "new");
    assert_eq!(entry.url_host, "new.example.com");
    assert!(entry.modified_at >= before);
}

#[test]
fn update_entry_password_refreshes_derived_columns() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "a"))
        .expect("create");
    let weak = engine.entry(uuid).unwrap().unwrap();
    let weak_entropy = weak.password_entropy.unwrap_or(0.0);
    engine
        .update_entry(
            uuid,
            EntryUpdate {
                password: Some(SecretString::from("8&hG2!q%LpZx#7eMb")),
                ..Default::default()
            },
        )
        .expect("update");
    let strong = engine.entry(uuid).unwrap().unwrap();
    let strong_entropy = strong.password_entropy.unwrap_or(0.0);
    assert!(strong_entropy > weak_entropy);
    // Reveal the new password.
    let revealed = engine.reveal_password(uuid).expect("reveal");
    assert_eq!(revealed.expose_secret(), "8&hG2!q%LpZx#7eMb");
}

#[test]
fn update_entry_unknown_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let err = engine
        .update_entry(Uuid::new_v4(), EntryUpdate::default())
        .unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "entry" }
    ));
}

// ── recycle / restore ──────────────────────────────────────────────────

#[test]
fn recycle_then_restore_round_trip() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    // The soft-delete path needs a bin group to move into. Without a bin a
    // "recycle" is a permanent delete (see
    // `recycle_entry_without_bin_hard_deletes_and_tombstones`).
    let bin = engine
        .create_group(
            root,
            NewGroupFields {
                name: "Recycle Bin".into(),
                notes: String::new(),
                icon: IconRef::Builtin(43),
            },
        )
        .expect("create bin");
    engine.set_recycle_bin(true, Some(bin)).expect("set bin");
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    engine.recycle_entry(uuid).expect("recycle");
    assert!(engine.entry(uuid).unwrap().unwrap().is_recycled);
    engine.restore_entry(uuid).expect("restore");
    assert!(!engine.entry(uuid).unwrap().unwrap().is_recycled);
}

#[test]
fn recycle_entry_enabled_without_bin_lazy_creates_and_recycles() {
    // Recycle bin *enabled* but no bin group yet (a fresh vault, or one made
    // by keepassxc-cli). The first recycle must lazily create the bin and
    // soft-recycle the entry — NOT permanently delete it. Mirrors
    // keepass-core's `find_or_create_recycle_bin`.
    let (mut engine, root, _dir) = engine_with_empty_vault();
    engine
        .set_recycle_bin(true, None)
        .expect("enable bin without choosing a group");
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");

    engine.recycle_entry(uuid).expect("recycle");

    let entry = engine
        .entry(uuid)
        .unwrap()
        .expect("entry still exists — soft-recycled, not permanently deleted");
    assert!(entry.is_recycled, "entry moved into the lazily-created bin");
    assert!(
        engine.recycle_bin_uuid().unwrap().is_some(),
        "a recycle bin group was created on first recycle"
    );
}

#[test]
fn ensure_recycle_bin_creates_when_enabled_and_is_idempotent() {
    // Enabled but no bin group (the freshly-added-vault state). `ensure`
    // creates the bin up front; a second call is a no-op returning the same
    // uuid (so two adds / re-opens never mint a second bin).
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    engine
        .set_recycle_bin(true, None)
        .expect("enable bin without a group");
    assert!(engine.recycle_bin_uuid().unwrap().is_none());

    let bin = engine
        .ensure_recycle_bin()
        .expect("ensure")
        .expect("bin created");
    assert_eq!(
        engine.recycle_bin_uuid().unwrap().as_deref(),
        Some(bin.as_str())
    );

    let again = engine.ensure_recycle_bin().expect("ensure again");
    assert_eq!(again.as_deref(), Some(bin.as_str()), "idempotent");
}

#[test]
fn ensure_recycle_bin_noop_when_disabled() {
    // Disabled vault → ensure creates nothing (a permanent-delete vault by
    // the user's choice).
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    assert!(engine.ensure_recycle_bin().expect("ensure").is_none());
    assert!(engine.recycle_bin_uuid().unwrap().is_none());
}

#[test]
fn recycle_entry_disabled_without_bin_hard_deletes_and_tombstones() {
    // Recycle bin *disabled* and none exists → a "recycle" is a permanent
    // delete: the entry is removed and a tombstone recorded so the removal
    // persists to the file and propagates cross-peer (Phase 5b) — rather than
    // stranding behind an unsyncable `is_recycled` flag with no KDBX home.
    let (mut engine, root, dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    let path = dir.path().join("keys.db");

    engine
        .recycle_entry(uuid)
        .expect("recycle (no bin → hard delete)");
    assert!(
        engine.entry(uuid).unwrap().is_none(),
        "entry hard-deleted when there is no bin"
    );
    engine.close().expect("close");

    let raw = raw_open(&path);
    let tomb_ct: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM meta_deleted_object WHERE uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count tombstones");
    assert_eq!(tomb_ct, 1, "no-bin recycle recorded a tombstone");
}

#[test]
fn recycle_entry_unknown_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let err = engine.recycle_entry(Uuid::new_v4()).unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "entry" }
    ));
}

// ── empty_recycle_bin ──────────────────────────────────────────────────

#[test]
fn empty_recycle_bin_purges_contents_keeps_bin_and_tombstones() {
    // empty-bin permanently purges everything inside the bin — loose recycled
    // entries AND a subgroup parked in the bin with its own entry — recording
    // a `<DeletedObjects>` tombstone for each so the purge propagates
    // cross-peer (the permanent-delete contract), while keeping the bin group
    // itself and any live entry outside the bin.
    let (mut engine, root, dir) = engine_with_empty_vault();
    let path = dir.path().join("keys.db");

    let bin = engine
        .create_group(
            root,
            NewGroupFields {
                name: "Recycle Bin".into(),
                notes: String::new(),
                icon: IconRef::Builtin(43),
            },
        )
        .expect("create bin");
    engine.set_recycle_bin(true, Some(bin)).expect("set bin");

    let keeper = engine
        .create_entry(root, new_entry("keeper", "p"))
        .expect("keeper");
    let v1 = engine
        .create_entry(root, new_entry("victim-one", "p"))
        .expect("v1");
    let v2 = engine
        .create_entry(root, new_entry("victim-two", "p"))
        .expect("v2");
    engine.recycle_entry(v1).expect("recycle v1");
    engine.recycle_entry(v2).expect("recycle v2");

    // A subgroup parked in the bin, holding its own entry → empty-bin must
    // cascade (the nested entry AND the subgroup), not just the loose ones.
    let oldproj = engine
        .create_group(
            root,
            NewGroupFields {
                name: "Old Project".into(),
                notes: String::new(),
                icon: IconRef::Builtin(48),
            },
        )
        .expect("create subgroup");
    let nested = engine
        .create_entry(oldproj, new_entry("nested-secret", "p"))
        .expect("nested");
    engine
        .move_group(oldproj, bin)
        .expect("park subgroup in bin");

    engine.empty_recycle_bin().expect("empty bin");

    // Everything inside the bin is gone; the keeper and the bin survive.
    assert!(
        engine.entry(v1).unwrap().is_none(),
        "loose recycled entry purged"
    );
    assert!(
        engine.entry(v2).unwrap().is_none(),
        "loose recycled entry purged"
    );
    assert!(
        engine.entry(nested).unwrap().is_none(),
        "nested entry purged via the subgroup cascade"
    );
    assert!(
        engine.entry(keeper).unwrap().is_some(),
        "live entry outside the bin untouched"
    );
    assert!(
        !engine
            .group_tree()
            .unwrap()
            .iter()
            .any(|g| g.uuid == oldproj),
        "bin subgroup purged"
    );
    let bin_str = bin.to_string();
    assert_eq!(
        engine.recycle_bin_uuid().unwrap().as_deref(),
        Some(bin_str.as_str()),
        "the bin group itself survives an empty"
    );
    assert!(
        engine.recycle_bin_enabled().unwrap(),
        "empty does not disable the bin"
    );

    engine.close().expect("close");

    // Each purged entry AND the subgroup left a tombstone.
    let raw = raw_open(&path);
    for (id, what) in [
        (v1, "v1"),
        (v2, "v2"),
        (nested, "nested"),
        (oldproj, "oldproj"),
    ] {
        let ct: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM meta_deleted_object WHERE uuid = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .expect("count tombstones");
        assert_eq!(ct, 1, "{what} tombstoned by empty-bin");
    }
}

#[test]
fn empty_recycle_bin_without_bin_is_a_noop() {
    // A vault with no recycle bin group (bin disabled) → empty-bin removes
    // nothing and errors not. The lone live entry survives.
    let (mut engine, root, _dir) = engine_with_empty_vault();
    assert!(engine.recycle_bin_uuid().unwrap().is_none());
    let e = engine
        .create_entry(root, new_entry("solo", "p"))
        .expect("create");

    engine
        .empty_recycle_bin()
        .expect("empty (no bin) is a clean no-op");

    assert!(
        engine.entry(e).unwrap().is_some(),
        "no-bin empty-bin touched a live entry"
    );
}

// ── delete_entry ───────────────────────────────────────────────────────

#[test]
fn delete_cascades_protected_and_attachments() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    engine
        .attach_file(uuid, "file.txt", b"hello".to_vec())
        .expect("attach");
    let path = dir.path().join("keys.db");

    engine.delete_entry(uuid).expect("delete");
    engine.close().expect("close");

    let raw = raw_open(&path);
    let entry_ct: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM entry WHERE uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(entry_ct, 0);
    let protected_ct: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM entry_protected WHERE entry_uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(protected_ct, 0);
    let att_ct: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM entry_attachment WHERE entry_uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(att_ct, 0);
}

#[test]
fn delete_entry_records_tombstone() {
    // Phase 5b producer side: a hard delete must leave a `<DeletedObjects>`
    // tombstone so the deletion can propagate cross-peer (otherwise a peer that
    // still holds the entry would resurrect it on the next owner-rows ingest).
    let (mut engine, root, dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    let path = dir.path().join("keys.db");

    engine.delete_entry(uuid).expect("delete");
    engine.close().expect("close");

    let raw = raw_open(&path);
    let tomb_ct: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM meta_deleted_object WHERE uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count tombstones");
    assert_eq!(tomb_ct, 1, "delete recorded a tombstone");
    let deleted_at: Option<i64> = raw
        .query_row(
            "SELECT deleted_at FROM meta_deleted_object WHERE uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )
        .expect("deleted_at");
    assert!(deleted_at.is_some(), "tombstone carries a deletion time");
}

#[test]
fn delete_entry_unknown_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let err = engine.delete_entry(Uuid::new_v4()).unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "entry" }
    ));
}

// ── move_entry ─────────────────────────────────────────────────────────

#[test]
fn move_entry_changes_group_membership() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let other = engine
        .create_group(
            root,
            NewGroupFields {
                name: "Other".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("create_group");
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    engine.move_entry(uuid, other).expect("move");
    let entry = engine.entry(uuid).unwrap().unwrap();
    assert_eq!(entry.group_uuid, other);
}

#[test]
fn move_entry_unknown_group_returns_not_found() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    let err = engine.move_entry(uuid, Uuid::new_v4()).unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "group" }
    ));
}

// ── set_protected_field / set_non_protected_custom_field ───────────────

#[test]
fn set_protected_field_password_updates_derived_columns() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "a"))
        .expect("create");
    engine
        .set_protected_field(uuid, "Password", SecretString::from("BetterStuff!42"))
        .expect("set pw");
    assert_eq!(
        engine
            .reveal_password(uuid)
            .expect("reveal")
            .expose_secret(),
        "BetterStuff!42"
    );
}

#[test]
fn set_protected_field_custom_inserts() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    engine
        .set_protected_field(uuid, "Token", SecretString::from("xyz"))
        .expect("set");
    let revealed = engine.reveal_custom_field(uuid, "Token").expect("reveal");
    assert_eq!(revealed.expose_secret(), "xyz");
}

#[test]
fn set_protected_field_unknown_entry_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let err = engine
        .set_protected_field(Uuid::new_v4(), "Password", SecretString::from("p"))
        .unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "entry" }
    ));
}

#[test]
fn set_non_protected_custom_field_upserts() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    engine
        .set_non_protected_custom_field(uuid, "Website", "example.com")
        .expect("set");
    engine
        .set_non_protected_custom_field(uuid, "Website", "new.example.com")
        .expect("upsert");
    let entry = engine.entry(uuid).unwrap().unwrap();
    assert!(
        entry
            .custom_fields
            .iter()
            .any(|c| c.name == "Website" && !c.is_protected)
    );
    // Round-trip the value through the dedicated reader.
    assert_eq!(
        engine
            .non_protected_custom_field(uuid, "Website")
            .expect("read"),
        Some("new.example.com".to_owned())
    );
}

#[test]
fn non_protected_custom_field_returns_none_for_absent_or_protected() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    // Missing row → None.
    assert_eq!(
        engine
            .non_protected_custom_field(uuid, "Nope")
            .expect("read"),
        None
    );
    // Protected field lives in entry_protected; the non-protected
    // reader must not see it.
    engine
        .set_protected_field(uuid, "Secret", SecretString::from("shh"))
        .expect("set protected");
    assert_eq!(
        engine
            .non_protected_custom_field(uuid, "Secret")
            .expect("read"),
        None
    );
}

#[test]
fn remove_custom_field_idempotent_and_blocks_password() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    engine
        .set_non_protected_custom_field(uuid, "Website", "example.com")
        .expect("set");
    engine
        .remove_custom_field(uuid, "Website")
        .expect("remove once");
    // Idempotent.
    engine
        .remove_custom_field(uuid, "Website")
        .expect("remove twice");
    // Password slot refuses.
    let err = engine.remove_custom_field(uuid, "Password").unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound {
            entity: "custom_field"
        }
    ));
}

// ── set_tags ───────────────────────────────────────────────────────────

#[test]
fn set_tags_replaces_existing() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut fields = new_entry("x", "p");
    fields.tags = vec!["a".into(), "b".into()];
    let uuid = engine.create_entry(root, fields).expect("create");
    engine
        .set_tags(uuid, vec!["c".into(), "d".into(), "c".into()])
        .expect("set");
    let entry = engine.entry(uuid).unwrap().unwrap();
    let mut tags = entry.tags.clone();
    tags.sort();
    assert_eq!(tags, vec!["c".to_owned(), "d".to_owned()]);
}

// ── attach / remove attachment ─────────────────────────────────────────

#[test]
fn attach_then_remove_attachment_round_trips() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("x", "p"))
        .expect("create");
    engine
        .attach_file(uuid, "logo.png", b"PNGDATA".to_vec())
        .expect("attach");
    let entry = engine.entry(uuid).unwrap().unwrap();
    assert_eq!(entry.attachments.len(), 1);
    assert_eq!(entry.attachments[0].name, "logo.png");
    assert_eq!(entry.attachments[0].size, 7);

    engine.remove_attachment(uuid, "logo.png").expect("remove");
    let entry2 = engine.entry(uuid).unwrap().unwrap();
    assert!(entry2.attachments.is_empty());

    let path = dir.path().join("keys.db");
    engine.close().expect("close");
    // Blob row is not GC'd.
    let raw = raw_open(&path);
    let blob_ct: i64 = raw
        .query_row("SELECT COUNT(*) FROM attachment_blob", [], |r| r.get(0))
        .expect("count");
    assert_eq!(blob_ct, 1);
}

// ── group mutations ────────────────────────────────────────────────────

#[test]
fn create_group_and_update_group() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let g = engine
        .create_group(
            root,
            NewGroupFields {
                name: "Work".into(),
                notes: String::new(),
                icon: IconRef::Builtin(1),
            },
        )
        .expect("create_group");
    engine
        .update_group(
            g,
            GroupUpdate {
                name: Some("Work2".into()),
                ..Default::default()
            },
        )
        .expect("update");
    let tree = engine.group_tree().expect("tree");
    let node = tree.iter().find(|n| n.uuid == g).expect("found");
    assert_eq!(node.name, "Work2");
}

#[test]
fn update_group_unknown_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let err = engine
        .update_group(Uuid::new_v4(), GroupUpdate::default())
        .unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "group" }
    ));
}

#[test]
fn delete_group_removes_descendants_recursively() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let parent = engine
        .create_group(
            root,
            NewGroupFields {
                name: "P".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("create p");
    let child = engine
        .create_group(
            parent,
            NewGroupFields {
                name: "C".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("create c");
    let _e1 = engine
        .create_entry(parent, new_entry("e1", "p"))
        .expect("e1");
    let _e2 = engine
        .create_entry(child, new_entry("e2", "p"))
        .expect("e2");

    engine.delete_group(parent).expect("delete");
    let path = dir.path().join("keys.db");
    engine.close().expect("close");
    let raw = raw_open(&path);
    let grp_ct: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM \"group\" WHERE uuid IN (?1, ?2)",
            params![parent.to_string(), child.to_string()],
            |r| r.get(0),
        )
        .expect("count groups");
    assert_eq!(grp_ct, 0);
    let entry_ct: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM entry WHERE group_uuid IN (?1, ?2)",
            params![parent.to_string(), child.to_string()],
            |r| r.get(0),
        )
        .expect("count entries");
    assert_eq!(entry_ct, 0);
}

#[test]
fn delete_group_records_tombstones() {
    // Phase 5b: a group-cascade delete must tombstone every removed entry AND
    // group, or a peer that still holds them resurrects them on the next sync
    // (the entries re-parented to root). Mirrors `delete_entry_records_tombstone`
    // for the cascade path.
    let (mut engine, root, dir) = engine_with_empty_vault();
    let parent = engine
        .create_group(
            root,
            NewGroupFields {
                name: "P".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("create p");
    let child = engine
        .create_group(
            parent,
            NewGroupFields {
                name: "C".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("create c");
    let e1 = engine
        .create_entry(parent, new_entry("e1", "p"))
        .expect("e1");
    let e2 = engine
        .create_entry(child, new_entry("e2", "p"))
        .expect("e2");

    engine.delete_group(parent).expect("delete");
    let path = dir.path().join("keys.db");
    engine.close().expect("close");
    let raw = raw_open(&path);
    // All four uuids — both groups and both entries — must be tombstoned.
    let tomb_ct: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM meta_deleted_object WHERE uuid IN (?1, ?2, ?3, ?4)",
            params![
                parent.to_string(),
                child.to_string(),
                e1.to_string(),
                e2.to_string()
            ],
            |r| r.get(0),
        )
        .expect("count tombstones");
    assert_eq!(
        tomb_ct, 4,
        "every cascade-deleted entry and group is tombstoned"
    );
}

#[test]
fn move_group_changes_parent() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let a = engine
        .create_group(
            root,
            NewGroupFields {
                name: "A".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("a");
    let b = engine
        .create_group(
            root,
            NewGroupFields {
                name: "B".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("b");
    engine.move_group(a, b).expect("move");
    let tree = engine.group_tree().expect("tree");
    let a_node = tree.iter().find(|n| n.uuid == a).expect("a");
    assert_eq!(a_node.parent_uuid, Some(b));
}

#[test]
fn move_group_rejects_cycle() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let a = engine
        .create_group(
            root,
            NewGroupFields {
                name: "A".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("a");
    let b = engine
        .create_group(
            a,
            NewGroupFields {
                name: "B".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("b");
    // Try to move A under its own descendant B.
    let err = engine.move_group(a, b).unwrap_err();
    assert!(matches!(err, keys_engine::EngineError::CycleDetected));
    // And under itself.
    let err = engine.move_group(a, a).unwrap_err();
    assert!(matches!(err, keys_engine::EngineError::CycleDetected));
}

#[test]
fn recycle_group_without_bin_returns_not_found() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let g = engine
        .create_group(
            root,
            NewGroupFields {
                name: "X".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("g");
    let err = engine.recycle_group(g).unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound {
            entity: "recycle_bin"
        }
    ));
}

#[test]
fn recycle_group_moves_under_bin() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    // Manually mark a group as the recycle bin via raw SQL.
    let bin = engine
        .create_group(
            root,
            NewGroupFields {
                name: "Bin".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("bin");
    let g = engine
        .create_group(
            root,
            NewGroupFields {
                name: "X".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("g");

    let path = dir.path().join("keys.db");
    engine.close().expect("close");
    let raw = raw_open(&path);
    raw.execute(
        "UPDATE \"group\" SET is_recycle_bin = 1 WHERE uuid = ?1",
        params![bin.to_string()],
    )
    .expect("mark bin");
    drop(raw);

    let mut engine =
        Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("reopen");
    engine.recycle_group(g).expect("recycle");
    let tree = engine.group_tree().expect("tree");
    let g_node = tree.iter().find(|n| n.uuid == g).expect("g");
    assert_eq!(g_node.parent_uuid, Some(bin));
}

#[test]
fn restore_group_moves_to_new_parent() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let a = engine
        .create_group(
            root,
            NewGroupFields {
                name: "A".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("a");
    let b = engine
        .create_group(
            root,
            NewGroupFields {
                name: "B".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("b");
    engine.restore_group(a, b).expect("restore");
    let tree = engine.group_tree().expect("tree");
    let a_node = tree.iter().find(|n| n.uuid == a).expect("a");
    assert_eq!(a_node.parent_uuid, Some(b));
}

// ── perf ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "perf benchmark; run via `--ignored` in release mode"]
fn mutation_perf_877_creates() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let start = std::time::Instant::now();
    for i in 0..877 {
        let _ = engine
            .create_entry(root, new_entry(&format!("e{i}"), "pw"))
            .expect("create");
    }
    let elapsed = start.elapsed();
    let per = elapsed / 877;
    eprintln!("877 creates: {elapsed:?}, per: {per:?}");
    assert!(
        per < std::time::Duration::from_millis(10),
        "per-create > 10ms (got {per:?})"
    );
}
