//! Tests for the `save_entry` engine API — the single-transaction,
//! single-history-snapshot funnel for the entry editor's "Save".
//!
//! The bug `save_entry` fixes: the old Swift-orchestrated save fired a
//! SEQUENCE of per-field engine mutations (`update_entry` + `set_tags` +
//! per-custom-field `set_*` + `remove_custom_field`), each of which
//! pushed its OWN `<History>` snapshot. One logical save of an entry
//! with N custom fields therefore archived ~1+N near-identical history
//! records. `save_entry` applies the whole desired state in one
//! transaction with exactly one snapshot.
//!
//! The headline gate is `save_with_many_custom_fields_archives_one`:
//! a save of an entry with five custom fields must add exactly ONE
//! history record, not one per field.

use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    ChangeEvent, DataChangeObserver, DbKey, Engine, EntrySave, IconRef, KeyProvider,
    KeyProviderError, NewCustomField, NewEntryFields, StrengthBucket,
};
use secrecy::{ExposeSecret, SecretString};
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
const COMPOSITE_PW: &[u8] = b"engine-save-entry-tests";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(COMPOSITE_PW)
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), "save-entry", Some(protector()))
        .expect("create")
}

fn engine_with_empty_vault() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx();
    let root_uuid = kdbx.vault().root.id.0;
    let mut engine =
        Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("engine open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, root_uuid, dir)
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

fn protected(name: &str, value: &str) -> NewCustomField {
    NewCustomField {
        name: name.to_owned(),
        value: SecretString::from(value.to_owned()),
        protected: true,
    }
}

fn plain(name: &str, value: &str) -> NewCustomField {
    NewCustomField {
        name: name.to_owned(),
        value: SecretString::from(value.to_owned()),
        protected: false,
    }
}

/// Build a `NewEntryFields` with `count` non-protected custom fields,
/// named `field-0..field-N`.
fn new_entry_with_custom_fields(title: &str, count: usize) -> NewEntryFields {
    NewEntryFields {
        title: title.into(),
        username: "alice".into(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        custom_fields: (0..count)
            .map(|i| plain(&format!("field-{i}"), &format!("value-{i}")))
            .collect(),
        tags: Vec::new(),
    }
}

/// A `save` payload that re-states the same five custom fields the entry
/// was created with, but flips the icon — i.e. the user changed the
/// icon via the picker and the editor re-submitted the unchanged custom
/// fields alongside (exactly the real-world repro).
fn save_keeping_five_fields(icon: IconRef) -> EntrySave {
    EntrySave {
        title: "five-fields".into(),
        username: "alice".into(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon,
        expires_at: None,
        custom_fields: (0..5)
            .map(|i| plain(&format!("field-{i}"), &format!("value-{i}")))
            .collect(),
        tags: Vec::new(),
    }
}

// ─────────────────────── the headline gate ───────────────────────

#[test]
fn save_with_many_custom_fields_archives_exactly_one_history_record() {
    // The bug repro: an entry with five custom fields, a single save
    // that only changes the icon. Old path: ~1+5 history records.
    // `save_entry`: exactly one.
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("five-fields", 5))
        .expect("create");

    let before = engine.entry(entry).expect("entry").expect("some");
    assert_eq!(before.history_count, 0, "fresh entry has no history");
    assert_eq!(before.custom_fields.len(), 5);

    engine
        .save_entry(entry, save_keeping_five_fields(IconRef::Builtin(12)))
        .expect("save");

    let after = engine.entry(entry).expect("entry").expect("some");
    assert_eq!(
        after.history_count, 1,
        "one save of a five-custom-field entry must archive exactly ONE history record"
    );
    assert!(
        matches!(after.icon, IconRef::Builtin(12)),
        "icon change should have landed, got {:?}",
        after.icon
    );
    assert_eq!(
        after.custom_fields.len(),
        5,
        "all five fields still present"
    );
}

// ─────────────────────── one correct pre-state ───────────────────────

#[test]
fn single_field_change_archives_one_correct_pre_state() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("original-title", 1))
        .expect("create");

    let save = EntrySave {
        title: "new-title".into(),
        username: "alice".into(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: vec![plain("field-0", "value-0")],
        tags: Vec::new(),
    };
    engine.save_entry(entry, save).expect("save");

    let history = engine.history(entry).expect("history");
    assert_eq!(history.len(), 1, "exactly one snapshot");
    assert_eq!(
        history[0].title, "original-title",
        "the one snapshot must hold the PRE-save title, not the new one"
    );

    let after = engine.entry(entry).expect("entry").expect("some");
    assert_eq!(after.title, "new-title", "live entry shows the new title");
}

// ─────────────────────── protected + non-protected land ───────────────────────

#[test]
fn save_lands_protected_and_non_protected_fields_and_password() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("fields", 0))
        .expect("create");

    let save = EntrySave {
        title: "fields".into(),
        username: "alice".into(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("new-password"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: vec![
            plain("website", "example.com"),
            protected("Token", "secret-token"),
        ],
        tags: Vec::new(),
    };
    engine.save_entry(entry, save).expect("save");

    let full = engine.entry(entry).expect("entry").expect("some");
    assert_eq!(full.custom_fields.len(), 2);
    assert!(
        full.custom_fields
            .iter()
            .any(|c| c.name == "website" && !c.is_protected),
        "website should be non-protected"
    );
    assert!(
        full.custom_fields
            .iter()
            .any(|c| c.name == "Token" && c.is_protected),
        "Token should be protected"
    );

    assert_eq!(
        engine
            .non_protected_custom_field(entry, "website")
            .expect("read")
            .as_deref(),
        Some("example.com")
    );
    assert_eq!(
        engine
            .reveal_custom_field(entry, "Token")
            .expect("reveal")
            .expose_secret(),
        "secret-token"
    );
    assert_eq!(
        engine
            .reveal_password(entry)
            .expect("reveal pw")
            .expose_secret(),
        "new-password"
    );
}

// ─────────────────────── replace-all removal ───────────────────────

#[test]
fn save_removes_custom_fields_absent_from_the_set() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("shrink", 3))
        .expect("create");
    assert_eq!(
        engine
            .entry(entry)
            .expect("e")
            .expect("s")
            .custom_fields
            .len(),
        3
    );

    // Save with only one of the three fields present — the other two
    // are absent and must be removed (replace-all).
    let save = EntrySave {
        title: "shrink".into(),
        username: "alice".into(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: vec![plain("field-1", "kept")],
        tags: Vec::new(),
    };
    engine.save_entry(entry, save).expect("save");

    let full = engine.entry(entry).expect("entry").expect("some");
    assert_eq!(full.custom_fields.len(), 1, "two fields were removed");
    assert_eq!(full.custom_fields[0].name, "field-1");
    assert_eq!(
        engine
            .non_protected_custom_field(entry, "field-1")
            .expect("read")
            .as_deref(),
        Some("kept")
    );
    assert_eq!(
        engine
            .non_protected_custom_field(entry, "field-0")
            .expect("read"),
        None,
        "field-0 must be gone"
    );
}

// ─────────────────────── TOTP / strength / tags / icon ───────────────────────

#[test]
fn save_recomputes_has_totp() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("totp", 0))
        .expect("create");
    assert!(
        !engine
            .list_entries(Some(root), keys_engine::Pagination::all())
            .expect("list")
            .iter()
            .find(|e| e.uuid == entry)
            .expect("found")
            .has_totp
    );

    // Add a recognised TOTP-bearing protected field → has_totp flips on.
    let with_totp = EntrySave {
        title: "totp".into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: vec![protected("TOTP Seed", "JBSWY3DPEHPK3PXP")],
        tags: Vec::new(),
    };
    engine.save_entry(entry, with_totp).expect("save totp");
    assert!(
        engine
            .list_entries(Some(root), keys_engine::Pagination::all())
            .expect("list")
            .iter()
            .find(|e| e.uuid == entry)
            .expect("found")
            .has_totp,
        "TOTP Seed field should flip has_totp on"
    );

    // Remove it again (replace-all with no fields) → has_totp flips off.
    let no_totp = EntrySave {
        title: "totp".into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: Vec::new(),
        tags: Vec::new(),
    };
    engine.save_entry(entry, no_totp).expect("save no totp");
    assert!(
        !engine
            .list_entries(Some(root), keys_engine::Pagination::all())
            .expect("list")
            .iter()
            .find(|e| e.uuid == entry)
            .expect("found")
            .has_totp,
        "removing the TOTP field should flip has_totp back off"
    );
}

#[test]
fn save_recomputes_password_strength() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("strength", 0))
        .expect("create");

    let strong = EntrySave {
        title: "strength".into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("Tr0ub4dour&3xtr4-L0ng-P@ssphrase!"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: Vec::new(),
        tags: Vec::new(),
    };
    engine.save_entry(entry, strong).expect("save strong");
    let full = engine.entry(entry).expect("entry").expect("some");
    assert!(
        matches!(
            full.password_strength_bucket,
            Some(StrengthBucket::Strong | StrengthBucket::VeryStrong)
        ),
        "a long mixed password should bucket strong, got {:?}",
        full.password_strength_bucket
    );
    assert!(full.password_entropy.unwrap_or(0.0) > 0.0);
}

#[test]
fn save_applies_tags_with_set_semantics() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("tags", 0))
        .expect("create");

    let save = EntrySave {
        title: "tags".into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: Vec::new(),
        // Duplicates + whitespace exercise the engine's trim + dedup.
        tags: vec!["work".into(), "  personal ".into(), "work".into()],
    };
    engine.save_entry(entry, save).expect("save");

    let mut tags = engine.entry(entry).expect("entry").expect("some").tags;
    tags.sort();
    assert_eq!(tags, vec!["personal".to_string(), "work".to_string()]);
}

#[test]
fn save_applies_custom_icon() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("icon", 0))
        .expect("create");
    let icon_uuid_str = engine
        .add_custom_icon(b"\x89PNG\r\n\x1a\nfake-icon")
        .expect("add icon");
    let icon_uuid = Uuid::parse_str(&icon_uuid_str).expect("parse");

    let save = EntrySave {
        title: "icon".into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Custom(icon_uuid),
        expires_at: None,
        custom_fields: Vec::new(),
        tags: Vec::new(),
    };
    engine.save_entry(entry, save).expect("save");

    let full = engine.entry(entry).expect("entry").expect("some");
    assert!(
        matches!(full.icon, IconRef::Custom(u) if u == icon_uuid),
        "custom icon should have landed, got {:?}",
        full.icon
    );
}

// ─────────────────────── idempotency ───────────────────────

#[test]
fn resaving_identical_state_still_archives_exactly_one_snapshot() {
    // Documented contract: `save_entry` does NOT diff — every call is a
    // user-initiated save that unconditionally archives one snapshot.
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("idem", 2))
        .expect("create");

    let build = || EntrySave {
        title: "idem".into(),
        username: "alice".into(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: vec![plain("field-0", "value-0"), plain("field-1", "value-1")],
        tags: Vec::new(),
    };

    engine.save_entry(entry, build()).expect("save 1");
    assert_eq!(engine.entry(entry).expect("e").expect("s").history_count, 1);
    // Re-save the byte-identical state.
    engine.save_entry(entry, build()).expect("save 2");
    assert_eq!(
        engine.entry(entry).expect("e").expect("s").history_count,
        2,
        "each save archives one snapshot, even when nothing changed"
    );
}

// ─────────────────────── round-trip ───────────────────────

#[test]
fn save_entry_state_round_trips_through_kdbx() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx_path = dir.path().join("vault.kdbx");

    let kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id.0;
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("rt", 0))
        .expect("create");
    let save = EntrySave {
        title: "round-trip".into(),
        username: "bob".into(),
        url: "https://example.org".into(),
        notes: "some notes".into(),
        password: SecretString::from("rt-password"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: vec![
            plain("website", "example.org"),
            protected("Token", "rt-secret"),
        ],
        tags: vec!["alpha".into(), "beta".into()],
    };
    engine.save_entry(entry, save).expect("save");

    let mut kdbx = kdbx;
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save_to_kdbx");
    drop(engine);
    drop(kdbx);

    let reopened = Kdbx::open(&kdbx_path)
        .expect("reopen")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock");
    let vault = reopened
        .vault_with_unwrapped_protected()
        .expect("unwrap reopened");

    let e = vault
        .root
        .entries
        .iter()
        .find(|e| e.title == "round-trip")
        .expect("entry present after reopen");
    assert_eq!(e.username.as_str(), "bob");
    assert_eq!(e.url.as_str(), "https://example.org");

    let website = e
        .custom_fields
        .iter()
        .find(|cf| cf.key == "website")
        .expect("website survived");
    assert!(!website.protected);
    assert_eq!(website.value.as_str(), "example.org");

    let token = e
        .custom_fields
        .iter()
        .find(|cf| cf.key == "Token")
        .expect("Token survived");
    assert!(token.protected);
    assert_eq!(token.value.as_str(), "rt-secret");

    let mut tags = e.tags.clone();
    tags.sort();
    assert_eq!(tags, vec!["alpha".to_string(), "beta".to_string()]);
}

// ─────────────────────── events + errors ───────────────────────

#[test]
fn save_entry_emits_entries_updated() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let entry = engine
        .create_entry(root, new_entry_with_custom_fields("evt", 0))
        .expect("create");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    let save = EntrySave {
        title: "evt".into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: Vec::new(),
        tags: Vec::new(),
    };
    engine.save_entry(entry, save).expect("save");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1, "exactly one event");
    match &events[0] {
        ChangeEvent::EntriesUpdated(uuids) => assert_eq!(uuids, &vec![entry]),
        other => panic!("expected EntriesUpdated, got {other:?}"),
    }
}

#[test]
fn save_entry_unknown_entry_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let save = EntrySave {
        title: "ghost".into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        expires_at: None,
        custom_fields: Vec::new(),
        tags: Vec::new(),
    };
    let err = engine
        .save_entry(Uuid::new_v4(), save)
        .expect_err("should fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("entry"),
        "expected NotFound for entry, got {msg}"
    );
}
