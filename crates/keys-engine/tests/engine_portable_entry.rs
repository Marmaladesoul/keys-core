//! Tests for the Phase 6.17-F `Engine::export_entry` /
//! `Engine::import_entry` cross-database move surface.
//!
//! Three scenarios stand out: same-engine round-trip (lightest path,
//! exercises every field type), cross-engine move (two distinct
//! databases — what the legacy `Vault::export_entry` / `importEntry`
//! actually backs), and custom-icon rehoming (source has a custom
//! icon, target doesn't — import must dedup the bytes into the target's
//! pool and rewrite the new entry's `icon_custom_uuid`).

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, IconRef, KeyProvider, KeyProviderError, NewCustomField, NewEntryFields,
    PortableAttachment, PortableEntry,
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

#[derive(Debug)]
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

/// `(engine, root_group_uuid, tempdir)`. `TempDir` is kept alive so the
/// db file isn't deleted out from under the engine.
fn engine_with_empty_vault() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();
    let root_uuid = kdbx.vault().root.id.0;
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, root_uuid, dir)
}

/// Minimal 1×1 PNG used as a stand-in for "real" icon bytes. Content
/// is irrelevant for the dedup logic — we just need bytes whose hash
/// is stable across runs.
const TINY_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

const OTHER_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x06, 0x00, 0x00, 0x00, 0x72, 0xb6, 0x0d,
    0x24, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

/// Create a fully-loaded entry: custom Title/URL/Username/Notes,
/// canonical password, one protected + one non-protected custom field,
/// two tags, one attachment, and a (custom or builtin) icon. The icon
/// is supplied by the caller so the same builder powers the
/// custom-icon and built-in-icon tests.
fn create_loaded_entry(engine: &mut Engine, group: Uuid, icon: IconRef) -> Uuid {
    let fields = NewEntryFields {
        title: "Acme".into(),
        username: "alice".into(),
        url: "https://example.com/login".into(),
        notes: "demo notes".into(),
        password: SecretString::from("hunter2"),
        icon,
        custom_fields: vec![
            NewCustomField {
                name: "Token".into(),
                value: SecretString::from("tok-abc"),
                protected: true,
            },
            NewCustomField {
                name: "Website".into(),
                value: SecretString::from("example.com"),
                protected: false,
            },
        ],
        tags: vec!["work".into(), "team".into()],
    };
    let uuid = engine.create_entry(group, fields).expect("create");
    engine
        .attach_file(uuid, "readme.txt", b"hello world".to_vec())
        .expect("attach");
    uuid
}

// ─────────────────────── tests ───────────────────────

#[test]
fn export_carries_every_field_type() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = create_loaded_entry(&mut engine, root, IconRef::Builtin(7));

    let portable = engine.export_entry(uuid).expect("export");

    assert_eq!(portable.title, "Acme");
    assert_eq!(portable.username, "alice");
    assert_eq!(portable.url, "https://example.com/login");
    assert_eq!(portable.notes, "demo notes");
    assert!(matches!(portable.icon, IconRef::Builtin(7)));
    assert!(portable.custom_icon_png.is_none());
    assert_eq!(portable.password.expose_secret(), "hunter2");
    // Protected custom fields, excluding the canonical Password slot.
    assert_eq!(portable.protected_fields.len(), 1);
    let (name, val) = &portable.protected_fields[0];
    assert_eq!(name, "Token");
    assert_eq!(val.expose_secret(), "tok-abc");
    // Non-protected custom fields.
    assert_eq!(
        portable.custom_fields,
        vec![("Website".to_owned(), "example.com".to_owned())]
    );
    let mut tags = portable.tags.clone();
    tags.sort();
    assert_eq!(tags, vec!["team".to_owned(), "work".to_owned()]);
    assert_eq!(portable.attachments.len(), 1);
    assert_eq!(portable.attachments[0].name, "readme.txt");
    assert_eq!(portable.attachments[0].bytes, b"hello world");
}

#[test]
fn export_unknown_uuid_returns_not_found() {
    let (engine, _root, _dir) = engine_with_empty_vault();
    let err = engine.export_entry(Uuid::new_v4()).unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "entry" }
    ));
}

#[test]
fn same_engine_round_trip_creates_distinct_entry() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let src_uuid = create_loaded_entry(&mut engine, root, IconRef::Builtin(3));

    let portable = engine.export_entry(src_uuid).expect("export");
    let new_uuid = engine.import_entry(portable, root).expect("import");
    assert_ne!(new_uuid, src_uuid);

    let original = engine.entry(src_uuid).expect("entry").expect("found");
    let imported = engine.entry(new_uuid).expect("entry").expect("found");

    // Identity-bearing fields differ (uuid + timestamps); content
    // fields match.
    assert_eq!(imported.title, original.title);
    assert_eq!(imported.username, original.username);
    assert_eq!(imported.url, original.url);
    assert_eq!(imported.notes, original.notes);
    assert_eq!(imported.icon, original.icon);
    assert_eq!(imported.tags, original.tags);
    assert_eq!(
        imported.custom_fields.len(),
        original.custom_fields.len(),
        "custom field count parity"
    );
    let imported_names: Vec<&str> = imported
        .custom_fields
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(imported_names, vec!["Token", "Website"]);

    // Attachments round-trip with content intact.
    let bytes = engine
        .attachment_bytes(new_uuid, "readme.txt")
        .expect("att bytes");
    assert_eq!(bytes, b"hello world");

    // Password reveals through the target's protector.
    let revealed = engine.reveal_password(new_uuid).expect("reveal");
    assert_eq!(revealed.expose_secret(), "hunter2");
    let revealed_token = engine
        .reveal_custom_field(new_uuid, "Token")
        .expect("reveal token");
    assert_eq!(revealed_token.expose_secret(), "tok-abc");
}

#[test]
fn cross_engine_move_preserves_all_data() {
    let (mut src_engine, src_root, _dir_src) = engine_with_empty_vault();
    let (mut tgt_engine, tgt_root, _dir_tgt) = engine_with_empty_vault();

    let src_uuid = create_loaded_entry(&mut src_engine, src_root, IconRef::Builtin(5));

    let portable = src_engine.export_entry(src_uuid).expect("export");
    let new_uuid = tgt_engine.import_entry(portable, tgt_root).expect("import");

    // The new entry exists on the target with all fields intact.
    let imported = tgt_engine.entry(new_uuid).expect("entry").expect("found");
    assert_eq!(imported.title, "Acme");
    assert_eq!(imported.url, "https://example.com/login");
    assert_eq!(imported.group_uuid, tgt_root);
    let pw = tgt_engine.reveal_password(new_uuid).expect("reveal");
    assert_eq!(pw.expose_secret(), "hunter2");
    let token = tgt_engine
        .reveal_custom_field(new_uuid, "Token")
        .expect("reveal");
    assert_eq!(token.expose_secret(), "tok-abc");
    let bytes = tgt_engine
        .attachment_bytes(new_uuid, "readme.txt")
        .expect("att");
    assert_eq!(bytes, b"hello world");

    // Caller completes the move with `delete_entry` on the source —
    // the export+import contract is otherwise independent.
    src_engine.delete_entry(src_uuid).expect("source delete");
    assert!(
        src_engine.entry(src_uuid).expect("query").is_none(),
        "source entry tombstoned"
    );
}

#[test]
fn custom_icon_rehomes_into_target_pool() {
    let (mut src_engine, src_root, _dir_src) = engine_with_empty_vault();
    let (mut tgt_engine, tgt_root, _dir_tgt) = engine_with_empty_vault();

    // Source registers a custom icon, attaches it to a new entry.
    let src_icon_uuid_str = src_engine.add_custom_icon(TINY_PNG).expect("add icon");
    let src_icon_uuid = Uuid::parse_str(&src_icon_uuid_str).expect("parse");
    let src_uuid = create_loaded_entry(&mut src_engine, src_root, IconRef::Custom(src_icon_uuid));

    // Sanity: the target has no entries yet, no icons that match TINY_PNG.
    let portable = src_engine.export_entry(src_uuid).expect("export");
    assert!(portable.custom_icon_png.is_some(), "carrier ferries PNG");
    assert_eq!(portable.custom_icon_png.as_deref(), Some(TINY_PNG));

    let new_uuid = tgt_engine.import_entry(portable, tgt_root).expect("import");
    let imported = tgt_engine.entry(new_uuid).expect("entry").expect("found");

    // The new entry's icon is a custom ref; the UUID it points at
    // resolves to the same PNG bytes (which is what the dedup
    // guarantees end-to-end, regardless of whether the UUID matches
    // the source's).
    let tgt_icon_uuid = match imported.icon {
        IconRef::Custom(u) => u,
        IconRef::Builtin(idx) => panic!("expected custom icon, got builtin {idx}"),
    };
    let tgt_bytes = tgt_engine
        .custom_icon_bytes(tgt_icon_uuid)
        .expect("icon bytes")
        .expect("present");
    assert_eq!(tgt_bytes, TINY_PNG);
}

#[test]
fn custom_icon_dedupes_when_target_already_has_bytes() {
    let (mut src_engine, src_root, _dir_src) = engine_with_empty_vault();
    let (mut tgt_engine, tgt_root, _dir_tgt) = engine_with_empty_vault();

    // Both engines independently register the same PNG. Their UUIDs
    // for that PNG will differ (uuid_v4 each time), proving that
    // dedup-by-bytes is the only thing keeping the import consistent.
    let src_icon = src_engine.add_custom_icon(TINY_PNG).expect("src icon");
    let tgt_pre_uuid = tgt_engine.add_custom_icon(TINY_PNG).expect("tgt pre icon");

    let src_uuid = create_loaded_entry(
        &mut src_engine,
        src_root,
        IconRef::Custom(Uuid::parse_str(&src_icon).unwrap()),
    );

    let portable = src_engine.export_entry(src_uuid).expect("export");
    let new_uuid = tgt_engine.import_entry(portable, tgt_root).expect("import");
    let imported = tgt_engine.entry(new_uuid).expect("entry").expect("found");

    // Dedup wins: the imported entry's icon UUID matches the
    // pre-existing target row, not the source's.
    let tgt_icon_uuid = match imported.icon {
        IconRef::Custom(u) => u,
        IconRef::Builtin(idx) => panic!("expected custom icon, got builtin {idx}"),
    };
    assert_eq!(
        tgt_icon_uuid.to_string(),
        tgt_pre_uuid,
        "import reused pre-existing target icon UUID"
    );
}

#[test]
fn import_carrier_without_target_group_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let portable = manual_portable("solo", IconRef::Builtin(0));
    let err = engine.import_entry(portable, Uuid::new_v4()).unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound { entity: "group" }
    ));
}

#[test]
fn import_carrier_with_custom_icon_but_no_bytes_errors() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut portable = manual_portable("solo", IconRef::Custom(Uuid::new_v4()));
    portable.custom_icon_png = None; // belt-and-braces — already None
    let err = engine.import_entry(portable, root).unwrap_err();
    assert!(matches!(
        err,
        keys_engine::EngineError::NotFound {
            entity: "custom_icon"
        }
    ));
}

#[test]
fn import_preserves_expires_at() {
    let (mut src_engine, src_root, _dir_src) = engine_with_empty_vault();
    let (mut tgt_engine, tgt_root, _dir_tgt) = engine_with_empty_vault();

    let fields = NewEntryFields {
        title: "expiring".into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        custom_fields: Vec::new(),
        tags: Vec::new(),
    };
    let src_uuid = src_engine.create_entry(src_root, fields).expect("create");
    src_engine
        .update_entry(
            src_uuid,
            keys_engine::EntryUpdate {
                expires_at: Some(Some(1_700_000_000_000)),
                ..Default::default()
            },
        )
        .expect("set expiry");

    let portable = src_engine.export_entry(src_uuid).expect("export");
    let new_uuid = tgt_engine.import_entry(portable, tgt_root).expect("import");
    let imported = tgt_engine.entry(new_uuid).expect("entry").expect("found");
    assert_eq!(imported.expires_at, Some(1_700_000_000_000));
}

/// Build a minimal carrier without going through `export_entry`. Used
/// by error-path tests that don't need a fully loaded source entry.
fn manual_portable(title: &str, icon: IconRef) -> PortableEntry {
    PortableEntry {
        title: title.into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        icon,
        tags: Vec::new(),
        created_at: None,
        modified_at: None,
        accessed_at: None,
        last_used_at: None,
        expires_at: None,
        password: SecretString::from(""),
        protected_fields: Vec::new(),
        custom_fields: Vec::new(),
        attachments: Vec::<PortableAttachment>::new(),
        custom_icon_png: None,
    }
}

/// Touch the unused PNG so a stray edit doesn't accidentally drop the
/// constant.
#[test]
fn other_png_constant_is_defined() {
    assert!(!OTHER_PNG.is_empty());
}
