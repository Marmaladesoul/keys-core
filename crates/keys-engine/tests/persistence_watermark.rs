//! Integration tests for the persistence watermark (migration 0012) —
//! [`Engine::persistence_state`] and the "does the KDBX still owe a
//! write?" truth it answers below the seam.
//!
//! The watermark's contract: every projected-content mutation advances
//! `mutation_seq` inside the mutating transaction (trigger-maintained);
//! every mirror↔disk correspondence point — save, from-file ingest
//! (settled inside its own transaction), rebuild — advances
//! `persisted_seq`. A from-file ingest over a dirty mirror is refused. Dirty = `mutation_seq > persisted_seq`,
//! and BOTH values persist in the mirror, so an unsaved mutation reads
//! back dirty across close + reopen (the crash-recovery signal).
//!
//! The trigger-coverage census (which tables bump, which must not)
//! lives next to the migration in `migrations.rs` unit tests; these
//! tests pin the behavioural contract.

use std::path::Path;
use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, IconRef, KeyProvider, KeyProviderError, NewEntryFields, NewGroupFields,
};
use secrecy::SecretString;

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
    Kdbx::create_empty_v4_with_protector(&composite, "watermark-test", Some(protector()))
        .expect("create")
}

fn open_engine(path: &Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

fn new_entry_fields(title: &str) -> NewEntryFields {
    NewEntryFields {
        title: title.to_string(),
        username: "user".to_string(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("entry-pw"),
        icon: IconRef::Builtin(0),
        custom_fields: Vec::new(),
        tags: Vec::new(),
    }
}

fn new_group_fields(name: &str) -> NewGroupFields {
    NewGroupFields {
        name: name.to_string(),
        notes: String::new(),
        icon: IconRef::Builtin(48),
    }
}

/// Open an engine over a freshly-ingested vault with the watermark
/// settled the way a frontend leaves it after unlock (ingest + record
/// signature). Returns the engine, the root group uuid, the kdbx
/// handle, and the tempdir (kept alive).
fn settled_engine() -> (Engine, uuid::Uuid, Kdbx<Unlocked>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id.0;
    std::fs::write(&kdbx_path, kdbx.save_to_bytes().expect("bytes")).expect("seed kdbx");

    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .record_kdbx_state_signature(&kdbx_path)
        .expect("record signature");
    (engine, root, kdbx, dir)
}

#[test]
fn fresh_mirror_starts_settled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = open_engine(&dir.path().join("keys.db"));

    let st = engine.persistence_state().expect("state");
    assert_eq!(st.mutation_seq, 0);
    assert_eq!(st.persisted_seq, 0);
    assert!(!st.is_dirty(), "an empty mirror owes nothing");
}

#[test]
fn ingest_plus_signature_settles() {
    let (engine, _root, _kdbx, _dir) = settled_engine();

    let st = engine.persistence_state().expect("state");
    assert!(
        !st.is_dirty(),
        "post-ingest the mirror corresponds to disk; got {st:?}"
    );
    // Ingest writes rows, so the census actually ran (the counter is
    // live, not stuck at zero).
    assert!(st.mutation_seq > 0, "ingest row writes must have bumped");
}

#[test]
fn mutations_dirty_the_watermark() {
    let (mut engine, root, _kdbx, _dir) = settled_engine();

    // Entry create — entry + protected-slot rows.
    engine
        .create_entry(root, new_entry_fields("dirty-me"))
        .expect("create entry");
    let st = engine.persistence_state().expect("state");
    assert!(st.is_dirty(), "entry create must owe a write; got {st:?}");
    let after_entry = st.mutation_seq;

    // Group create.
    engine
        .create_group(root, new_group_fields("subgroup"))
        .expect("create group");
    let st = engine.persistence_state().expect("state");
    assert!(
        st.mutation_seq > after_entry,
        "group create must advance the counter"
    );

    // Meta scalar — lives in the `setting` table under a `meta.%` key;
    // proves the conditional setting-table trigger.
    engine
        .set_recycle_bin(false, None)
        .expect("set recycle bin");
    let after_group = st.mutation_seq;
    let st = engine.persistence_state().expect("state");
    assert!(
        st.mutation_seq > after_group,
        "meta scalar write must advance the counter (setting-table meta.% trigger)"
    );
}

#[test]
fn unsaved_mutation_reads_back_dirty_after_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id.0;
    std::fs::write(&kdbx_path, kdbx.save_to_bytes().expect("bytes")).expect("seed kdbx");

    {
        let mut engine = open_engine(&db_path);
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine
            .record_kdbx_state_signature(&kdbx_path)
            .expect("record signature");
        engine
            .create_entry(root, new_entry_fields("crash-me"))
            .expect("create entry");
        // Dropped without save — the "process died before the flush"
        // shape.
    }

    let engine = open_engine(&db_path);
    let st = engine.persistence_state().expect("state");
    assert!(
        st.is_dirty(),
        "the owed write must survive close + reopen; got {st:?}"
    );
}

#[test]
fn ingest_alone_settles_the_watermark_and_re_ingests_idempotently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut engine = open_engine(&dir.path().join("keys.db"));
    let kdbx = fresh_kdbx();

    // No signature record: the ingest itself is the correspondence point,
    // settled inside its own transaction.
    engine.ingest_from_kdbx(&kdbx).expect("first ingest");
    let st = engine.persistence_state().expect("state");
    assert!(!st.is_dirty(), "a from-file ingest must settle; got {st:?}");
    assert!(engine.kdbx_state_signature().expect("sig").is_none());

    let count = engine.entry_count(None).expect("count");
    engine
        .ingest_from_kdbx(&kdbx)
        .expect("re-ingest of the same vault");
    assert_eq!(engine.entry_count(None).expect("count"), count);
    assert!(!engine.persistence_state().expect("state").is_dirty());
}

#[test]
fn ingest_refuses_a_dirty_mirror_and_touches_nothing() {
    let (mut engine, root, kdbx, _dir) = settled_engine();

    engine
        .create_entry(root, new_entry_fields("unsaved"))
        .expect("create entry");
    let before = engine.persistence_state().expect("state");
    assert!(before.is_dirty());
    let count_before = engine.entry_count(None).expect("count");

    // The file on hand predates the mutation — exactly the stale
    // content an unguarded ingest would replace the mirror with.
    let err = engine
        .ingest_from_kdbx(&kdbx)
        .expect_err("ingest over a dirty mirror must be refused");
    assert!(
        matches!(
            err,
            keys_engine::EngineError::MirrorOwesWrite { mutation_seq, persisted_seq }
                if mutation_seq == before.mutation_seq && persisted_seq == before.persisted_seq
        ),
        "expected MirrorOwesWrite carrying the watermark, got {err:?}"
    );

    // Refusal is all-or-nothing: content and watermark untouched.
    assert_eq!(engine.entry_count(None).expect("count"), count_before);
    assert_eq!(engine.persistence_state().expect("state"), before);
}

#[test]
fn ingest_proceeds_once_the_owed_write_is_saved() {
    let (mut engine, root, mut kdbx, dir) = settled_engine();
    let kdbx_path = dir.path().join("vault.kdbx");

    engine
        .create_entry(root, new_entry_fields("saved-then-reingested"))
        .expect("create entry");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save");
    let count_saved = engine.entry_count(None).expect("count");

    // Clean mirror → the guard steps aside; re-ingesting the file just
    // written loses nothing.
    let saved = Kdbx::open(&kdbx_path)
        .expect("open saved kdbx")
        .read_header()
        .expect("header")
        .unlock_with_protector(&CompositeKey::from_password(b"pw"), Some(protector()))
        .expect("unlock saved kdbx");
    engine.ingest_from_kdbx(&saved).expect("clean re-ingest");
    assert_eq!(engine.entry_count(None).expect("count"), count_saved);
}

#[test]
fn save_settles_the_watermark() {
    let (mut engine, root, mut kdbx, dir) = settled_engine();
    let kdbx_path = dir.path().join("vault.kdbx");

    engine
        .create_entry(root, new_entry_fields("save-me"))
        .expect("create entry");
    assert!(engine.persistence_state().expect("state").is_dirty());

    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save");

    let st = engine.persistence_state().expect("state");
    assert!(!st.is_dirty(), "save must settle the watermark; got {st:?}");
}

#[test]
fn save_time_blob_gc_does_not_redirty() {
    let (mut engine, root, mut kdbx, dir) = settled_engine();
    let kdbx_path = dir.path().join("vault.kdbx");

    let entry = engine
        .create_entry(root, new_entry_fields("with-attachment"))
        .expect("create entry");
    engine
        .attach_file(entry, "note.txt", b"attachment bytes".to_vec())
        .expect("attach");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("first save");

    // Orphan the blob, then save again: THIS save's GC sweep deletes
    // the now-unreferenced pool row. Pool deletes must not bump, or
    // every GC-ing save would re-dirty the mirror it just persisted —
    // a save loop.
    engine
        .remove_attachment(entry, "note.txt")
        .expect("remove attachment");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("second save");

    let st = engine.persistence_state().expect("state");
    assert!(
        !st.is_dirty(),
        "a save whose GC swept a blob must still settle; got {st:?}"
    );
}
