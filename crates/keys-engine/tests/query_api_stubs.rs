//! Smoke test that the query API stubs compile end-to-end against a
//! real opened engine.
//!
//! Bodies are `unimplemented!("task X.Y")`, so this test is `#[ignore]`d
//! — running it confirms the panic message points at the right task.
//! The value is in the *compile* step: it proves the public surface
//! lines up against `Engine::open`, the model types, and `Pagination`
//! the way a frontend will call them.

use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError, Pagination};
use uuid::Uuid;

#[derive(Debug)]
struct FixedKey([u8; 32]);

impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

#[derive(Debug)]
struct TestProtector([u8; 32]);

impl FieldProtector for TestProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes(self.0))
    }
}

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(TestProtector([0x5a; 32]))
}

#[test]
#[ignore = "stubs panic with unimplemented!('task 3.1'); implementation lands in Phase 3"]
fn list_entries_stub_panics_with_task_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key = FixedKey([0x42; 32]);

    let engine = Engine::open(&path, &key, protector()).expect("open");

    // Should panic with "not implemented: task 3.1".
    let _ = engine.list_entries(None, Pagination::all());

    unreachable!("list_entries stub must panic before returning");
}

#[test]
fn surface_methods_compile_against_real_engine() {
    // Compile-only smoke test: never actually calls the stubs. Confirms
    // the public surface is callable shape-wise from a downstream
    // crate without `unimplemented!()` panicking.
    fn _shapes(engine: &Engine, uuid: Uuid) {
        let _: Result<_, _> = engine.list_entries(None, Pagination::all());
        let _: Result<_, _> = engine.list_entries(
            Some(uuid),
            Pagination {
                offset: 0,
                limit: 50,
            },
        );
        let _: Result<_, _> = engine.entry(uuid);
        let _: Result<_, _> = engine.entry_count(None);
        let _: Result<_, _> = engine.group_tree();
        let _: Result<_, _> = engine.search("query", Pagination::all());
        let _: Result<_, _> = engine.smart_folder_entries(0, Pagination::all());
        let _: Result<_, _> = engine.smart_folder_count(0);
        let _: Result<_, _> = engine.reveal_password(uuid);
        let _: Result<_, _> = engine.reveal_custom_field(uuid, "Token");
        let _: Result<_, _> = engine.reveal_history_field(uuid, 0, "Password");
        let _: Result<_, _> = engine.attachment_bytes(uuid, "att.pdf");
        let _: Result<_, _> = engine.history(uuid);
    }
    let _ = _shapes; // suppress dead-code warnings without running
}
