//! Smoke test that the query API compiles end-to-end against a real
//! opened engine.
//!
//! Originally guarded the `unimplemented!()` stubs from task 1.5; now
//! that the bodies are real, the file's value is in the *compile*
//! step: it proves the public surface lines up against `Engine::open`,
//! the model types, and `Pagination` the way a frontend will call them.

use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError, Pagination, SearchScope};
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
fn list_entries_on_fresh_engine_returns_empty() {
    // Task 3.1 has landed: `list_entries` no longer panics. A freshly
    // opened engine has no entries, so all-rows pagination returns an
    // empty Vec rather than the previous `unimplemented!()` panic.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key = FixedKey([0x42; 32]);

    let engine = Engine::open(&path, &key, protector(), None).expect("open");

    let rows = engine
        .list_entries(None, Pagination::all())
        .expect("list_entries");
    assert!(rows.is_empty());
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
        let _: Result<_, _> = engine.search("query", SearchScope::AnyField, Pagination::all());
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
