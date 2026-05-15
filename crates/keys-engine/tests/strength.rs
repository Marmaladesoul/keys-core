//! Integration tests for the strength-estimation surface (task 2.2).
//!
//! The strength computation itself is pure and doesn't touch the
//! engine; the integration coverage here is limited to confirming that
//! [`Engine::strength`] is a thin alias for the free
//! [`keys_engine::strength`] function, so that the engine-handle
//! convenience method can't silently drift from the canonical
//! implementation.

use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};

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
fn engine_strength_method_matches_module_strength() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let engine = Engine::open(&path, &FixedKey([0x88; 32]), protector()).expect("open");

    for input in [
        "",
        "abc",
        "Password1",
        "Tr0ub4dor&3",
        "correcthorsebatterystaple",
    ] {
        let via_engine = engine.strength(input);
        let via_module = keys_engine::strength(input);
        assert_eq!(
            via_engine, via_module,
            "Engine::strength must mirror keys_engine::strength for {input:?}",
        );
    }
}
