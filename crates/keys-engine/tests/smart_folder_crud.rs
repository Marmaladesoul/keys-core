//! Integration tests for the smart-folder CRUD surface (task 3.5).
//!
//! Each test opens a fresh `SQLCipher`-backed engine against a temp
//! path, exercises the
//! [`Engine::create_smart_folder`] /
//! [`Engine::list_smart_folders`] /
//! [`Engine::smart_folder`] /
//! [`Engine::update_smart_folder`] /
//! [`Engine::delete_smart_folder`] surface, and asserts on the
//! returned [`SmartFolder`] rows.

use std::sync::Arc;
use std::time::Duration;

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::predicate::Predicate;
use keys_engine::{
    DbKey, Engine, EngineError, KeyProvider, KeyProviderError, SmartFolder, StrengthBucket,
};
use tempfile::TempDir;
use uuid::Uuid;

// ── test wiring ────────────────────────────────────────────────────────

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

struct Fixture {
    _dir: TempDir,
    engine: Engine,
}

fn fresh_engine() -> Fixture {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("vault.sqlcipher");
    let engine =
        Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine");
    Fixture { _dir: dir, engine }
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn create_returns_id_and_populates_row() {
    let mut fx = fresh_engine();
    let pred = Predicate::TagEquals {
        tag: "banking".into(),
    };
    let id = fx
        .engine
        .create_smart_folder("Banking", &pred)
        .expect("create");

    let rows = fx.engine.list_smart_folders().expect("list");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.id, id);
    assert_eq!(row.name, "Banking");
    assert_eq!(row.predicate, pred);
    assert_eq!(row.version, 1);
    assert!(row.evaluable);
    assert!(row.created_at > 0);
    assert_eq!(row.created_at, row.modified_at);
}

#[test]
fn smart_folder_returns_none_for_missing_id() {
    let fx = fresh_engine();
    assert!(fx.engine.smart_folder(999).expect("query").is_none());
}

#[test]
fn smart_folder_returns_row_for_existing_id() {
    let mut fx = fresh_engine();
    let pred = Predicate::Expired;
    let id = fx
        .engine
        .create_smart_folder("Expired", &pred)
        .expect("create");
    let row = fx.engine.smart_folder(id).expect("query").expect("found");
    assert_eq!(row.id, id);
    assert_eq!(row.predicate, pred);
}

#[test]
fn update_modifies_existing_row() {
    let mut fx = fresh_engine();
    let pred1 = Predicate::TagEquals { tag: "old".into() };
    let id = fx
        .engine
        .create_smart_folder("Old name", &pred1)
        .expect("create");

    // Sleep briefly so modified_at can diverge from created_at on
    // platforms where the system clock advances only every ms or so.
    std::thread::sleep(std::time::Duration::from_millis(2));

    let pred2 = Predicate::And {
        predicates: vec![
            Predicate::TagEquals { tag: "new".into() },
            Predicate::Expired,
        ],
    };
    fx.engine
        .update_smart_folder(id, "New name", &pred2)
        .expect("update");

    let row = fx.engine.smart_folder(id).expect("query").expect("found");
    assert_eq!(row.name, "New name");
    assert_eq!(row.predicate, pred2);
    assert!(row.modified_at >= row.created_at);
}

#[test]
fn update_returns_error_for_missing_id() {
    let mut fx = fresh_engine();
    let pred = Predicate::Expired;
    let err = fx
        .engine
        .update_smart_folder(999, "no-such", &pred)
        .expect_err("missing id should error");
    assert!(matches!(err, EngineError::NotFound { entity } if entity == "smart_folder"));
}

#[test]
fn delete_removes_row() {
    let mut fx = fresh_engine();
    let id = fx
        .engine
        .create_smart_folder("Temp", &Predicate::Expired)
        .expect("create");
    assert!(fx.engine.smart_folder(id).expect("query").is_some());

    fx.engine.delete_smart_folder(id).expect("delete");
    assert!(fx.engine.smart_folder(id).expect("query").is_none());
    assert!(fx.engine.list_smart_folders().expect("list").is_empty());
}

#[test]
fn delete_returns_error_for_missing_id() {
    let mut fx = fresh_engine();
    let err = fx
        .engine
        .delete_smart_folder(999)
        .expect_err("missing id should error");
    assert!(matches!(err, EngineError::NotFound { entity } if entity == "smart_folder"));
}

#[test]
fn create_with_unknown_predicate_marks_evaluable_false() {
    let mut fx = fresh_engine();
    // Construct an `Unknown` predicate by deserialising a JSON
    // object with an unrecognised discriminator. (The variant
    // itself isn't ordinarily constructable from outside the
    // crate's tolerant decoder, which is exactly the surface we
    // want to exercise here.)
    let unknown_json = serde_json::json!({ "type": "fancy_future_predicate_v9000", "payload": 42 });
    let pred: Predicate = serde_json::from_value(unknown_json).expect("tolerant decode");
    assert!(matches!(pred, Predicate::Unknown(_)));

    let id = fx
        .engine
        .create_smart_folder("Future", &pred)
        .expect("create");
    let row = fx.engine.smart_folder(id).expect("query").expect("found");
    assert!(!row.evaluable);
    assert_eq!(row.predicate, pred);
}

#[test]
fn stored_predicate_round_trips_through_db() {
    let mut fx = fresh_engine();
    let cases = vec![
        Predicate::And {
            predicates: vec![Predicate::Expired],
        },
        Predicate::Or {
            predicates: vec![Predicate::Duplicates],
        },
        Predicate::Not {
            predicate: Box::new(Predicate::Expired),
        },
        Predicate::TitleContains {
            substring: "foo".into(),
        },
        Predicate::UrlContains {
            substring: "example.com".into(),
        },
        Predicate::UsernameContains {
            substring: "alice".into(),
        },
        Predicate::UrlHostEquals {
            host: "github.com".into(),
        },
        Predicate::TagEquals {
            tag: "banking".into(),
        },
        Predicate::TagHasAny {
            tags: vec!["a".into(), "b".into()],
        },
        Predicate::TagHasAll {
            tags: vec!["x".into(), "y".into()],
        },
        Predicate::ModifiedWithin {
            duration: Duration::from_secs(60),
        },
        Predicate::ModifiedBefore {
            timestamp_ms: 1_700_000_000_000,
        },
        Predicate::Expired,
        Predicate::ExpiringWithin {
            duration: Duration::from_secs(86_400 * 30),
        },
        Predicate::StrengthBelow {
            bucket: StrengthBucket::Reasonable,
        },
        Predicate::EntropyBelow { bits: 40.0 },
        Predicate::Duplicates,
        Predicate::Group {
            uuid: Uuid::from_u128(0xdead_beef_1234_5678_9abc_def0_1234_5678),
        },
    ];
    for (i, pred) in cases.iter().enumerate() {
        let name = format!("case-{i}");
        let id = fx.engine.create_smart_folder(&name, pred).expect("create");
        let row: SmartFolder = fx.engine.smart_folder(id).expect("query").expect("found");
        assert_eq!(&row.predicate, pred, "mismatch on case {i}: {pred:?}");
        assert!(row.evaluable);
    }
}
