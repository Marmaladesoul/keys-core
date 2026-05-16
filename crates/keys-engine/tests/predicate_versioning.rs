//! Integration tests for the predicate versioning discipline (task 3.9).
//!
//! These tests exercise the four rules from
//! `docs/predicate-versioning.md` end-to-end. Unit-level round-trip and
//! `is_evaluable` coverage lives next to the implementation in
//! `src/predicate.rs`; this file focuses on the cross-version
//! tolerance guarantees and the `SmartFolder` DB envelope.
//!
//! Coverage map:
//!
//! - Rule 1 (tagged unions): covered indirectly by every round-trip
//!   test.
//! - Rule 2 (additive-only producers): `old_decoder_ignores_new_field_*`
//!   tests + `no_deny_unknown_fields_in_source` source-level audit.
//! - Rule 3 (tolerant decoders): `old_decoder_handles_new_predicate_type`,
//!   `is_evaluable_propagates_unknown`, `unknown_predicate_round_trips_through_db`.
//! - Rule 4 (top-level version): `new_folder_defaults_to_version_one` +
//!   `evaluable_column_matches_predicate_evaluable`.

use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::predicate::Predicate;
use keys_engine::predicate_sql::{self, CompileError};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use tempfile::TempDir;

// ── test wiring (mirrors tests/smart_folder_crud.rs) ───────────────────

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
    let engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector()).expect("open engine");
    Fixture { _dir: dir, engine }
}

// ── Rule 2 — additive-only producers ───────────────────────────────────

/// A producer running a newer schema emits an extra field on an
/// existing predicate type. The current decoder must accept the JSON
/// and silently ignore the future field — that is the wire-level
/// promise of Rule 2.
#[test]
fn old_decoder_ignores_new_field_on_existing_type() {
    let raw = serde_json::json!({
        "type": "title_contains",
        "substring": "banking",
        "future_match_mode": "exact"
    });
    let decoded: Predicate = serde_json::from_value(raw).expect("tolerant decode");
    assert_eq!(
        decoded,
        Predicate::TitleContains {
            substring: "banking".into()
        }
    );
}

/// Same property for a nested predicate inside an `And`.
#[test]
fn old_decoder_ignores_new_field_inside_nested_predicate() {
    let raw = serde_json::json!({
        "type": "and",
        "predicates": [
            { "type": "tag_equals", "tag": "banking", "future_case_mode": "ci" },
            { "type": "expired" }
        ]
    });
    let decoded: Predicate = serde_json::from_value(raw).expect("tolerant decode");
    let Predicate::And { predicates } = decoded else {
        panic!("expected And");
    };
    assert_eq!(predicates.len(), 2);
    assert_eq!(
        predicates[0],
        Predicate::TagEquals {
            tag: "banking".into()
        }
    );
    assert_eq!(predicates[1], Predicate::Expired);
}

/// Source-level audit of Rule 2: `#[serde(deny_unknown_fields)]` on
/// the predicate type would silently turn every "additive producer"
/// scenario into a hard decode error, breaking the wire promise.
/// This test guards against re-introducing it.
#[test]
fn no_deny_unknown_fields_in_predicate_source() {
    let src = include_str!("../src/predicate.rs");
    assert!(
        !src.contains("deny_unknown_fields"),
        "predicate.rs must not use deny_unknown_fields — it would violate \
         versioning Rule 2 (additive-only producers). See \
         docs/predicate-versioning.md."
    );
}

// ── Rule 3 — tolerant decoders ─────────────────────────────────────────

#[test]
fn old_decoder_handles_new_predicate_type() {
    let raw = serde_json::json!({ "type": "fancy_new_predicate", "x": 42 });
    let decoded: Predicate = serde_json::from_value(raw.clone()).expect("tolerant decode");
    assert_eq!(decoded, Predicate::Unknown(raw));
}

#[test]
fn is_evaluable_propagates_unknown() {
    let p = Predicate::And {
        predicates: vec![
            Predicate::TitleContains {
                substring: "banking".into(),
            },
            Predicate::Unknown(serde_json::json!({"type": "future_v2"})),
        ],
    };
    assert!(!p.is_evaluable());
}

/// Compiler refuses non-evaluable predicates rather than producing
/// nonsense SQL.
#[test]
fn compile_refuses_unknown_predicate() {
    let p = Predicate::Unknown(serde_json::json!({"type": "future_v2"}));
    let err = predicate_sql::compile(&p, 0).expect_err("compile must refuse");
    assert_eq!(err, CompileError::NotEvaluable);
}

// ── Rule 3 + Rule 4 — DB round-trip ────────────────────────────────────

#[test]
fn unknown_predicate_round_trips_through_db() {
    let mut fx = fresh_engine();

    let raw = serde_json::json!({
        "type": "fancy_new_predicate",
        "extra": "data",
        "nested": { "deep": [1, 2, 3] }
    });
    let unknown = Predicate::Unknown(raw.clone());

    let id = fx
        .engine
        .create_smart_folder("future folder", &unknown)
        .expect("create");

    let fetched = fx
        .engine
        .smart_folder(id)
        .expect("query")
        .expect("row exists");

    assert_eq!(fetched.predicate, unknown);
    assert!(
        !fetched.evaluable,
        "evaluable column must be false for Unknown predicate"
    );

    // Re-serialise the round-tripped predicate; the original JSON
    // payload must survive verbatim (Rule 3: preserve raw JSON).
    let re_emitted = serde_json::to_value(&fetched.predicate).expect("serialise");
    assert_eq!(re_emitted, raw);
}

#[test]
fn evaluable_column_matches_predicate_evaluable() {
    let mut fx = fresh_engine();

    // Evaluable predicate.
    let good = Predicate::TitleContains {
        substring: "banking".into(),
    };
    let good_id = fx
        .engine
        .create_smart_folder("good", &good)
        .expect("create good");
    let good_row = fx
        .engine
        .smart_folder(good_id)
        .expect("query good")
        .expect("good exists");
    assert_eq!(good_row.evaluable, good.is_evaluable());
    assert!(good_row.evaluable);

    // Non-evaluable predicate.
    let bad = Predicate::Or {
        predicates: vec![
            Predicate::Expired,
            Predicate::Unknown(serde_json::json!({"type": "future"})),
        ],
    };
    let bad_id = fx
        .engine
        .create_smart_folder("bad", &bad)
        .expect("create bad");
    let bad_row = fx
        .engine
        .smart_folder(bad_id)
        .expect("query bad")
        .expect("bad exists");
    assert_eq!(bad_row.evaluable, bad.is_evaluable());
    assert!(!bad_row.evaluable);
}

// ── Rule 4 — version column ────────────────────────────────────────────

#[test]
fn new_folder_defaults_to_version_one() {
    let mut fx = fresh_engine();
    let p = Predicate::Expired;
    let id = fx
        .engine
        .create_smart_folder("v1 folder", &p)
        .expect("create");
    let row = fx.engine.smart_folder(id).expect("query").expect("exists");
    assert_eq!(row.version, 1);
}

// ── Empty And/Or behaviour: round-trips but won't compile ──────────────

/// `And { predicates: [] }` is a structurally valid, *known* predicate
/// — `is_evaluable` returns `true` for it. The compiler is where it
/// gets rejected, via `CompileError::EmptyAndOr`. Documenting the
/// split so future readers don't try to "fix" `is_evaluable`.
#[test]
fn empty_and_round_trips_but_fails_compile() {
    let mut fx = fresh_engine();
    let p = Predicate::And { predicates: vec![] };

    // Round-trips through JSON.
    let json = serde_json::to_string(&p).expect("ser");
    let back: Predicate = serde_json::from_str(&json).expect("de");
    assert_eq!(back, p);

    // `is_evaluable` says yes — the structure is well-known.
    assert!(p.is_evaluable());

    // Folder write succeeds and is marked evaluable.
    let id = fx
        .engine
        .create_smart_folder("empty and", &p)
        .expect("create");
    let row = fx.engine.smart_folder(id).expect("query").expect("exists");
    assert!(row.evaluable);

    // But the SQL compiler refuses — empty And/Or is a no-op the
    // compiler isn't willing to translate.
    let err = predicate_sql::compile(&p, 0).expect_err("compile must refuse");
    assert_eq!(err, CompileError::EmptyAndOr);
}
