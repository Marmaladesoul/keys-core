//! Integration tests for the smart-folder evaluation surface
//! (task 3.8): [`Engine::smart_folder_entries`],
//! [`Engine::smart_folder_count`], [`Engine::entries_matching`],
//! [`Engine::count_matching`].

use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::predicate::Predicate;
use keys_engine::{
    DbKey, Engine, EngineError, KeyProvider, KeyProviderError, Pagination, StrengthBucket,
    expiring_soon, weak_password,
};
use secrecy::SecretString;

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

fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

/// Force `modified_at` on an entry to a deterministic timestamp so
/// list ordering is testable.
fn set_modified_at(kdbx: &mut Kdbx<Unlocked>, id: keepass_core::model::EntryId, ms: i64) {
    let mut vault = kdbx.vault().clone();
    for entry in walk_entries_mut(&mut vault.root) {
        if entry.id == id {
            entry.times.last_modification_time = Utc.timestamp_millis_opt(ms).single();
        }
    }
    kdbx.replace_vault(vault);
}

fn walk_entries_mut(
    group: &mut keepass_core::model::Group,
) -> Vec<&mut keepass_core::model::Entry> {
    let mut out: Vec<&mut keepass_core::model::Entry> = Vec::new();
    out.extend(group.entries.iter_mut());
    for child in &mut group.groups {
        out.extend(walk_entries_mut(child));
    }
    out
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn smart_folder_entries_runs_predicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let weak = kdbx
        .add_entry(
            root,
            NewEntry::new("weak").password(SecretString::from("a")),
        )
        .expect("add");
    let strong = kdbx
        .add_entry(
            root,
            NewEntry::new("strong")
                .password(SecretString::from("Tr0ub4dor&3-correct-horse-battery!")),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let id = engine
        .create_smart_folder(
            "Weak",
            &Predicate::StrengthBelow {
                bucket: StrengthBucket::Reasonable,
            },
        )
        .expect("create");

    let rows = engine
        .smart_folder_entries(id, Pagination::all())
        .expect("smart_folder_entries");
    let uuids: Vec<_> = rows.iter().map(|r| r.uuid).collect();
    assert!(uuids.contains(&weak.0), "weak should match");
    assert!(!uuids.contains(&strong.0), "strong must not match");
}

#[test]
fn smart_folder_count_matches_entries_len() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    for _ in 0..3 {
        kdbx.add_entry(root, NewEntry::new("w").password(SecretString::from("a")))
            .expect("add");
    }
    kdbx.add_entry(
        root,
        NewEntry::new("s").password(SecretString::from("Tr0ub4dor&3-correct-horse!")),
    )
    .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let id = engine
        .create_smart_folder(
            "Weak",
            &Predicate::StrengthBelow {
                bucket: StrengthBucket::Reasonable,
            },
        )
        .expect("create");

    let rows = engine
        .smart_folder_entries(id, Pagination::all())
        .expect("list");
    let count = engine.smart_folder_count(id).expect("count");
    assert_eq!(count, rows.len() as u64);
}

#[test]
fn smart_folder_entries_returns_not_found_for_bad_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let engine = open_engine(&path);

    let err = engine
        .smart_folder_entries(9_999, Pagination::all())
        .expect_err("should fail");
    assert!(matches!(
        err,
        EngineError::NotFound {
            entity: "smart_folder"
        }
    ));

    let err = engine.smart_folder_count(9_999).expect_err("should fail");
    assert!(matches!(
        err,
        EngineError::NotFound {
            entity: "smart_folder"
        }
    ));
}

#[test]
fn smart_folder_entries_returns_not_evaluable_for_unknown_predicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut engine = open_engine(&path);

    // Craft a predicate that's not evaluable: the `Unknown` catch-all
    // carries arbitrary JSON and `is_evaluable()` returns false, so
    // `create_smart_folder` will persist `evaluable = 0`.
    let unknown = Predicate::Unknown(serde_json::json!({ "type": "future_predicate", "x": 1 }));
    let id = engine
        .create_smart_folder("Future", &unknown)
        .expect("create");

    let err = engine
        .smart_folder_entries(id, Pagination::all())
        .expect_err("should fail");
    assert!(matches!(err, EngineError::NotEvaluable));

    let err = engine.smart_folder_count(id).expect_err("should fail");
    assert!(matches!(err, EngineError::NotEvaluable));
}

#[test]
fn entries_matching_with_builtin_weak_password() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let weak = kdbx
        .add_entry(root, NewEntry::new("w").password(SecretString::from("a")))
        .expect("add");
    let strong = kdbx
        .add_entry(
            root,
            NewEntry::new("s").password(SecretString::from("Tr0ub4dor&3-correct-horse!")),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine
        .entries_matching(&weak_password(), Pagination::all())
        .expect("entries_matching");
    let uuids: Vec<_> = rows.iter().map(|r| r.uuid).collect();
    assert!(uuids.contains(&weak.0));
    assert!(!uuids.contains(&strong.0));

    let count = engine
        .count_matching(&weak_password())
        .expect("count_matching");
    assert_eq!(count, uuids.len() as u64);
}

#[test]
fn entries_matching_with_builtin_expiring_soon() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    // Build entries with various expiries.
    let now_ms: i64 = Utc::now().timestamp_millis();

    let soon = kdbx.add_entry(root, NewEntry::new("soon")).expect("add");
    kdbx.edit_entry(soon, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(Utc.timestamp_millis_opt(now_ms + 3_600_000).unwrap()));
    })
    .expect("expiry");

    let far = kdbx.add_entry(root, NewEntry::new("far")).expect("add");
    kdbx.edit_entry(far, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(
            Utc.timestamp_millis_opt(now_ms + 30 * 86_400_000).unwrap(),
        ));
    })
    .expect("expiry");

    let past = kdbx.add_entry(root, NewEntry::new("past")).expect("add");
    kdbx.edit_entry(past, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(Utc.timestamp_millis_opt(now_ms - 1_000_000).unwrap()));
    })
    .expect("expiry");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine
        .entries_matching(&expiring_soon(), Pagination::all())
        .expect("entries_matching");
    let uuids: Vec<_> = rows.iter().map(|r| r.uuid).collect();
    assert!(uuids.contains(&soon.0), "soon-expiring should match");
    assert!(!uuids.contains(&far.0), "far-future should not match");
    assert!(!uuids.contains(&past.0), "already-expired should not match");
}

#[test]
fn entries_matching_with_complex_predicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    // banking + weak: should match.
    let banking_weak = kdbx
        .add_entry(
            root,
            NewEntry::new("bw")
                .tags(vec!["banking".into()])
                .password(SecretString::from("a")),
        )
        .expect("add");
    // banking + strong: tag matches, strength does not.
    let banking_strong = kdbx
        .add_entry(
            root,
            NewEntry::new("bs")
                .tags(vec!["banking".into()])
                .password(SecretString::from("Tr0ub4dor&3-correct-horse!")),
        )
        .expect("add");
    // not-banking + weak: strength matches, tag does not.
    let other_weak = kdbx
        .add_entry(
            root,
            NewEntry::new("ow")
                .tags(vec!["finance".into()])
                .password(SecretString::from("a")),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let pred = Predicate::And {
        predicates: vec![
            Predicate::TagEquals {
                tag: "banking".into(),
            },
            Predicate::StrengthBelow {
                bucket: StrengthBucket::Strong,
            },
        ],
    };
    let rows = engine
        .entries_matching(&pred, Pagination::all())
        .expect("entries_matching");
    let uuids: Vec<_> = rows.iter().map(|r| r.uuid).collect();
    assert!(uuids.contains(&banking_weak.0));
    assert!(!uuids.contains(&banking_strong.0));
    assert!(!uuids.contains(&other_weak.0));
}

#[test]
fn smart_folder_entries_paginates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let mut ids = Vec::new();
    for i in 0..10 {
        let id = kdbx
            .add_entry(
                root,
                NewEntry::new(format!("w{i}")).password(SecretString::from("a")),
            )
            .expect("add");
        ids.push(id);
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let pred = Predicate::StrengthBelow {
        bucket: StrengthBucket::Reasonable,
    };
    let folder_id = engine.create_smart_folder("Weak", &pred).expect("create");

    let page1 = engine
        .smart_folder_entries(
            folder_id,
            Pagination {
                offset: 0,
                limit: 2,
            },
        )
        .expect("p1");
    let page2 = engine
        .smart_folder_entries(
            folder_id,
            Pagination {
                offset: 2,
                limit: 2,
            },
        )
        .expect("p2");
    let page3 = engine
        .smart_folder_entries(
            folder_id,
            Pagination {
                offset: 4,
                limit: 2,
            },
        )
        .expect("p3");

    assert_eq!(page1.len(), 2);
    assert_eq!(page2.len(), 2);
    assert_eq!(page3.len(), 2);

    // Pages should not overlap.
    let mut seen = std::collections::HashSet::new();
    for r in page1.iter().chain(page2.iter()).chain(page3.iter()) {
        assert!(seen.insert(r.uuid), "duplicate uuid across pages");
    }
}

#[test]
fn smart_folder_entries_ordering_stable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let now_ms: i64 = 1_700_000_000_000;
    let mut entry_ids = Vec::new();
    for i in 0..5 {
        let id = kdbx
            .add_entry(
                root,
                NewEntry::new(format!("e{i}")).password(SecretString::from("a")),
            )
            .expect("add");
        entry_ids.push(id);
    }
    // Stamp distinct modified_at values descending so ordering is
    // deterministic.
    for (i, id) in entry_ids.iter().enumerate() {
        let offset = i64::try_from(i).expect("small loop") * 1000;
        set_modified_at(&mut kdbx, *id, now_ms - offset);
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let pred = Predicate::StrengthBelow {
        bucket: StrengthBucket::Reasonable,
    };
    let id = engine.create_smart_folder("Weak", &pred).expect("create");

    let rows = engine
        .smart_folder_entries(id, Pagination::all())
        .expect("list");

    // Expect rows sorted by modified_at DESC, so first row has the
    // largest modified_at.
    let modifieds: Vec<i64> = rows.iter().map(|r| r.modified_at).collect();
    let mut sorted = modifieds.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(modifieds, sorted, "rows must be sorted modified_at DESC");
}

/// Performance smoke test: 877 entries, weak-password predicate
/// evaluation must complete within 50 ms.
///
/// `#[ignore]` because the bound is environment-sensitive — under
/// `cargo test` debug builds with sanitizers etc. the budget is too
/// tight. Run explicitly via `cargo test --release -- --ignored`
/// when validating the perf goal.
#[test]
#[ignore = "environment-sensitive; run with --release --ignored to validate the perf goal"]
fn smart_folder_perf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    for i in 0..877 {
        let pw = if i % 2 == 0 {
            "a"
        } else {
            "Tr0ub4dor&3-correct-horse!"
        };
        kdbx.add_entry(
            root,
            NewEntry::new(format!("e{i}")).password(SecretString::from(pw)),
        )
        .expect("add");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let pred = weak_password();
    let start = std::time::Instant::now();
    let rows = engine
        .entries_matching(&pred, Pagination::all())
        .expect("entries_matching");
    let elapsed = start.elapsed();
    assert!(!rows.is_empty());
    assert!(
        elapsed < Duration::from_millis(50),
        "evaluation took {elapsed:?}, expected < 50ms"
    );
}
