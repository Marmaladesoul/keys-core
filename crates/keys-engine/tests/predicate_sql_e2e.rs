//! End-to-end test for the predicate-SQL compiler (task 3.6).
//!
//! Ingests a curated KDBX vault into a fresh engine, compiles each
//! predicate variant against the real schema, runs it via
//! `Engine::compiled_predicate_uuids_for_test`, and asserts the
//! returned UUID set matches expectations. Proves the compiled SQL is
//! valid against the schema migration 0001 produces, not just
//! string-equal to the expected template.

use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{HistoryPolicy, NewEntry, NewGroup};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::predicate::Predicate;
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError, StrengthBucket};
use secrecy::SecretString;

// ── test wiring (copied from entry_reads.rs) ───────────────────────────

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
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector()).expect("open engine")
}

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

// ── e2e test ───────────────────────────────────────────────────────────

/// Build a vault with one entry per predicate-variant flavour, then
/// run each compiled predicate against the engine and assert the
/// matching UUID set.
#[test]
#[allow(clippy::too_many_lines)]
fn compiled_sql_executes_against_real_db() {
    // Anchor "now" so time-relative predicates are deterministic.
    let now_ms: i64 = 1_700_000_000_000;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let group_a = kdbx
        .add_group(root, NewGroup::new("A"))
        .expect("add group A");

    // Distinct entries — each surfaces one predicate variant clearly.
    let title_hit = kdbx
        .add_entry(root, NewEntry::new("MyBankingLogin"))
        .expect("add");
    let url_hit = kdbx
        .add_entry(root, NewEntry::new("github").url("https://github.com/foo"))
        .expect("add");
    let username_hit = kdbx
        .add_entry(root, NewEntry::new("u").username("alice@example.com"))
        .expect("add");
    let weak_pw = kdbx
        .add_entry(
            root,
            NewEntry::new("weak").password(SecretString::from("a")),
        )
        .expect("add");
    let strong_pw = kdbx
        .add_entry(
            root,
            NewEntry::new("strong")
                .password(SecretString::from("Tr0ub4dor&3-correct-horse-battery!")),
        )
        .expect("add");
    let tagged_banking = kdbx
        .add_entry(
            root,
            NewEntry::new("tagged").tags(vec!["banking".into(), "finance".into()]),
        )
        .expect("add");
    let tagged_other = kdbx
        .add_entry(
            root,
            NewEntry::new("just-finance").tags(vec!["finance".into()]),
        )
        .expect("add");
    let in_group_a = kdbx
        .add_entry(group_a, NewEntry::new("in-a"))
        .expect("add in A");
    let expired = kdbx.add_entry(root, NewEntry::new("expired")).expect("add");
    let expiring_soon = kdbx.add_entry(root, NewEntry::new("soon")).expect("add");

    // Two duplicate-password entries so `Duplicates` picks them up.
    let dup1 = kdbx
        .add_entry(
            root,
            NewEntry::new("dup1").password(SecretString::from("samePass!")),
        )
        .expect("add");
    let dup2 = kdbx
        .add_entry(
            root,
            NewEntry::new("dup2").password(SecretString::from("samePass!")),
        )
        .expect("add");

    // Stamp deterministic modified_at on a couple of entries.
    set_modified_at(&mut kdbx, title_hit, now_ms - 1_000); // recent
    set_modified_at(&mut kdbx, url_hit, now_ms - 10_000_000_000); // old

    // Expired: expiry in the past.
    kdbx.edit_entry(expired, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(Utc.timestamp_millis_opt(now_ms - 1_000_000).unwrap()));
    })
    .expect("set expiry past");
    // Expiring within 1 day: expiry in [now, now + 1d].
    kdbx.edit_entry(expiring_soon, HistoryPolicy::NoSnapshot, |e| {
        e.set_expiry(Some(Utc.timestamp_millis_opt(now_ms + 3_600_000).unwrap()));
    })
    .expect("set expiry soon");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    // ── Per-variant assertions ────────────────────────────────────

    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::TitleContains {
                substring: "Banking".into(),
            },
            now_ms,
        )
        .expect("title");
    assert_eq!(got, vec![title_hit.0]);

    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::UrlContains {
                substring: "github".into(),
            },
            now_ms,
        )
        .expect("url contains");
    assert_eq!(got, vec![url_hit.0]);

    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::UsernameContains {
                substring: "alice".into(),
            },
            now_ms,
        )
        .expect("username");
    assert_eq!(got, vec![username_hit.0]);

    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::UrlHostEquals {
                host: "github.com".into(),
            },
            now_ms,
        )
        .expect("url host");
    assert_eq!(got, vec![url_hit.0]);

    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::TagEquals {
                tag: "banking".into(),
            },
            now_ms,
        )
        .expect("tag equals");
    assert_eq!(got, vec![tagged_banking.0]);

    let mut got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::TagHasAny {
                tags: vec!["banking".into(), "finance".into()],
            },
            now_ms,
        )
        .expect("tag has any");
    got.sort();
    let mut expected = vec![tagged_banking.0, tagged_other.0];
    expected.sort();
    assert_eq!(got, expected);

    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::TagHasAll {
                tags: vec!["banking".into(), "finance".into()],
            },
            now_ms,
        )
        .expect("tag has all");
    assert_eq!(got, vec![tagged_banking.0]);

    // ModifiedWithin: title_hit was stamped at now - 1s, url_hit at
    // now - 10_000_000s. A 60s window picks only title_hit (most
    // freshly-ingested entries also stamp `now`-ish modified_at, so
    // we use modified_before below for a tighter check).
    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::ModifiedBefore {
                timestamp_ms: now_ms - 5_000_000_000,
            },
            now_ms,
        )
        .expect("modified_before");
    assert_eq!(got, vec![url_hit.0]);

    // ModifiedWithin: 2s window from now_ms picks title_hit only.
    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::And {
                predicates: vec![
                    Predicate::ModifiedWithin {
                        duration: Duration::from_secs(2),
                    },
                    // Restrict to title_hit's known title so freshly
                    // ingested entries with modified_at ≈ now don't
                    // contaminate the result.
                    Predicate::TitleContains {
                        substring: "MyBankingLogin".into(),
                    },
                ],
            },
            now_ms,
        )
        .expect("modified_within");
    assert_eq!(got, vec![title_hit.0]);

    let got = engine
        .compiled_predicate_uuids_for_test(&Predicate::Expired, now_ms)
        .expect("expired");
    assert_eq!(got, vec![expired.0]);

    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::ExpiringWithin {
                duration: Duration::from_secs(86_400),
            },
            now_ms,
        )
        .expect("expiring within");
    assert_eq!(got, vec![expiring_soon.0]);

    // StrengthBelow: anything below Reasonable picks the single-char
    // password. Strong password should not appear.
    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::StrengthBelow {
                bucket: StrengthBucket::Reasonable,
            },
            now_ms,
        )
        .expect("strength below");
    assert!(got.contains(&weak_pw.0), "weak should match");
    assert!(!got.contains(&strong_pw.0), "strong must not match");

    // EntropyBelow: arbitrary high bar — picks every entry with a
    // computed entropy (any entry that has a password).
    let got = engine
        .compiled_predicate_uuids_for_test(&Predicate::EntropyBelow { bits: 1_000.0 }, now_ms)
        .expect("entropy below");
    assert!(got.contains(&weak_pw.0));

    let mut got = engine
        .compiled_predicate_uuids_for_test(&Predicate::Duplicates, now_ms)
        .expect("duplicates");
    got.sort();
    let mut expected = vec![dup1.0, dup2.0];
    expected.sort();
    assert_eq!(got, expected);

    let got = engine
        .compiled_predicate_uuids_for_test(&Predicate::Group { uuid: group_a.0 }, now_ms)
        .expect("group");
    assert_eq!(got, vec![in_group_a.0]);

    // Compound: NOT(TagEquals("banking"))  AND  Group(root).
    // Must include url_hit, exclude tagged_banking and in_group_a.
    let got = engine
        .compiled_predicate_uuids_for_test(
            &Predicate::And {
                predicates: vec![
                    Predicate::Not {
                        predicate: Box::new(Predicate::TagEquals {
                            tag: "banking".into(),
                        }),
                    },
                    Predicate::Group { uuid: root.0 },
                ],
            },
            now_ms,
        )
        .expect("compound");
    assert!(got.contains(&url_hit.0));
    assert!(!got.contains(&tagged_banking.0));
    assert!(!got.contains(&in_group_a.0));

    // Avoid `unused` warnings on test-only locals.
    let _ = (dup1, dup2, username_hit);
}
