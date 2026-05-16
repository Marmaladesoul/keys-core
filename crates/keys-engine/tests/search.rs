//! Integration tests for [`Engine::search`] (task 3.3).
//!
//! Builds in-memory KDBX vaults, ingests them, then exercises the
//! FTS5-backed search surface plus the tag-substring fallback.

use std::sync::Arc;
use std::time::Duration;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewEntry;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError, Pagination};
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

fn engine_with<F>(setup: F) -> (Engine, tempfile::TempDir)
where
    F: FnOnce(&mut Kdbx<Unlocked>),
{
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    setup(&mut kdbx);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, dir)
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn search_empty_query_returns_empty() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking")).expect("add");
    });

    let rows = engine.search("", Pagination::all()).expect("search");
    assert!(rows.is_empty());
    // Whitespace-only is also empty.
    let rows = engine.search("   ", Pagination::all()).expect("search ws");
    assert!(rows.is_empty());
}

#[test]
fn search_matches_title() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking site"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("other thing"))
            .expect("add");
    });

    let rows = engine.search("banking", Pagination::all()).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "banking site");
}

#[test]
fn search_matches_url() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(
            root,
            NewEntry::new("login").url("https://login.example.com/path"),
        )
        .expect("add");
        kdbx.add_entry(root, NewEntry::new("other")).expect("add");
    });

    let rows = engine.search("example", Pagination::all()).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "login");
}

#[test]
fn search_matches_notes() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("with notes").notes("my work email"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("plain")).expect("add");
    });

    let rows = engine.search("email", Pagination::all()).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "with notes");
}

#[test]
fn search_is_case_insensitive() {
    // unicode61 tokenizer folds case by default.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("Banking")).expect("add");
    });

    let rows = engine.search("banking", Pagination::all()).expect("search");
    assert_eq!(rows.len(), 1);
    let rows = engine.search("BANKING", Pagination::all()).expect("search");
    assert_eq!(rows.len(), 1);
}

#[test]
fn search_ranks_better_matches_first() {
    // Both entries contain "banking", but the second has it three times
    // — bm25 should rank it higher (lower score).
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking site"))
            .expect("add a");
        kdbx.add_entry(
            root,
            NewEntry::new("my banking site for everything banking").notes("banking notes here"),
        )
        .expect("add b");
    });

    let rows = engine.search("banking", Pagination::all()).expect("search");
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].title, "my banking site for everything banking",
        "denser match should rank first",
    );
    assert_eq!(rows[1].title, "banking site");
}

#[test]
fn search_handles_special_characters() {
    // @ is not an FTS5 syntax character; unicode61 treats it as a
    // token separator, so "user@example" tokenises to "user" and
    // "example". Either token-match suffices. The point of the test
    // is that we don't crash on user-supplied punctuation.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(
            root,
            NewEntry::new("acct")
                .username("alice")
                .url("https://example.com"),
        )
        .expect("add");
    });

    // The point of the test is that we don't crash on punctuation.
    // `user@example` gets quoted into a phrase, which FTS5 tokenises
    // as the sequence `user example` — that does not appear in any
    // indexed column here, so a 0-row result is expected. The
    // important thing is the call succeeds.
    let _ = engine
        .search("user@example", Pagination::all())
        .expect("search must not raise FTS5 syntax error");

    // Other FTS5-special chars: ensure these don't error.
    for q in &[
        "a:b",
        "(paren)",
        "star*",
        "\"quoted\"",
        "^caret",
        "a-b",
        "+plus",
    ] {
        let _ = engine
            .search(q, Pagination::all())
            .expect("no syntax error");
    }
}

#[test]
fn search_paginates() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        for i in 0..5 {
            kdbx.add_entry(root, NewEntry::new(format!("banking {i}")))
                .expect("add");
        }
    });

    let p1 = engine
        .search(
            "banking",
            Pagination {
                offset: 0,
                limit: 2,
            },
        )
        .expect("p1");
    let p2 = engine
        .search(
            "banking",
            Pagination {
                offset: 2,
                limit: 2,
            },
        )
        .expect("p2");
    let p3 = engine
        .search(
            "banking",
            Pagination {
                offset: 4,
                limit: 2,
            },
        )
        .expect("p3");
    assert_eq!(p1.len(), 2);
    assert_eq!(p2.len(), 2);
    assert_eq!(p3.len(), 1);

    let mut all_uuids: Vec<_> = p1
        .iter()
        .chain(p2.iter())
        .chain(p3.iter())
        .map(|e| e.uuid)
        .collect();
    all_uuids.sort();
    all_uuids.dedup();
    assert_eq!(all_uuids.len(), 5, "no overlap, full coverage");
}

#[test]
fn search_matches_tag() {
    // Tag-fallback: an entry whose title/username/url/notes don't
    // contain "banking" but whose tag does should still match.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("acme").tags(vec!["banking".into()]))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("other")).expect("add");
    });

    let rows = engine.search("banking", Pagination::all()).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "acme");
}

#[test]
fn search_tag_fallback_ranks_after_fts_hits() {
    // FTS hit on title and tag-only hit on a separate entry — FTS
    // hit must come first, regardless of insertion order.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(
            root,
            NewEntry::new("zzz tagged only").tags(vec!["banking".into()]),
        )
        .expect("add tag-only");
        kdbx.add_entry(root, NewEntry::new("aaa banking in title"))
            .expect("add fts");
    });

    let rows = engine.search("banking", Pagination::all()).expect("search");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].title, "aaa banking in title");
    assert_eq!(rows[1].title, "zzz tagged only");
}

#[test]
fn search_returns_empty_for_no_matches() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking")).expect("add");
    });

    let rows = engine
        .search("nonexistentterm", Pagination::all())
        .expect("search");
    assert!(rows.is_empty());
}

#[test]
#[ignore = "perf benchmark — run with --ignored to confirm <50ms search across 877 entries"]
fn search_perf_877() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    for i in 0..877 {
        kdbx.add_entry(
            root,
            NewEntry::new(format!("entry {i}"))
                .username(format!("user{i}"))
                .url(format!("https://host{i}.example.com"))
                .notes(format!("notes for entry number {i} — banking site"))
                .password(SecretString::from(format!("pw-{i}-{}", "x".repeat(16)))),
        )
        .expect("add");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let start = std::time::Instant::now();
    let rows = engine.search("banking", Pagination::all()).expect("search");
    let elapsed = start.elapsed();
    eprintln!("877-entry search took {elapsed:?}, {} hits", rows.len());
    assert_eq!(rows.len(), 877);
    assert!(
        elapsed < Duration::from_millis(50),
        "877-entry search must complete in <50ms, took {elapsed:?}",
    );
}
