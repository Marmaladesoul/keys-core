//! Integration tests for [`Engine::search`].
//!
//! Builds in-memory KDBX vaults, ingests them, then exercises the
//! LIKE-based substring search across the three [`SearchScope`]
//! variants.

use std::sync::Arc;
use std::time::Duration;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewEntry;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, KeyProvider, KeyProviderError, Pagination, RecycleBinFilter, SearchScope,
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

fn titles(rows: &[keys_engine::EntrySummary]) -> Vec<&str> {
    rows.iter().map(|r| r.title.as_str()).collect()
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn search_empty_query_returns_empty() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking")).expect("add");
    });

    let rows = engine
        .search(
            "",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert!(rows.is_empty());
    let rows = engine
        .search(
            "   ",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search ws");
    assert!(rows.is_empty());
}

#[test]
fn search_substring_matches_mid_word() {
    // The headline reason this slice exists: FTS5 only matched at
    // word starts, so `a` did not find "Marmalade". Substring search
    // does.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("aaaa")).expect("add");
        kdbx.add_entry(root, NewEntry::new("Marmalade"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("VicServices").notes("admin portal"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("Getting Started"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("zzz")).expect("add");
    });

    let rows = engine
        .search(
            "a",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    let t = titles(&rows);
    assert!(t.contains(&"aaaa"));
    assert!(t.contains(&"Marmalade"));
    assert!(t.contains(&"VicServices"));
    assert!(t.contains(&"Getting Started"));
    assert!(!t.contains(&"zzz"), "got {t:?}");
}

#[test]
fn search_matches_mid_word_token() {
    // `manag` should find entries titled "Management" — a prefix that
    // FTS5's whole-token matcher would miss.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("Account Management"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("Management Console"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("unrelated"))
            .expect("add");
    });

    let rows = engine
        .search(
            "manag",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    let t = titles(&rows);
    assert_eq!(t.len(), 2);
    assert!(t.contains(&"Account Management"));
    assert!(t.contains(&"Management Console"));
}

#[test]
fn search_is_case_insensitive() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("Banking")).expect("add");
    });

    for q in &["banking", "BANKING", "BaNkInG"] {
        let rows = engine
            .search(
                q,
                SearchScope::AnyField,
                RecycleBinFilter::ExcludeRecycled,
                Pagination::all(),
            )
            .expect("search");
        assert_eq!(rows.len(), 1, "case-insensitive miss for {q}");
    }
}

#[test]
fn search_multi_token_ands_with_field_or() {
    // Both tokens must appear, but each token may appear in a
    // different field: `one two` matches "Tone and Atwog" because
    // both substrings exist somewhere in the in-scope fields.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("Tone and Atwog"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("only one"))
            .expect("add only-one");
        kdbx.add_entry(root, NewEntry::new("only two"))
            .expect("add only-two");
    });

    let rows = engine
        .search(
            "one two",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    let t = titles(&rows);
    assert_eq!(t, vec!["Tone and Atwog"], "got {t:?}");
}

#[test]
fn search_anyfield_spans_multiple_fields() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(
            root,
            NewEntry::new("title-hit").notes("matching is in notes"),
        )
        .expect("add notes");
        kdbx.add_entry(
            root,
            NewEntry::new("url-hit").url("https://acme.example.com"),
        )
        .expect("add url");
        kdbx.add_entry(root, NewEntry::new("u-hit").username("alice"))
            .expect("add username");
    });

    // Notes
    let rows = engine
        .search(
            "matching",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert_eq!(titles(&rows), vec!["title-hit"]);
    // URL
    let rows = engine
        .search(
            "acme",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert_eq!(titles(&rows), vec!["url-hit"]);
    // Username
    let rows = engine
        .search(
            "alice",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert_eq!(titles(&rows), vec!["u-hit"]);
}

#[test]
fn search_anyfield_matches_tag() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("acme").tags(vec!["banking".into()]))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("other")).expect("add");
    });

    let rows = engine
        .search(
            "banking",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert_eq!(titles(&rows), vec!["acme"]);
}

#[test]
fn search_title_only_excludes_other_fields() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(
            root,
            NewEntry::new("plain").notes("the word banking appears here"),
        )
        .expect("add");
        kdbx.add_entry(root, NewEntry::new("Banking site"))
            .expect("add");
    });

    let rows = engine
        .search(
            "banking",
            SearchScope::TitleOnly,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert_eq!(titles(&rows), vec!["Banking site"]);
}

#[test]
fn search_notes_only_excludes_other_fields() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking")).expect("add");
        kdbx.add_entry(
            root,
            NewEntry::new("plain").notes("banking-related material"),
        )
        .expect("add");
    });

    let rows = engine
        .search(
            "banking",
            SearchScope::NotesOnly,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert_eq!(titles(&rows), vec!["plain"]);
}

#[test]
fn search_results_are_sorted_alphabetically() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("zzz banking"))
            .expect("add z");
        kdbx.add_entry(root, NewEntry::new("aaa banking"))
            .expect("add a");
        kdbx.add_entry(root, NewEntry::new("Mmm banking"))
            .expect("add m");
    });

    let rows = engine
        .search(
            "banking",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert_eq!(
        titles(&rows),
        vec!["aaa banking", "Mmm banking", "zzz banking"],
        "title COLLATE NOCASE ASC",
    );
}

#[test]
fn search_handles_special_characters_without_error() {
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

    // Any of these would have tripped FTS5's grammar. With LIKE,
    // they're just substring needles — no syntax to honour.
    for q in &[
        "user@example",
        "a:b",
        "(paren)",
        "star*",
        "\"quoted\"",
        "^caret",
        "a-b",
        "+plus",
        "50%",
        "a_b",
    ] {
        let _ = engine
            .search(
                q,
                SearchScope::AnyField,
                RecycleBinFilter::ExcludeRecycled,
                Pagination::all(),
            )
            .expect("no error");
    }
}

#[test]
fn search_like_wildcards_in_query_are_escaped() {
    // `%` and `_` are SQL LIKE wildcards. A user typing `50%`
    // should match a literal "50%" — not "anything-50-anything".
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("50% off coupon"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("50 something"))
            .expect("add");
    });

    let rows = engine
        .search(
            "50%",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert_eq!(titles(&rows), vec!["50% off coupon"]);
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
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination {
                offset: 0,
                limit: 2,
            },
        )
        .expect("p1");
    let p2 = engine
        .search(
            "banking",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination {
                offset: 2,
                limit: 2,
            },
        )
        .expect("p2");
    let p3 = engine
        .search(
            "banking",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
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
fn search_returns_empty_for_no_matches() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking")).expect("add");
    });

    let rows = engine
        .search(
            "nonexistentterm",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
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
    let rows = engine
        .search(
            "banking",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    let elapsed = start.elapsed();
    eprintln!("877-entry search took {elapsed:?}, {} hits", rows.len());
    assert_eq!(rows.len(), 877);
    assert!(
        elapsed < Duration::from_millis(50),
        "877-entry search must complete in <50ms, took {elapsed:?}",
    );
}

// ── recycle-bin filter ─────────────────────────────────────────────────
//
// Pins the `RecycleBinFilter` contract. The exclusion mirrors
// `search_by_service_excludes_recycled_entries`; the bin-only and
// include variants pin that bin inclusion is the CALLER's choice (a
// "Deleted items" view searches inside the bin), never a blanket
// policy.

/// Search + filter, all rows, `AnyField` — the shape every test below uses.
fn search_with(engine: &Engine, q: &str, bin: RecycleBinFilter) -> Vec<String> {
    engine
        .search(q, SearchScope::AnyField, bin, Pagination::all())
        .expect("search")
        .into_iter()
        .map(|s| s.title)
        .collect()
}

/// Seed two matching entries, recycle "banking doomed", return the engine.
///
/// A `Vault::empty`-based fixture has the bin DISABLED (recycling would
/// permanently delete — no `is_recycled` row would ever exist), so
/// enable it first: these tests need an entry genuinely sitting in the
/// bin.
fn engine_with_one_recycled() -> (Engine, tempfile::TempDir) {
    let (mut engine, dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking alive"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("banking doomed"))
            .expect("add");
    });
    engine.set_recycle_bin(true, None).expect("enable bin");
    let doomed = engine
        .search(
            "doomed",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("pre-recycle")
        .pop()
        .expect("doomed present")
        .uuid;
    engine.recycle_entry(doomed).expect("recycle");
    (engine, dir)
}

#[test]
fn search_exclude_recycled_omits_recycled_entries() {
    let (engine, _dir) = engine_with_one_recycled();
    let titles = search_with(&engine, "banking", RecycleBinFilter::ExcludeRecycled);
    assert_eq!(titles, vec!["banking alive"]);
}

#[test]
fn search_recycled_only_finds_only_bin_contents() {
    let (engine, _dir) = engine_with_one_recycled();
    let titles = search_with(&engine, "banking", RecycleBinFilter::RecycledOnly);
    assert_eq!(titles, vec!["banking doomed"]);
}

#[test]
fn search_include_recycled_spans_live_and_bin() {
    let (engine, _dir) = engine_with_one_recycled();
    let titles = search_with(&engine, "banking", RecycleBinFilter::IncludeRecycled);
    assert_eq!(titles, vec!["banking alive", "banking doomed"]);
}

#[test]
fn search_bin_filter_is_by_subtree_membership_not_flag() {
    // The discriminating warm-mirror case: recycling a GROUP re-parents
    // it under the bin but leaves its descendant entries'
    // `is_recycled = 0` until the next ingest re-derives the flag from
    // ancestry. A flag-based filter would leak the buried entry into
    // live results (and hide it from bin-only results) in exactly the
    // state a client searches right after the mutation.
    let (mut engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking alive"))
            .expect("add");
    });
    engine.set_recycle_bin(true, None).expect("enable bin");
    engine.ensure_recycle_bin().expect("ensure bin");

    let root = engine
        .group_tree()
        .expect("tree")
        .into_iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root")
        .uuid;
    let doomed_group = engine
        .create_group(
            root,
            keys_engine::NewGroupFields {
                name: "Doomed".into(),
                notes: String::new(),
                icon: keys_engine::IconRef::Builtin(0),
            },
        )
        .expect("create group");
    engine
        .create_entry(
            doomed_group,
            keys_engine::NewEntryFields {
                title: "banking buried".into(),
                username: String::new(),
                url: String::new(),
                notes: String::new(),
                password: SecretString::from("pw"),
                icon: keys_engine::IconRef::Builtin(0),
                custom_fields: Vec::new(),
                tags: Vec::new(),
            },
        )
        .expect("create entry");

    engine.recycle_group(doomed_group).expect("recycle group");

    // Warm mirror, flag still 0 on the buried entry — membership must
    // decide anyway.
    assert_eq!(
        search_with(&engine, "banking", RecycleBinFilter::ExcludeRecycled),
        vec!["banking alive"]
    );
    assert_eq!(
        search_with(&engine, "banking", RecycleBinFilter::RecycledOnly),
        vec!["banking buried"]
    );
}

#[test]
fn search_with_bin_disabled_treats_every_entry_as_live() {
    // With the bin disabled there is no live/binned distinction
    // (recycling permanently deletes), so exclusion filters nothing and
    // bin-only matches nothing.
    let (mut engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("banking a"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("banking b"))
            .expect("add");
    });
    engine.set_recycle_bin(false, None).expect("disable bin");

    assert_eq!(
        search_with(&engine, "banking", RecycleBinFilter::ExcludeRecycled),
        vec!["banking a", "banking b"]
    );
    assert!(search_with(&engine, "banking", RecycleBinFilter::RecycledOnly).is_empty());
    assert_eq!(
        search_with(&engine, "banking", RecycleBinFilter::IncludeRecycled),
        vec!["banking a", "banking b"]
    );
}
