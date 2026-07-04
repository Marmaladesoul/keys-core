//! Integration tests for [`Engine::search_by_service`] (task 7.2).
//!
//! Exercises the three matching tiers (exact host, eTLD+1, substring),
//! recycle-bin exclusion, dedupe by uuid, and ranking by recency.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewEntry;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use secrecy::SecretString;
use uuid::Uuid;

// ── test wiring (mirrors crates/keys-engine/tests/search.rs) ────────────

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
fn search_by_service_empty_identifier_returns_empty() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("g").url("https://google.com"))
            .expect("add");
    });

    assert!(engine.search_by_service("", 10).expect("search").is_empty());
    assert!(engine.search_by_service("   ", 10).expect("ws").is_empty());
}

#[test]
fn search_by_service_zero_limit_returns_empty() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("g").url("https://google.com"))
            .expect("add");
    });

    assert!(
        engine
            .search_by_service("google.com", 0)
            .expect("search")
            .is_empty()
    );
}

#[test]
fn search_by_service_exact_host_match() {
    // Tier 1 — exact url_host equality.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("google").url("https://google.com"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("github").url("https://github.com"))
            .expect("add");
    });

    let rows = engine.search_by_service("google.com", 10).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "google");
}

#[test]
fn search_by_service_exact_host_case_insensitive() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        // url_host is lowercased at ingest, so this stores `google.com`.
        kdbx.add_entry(root, NewEntry::new("g").url("https://Google.COM"))
            .expect("add");
    });

    let rows = engine.search_by_service("GOOGLE.com", 10).expect("search");
    assert_eq!(rows.len(), 1);
}

#[test]
fn search_by_service_full_url_identifier() {
    // Identifier is a full URL — host should be extracted and used
    // for matching.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(
            root,
            NewEntry::new("google").url("https://accounts.google.com"),
        )
        .expect("add");
    });

    let rows = engine
        .search_by_service("https://accounts.google.com/signin?continue=/", 10)
        .expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "google");
}

#[test]
fn search_by_service_etld1_subdomain_to_apex() {
    // Tier 2 — identifier is a subdomain, entry is at apex.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("g-apex").url("https://google.com"))
            .expect("add");
    });

    let rows = engine
        .search_by_service("accounts.google.com", 10)
        .expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "g-apex");
}

#[test]
fn search_by_service_etld1_apex_to_subdomain() {
    // Tier 2 — identifier is the apex, entry is on a subdomain.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(
            root,
            NewEntry::new("g-sub").url("https://accounts.google.com"),
        )
        .expect("add");
    });

    let rows = engine.search_by_service("google.com", 10).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "g-sub");
}

#[test]
fn search_by_service_etld1_handles_two_label_suffix() {
    // bbc.co.uk should match news.bbc.co.uk via eTLD+1.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("bbc").url("https://news.bbc.co.uk"))
            .expect("add");
    });

    let rows = engine.search_by_service("bbc.co.uk", 10).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "bbc");
}

#[test]
fn search_by_service_substring_fallback() {
    // Tier 3 — url has no parseable host (the engine ingests an
    // empty url_host), so only the substring tier can match. We
    // store the identifier inside the `url` column.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        // Bare string with no scheme — url::Url::parse will fail,
        // so url_host stays empty.
        kdbx.add_entry(
            root,
            NewEntry::new("legacy").url("legacy-app-id://my-service-marker/x"),
        )
        .expect("add");
    });

    let rows = engine
        .search_by_service("my-service-marker", 10)
        .expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "legacy");
}

#[test]
fn search_by_service_ranks_tiers_in_order() {
    // All three tiers fire for "google.com". Verify ordering: exact
    // host < eTLD+1 < substring.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        // Tier 3 — substring only. url unparseable so host extraction
        // fails and exact/eTLD+1 tiers cannot fire.
        kdbx.add_entry(
            root,
            NewEntry::new("substr").url("notes-about-google.com-here"),
        )
        .expect("add");
        // Tier 2 — eTLD+1 (subdomain).
        kdbx.add_entry(
            root,
            NewEntry::new("etld1").url("https://accounts.google.com"),
        )
        .expect("add");
        // Tier 1 — exact host match.
        kdbx.add_entry(root, NewEntry::new("exact").url("https://google.com"))
            .expect("add");
    });

    let rows = engine.search_by_service("google.com", 10).expect("search");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].title, "exact");
    assert_eq!(rows[1].title, "etld1");
    assert_eq!(rows[2].title, "substr");
}

#[test]
fn search_by_service_excludes_recycled_entries() {
    let (mut engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("alive").url("https://google.com"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("doomed").url("https://google.com"))
            .expect("add");
    });

    // A `Vault::empty`-based fixture has the bin DISABLED, under which
    // `recycle_entry` permanently deletes — the exclusion would pass
    // vacuously with no recycled row ever existing. Enable the bin so
    // "doomed" genuinely sits in it.
    engine.set_recycle_bin(true, None).expect("enable bin");

    // Find the "doomed" uuid and recycle it.
    let doomed_uuid: Uuid = {
        let all = engine
            .search_by_service("google.com", 10)
            .expect("pre-recycle");
        all.iter()
            .find(|s| s.title == "doomed")
            .expect("doomed present")
            .uuid
    };
    engine.recycle_entry(doomed_uuid).expect("recycle");

    let rows = engine.search_by_service("google.com", 10).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "alive");
}

#[test]
fn search_by_service_bin_filter_is_by_subtree_membership_not_flag() {
    // The discriminating warm-mirror case (mirrors
    // search_bin_filter_is_by_subtree_membership_not_flag in search.rs):
    // recycling a GROUP re-parents it under the bin but leaves its
    // descendant entries' `is_recycled = 0` until the next ingest
    // re-derives the flag from ancestry. A flag-based filter would keep
    // serving the buried entry to the service lookup in exactly the
    // state a client fills from right after the mutation.
    let (mut engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("alive").url("https://google.com"))
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
                title: "buried".into(),
                username: String::new(),
                url: "https://google.com".into(),
                notes: String::new(),
                password: SecretString::from("pw"),
                icon: keys_engine::IconRef::Builtin(0),
                custom_fields: Vec::new(),
                tags: Vec::new(),
            },
        )
        .expect("create entry");

    // Both visible while the group is live.
    assert_eq!(
        engine
            .search_by_service("google.com", 10)
            .expect("pre-recycle")
            .len(),
        2
    );

    engine.recycle_group(doomed_group).expect("recycle group");

    // Warm mirror, flag still 0 on the buried entry — membership must
    // decide anyway.
    let rows = engine.search_by_service("google.com", 10).expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "alive");
}

#[test]
fn search_by_service_with_bin_disabled_treats_every_entry_as_live() {
    // Disabling the bin erases the live/binned distinction (matching
    // Engine::search's ExcludeRecycled): entries still sitting under
    // the old bin subtree come back into lookup results rather than
    // being filtered by their stale `is_recycled` flag.
    let (mut engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("alive").url("https://google.com"))
            .expect("add");
        kdbx.add_entry(root, NewEntry::new("binned").url("https://google.com"))
            .expect("add");
    });
    engine.set_recycle_bin(true, None).expect("enable bin");

    let binned_uuid: Uuid = engine
        .search_by_service("google.com", 10)
        .expect("pre-recycle")
        .iter()
        .find(|s| s.title == "binned")
        .expect("binned present")
        .uuid;
    engine.recycle_entry(binned_uuid).expect("recycle");
    assert_eq!(
        engine
            .search_by_service("google.com", 10)
            .expect("bin on")
            .len(),
        1
    );

    engine.set_recycle_bin(false, None).expect("disable bin");

    let rows = engine.search_by_service("google.com", 10).expect("bin off");
    assert_eq!(rows.len(), 2);
}

#[test]
fn search_by_service_dedupes_by_uuid() {
    // A single entry matching both tier 1 (exact host) and tier 3
    // (url substring) must appear exactly once, ranked by its best
    // tier (1).
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        // url_host = google.com, url = https://google.com — matches
        // tier 1 (exact host) AND tier 3 (substring "google.com" in
        // url). The dedupe must leave a single row.
        kdbx.add_entry(root, NewEntry::new("g").url("https://google.com"))
            .expect("add");
    });

    let rows = engine.search_by_service("google.com", 10).expect("search");
    assert_eq!(rows.len(), 1);
}

#[test]
fn search_by_service_respects_limit() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        for i in 0..5 {
            kdbx.add_entry(
                root,
                NewEntry::new(format!("g{i}")).url("https://google.com"),
            )
            .expect("add");
        }
    });

    let rows = engine.search_by_service("google.com", 3).expect("search");
    assert_eq!(rows.len(), 3);
}

#[test]
fn search_by_service_no_match_returns_empty() {
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("g").url("https://google.com"))
            .expect("add");
    });

    let rows = engine
        .search_by_service("unrelated.example", 10)
        .expect("search");
    assert!(rows.is_empty());
}

#[test]
fn search_by_service_bare_host_identifier_works() {
    // Bare hostname (no scheme) — url::Url::parse fails, fallback
    // treats the input as a host directly.
    let (engine, _dir) = engine_with(|kdbx| {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new("g").url("https://google.com"))
            .expect("add");
    });

    let rows = engine.search_by_service("google.com", 10).expect("search");
    assert_eq!(rows.len(), 1);
}
