//! Integration tests for non-blocking reconcile via
//! [`keys_engine::Engine::reconcile_with_disk_park_conflicts`] plus the
//! held-conflict badge surfaces
//! ([`Engine::entries_with_parked_conflict`] /
//! [`Engine::clear_parked_conflict_marker`]).
//!
//! Under the hold-open redesign a genuine clash keeps each side's own
//! current value — no winner, no history marker — and the divergent entry
//! is *derived* into a held-conflict set the engine caches locally for the
//! badge. These tests assert that derived-set behaviour, not the retired
//! `keys.field_conflict.v1` history marker.
//!
//! Mirrors the fixture posture of `external_change_merge.rs`
//! (`FixedKey` + `FixedProtector` + seeded one-entry vault) so the two
//! test files exercise the same code path with different merge modes.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{NewEntry, NewGroup};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError, ParkConflictsResult};

// ── Fixtures (duplicated from external_change_merge.rs intentionally —
//    `tests/` files can't share helpers without a shared `common` mod,
//    and the existing test posture is to inline). ──

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
const PASSWORD: &[u8] = b"pw";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(PASSWORD)
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), "test", Some(protector())).expect("create")
}

fn reopen_kdbx(path: &std::path::Path) -> Kdbx<Unlocked> {
    Kdbx::open(path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock kdbx")
}

struct Fixture {
    _dir: tempfile::TempDir,
    kdbx_path: std::path::PathBuf,
    engine: Engine,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed"))
        .expect("seed entry");
    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("initial save");
    let kdbx_reread = reopen_kdbx(&kdbx_path);
    engine
        .ingest_from_kdbx(&kdbx_reread)
        .expect("re-ingest from disk");
    Fixture {
        _dir: dir,
        kdbx_path,
        engine,
    }
}

// ── Tests ──

/// Trivial sanity: a clean reconcile with no actual divergence
/// returns `NoChange` from the park-conflicts surface too.
#[test]
fn park_conflicts_no_change_when_in_sync() {
    let mut f = fixture();
    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(matches!(result, ParkConflictsResult::NoChange));
}

/// Owner-rows scope (Phase 4): a peer-only **add** propagates. An add is
/// unambiguous (present beats absent) and needs no tombstone; a delete is
/// recognised via the peer's `<DeletedObjects>` tombstone (Phase 5b — see
/// `park_conflicts_propagates_peer_delete`). So a disk-side add advances local
/// ⇒ `Applied`, and the entry appears locally — not a conflict.
#[test]
fn park_conflicts_applies_peer_only_add() {
    let mut f = fixture();

    let mut external = reopen_kdbx(&f.kdbx_path);
    let root = external.vault().root.id;
    let new_id = external
        .add_entry(root, NewEntry::new("from-disk"))
        .expect("add external");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");

    assert!(
        matches!(result, ParkConflictsResult::Applied { .. }),
        "a peer-only add advances local and applies, got {result:?}",
    );

    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    assert!(
        summaries.iter().any(|s| s.uuid == new_id.0),
        "peer-only add is ingested locally",
    );
    assert!(
        f.engine
            .entries_with_parked_conflict()
            .expect("query")
            .is_empty(),
        "a peer-only add is not a conflict",
    );
}

/// Phase 5b on the live path: a disk-side **delete** (a `<DeletedObjects>`
/// tombstone) propagates — the entry is removed locally, the reconcile is
/// `Applied` (a real local change, like a peer-only add), and a re-reconcile is
/// a stable no-op (loop-safe). End-to-end: keepass-core records the disk
/// tombstone, `ingest_peer` consumes it.
#[test]
fn park_conflicts_propagates_peer_delete() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    // Disk side deletes the seed entry (keepass-core records the tombstone).
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .delete_entry(keepass_core::model::EntryId(seed_uuid))
        .expect("disk delete");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    match result {
        ParkConflictsResult::Applied { applied, .. } => {
            assert_eq!(applied.entries_deleted, 1, "one entry deleted");
        }
        other => panic!("expected Applied, got {other:?}"),
    }

    let after = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list after");
    assert!(
        !after.iter().any(|s| s.uuid == seed_uuid),
        "peer-deleted entry removed locally",
    );

    // Loop-safety: the disk file no longer changes, so a re-reconcile is a
    // stable no-op (the unioned tombstone matches; nothing to advance).
    let again = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile 2");
    assert!(
        matches!(again, ParkConflictsResult::NoChange),
        "re-reconcile after a propagated delete is a stable no-op, got {again:?}",
    );
}

/// The headline test under hold-open: a same-entry field clash on disk +
/// locally lands non-blocking. Each side keeps its **own** current value
/// (no winner, no `keys.field_conflict.v1` marker written to history), the
/// divergent entry surfaces in the derived held-conflict set, and a
/// re-reconcile with no further disk change is a stable no-op that leaves
/// the badge in place (loop-safe — no re-park, no churn).
#[test]
fn park_conflicts_holds_field_conflict_keeping_local() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    // Local edit via the engine.
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rename".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    // Concurrent disk edit via keepass-core.
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| {
                e.set_title("disk-rename");
            },
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    // Hold-open: a held conflict that keeps local changes NOTHING locally,
    // so the loop-safety guard returns `NoChange` (NOT `Applied`) — that is
    // what stops a re-merge from re-saving + re-pushing forever. The badge
    // is still recorded (asserted below).
    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(result, ParkConflictsResult::NoChange),
        "a held conflict that keeps local must be a no-op (loop-safe), got {result:?}",
    );

    // Hold-open keeps local: our current value is untouched (no winner).
    let after = f.engine.entry(seed_uuid).expect("entry").expect("present");
    assert_eq!(after.title, "local-rename");

    // The derived held set surfaces the entry for the badge.
    let held = f.engine.entries_with_parked_conflict().expect("query");
    assert_eq!(held, vec![seed_uuid]);

    // Clean cut: hold-open writes no `keys.field_conflict.v1` marker into
    // history (the divergence lives in current state, not on a marker).
    let history = f.engine.history(seed_uuid).expect("history");
    assert!(
        !history.iter().any(|h| h
            .custom_data
            .iter()
            .any(|cd| cd.key == "keys.field_conflict.v1")),
        "hold-open must not write a conflict marker into history",
    );

    // Loop-safety: disk is unchanged, so a second reconcile is a stable
    // no-op and the badge persists — no re-park, no doc-version churn.
    let again = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile 2");
    assert!(
        matches!(again, ParkConflictsResult::NoChange),
        "re-reconcile of a held conflict must be a no-op, got {again:?}",
    );
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
        "badge persists across a no-op reconcile",
    );
}

/// Owner-rows contract (Phase 4): a held conflict advances **nothing** locally
/// — there is no silent facet-folding onto the held entry. Here the disk side
/// renames the title (→ held conflict) AND adds a tag local lacks. Under the
/// owner-rows model the entry classifies as a Conflict (item granularity: both
/// touched the same entry), so it holds open: local is untouched, the peer's
/// value (including its tag) is captured in the owner row for the resolver, and
/// the reconcile is `NoChange` (loop-safe — nothing advanced ⇒ nothing to
/// save). The peer's tag does NOT silently appear on the local entry; it
/// surfaces through the resolver's "theirs" instead. A re-reconcile stays a
/// stable no-op.
#[test]
fn park_conflicts_held_entry_does_not_fold_peer_tag() {
    let mut f = fixture();
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // Local: rename the title (one half of the field conflict).
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rename".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    // Disk: rename the SAME entry's title differently (→ Conflict) AND add a
    // tag local doesn't have.
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| {
                e.set_title("disk-rename");
                e.add_tag("disk-only-tag");
            },
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    // Held conflict ⇒ nothing advances locally ⇒ NoChange (loop-safe).
    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(result, ParkConflictsResult::NoChange),
        "a held conflict advances nothing locally ⇒ NoChange, got {result:?}",
    );

    // Held: local's conflicting title is kept, and the peer's tag is NOT
    // silently folded onto the local entry (it rides in the owner row).
    let after = f.engine.entry(seed_uuid).expect("entry").expect("present");
    assert_eq!(after.title, "local-rename", "hold-open keeps local's title");
    assert!(
        !after.tags.iter().any(|t| t == "disk-only-tag"),
        "the peer's tag must NOT be silently folded onto the held entry, got {:?}",
        after.tags,
    );

    // Badge set for the held entry.
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
    );

    // Loop-safety: disk unchanged → second reconcile is a stable no-op and the
    // badge persists.
    let again = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile 2");
    assert!(
        matches!(again, ParkConflictsResult::NoChange),
        "re-reconcile of a held conflict must stay a no-op, got {again:?}",
    );
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
        "badge persists across a no-op reconcile",
    );
}

/// Owner-rows contract (Phase 4): a concurrent **group** rename alongside a
/// held entry conflict does not change the loop-safety verdict. Group
/// reconciliation is Phase-5 scope, so the owner-rows ingest neither advances
/// the held entry nor applies the group rename — the reconcile is `NoChange`
/// (loop-safe). The peer's group rename is simply not adopted yet; it is not
/// lost (a future Phase-5 group pass handles it). The held entry keeps local's
/// title and stays badged.
#[test]
fn park_conflicts_held_entry_group_rename_stays_loop_safe() {
    let mut f = fixture();
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // Local: rename the entry title (one half of the field conflict).
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rename".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    // Disk: rename the SAME entry's title differently (→ Conflict) AND rename
    // the group that holds the entry (Phase-5 group scope).
    let mut external = reopen_kdbx(&f.kdbx_path);
    let root_id = external.vault().root.id;
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| {
                e.set_title("disk-rename");
            },
        )
        .expect("disk entry edit");
    external
        .edit_group(root_id, |g| g.set_name("disk-renamed-group"))
        .expect("disk group rename");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    // Held conflict + Phase-5 group rename ⇒ nothing advances ⇒ NoChange.
    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(result, ParkConflictsResult::NoChange),
        "owner-rows holds the entry and defers the group rename ⇒ NoChange, got {result:?}",
    );

    // The held entry kept local's conflicting title and stays badged.
    let after = f.engine.entry(seed_uuid).expect("entry").expect("present");
    assert_eq!(after.title, "local-rename", "hold-open keeps local's title");
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
    );

    // Loop-safety: disk unchanged → second reconcile is a stable no-op.
    let again = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile 2");
    assert!(
        matches!(again, ParkConflictsResult::NoChange),
        "re-reconcile must stay a no-op, got {again:?}",
    );
}

/// Regression for the icon-conflict sync loop (the soak bug): a held ICON
/// conflict must be loop-safe just like a field conflict. The danger is the
/// shared custom-icon POOL — the merge transiently unions the peer's icon
/// (here the disk side carries it in its `<CustomIcons>` pool), but that
/// icon is unreferenced (hold-open keeps local's icon) and the save-time GC
/// would strip it, so it must NOT count as a real change. If it did, every
/// merge would re-save with different bytes → push → peer merges → push →
/// forever. Asserts the reconcile is a no-op, the badge is set, local's
/// icon is kept, and a re-reconcile stays a no-op (idempotent).
#[test]
fn park_conflicts_holds_icon_conflict_loop_safe() {
    let mut f = fixture();
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // Local: set the entry's icon to a custom UUID (no pool bitmap needed —
    // the merge keys on the entry's `custom_icon_uuid`).
    let local_icon = uuid::Uuid::new_v4();
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                icon: Some(keys_engine::IconRef::Custom(local_icon)),
                ..Default::default()
            },
        )
        .expect("local icon");

    // Disk: a DIFFERENT custom icon, and put it in the disk's <CustomIcons>
    // pool so the merge's pool-union actually has the peer icon to fold in —
    // this is what reproduced the loop.
    let mut external = reopen_kdbx(&f.kdbx_path);
    let disk_icon = external.add_custom_icon(vec![0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4]);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| e.set_custom_icon(Some(disk_icon)),
        )
        .expect("disk icon");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    // A held icon conflict changes nothing locally (hold-open keeps
    // local_icon; the peer's pool icon is a phantom the save-GC strips) →
    // loop-safe `NoChange`, not `Applied`.
    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(result, ParkConflictsResult::NoChange),
        "a held icon conflict must be a no-op (loop-safe), got {result:?}",
    );

    // Badge set; local icon kept.
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
        "the icon-conflicted entry is badged",
    );
    let after = f.engine.entry(seed_uuid).expect("entry").expect("present");
    assert!(
        matches!(after.icon, keys_engine::IconRef::Custom(u) if u == local_icon),
        "hold-open keeps the local icon, got {:?}",
        after.icon,
    );

    // Idempotent: a second reconcile with no further disk change is still a
    // no-op and the badge persists — the loop is dead.
    let again = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile 2");
    assert!(
        matches!(again, ParkConflictsResult::NoChange),
        "re-reconcile of a held icon conflict must stay a no-op, got {again:?}",
    );
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
    );
}

/// `clear_parked_conflict_marker` is the local badge-dismissal half of
/// hold-open: after a held conflict it drops the entry from the derived
/// held set so the badge clears on this device. (Cross-peer convergence is
/// driven by the `keys.conflict_resolutions.v1` record that
/// `apply_conflict_resolution` writes — exercised in
/// `tests/conflict_resolution.rs`, not here.)
#[test]
fn clear_parked_conflict_dismisses_held_badge() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rename".into()),
                ..Default::default()
            },
        )
        .expect("local edit");
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| e.set_title("disk-rename"),
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    f.engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
    );

    // Dismiss the held badge locally.
    let cleared = f
        .engine
        .clear_parked_conflict_marker(seed_uuid, chrono::Utc::now())
        .expect("clear");
    assert_eq!(cleared, 1, "held badge dismissed");

    // No more entries flagged on this device.
    assert!(
        f.engine
            .entries_with_parked_conflict()
            .expect("query")
            .is_empty(),
        "held set empty after dismiss",
    );

    // Idempotent: dismissing again is a clean 0.
    let again = f
        .engine
        .clear_parked_conflict_marker(seed_uuid, chrono::Utc::now())
        .expect("clear again");
    assert_eq!(again, 0, "second dismiss is a no-op");
}

/// Regression test for Bug #1 — `vaults_equivalent` short-circuited
/// reconcile on content-only edits (password/tags/custom fields/
/// attachments/custom icon), so a password edit on one Mac never
/// propagated to a peer. The fix replaces the field-content comparator
/// with a byte-equivalence check against the engine's last-saved
/// baseline. If the disk bytes differ from the baseline, the merge
/// runs unconditionally; identical content produces empty buckets that
/// the apply path treats as a no-op.
#[test]
fn two_engine_one_sided_password_edit_propagates() {
    use secrecy::{ExposeSecret, SecretString};

    let dir = tempfile::tempdir().expect("tempdir");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed")).expect("seed");

    // Engine A: ingests, saves the kdbx to disk.
    let db_a = dir.path().join("a.db");
    let mut engine_a =
        Engine::open(&db_a, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open a");
    engine_a.ingest_from_kdbx(&kdbx).expect("a ingest");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a save");

    // Engine B: reads the kdbx A wrote, ingests, then re-ingests after
    // re-reading from disk so its baseline equals the disk bytes.
    let kdbx_b_view = reopen_kdbx(&kdbx_path);
    let db_b = dir.path().join("b.db");
    let mut engine_b =
        Engine::open(&db_b, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open b");
    engine_b.ingest_from_kdbx(&kdbx_b_view).expect("b ingest");
    // Run an initial reconcile so B picks up the current disk bytes as
    // its baseline. (Without this, B's `last_saved_kdbx_bytes` is None
    // and the short-circuit falls through anyway, but we want to
    // exercise the post-baseline path.)
    let _ = engine_b
        .reconcile_with_disk_park_conflicts(&kdbx_path, &composite(), chrono::Utc::now())
        .expect("b initial reconcile");

    let seed_uuid = engine_a
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // A edits ONLY the password — the kind of edit `vaults_equivalent`
    // used to ignore (it only compared title/username/url/notes).
    engine_a
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                password: Some(SecretString::from("new-secret-pw".to_string())),
                ..Default::default()
            },
        )
        .expect("a edit pw");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a save 2");

    // B reconciles — must see the password edit, not NoChange.
    let result = engine_b
        .reconcile_with_disk_park_conflicts(&kdbx_path, &composite(), chrono::Utc::now())
        .expect("b reconcile");
    match result {
        ParkConflictsResult::Applied { .. } => {
            // The merge ran. Whether the change lands in
            // `entries_updated` or via the park path is incidental for
            // Bug #1 — what matters is that the short-circuit didn't
            // swallow it. The password assertion below proves the
            // edit actually reached B.
        }
        ParkConflictsResult::NoChange => {
            panic!("password-only edit was lost (Bug #1 — vaults_equivalent ignored password)")
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Verify the password actually landed in B's projection.
    let revealed = engine_b.reveal_password(seed_uuid).expect("reveal");
    assert_eq!(revealed.expose_secret(), "new-secret-pw");
}

/// Regression test for the iroh ping-pong loop: after both sides
/// converge on the same logical content, the receiving engine must
/// return `NoChange` even though the disk bytes don't byte-equal the
/// engine's last-saved baseline (every save produces fresh
/// encryption nonces). Without this guard, every reconcile would
/// return `Applied` with zero stats, triggering a save+push cascade
/// that the peer answers with another save+push, forever.
#[test]
fn empty_outcome_after_byte_different_input_returns_no_change() {
    use std::io::Write;

    let dir = tempfile::tempdir().expect("tempdir");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed")).expect("seed");
    let db_a = dir.path().join("a.db");
    let mut engine_a =
        Engine::open(&db_a, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open a");
    engine_a.ingest_from_kdbx(&kdbx).expect("a ingest");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a initial save");

    // Engine A re-saves the kdbx WITHOUT mutating any content. The
    // re-save produces fresh bytes (new encryption nonce) but the
    // logical content is identical. Simulates peer's "save +
    // push-back" after an empty-merge reconcile.
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a re-save");
    let disk_bytes_after_resave = std::fs::read(&kdbx_path).expect("read");
    // Force a difference from A's last-saved baseline so the byte-
    // equality short-circuit doesn't fire — we need to exercise the
    // post-merge outcome_is_no_op path. Open the kdbx fresh and
    // re-save it via a separate handle so the bytes on disk differ
    // from what A wrote.
    let external = reopen_kdbx(&kdbx_path);
    let alt_bytes = external.save_to_bytes().expect("external save");
    assert_ne!(
        disk_bytes_after_resave, alt_bytes,
        "fresh nonce should produce different bytes",
    );
    {
        let mut f = std::fs::File::create(&kdbx_path).expect("open for write");
        f.write_all(&alt_bytes).expect("overwrite");
    }

    // Now A's last-saved baseline (disk_bytes_after_resave) differs
    // from disk_bytes (alt_bytes). Reconcile should run the merge,
    // see empty buckets, and return NoChange.
    let result = engine_a
        .reconcile_with_disk_park_conflicts(&kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(result, ParkConflictsResult::NoChange),
        "byte-different but content-equivalent disk must yield NoChange, got: {result:?}",
    );
}

/// Clearing an entry with no markers is a clean no-op.
#[test]
fn clear_parked_conflict_marker_no_op_on_clean_entry() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    let cleared = f
        .engine
        .clear_parked_conflict_marker(seed_uuid, chrono::Utc::now())
        .expect("clear");
    assert_eq!(cleared, 0);
}

/// Bug #2 regression: a one-sided engine edit on Mac-A must reconcile
/// cleanly on Mac-B without parking a conflict. Before the fix the
/// engine's mutations didn't push a history snapshot of the pre-edit
/// state, so the projected kdbx had empty `<History>` for the edited
/// entry — the peer's merger then had no common ancestor and fell back
/// to parking. After the fix, A's save carries the pre-edit snapshot
/// and the merger adopts the change as a clean update.
#[test]
fn two_engine_one_sided_title_edit_updates_without_parking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed"))
        .expect("seed entry");

    // Mac-A engine: owns the kdbx, will edit and save.
    let db_a = dir.path().join("a.db");
    let mut engine_a =
        Engine::open(&db_a, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open a");
    engine_a.ingest_from_kdbx(&kdbx).expect("a ingest");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a initial save");

    // Mac-B engine: ingests from the same disk file.
    let kdbx_b_view = reopen_kdbx(&kdbx_path);
    let db_b = dir.path().join("b.db");
    let mut engine_b =
        Engine::open(&db_b, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open b");
    engine_b.ingest_from_kdbx(&kdbx_b_view).expect("b ingest");

    let summaries = engine_a
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    // Mac-A: edit the title via the engine, save to disk.
    engine_a
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("edited-on-A".into()),
                ..Default::default()
            },
        )
        .expect("a edit");
    engine_a
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("a save");

    // Mac-B: reconcile against the updated disk. No conflict should be parked.
    let result = engine_b
        .reconcile_with_disk_park_conflicts(&kdbx_path, &composite(), chrono::Utc::now())
        .expect("b reconcile");

    match result {
        ParkConflictsResult::Applied { applied, parked } => {
            assert!(
                parked.entries_with_parked_conflict.is_empty(),
                "B should not park; got: {:?}",
                parked.entries_with_parked_conflict
            );
            assert_eq!(
                applied.entries_updated, 1,
                "B should adopt A's edit as a clean update"
            );
        }
        other => panic!("expected Applied with one update, got {other:?}"),
    }

    let after = engine_b.entry(seed_uuid).expect("entry").expect("present");
    assert_eq!(after.title, "edited-on-A");
}

/// Phase 5d: a one-sided entry MOVE reconciles across peers via
/// `<LocationChanged>` LWW, and the replicas CONVERGE on one location.
/// A and B fork from a shared base holding a Folder group; A moves the
/// seed into Folder; both sync both ways. A pure move is
/// content-identical, so classify alone verdicts `InSync` —
/// `reconcile_entry_location` is what carries it; the two sides must
/// end up agreeing on the entry's group (whichever the deterministic
/// LWW + tiebreak selects).
///
/// We assert *convergence* rather than a fixed destination: the move's
/// `location_changed` and the entry's creation-time stamp can land in
/// the same floored second in a fast test (keepass-core stamps
/// `location_changed` on creation too), so the same-second tiebreak —
/// not wall-clock — decides the winner. Convergence is the contract;
/// the deterministic-winner direction is pinned by keyhole's
/// `move-lww.sh` (which separates the seconds with a sleep).
#[test]
fn two_engine_move_reconciles_and_converges() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Shared base: one entry at root + a Folder group, so the move has a
    // destination both replicas already hold (peer-only group adoption is
    // a later 5d slice).
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let folder = kdbx
        .add_group(root, NewGroup::new("Folder"))
        .expect("add folder");
    let seed = kdbx
        .add_entry(root, NewEntry::new("Mover"))
        .expect("seed")
        .0;

    let kdbx_a = dir.path().join("a.kdbx");
    let kdbx_b = dir.path().join("b.kdbx");
    let db_a = dir.path().join("a.db");
    let mut engine_a =
        Engine::open(&db_a, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open a");
    engine_a.ingest_from_kdbx(&kdbx).expect("a ingest");
    engine_a
        .save_to_kdbx(&kdbx_a, &mut kdbx, None)
        .expect("a save");

    // B forks from the same on-disk base and keeps its own KDBX file.
    let db_b = dir.path().join("b.db");
    let mut engine_b =
        Engine::open(&db_b, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open b");
    engine_b
        .ingest_from_kdbx(&reopen_kdbx(&kdbx_a))
        .expect("b ingest");
    let mut handle_b = reopen_kdbx(&kdbx_a);
    engine_b
        .save_to_kdbx(&kdbx_b, &mut handle_b, None)
        .expect("b save");

    // Pre-state: the two replicas disagree on the entry's group (B at
    // root, A about to move it), so a no-op reconcile would leave them
    // diverged — the assertion below has teeth.
    engine_a.move_entry(seed, folder.0).expect("a move");
    let mut handle_a = reopen_kdbx(&kdbx_a);
    engine_a
        .save_to_kdbx(&kdbx_a, &mut handle_a, None)
        .expect("a save 2");

    // Exchange both ways: B ingests A, then A ingests B (re-saving each
    // so the next pull reads the reconciled state).
    engine_b
        .ingest_peer_from_kdbx(&kdbx_a, &composite(), "device-a")
        .expect("b ingest a");
    let mut hb = reopen_kdbx(&kdbx_b);
    engine_b
        .save_to_kdbx(&kdbx_b, &mut hb, None)
        .expect("b save 2");
    engine_a
        .ingest_peer_from_kdbx(&kdbx_b, &composite(), "device-b")
        .expect("a ingest b");

    // Converged: both digests equal, and the entry sits in exactly one
    // group on each side — the same group.
    assert_eq!(
        engine_a.content_digest().expect("a digest"),
        engine_b.content_digest().expect("b digest"),
        "replicas converged after the move exchange",
    );
    let a_in_folder = !engine_a
        .list_entries(Some(folder.0), keys_engine::Pagination::all())
        .expect("a folder")
        .is_empty();
    let b_in_folder = !engine_b
        .list_entries(Some(folder.0), keys_engine::Pagination::all())
        .expect("b folder")
        .is_empty();
    assert_eq!(a_in_folder, b_in_folder, "both agree on the entry's group");
}

/// Phase 5d group adoption: a peer-only GROUP (one B has never seen)
/// is adopted on ingest, and an entry the peer moved into it lands
/// there rather than at root. Group adoption is unconditional (not
/// LWW-gated), so this asserts the group's presence directly; the
/// entry placement converges via the same ingest.
#[test]
fn two_engine_adopts_peer_only_group() {
    use keys_engine::{IconRef, NewGroupFields};

    let dir = tempfile::tempdir().expect("tempdir");
    let kdbx_a = dir.path().join("a.kdbx");

    // Shared base: one entry at root, no extra groups.
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let seed = kdbx
        .add_entry(root, NewEntry::new("Mover"))
        .expect("seed")
        .0;

    let db_a = dir.path().join("a.db");
    let mut engine_a =
        Engine::open(&db_a, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open a");
    engine_a.ingest_from_kdbx(&kdbx).expect("a ingest");
    engine_a
        .save_to_kdbx(&kdbx_a, &mut kdbx, None)
        .expect("a save");

    let kdbx_b = dir.path().join("b.kdbx");
    let db_b = dir.path().join("b.db");
    let mut engine_b =
        Engine::open(&db_b, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open b");
    engine_b
        .ingest_from_kdbx(&reopen_kdbx(&kdbx_a))
        .expect("b ingest");
    let mut hb0 = reopen_kdbx(&kdbx_a);
    engine_b
        .save_to_kdbx(&kdbx_b, &mut hb0, None)
        .expect("b save");

    // A creates a brand-new group B has never seen and moves the entry in.
    let fresh = engine_a
        .create_group(
            root.0,
            NewGroupFields {
                name: "Fresh".into(),
                notes: String::new(),
                icon: IconRef::Builtin(0),
            },
        )
        .expect("a create group");
    engine_a.move_entry(seed, fresh).expect("a move");
    let mut handle = reopen_kdbx(&kdbx_a);
    engine_a
        .save_to_kdbx(&kdbx_a, &mut handle, None)
        .expect("a save 2");

    // Precondition: B doesn't hold the group yet.
    assert!(
        !engine_b
            .group_tree()
            .expect("b groups")
            .iter()
            .any(|g| g.uuid == fresh),
        "precondition: B lacks the peer-only group before ingest",
    );

    // B ingests A — adopts the group, and the move lands in it.
    let result = engine_b
        .ingest_peer_from_kdbx(&kdbx_a, &composite(), "device-a")
        .expect("b ingest peer");
    assert!(
        matches!(result, ParkConflictsResult::Applied { .. }),
        "adopting a peer-only group is a local change → Applied, got {result:?}",
    );
    assert!(
        engine_b
            .group_tree()
            .expect("b groups")
            .iter()
            .any(|g| g.uuid == fresh && g.parent_uuid == Some(root.0)),
        "B adopted the peer-only group under root",
    );

    // Entry PLACEMENT into the adopted group rides location LWW, which can
    // tie on the floored second in a fast test (create + move land in the
    // same second as the base entry's creation stamp). So assert the
    // timing-independent contract — the replicas CONVERGE on one placement
    // — rather than a fixed destination (the deterministic
    // entry-lands-in-the-group direction is pinned by keyhole's
    // group-adopt.sh, which separates the seconds with a sleep). Sync the
    // other way and compare digests.
    let mut hb = reopen_kdbx(&kdbx_b);
    engine_b
        .save_to_kdbx(&kdbx_b, &mut hb, None)
        .expect("b save back");
    engine_a
        .ingest_peer_from_kdbx(&kdbx_b, &composite(), "device-b")
        .expect("a ingest b");
    assert_eq!(
        engine_a.content_digest().expect("a digest"),
        engine_b.content_digest().expect("b digest"),
        "replicas converge after adopting the peer-only group",
    );
}
