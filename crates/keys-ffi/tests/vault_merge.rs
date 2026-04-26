//! Integration tests for slice 7.5a — `Vault::merge_external`.
//!
//! Fixture-pair construction: open `kdbx3-basic.kdbx` twice into
//! separate temp directories, mutate one copy via the FFI mutators
//! (which use `HistoryPolicy::Snapshot` and bump `last_modified_ms`
//! correctly), call `save()`. Yields a real on-disk pair without
//! committing new fixtures.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use keys_ffi::{
    EntryCreate, EntryPatch, FieldDeltaKindFfi, Vault, VaultChange, VaultError, VaultObserver,
};
use tempfile::TempDir;

const PASSWORD: &str = "test-basic-002";

fn fixture(rel: &str) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../../../KeepassCore/tests/fixtures")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

/// Copy `kdbx3-basic.kdbx` into a fresh temp directory and return the
/// `Vault` opened against the copy plus the temp dir for cleanup.
fn open_basic_in_temp() -> (Arc<Vault>, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let dest = dir.path().join("basic.kdbx");
    fs::copy(fixture("keepassxc/kdbx3-basic.kdbx"), &dest).expect("copy fixture");
    let vault = Vault::new(dest.to_string_lossy().into_owned(), PASSWORD.to_owned()).expect("open");
    (vault, dir)
}

/// Build two on-disk vaults that share a baseline edit history.
///
/// Each side opens its own copy of `kdbx3-basic.kdbx`, applies one
/// shared seed-edit on a target entry (which writes a history record
/// of the pre-seed state), and saves. After this both sides have an
/// identical history record on the target — that record is the LCA
/// the merge crate walks `<History>` for. Without it, the merger's
/// "no ancestor → everything is a conflict" fallback kicks in and
/// invalidates the auto-applicable scenarios.
fn make_pair() -> (Arc<Vault>, TempDir, Arc<Vault>, TempDir) {
    let (local, ldir) = open_basic_in_temp();
    let (remote, rdir) = open_basic_in_temp();
    let target = first_entry_uuid(&local);
    seed_history(&local, &target);
    seed_history(&remote, &target);
    local.save().expect("seed local save");
    remote.save().expect("seed remote save");
    // Re-open after save to drop the seed snapshot from in-memory state
    // and exercise the same path Swift would.
    let local_path = local.path();
    let remote_path = remote.path();
    drop(local);
    drop(remote);
    let local = Vault::new(local_path, PASSWORD.to_owned()).expect("reopen local");
    let remote = Vault::new(remote_path, PASSWORD.to_owned()).expect("reopen remote");
    (local, ldir, remote, rdir)
}

/// Apply a deterministic seed edit on `target` so the entry's
/// `<History>` carries one record both sides agree on. The edit is
/// the same on both sides — this is intentional; the goal is to
/// produce a shared LCA in `<History>`, not to diverge state.
fn seed_history(vault: &Vault, target: &str) {
    let mut patch = EntryPatch::empty();
    patch.notes = Some("__merge-seed__".to_owned());
    vault
        .update_entry(target.to_owned(), patch)
        .expect("seed edit");
}

fn personal_uuid(vault: &Vault) -> String {
    vault
        .list_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.name == "Personal")
        .unwrap()
        .uuid
}

fn first_entry_uuid(vault: &Vault) -> String {
    vault
        .list_entries(None)
        .unwrap()
        .first()
        .expect("fixture has entries")
        .uuid
        .clone()
}

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<VaultChange>>,
}

impl Recorder {
    fn snapshot(&self) -> Vec<VaultChange> {
        self.events.lock().unwrap().clone()
    }
}

impl VaultObserver for Recorder {
    fn on_change(&self, change: VaultChange) {
        self.events.lock().unwrap().push(change);
    }
}

fn attach(vault: &Vault) -> Arc<Recorder> {
    let r = Arc::new(Recorder::default());
    let trait_obj: Arc<dyn VaultObserver> = r.clone();
    vault.set_observer(trait_obj);
    r
}

// =======================================================================
// Auto-mergeable buckets
// =======================================================================

#[test]
fn merge_external_disk_only_changes_yields_auto_applicable() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    // Mutate only the remote side and save.
    let mut patch = EntryPatch::empty();
    patch.title = Some("disk-only-edit".to_owned());
    remote
        .update_entry(target.clone(), patch)
        .expect("remote update");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");

    let summary = outcome.summary().expect("summary");
    assert_eq!(summary.disk_only_count, 1, "{summary:?}");
    assert_eq!(summary.entry_conflict_count, 0, "{summary:?}");
    assert!(outcome.is_auto_applicable().unwrap());
}

#[test]
fn merge_external_local_only_changes_yields_auto_applicable() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    // Mutate only the local side. Don't save the local — merge_external
    // reads the in-memory local vault, not disk.
    let mut patch = EntryPatch::empty();
    patch.title = Some("local-only-edit".to_owned());
    local.update_entry(target, patch).expect("local update");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");

    let summary = outcome.summary().expect("summary");
    assert_eq!(summary.local_only_count, 1, "{summary:?}");
    assert_eq!(summary.entry_conflict_count, 0, "{summary:?}");
    assert!(outcome.is_auto_applicable().unwrap());
}

// =======================================================================
// Conflict-bearing buckets
// =======================================================================

#[test]
fn merge_external_entry_conflict_surfaces_field_deltas() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut local_patch = EntryPatch::empty();
    local_patch.title = Some("local-title".to_owned());
    local
        .update_entry(target.clone(), local_patch)
        .expect("local");

    let mut remote_patch = EntryPatch::empty();
    remote_patch.title = Some("remote-title".to_owned());
    remote
        .update_entry(target.clone(), remote_patch)
        .expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");

    let summary = outcome.summary().expect("summary");
    assert_eq!(summary.entry_conflict_count, 1, "{summary:?}");

    let conflicts = outcome.entry_conflicts().expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    let c = &conflicts[0];
    assert_eq!(c.entry_uuid, target);
    assert!(
        c.field_deltas
            .iter()
            .any(|d| d.key == "Title" && d.kind == FieldDeltaKindFfi::BothDiffer),
        "Title BothDiffer expected; got {:?}",
        c.field_deltas
    );
    assert_eq!(c.local.title, "local-title");
    assert_eq!(c.remote.title, "remote-title");
}

#[test]
fn merge_external_added_on_disk() {
    let (local, _ldir, remote, _rdir) = make_pair();

    let group = personal_uuid(&remote);
    remote
        .create_entry(EntryCreate::new("brand-new", group))
        .expect("remote create");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let summary = outcome.summary().expect("summary");
    assert_eq!(summary.added_on_disk_count, 1, "{summary:?}");
    assert!(outcome.is_auto_applicable().unwrap());
}

#[test]
fn merge_external_deleted_on_disk() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    remote.delete_entry(target).expect("remote delete");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let summary = outcome.summary().expect("summary");
    assert_eq!(summary.deleted_on_disk_count, 1, "{summary:?}");
    assert!(outcome.is_auto_applicable().unwrap());
}

#[test]
fn merge_external_delete_edit_conflict_surfaces_local_state() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);
    let title_before = local
        .get_entry(target.clone())
        .expect("get local")
        .title
        .clone();

    // Local edits the entry.
    let mut patch = EntryPatch::empty();
    patch.title = Some(format!("{title_before}-locally-edited"));
    local
        .update_entry(target.clone(), patch)
        .expect("local edit");

    // Remote tombstones the same entry.
    remote.delete_entry(target.clone()).expect("remote delete");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let summary = outcome.summary().expect("summary");
    assert_eq!(summary.delete_edit_conflict_count, 1, "{summary:?}");
    assert!(!outcome.is_auto_applicable().unwrap());

    let conflicts = outcome.delete_edit_conflicts().expect("delete-edit");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].entry_uuid, target);
    let local_state = conflicts[0].local.as_ref().expect("local state");
    assert!(local_state.title.ends_with("-locally-edited"));
}

// =======================================================================
// Error paths
// =======================================================================

#[test]
fn merge_external_wrong_password_yields_wrong_key() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let err = local
        .merge_external(remote.path(), "totally-wrong".to_owned())
        .expect_err("should fail");
    assert!(matches!(err, VaultError::WrongKey), "got {err:?}");
}

#[test]
fn merge_external_missing_path_yields_io() {
    let (local, _ldir) = open_basic_in_temp();
    let err = local
        .merge_external("/no/such/file.kdbx".to_owned(), PASSWORD.to_owned())
        .expect_err("should fail");
    assert!(matches!(err, VaultError::Io(_)), "got {err:?}");
}

#[test]
fn merge_external_locked_vault_yields_locked() {
    let (local, _ldir, remote, _rdir) = make_pair();
    local.lock().expect("lock");
    let err = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect_err("should fail");
    assert!(matches!(err, VaultError::Locked), "got {err:?}");
}

// =======================================================================
// Read-only invariant
// =======================================================================

#[test]
fn merge_external_does_not_mutate_local_or_fire_observer() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    // Set up a conflict-bearing scenario so the merge has work to
    // describe — assert *despite* the work, no mutation/observer fires.
    let mut local_patch = EntryPatch::empty();
    local_patch.title = Some("local".to_owned());
    local
        .update_entry(target.clone(), local_patch)
        .expect("local");
    let mut remote_patch = EntryPatch::empty();
    remote_patch.title = Some("remote".to_owned());
    remote
        .update_entry(target.clone(), remote_patch)
        .expect("remote");
    remote.save().expect("remote save");

    let recorder = attach(&local);
    let entries_before = local.list_entries(None).expect("list");
    let target_title_before = local.get_entry(target.clone()).expect("get").title.clone();

    let _outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");

    let entries_after = local.list_entries(None).expect("list");
    let target_title_after = local.get_entry(target).expect("get").title.clone();

    assert_eq!(entries_before.len(), entries_after.len());
    assert_eq!(target_title_before, target_title_after);
    assert!(
        recorder.snapshot().is_empty(),
        "merge_external must not fire observer events; got {:?}",
        recorder.snapshot()
    );
}
