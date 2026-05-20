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
    AttachmentChoiceFfi, AttachmentChoiceKindFfi, AttachmentDeltaKindFfi, ConflictSideFfi,
    DeleteEditChoiceEntryFfi, DeleteEditChoiceFfi, EntryAttachmentChoiceFfi, EntryCreate,
    EntryFieldChoiceFfi, EntryPatch, FieldChoiceFfi, FieldDeltaKindFfi, ResolutionFfi, Vault,
    VaultChange, VaultError, VaultObserver,
};
use tempfile::TempDir;

const PASSWORD: &str = "tëst pässwörd 🔑/\\";

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
    let vault = Vault::new(
        dest.to_string_lossy().into_owned(),
        PASSWORD.to_owned(),
        None,
    )
    .expect("open");
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
    let local = Vault::new(local_path, PASSWORD.to_owned(), None).expect("reopen local");
    let remote = Vault::new(remote_path, PASSWORD.to_owned(), None).expect("reopen remote");
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

// =======================================================================
// Slice 7.5b — apply_merge_outcome
// =======================================================================

fn entry_field_choice(uuid: &str, key: &str, side: ConflictSideFfi) -> EntryFieldChoiceFfi {
    EntryFieldChoiceFfi::new(uuid, vec![FieldChoiceFfi::new(key, side)])
}

fn delete_edit_choice(uuid: &str, choice: DeleteEditChoiceFfi) -> DeleteEditChoiceEntryFfi {
    DeleteEditChoiceEntryFfi::new(uuid, choice)
}

#[test]
fn apply_merge_outcome_auto_applicable_disk_only() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut patch = EntryPatch::empty();
    patch.title = Some("disk-only-title".to_owned());
    remote.update_entry(target.clone(), patch).expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    local
        .apply_merge_outcome(outcome, ResolutionFfi::empty())
        .expect("apply");

    let after = local.get_entry(target).expect("get");
    assert_eq!(after.title, "disk-only-title");
}

#[test]
fn apply_merge_outcome_added_on_disk_brings_in_entry() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let group = personal_uuid(&remote);
    let new_uuid = remote
        .create_entry(EntryCreate::new("brand-new", group))
        .expect("remote create");
    remote.save().expect("remote save");
    let count_before = local.list_entries(None).expect("list").len();

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    local
        .apply_merge_outcome(outcome, ResolutionFfi::empty())
        .expect("apply");

    let after = local.list_entries(None).expect("list");
    assert_eq!(after.len(), count_before + 1);
    assert!(after.iter().any(|e| e.uuid == new_uuid));
}

#[test]
fn apply_merge_outcome_deleted_on_disk_removes_entry() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    remote.delete_entry(target.clone()).expect("remote delete");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    local
        .apply_merge_outcome(outcome, ResolutionFfi::empty())
        .expect("apply");

    let err = local.get_entry(target).expect_err("entry should be gone");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn apply_merge_outcome_entry_conflict_keep_local() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut lp = EntryPatch::empty();
    lp.title = Some("local-wins".to_owned());
    local.update_entry(target.clone(), lp).expect("local");
    let mut rp = EntryPatch::empty();
    rp.title = Some("remote-loses".to_owned());
    remote.update_entry(target.clone(), rp).expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let resolution = ResolutionFfi::new(
        vec![entry_field_choice(&target, "Title", ConflictSideFfi::Local)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    local
        .apply_merge_outcome(outcome, resolution)
        .expect("apply");

    assert_eq!(local.get_entry(target).expect("get").title, "local-wins");
}

#[test]
fn apply_merge_outcome_entry_conflict_keep_remote() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut lp = EntryPatch::empty();
    lp.title = Some("local-loses".to_owned());
    local.update_entry(target.clone(), lp).expect("local");
    let mut rp = EntryPatch::empty();
    rp.title = Some("remote-wins".to_owned());
    remote.update_entry(target.clone(), rp).expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let resolution = ResolutionFfi::new(
        vec![entry_field_choice(
            &target,
            "Title",
            ConflictSideFfi::Remote,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    local
        .apply_merge_outcome(outcome, resolution)
        .expect("apply");

    assert_eq!(local.get_entry(target).expect("get").title, "remote-wins");
}

#[test]
fn apply_merge_outcome_entry_conflict_per_field_split() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut lp = EntryPatch::empty();
    lp.title = Some("local-title".to_owned());
    lp.username = Some("local-user".to_owned());
    local.update_entry(target.clone(), lp).expect("local");
    let mut rp = EntryPatch::empty();
    rp.title = Some("remote-title".to_owned());
    rp.username = Some("remote-user".to_owned());
    remote.update_entry(target.clone(), rp).expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let resolution = ResolutionFfi::new(
        vec![EntryFieldChoiceFfi::new(
            target.clone(),
            vec![
                FieldChoiceFfi::new("Title", ConflictSideFfi::Local),
                FieldChoiceFfi::new("UserName", ConflictSideFfi::Remote),
            ],
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    local
        .apply_merge_outcome(outcome, resolution)
        .expect("apply");

    let e = local.get_entry(target).expect("get");
    assert_eq!(e.title, "local-title");
    assert_eq!(e.username, "remote-user");
}

#[test]
fn apply_merge_outcome_delete_edit_keep_local() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut lp = EntryPatch::empty();
    lp.title = Some("kept-locally".to_owned());
    local.update_entry(target.clone(), lp).expect("local edit");
    remote.delete_entry(target.clone()).expect("remote delete");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let resolution = ResolutionFfi::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![delete_edit_choice(&target, DeleteEditChoiceFfi::KeepLocal)],
    );
    local
        .apply_merge_outcome(outcome, resolution)
        .expect("apply");

    let e = local.get_entry(target).expect("survived");
    assert_eq!(e.title, "kept-locally");
}

#[test]
fn apply_merge_outcome_delete_edit_accept_remote_delete() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut lp = EntryPatch::empty();
    lp.title = Some("about-to-die".to_owned());
    local.update_entry(target.clone(), lp).expect("local edit");
    remote.delete_entry(target.clone()).expect("remote delete");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let resolution = ResolutionFfi::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![delete_edit_choice(
            &target,
            DeleteEditChoiceFfi::AcceptRemoteDelete,
        )],
    );
    local
        .apply_merge_outcome(outcome, resolution)
        .expect("apply");

    let err = local.get_entry(target).expect_err("entry should be gone");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn apply_merge_outcome_fires_bulk_merge_observer() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut patch = EntryPatch::empty();
    patch.title = Some("auto".to_owned());
    remote.update_entry(target, patch).expect("remote");
    remote.save().expect("remote save");

    let recorder = attach(&local);
    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    local
        .apply_merge_outcome(outcome, ResolutionFfi::empty())
        .expect("apply");

    let events = recorder.snapshot();
    let bulk_count = events
        .iter()
        .filter(|e| matches!(e, VaultChange::BulkMerge))
        .count();
    assert_eq!(
        bulk_count, 1,
        "expected exactly one BulkMerge; got {events:?}"
    );
}

#[test]
fn apply_merge_outcome_consumes_carrier() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut patch = EntryPatch::empty();
    patch.title = Some("once".to_owned());
    remote.update_entry(target, patch).expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    local
        .apply_merge_outcome(outcome.clone(), ResolutionFfi::empty())
        .expect("first apply");

    // Accessors return NotFound after consume.
    let summary_err = outcome.summary().expect_err("summary after consume");
    assert!(
        matches!(summary_err, VaultError::NotFound),
        "{summary_err:?}"
    );

    // Second apply on the same handle returns NotFound.
    let apply_err = local
        .apply_merge_outcome(outcome, ResolutionFfi::empty())
        .expect_err("second apply");
    assert!(matches!(apply_err, VaultError::NotFound), "{apply_err:?}");
}

#[test]
fn apply_merge_outcome_missing_resolution_yields_merge_error() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut lp = EntryPatch::empty();
    lp.title = Some("local".to_owned());
    local.update_entry(target.clone(), lp).expect("local");
    let mut rp = EntryPatch::empty();
    rp.title = Some("remote".to_owned());
    remote.update_entry(target, rp).expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let err = local
        .apply_merge_outcome(outcome, ResolutionFfi::empty())
        .expect_err("should fail");
    assert!(matches!(err, VaultError::Merge(_)), "got {err:?}");
}

#[test]
fn apply_merge_outcome_unknown_field_in_resolution_yields_merge_error() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut lp = EntryPatch::empty();
    lp.title = Some("local".to_owned());
    local.update_entry(target.clone(), lp).expect("local");
    let mut rp = EntryPatch::empty();
    rp.title = Some("remote".to_owned());
    remote.update_entry(target.clone(), rp).expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    // Resolution names a field key that isn't in field_deltas.
    let resolution = ResolutionFfi::new(
        vec![entry_field_choice(
            &target,
            "NotARealField",
            ConflictSideFfi::Local,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let err = local
        .apply_merge_outcome(outcome, resolution)
        .expect_err("should fail");
    assert!(matches!(err, VaultError::Merge(_)), "got {err:?}");
}

#[test]
fn apply_merge_outcome_locked_vault_yields_locked_without_consuming() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    let mut patch = EntryPatch::empty();
    patch.title = Some("auto".to_owned());
    remote.update_entry(target, patch).expect("remote");
    remote.save().expect("remote save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    local.lock().expect("lock");

    let err = local
        .apply_merge_outcome(outcome.clone(), ResolutionFfi::empty())
        .expect_err("should fail");
    assert!(matches!(err, VaultError::Locked), "got {err:?}");

    // Carrier still usable — accessors don't return NotFound.
    let summary = outcome.summary().expect("summary still works");
    assert_eq!(summary.disk_only_count, 1);
}

// =======================================================================
// Attachment-conflict surface (mirrors upstream B4 work)
// =======================================================================

/// Both sides edit the same-named attachment with different bytes →
/// `BothDiffer` delta surfaces on `EntryConflictFfi.attachment_deltas`,
/// and the caller can resolve via `entry_attachment_choices`.
#[test]
fn merge_external_attachment_both_differ_surfaces_delta() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    // Seed a shared attachment + save both sides so the LCA-bearing
    // history record carries the same bytes on both pools.
    local
        .add_entry_attachment(target.clone(), "note.txt".into(), b"v0".to_vec())
        .expect("local seed attach");
    remote
        .add_entry_attachment(target.clone(), "note.txt".into(), b"v0".to_vec())
        .expect("remote seed attach");
    local.save().expect("local seed save");
    remote.save().expect("remote seed save");

    // Each side then edits the attachment to its own bytes.
    local
        .add_entry_attachment(target.clone(), "note.txt".into(), b"L".to_vec())
        .expect("local edit attach");
    remote
        .add_entry_attachment(target.clone(), "note.txt".into(), b"R".to_vec())
        .expect("remote edit attach");
    remote.save().expect("remote edit save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let conflicts = outcome.entry_conflicts().expect("conflicts");
    assert_eq!(conflicts.len(), 1, "expected one entry conflict");
    let c = &conflicts[0];
    assert_eq!(c.attachment_deltas.len(), 1, "{:?}", c.attachment_deltas);
    let delta = &c.attachment_deltas[0];
    assert_eq!(delta.name, "note.txt");
    assert_eq!(delta.kind, AttachmentDeltaKindFfi::BothDiffer);
    assert!(delta.local_sha256_hex.is_some());
    assert!(delta.remote_sha256_hex.is_some());
    assert_ne!(delta.local_sha256_hex, delta.remote_sha256_hex);
    assert_eq!(delta.local_size_bytes, Some(1));
    assert_eq!(delta.remote_size_bytes, Some(1));

    // Resolve KeepRemote and apply.
    let resolution = ResolutionFfi::new(
        Vec::new(),
        vec![EntryAttachmentChoiceFfi::new(
            target.clone(),
            vec![AttachmentChoiceFfi::new(
                "note.txt",
                AttachmentChoiceKindFfi::KeepRemote,
            )],
        )],
        Vec::new(),
        Vec::new(),
    );
    local
        .apply_merge_outcome(outcome, resolution)
        .expect("apply");

    let bytes = local
        .entry_attachment_bytes(target, "note.txt".into())
        .expect("read attachment");
    assert_eq!(bytes, b"R");
}

/// `KeepBoth` resolution renames the remote-side attachment using
/// the merge crate's default pattern (`<stem> (remote).<ext>`).
#[test]
fn apply_merge_outcome_attachment_keep_both_renames_remote() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    local
        .add_entry_attachment(target.clone(), "note.txt".into(), b"v0".to_vec())
        .expect("local seed");
    remote
        .add_entry_attachment(target.clone(), "note.txt".into(), b"v0".to_vec())
        .expect("remote seed");
    local.save().expect("local seed save");
    remote.save().expect("remote seed save");

    local
        .add_entry_attachment(target.clone(), "note.txt".into(), b"L-edit".to_vec())
        .expect("local edit");
    remote
        .add_entry_attachment(target.clone(), "note.txt".into(), b"R-edit".to_vec())
        .expect("remote edit");
    remote.save().expect("remote edit save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let resolution = ResolutionFfi::new(
        Vec::new(),
        vec![EntryAttachmentChoiceFfi::new(
            target.clone(),
            vec![AttachmentChoiceFfi::new(
                "note.txt",
                AttachmentChoiceKindFfi::KeepBoth {
                    rename_override: None,
                },
            )],
        )],
        Vec::new(),
        Vec::new(),
    );
    local
        .apply_merge_outcome(outcome, resolution)
        .expect("apply");

    let local_bytes = local
        .entry_attachment_bytes(target.clone(), "note.txt".into())
        .expect("local attachment");
    assert_eq!(local_bytes, b"L-edit");
    let remote_bytes = local
        .entry_attachment_bytes(target, "note (remote).txt".into())
        .expect("remote attachment under default rename");
    assert_eq!(remote_bytes, b"R-edit");
}

/// Caller-supplied `rename_override` pins the renamed slot for the
/// remote-side attachment.
#[test]
fn apply_merge_outcome_attachment_keep_both_with_override_uses_caller_name() {
    let (local, _ldir, remote, _rdir) = make_pair();
    let target = first_entry_uuid(&local);

    local
        .add_entry_attachment(target.clone(), "note.txt".into(), b"v0".to_vec())
        .expect("local seed");
    remote
        .add_entry_attachment(target.clone(), "note.txt".into(), b"v0".to_vec())
        .expect("remote seed");
    local.save().expect("local seed save");
    remote.save().expect("remote seed save");

    local
        .add_entry_attachment(target.clone(), "note.txt".into(), b"L".to_vec())
        .expect("local edit");
    remote
        .add_entry_attachment(target.clone(), "note.txt".into(), b"R".to_vec())
        .expect("remote edit");
    remote.save().expect("remote edit save");

    let outcome = local
        .merge_external(remote.path(), PASSWORD.to_owned())
        .expect("merge");
    let resolution = ResolutionFfi::new(
        Vec::new(),
        vec![EntryAttachmentChoiceFfi::new(
            target.clone(),
            vec![AttachmentChoiceFfi::new(
                "note.txt",
                AttachmentChoiceKindFfi::KeepBoth {
                    rename_override: Some("note-from-laptop.txt".into()),
                },
            )],
        )],
        Vec::new(),
        Vec::new(),
    );
    local
        .apply_merge_outcome(outcome, resolution)
        .expect("apply");

    assert_eq!(
        local
            .entry_attachment_bytes(target.clone(), "note.txt".into())
            .expect("local"),
        b"L",
    );
    assert_eq!(
        local
            .entry_attachment_bytes(target, "note-from-laptop.txt".into())
            .expect("remote-renamed"),
        b"R",
    );
}

// Note: the upstream validation that rejects `KeepBoth` for one-sided
// deltas is exercised in `keepass-merge`'s
// `tests/attachment_conflict_resolution.rs::keep_both_rejected_for_one_sided_delta`.
// The keys-ffi marshalling layer just passes that error through as
// `VaultError::Merge`. Constructing a `LocalOnly` / `RemoteOnly`
// conflict from the FFI's `make_pair` infrastructure is awkward —
// the LCA walker needs both sides' history to agree on the attachment
// at a point in time, which the per-side mtime drift in
// `add_entry_attachment` doesn't naturally produce. The pure-Rust
// upstream tests use in-memory vault construction to set this up
// cleanly; duplicating that here would just retest upstream.
