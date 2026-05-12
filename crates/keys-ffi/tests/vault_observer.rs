//! Integration tests for slice 9 — observer callbacks.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use keys_ffi::{EntryCreate, EntryPatch, GroupPatch, Vault, VaultChange, VaultObserver};

fn fixture(rel: &str) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../../../KeepassCore/tests/fixtures")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

fn open_basic() -> Arc<Vault> {
    Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "test-basic-002".to_owned(),
        None,
    )
    .expect("open")
}

/// Test observer that records every change for later assertions.
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

fn make_recorder(vault: &Vault) -> Arc<Recorder> {
    let r = Arc::new(Recorder::default());
    let trait_obj: Arc<dyn VaultObserver> = r.clone();
    vault.set_observer(trait_obj);
    r
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

// =======================================================================
// Wiring matrix
// =======================================================================

#[test]
fn create_entry_fires_entry_modified() {
    let vault = open_basic();
    let recorder = make_recorder(&vault);
    let group = personal_uuid(&vault);

    let new_uuid = vault
        .create_entry(EntryCreate::new("New", group))
        .expect("create");

    let events = recorder.snapshot();
    assert_eq!(events.len(), 1, "exactly one event");
    matches!(
        &events[0],
        VaultChange::EntryModified { uuid } if uuid == &new_uuid,
    );
}

#[test]
fn update_entry_fires_entry_modified() {
    let vault = open_basic();
    let uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    let recorder = make_recorder(&vault);

    let mut patch = EntryPatch::empty();
    patch.title = Some("renamed".to_owned());
    vault.update_entry(uuid.clone(), patch).expect("update");

    let events = recorder.snapshot();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        VaultChange::EntryModified { uuid: u } if u == &uuid,
    ));
}

#[test]
fn delete_entry_fires_entry_deleted() {
    let vault = open_basic();
    let uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    let recorder = make_recorder(&vault);

    vault.delete_entry(uuid.clone()).expect("delete");

    let events = recorder.snapshot();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        VaultChange::EntryDeleted { uuid: u } if u == &uuid,
    ));
}

#[test]
fn touch_entry_fires_no_event() {
    let vault = open_basic();
    let uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    let recorder = make_recorder(&vault);

    vault.touch_entry(uuid).expect("touch");

    assert!(recorder.snapshot().is_empty(), "touch is silent");
}

#[test]
fn move_entry_fires_entry_modified() {
    let vault = open_basic();
    let uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    let work = vault
        .list_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.name == "Work")
        .unwrap()
        .uuid;
    let recorder = make_recorder(&vault);

    vault.move_entry(uuid.clone(), work).expect("move");

    let events = recorder.snapshot();
    assert!(matches!(
        &events[0],
        VaultChange::EntryModified { uuid: u } if u == &uuid,
    ));
}

#[test]
fn create_group_fires_group_changed() {
    let vault = open_basic();
    let recorder = make_recorder(&vault);

    let new_uuid = vault
        .create_group("Sub".to_owned(), Some(personal_uuid(&vault)))
        .expect("create_group");

    let events = recorder.snapshot();
    assert!(matches!(
        &events[0],
        VaultChange::GroupChanged { uuid } if uuid == &new_uuid,
    ));
}

#[test]
fn update_group_fires_group_changed() {
    let vault = open_basic();
    let target = personal_uuid(&vault);
    let recorder = make_recorder(&vault);

    let mut patch = GroupPatch::empty();
    patch.name = Some("Personal X".to_owned());
    vault.update_group(target.clone(), patch).expect("update");

    let events = recorder.snapshot();
    assert!(matches!(
        &events[0],
        VaultChange::GroupChanged { uuid } if uuid == &target,
    ));
}

#[test]
fn save_fires_saved() {
    use std::fs;
    use tempfile::TempDir;
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("v.kdbx");
    fs::copy(fixture("keepassxc/kdbx3-basic.kdbx"), &dest).unwrap();
    let vault = Vault::new(
        dest.to_string_lossy().into_owned(),
        "test-basic-002".to_owned(),
        None,
    )
    .unwrap();
    let recorder = make_recorder(&vault);

    vault.save().expect("save");

    let events = recorder.snapshot();
    assert!(events.iter().any(|e| matches!(e, VaultChange::Saved)));
}

#[test]
fn lock_fires_locked_then_clears_observer() {
    let vault = open_basic();
    let recorder = make_recorder(&vault);

    vault.lock().expect("lock");

    let events = recorder.snapshot();
    assert!(matches!(events.last(), Some(VaultChange::Locked)));

    // Subsequent activity (not that the locked vault accepts much) —
    // re-set an observer and verify lock left observer cleared. We
    // can't mutate post-lock anyway, but the structural check still
    // holds: the recorder we registered shouldn't see anything new.
    let count_before = recorder.snapshot().len();
    let _ = vault.lock(); // idempotent, second call should not double-fire
    assert_eq!(
        recorder.snapshot().len(),
        count_before,
        "observer cleared after Locked — second lock fires nothing",
    );
}

#[test]
fn clear_observer_silences_subsequent_events() {
    let vault = open_basic();
    let uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    let recorder = make_recorder(&vault);

    let mut patch = EntryPatch::empty();
    patch.title = Some("first".to_owned());
    vault.update_entry(uuid.clone(), patch).expect("update");
    assert_eq!(recorder.snapshot().len(), 1);

    vault.clear_observer();

    let mut patch = EntryPatch::empty();
    patch.title = Some("second".to_owned());
    vault.update_entry(uuid, patch).expect("second update");
    assert_eq!(
        recorder.snapshot().len(),
        1,
        "post-clear update fires nothing",
    );
}

#[test]
fn set_observer_replaces_previous() {
    let vault = open_basic();
    let uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    let first = Arc::new(Recorder::default());
    vault.set_observer(first.clone() as Arc<dyn VaultObserver>);
    let second = Arc::new(Recorder::default());
    vault.set_observer(second.clone() as Arc<dyn VaultObserver>);

    let mut patch = EntryPatch::empty();
    patch.title = Some("only second sees this".to_owned());
    vault.update_entry(uuid, patch).expect("update");

    assert!(first.snapshot().is_empty());
    assert_eq!(second.snapshot().len(), 1);
}

// =======================================================================
// Reentrancy
// =======================================================================

/// An observer that calls back into the vault inside `on_change`.
/// Must not deadlock — the vault's inner lock is dropped before
/// dispatch.
struct Reentering {
    vault: Mutex<Option<Arc<Vault>>>,
    saw_count: Mutex<usize>,
}

impl VaultObserver for Reentering {
    fn on_change(&self, _change: VaultChange) {
        if let Some(v) = self.vault.lock().unwrap().as_ref().cloned() {
            // Read-only call back into the vault. Would deadlock if
            // dispatch happened under the inner mutex.
            let count = v.list_entries(None).expect("reenter list_entries").len();
            *self.saw_count.lock().unwrap() = count;
        }
    }
}

#[test]
fn observer_reentry_does_not_deadlock() {
    let vault = open_basic();
    let uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    let observer = Arc::new(Reentering {
        vault: Mutex::new(Some(vault.clone())),
        saw_count: Mutex::new(0),
    });
    vault.set_observer(observer.clone() as Arc<dyn VaultObserver>);

    let mut patch = EntryPatch::empty();
    patch.title = Some("reenter".to_owned());
    vault.update_entry(uuid, patch).expect("update");

    let saw = *observer.saw_count.lock().unwrap();
    assert!(
        saw > 0,
        "observer's reentrant list_entries returned > 0 entries",
    );
}
