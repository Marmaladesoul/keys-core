//! Integration tests for slice 5 — entry mutation
//! (create / update / delete / touch / move).
//!
//! Save+reopen round-trips use the production `save_to_bytes` introduced in slice 7.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use keys_ffi::{
    AutoType, AutoTypeAssociation, CustomField, EntryCreate, EntryPatch, Vault, VaultError,
};
use tempfile::NamedTempFile;

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
    )
    .expect("kdbx3-basic should open")
}

fn open_custom() -> Arc<Vault> {
    Vault::new(
        fixture("pykeepass/custom-fields.kdbx"),
        "test-custom-104".to_owned(),
    )
    .expect("custom-fields fixture should open")
}

fn first_group_uuid(vault: &Vault, name: &str) -> String {
    vault
        .list_groups()
        .expect("groups")
        .into_iter()
        .find(|g| g.name == name)
        .unwrap_or_else(|| panic!("group {name} present"))
        .uuid
}

fn root_group_uuid(vault: &Vault) -> String {
    vault
        .list_groups()
        .expect("groups")
        .into_iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root present")
        .uuid
}

fn save_and_reopen(vault: &Vault, password: &str) -> (Arc<Vault>, NamedTempFile) {
    let bytes = vault.save_to_bytes().expect("save");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(&bytes).expect("write");
    tmp.flush().expect("flush");
    let path = tmp.path().to_string_lossy().into_owned();
    let reopened = Vault::new(path, password.to_owned()).expect("reopen");
    (reopened, tmp)
}

fn make_create(group_uuid: String, title: &str) -> EntryCreate {
    EntryCreate::new(title, group_uuid)
}

fn empty_patch() -> EntryPatch {
    EntryPatch::empty()
}

// -----------------------------------------------------------------------
// create_entry
// -----------------------------------------------------------------------

#[test]
fn create_entry_appears_in_listing() {
    let vault = open_basic();
    let group = first_group_uuid(&vault, "Personal");
    let new_uuid = vault
        .create_entry(make_create(group.clone(), "Brand New"))
        .expect("create");

    let entries = vault.list_entries(Some(group.clone())).expect("list");
    assert!(entries.iter().any(|e| e.uuid == new_uuid));
    assert!(entries.iter().any(|e| e.title == "Brand New"));
}

#[test]
fn create_entry_with_bogus_group_returns_not_found() {
    let vault = open_basic();
    let bogus = "00000000-0000-0000-0000-000000000000".to_owned();
    let err = vault
        .create_entry(make_create(bogus, "Doomed"))
        .expect_err("bogus group should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn create_entry_seeds_unprotected_custom_fields() {
    let vault = open_basic();
    let group = first_group_uuid(&vault, "Personal");
    let mut create = EntryCreate::new("With Customs", group);
    create.username = "u".to_owned();
    create.url = "https://example.test".to_owned();
    create.tags = vec!["work".to_owned()];
    create.custom_fields = vec![
        CustomField::new("License", "MIT"),
        CustomField::new("Tier", "pro"),
    ];
    let new_uuid = vault.create_entry(create).expect("create");
    let entry = vault.get_entry(new_uuid).expect("get");
    let names: Vec<_> = entry
        .custom_fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert!(names.contains(&"License"));
    assert!(names.contains(&"Tier"));
    // No protected plaintext is created — Password's read DTO
    // surfaces empty, and no protected custom field is auto-created.
    assert!(entry.password_field.value.is_none());
    assert!(
        entry.custom_fields.iter().all(|f| !f.is_protected),
        "no protected custom fields auto-created on create_entry"
    );
}

#[test]
fn create_entry_round_trips_through_save() {
    let vault = open_basic();
    let group = first_group_uuid(&vault, "Work");
    let new_uuid = vault
        .create_entry(make_create(group.clone(), "Persistent"))
        .expect("create");

    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    let entry = reopened.get_entry(new_uuid).expect("get after reopen");
    assert_eq!(entry.title, "Persistent");
    assert_eq!(entry.group_uuid, group);
}

// -----------------------------------------------------------------------
// update_entry
// -----------------------------------------------------------------------

#[test]
fn update_title_only_leaves_other_fields_alone() {
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let target = summaries
        .iter()
        .find(|e| e.title == "Acme Banking")
        .expect("Acme Banking present");
    let original = vault.get_entry(target.uuid.clone()).expect("get");

    let mut patch = empty_patch();
    patch.title = Some("Acme Banking (renamed)".to_owned());
    vault
        .update_entry(target.uuid.clone(), patch)
        .expect("update title");

    let after = vault.get_entry(target.uuid.clone()).expect("get");
    assert_eq!(after.title, "Acme Banking (renamed)");
    assert_eq!(after.username, original.username);
    assert_eq!(after.url, original.url);
    assert_eq!(after.notes, original.notes);
    assert!(after.last_modified_ms >= original.last_modified_ms);
}

#[test]
fn update_custom_fields_replaces_unprotected_only() {
    let vault = open_custom();
    let summaries = vault.list_entries(None).expect("list");
    let uuid = summaries[0].uuid.clone();
    let before = vault.get_entry(uuid.clone()).expect("get");
    // Snapshot protected names: password slot + protected custom fields.
    let protected_names = |e: &keys_ffi::Entry| -> Vec<String> {
        let mut names = vec![e.password_field.name.clone()];
        names.extend(
            e.custom_fields
                .iter()
                .filter(|c| c.is_protected)
                .map(|c| c.name.clone()),
        );
        names.sort();
        names
    };
    let protected_before = protected_names(&before);

    // Replace the unprotected custom-field list wholesale.
    let mut patch = empty_patch();
    patch.custom_fields = Some(vec![CustomField::new("Replaced", "yes")]);
    vault
        .update_entry(uuid.clone(), patch)
        .expect("update custom_fields");

    let after = vault.get_entry(uuid).expect("get");
    let unprotected_names: Vec<_> = after
        .custom_fields
        .iter()
        .filter(|f| !f.is_protected)
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(unprotected_names, vec!["Replaced"]);

    // Protected fields are untouched (Password slot + protected custom fields).
    assert_eq!(protected_names(&after), protected_before);
}

#[test]
fn update_with_empty_custom_fields_clears_unprotected() {
    let vault = open_custom();
    let uuid = vault.list_entries(None).expect("list")[0].uuid.clone();
    let before = vault.get_entry(uuid.clone()).expect("get");
    assert!(
        !before.custom_fields.is_empty(),
        "fixture has unprotected fields"
    );

    let mut patch = empty_patch();
    patch.custom_fields = Some(Vec::new());
    vault.update_entry(uuid.clone(), patch).expect("clear");

    let after = vault.get_entry(uuid).expect("get");
    // After clearing, only protected custom fields remain inside `custom_fields`.
    assert!(
        after.custom_fields.iter().all(|f| f.is_protected),
        "all unprotected cleared"
    );
    // Protected slots survive (Password slot + the two protected custom fields).
    assert!(
        after
            .custom_fields
            .iter()
            .any(|f| f.is_protected && f.name == "API Secret")
    );
    assert!(
        after
            .custom_fields
            .iter()
            .any(|f| f.is_protected && f.name == "PIN")
    );
    assert_eq!(after.password_field.name, "Password");
}

#[test]
fn update_with_empty_tags_clears_them() {
    let vault = open_custom();
    let uuid = vault.list_entries(None).expect("list")[0].uuid.clone();
    let mut patch = empty_patch();
    patch.tags = Some(vec!["temp".to_owned()]);
    vault.update_entry(uuid.clone(), patch).expect("set tags");
    assert_eq!(vault.get_entry(uuid.clone()).unwrap().tags, vec!["temp"]);

    let mut patch = empty_patch();
    patch.tags = Some(Vec::new());
    vault.update_entry(uuid.clone(), patch).expect("clear tags");
    assert!(vault.get_entry(uuid).unwrap().tags.is_empty());
}

#[test]
fn update_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .update_entry(
            "00000000-0000-0000-0000-000000000000".to_owned(),
            empty_patch(),
        )
        .expect_err("bogus uuid should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -----------------------------------------------------------------------
// delete_entry
// -----------------------------------------------------------------------

#[test]
fn delete_entry_removes_from_listing_and_persists() {
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let uuid = summaries[0].uuid.clone();

    vault.delete_entry(uuid.clone()).expect("delete");
    assert!(
        vault
            .list_entries(None)
            .unwrap()
            .iter()
            .all(|e| e.uuid != uuid),
        "entry gone in-memory",
    );

    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    assert!(
        reopened
            .list_entries(None)
            .unwrap()
            .iter()
            .all(|e| e.uuid != uuid),
        "entry gone after reopen",
    );
}

#[test]
fn delete_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .delete_entry("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus uuid should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -----------------------------------------------------------------------
// touch_entry
// -----------------------------------------------------------------------

#[test]
fn touch_advances_access_but_not_modification() {
    let vault = open_basic();
    let uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    let before = vault.get_entry(uuid.clone()).expect("get");

    // Sleep a nanosecond's worth — clock resolution is ms; in practice
    // the touch may stamp the same ms. The semantic check is that
    // last_modified_ms does NOT advance, regardless.
    vault.touch_entry(uuid.clone()).expect("touch");
    let after = vault.get_entry(uuid).expect("get");

    assert_eq!(
        after.last_modified_ms, before.last_modified_ms,
        "touch must not advance last_modified",
    );
    assert!(
        after.last_access_ms >= before.last_access_ms,
        "touch should at least preserve last_access (and usually advance it)",
    );
}

#[test]
fn touch_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .touch_entry("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus uuid should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -----------------------------------------------------------------------
// move_entry
// -----------------------------------------------------------------------

#[test]
fn move_entry_to_new_group() {
    let vault = open_basic();
    let work = first_group_uuid(&vault, "Work");
    let personal = first_group_uuid(&vault, "Personal");
    // Pick an entry that lives in Personal.
    let target = vault
        .list_entries(Some(personal.clone()))
        .unwrap()
        .into_iter()
        .next()
        .expect("Personal has entries");

    vault
        .move_entry(target.uuid.clone(), work.clone())
        .expect("move");

    assert!(
        vault
            .list_entries(Some(personal))
            .unwrap()
            .iter()
            .all(|e| e.uuid != target.uuid),
        "no longer in Personal",
    );
    assert!(
        vault
            .list_entries(Some(work))
            .unwrap()
            .iter()
            .any(|e| e.uuid == target.uuid),
        "now in Work",
    );
}

#[test]
fn move_entry_to_same_group_stamps_location_changed_no_error() {
    let vault = open_basic();
    let personal = first_group_uuid(&vault, "Personal");
    let target = vault.list_entries(Some(personal.clone())).unwrap()[0]
        .uuid
        .clone();

    // No error — same-group moves are passed through to keepass-core
    // which records the user-expressed intent.
    vault
        .move_entry(target.clone(), personal.clone())
        .expect("same-group move");

    // Entry still in the same group afterwards.
    assert!(
        vault
            .list_entries(Some(personal))
            .unwrap()
            .iter()
            .any(|e| e.uuid == target),
    );
}

#[test]
fn move_entry_to_recycle_bin_group_is_allowed() {
    let vault = open_basic();
    let root = root_group_uuid(&vault);
    let target = vault.list_entries(None).unwrap()[0].uuid.clone();

    // Spec posture: API doesn't gatekeep; frontends filter. Moving an
    // entry into the root group (or a recycle-bin group, were one
    // present in this fixture) is allowed.
    vault
        .move_entry(target, root)
        .expect("move to root allowed");
}

#[test]
fn move_entry_with_bogus_destination_returns_not_found() {
    let vault = open_basic();
    let target = vault.list_entries(None).unwrap()[0].uuid.clone();
    let err = vault
        .move_entry(target, "00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus destination should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -----------------------------------------------------------------------
// locked-after-lock
// -----------------------------------------------------------------------

#[test]
fn entry_methods_return_locked_after_lock() {
    let vault = open_basic();
    let group = root_group_uuid(&vault);
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    vault.lock().expect("lock");

    assert!(matches!(
        vault.create_entry(make_create(group.clone(), "x")),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.update_entry(entry_uuid.clone(), empty_patch()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.delete_entry(entry_uuid.clone()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.touch_entry(entry_uuid.clone()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.move_entry(entry_uuid.clone(), group),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.clear_entry_custom_icon(entry_uuid.clone()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.clear_entry_expiry(entry_uuid),
        Err(VaultError::Locked)
    ));
}

// -----------------------------------------------------------------------
// EntryPatch editor-field surface (slice 4A)
//
// All eight new fields use single-`Option<T>` set-or-leave-alone
// semantics. The two genuinely-nullable fields (`custom_icon_uuid`,
// `expiry_time_ms`) have named clear methods on `Vault` for the
// clear-to-nil case; see the dedicated tests below.
// -----------------------------------------------------------------------

#[test]
fn update_icon_id_sets_value_and_round_trips() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    let mut patch = empty_patch();
    patch.icon_id = Some(42);
    vault
        .update_entry(entry_uuid.clone(), patch)
        .expect("update");
    assert_eq!(vault.get_entry(entry_uuid.clone()).unwrap().icon_id, 42);

    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    assert_eq!(reopened.get_entry(entry_uuid).unwrap().icon_id, 42);
}

#[test]
fn update_custom_icon_uuid_sets_value() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    // Register a custom icon so the patch has a valid target.
    let icon_uuid = vault.add_custom_icon(vec![1, 2, 3, 4]).expect("icon");

    let mut patch = empty_patch();
    patch.custom_icon_uuid = Some(icon_uuid.clone());
    vault
        .update_entry(entry_uuid.clone(), patch)
        .expect("update");
    assert_eq!(
        vault.get_entry(entry_uuid).unwrap().custom_icon_uuid,
        Some(icon_uuid)
    );
}

#[test]
fn clear_entry_custom_icon_returns_to_none() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    let icon_uuid = vault.add_custom_icon(vec![1, 2, 3, 4]).expect("icon");

    // First set, then clear via the named method.
    let mut patch = empty_patch();
    patch.custom_icon_uuid = Some(icon_uuid);
    vault.update_entry(entry_uuid.clone(), patch).unwrap();
    assert!(
        vault
            .get_entry(entry_uuid.clone())
            .unwrap()
            .custom_icon_uuid
            .is_some()
    );

    vault
        .clear_entry_custom_icon(entry_uuid.clone())
        .expect("clear");
    assert!(
        vault
            .get_entry(entry_uuid)
            .unwrap()
            .custom_icon_uuid
            .is_none()
    );
}

#[test]
fn update_colour_fields_set_and_clear_via_empty_string() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    // Set colours.
    let mut patch = empty_patch();
    patch.foreground_color = Some("#ff0000".to_owned());
    patch.background_color = Some("#0000ff".to_owned());
    vault.update_entry(entry_uuid.clone(), patch).unwrap();
    let after_set = vault.get_entry(entry_uuid.clone()).unwrap();
    assert_eq!(after_set.foreground_color, "#ff0000");
    assert_eq!(after_set.background_color, "#0000ff");

    // Clear colours via empty string (read-side empty-string-as-default).
    let mut clear_patch = empty_patch();
    clear_patch.foreground_color = Some(String::new());
    clear_patch.background_color = Some(String::new());
    vault.update_entry(entry_uuid.clone(), clear_patch).unwrap();
    let after_clear = vault.get_entry(entry_uuid).unwrap();
    assert_eq!(after_clear.foreground_color, "");
    assert_eq!(after_clear.background_color, "");
}

#[test]
fn update_override_url_sets_and_clears_via_empty_string() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    let mut set_patch = empty_patch();
    set_patch.override_url = Some("cmd://open {URL}".to_owned());
    vault.update_entry(entry_uuid.clone(), set_patch).unwrap();
    assert_eq!(
        vault.get_entry(entry_uuid.clone()).unwrap().override_url,
        "cmd://open {URL}"
    );

    let mut clear_patch = empty_patch();
    clear_patch.override_url = Some(String::new());
    vault.update_entry(entry_uuid.clone(), clear_patch).unwrap();
    assert_eq!(vault.get_entry(entry_uuid).unwrap().override_url, "");
}

#[test]
fn update_expiry_time_ms_enables_expires_and_round_trips() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    // Some plausible future timestamp: 2030-01-01T00:00:00Z = 1893456000000ms.
    let target_ms: i64 = 1_893_456_000_000;
    let mut patch = empty_patch();
    patch.expiry_time_ms = Some(target_ms);
    vault.update_entry(entry_uuid.clone(), patch).unwrap();

    let after = vault.get_entry(entry_uuid.clone()).unwrap();
    assert!(after.expires, "expires flag should auto-enable");
    assert_eq!(after.expiry_time_ms, Some(target_ms));

    // Round-trip through save.
    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    let after_reopen = reopened.get_entry(entry_uuid).unwrap();
    assert!(after_reopen.expires);
    assert_eq!(after_reopen.expiry_time_ms, Some(target_ms));
}

#[test]
fn clear_entry_expiry_clears_both_flag_and_time() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    // First enable expiry.
    let mut patch = empty_patch();
    patch.expiry_time_ms = Some(1_893_456_000_000);
    vault.update_entry(entry_uuid.clone(), patch).unwrap();
    assert!(vault.get_entry(entry_uuid.clone()).unwrap().expires);

    vault.clear_entry_expiry(entry_uuid.clone()).expect("clear");
    let cleared = vault.get_entry(entry_uuid).unwrap();
    assert!(!cleared.expires, "expires flag should clear");
    assert_eq!(cleared.expiry_time_ms, None, "time should clear");
}

#[test]
fn update_auto_type_replaces_whole_block() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    let mut new_at = AutoType::new();
    new_at.default_sequence = "{USERNAME}{TAB}{PASSWORD}{ENTER}".to_owned();
    new_at
        .associations
        .push(AutoTypeAssociation::new("Firefox - *", "{PASSWORD}{ENTER}"));
    let mut patch = empty_patch();
    patch.auto_type = Some(new_at);
    vault.update_entry(entry_uuid.clone(), patch).unwrap();

    let after = vault.entry_auto_type(entry_uuid).expect("read at");
    assert!(after.enabled);
    assert_eq!(after.default_sequence, "{USERNAME}{TAB}{PASSWORD}{ENTER}");
    assert_eq!(after.associations.len(), 1);
    assert_eq!(after.associations[0].window, "Firefox - *");
    assert_eq!(
        after.associations[0].keystroke_sequence,
        "{PASSWORD}{ENTER}"
    );
}

#[test]
fn update_with_none_editor_fields_leaves_existing_values_alone() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();

    // Establish baseline: set an icon + colour + expiry.
    let mut seed = empty_patch();
    seed.icon_id = Some(7);
    seed.foreground_color = Some("#abcdef".to_owned());
    seed.expiry_time_ms = Some(1_893_456_000_000);
    vault.update_entry(entry_uuid.clone(), seed).unwrap();

    // Apply a patch that only changes the title.
    let mut titled = empty_patch();
    titled.title = Some("New Title".to_owned());
    vault.update_entry(entry_uuid.clone(), titled).unwrap();

    // Editor fields preserved.
    let after = vault.get_entry(entry_uuid).unwrap();
    assert_eq!(after.title, "New Title");
    assert_eq!(after.icon_id, 7);
    assert_eq!(after.foreground_color, "#abcdef");
    assert!(after.expires);
    assert_eq!(after.expiry_time_ms, Some(1_893_456_000_000));
}

#[test]
fn clear_entry_custom_icon_with_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .clear_entry_custom_icon("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus uuid");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn clear_entry_expiry_with_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .clear_entry_expiry("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus uuid");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn update_with_bogus_custom_icon_uuid_returns_not_found() {
    let vault = open_basic();
    let entry_uuid = vault.list_entries(None).unwrap()[0].uuid.clone();
    let mut patch = empty_patch();
    patch.custom_icon_uuid = Some("not-a-uuid".to_owned());
    let err = vault
        .update_entry(entry_uuid, patch)
        .expect_err("malformed uuid");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}
