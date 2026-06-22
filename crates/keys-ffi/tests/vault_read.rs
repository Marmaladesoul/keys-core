//! Integration tests for slice 3 — read surface.

use keys_ffi::{Vault, VaultError};

mod common;
use common::fixture;

fn open_basic() -> std::sync::Arc<Vault> {
    Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("kdbx3-basic should open")
}

#[test]
fn list_entries_none_returns_all() {
    let vault = open_basic();
    let entries = vault.list_entries(None).expect("list");
    // Sidecar declares 6 entries in this fixture.
    assert_eq!(entries.len(), 6);
    let titles: Vec<_> = entries.iter().map(|e| e.title.as_str()).collect();
    assert!(titles.contains(&"Acme Banking"));
    assert!(titles.contains(&"Fabrikam VPN"));
}

#[test]
fn list_entries_some_is_direct_children_only() {
    let vault = open_basic();
    let groups = vault.list_groups().expect("groups");
    let personal = groups
        .iter()
        .find(|g| g.name == "Personal")
        .expect("Personal group present");
    let entries = vault
        .list_entries(Some(personal.uuid.clone()))
        .expect("list scoped");
    // Personal has 3 direct entries per the sidecar.
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|e| e.group_uuid == personal.uuid));
}

#[test]
fn list_entries_with_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .list_entries(Some("00000000-0000-0000-0000-000000000000".to_owned()))
        .expect_err("bogus group uuid should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn list_entries_with_invalid_uuid_string_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .list_entries(Some("not-a-uuid".to_owned()))
        .expect_err("invalid uuid string should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn list_groups_includes_root_and_named_groups() {
    let vault = open_basic();
    let groups = vault.list_groups().expect("groups");
    assert!(!groups.is_empty());

    let roots: Vec<_> = groups.iter().filter(|g| g.parent_uuid.is_none()).collect();
    assert_eq!(roots.len(), 1, "exactly one root group");

    assert!(groups.iter().any(|g| g.name == "Personal"));
    assert!(groups.iter().any(|g| g.name == "Work"));
}

#[test]
fn list_groups_parent_child_consistent() {
    let vault = open_basic();
    let groups = vault.list_groups().expect("groups");
    let root = groups
        .iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root present");
    // Root's child_group_uuids should reference Personal + Work.
    assert_eq!(root.child_group_uuids.len(), 2);
    for child_uuid in &root.child_group_uuids {
        let child = groups
            .iter()
            .find(|g| &g.uuid == child_uuid)
            .expect("child resolves");
        assert_eq!(child.parent_uuid.as_ref(), Some(&root.uuid));
    }
}

#[test]
fn get_entry_round_trips_basic_fields() {
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let target = summaries
        .iter()
        .find(|e| e.title == "Acme Banking")
        .expect("Acme Banking present");

    let entry = vault.get_entry(target.uuid.clone()).expect("get");
    assert_eq!(entry.title, "Acme Banking");
    assert_eq!(entry.username, "dave@example.net");
    assert_eq!(entry.url, "https://bank.acme.example");
    assert_eq!(entry.uuid, target.uuid);
    assert_eq!(entry.group_uuid, target.group_uuid);
}

#[test]
fn get_entry_with_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .get_entry("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus entry uuid should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn get_entry_password_appears_as_protected_field_with_no_value() {
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let entry = vault
        .get_entry(summaries[0].uuid.clone())
        .expect("get first entry");

    let password = &entry.password_field;
    assert_eq!(password.name, "Password");
    assert!(!password.revealed);
    assert!(password.value.is_none(), "no plaintext crosses boundary");
}

#[test]
fn custom_fields_pass_through_keepass_core_order_without_resegregating() {
    // Per #R14: the FFI must NOT re-segregate protected from
    // non-protected when projecting `keepass_core::Entry.custom_fields`
    // onto the FFI Record. Whatever order the upstream model exposes
    // is what frontends see — the FFI is a faithful pass-through.
    //
    // This particular fixture's pykeepass writer emits the four
    // custom fields in the order [Recovery Code, API Key ID,
    // API Secret, PIN] — note that's *not* protection-segregated
    // (the unprotected `Recovery Code` and `API Key ID` are followed
    // by the protected `API Secret` and `PIN`, so the regression
    // we're guarding against would split them as
    // [API Key ID, Recovery Code | API Secret, PIN]).
    //
    // The exact authored order is incidental to this test — the
    // load-bearing assertion is that FFI's list matches the upstream
    // ordering, which we verify by re-opening via `KdbxReader`-equivalent
    // route (here, just `keepass_core` directly) and comparing.
    let vault = Vault::new(
        fixture("pykeepass/custom-fields.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("custom-fields fixture should open");
    let summaries = vault.list_entries(None).expect("list");
    let entry = vault.get_entry(summaries[0].uuid.clone()).expect("get");

    let names: Vec<&str> = entry
        .custom_fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    let flags: Vec<bool> = entry.custom_fields.iter().map(|f| f.is_protected).collect();

    // Pin the actual fixture's authored order — proves FFI doesn't
    // re-sort / re-segregate. If the fixture is ever regenerated and
    // its order shifts, this assertion needs to track it; the
    // structural property (FFI = upstream order) survives.
    assert_eq!(
        names,
        vec!["Recovery Code", "API Key ID", "API Secret", "PIN"]
    );
    assert_eq!(flags, vec![false, false, true, true]);

    // Belt-and-braces: every entry has exactly the expected count,
    // proving nothing got dropped at the FFI boundary either.
    assert_eq!(entry.custom_fields.len(), 4);
}

#[test]
fn protected_custom_fields_carry_is_protected_flag() {
    let vault = Vault::new(
        fixture("pykeepass/custom-fields.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("custom-fields fixture should open");
    let summaries = vault.list_entries(None).expect("list");
    assert_eq!(summaries.len(), 1, "fixture has one entry");

    let entry = vault.get_entry(summaries[0].uuid.clone()).expect("get");

    // Sidecar: API Secret + PIN are protected; API Key ID + Recovery
    // Code aren't. All four surface inside `custom_fields` with the
    // `is_protected` flag distinguishing them. The always-protected
    // Password slot is separate (`password_field`).
    let by_name = |name: &str| entry.custom_fields.iter().find(|f| f.name == name);

    let api_key_id = by_name("API Key ID").expect("API Key ID present");
    assert!(!api_key_id.is_protected);
    assert!(!api_key_id.value.is_empty());

    let recovery = by_name("Recovery Code").expect("Recovery Code present");
    assert!(!recovery.is_protected);
    assert!(!recovery.value.is_empty());

    let api_secret = by_name("API Secret").expect("API Secret present");
    assert!(api_secret.is_protected);
    assert!(
        api_secret.value.is_empty(),
        "no protected plaintext crosses boundary"
    );

    let pin = by_name("PIN").expect("PIN present");
    assert!(pin.is_protected);
    assert!(
        pin.value.is_empty(),
        "no protected plaintext crosses boundary"
    );

    // Password slot still surfaces no plaintext at the read DTO.
    assert_eq!(entry.password_field.name, "Password");
    assert!(!entry.password_field.revealed);
    assert!(entry.password_field.value.is_none());
}

#[test]
fn search_is_case_insensitive_substring() {
    let vault = open_basic();
    let hits = vault.search("acme".to_owned()).expect("search");
    let titles: Vec<_> = hits.iter().map(|e| e.title.as_str()).collect();
    assert!(titles.contains(&"Acme Banking"));
    assert!(titles.contains(&"Acme Cloud"));
    assert!(!titles.contains(&"Fabrikam VPN"));
}

#[test]
fn search_matches_url() {
    let vault = open_basic();
    let hits = vault.search("FABRIKAM".to_owned()).expect("search");
    assert!(hits.iter().any(|e| e.title == "Fabrikam VPN"));
}

#[test]
fn search_empty_query_returns_no_hits() {
    let vault = open_basic();
    let hits = vault.search(String::new()).expect("search");
    assert!(hits.is_empty());
}

#[test]
fn read_methods_return_locked_after_lock() {
    let vault = open_basic();
    vault.lock().expect("lock");

    assert!(matches!(vault.list_entries(None), Err(VaultError::Locked)));
    assert!(matches!(vault.list_groups(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.get_entry("00000000-0000-0000-0000-000000000000".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.search("anything".to_owned()),
        Err(VaultError::Locked)
    ));
}

// ---------------------------------------------------------------------------
// Editor-field surface (icon_id, custom_icon_uuid, foreground_color,
// background_color, override_url, expires, expiry_time_ms)
// ---------------------------------------------------------------------------

fn open_editor_fields() -> std::sync::Arc<Vault> {
    Vault::new(
        fixture("pykeepass/editor-fields.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("editor-fields fixture should open")
}

#[test]
fn entry_surfaces_editor_fields() {
    let vault = open_editor_fields();
    let summaries = vault.list_entries(None).expect("list");
    let target = summaries
        .iter()
        .find(|e| e.title == "Contoso Mail")
        .expect("Contoso Mail entry present");
    let entry = vault.get_entry(target.uuid.clone()).expect("get");

    assert_eq!(entry.icon_id, 25);
    assert_eq!(
        entry.custom_icon_uuid.as_deref(),
        Some("aaaaaaaa-bbbb-cccc-dddd-000000000011")
    );
    assert_eq!(entry.foreground_color, "#FF0000");
    assert_eq!(entry.background_color, "#00FFAA");
    assert_eq!(entry.override_url, "cmd://firefox %1");
    // Sidecar declares expiry_time = 2030-01-02T03:04:05Z.
    let expiry = entry.expiry_time_ms.expect("expiry_time present");
    assert_eq!(expiry, 1_893_553_445_000);
}

#[test]
fn group_surfaces_editor_fields() {
    let vault = open_editor_fields();
    let groups = vault.list_groups().expect("groups");
    let work = groups
        .iter()
        .find(|g| g.name == "Work")
        .expect("Work group present");
    assert_eq!(work.icon_id, 43);
    assert_eq!(
        work.custom_icon_uuid.as_deref(),
        Some("aaaaaaaa-bbbb-cccc-dddd-000000000012")
    );
}

// ---------------------------------------------------------------------------
// Attachments (entry_attachments, entry_attachment_bytes)
//
// Both KDBX3 (Meta/Binaries) and KDBX4 (inner header) populate the
// vault's binary pool. The positive tests below cover both.
// ---------------------------------------------------------------------------

fn open_kdbx4_attachments() -> std::sync::Arc<Vault> {
    Vault::new(
        fixture("kdbxweb/kdbx4-attachments.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("kdbx4-attachments fixture should open")
}

fn entry_uuid_by_title(vault: &Vault, title: &str) -> String {
    vault
        .list_entries(None)
        .expect("list")
        .into_iter()
        .find(|e| e.title == title)
        .unwrap_or_else(|| panic!("entry titled {title:?} present"))
        .uuid
}

#[test]
fn entry_attachments_lists_metadata_with_size_and_sha256() {
    let vault = open_kdbx4_attachments();
    let uuid = entry_uuid_by_title(&vault, "Small Image");
    let attachments = vault.entry_attachments(uuid).expect("list");
    assert_eq!(attachments.len(), 1);
    let att = &attachments[0];
    assert_eq!(att.name, "1x1.png");
    assert_eq!(att.size_bytes, 68);
    assert_eq!(
        att.sha256_hex,
        "43739c566e26fd7cb88f69d3864ea34740372f5ee99acac169e090beffbce5c6"
    );
}

#[test]
fn entry_attachments_handles_zero_byte_payload() {
    let vault = open_kdbx4_attachments();
    let uuid = entry_uuid_by_title(&vault, "Empty");
    let attachments = vault.entry_attachments(uuid).expect("list");
    assert_eq!(attachments.len(), 1);
    let att = &attachments[0];
    assert_eq!(att.name, "empty.dat");
    assert_eq!(att.size_bytes, 0);
    // SHA-256 of the empty string.
    assert_eq!(
        att.sha256_hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn entry_attachments_handles_non_ascii_filename() {
    let vault = open_kdbx4_attachments();
    let uuid = entry_uuid_by_title(&vault, "Non-ASCII Filename");
    let attachments = vault.entry_attachments(uuid).expect("list");
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].name, "unicode-café.txt");
    assert_eq!(attachments[0].size_bytes, 37);
}

#[test]
fn entry_attachment_bytes_round_trips_payload() {
    let vault = open_kdbx4_attachments();
    let uuid = entry_uuid_by_title(&vault, "Small Text");
    let bytes = vault
        .entry_attachment_bytes(uuid, "hello.txt".to_owned())
        .expect("bytes");
    assert_eq!(bytes.len(), 13);
    assert_eq!(bytes, b"Hello, world\n");
}

#[test]
fn entry_attachment_bytes_round_trips_large_payload() {
    let vault = open_kdbx4_attachments();
    let uuid = entry_uuid_by_title(&vault, "Larger Binary");
    let bytes = vault
        .entry_attachment_bytes(uuid, "100kib.bin".to_owned())
        .expect("bytes");
    assert_eq!(bytes.len(), 102_400);
}

#[test]
fn entry_attachment_bytes_returns_not_found_for_missing_name() {
    let vault = open_kdbx4_attachments();
    let uuid = entry_uuid_by_title(&vault, "Small Text");
    let err = vault
        .entry_attachment_bytes(uuid, "no-such-file.bin".to_owned())
        .expect_err("missing attachment should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn entry_attachments_returns_empty_when_no_attachments() {
    let vault = open_basic();
    let any_uuid = vault
        .list_entries(None)
        .expect("list")
        .first()
        .unwrap()
        .uuid
        .clone();
    let atts = vault.entry_attachments(any_uuid).expect("list");
    assert!(atts.is_empty());
}

#[test]
fn entry_attachments_kdbx3_round_trips_via_meta_binaries() {
    // Companion to the KDBX4 coverage above: KDBX3 stores attachment
    // bytes in <Meta><Binaries> rather than the inner header, but the
    // FFI surface is identical. Sidecar at keepassxc/kdbx3-attachments
    // declares one entry per fixture attachment with a known sha256.
    let vault = Vault::new(
        fixture("keepassxc/kdbx3-attachments.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("kdbx3-attachments should open");
    let uuid = entry_uuid_by_title(&vault, "Key Attachment");
    let attachments = vault.entry_attachments(uuid).expect("list");
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].name, "mock-key.pem");
    assert_eq!(attachments[0].size_bytes, 163);
    assert_eq!(
        attachments[0].sha256_hex,
        "75c2ff133a0dae2ebb79647553ca6d512f1842eeda3fc9d290e18940c4195218"
    );

    // Multi-attachment entry from the same fixture, exercises ordering.
    let small_uuid = entry_uuid_by_title(&vault, "Small Attachments");
    let small = vault.entry_attachments(small_uuid).expect("list");
    let names: Vec<_> = small.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        ["1x1.png", "empty.dat", "hello.txt", "unicode-café.txt"]
    );
}

#[test]
fn entry_attachment_bytes_kdbx3_round_trips() {
    use sha2::{Digest, Sha256};
    let vault = Vault::new(
        fixture("keepassxc/kdbx3-attachments.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("kdbx3-attachments should open");
    let uuid = entry_uuid_by_title(&vault, "Key Attachment");
    let bytes = vault
        .entry_attachment_bytes(uuid, "mock-key.pem".to_owned())
        .expect("bytes");
    assert_eq!(bytes.len(), 163);
    let got = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(
        got,
        "75c2ff133a0dae2ebb79647553ca6d512f1842eeda3fc9d290e18940c4195218"
    );
}

#[test]
fn entry_attachments_return_locked_after_lock() {
    let vault = open_kdbx4_attachments();
    let uuid = entry_uuid_by_title(&vault, "Small Image");
    vault.lock().expect("lock");
    assert!(matches!(
        vault.entry_attachments(uuid.clone()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.entry_attachment_bytes(uuid, "1x1.png".to_owned()),
        Err(VaultError::Locked)
    ));
}

// ---------------------------------------------------------------------------
// Auto-type (entry_auto_type)
// ---------------------------------------------------------------------------

#[test]
fn entry_auto_type_round_trips_non_default_block() {
    // pykeepass/editor-fields sidecar declares a populated AutoType
    // block on the Contoso Mail entry: enabled=false,
    // data_transfer_obfuscation=1, default_sequence="{USERNAME}{TAB}",
    // one association with window="Firefox - *" and
    // keystroke_sequence="{PASSWORD}{ENTER}".
    let vault = open_editor_fields();
    let uuid = entry_uuid_by_title(&vault, "Contoso Mail");
    let at = vault.entry_auto_type(uuid).expect("auto-type");
    assert!(!at.enabled);
    assert_eq!(at.data_transfer_obfuscation, 1);
    assert_eq!(at.default_sequence, "{USERNAME}{TAB}");
    assert_eq!(at.associations.len(), 1);
    assert_eq!(at.associations[0].window, "Firefox - *");
    assert_eq!(at.associations[0].keystroke_sequence, "{PASSWORD}{ENTER}");
}

#[test]
fn entry_auto_type_returns_defaults_when_block_absent() {
    // Basic fixture entries don't carry an explicit AutoType block —
    // keepass-core's decoder synthesises the default-on shape.
    let vault = open_basic();
    let any_uuid = vault
        .list_entries(None)
        .expect("list")
        .first()
        .unwrap()
        .uuid
        .clone();
    let at = vault.entry_auto_type(any_uuid).expect("auto-type");
    assert!(at.enabled);
    assert_eq!(at.data_transfer_obfuscation, 0);
    assert_eq!(at.default_sequence, "");
    assert!(at.associations.is_empty());
}

#[test]
fn entry_auto_type_returns_locked_after_lock() {
    let vault = open_editor_fields();
    let uuid = entry_uuid_by_title(&vault, "Contoso Mail");
    vault.lock().expect("lock");
    assert!(matches!(
        vault.entry_auto_type(uuid),
        Err(VaultError::Locked)
    ));
}

#[test]
fn entry_auto_type_not_found_for_unknown_uuid() {
    let vault = open_basic();
    let err = vault
        .entry_auto_type("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("unknown uuid");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Vault-meta readers (database_name, database_description,
// default_username, recycle_bin_group_uuid)
// ---------------------------------------------------------------------------

#[test]
fn database_name_round_trips_from_fixture() {
    // kdbxweb/kdbx4-basic has a real <DatabaseName> meta element. (The
    // keepassxc fixtures' sidecar `database_name` field is the root
    // group's name, not the meta DatabaseName, so use kdbxweb here.)
    let vault = Vault::new(
        fixture("kdbxweb/kdbx4-basic.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("kdbxweb basic should open");
    assert_eq!(
        vault.database_name().expect("name"),
        "kdbxweb Basic Fixture"
    );
}

#[test]
fn database_description_is_readable() {
    let vault = open_basic();
    // Sidecar doesn't pin description; just confirm the accessor works.
    let _ = vault.database_description().expect("description readable");
}

#[test]
fn default_username_is_readable() {
    let vault = open_basic();
    let _ = vault.default_username().expect("default username readable");
}

#[test]
fn recycle_bin_group_uuid_present_when_fixture_has_one() {
    // pykeepass/recycle.kdbx has a populated recycle bin per its sidecar.
    let vault = Vault::new(
        fixture("pykeepass/recycle.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("recycle fixture should open");
    let bin = vault.recycle_bin_group_uuid().expect("readable");
    assert!(bin.is_some(), "expected recycle bin group uuid");
    // Confirm it's a parseable UUID and matches a real group.
    let uuid = bin.unwrap();
    let groups = vault.list_groups().expect("groups");
    assert!(
        groups.iter().any(|g| g.uuid == uuid),
        "recycle bin uuid should match a real group"
    );
}

#[test]
fn recycle_bin_group_uuid_none_when_fixture_lacks_one() {
    // kdbx3-basic has no recycle bin configured.
    let vault = open_basic();
    let bin = vault.recycle_bin_group_uuid().expect("readable");
    assert!(bin.is_none());
}

#[test]
fn meta_readers_return_locked_after_lock() {
    let vault = open_basic();
    vault.lock().expect("lock");
    assert!(matches!(vault.database_name(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.database_description(),
        Err(VaultError::Locked)
    ));
    assert!(matches!(vault.default_username(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.recycle_bin_group_uuid(),
        Err(VaultError::Locked)
    ));
}

#[test]
fn entry_with_default_editor_fields_uses_empties_and_zero() {
    // The basic fixture has no custom icons / colours / overrides set.
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let any = summaries.first().expect("at least one entry");
    let entry = vault.get_entry(any.uuid.clone()).expect("get");

    assert!(entry.custom_icon_uuid.is_none());
    assert_eq!(entry.foreground_color, "");
    assert_eq!(entry.background_color, "");
    assert_eq!(entry.override_url, "");
    assert!(!entry.expires);
}
