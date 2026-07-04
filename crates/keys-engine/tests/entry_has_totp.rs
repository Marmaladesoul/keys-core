//! Integration tests for the `EntrySummary.has_totp` column added in
//! migration 0005.
//!
//! Covers the bit's lifecycle:
//!   * `create_entry` with / without a TOTP custom field
//!   * `create_entry` with `otpauth://` URL
//!   * `set_protected_field` adding / replacing the TOTP slot
//!   * `set_non_protected_custom_field` adding the TOTP slot
//!   * `remove_custom_field` removing it
//!   * `update_entry` flipping the bit via URL change
//!   * All five `EntrySummary`-returning paths carry the flag
//!   * Migration backfill against a pre-migration DB

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::CustomField as KcCustomField;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, EntryUpdate, IconRef, KeyProvider, KeyProviderError, NewCustomField,
    NewEntryFields, Pagination, Predicate, RecycleBinFilter, SearchScope,
};
use secrecy::SecretString;
use uuid::Uuid;

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

fn fresh_kdbx(protector: Arc<dyn FieldProtector>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector)).expect("create")
}

fn engine_with_empty_vault() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx(protector());
    let root_uuid = kdbx.vault().root.id.0;
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, root_uuid, dir)
}

fn new_entry(title: &str) -> NewEntryFields {
    NewEntryFields {
        title: title.into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon: IconRef::Builtin(0),
        custom_fields: Vec::new(),
        tags: Vec::new(),
    }
}

fn summary_has_totp(engine: &Engine, uuid: Uuid) -> bool {
    let rows = engine
        .list_entries(None, Pagination::all())
        .expect("list_entries");
    let s = rows.into_iter().find(|s| s.uuid == uuid).expect("found");
    s.has_totp
}

// ── create_entry ───────────────────────────────────────────────────────

#[test]
fn create_entry_without_totp_field_has_flag_false() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("plain"))
        .expect("create");
    assert!(!summary_has_totp(&engine, uuid));
}

#[test]
fn create_entry_with_totp_seed_field_has_flag_true() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut fields = new_entry("with-totp");
    fields.custom_fields = vec![NewCustomField {
        name: "TOTP Seed".into(),
        value: SecretString::from("JBSWY3DPEHPK3PXP"),
        protected: true,
    }];
    let uuid = engine.create_entry(root, fields).expect("create");
    assert!(summary_has_totp(&engine, uuid));
}

#[test]
fn create_entry_with_non_protected_otp_field_has_flag_true() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut fields = new_entry("with-otp");
    fields.custom_fields = vec![NewCustomField {
        name: "otp".into(),
        value: SecretString::from("otpauth://totp/Acme?secret=JBSW"),
        protected: false,
    }];
    let uuid = engine.create_entry(root, fields).expect("create");
    assert!(summary_has_totp(&engine, uuid));
}

#[test]
fn create_entry_with_otpauth_url_has_flag_true() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut fields = new_entry("url-otp");
    fields.url = "otpauth://totp/Acme?secret=JBSW".into();
    let uuid = engine.create_entry(root, fields).expect("create");
    assert!(summary_has_totp(&engine, uuid));
}

#[test]
fn create_entry_with_unrecognised_field_name_has_flag_false() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut fields = new_entry("not-totp");
    // Case-sensitive — lowercase `totp` is not in the recognised set.
    fields.custom_fields = vec![NewCustomField {
        name: "totp".into(),
        value: SecretString::from("x"),
        protected: false,
    }];
    let uuid = engine.create_entry(root, fields).expect("create");
    assert!(!summary_has_totp(&engine, uuid));
}

// ── set_protected_field / remove_custom_field ──────────────────────────

#[test]
fn set_protected_totp_field_flips_flag_on_and_remove_flips_off() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("x")).expect("create");
    assert!(!summary_has_totp(&engine, uuid));

    engine
        .set_protected_field(uuid, "TOTP Seed", SecretString::from("JBSW"))
        .expect("set");
    assert!(summary_has_totp(&engine, uuid));

    engine
        .remove_custom_field(uuid, "TOTP Seed")
        .expect("remove");
    assert!(!summary_has_totp(&engine, uuid));
}

#[test]
fn set_non_protected_otp_field_flips_flag_on_and_remove_flips_off() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("x")).expect("create");
    assert!(!summary_has_totp(&engine, uuid));

    engine
        .set_non_protected_custom_field(uuid, "otp", "otpauth://x")
        .expect("set");
    assert!(summary_has_totp(&engine, uuid));

    engine.remove_custom_field(uuid, "otp").expect("remove");
    assert!(!summary_has_totp(&engine, uuid));
}

#[test]
fn setting_non_totp_field_does_not_flip_flag() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("x")).expect("create");
    engine
        .set_non_protected_custom_field(uuid, "Website", "example.com")
        .expect("set");
    assert!(!summary_has_totp(&engine, uuid));
    engine.remove_custom_field(uuid, "Website").expect("remove");
    assert!(!summary_has_totp(&engine, uuid));
}

#[test]
fn url_set_to_otpauth_via_update_flips_flag_on() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("x")).expect("create");
    assert!(!summary_has_totp(&engine, uuid));

    engine
        .update_entry(
            uuid,
            EntryUpdate {
                url: Some("otpauth://totp/Acme?secret=JBSW".into()),
                ..Default::default()
            },
        )
        .expect("update");
    assert!(summary_has_totp(&engine, uuid));

    engine
        .update_entry(
            uuid,
            EntryUpdate {
                url: Some("https://example.com".into()),
                ..Default::default()
            },
        )
        .expect("update");
    assert!(!summary_has_totp(&engine, uuid));
}

#[test]
fn url_flag_holds_when_custom_field_also_present() {
    // Both URL and field set → still true. Removing one source while
    // the other remains keeps the flag on.
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let mut fields = new_entry("dual");
    fields.url = "otpauth://totp/X?secret=ABC".into();
    fields.custom_fields = vec![NewCustomField {
        name: "TOTP Seed".into(),
        value: SecretString::from("JBSW"),
        protected: true,
    }];
    let uuid = engine.create_entry(root, fields).expect("create");
    assert!(summary_has_totp(&engine, uuid));

    // Drop the URL — field still flips the bit on.
    engine
        .update_entry(
            uuid,
            EntryUpdate {
                url: Some(String::new()),
                ..Default::default()
            },
        )
        .expect("update");
    assert!(summary_has_totp(&engine, uuid));

    // Now drop the field — flag clears.
    engine
        .remove_custom_field(uuid, "TOTP Seed")
        .expect("remove");
    assert!(!summary_has_totp(&engine, uuid));
}

// ── all five EntrySummary-returning paths carry the flag ───────────────

#[test]
fn all_summary_paths_carry_has_totp() {
    let (mut engine, root, _dir) = engine_with_empty_vault();

    // Entry A: with TOTP. URL gives `url_host` for search_by_service.
    let mut a = new_entry("acme-totp");
    a.url = "https://acme.example.com".into();
    a.custom_fields = vec![NewCustomField {
        name: "TOTP Seed".into(),
        value: SecretString::from("JBSW"),
        protected: true,
    }];
    let a_uuid = engine.create_entry(root, a).expect("create A");

    // Entry B: no TOTP, same host so search_by_service returns both.
    let mut b = new_entry("acme-plain");
    b.url = "https://acme.example.com/login".into();
    let b_uuid = engine.create_entry(root, b).expect("create B");

    // list_entries
    let list = engine.list_entries(None, Pagination::all()).expect("list");
    assert!(find(&list, a_uuid).has_totp);
    assert!(!find(&list, b_uuid).has_totp);

    // search
    let search = engine
        .search(
            "acme",
            SearchScope::AnyField,
            RecycleBinFilter::ExcludeRecycled,
            Pagination::all(),
        )
        .expect("search");
    assert!(find(&search, a_uuid).has_totp);
    assert!(!find(&search, b_uuid).has_totp);

    // search_by_service
    let svc = engine
        .search_by_service("acme.example.com", 10)
        .expect("search_by_service");
    assert!(find(&svc, a_uuid).has_totp);
    assert!(!find(&svc, b_uuid).has_totp);

    // entries_matching (predicate path — same backend as
    // smart_folder_entries). Title-prefix matches both.
    let matched = engine
        .entries_matching(
            &Predicate::TitleContains {
                substring: "acme".into(),
            },
            Pagination::all(),
        )
        .expect("entries_matching");
    assert!(find(&matched, a_uuid).has_totp);
    assert!(!find(&matched, b_uuid).has_totp);

    // smart_folder_entries: register a folder for the same predicate.
    let folder_id = engine
        .create_smart_folder(
            "TOTP-bearing acme",
            &Predicate::TitleContains {
                substring: "acme".into(),
            },
        )
        .expect("create folder");
    let sf = engine
        .smart_folder_entries(folder_id, Pagination::all())
        .expect("smart_folder_entries");
    assert!(find(&sf, a_uuid).has_totp);
    assert!(!find(&sf, b_uuid).has_totp);
}

fn find(rows: &[keys_engine::EntrySummary], uuid: Uuid) -> &keys_engine::EntrySummary {
    rows.iter()
        .find(|s| s.uuid == uuid)
        .expect("entry uuid in results")
}

// ── ingest path ────────────────────────────────────────────────────────

#[test]
fn ingest_from_kdbx_with_totp_fields_sets_flag() {
    // Build a KDBX containing a mix of TOTP-bearing and plain entries,
    // ingest it, and confirm `has_totp` is populated correctly. This
    // exercises the ingest-side `has_totp` computation in
    // `insert_entry`.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx(protector());

    let mut vault = kdbx.vault_with_unwrapped_protected().expect("unwrap");

    let mut totp_entry =
        keepass_core::model::Entry::empty(keepass_core::model::EntryId(Uuid::new_v4()));
    totp_entry.title = "with-totp".into();
    totp_entry
        .custom_fields
        .push(KcCustomField::new("TOTP Seed", "JBSWY3DPEHPK3PXP", true));
    let totp_uuid = totp_entry.id.0;

    let mut plain_entry =
        keepass_core::model::Entry::empty(keepass_core::model::EntryId(Uuid::new_v4()));
    plain_entry.title = "plain".into();
    let plain_uuid = plain_entry.id.0;

    let mut url_entry =
        keepass_core::model::Entry::empty(keepass_core::model::EntryId(Uuid::new_v4()));
    url_entry.title = "url-totp".into();
    url_entry.url = "otpauth://totp/Acme?secret=JBSW".into();
    let url_uuid = url_entry.id.0;

    vault.root.entries.push(totp_entry);
    vault.root.entries.push(plain_entry);
    vault.root.entries.push(url_entry);

    let mut kdbx = kdbx;
    kdbx.replace_vault(vault);

    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine.list_entries(None, Pagination::all()).expect("list");
    let totp_summary = rows.iter().find(|s| s.uuid == totp_uuid).expect("totp");
    let plain_summary = rows.iter().find(|s| s.uuid == plain_uuid).expect("plain");
    let url_summary = rows.iter().find(|s| s.uuid == url_uuid).expect("url");

    assert!(totp_summary.has_totp, "TOTP Seed field should flip flag");
    assert!(!plain_summary.has_totp, "plain entry should not");
    assert!(url_summary.has_totp, "otpauth:// URL should flip flag");
}

// ── migration backfill (raw SQL) ───────────────────────────────────────

#[test]
fn migration_0005_backfills_existing_rows() {
    // Apply migrations 1..=4, insert entry rows that exemplify the
    // three TOTP detection paths, then apply migration 5 and verify
    // the backfill flipped the right rows. We re-run `apply_pending`
    // — the runner only applies migrations strictly above the
    // recorded `schema_version`, so the partial-version setup below
    // is honoured.
    use keys_engine::migrations::MIGRATIONS;
    use rusqlite::{Connection, params};

    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (\
            version INTEGER NOT NULL PRIMARY KEY\
         )",
    )
    .expect("schema_version");

    // Apply only migrations 1..=4 manually so the DB looks like a
    // pre-0005 vault.
    for m in MIGRATIONS.iter().take_while(|m| m.version <= 4) {
        let tx = conn.transaction().expect("tx");
        tx.execute_batch(m.sql).expect("apply");
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![m.version],
        )
        .expect("record");
        tx.commit().expect("commit");
    }

    // Insert a group row (FK target for entries).
    let group_uuid = "00000000-0000-0000-0000-000000000001";
    conn.execute(
        "INSERT INTO \"group\" (uuid, parent_uuid, name, created_at, modified_at) \
         VALUES (?1, NULL, 'root', 0, 0)",
        params![group_uuid],
    )
    .expect("insert group");

    // Four entries:
    //   A: plain — should stay 0
    //   B: otpauth:// URL — should flip to 1
    //   C: protected custom field 'TOTP Seed' — should flip to 1
    //   D: non-protected custom field 'otp' — should flip to 1
    let (a, b, c, d) = (
        "10000000-0000-0000-0000-000000000001",
        "10000000-0000-0000-0000-000000000002",
        "10000000-0000-0000-0000-000000000003",
        "10000000-0000-0000-0000-000000000004",
    );
    for (uuid, url) in [
        (a, ""),
        (b, "otpauth://totp/X?secret=ABC"),
        (c, ""),
        (d, ""),
    ] {
        conn.execute(
            "INSERT INTO entry (uuid, group_uuid, url, created_at, modified_at, accessed_at) \
             VALUES (?1, ?2, ?3, 0, 0, 0)",
            params![uuid, group_uuid, url],
        )
        .expect("insert entry");
    }
    conn.execute(
        "INSERT INTO entry_protected (entry_uuid, field_name, wrapped_blob) \
         VALUES (?1, 'TOTP Seed', x'00')",
        params![c],
    )
    .expect("insert protected");
    conn.execute(
        "INSERT INTO entry_custom_field (entry_uuid, field_name, value) \
         VALUES (?1, 'otp', 'otpauth://x')",
        params![d],
    )
    .expect("insert custom");

    // Apply 0005 via the public runner.
    keys_engine::migrations::apply_pending(&mut conn).expect("apply 0005");

    let read = |uuid: &str| -> i64 {
        conn.query_row(
            "SELECT has_totp FROM entry WHERE uuid = ?1",
            params![uuid],
            |r| r.get(0),
        )
        .expect("read has_totp")
    };
    assert_eq!(read(a), 0, "plain entry has_totp should be 0");
    assert_eq!(read(b), 1, "otpauth:// URL entry has_totp should be 1");
    assert_eq!(read(c), 1, "TOTP Seed protected entry has_totp should be 1");
    assert_eq!(read(d), 1, "otp custom-field entry has_totp should be 1");
}
