//! Integration tests for Phase 4 task 4.7 — conflict-resolution apply.
//!
//! Covers `Engine::apply_conflict_resolution` end to end: the happy-
//! path resolution outcomes (keep-local / take-remote / mixed /
//! custom-field choice / attachment / icon / delete-vs-edit), the
//! stash-consumption contract (`NotFound` on second apply, on missing
//! id, on mismatched entry), atomicity on failure, event emission,
//! and common-ancestor refresh.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomFieldValue, EntryId, HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    AttachmentChoice, ChangeEvent, ConflictResolution, ConflictSide, DataChangeObserver, DbKey,
    DeleteEditChoice, Engine, EngineError, KeyProvider, KeyProviderError, MergeResult,
    ParkConflictsResult,
};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

// ── Fixtures ──────────────────────────────────────────────────────────

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

#[derive(Default, Debug)]
struct CaptureObserver {
    events: Mutex<Vec<ChangeEvent>>,
}

impl CaptureObserver {
    fn snapshot(&self) -> Vec<ChangeEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl DataChangeObserver for CaptureObserver {
    fn on_event(&self, event: ChangeEvent) {
        self.events.lock().unwrap().push(event);
    }
}

/// Shared seeded fixture: one entry under the root, both engine and
/// disk in sync at start.
struct Fixture {
    _dir: tempfile::TempDir,
    kdbx_path: std::path::PathBuf,
    engine: Engine,
    seed_uuid: Uuid,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let seed_id = kdbx
        .add_entry(
            root,
            NewEntry::new("seed")
                .username("alice")
                .password(SecretString::new("orig-pw".into())),
        )
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
        seed_uuid: seed_id.0,
    }
}

/// Drive a Title-field conflict: engine edits Title to `local`, disk
/// edits to `disk`, reconcile detects the conflict and stashes it.
/// Returns the stash id.
fn drive_title_conflict(f: &mut Fixture, local_title: &str, disk_title: &str) -> i64 {
    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                title: Some(local_title.into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    let mut external = reopen_kdbx(&f.kdbx_path);
    let disk_title_owned = disk_title.to_string();
    external
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title(disk_title_owned.clone());
        })
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");
    match result {
        MergeResult::Conflict(payload) => payload.id,
        other => panic!("expected Conflict, got {other:?}"),
    }
}

/// Build a `Resolution` that resolves the single Title-field conflict
/// on `seed_uuid` with the given side.
fn title_resolution(seed_uuid: Uuid, side: ConflictSide) -> ConflictResolution {
    let mut fields: HashMap<String, ConflictSide> = HashMap::new();
    fields.insert("Title".into(), side);
    let mut resolution = ConflictResolution::default();
    resolution
        .entry_field_choices
        .insert(EntryId(seed_uuid), fields);
    resolution
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn apply_resolution_with_take_remote_all_fields() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local-title", "disk-title");

    f.engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Remote))
        .expect("apply remote");

    let after = f
        .engine
        .entry(f.seed_uuid)
        .expect("entry")
        .expect("present");
    assert_eq!(after.title, "disk-title", "remote side won");
}

/// Phase 2b: resolving writes a `keys.conflict_resolutions.v1` record into
/// the vault Meta so the decision propagates to peers (design §5.3). The
/// record is secret-safe — it carries the facet identity (entry, kind,
/// key) and a timestamp, but **no value and no winning side**.
#[test]
fn apply_resolution_writes_conflict_resolution_record_to_meta() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local-title", "disk-title");

    f.engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Remote))
        .expect("apply remote");

    // Persist the resolved state so the record (now in the engine's SQLite
    // Meta) projects into the KDBX that iroh would sync.
    let mut handle = reopen_kdbx(&f.kdbx_path);
    f.engine
        .save_to_kdbx(&f.kdbx_path, &mut handle, None)
        .expect("save resolved");

    // Reopen from disk and assert the record landed in Meta.
    let reopened = reopen_kdbx(&f.kdbx_path);
    let records = keepass_merge::parse_conflict_resolutions(&reopened.vault().meta.custom_data)
        .expect("parse resolutions");
    let rec = records
        .iter()
        .find(|r| r.entry == f.seed_uuid && r.kind == keepass_merge::ConflictKind::Field)
        .expect("a Field resolution for the seed entry");
    assert_eq!(
        rec.key.as_deref(),
        Some("Title"),
        "names the resolved field"
    );
    assert!(rec.by.is_none(), "pre-P2P resolutions carry no `by`");
}

/// Phase 3: a **held** (parked) conflict is resolvable through the same
/// `apply_conflict_resolution` entry point as the live path. The
/// non-blocking park reconcile holds the conflict (keeping local, setting
/// the badge); `held_conflict_payload` rebuilds the rich payload + a
/// resolvable stash on demand — even though the byte-equiv short-circuit
/// would make a plain reconcile a no-op; applying converges to the chosen
/// value, clears the badge, and writes the propagating record.
#[test]
fn held_conflict_payload_enables_parked_resolution() {
    let mut f = fixture();

    // Hold a title conflict via the non-blocking park path.
    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-title".into()),
                ..Default::default()
            },
        )
        .expect("local edit");
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title("disk-title");
        })
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    match f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("park")
    {
        ParkConflictsResult::Applied { parked, .. } => assert_eq!(
            parked.entries_with_parked_conflict,
            vec![f.seed_uuid.to_string()],
        ),
        other => panic!("expected Applied, got {other:?}"),
    }
    // Hold-open kept local; badge shows.
    assert_eq!(
        f.engine.entry(f.seed_uuid).unwrap().unwrap().title,
        "local-title",
    );
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("badge"),
        vec![f.seed_uuid],
    );

    // Resolver-open: rebuild the rich payload + stash on demand.
    let payload = f
        .engine
        .held_conflict_payload(&f.kdbx_path, &composite())
        .expect("derive")
        .expect("a held conflict is present");
    assert_eq!(payload.entry_conflicts.len(), 1, "one held entry surfaced");

    // Resolve to the remote side through the unified entry point.
    f.engine
        .apply_conflict_resolution(
            payload.id,
            &title_resolution(f.seed_uuid, ConflictSide::Remote),
        )
        .expect("apply");

    // Converged to the disk value and the badge cleared.
    assert_eq!(
        f.engine.entry(f.seed_uuid).unwrap().unwrap().title,
        "disk-title",
        "resolved to the chosen (remote) value",
    );
    assert!(
        f.engine
            .entries_with_parked_conflict()
            .expect("badge")
            .is_empty(),
        "badge cleared after parked resolution",
    );
}

#[test]
fn apply_resolution_with_keep_local_all_fields() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local-title", "disk-title");

    f.engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Local))
        .expect("apply local");

    let after = f
        .engine
        .entry(f.seed_uuid)
        .expect("entry")
        .expect("present");
    assert_eq!(after.title, "local-title", "local side preserved");
}

#[test]
fn apply_resolution_mixed_choices() {
    // Two-field conflict: Title (pick Local), URL (pick Remote).
    let mut f = fixture();

    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-title".into()),
                url: Some("https://local.example".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title("disk-title");
            e.set_url("https://disk.example");
        })
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let id = match f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile")
    {
        MergeResult::Conflict(p) => p.id,
        other => panic!("expected Conflict, got {other:?}"),
    };

    let mut fields: HashMap<String, ConflictSide> = HashMap::new();
    fields.insert("Title".into(), ConflictSide::Local);
    fields.insert("URL".into(), ConflictSide::Remote);
    let mut resolution = ConflictResolution::default();
    resolution
        .entry_field_choices
        .insert(EntryId(f.seed_uuid), fields);

    f.engine
        .apply_conflict_resolution(id, &resolution)
        .expect("apply mixed");

    let after = f
        .engine
        .entry(f.seed_uuid)
        .expect("entry")
        .expect("present");
    assert_eq!(after.title, "local-title", "local Title preserved");
    assert_eq!(after.url, "https://disk.example", "remote URL applied");
}

#[test]
fn apply_resolution_with_custom_field_choice() {
    // A custom-field conflict: both sides edit a custom field
    // differently. `ConflictSide` already supports Local / Remote
    // semantics; there's no `Custom(String)` variant in
    // keepass-merge's resolution surface (the user picks a side, and
    // can edit either side beforehand to inject their bespoke value).
    // This test exercises the custom-field key path through apply.
    let mut f = fixture();

    // Seed the field on both sides via a save round-trip so the
    // engine and disk agree on the LCA.
    f.engine
        .set_non_protected_custom_field(f.seed_uuid, "Server", "local-server")
        .expect("seed custom field");
    let mut sync_kdbx = reopen_kdbx(&f.kdbx_path);
    f.engine
        .save_to_kdbx(&f.kdbx_path, &mut sync_kdbx, None)
        .expect("sync save");
    let sync_reread = reopen_kdbx(&f.kdbx_path);
    f.engine.ingest_from_kdbx(&sync_reread).expect("re-ingest");

    // Local edit: bump title (reconcile's cheap-equivalence check
    // only compares standard fields) and edit the custom field.
    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-cf".into()),
                ..Default::default()
            },
        )
        .expect("local title");
    f.engine
        .set_non_protected_custom_field(f.seed_uuid, "Server", "local-edited")
        .expect("local edit");

    // Disk edit: bump title and edit the same custom field.
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title("disk-cf");
            e.set_custom_field("Server", CustomFieldValue::Plain("disk-edited".into()));
        })
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let id = match f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile")
    {
        MergeResult::Conflict(p) => p.id,
        other => panic!("expected Conflict, got {other:?}"),
    };

    let mut fields: HashMap<String, ConflictSide> = HashMap::new();
    fields.insert("Server".into(), ConflictSide::Remote);
    fields.insert("Title".into(), ConflictSide::Remote);
    let mut resolution = ConflictResolution::default();
    resolution
        .entry_field_choices
        .insert(EntryId(f.seed_uuid), fields);

    f.engine
        .apply_conflict_resolution(id, &resolution)
        .expect("apply custom field");

    // Inspect via project_to_vault so we don't depend on the
    // reveal path (which is for protected fields only).
    let vault = f.engine.project_to_vault().expect("project");
    let mut found_value: Option<String> = None;
    walk_for_custom_field(&vault.root, f.seed_uuid, "Server", &mut found_value);
    assert_eq!(found_value.as_deref(), Some("disk-edited"));
}

fn walk_for_custom_field(
    g: &keepass_core::model::Group,
    target: Uuid,
    key: &str,
    out: &mut Option<String>,
) {
    for e in &g.entries {
        if e.id.0 == target {
            for cf in &e.custom_fields {
                if cf.key == key {
                    *out = Some(cf.value.clone());
                }
            }
        }
    }
    for sub in &g.groups {
        walk_for_custom_field(sub, target, key, out);
    }
}

#[test]
fn apply_resolution_handles_attachment_conflicts() {
    // Both sides attach a file under the same name with different
    // bytes; the conflict surfaces as a BothDiffer attachment delta.
    // Picking KeepRemote drops the local bytes and keeps the disk
    // bytes.
    let mut f = fixture();

    // Local edit: bump the title (so reconcile's cheap-equivalence
    // check doesn't short-circuit to NoChange — it only compares
    // standard fields, not attachments) and attach bytes.
    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-att".into()),
                ..Default::default()
            },
        )
        .expect("local title");
    f.engine
        .attach_file(f.seed_uuid, "report.bin", b"local-bytes".to_vec())
        .expect("local attach");

    // Disk edit: bump the title too and attach under the same name
    // with different bytes. The title conflict will surface as a
    // field_delta; the attachment conflict as an attachment_delta.
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title("disk-att");
            e.attach("report.bin", b"disk-bytes".to_vec(), false);
        })
        .expect("disk attach");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let (id, attachment_name) = match f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile")
    {
        MergeResult::Conflict(p) => {
            assert_eq!(p.entry_conflicts.len(), 1);
            let conflict = &p.entry_conflicts[0];
            let delta = conflict
                .attachment_deltas
                .first()
                .expect("attachment delta");
            (p.id, delta.name.clone())
        }
        other => panic!("expected Conflict, got {other:?}"),
    };

    let mut atts: HashMap<String, AttachmentChoice> = HashMap::new();
    atts.insert(attachment_name, AttachmentChoice::KeepRemote);
    let mut resolution = ConflictResolution::default();
    resolution
        .entry_attachment_choices
        .insert(EntryId(f.seed_uuid), atts);
    let mut fields: HashMap<String, ConflictSide> = HashMap::new();
    fields.insert("Title".into(), ConflictSide::Remote);
    resolution
        .entry_field_choices
        .insert(EntryId(f.seed_uuid), fields);

    f.engine
        .apply_conflict_resolution(id, &resolution)
        .expect("apply attachment");

    let after = f
        .engine
        .entry(f.seed_uuid)
        .expect("entry")
        .expect("present");
    let names: Vec<&str> = after.attachments.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"report.bin"),
        "report.bin survives, got {names:?}"
    );
}

#[test]
fn apply_resolution_handles_icon_conflict() {
    // Both sides set different custom_icon_uuids; the conflict
    // surfaces as an icon_delta and apply consumes the
    // `entry_icon_choices` slot of the Resolution.
    let mut f = fixture();
    let local_icon = Uuid::new_v4();
    let disk_icon = Uuid::new_v4();

    // Seed both custom-icon UUIDs on both sides so the merge has
    // something to land. We can't easily install a custom-icon
    // record via the engine API in v0.1, but the merger only needs
    // the `custom_icon_uuid` slot on the entry — the icon pool
    // reconciliation rides through `apply_merge`'s group-tree pass.
    // For this test we rely on the resolution carrier accepting the
    // icon choice without requiring the bitmap on the side. If the
    // merge surface complains, we widen to use the kdbx-level
    // custom-icon API.

    // Local edit: set the entry's icon to a custom UUID.
    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                icon: Some(keys_engine::IconRef::Custom(local_icon)),
                ..Default::default()
            },
        )
        .expect("local icon");

    // Disk edit.
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_custom_icon(Some(disk_icon));
        })
        .expect("disk icon");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");
    // Icon-only divergence may auto-resolve via the 3-way classifier
    // when the LCA carries neither uuid; in that case the test
    // becomes a no-op assertion of the auto-merged side. If the
    // classifier surfaces a true conflict, drive it through apply
    // with `ConflictSide::Remote`.
    // If the classifier auto-resolves (e.g. when the LCA carries
    // neither uuid), the merge pipeline takes the auto path and
    // there's nothing for apply to do — reaching that branch
    // confirms the icon divergence doesn't crash the merge. If the
    // classifier surfaces a true conflict, drive it through apply
    // with `ConflictSide::Remote` (plus any sibling field deltas
    // the title bump may have brought along).
    if let MergeResult::Conflict(payload) = result {
        let mut resolution = ConflictResolution::default();
        for conflict in &payload.entry_conflicts {
            let mut fields: HashMap<String, ConflictSide> = HashMap::new();
            for delta in &conflict.field_deltas {
                fields.insert(delta.key.clone(), ConflictSide::Local);
            }
            if !fields.is_empty() {
                resolution
                    .entry_field_choices
                    .insert(conflict.entry_id, fields);
            }
            if conflict.icon_delta.is_some() {
                resolution
                    .entry_icon_choices
                    .insert(conflict.entry_id, ConflictSide::Remote);
            }
        }
        f.engine
            .apply_conflict_resolution(payload.id, &resolution)
            .expect("apply icon");
    }
}

#[test]
fn apply_resolution_handles_delete_edit_choice() {
    // Disk deletes the entry; local then edits it after the deletion
    // tombstone. `KeepLocal` keeps the edited entry alive;
    // `AcceptRemoteDelete` honours the deletion. The order matters
    // for the merger's `local_edited_after(local, deleted_at)` check
    // — local must mtime AFTER the tombstone for the delete-edit
    // bucket to fire (otherwise the merger correctly classifies as a
    // clean remote-delete adoption).
    let mut f = fixture();

    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .delete_entry(EntryId(f.seed_uuid))
        .expect("disk delete");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    // Ensure the local edit's wall-clock mtime is strictly after the
    // tombstone — KDBX timestamps land at ms precision, so a 2ms
    // pause makes the ordering deterministic across thread loads.
    std::thread::sleep(std::time::Duration::from_millis(2));
    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rescue".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    let id = match f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile")
    {
        MergeResult::Conflict(p) => {
            assert_eq!(p.delete_edit_conflicts.len(), 1);
            p.id
        }
        other => panic!("expected Conflict, got {other:?}"),
    };

    let mut resolution = ConflictResolution::default();
    resolution
        .delete_edit_choices
        .insert(EntryId(f.seed_uuid), DeleteEditChoice::KeepLocal);

    f.engine
        .apply_conflict_resolution(id, &resolution)
        .expect("apply delete-edit");

    let after = f.engine.entry(f.seed_uuid).expect("entry");
    assert!(after.is_some(), "entry survived KeepLocal");
    assert_eq!(after.unwrap().title, "local-rescue");
}

#[test]
fn apply_resolution_consumes_stash() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local", "disk");

    f.engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Local))
        .expect("first apply");

    let result = f
        .engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Local));
    assert!(
        matches!(
            result,
            Err(EngineError::NotFound {
                entity: "conflict_payload"
            })
        ),
        "second apply returns NotFound, got {result:?}"
    );
}

#[test]
fn apply_resolution_missing_id_returns_not_found() {
    let mut f = fixture();
    let result = f
        .engine
        .apply_conflict_resolution(99_999, &title_resolution(f.seed_uuid, ConflictSide::Local));
    assert!(
        matches!(
            result,
            Err(EngineError::NotFound {
                entity: "conflict_payload"
            })
        ),
        "missing id → NotFound, got {result:?}"
    );
}

/// Dismissing a resolver ("Resolve Later") drops both stash halves —
/// the peek-side payload mirror and the resolvable context — without
/// touching the held value or the badge. Guards against the orphaned-
/// stash leak that repeated open/dismiss would otherwise cause.
#[test]
fn discard_conflict_drops_stash_without_resolving() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local-title", "disk-title");

    // Stash present: payload mirror peekable, context resolvable.
    assert!(f.engine.pending_conflict(id).is_some(), "payload stashed");
    assert_eq!(f.engine.pending_conflict_count_for_test(), 1);
    let held_before = f.engine.entry(f.seed_uuid).unwrap().unwrap().title;

    // Dismiss without resolving.
    f.engine.discard_conflict(id);

    // Payload mirror gone.
    assert!(
        f.engine.pending_conflict(id).is_none(),
        "payload mirror dropped",
    );
    assert_eq!(f.engine.pending_conflict_count_for_test(), 0);

    // Context gone too: apply now reports NotFound rather than a stale
    // resolve.
    let result = f
        .engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Local));
    assert!(
        matches!(
            result,
            Err(EngineError::NotFound {
                entity: "conflict_payload"
            })
        ),
        "context dropped → apply NotFound, got {result:?}",
    );

    // Dismiss is not a resolve: the held value is unchanged.
    assert_eq!(
        f.engine.entry(f.seed_uuid).unwrap().unwrap().title,
        held_before,
        "dismiss leaves the held value untouched",
    );
}

/// `discard_conflict` is idempotent: an unknown id is a no-op that
/// leaves an unrelated live stash intact.
#[test]
fn discard_conflict_unknown_id_is_noop() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local", "disk");

    f.engine.discard_conflict(99_999);

    assert!(
        f.engine.pending_conflict(id).is_some(),
        "unrelated stash untouched",
    );
    assert_eq!(f.engine.pending_conflict_count_for_test(), 1);
}

#[test]
fn apply_resolution_mismatched_entries_returns_error() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local", "disk");

    // Resolution refers to an entry that isn't in the conflict bucket.
    let bogus = Uuid::new_v4();
    let resolution = title_resolution(bogus, ConflictSide::Local);

    let result = f.engine.apply_conflict_resolution(id, &resolution);
    assert!(
        matches!(result, Err(EngineError::ResolutionMismatch { .. })),
        "mismatched entry → ResolutionMismatch, got {result:?}"
    );
}

#[test]
fn apply_resolution_atomic_on_failure() {
    let mut f = fixture();
    let before = f
        .engine
        .entry(f.seed_uuid)
        .expect("entry")
        .expect("present");
    let id = drive_title_conflict(&mut f, "local-on-failure", "disk-on-failure");

    // Drive a validation failure: supply a Resolution that refers to
    // a field key not in the conflict's deltas. apply_merge bails
    // before touching SQLite.
    let mut fields: HashMap<String, ConflictSide> = HashMap::new();
    fields.insert("UnknownField".into(), ConflictSide::Local);
    let mut resolution = ConflictResolution::default();
    resolution
        .entry_field_choices
        .insert(EntryId(f.seed_uuid), fields);

    let result = f.engine.apply_conflict_resolution(id, &resolution);
    assert!(result.is_err(), "expected validation failure");

    // SQLite untouched: the local edit (title = "local-on-failure")
    // is still there, the disk edit ("disk-on-failure") never landed.
    let after = f
        .engine
        .entry(f.seed_uuid)
        .expect("entry")
        .expect("present");
    assert_eq!(
        after.title, "local-on-failure",
        "local title preserved (no apply happened); before title was {:?}",
        before.title
    );
}

#[test]
fn apply_resolution_emits_external_change_merged() {
    let mut f = fixture();
    let observer = Arc::new(CaptureObserver::default());
    f.engine.set_observer(observer.clone());

    let id = drive_title_conflict(&mut f, "local-event", "disk-event");
    observer.events.lock().unwrap().clear();

    f.engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Remote))
        .expect("apply");

    let events = observer.snapshot();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::ExternalChangeMerged { .. })),
        "expected ExternalChangeMerged in {events:?}",
    );
}

#[test]
fn apply_resolution_updates_common_ancestor() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local-anc", "disk-anc");

    f.engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Remote))
        .expect("apply");

    let stored = f
        .engine
        .last_saved_kdbx_bytes()
        .expect("query")
        .expect("ancestor stored");
    let on_disk = std::fs::read(&f.kdbx_path).expect("read kdbx");
    assert_eq!(stored, on_disk, "ancestor refreshed to disk bytes");
}

#[test]
fn pending_conflict_peek_is_idempotent_until_apply() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local-peek", "disk-peek");

    // Two back-to-back peeks return the same payload — this is a
    // peek, not a take.
    let first = f.engine.pending_conflict(id).expect("first peek");
    let second = f.engine.pending_conflict(id).expect("second peek");
    assert_eq!(first.id, id);
    assert_eq!(second.id, id);
    assert_eq!(first.entry_conflicts.len(), second.entry_conflicts.len());
    assert_eq!(
        f.engine.pending_conflict_count_for_test(),
        1,
        "peek does not consume",
    );

    // Apply consumes the matching context AND the peek-side payload.
    f.engine
        .apply_conflict_resolution(id, &title_resolution(f.seed_uuid, ConflictSide::Remote))
        .expect("apply");
    assert!(
        f.engine.pending_conflict(id).is_none(),
        "peek returns None after apply consumed the stash",
    );
    assert_eq!(
        f.engine.pending_conflict_count_for_test(),
        0,
        "peek-side stash cleared on apply",
    );
}

#[test]
fn pending_conflict_unknown_id_is_none() {
    let f = fixture();
    assert!(
        f.engine.pending_conflict(424_242).is_none(),
        "unknown id returns None without panicking",
    );
}

#[test]
fn pending_conflict_parent_groups_covers_every_conflict_entry() {
    let mut f = fixture();
    let id = drive_title_conflict(&mut f, "local-parents", "disk-parents");

    let payload = f.engine.pending_conflict(id).expect("payload");
    let parents = f
        .engine
        .pending_conflict_parent_groups(id)
        .expect("parents");
    for c in &payload.entry_conflicts {
        let entry = parents
            .get(&c.entry_id)
            .expect("parent entry present for every entry_conflict");
        // The seed entry is alive on both sides in this fixture.
        assert!(entry.local.is_some(), "local parent resolved");
        assert!(entry.remote.is_some(), "remote parent resolved");
    }
}

// ── Per-side conflict-field reveal ───────────────────────────────────

/// Drive a Password-field conflict on the seed entry. Engine sets
/// local password via `update_entry`; disk sets via `edit_entry` /
/// `set_password`. We also bump the Title on both sides because
/// `reconcile_with_disk`'s cheap-equivalence short-circuit only
/// compares `(title, username, url, notes)` — a password-only diff
/// would short-circuit to `NoChange` and we'd never reach the
/// conflict path. Returns the stash id.
fn drive_password_conflict(f: &mut Fixture, local_pw: &str, disk_pw: &str) -> i64 {
    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-pw".into()),
                password: Some(SecretString::from(local_pw.to_owned())),
                ..Default::default()
            },
        )
        .expect("local pw edit");

    let mut external = reopen_kdbx(&f.kdbx_path);
    let disk_pw_owned = disk_pw.to_string();
    external
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title("disk-pw");
            e.set_password(SecretString::from(disk_pw_owned.clone()));
        })
        .expect("disk pw edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    match f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile")
    {
        MergeResult::Conflict(payload) => payload.id,
        other => panic!("expected Conflict, got {other:?}"),
    }
}

#[test]
fn reveal_conflict_local_field_returns_local_plaintext() {
    let mut f = fixture();
    let id = drive_password_conflict(&mut f, "old-secret", "new-secret");

    let local = f
        .engine
        .reveal_conflict_local_field(id, f.seed_uuid, "Password")
        .expect("local reveal");
    assert_eq!(local.expose_secret(), "old-secret");
}

#[test]
fn reveal_conflict_remote_field_returns_remote_plaintext() {
    let mut f = fixture();
    let id = drive_password_conflict(&mut f, "old-secret", "new-secret");

    let remote = f
        .engine
        .reveal_conflict_remote_field(id, f.seed_uuid, "Password")
        .expect("remote reveal");
    assert_eq!(remote.expose_secret(), "new-secret");
}

#[test]
fn reveal_conflict_local_field_returns_not_found_for_missing_conflict_id() {
    let mut f = fixture();
    let _ = drive_password_conflict(&mut f, "old-secret", "new-secret");

    // Use an id we know was never handed out: the stash counter is
    // monotonic, so a far-future id is guaranteed absent.
    let err = f
        .engine
        .reveal_conflict_local_field(9_999_999, f.seed_uuid, "Password")
        .expect_err("expected NotFound");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "conflict_payload"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn reveal_conflict_local_field_returns_not_found_for_missing_entry() {
    let mut f = fixture();
    let id = drive_password_conflict(&mut f, "old-secret", "new-secret");

    let bogus = Uuid::from_bytes([0xab; 16]);
    let err = f
        .engine
        .reveal_conflict_local_field(id, bogus, "Password")
        .expect_err("expected NotFound");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "entry"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn reveal_conflict_local_field_returns_not_found_for_missing_field_name() {
    let mut f = fixture();
    let id = drive_password_conflict(&mut f, "old-secret", "new-secret");

    let err = f
        .engine
        .reveal_conflict_local_field(id, f.seed_uuid, "NoSuchField")
        .expect_err("expected NotFound");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "custom_field"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn reveal_conflict_field_handles_protected_custom_field() {
    // Seed a protected custom field on both sides via a save round-
    // trip (engine has no protected-custom-field mutator today; we
    // seed via the disk side then re-ingest before each side edits).
    let mut f = fixture();

    // Seed: write a protected custom field on the disk via the
    // editor's CustomFieldValue::Protected route, then ingest so the
    // engine sees the same baseline.
    let mut seeder = reopen_kdbx(&f.kdbx_path);
    seeder
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_custom_field(
                "OTP",
                CustomFieldValue::Protected(SecretString::from("seed-totp")),
            );
        })
        .expect("seed protected cf");
    let bytes = seeder.save_to_bytes().expect("save seed");
    std::fs::write(&f.kdbx_path, &bytes).expect("write seed");
    let seed_reread = reopen_kdbx(&f.kdbx_path);
    f.engine
        .ingest_from_kdbx(&seed_reread)
        .expect("re-ingest seed");

    // Engine bumps the entry title — touching a standard field so the
    // reconcile's cheap-equivalence short-circuit doesn't fire — and
    // we'll let the disk side edit the protected custom field with a
    // fresh value. That gives us a conflict bucket whose `field_name`
    // surfaces "OTP" on the disk side; the local side carries the
    // seeded value, the remote side carries the new value.
    f.engine
        .update_entry(
            f.seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-otp".into()),
                ..Default::default()
            },
        )
        .expect("local title bump");

    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(EntryId(f.seed_uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title("disk-otp");
            e.set_custom_field(
                "OTP",
                CustomFieldValue::Protected(SecretString::from("rotated-totp")),
            );
        })
        .expect("disk otp edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let id = match f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile")
    {
        MergeResult::Conflict(p) => p.id,
        other => panic!("expected Conflict, got {other:?}"),
    };

    let local = f
        .engine
        .reveal_conflict_local_field(id, f.seed_uuid, "OTP")
        .expect("local OTP reveal");
    assert_eq!(local.expose_secret(), "seed-totp");
    let remote = f
        .engine
        .reveal_conflict_remote_field(id, f.seed_uuid, "OTP")
        .expect("remote OTP reveal");
    assert_eq!(remote.expose_secret(), "rotated-totp");
}

#[test]
fn reveal_conflict_field_after_apply_resolution_returns_not_found() {
    let mut f = fixture();
    let id = drive_password_conflict(&mut f, "old-secret", "new-secret");

    // Reveal works before apply.
    let _ = f
        .engine
        .reveal_conflict_local_field(id, f.seed_uuid, "Password")
        .expect("pre-apply reveal");

    // Apply the resolution — pick Local side for both conflicting
    // fields (Title + Password; see `drive_password_conflict` for why
    // Title is in there).
    let mut fields: HashMap<String, ConflictSide> = HashMap::new();
    fields.insert("Title".into(), ConflictSide::Local);
    fields.insert("Password".into(), ConflictSide::Local);
    let mut resolution = ConflictResolution::default();
    resolution
        .entry_field_choices
        .insert(EntryId(f.seed_uuid), fields);
    f.engine
        .apply_conflict_resolution(id, &resolution)
        .expect("apply");

    // Reveal now returns NotFound — the stash was consumed.
    let err = f
        .engine
        .reveal_conflict_local_field(id, f.seed_uuid, "Password")
        .expect_err("post-apply reveal should fail");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "conflict_payload"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}
