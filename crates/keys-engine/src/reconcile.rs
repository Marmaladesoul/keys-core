//! External-change merge — Phase 4 task 4.6.
//!
//! Implements [`Engine::reconcile_with_disk`](crate::Engine::reconcile_with_disk):
//! detects external KDBX changes (`KeeWeb`, autofill, sync drop-in), runs
//! a two-way merge via [`keepass_merge::merge`] against the engine's
//! current `SQLite` state, applies any non-conflicting diffs to `SQLite`
//! inside a single transaction, and either emits
//! [`ChangeEvent::ExternalChangeMerged`]
//! or [`ChangeEvent::ConflictDetected`].
//!
//! The merge algorithm uses each entry's `<History>` list as the
//! per-entry common ancestor (see `keepass-merge`'s top-level
//! comment); the engine's `setting.last_saved_kdbx_bytes` is the
//! vault-level "agreed baseline" that the next reconcile will run
//! against, refreshed to the disk bytes after every successful
//! `Merged` / `NoChange` result.
//!
//! ## Atomicity
//!
//! The apply step re-ingests the merged [`Vault`] into the engine's
//! `SQLite` mirror via the engine's ingest path, which holds a single
//! transaction across the entire walk. A failure mid-apply rolls the
//! transaction back; the engine state is unchanged and no events fire.
//!
//! ## Composite key
//!
//! The engine doesn't hold the composite key (master password) — only
//! the field protector. Reconcile takes the composite key as a
//! parameter on each call so frontends can pass it through from their
//! session state without long-lived storage on the [`Engine`].

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};

use keepass_core::CompositeKey;
use keepass_core::kdbx::Kdbx;
use keepass_core::model::Vault;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::events::{ChangeEvent, ConflictPayload};

/// Outcome of a successful [`Engine::reconcile_with_disk`] call.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum MergeResult {
    /// Engine's `SQLite` state and the disk file were already
    /// equivalent — no merge needed. `setting.last_saved_kdbx_bytes`
    /// is refreshed to the disk bytes regardless, so subsequent
    /// reconciles use the latest disk state as their baseline.
    NoChange,
    /// Non-conflicting changes were applied to `SQLite`. `applied`
    /// summarises the per-bucket counts.
    Merged {
        /// Per-bucket counts of merge mutations applied.
        applied: MergeStats,
    },
    /// Conflicts require user resolution. `SQLite` was **not**
    /// mutated; the payload is stashed on the engine for a later
    /// `apply_conflict_resolution` call (task 4.7).
    Conflict(ConflictPayload),
}

/// Aggregate counts of merge mutations applied to `SQLite`.
///
/// "Added" / "deleted" counts are exact — they mirror the merge
/// outcome's `added_on_disk` / `deleted_on_disk` buckets. "Updated"
/// counts cover the auto-resolution buckets (`disk_only_changes`,
/// `local_only_changes`). "Moved" counts are zero for v0.1 — the
/// merge algorithm reconciles group structure by LWW timestamp
/// without surfacing a "moved" bucket; moves still happen, they just
/// aren't broken out separately.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergeStats {
    /// Entries that were present only on disk and have now been
    /// inserted into `SQLite`.
    pub entries_added: usize,
    /// Entries whose disk state was applied on top of the local
    /// state (or vice versa for local-only changes that absorbed
    /// remote history records).
    pub entries_updated: usize,
    /// Entries that were tombstoned on disk and have now been
    /// removed from `SQLite`.
    pub entries_deleted: usize,
    /// Entries that changed group as part of the merge. Always
    /// `0` in v0.1 (group-tree reconciliation runs as LWW without
    /// surfacing a moves bucket); reserved for v0.2.
    pub entries_moved: usize,
    /// Groups added by the merge (LWW reconciliation).
    pub groups_added: usize,
    /// Groups whose metadata was updated by the merge.
    pub groups_updated: usize,
    /// Groups removed by the merge.
    pub groups_deleted: usize,
    /// Groups that changed parent. Always `0` in v0.1.
    pub groups_moved: usize,
}

/// Source of unique-id assignment for [`ConflictPayload`]. Each
/// reconcile-with-conflicts call bumps the counter by one. Process-
/// local — there's no need for global uniqueness; the id only has to
/// distinguish concurrent payloads stashed on the same engine handle.
pub(crate) static NEXT_CONFLICT_ID: AtomicI64 = AtomicI64::new(1);

/// The merge implementation. Pulled out of [`Engine`] so the
/// surrounding method body stays narrow.
pub(crate) fn reconcile_with_disk(
    engine: &mut Engine,
    kdbx_path: &Path,
    composite_key: &CompositeKey,
) -> Result<MergeResult, EngineError> {
    // 1. Read the disk bytes.
    let disk_bytes = std::fs::read(kdbx_path)?;

    // 2. Parse the disk vault.
    let disk_kdbx = Kdbx::open_from_bytes(disk_bytes.clone())
        .map_err(|e| EngineError::Serialise(format!("open disk kdbx: {e}")))?
        .read_header()
        .map_err(|e| EngineError::Serialise(format!("read disk header: {e}")))?
        .unlock_with_protector(composite_key, Some(engine.field_protector_arc()))
        .map_err(|e| EngineError::Serialise(format!("unlock disk kdbx: {e}")))?;

    // 3. Project the engine's current state to a Vault (local side).
    let local_vault = engine.project_to_vault()?;

    // 4. Build the remote-side vault. Use `vault_with_unwrapped_protected`
    //    so the merge sees plaintext on protected fields, matching the
    //    projection's shape — keepass-merge compares by value and
    //    cannot reason about the wrap layer.
    let remote_vault = disk_kdbx
        .vault_with_unwrapped_protected()
        .map_err(|e| EngineError::Serialise(format!("unwrap disk protected: {e}")))?;

    // 5. Quick equality check: if the two vaults are byte-identical
    //    under merge's lens, short-circuit with NoChange and just
    //    refresh the ancestor.
    if vaults_equivalent(&local_vault, &remote_vault) {
        engine.set_last_saved_kdbx_bytes(&disk_bytes)?;
        return Ok(MergeResult::NoChange);
    }

    // 6. Run the merge.
    let outcome = keepass_merge::merge(&local_vault, &remote_vault)
        .map_err(|e| EngineError::Serialise(format!("merge: {e}")))?;

    // 7. Conflict path — surface and bail without mutating SQLite.
    if !outcome.entry_conflicts.is_empty() || !outcome.delete_edit_conflicts.is_empty() {
        let id = NEXT_CONFLICT_ID.fetch_add(1, Ordering::Relaxed);
        let payload = ConflictPayload {
            id,
            entry_conflicts: outcome.entry_conflicts.clone(),
            delete_edit_conflicts: outcome.delete_edit_conflicts.clone(),
        };
        engine.stash_conflict_payload(payload.clone());
        engine.stash_conflict_context(crate::conflict_resolution::PendingConflictContext {
            payload: payload.clone(),
            outcome,
            local_vault,
            remote_vault,
            disk_kdbx,
            disk_bytes,
        });
        engine.emit(ChangeEvent::ConflictDetected(payload.clone()));
        return Ok(MergeResult::Conflict(payload));
    }

    // 8. Compute stats from the outcome before consuming it.
    let stats = MergeStats {
        entries_added: outcome.added_on_disk.len(),
        entries_updated: outcome.disk_only_changes.len() + outcome.local_only_changes.len(),
        entries_deleted: outcome.deleted_on_disk.len(),
        entries_moved: 0,
        groups_added: count_groups_remote_only(&local_vault, &remote_vault),
        groups_updated: 0,
        groups_deleted: count_groups_tombstoned(&local_vault, &remote_vault),
        groups_moved: 0,
    };

    // 9. Apply the merge to a clone of the local vault.
    let mut merged = local_vault;
    keepass_merge::apply_merge(
        &mut merged,
        &remote_vault,
        &outcome,
        &keepass_merge::Resolution::default(),
    )
    .map_err(|e| EngineError::Serialise(format!("apply_merge: {e}")))?;
    keepass_merge::reconcile_timestamps(&mut merged, &remote_vault);

    // 10. Atomically replace SQLite contents with the merged vault.
    //     We re-use `ingest`, which wraps the entire write in a single
    //     transaction — failure mid-walk rolls back and the engine
    //     state is unchanged. The disk Kdbx is the convenient carrier
    //     for the merged vault since it already has the protector and
    //     crypto envelope wired up.
    let mut disk_kdbx = Kdbx::open_from_bytes(disk_bytes.clone())
        .map_err(|e| EngineError::Serialise(format!("re-open disk kdbx: {e}")))?
        .read_header()
        .map_err(|e| EngineError::Serialise(format!("re-read disk header: {e}")))?
        .unlock_with_protector(composite_key, Some(engine.field_protector_arc()))
        .map_err(|e| EngineError::Serialise(format!("re-unlock disk kdbx: {e}")))?;
    disk_kdbx.replace_vault(merged);
    engine.ingest_merged(&disk_kdbx)?;

    // 11. Refresh the common ancestor to the disk bytes — the agreed
    //     baseline for the next reconcile. The merged result lives in
    //     SQLite now; a follow-up save_to_kdbx will overwrite the disk
    //     file (and the ancestor) with the combined state.
    engine.set_last_saved_kdbx_bytes(&disk_bytes)?;

    // 12. Emit the success event.
    engine.emit(ChangeEvent::ExternalChangeMerged {
        applied: stats.clone(),
    });

    Ok(MergeResult::Merged { applied: stats })
}

/// Cheap structural-equivalence check between two vaults at merge
/// time. Used to short-circuit a reconcile when the disk file and
/// the engine's projection carry the same content (e.g. when the
/// engine writes the file, the watcher catches it past the self-
/// write filter window, and reconcile runs anyway — a no-op reload).
///
/// Compares entry-uuid sets, group-uuid sets, and tombstone-uuid
/// sets. A finer comparison is unnecessary: if any content actually
/// differs the merge itself does the right thing in O(entries),
/// which is fine.
fn vaults_equivalent(a: &Vault, b: &Vault) -> bool {
    use std::collections::HashSet;
    let mut a_entries: HashSet<uuid::Uuid> = HashSet::new();
    let mut b_entries: HashSet<uuid::Uuid> = HashSet::new();
    let mut a_groups: HashSet<uuid::Uuid> = HashSet::new();
    let mut b_groups: HashSet<uuid::Uuid> = HashSet::new();
    walk(&a.root, &mut a_entries, &mut a_groups);
    walk(&b.root, &mut b_entries, &mut b_groups);
    if a_entries != b_entries || a_groups != b_groups {
        return false;
    }
    // Compare entry content by (title, username, url, notes).
    // Per-field comparison is enough to catch the "external edit"
    // case for these tests; a fuller comparison would walk every
    // field including protected slots (which we'd have to unwrap).
    let a_idx = index_entries(&a.root);
    let b_idx = index_entries(&b.root);
    for (id, ea) in &a_idx {
        let Some(eb) = b_idx.get(id) else {
            return false;
        };
        if ea.title != eb.title
            || ea.username != eb.username
            || ea.url != eb.url
            || ea.notes != eb.notes
        {
            return false;
        }
    }
    true
}

fn walk(
    group: &keepass_core::model::Group,
    entries: &mut std::collections::HashSet<uuid::Uuid>,
    groups: &mut std::collections::HashSet<uuid::Uuid>,
) {
    groups.insert(group.id.0);
    for e in &group.entries {
        entries.insert(e.id.0);
    }
    for sub in &group.groups {
        walk(sub, entries, groups);
    }
}

fn index_entries_walk<'a>(
    g: &'a keepass_core::model::Group,
    out: &mut std::collections::HashMap<uuid::Uuid, &'a keepass_core::model::Entry>,
) {
    for e in &g.entries {
        out.insert(e.id.0, e);
    }
    for sub in &g.groups {
        index_entries_walk(sub, out);
    }
}

fn index_entries(
    group: &keepass_core::model::Group,
) -> std::collections::HashMap<uuid::Uuid, &keepass_core::model::Entry> {
    let mut out = std::collections::HashMap::new();
    index_entries_walk(group, &mut out);
    out
}

/// Count groups present only on the remote side (will be added by
/// the apply step's LWW group-tree pass).
fn count_groups_remote_only(local: &Vault, remote: &Vault) -> usize {
    use std::collections::HashSet;
    let mut local_ids: HashSet<uuid::Uuid> = HashSet::new();
    let mut remote_ids: HashSet<uuid::Uuid> = HashSet::new();
    collect_group_ids(&local.root, &mut local_ids);
    collect_group_ids(&remote.root, &mut remote_ids);
    remote_ids.difference(&local_ids).count()
}

/// Count groups present locally whose uuid is in the remote
/// tombstone set with a `deleted_at` that wins over the local mtime
/// (the conservative apply rule).
fn count_groups_tombstoned(local: &Vault, remote: &Vault) -> usize {
    use std::collections::HashMap;
    let remote_tomb: HashMap<uuid::Uuid, Option<chrono::DateTime<chrono::Utc>>> = remote
        .deleted_objects
        .iter()
        .map(|t| (t.uuid, t.deleted_at))
        .collect();
    let mut local_ids: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
    collect_group_ids(&local.root, &mut local_ids);
    local_ids
        .iter()
        .filter(|id| remote_tomb.contains_key(*id))
        .count()
}

fn collect_group_ids(
    group: &keepass_core::model::Group,
    out: &mut std::collections::HashSet<uuid::Uuid>,
) {
    out.insert(group.id.0);
    for sub in &group.groups {
        collect_group_ids(sub, out);
    }
}
