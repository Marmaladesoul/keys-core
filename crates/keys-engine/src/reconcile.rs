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
use keepass_core::model::{EntryId, Vault};

use crate::engine::Engine;
use crate::error::EngineError;
use crate::events::{ChangeEvent, ConflictPayload};

/// Legacy `<CustomData>` key of the pre-redesign parked-conflict history
/// marker. The hold-open redesign (keepass-merge #215, clean cut) deleted
/// the marker entirely — conflicts are now *derived* and badged via the
/// `held_conflicts` setting kv ([`Engine::held_conflicts`]), not stored on
/// history records. This const survives **only** to recognise and clean up
/// markers left in vaults written by an older build:
/// [`clear_parked_conflict_marker`] tombstones them, and the history
/// quota-trim ([`crate::mutations`]) still pins them so a cleanup pass can
/// find them. No code path writes it any more.
pub(crate) const FIELD_CONFLICT_CUSTOM_DATA_KEY: &str = "keys.field_conflict.v1";

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

/// Outcome of a successful
/// [`Engine::reconcile_with_disk_park_conflicts`] call.
///
/// Mirrors [`MergeResult`] for the non-conflict cases (`NoChange`,
/// `Merged`); the third variant is `Parked` rather than `Conflict`
/// because the conflicting entries have been resolved into local's
/// `<History>` with `keys.field_conflict.v1` markers attached — sync
/// never blocks. The user reviews via the resolver UI at their leisure.
///
/// `applied` reflects the same per-bucket stats as
/// [`MergeResult::Merged`]; `parked` lists the entry UUIDs whose
/// conflicts were parked plus the auto-handled categories from
/// [`keepass_merge::ParkedConflictsReport`] for downstream UX.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ParkConflictsResult {
    /// Engine state and disk were already equivalent. The ancestor
    /// is refreshed; nothing else changes.
    NoChange,
    /// Non-conflicting changes applied; any conflicts the merge
    /// surfaced were parked rather than reported.
    Applied {
        /// Per-bucket counts of merge mutations applied to `SQLite`.
        applied: MergeStats,
        /// Per-bucket lists of entries the parker touched.
        parked: ParkedConflictsSummary,
    },
}

/// Wire-friendly mirror of
/// [`keepass_merge::ParkedConflictsReport`] in `Vec<String>` form so
/// the FFI boundary doesn't have to round-trip `EntryId`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParkedConflictsSummary {
    /// UUIDs of entries whose conflict was parked into history with
    /// a `keys.field_conflict.v1` marker.
    pub entries_with_parked_conflict: Vec<String>,
    /// UUIDs of entries restored from a remote tombstone under the
    /// edit-wins rule.
    pub entries_restored_from_deletion: Vec<String>,
    /// UUIDs of entries where attachment-both-differ was resolved
    /// via the keep-both rename path.
    pub attachments_kept_both: Vec<String>,
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

    // 5. Quick equality check: if the disk bytes are byte-identical to
    //    the engine's last-saved baseline, short-circuit with NoChange.
    //    Every engine save produces fresh bytes from a new nonce only
    //    when something actually changed, so byte equality against the
    //    agreed baseline IS content equality. If we have no baseline
    //    (first-ever reconcile), fall through and let the merge run.
    let baseline = engine.last_saved_kdbx_bytes()?;
    if let Some(ref b) = baseline {
        if b == &disk_bytes {
            debug_dump_reconcile(
                "classic",
                &local_vault,
                &remote_vault,
                None,
                true,
                &disk_bytes,
            );
            engine.set_last_saved_kdbx_bytes(&disk_bytes)?;
            return Ok(MergeResult::NoChange);
        }
    }

    // 6. Run the merge.
    let outcome = keepass_merge::merge(&local_vault, &remote_vault)
        .map_err(|e| EngineError::Serialise(format!("merge: {e}")))?;

    debug_dump_reconcile(
        "classic",
        &local_vault,
        &remote_vault,
        Some(&outcome),
        false,
        &disk_bytes,
    );

    // 6a. Empty-merge short-circuit. The byte-equivalence check above
    //     catches the "same kdbx file" case, but two byte-different
    //     kdbx files can carry content-identical vaults (fresh
    //     encryption nonce on each save). Without this guard, an
    //     empty-bucket merge would still return `Merged`, which makes
    //     SyncManager save + push fresh bytes that the peer then sees
    //     as a new disk update — an infinite ping-pong loop.
    if outcome_is_no_op(&outcome, &local_vault, &remote_vault) {
        engine.set_last_saved_kdbx_bytes(&disk_bytes)?;
        return Ok(MergeResult::NoChange);
    }

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

/// Derive the current conflict payload for the **held** (parked) path and
/// stash a context so it can be resolved through the same
/// [`Engine::apply_conflict_resolution`] entry point the live path uses.
///
/// This is the resolver-open counterpart to the badge query
/// [`entries_with_parked_conflict`]. Under hold-open a conflict's
/// divergence stays live in current state, but once
/// [`reconcile_with_disk_park_conflicts`] has set the baseline to the disk
/// bytes the byte-equivalence short-circuit means a plain reconcile would
/// return `NoChange` and never re-derive the conflict — so neither reconcile
/// variant can rebuild a resolvable payload after the badge has been cached
/// (e.g. across an app relaunch). This method merges local-vs-disk
/// **unconditionally** (no short-circuit, no apply) purely to:
///
/// 1. rebuild the rich [`ConflictPayload`] (field / icon / attachment deltas,
///    the same shape the live path produces), and
/// 2. stash the [`PendingConflictContext`] so a subsequent
///    `apply_conflict_resolution(id, …)` converges the chosen values and
///    writes the propagating resolution records (phase 2b).
///
/// It mutates **no** `SQLite` state (the park reconcile owns the held-open
/// apply + the badge cache); its only side effect is the stash. Returns
/// `None` — and the stash is left untouched — when the merge surfaces no
/// conflicts (e.g. the conflict was resolved on a peer and the resolution
/// record has since synced in, so adoption converged it).
pub(crate) fn held_conflict_payload(
    engine: &mut Engine,
    kdbx_path: &Path,
    composite_key: &CompositeKey,
) -> Result<Option<ConflictPayload>, EngineError> {
    let disk_bytes = std::fs::read(kdbx_path)?;
    let disk_kdbx = Kdbx::open_from_bytes(disk_bytes.clone())
        .map_err(|e| EngineError::Serialise(format!("open disk kdbx: {e}")))?
        .read_header()
        .map_err(|e| EngineError::Serialise(format!("read disk header: {e}")))?
        .unlock_with_protector(composite_key, Some(engine.field_protector_arc()))
        .map_err(|e| EngineError::Serialise(format!("unlock disk kdbx: {e}")))?;

    let local_vault = engine.project_to_vault()?;
    let remote_vault = disk_kdbx
        .vault_with_unwrapped_protected()
        .map_err(|e| EngineError::Serialise(format!("unwrap disk protected: {e}")))?;

    // Unconditional merge — deliberately no byte-equivalence / no-op
    // short-circuit. A held conflict has disk == baseline (the park reconcile
    // refreshed it) yet local still diverges from disk, so the short-circuits
    // would wrongly report "nothing to resolve".
    let outcome = keepass_merge::merge(&local_vault, &remote_vault)
        .map_err(|e| EngineError::Serialise(format!("merge: {e}")))?;

    if outcome.entry_conflicts.is_empty() && outcome.delete_edit_conflicts.is_empty() {
        return Ok(None);
    }

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
    Ok(Some(payload))
}

/// Park-conflicts variant of [`reconcile_with_disk`].
///
/// Identical disk read / parse / project / merge prefix, but continues
/// past genuine conflicts by calling
/// [`keepass_merge::apply_merge_park_conflicts`] (the hold-open apply).
/// On a genuine clash each side keeps its **own** current value — no
/// winner, no marker, no history write — and the merge adopts any
/// `keys.conflict_resolutions.v1` record that covers the facet. Sync
/// never blocks.
///
/// The set of still-divergent ("held") entries the apply reports is
/// cached locally via [`Engine::set_held_conflicts`] so the badge
/// ([`entries_with_parked_conflict`]) survives engine close + reopen
/// without re-merging. That set is *derived* each merge, not stored in
/// the KDBX — the only convergent KDBX state is the resolution record.
pub(crate) fn reconcile_with_disk_park_conflicts(
    engine: &mut Engine,
    kdbx_path: &Path,
    composite_key: &CompositeKey,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ParkConflictsResult, EngineError> {
    // Steps 1–4: same prefix as `reconcile_with_disk`.
    let disk_bytes = std::fs::read(kdbx_path)?;
    let disk_kdbx = Kdbx::open_from_bytes(disk_bytes.clone())
        .map_err(|e| EngineError::Serialise(format!("open disk kdbx: {e}")))?
        .read_header()
        .map_err(|e| EngineError::Serialise(format!("read disk header: {e}")))?
        .unlock_with_protector(composite_key, Some(engine.field_protector_arc()))
        .map_err(|e| EngineError::Serialise(format!("unlock disk kdbx: {e}")))?;

    let local_vault = engine.project_to_vault()?;
    let remote_vault = disk_kdbx
        .vault_with_unwrapped_protected()
        .map_err(|e| EngineError::Serialise(format!("unwrap disk protected: {e}")))?;

    // Byte-equivalence short-circuit against the engine's last-saved
    // baseline. See `reconcile_with_disk` for the rationale: byte
    // equality of disk_bytes vs the agreed baseline IS content
    // equality, because the engine only re-encrypts on a real state
    // advance. No baseline (first-ever reconcile) → fall through and
    // run the merge (which is a no-op on identical content anyway).
    let baseline = engine.last_saved_kdbx_bytes()?;
    if let Some(ref b) = baseline {
        if b == &disk_bytes {
            debug_dump_reconcile("park", &local_vault, &remote_vault, None, true, &disk_bytes);
            engine.set_last_saved_kdbx_bytes(&disk_bytes)?;
            return Ok(ParkConflictsResult::NoChange);
        }
    }

    let outcome = keepass_merge::merge(&local_vault, &remote_vault)
        .map_err(|e| EngineError::Serialise(format!("merge: {e}")))?;

    debug_dump_reconcile(
        "park",
        &local_vault,
        &remote_vault,
        Some(&outcome),
        false,
        &disk_bytes,
    );

    // Same empty-merge short-circuit as `reconcile_with_disk` — see
    // there for the ping-pong-loop rationale. `outcome_is_no_op` is true
    // only when there are zero conflicts (it checks `entry_conflicts` /
    // `delete_edit_conflicts`), so a held conflict could never reach
    // here while still divergent — meaning the derived held set is now
    // empty. Clear the badge cache to match (covers coincidental
    // convergence: both sides independently landed on the same value).
    if outcome_is_no_op(&outcome, &local_vault, &remote_vault) {
        engine.set_last_saved_kdbx_bytes(&disk_bytes)?;
        engine.set_held_conflicts(&[])?;
        return Ok(ParkConflictsResult::NoChange);
    }

    // Stats reflect the non-conflicting buckets. Conflict-bucket
    // entries are NOT counted as "updated" — they're parked, leaving
    // local's current state untouched (the additions live only in
    // history).
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

    let mut merged = local_vault;
    let report = keepass_merge::apply_merge_park_conflicts(
        &mut merged,
        &remote_vault,
        &outcome,
        &keepass_merge::ParkConflictsConfig::with_now(now),
    )
    .map_err(|e| EngineError::Serialise(format!("apply_merge_park_conflicts: {e}")))?;
    keepass_merge::reconcile_timestamps(&mut merged, &remote_vault);

    // Re-ingest the merged vault into SQLite via the same `ingest_merged`
    // path the standard reconcile uses. The migration-0006
    // entry_custom_data table plus the history JSON shape extension
    // round-trip both `keys.history_tombstones.v1` (on the live entry)
    // and `keys.field_conflict.v1` (on parked history records) so
    // markers + tombstones survive the SQLite mirror.
    let mut disk_kdbx = Kdbx::open_from_bytes(disk_bytes.clone())
        .map_err(|e| EngineError::Serialise(format!("re-open disk kdbx: {e}")))?
        .read_header()
        .map_err(|e| EngineError::Serialise(format!("re-read disk header: {e}")))?
        .unlock_with_protector(composite_key, Some(engine.field_protector_arc()))
        .map_err(|e| EngineError::Serialise(format!("re-unlock disk kdbx: {e}")))?;
    disk_kdbx.replace_vault(merged);
    engine.ingest_merged(&disk_kdbx)?;

    engine.set_last_saved_kdbx_bytes(&disk_bytes)?;

    // Cache the derived held-conflict set for the badge. This is the full
    // current set (the apply walks every conflict), so it replaces the kv
    // outright — entries that converged this round drop off, new ones
    // appear. Set after `ingest_merged` for the same reason
    // `last_saved_kdbx_bytes` is: the `held_conflicts` setting row is not a
    // `meta.*` key so the re-ingest leaves it alone, but mirroring the
    // ordering keeps the invariant obvious.
    let held: Vec<uuid::Uuid> = report
        .entries_with_parked_conflict
        .iter()
        .map(|id| id.0)
        .collect();
    engine.set_held_conflicts(&held)?;

    let parked = ParkedConflictsSummary {
        entries_with_parked_conflict: report
            .entries_with_parked_conflict
            .iter()
            .map(|id| id.0.to_string())
            .collect(),
        entries_restored_from_deletion: report
            .entries_restored_from_deletion
            .iter()
            .map(|id| id.0.to_string())
            .collect(),
        attachments_kept_both: report
            .attachments_kept_both
            .iter()
            .map(|id| id.0.to_string())
            .collect(),
    };

    engine.emit(ChangeEvent::ExternalChangeMerged {
        applied: stats.clone(),
    });

    Ok(ParkConflictsResult::Applied {
        applied: stats,
        parked,
    })
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

// ---------------------------------------------------------------------------
// Parked-conflict surface — queries + marker-clearing.
// ---------------------------------------------------------------------------

/// Return the UUIDs of every entry currently **held** in an unresolved
/// sync conflict — the resolver badge set.
///
/// Reads the locally-cached derived set from the `held_conflicts` setting
/// kv ([`Engine::held_conflicts`]), which
/// [`reconcile_with_disk_park_conflicts`] refreshes on every merge. This
/// replaced the old scan of `entry_history.snapshot_json` for the
/// `keys.field_conflict.v1` marker: under hold-open the divergence lives in
/// current state, not on a history marker, so there is nothing in history to
/// scan — the engine derives the set at merge time and caches it here.
pub(crate) fn entries_with_parked_conflict(
    engine: &Engine,
) -> Result<Vec<uuid::Uuid>, EngineError> {
    engine.held_conflicts()
}

/// Dismiss the held-conflict badge on the named entry locally.
///
/// Under hold-open this is the **local** dismissal half: it drops
/// `entry_uuid` from the derived held-conflict set
/// ([`Engine::held_conflicts`]) so the badge clears immediately on this
/// device. Cross-peer convergence is driven separately by the
/// `keys.conflict_resolutions.v1` record that
/// [`crate::conflict_resolution::apply_conflict_resolution`] writes — merely
/// clearing the badge here does not resolve the conflict on other peers.
///
/// It also performs **legacy cleanup**: if the entry still carries any
/// pre-redesign [`FIELD_CONFLICT_CUSTOM_DATA_KEY`] history markers (from a
/// vault last written by an older build), each is tombstoned via
/// [`keepass_merge::add_history_tombstone`] (which drops the record from
/// `<History>` and writes a `keys.history_tombstones.v1` tombstone) and the
/// vault re-ingested. The redesign never writes these, so this is a no-op on
/// fresh data.
///
/// Idempotent: clearing an entry that is neither held nor marked returns 0.
/// Surfaces [`EngineError::NotFound`] if the entry doesn't exist.
///
/// Returns the number of facets cleared (legacy markers tombstoned, plus 1 if
/// the entry was in the held set).
pub(crate) fn clear_parked_conflict_marker(
    engine: &mut Engine,
    entry_uuid: uuid::Uuid,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<u32, EngineError> {
    let mut vault = engine.project_to_vault()?;
    let id = EntryId(entry_uuid);

    // Find the entry; if it doesn't exist, surface NotFound rather
    // than silently succeeding — the caller asked about an entry we
    // can't find.
    let Some(entry) = find_entry_mut(&mut vault.root, id) else {
        return Err(EngineError::NotFound { entity: "entry" });
    };

    // Legacy cleanup: collect every pre-redesign marker-bearing history
    // record as owned clones — we need them out of the borrow before we can
    // mutate the entry via `add_history_tombstone`. The clone is cheap
    // (single Entry) and there are at most a handful per entry in practice.
    // The redesign no longer writes markers, so this is empty on fresh data.
    let marker_records: Vec<keepass_core::model::Entry> = entry
        .history
        .iter()
        .filter(|h| {
            h.custom_data
                .iter()
                .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
        })
        .cloned()
        .collect();
    let legacy_cleared = u32::try_from(marker_records.len()).unwrap_or(u32::MAX);

    if !marker_records.is_empty() {
        // `add_history_tombstone` does the dual write: drops the matching
        // record from `entry.history` AND adds the (mtime, hash) entry to
        // the entry's `keys.history_tombstones.v1` list. Binaries are
        // unused for the marker case (parked-remote snapshots clone
        // attachment refs but the hash inputs include attachment bytes
        // for cross-binary-pool stability — see entry_content_hash).
        for record in &marker_records {
            keepass_merge::add_history_tombstone(
                entry,
                record,
                &vault.binaries,
                keepass_merge::TombstoneReason::ConflictCleanup,
                None,
                now,
            )
            .map_err(|e| EngineError::Serialise(format!("add_history_tombstone: {e}")))?;
        }

        // Re-ingest the mutated vault directly. The KDBX envelope on
        // disk hasn't changed (we haven't touched the file), so the
        // `meta.*` outer-header rows already in SQLite remain accurate
        // and `ingest_vault` skips re-persisting them.
        engine.ingest_vault(&vault)?;
        engine.emit(ChangeEvent::EntriesUpdated(vec![entry_uuid]));
    }

    // Primary action: drop the entry from the derived held-conflict badge
    // set. `held_conflicts` is a plain `setting` row (not a `meta.*` key) so
    // the re-ingest above leaves it intact; do the read-modify-write after.
    let mut held = engine.held_conflicts()?;
    let before = held.len();
    held.retain(|u| *u != entry_uuid);
    let removed = held.len() != before;
    if removed {
        engine.set_held_conflicts(&held)?;
    }

    Ok(legacy_cleared + u32::from(removed))
}

/// True when a merge outcome has no actual state change for the
/// engine to apply: no entry buckets populated, no group structural
/// changes, no conflicts. Used by both reconcile variants to break
/// the iroh ping-pong loop where each `save_to_kdbx` produces fresh
/// bytes (new nonce) even when the logical content is unchanged.
///
/// `entry_conflicts` and `delete_edit_conflicts` deliberately count
/// as "something happened" — even though they don't mutate `SQLite` in
/// the classic reconcile path, the park-conflicts variant pushes a
/// marked snapshot into history and the engine state genuinely
/// advances.
fn outcome_is_no_op(outcome: &keepass_merge::MergeOutcome, local: &Vault, remote: &Vault) -> bool {
    outcome.added_on_disk.is_empty()
        && outcome.disk_only_changes.is_empty()
        && outcome.local_only_changes.is_empty()
        && outcome.deleted_on_disk.is_empty()
        && outcome.local_deletions_pending_sync.is_empty()
        && outcome.entry_conflicts.is_empty()
        && outcome.delete_edit_conflicts.is_empty()
        && count_groups_remote_only(local, remote) == 0
        && count_groups_tombstoned(local, remote) == 0
}

// ---------------------------------------------------------------------------
// Diagnostic logging — investigation scaffolding while we chase a sync bug.
// Always emits one record per reconcile to a file inside the Keys.app
// sandbox container; non-sandbox callers (tests, CLI) are silent.
// ---------------------------------------------------------------------------

#[allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::format_push_string,
    reason = "diagnostic dump prioritises legibility over style nits"
)]
fn debug_dump_reconcile(
    variant: &'static str,
    local: &Vault,
    remote: &Vault,
    outcome: Option<&keepass_merge::MergeOutcome>,
    short_circuit_no_change: bool,
    disk_bytes: &[u8],
) {
    let tmp = std::env::temp_dir();
    let in_sandbox = tmp
        .to_string_lossy()
        .contains("Containers/com.marmaladesoul.Keys");
    let force_env = std::env::var("KEYS_DEBUG_RECONCILE").is_ok();
    if !in_sandbox && !force_env {
        return;
    }
    let logfile = tmp.join("reconcile.log");
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&logfile)
    else {
        return;
    };
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let disk_hash = {
        let mut h = Sha256::new();
        h.update(disk_bytes);
        let d: [u8; 32] = h.finalize().into();
        hex(&d[..6])
    };
    let _ = writeln!(
        f,
        "\n=== {} variant={} disk_hash={} short_circuit_no_change={} binary_mtime={} ===",
        chrono::Utc::now().to_rfc3339(),
        variant,
        disk_hash,
        short_circuit_no_change,
        binary_mtime_iso(),
    );
    if short_circuit_no_change {
        let _ = writeln!(f, "  (byte-equal to last saved baseline; merge not run)");
        return;
    }
    if let Some(o) = outcome {
        let groups_remote_only = count_groups_remote_only(local, remote);
        let groups_tombstoned = count_groups_tombstoned(local, remote);
        let _ = writeln!(
            f,
            "  outcome: added={} disk_only={} local_only={} \
             deleted_disk={} local_pending={} entry_conflicts={} delete_edit={} \
             groups_remote_only={} groups_tombstoned={}",
            o.added_on_disk.len(),
            o.disk_only_changes.len(),
            o.local_only_changes.len(),
            o.deleted_on_disk.len(),
            o.local_deletions_pending_sync.len(),
            o.entry_conflicts.len(),
            o.delete_edit_conflicts.len(),
            groups_remote_only,
            groups_tombstoned,
        );
        let _ = writeln!(
            f,
            "  no_op={} (true => NoChange short-circuit fires)",
            outcome_is_no_op(o, local, remote)
        );
        let _ = writeln!(
            f,
            "  L groups: {} L tombstones: {} | R groups: {} R tombstones: {}",
            count_all_groups(local),
            local.deleted_objects.len(),
            count_all_groups(remote),
            remote.deleted_objects.len()
        );
        let _ = writeln!(
            f,
            "  L meta.recycle_bin_uuid={:?}",
            local.meta.recycle_bin_uuid
        );
        let _ = writeln!(
            f,
            "  R meta.recycle_bin_uuid={:?}",
            remote.meta.recycle_bin_uuid
        );
        for c in &o.entry_conflicts {
            let _ = writeln!(
                f,
                "    conflict entry {} fields={:?}",
                c.entry_id.0,
                c.field_deltas.iter().map(|d| &d.key).collect::<Vec<_>>(),
            );
        }
    }
    let mut local_index: std::collections::HashMap<uuid::Uuid, &keepass_core::model::Entry> =
        std::collections::HashMap::new();
    index_into(&local.root, &mut local_index);
    let mut remote_index: std::collections::HashMap<uuid::Uuid, &keepass_core::model::Entry> =
        std::collections::HashMap::new();
    index_into(&remote.root, &mut remote_index);
    let all_ids: std::collections::BTreeSet<uuid::Uuid> = local_index
        .keys()
        .chain(remote_index.keys())
        .copied()
        .collect();
    for id in all_ids {
        let le = local_index.get(&id);
        let re = remote_index.get(&id);
        let title = le
            .map(|e| e.title.as_str())
            .or_else(|| re.map(|e| e.title.as_str()))
            .unwrap_or("?");
        let _ = writeln!(f, "  entry {id} title={title:?}");
        if let Some(e) = le {
            dump_side(&mut f, "    L", e, &local.binaries);
        } else {
            let _ = writeln!(f, "    L: <absent>");
        }
        if let Some(e) = re {
            dump_side(&mut f, "    R", e, &remote.binaries);
        } else {
            let _ = writeln!(f, "    R: <absent>");
        }
    }
}

fn dump_side(
    f: &mut std::fs::File,
    prefix: &str,
    entry: &keepass_core::model::Entry,
    _binaries: &[keepass_core::model::Binary],
) {
    use std::io::Write;
    let mtime = entry
        .times
        .last_modification_time
        .map_or_else(|| "<none>".into(), |t| t.to_rfc3339());
    let _ = writeln!(
        f,
        "{prefix} current mtime={} hash={} title={:?} user={:?} url={:?} notes_len={}",
        mtime,
        comparator_hash(entry),
        entry.title,
        entry.username,
        entry.url,
        entry.notes.len()
    );
    for (i, h) in entry.history.iter().enumerate() {
        let hm = h
            .times
            .last_modification_time
            .map_or_else(|| "<none>".into(), |t| t.to_rfc3339());
        let marker = h
            .custom_data
            .iter()
            .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY);
        let marker_str = if marker { " [⚠MARKER]" } else { "" };
        let _ = writeln!(
            f,
            "{prefix}   h[{i}] mtime={} hash={} title={:?} user={:?}{}",
            hm,
            comparator_hash(h),
            h.title,
            h.username,
            marker_str
        );
    }
}

/// Diagnostic-only hash over the LCA-comparator-visible field surface.
/// Tracks the keepass-merge `entry_content_hash` semantics closely
/// enough to spot drift in real-world repros, but doesn't try to be
/// byte-exact (we don't need to identify the LCA, just spot why one
/// wasn't found). Password is NOT included — diagnostic logs should
/// never carry credentials. The LCA walker hashes password too, so a
/// matching diagnostic hash here + diverging mtimes means
/// password-content matches; matching mtimes + diverging hash here is
/// the rare "non-credential field drift" signal.
fn comparator_hash(entry: &keepass_core::model::Entry) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(entry.title.as_bytes());
    h.update([0u8]);
    h.update(entry.username.as_bytes());
    h.update([0u8]);
    h.update(entry.url.as_bytes());
    h.update([0u8]);
    h.update(entry.notes.as_bytes());
    h.update([0u8]);
    let mut tags: Vec<&str> = entry.tags.iter().map(String::as_str).collect();
    tags.sort_unstable();
    for t in tags {
        h.update(t.as_bytes());
        h.update([0u8]);
    }
    let d: [u8; 32] = h.finalize().into();
    hex(&d[..6])
}

/// Stat the running binary's mtime and format as ISO8601. Cached at
/// first call so we don't stat per-reconcile. "?" if the stat fails
/// (very rare — would have to be a launched-then-deleted binary).
fn binary_mtime_iso() -> String {
    use std::sync::OnceLock;
    static CACHED: OnceLock<String> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            let Ok(path) = std::env::current_exe() else {
                return "?".into();
            };
            let Ok(meta) = std::fs::metadata(&path) else {
                return "?".into();
            };
            let Ok(mtime) = meta.modified() else {
                return "?".into();
            };
            let dt: chrono::DateTime<chrono::Utc> = mtime.into();
            dt.to_rfc3339()
        })
        .clone()
}

fn count_all_groups(v: &Vault) -> usize {
    fn walk(g: &keepass_core::model::Group) -> usize {
        1 + g.groups.iter().map(walk).sum::<usize>()
    }
    walk(&v.root)
}

fn index_into<'a>(
    group: &'a keepass_core::model::Group,
    out: &mut std::collections::HashMap<uuid::Uuid, &'a keepass_core::model::Entry>,
) {
    for e in &group.entries {
        out.insert(e.id.0, e);
    }
    for sub in &group.groups {
        index_into(sub, out);
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Walk the group tree looking for the live entry with `id`. Returns
/// the mutable borrow on first match. Mirrors the same helper in
/// `keepass-merge::auto`; kept private here to avoid a public re-
/// export from a sibling crate.
fn find_entry_mut(
    group: &mut keepass_core::model::Group,
    id: EntryId,
) -> Option<&mut keepass_core::model::Entry> {
    if let Some(idx) = group.entries.iter().position(|e| e.id == id) {
        return Some(&mut group.entries[idx]);
    }
    for sub in &mut group.groups {
        if let Some(e) = find_entry_mut(sub, id) {
            return Some(e);
        }
    }
    None
}
