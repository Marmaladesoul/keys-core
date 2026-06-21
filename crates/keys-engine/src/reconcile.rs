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

use crate::conflict_rows;
use crate::engine::Engine;
use crate::error::EngineError;
use crate::events::{ChangeEvent, ConflictPayload};

/// Owner sentinel for the disk/iroh sync peer.
///
/// The owner-rows store keys conflict rows by an opaque peer identifier. The
/// reconcile path collapses "whatever synced into the watched kdbx file" into
/// a single peer — correct for the 2-device path the live sync ships today.
///
/// TODO(multi-peer): true N-peer differentiation threads a real peer id from
/// the sync layer through to [`Engine::ingest_peer`] instead of this single
/// sentinel, so divergent values from peers B and C don't share one owner row.
/// Out of scope for the Phase-4 switch.
const FILE_OWNER: &str = "file";

/// Legacy `<CustomData>` key of the pre-redesign parked-conflict history
/// marker. The hold-open redesign (keepass-merge #215, clean cut) deleted
/// the marker entirely, and the Phase-4 owner-rows switch now badges
/// conflicts from the `conflict_entry` rows
/// ([`entries_with_parked_conflict`]) — never stored on history records.
/// This const survives **only** to recognise and clean up markers left in
/// vaults written by an older build:
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
    /// Entries whose history was pruned because a peer's
    /// `keys.history_tombstones.v1` record propagated a history-snapshot
    /// deletion (the privacy fix, part 2). Distinct bucket because the live
    /// entry is typically `InSync` — only its history changed — so it would
    /// otherwise be an invisible `Applied`-with-zero-counts.
    pub history_pruned: usize,
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
        // The disk-reconcile path folds history-tombstone reconciliation into
        // its eager merge (`apply_merge`), so it has no separate count.
        history_pruned: 0,
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

/// Rebuild the rich conflict payload for the **held** (parked) entries from
/// the owner-rows store and stash a context so they can be resolved through
/// the same [`Engine::apply_conflict_resolution`] entry point the live path
/// uses.
///
/// This is the resolver-open counterpart to the badge query
/// [`entries_with_parked_conflict`]. "Theirs" is reconstructed from the
/// `conflict_*` owner rows the park reconcile wrote — NOT from the vault file:
/// hold-open never writes the peer value to disk (loop-safety), and over iroh
/// the peer blob arrives in a throwaway temp file. `_kdbx_path` / `_composite`
/// are retained only for FFI-signature stability — this method touches neither
/// the disk file nor the composite key.
///
/// It builds a synthetic `theirs` vault (a clone of local with each parked
/// entry swapped for its reconstructed peer value), merges local-vs-theirs to
/// produce the rich [`ConflictPayload`] (the same field / icon / attachment
/// delta shape the live path emits), and stashes a [`PendingConflictContext`]
/// so a later `apply_conflict_resolution(id, …)` converges the chosen values
/// and writes the propagating resolution records.
///
/// Side effects: the stash, plus **clearing the `conflict_*` rows of any
/// candidate whose conflict has dissolved** — when the local-vs-theirs merge
/// for a held entry surfaces no conflict (e.g. a peer's resolution record
/// synced in, or local has since converged on the peer's values), the rows
/// are stale state. Leaving them made the badge immortal: the resolver
/// opened to nothing while [`entries_with_parked_conflict`] kept reporting
/// the entry forever (found by keyhole's fuzz soak — DESIGN.md Finding #5).
/// After clearing a dissolved candidate, the unfiltered path moves on to the
/// next held entry, so `None` genuinely means "nothing left to resolve".
///
/// Multi-peer note: when an entry carries rows from several peers this picks
/// the first owner ([`conflict_rows::conflict_owners_for`] returns them sorted)
/// — surfacing the full N-value picker is deferred.
pub(crate) fn held_conflict_payload(
    engine: &mut Engine,
    _kdbx_path: &Path,
    _composite_key: &CompositeKey,
    entry_filter: Option<uuid::Uuid>,
) -> Result<Option<ConflictPayload>, EngineError> {
    let mut parked = conflict_rows::parked_conflict_uuids(engine.conn())?;
    // One conflict per resolution session — the resolver is one-entry-at-a-time.
    // The apply validates a session atomically, so a multi-entry session rejects
    // a single-entry resolution (the badge-never-clears soak bug). Scope to the
    // requested entry, else walk the held set uuid-sorted (deterministic pick);
    // resolving one drops only its rows, leaving the rest held.
    parked.sort();
    if let Some(filter) = entry_filter {
        parked.retain(|u| *u == filter);
    }

    let local_vault = engine.project_to_vault()?;
    let session_key = engine
        .field_protector_arc()
        .acquire_session_key()
        .map_err(|e| EngineError::Serialise(format!("acquire session key: {e}")))?;

    for uuid in parked {
        // First reconcile this entry's rows owner-by-owner: drop any whose
        // divergence has dissolved (or all, if the entry is gone), leaving
        // only genuinely-live owners. Using the same machinery as the
        // write-side reconcile keeps badge and resolver in agreement and
        // avoids the multi-owner over-clear an owner-agnostic drop here
        // would cause (drop owner B's dissolved row, NOT peer C's live one).
        let owners = conflict_rows::conflict_owners_for(engine.conn(), uuid)?;
        if owners.is_empty() {
            continue;
        }
        let decision = dissolve_decision(engine, &local_vault, &session_key, uuid, &owners)?;
        apply_dissolve(engine, uuid, decision)?;

        // Build "theirs" from the first still-live owner, if any remain.
        let live_owners = conflict_rows::conflict_owners_for(engine.conn(), uuid)?;
        let Some(owner) = live_owners.first() else {
            continue; // fully dissolved — nothing to resolve.
        };
        let Some(reconstructed) =
            conflict_rows::reconstruct_peer_entry(engine.conn(), owner, uuid, &session_key)?
        else {
            continue;
        };
        let mut theirs_vault = local_vault.clone();
        let peer_entry = bind_attachments_into_pool(reconstructed, &mut theirs_vault.binaries);
        swap_entry_in_tree(&mut theirs_vault.root, peer_entry);

        let outcome = keepass_merge::merge(&local_vault, &theirs_vault)
            .map_err(|e| EngineError::Serialise(format!("merge: {e}")))?;

        if outcome.entry_conflicts.is_empty() && outcome.delete_edit_conflicts.is_empty() {
            // A live owner that nonetheless merges clean is a belt-and-
            // braces case (reconcile above should have dropped it); skip.
            continue;
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
            remote_vault: theirs_vault,
        });
        return Ok(Some(payload));
    }
    Ok(None)
}

/// Per-owner decision for one entry's parked conflict rows.
enum DissolveDecision {
    /// The entry is gone locally (deleted) — drop every owner's rows.
    DropAll,
    /// Drop only these owners' rows (their divergence dissolved); any
    /// owner not listed still genuinely conflicts and stays parked.
    DropOwners(Vec<String>),
}

/// Read-only: decide which of `uuid`'s parked conflict rows have
/// dissolved against the current local state. No DB writes — the caller
/// applies the decision in a transaction. `owners` is `uuid`'s current
/// owner set (already known non-empty by the caller).
fn dissolve_decision(
    engine: &Engine,
    local_vault: &keepass_core::model::Vault,
    session_key: &keepass_core::protector::SessionKey,
    uuid: uuid::Uuid,
    owners: &[String],
) -> Result<DissolveDecision, EngineError> {
    // Entry deleted locally → no live side to conflict against; the
    // rows are orphans (Finding #11). Drop them all.
    if !child_contains_entry(&local_vault.root, keepass_core::model::EntryId(uuid)) {
        return Ok(DissolveDecision::DropAll);
    }
    let mut dissolved = Vec::new();
    for owner in owners {
        // A row that no longer reconstructs is itself stale → drop it.
        let Some(reconstructed) =
            conflict_rows::reconstruct_peer_entry(engine.conn(), owner, uuid, session_key)?
        else {
            dissolved.push(owner.clone());
            continue;
        };
        // "Theirs" = local with this entry swapped for the owner's parked
        // value; if a merge against local finds no conflict, this owner's
        // divergence has dissolved. Same check the resolver
        // (`held_conflict_payload`) runs — kept identical so badge and
        // resolver always agree.
        let mut theirs = local_vault.clone();
        let peer_entry = bind_attachments_into_pool(reconstructed, &mut theirs.binaries);
        swap_entry_in_tree(&mut theirs.root, peer_entry);
        let outcome = keepass_merge::merge(local_vault, &theirs)
            .map_err(|e| EngineError::Serialise(format!("merge: {e}")))?;
        if outcome.entry_conflicts.is_empty() && outcome.delete_edit_conflicts.is_empty() {
            dissolved.push(owner.clone());
        }
    }
    Ok(DissolveDecision::DropOwners(dissolved))
}

/// Apply a [`DissolveDecision`] in a single transaction.
fn apply_dissolve(
    engine: &mut Engine,
    uuid: uuid::Uuid,
    decision: DissolveDecision,
) -> Result<(), EngineError> {
    let owners = match decision {
        DissolveDecision::DropAll => {
            let tx = engine.conn_mut().transaction()?;
            conflict_rows::drop_conflict_rows(&tx, uuid)?;
            tx.commit()?;
            return Ok(());
        }
        DissolveDecision::DropOwners(o) => o,
    };
    if owners.is_empty() {
        return Ok(());
    }
    let tx = engine.conn_mut().transaction()?;
    for owner in &owners {
        conflict_rows::drop_conflict_rows_for_owner(&tx, owner, uuid)?;
    }
    tx.commit()?;
    Ok(())
}

/// Reconcile ONE entry's parked conflict rows against the current local
/// state, dropping rows whose divergence has dissolved (Finding #10).
///
/// The badge query ([`conflict_rows::parked_conflict_uuids`]) is a cheap
/// `SELECT` that can't tell a live conflict from a dissolved one; the
/// merge-backed resolver ([`held_conflict_payload`]) only healed stale
/// rows lazily on open, so the badge could show a conflict the resolver
/// considered gone (a ghost badge). This restores the invariant "a
/// `conflict_entry(owner, E)` row exists iff E exists locally AND still
/// genuinely diverges from that owner's stored value" eagerly, on the
/// write side — so badge reads stay a trivial `SELECT`.
///
/// Cheap when `entry_uuid` has no parked rows (the overwhelmingly common
/// case): one indexed `SELECT` and return, no projection. Only an entry
/// that is *actually* in conflict pays the projection + per-owner merge —
/// rare, and exactly when the caller is already touching that conflict.
/// Call it after any local content edit or delete of an entry.
///
/// Best-effort, not part of the edit's atomic unit: callers run this in
/// its own transaction *after* the mutation has committed, so a crash in
/// the window leaves a transiently over-reported badge (never lost vault
/// data). The next ingest sweep ([`reconcile_all_conflict_rows`]) or
/// resolver-open ([`held_conflict_payload`]) is the backstop.
pub(crate) fn reconcile_conflict_rows(
    engine: &mut Engine,
    entry_uuid: uuid::Uuid,
) -> Result<(), EngineError> {
    let owners = conflict_rows::conflict_owners_for(engine.conn(), entry_uuid)?;
    if owners.is_empty() {
        return Ok(());
    }
    let local_vault = engine.project_to_vault()?;
    let session_key = engine
        .field_protector_arc()
        .acquire_session_key()
        .map_err(|e| EngineError::Serialise(format!("acquire session key: {e}")))?;
    let decision = dissolve_decision(engine, &local_vault, &session_key, entry_uuid, &owners)?;
    apply_dissolve(engine, entry_uuid, decision)
}

/// Reconcile EVERY parked entry's conflict rows in one pass — the
/// post-ingest sweep. A sync can dissolve a conflict with peer C as a
/// side effect of adopting peer B's value (the ingest arms only clear
/// the ingested owner, owner-scoped), so after ingest we sweep the whole
/// parked set to drop any rows that dissolved. Projects the vault once.
pub(crate) fn reconcile_all_conflict_rows(engine: &mut Engine) -> Result<(), EngineError> {
    let parked = conflict_rows::parked_conflict_uuids(engine.conn())?;
    if parked.is_empty() {
        return Ok(());
    }
    let local_vault = engine.project_to_vault()?;
    let session_key = engine
        .field_protector_arc()
        .acquire_session_key()
        .map_err(|e| EngineError::Serialise(format!("acquire session key: {e}")))?;
    for uuid in parked {
        let owners = conflict_rows::conflict_owners_for(engine.conn(), uuid)?;
        if owners.is_empty() {
            continue;
        }
        let decision = dissolve_decision(engine, &local_vault, &session_key, uuid, &owners)?;
        apply_dissolve(engine, uuid, decision)?;
    }
    Ok(())
}

/// Bind a reconstructed peer entry's attachment bytes into `pool` and return
/// the entry with its `Attachment` refs set (Finding #7).
///
/// `pool` is the synthetic "theirs" vault's binary pool — a clone of the
/// local projection's, which is content-deduplicated — so the common case
/// (peer and local agree on the bytes) reuses an existing binary and adds
/// nothing; only genuinely divergent peer bytes grow the pool.
fn bind_attachments_into_pool(
    reconstructed: crate::conflict_rows::ReconstructedPeerEntry,
    pool: &mut Vec<keepass_core::model::Binary>,
) -> keepass_core::model::Entry {
    let crate::conflict_rows::ReconstructedPeerEntry {
        mut entry,
        attachments,
    } = reconstructed;
    for (name, bytes) in attachments {
        let ref_id = pool
            .iter()
            .position(|b| b.data == bytes)
            .unwrap_or_else(|| {
                pool.push(keepass_core::model::Binary::new(bytes, false));
                pool.len() - 1
            });
        // Pools are tiny relative to u32; saturate rather than panic on a
        // pathological vault (a wrong ref is a skipped attachment, caught
        // by the digest oracle, not corruption).
        let ref_id = u32::try_from(ref_id).unwrap_or(u32::MAX);
        entry
            .attachments
            .push(keepass_core::model::Attachment::new(name, ref_id));
    }
    entry
}

/// Replace the entry with `replacement.id` in the group tree with
/// `replacement` (in place, preserving its group). A no-op if no entry with
/// that id exists in the tree. Used to splice a reconstructed peer entry into
/// the synthetic "theirs" vault.
fn swap_entry_in_tree(
    group: &mut keepass_core::model::Group,
    replacement: keepass_core::model::Entry,
) {
    if let Some(slot) = group.entries.iter_mut().find(|e| e.id == replacement.id) {
        *slot = replacement;
        return;
    }
    for child in &mut group.groups {
        // Cheap to recurse; the entry lives in exactly one group.
        if child_contains_entry(child, replacement.id) {
            swap_entry_in_tree(child, replacement);
            return;
        }
    }
}

/// Whether `group` (or a descendant) holds an entry with `id`.
fn child_contains_entry(group: &keepass_core::model::Group, id: EntryId) -> bool {
    group.entries.iter().any(|e| e.id == id)
        || group.groups.iter().any(|g| child_contains_entry(g, id))
}

/// Park-conflicts variant of [`reconcile_with_disk`] — the live sync path,
/// now backed by the multi-peer **owner-rows** store.
///
/// Reads / parses / unlocks the disk kdbx and projects the remote vault, then
/// hands it to [`Engine::ingest_peer`] (the owner-rows ingest) under the
/// [`FILE_OWNER`] sentinel. `ingest_peer` runs the per-entry `classify` brain
/// and, in one transaction:
///
/// - advances the local mirror for one-sided / non-overlapping peer edits
///   (`auto_merged`), and
/// - holds open genuine clashes — local untouched, the peer's value stored as
///   an `owner`-keyed `conflict_*` row (`conflicted`) the resolver reads.
///
/// **Loop-safety (the #1 invariant).** A held conflict advances *nothing*
/// locally, so there is nothing to save → no fresh-nonce re-push → the iroh
/// loop can't start. The discriminator is exact: `auto_merged`, `added`, *and*
/// `deleted` all empty ⇒ `NoChange`; any non-empty (a real local advance — a
/// merged edit, a peer-only add, or a propagated cross-peer delete) ⇒
/// `Applied`. This structural guarantee replaces the old `park_merge_is_no_op`
/// tree-compare guard.
///
/// The badge ([`entries_with_parked_conflict`]) and the resolver's "theirs"
/// ([`held_conflict_payload`]) both read the owner rows directly — no derived
/// `held_conflicts` kv, no theirs-stash, no baseline refresh on this path.
/// Keys-Mac saves the KDBX from the advanced projection on `Applied`.
pub(crate) fn reconcile_with_disk_park_conflicts(
    engine: &mut Engine,
    kdbx_path: &Path,
    composite_key: &CompositeKey,
    _now: chrono::DateTime<chrono::Utc>,
) -> Result<ParkConflictsResult, EngineError> {
    // The disk file is one peer under the FILE_OWNER sentinel — the
    // file-watcher / Syncthing / external-client path.
    ingest_kdbx_as_owner(engine, kdbx_path, composite_key, FILE_OWNER)
}

/// Per-device-key sync transport: ingest a fetched peer KDBX blob under the
/// peer's own device-id `owner`, so 3+ peers' divergences land in distinct
/// owner rows (vs the single `FILE_OWNER` used for the disk-watcher path). Same
/// owner-rows engine; the owner string is the only difference.
pub(crate) fn ingest_peer_from_kdbx(
    engine: &mut Engine,
    kdbx_path: &Path,
    composite_key: &CompositeKey,
    owner: &str,
) -> Result<ParkConflictsResult, EngineError> {
    ingest_kdbx_as_owner(engine, kdbx_path, composite_key, owner)
}

fn ingest_kdbx_as_owner(
    engine: &mut Engine,
    kdbx_path: &Path,
    composite_key: &CompositeKey,
    owner: &str,
) -> Result<ParkConflictsResult, EngineError> {
    // Read / parse / unlock the disk kdbx and project the remote vault — the
    // same prefix the eager-merge path used.
    let disk_bytes = std::fs::read(kdbx_path)?;
    let disk_kdbx = Kdbx::open_from_bytes(disk_bytes.clone())
        .map_err(|e| EngineError::Serialise(format!("open disk kdbx: {e}")))?
        .read_header()
        .map_err(|e| EngineError::Serialise(format!("read disk header: {e}")))?
        .unlock_with_protector(composite_key, Some(engine.field_protector_arc()))
        .map_err(|e| EngineError::Serialise(format!("unlock disk kdbx: {e}")))?;

    let remote_vault = disk_kdbx
        .vault_with_unwrapped_protected()
        .map_err(|e| EngineError::Serialise(format!("unwrap disk protected: {e}")))?;

    // Owner-rows ingest under `owner` (FILE_OWNER for the disk path, the peer's
    // device id for the per-device-key transport). `ingest_peer` advances local
    // on auto-merge and writes owner rows on a held conflict, committing its
    // own transaction.
    let outcome = engine.ingest_peer(owner, &remote_vault)?;

    // Loop-safety discriminator: only an advanced local side (a non-empty
    // `auto_merged`, `added`, `deleted`, `moved`, or `history_pruned`) is
    // something to save. A held conflict advanced nothing → NoChange → no save
    // → no re-push → the loop never starts. The badge reads the owner rows
    // directly, so `conflicted` does NOT make this `Applied`. A propagated
    // cross-peer delete (Phase 5b), location move (Phase 5d), or history-
    // snapshot deletion (the privacy fix, part 2) is a real local change, so it
    // does (mirrors the `added` bucket). Loop-safe: an adopted move takes the
    // peer's verbatim `location_changed`, and a history-tombstone reconcile is
    // idempotent once both sides agree, so the re-saved value matches what the
    // peer holds → the peer's next pull sees nothing newer → the loop settles.
    if outcome.auto_merged.is_empty()
        && outcome.added.is_empty()
        && outcome.deleted.is_empty()
        && outcome.moved.is_empty()
        && outcome.groups_added.is_empty()
        && outcome.groups_updated.is_empty()
        && outcome.groups_moved.is_empty()
        && outcome.groups_deleted.is_empty()
        && outcome.history_pruned.is_empty()
    {
        return Ok(ParkConflictsResult::NoChange);
    }

    let stats = MergeStats {
        entries_added: outcome.added.len(),
        entries_updated: outcome.auto_merged.len(),
        entries_deleted: outcome.deleted.len(),
        entries_moved: outcome.moved.len(),
        groups_added: outcome.groups_added.len(),
        groups_updated: outcome.groups_updated.len(),
        groups_moved: outcome.groups_moved.len(),
        groups_deleted: outcome.groups_deleted.len(),
        history_pruned: outcome.history_pruned.len(),
    };
    let parked = ParkedConflictsSummary {
        entries_with_parked_conflict: outcome
            .conflicted
            .iter()
            .map(uuid::Uuid::to_string)
            .collect(),
        ..Default::default()
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
/// Reads the owner-rows store directly: any entry with at least one stored
/// peer `conflict_*` row (`SELECT DISTINCT entry_uuid FROM conflict_entry`).
/// This replaced the derived `held_conflicts` kv — the badge is now a plain
/// query over the rows [`reconcile_with_disk_park_conflicts`] populates, so it
/// can't flap or go stale, and it survives engine close + reopen for free.
pub(crate) fn entries_with_parked_conflict(
    engine: &Engine,
) -> Result<Vec<uuid::Uuid>, EngineError> {
    conflict_rows::parked_conflict_uuids(engine.conn())
}

/// Dismiss the held-conflict badge on the named entry locally by dropping its
/// owner (`conflict_*`) rows across every peer.
///
/// This is the **local** dismissal half of hold-open: clearing the rows drops
/// the entry from the owner-rows badge query immediately on this device.
/// Cross-peer convergence is driven separately by the
/// `keys.conflict_resolutions.v1` record that
/// [`crate::conflict_resolution::apply_conflict_resolution`] writes — merely
/// clearing the rows here does not resolve the conflict on other peers.
///
/// Idempotent: an entry with no stored conflict rows returns 0.
///
/// Returns the number of `conflict_entry` rows removed.
pub(crate) fn clear_parked_conflict_marker(
    engine: &mut Engine,
    entry_uuid: uuid::Uuid,
    _now: chrono::DateTime<chrono::Utc>,
) -> Result<u32, EngineError> {
    conflict_rows::drop_conflict_rows(engine.conn(), entry_uuid)
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
