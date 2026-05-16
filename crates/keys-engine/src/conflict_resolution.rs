//! Conflict-resolution apply — Phase 4 task 4.7.
//!
//! Implements [`Engine::apply_conflict_resolution`](crate::Engine::apply_conflict_resolution):
//! the back half of the external-change merge dance kicked off by task
//! 4.6's [`Engine::reconcile_with_disk`](crate::Engine::reconcile_with_disk).
//!
//! When `reconcile_with_disk` surfaces irreconcilable conflicts it
//! stashes a `PendingConflictContext` on the engine alongside the
//! public [`crate::events::ConflictPayload`] (both keyed by a
//! synthetic `i64`). The frontend renders a resolver UI, gathers the
//! user's per-field / per-attachment / per-icon / delete-vs-edit
//! choices into a [`keepass_merge::Resolution`], and calls back into
//! [`Engine::apply_conflict_resolution`] with the stash id and the
//! resolution.
//!
//! Apply is a thin pass-through:
//!
//! 1. Take the stashed context by id (consumed — second call with the
//!    same id returns [`EngineError::NotFound`]).
//! 2. Run `keepass_merge::apply_merge` against the stashed local /
//!    remote vaults and outcome, with the caller's resolution.
//! 3. Reconcile timestamps and re-ingest into `SQLite` via the same
//!    single-transaction `ingest_merged` path 4.6 uses for `Merged`.
//! 4. Refresh `last_saved_kdbx_bytes` to the disk-side bytes and emit
//!    [`crate::events::ChangeEvent::ExternalChangeMerged`] with empty
//!    `conflicts`.
//!
//! ## Atomicity
//!
//! The `apply_merge` step runs against an owned clone of the local
//! vault; failure bails before touching `SQLite`. The re-ingest path
//! wraps the entire `SQLite` walk in a single transaction. The stash
//! is consumed *before* either step, so a failed apply does not leave
//! the same id reusable — by design, a retry needs a fresh
//! `reconcile_with_disk` run because the caller's mental model of the
//! conflict shape may be stale.
//!
//! ## Resolution validation
//!
//! `keepass_merge::apply_merge` runs a read-only validation pass
//! first; any mismatch (entry not in conflict bucket, field key not
//! in delta list, missing resolution for a `delete_edit` conflict,
//! `KeepBoth` on a single-sided attachment) is collapsed to
//! [`EngineError::ResolutionMismatch`] via the `MergeError` Display.

use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::Vault;
use keepass_merge::{MergeOutcome, Resolution};

use crate::engine::Engine;
use crate::error::EngineError;
use crate::events::{ChangeEvent, ConflictPayload};
use crate::reconcile::MergeStats;

/// Internal stash entry siblinged with a public [`ConflictPayload`].
///
/// Holds the additional context [`Engine::apply_conflict_resolution`]
/// needs to drive `keepass_merge::apply_merge` without re-running the
/// merge or re-asking the caller for the composite key:
///
/// - the full [`MergeOutcome`] (the public payload only carries the
///   conflict buckets);
/// - both pre-merge vaults (so apply has both sides verbatim);
/// - the already-unlocked disk [`Kdbx`] (so the merged [`Vault`] can be
///   spliced in and ingested without re-deriving keys);
/// - the disk bytes (so the common ancestor can be refreshed on the
///   same value 4.6 would have used had the merge auto-applied).
pub(crate) struct PendingConflictContext {
    pub(crate) payload: ConflictPayload,
    pub(crate) outcome: MergeOutcome,
    pub(crate) local_vault: Vault,
    pub(crate) remote_vault: Vault,
    pub(crate) disk_kdbx: Kdbx<Unlocked>,
    pub(crate) disk_bytes: Vec<u8>,
}

impl std::fmt::Debug for PendingConflictContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `MergeOutcome`, `Vault`, and `Kdbx<Unlocked>` are all heavy
        // types that would dominate any debug-print and add zero
        // signal here — the payload id and bucket sizes are the
        // only thing a caller actually needs. `finish_non_exhaustive`
        // makes the intent explicit to clippy.
        f.debug_struct("PendingConflictContext")
            .field("payload_id", &self.payload.id)
            .field("entry_conflicts", &self.payload.entry_conflicts.len())
            .field(
                "delete_edit_conflicts",
                &self.payload.delete_edit_conflicts.len(),
            )
            .field("disk_bytes_len", &self.disk_bytes.len())
            .finish_non_exhaustive()
    }
}

/// The apply implementation. Pulled out of [`Engine`] so the method
/// body stays narrow — mirrors `reconcile::reconcile_with_disk`.
pub(crate) fn apply_conflict_resolution(
    engine: &mut Engine,
    id: i64,
    resolution: &Resolution,
) -> Result<(), EngineError> {
    // 1. Consume the stash. A second call with the same id falls
    //    through to NotFound.
    let ctx = engine
        .take_pending_conflict_context(id)
        .ok_or(EngineError::NotFound {
            entity: "conflict_payload",
        })?;

    let PendingConflictContext {
        payload: _,
        outcome,
        local_vault,
        remote_vault,
        mut disk_kdbx,
        disk_bytes,
    } = ctx;

    // 2. Apply the merge against an owned copy of the local side.
    //    `apply_merge` does its own read-only validation pass before
    //    any mutation; a validation failure bails here without
    //    touching SQLite or the engine state.
    let mut merged = local_vault;
    keepass_merge::apply_merge(&mut merged, &remote_vault, &outcome, resolution).map_err(|e| {
        EngineError::ResolutionMismatch {
            reason: e.to_string(),
        }
    })?;
    keepass_merge::reconcile_timestamps(&mut merged, &remote_vault);

    // 3. Splice the merged vault into the unlocked disk Kdbx and
    //    re-ingest. The disk Kdbx already has the protector and crypto
    //    envelope wired up; reusing it avoids re-unlocking (and thus
    //    avoids asking the caller for the composite key again).
    disk_kdbx.replace_vault(merged);
    engine.ingest_merged(&disk_kdbx)?;

    // 4. Refresh the common ancestor to the disk bytes — same as 4.6's
    //    Merged path. A follow-up save_to_kdbx will overwrite the disk
    //    file (and the ancestor) with the resolved-and-combined state.
    engine.set_last_saved_kdbx_bytes(&disk_bytes)?;

    // 5. Emit the success event. Stats are best-effort — the resolved
    //    state has already landed and the frontend's primary signal is
    //    that the conflict has cleared; cardinality of the merge here
    //    is reported as zero across the board because the field-level
    //    resolution doesn't fit the "added / updated / deleted entry"
    //    taxonomy of the MergeStats counters cleanly. Future slices
    //    may refine this; the bucket counts on `outcome` are available
    //    if a downstream consumer wants finer breakdown.
    let applied = MergeStats {
        entries_added: outcome.added_on_disk.len(),
        entries_updated: outcome.disk_only_changes.len()
            + outcome.local_only_changes.len()
            + outcome.entry_conflicts.len(),
        entries_deleted: outcome.deleted_on_disk.len(),
        entries_moved: 0,
        groups_added: 0,
        groups_updated: 0,
        groups_deleted: 0,
        groups_moved: 0,
    };
    engine.emit(ChangeEvent::ExternalChangeMerged { applied });

    Ok(())
}
