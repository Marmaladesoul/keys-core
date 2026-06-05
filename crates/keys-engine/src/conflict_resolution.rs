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
//! 3. Record a `keys.conflict_resolutions.v1` entry into the merged
//!    vault's Meta for every resolved facet, so the decision propagates
//!    and peers adopt the resolving side's value (design §5.3). The
//!    record carries no value and no side — secret-safe; the chosen value
//!    rides as ordinary protected entry data that step 2 already set.
//! 4. Reconcile timestamps and re-ingest into `SQLite` via the same
//!    single-transaction `ingest_merged` path 4.6 uses for `Merged`.
//! 5. Refresh `last_saved_kdbx_bytes` to the disk-side bytes, drop the
//!    resolved entries from the derived held-conflict badge set, and emit
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

use std::collections::HashSet;

use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{Group, Vault};
use keepass_merge::{ConflictKind, ConflictResolution, MergeOutcome, Resolution};
use secrecy::SecretString;
use uuid::Uuid;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::events::{ChangeEvent, ConflictPayload};
use crate::reconcile::MergeStats;

/// Canonical KDBX field name for an entry's password slot.
///
/// Matched against `field_name` in [`reveal_conflict_field_from_vault`]
/// to route password reveals through [`keepass_core::model::Entry::password`]
/// rather than [`keepass_core::model::Entry::custom_fields`].
const PASSWORD_FIELD: &str = "Password";

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
    //    through to NotFound. Also drop the peek-side payload mirror
    //    so [`Engine::pending_conflict`] starts returning `None` —
    //    even if the apply walk below fails, the context is gone
    //    (see this fn's type-level doc on irrevocable consumption).
    let ctx = engine
        .take_pending_conflict_context(id)
        .ok_or(EngineError::NotFound {
            entity: "conflict_payload",
        })?;
    engine.discard_pending_conflict_payload(id);

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
    let now = chrono::Utc::now();
    let mut merged = local_vault;
    keepass_merge::apply_merge(&mut merged, &remote_vault, &outcome, resolution).map_err(|e| {
        EngineError::ResolutionMismatch {
            reason: e.to_string(),
        }
    })?;
    keepass_merge::reconcile_timestamps(&mut merged, &remote_vault);

    // 3. Record the resolution into the merged vault's Meta so it
    //    propagates: the next save writes a `keys.conflict_resolutions.v1`
    //    record per resolved facet, and on the peer's next merge the
    //    presence-asymmetry adoption rule converges that facet to this
    //    side's (now chosen) value (design §5.3). Secret-safe: the record
    //    carries no value and no side — the chosen value rides as ordinary
    //    protected entry data, which `apply_merge` already set above.
    record_resolutions_into_meta(&mut merged, resolution, now)?;

    // 4. Splice the merged vault into the unlocked disk Kdbx and
    //    re-ingest. The disk Kdbx already has the protector and crypto
    //    envelope wired up; reusing it avoids re-unlocking (and thus
    //    avoids asking the caller for the composite key again).
    disk_kdbx.replace_vault(merged);
    engine.ingest_merged(&disk_kdbx)?;

    // 5. Refresh the common ancestor to the disk bytes — same as 4.6's
    //    Merged path. A follow-up save_to_kdbx will overwrite the disk
    //    file (and the ancestor) with the resolved-and-combined state.
    engine.set_last_saved_kdbx_bytes(&disk_bytes)?;

    // Drop the resolved entries from the derived held-conflict badge set:
    // their conflicts have converged locally to the chosen values, so they
    // are no longer held on this device. (Cross-peer clearing rides the
    // resolution records written in step 3.) Keeps the badge consistent
    // without waiting for the next reconcile.
    let resolved_entries: HashSet<Uuid> = resolution
        .entry_field_choices
        .keys()
        .chain(resolution.entry_attachment_choices.keys())
        .chain(resolution.entry_icon_choices.keys())
        .chain(resolution.delete_edit_choices.keys())
        .map(|e| e.0)
        .collect();
    if !resolved_entries.is_empty() {
        let mut held = engine.held_conflicts()?;
        let before = held.len();
        held.retain(|u| !resolved_entries.contains(u));
        if held.len() != before {
            engine.set_held_conflicts(&held)?;
        }
    }

    // 6. Emit the success event. Stats are best-effort — the resolved
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

/// Write a [`ConflictResolution`] record into `merged`'s Meta for every
/// facet covered by `resolution`, so the user's decision propagates and
/// peers adopt the resolving side's value (design §5.3).
///
/// One record per resolved field / attachment / icon, keyed by
/// `(entry, kind, key)` and set-unioned via
/// [`keepass_merge::add_conflict_resolution`]. The records are
/// **side-agnostic and value-free** by the secret-safety rule: which side
/// won and the chosen value never travel in the record — the value rides as
/// ordinary protected entry data that `apply_merge` already set, and the
/// peer infers "adopt this side's current value" from presence-asymmetry.
///
/// `delete_edit_choices` get no record: a delete-vs-edit decision isn't a
/// field/icon/attachment facet (there's no matching [`ConflictKind`]), and
/// the merge's tombstone/restore logic already converges it.
fn record_resolutions_into_meta(
    merged: &mut Vault,
    resolution: &Resolution,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), EngineError> {
    let cd = &mut merged.meta.custom_data;
    let mut add = |record: &ConflictResolution| -> Result<(), EngineError> {
        keepass_merge::add_conflict_resolution(cd, record)
            .map_err(|e| EngineError::Serialise(format!("add_conflict_resolution: {e}")))
    };

    for (entry, fields) in &resolution.entry_field_choices {
        for field_name in fields.keys() {
            add(&ConflictResolution::new(
                entry.0,
                ConflictKind::Field,
                Some(field_name.clone()),
                now,
                None,
            ))?;
        }
    }
    for (entry, attachments) in &resolution.entry_attachment_choices {
        for name in attachments.keys() {
            add(&ConflictResolution::new(
                entry.0,
                ConflictKind::Attachment,
                Some(name.clone()),
                now,
                None,
            ))?;
        }
    }
    for entry in resolution.entry_icon_choices.keys() {
        add(&ConflictResolution::new(
            entry.0,
            ConflictKind::Icon,
            None,
            now,
            None,
        ))?;
    }
    Ok(())
}

/// Reveal a single field on the local side of a stashed conflict.
///
/// Pulled out of [`Engine`] so the method body stays narrow; mirrors
/// [`apply_conflict_resolution`]'s placement. See the engine method
/// [`Engine::reveal_conflict_local_field`] for the public contract.
pub(crate) fn reveal_conflict_local_field(
    engine: &Engine,
    conflict_id: i64,
    entry_uuid: Uuid,
    field_name: &str,
) -> Result<SecretString, EngineError> {
    let guard = engine.pending_conflict_contexts_lock();
    let ctx = guard.get(&conflict_id).ok_or(EngineError::NotFound {
        entity: "conflict_payload",
    })?;
    reveal_conflict_field_from_vault(&ctx.local_vault, entry_uuid, field_name)
}

/// Reveal a single field on the remote side of a stashed conflict.
///
/// Sibling of [`reveal_conflict_local_field`]; routes through the
/// stash's `remote_vault` instead.
pub(crate) fn reveal_conflict_remote_field(
    engine: &Engine,
    conflict_id: i64,
    entry_uuid: Uuid,
    field_name: &str,
) -> Result<SecretString, EngineError> {
    let guard = engine.pending_conflict_contexts_lock();
    let ctx = guard.get(&conflict_id).ok_or(EngineError::NotFound {
        entity: "conflict_payload",
    })?;
    reveal_conflict_field_from_vault(&ctx.remote_vault, entry_uuid, field_name)
}

/// Find `entry_uuid` in `vault` and return `field_name` as a
/// [`SecretString`].
///
/// ## Plaintext invariant
///
/// Both vaults stashed in [`PendingConflictContext`] hold protected
/// fields as **plaintext** by construction: `local_vault` is produced
/// by [`Engine::project_to_vault`] (which unwraps `entry_protected`
/// rows under the session key on projection) and `remote_vault` by
/// [`keepass_core::kdbx::Kdbx::vault_with_unwrapped_protected`] (same
/// post-unwrap shape). No protector / session-key acquisition is
/// needed here — the values already sit in `Entry::password` /
/// `CustomField::value` ready to read.
///
/// `field_name == "Password"` reads [`keepass_core::model::Entry::password`];
/// any other name reads from [`keepass_core::model::Entry::custom_fields`].
fn reveal_conflict_field_from_vault(
    vault: &Vault,
    entry_uuid: Uuid,
    field_name: &str,
) -> Result<SecretString, EngineError> {
    let entry = find_entry_in_group(&vault.root, entry_uuid)
        .ok_or(EngineError::NotFound { entity: "entry" })?;
    let value = if field_name == PASSWORD_FIELD {
        entry.password.clone()
    } else {
        entry
            .custom_fields
            .iter()
            .find(|cf| cf.key == field_name)
            .map(|cf| cf.value.clone())
            .ok_or(EngineError::NotFound {
                entity: "custom_field",
            })?
    };
    Ok(SecretString::from(value))
}

/// Walk `group` (and its descendants) for an entry whose UUID matches
/// `target`. Sibling of `engine::find_entry_parent_group` but returns
/// the entry itself rather than its parent group.
fn find_entry_in_group(group: &Group, target: Uuid) -> Option<&keepass_core::model::Entry> {
    if let Some(e) = group.entries.iter().find(|e| e.id.0 == target) {
        return Some(e);
    }
    group
        .groups
        .iter()
        .find_map(|child| find_entry_in_group(child, target))
}
