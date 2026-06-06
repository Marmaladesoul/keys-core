//! `Engine` conflict-resolution methods — the bridge between
//! `reconcile_with_disk` (which stashes a `ConflictPayload` when the
//! merge can't be fully auto-resolved) and the caller's eventual
//! `apply_conflict_resolution` call.
//!
//! Read-side accessors (`pending_conflict`,
//! `pending_conflict_parent_groups`, `pending_conflict_count_for_test`)
//! let the frontend render the resolver UI from the stashed payload.
//! Reveal-side accessors (`reveal_conflict_local_field`,
//! `reveal_conflict_remote_field`) unwrap protected slots from either
//! side of the conflict on demand.
//! `apply_conflict_resolution` consumes the stashed
//! [`PendingConflictContext`] and re-ingests the merged vault.
//! `consume_self_write_signature` lives here because the file-watcher's
//! "is this our own write?" check is what drives conflict detection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::FieldProtector;
use secrecy::SecretString;
use uuid::Uuid;

use crate::error::EngineError;
use crate::events::{ConflictPayload, EntryParentGroups};
use crate::save::SelfWriteSignature;

use super::{Engine, find_entry_parent_group};

impl Engine {
    /// Peek a stashed conflict payload by `id` without consuming it.
    ///
    /// Frontends call this after receiving
    /// [`crate::events::ChangeEvent::ConflictDetected`]
    /// to render the resolver UI, then later call
    /// [`Self::apply_conflict_resolution`] (which consumes the
    /// matching context) once the user has picked their per-field /
    /// per-attachment / per-icon / delete-vs-edit choices.
    ///
    /// Repeated calls with the same `id` return the same payload (a
    /// clone) until `apply_conflict_resolution` succeeds; from that
    /// point on this returns `None` for that id. A frontend that
    /// abandons the resolution (e.g. user closes the window) leaves
    /// the payload in the stash; a fresh
    /// [`Self::reconcile_with_disk`] produces a new
    /// [`ConflictPayload`] with a fresh id.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned —
    /// see [`Self::last_self_write`] for the same caveat. Not
    /// expected in practice.
    #[must_use]
    pub fn pending_conflict(&self, id: i64) -> Option<ConflictPayload> {
        self.pending_conflicts.lock().unwrap().get(&id).cloned()
    }

    /// For a stashed conflict `id`, return the parent
    /// [`GroupId`](keepass_core::model::GroupId) of every conflict
    /// entry as observed on each side at reconcile time.
    ///
    /// Conflict payloads in [`ConflictPayload::entry_conflicts`] hold
    /// the raw upstream [`keepass_merge::EntryConflict`], whose
    /// `local` / `remote` [`keepass_core::model::Entry`]s don't carry
    /// a parent group reference. The resolver UI needs to know where
    /// each side placed the entry so it can render the per-side
    /// "Group" line. The engine has both vaults stashed alongside the
    /// payload, so we resolve them here once and hand the table back.
    ///
    /// `None` if the id is unknown (no stash or already consumed).
    /// Inside the `Some` branch, the inner `HashMap` is keyed by every
    /// [`EntryId`](keepass_core::model::EntryId) that appears in
    /// either [`ConflictPayload::entry_conflicts`] or
    /// [`ConflictPayload::delete_edit_conflicts`]. The inner
    /// [`EntryParentGroups`] carries `Option<GroupId>` per side —
    /// `None` when that side doesn't carry the entry under any known
    /// parent (an in-flight group-tree change).
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned —
    /// see [`Self::last_self_write`] for the same caveat. Not
    /// expected in practice.
    #[must_use]
    pub fn pending_conflict_parent_groups(
        &self,
        id: i64,
    ) -> Option<std::collections::HashMap<keepass_core::model::EntryId, EntryParentGroups>> {
        use keepass_core::model::EntryId;
        let ctx_guard = self.pending_conflict_contexts.lock().unwrap();
        let ctx = ctx_guard.get(&id)?;
        let mut entry_ids: Vec<EntryId> = ctx
            .payload
            .entry_conflicts
            .iter()
            .map(|c| c.entry_id)
            .collect();
        entry_ids.extend(ctx.payload.delete_edit_conflicts.iter().copied());
        entry_ids.sort_by_key(|e| e.0);
        entry_ids.dedup();
        let mut out = std::collections::HashMap::with_capacity(entry_ids.len());
        for entry_id in entry_ids {
            out.insert(
                entry_id,
                EntryParentGroups {
                    local: find_entry_parent_group(&ctx.local_vault.root, entry_id),
                    remote: find_entry_parent_group(&ctx.remote_vault.root, entry_id),
                },
            );
        }
        Some(out)
    }

    /// Test-only: count of currently stashed conflict payloads.
    #[doc(hidden)]
    #[must_use]
    pub fn pending_conflict_count_for_test(&self) -> usize {
        self.pending_conflicts.lock().unwrap().len()
    }

    /// Crate-internal: return the engine's [`FieldProtector`] as an
    /// [`Arc`]. Used by [`crate::reconcile`] to feed the protector
    /// into a fresh [`Kdbx::unlock_with_protector`] call.
    pub(crate) fn field_protector_arc(&self) -> Arc<dyn FieldProtector> {
        Arc::clone(&self.field_protector)
    }

    /// Crate-internal: drop the peek-only [`ConflictPayload`] mirror
    /// for `id`. Called by `apply_conflict_resolution` so the public
    /// [`Self::pending_conflict`] surface stops returning the payload
    /// once the matching context has been consumed.
    pub(crate) fn discard_pending_conflict_payload(&self, id: i64) {
        self.pending_conflicts.lock().unwrap().remove(&id);
    }

    /// Crate-internal: stash a [`ConflictPayload`] so the eventual
    /// `apply_conflict_resolution` (task 4.7) can find it.
    pub(crate) fn stash_conflict_payload(&self, payload: ConflictPayload) {
        self.pending_conflicts
            .lock()
            .unwrap()
            .insert(payload.id, payload);
    }

    /// Crate-internal: stash the additional context
    /// [`Engine::apply_conflict_resolution`] needs alongside the
    /// public [`ConflictPayload`].
    pub(crate) fn stash_conflict_context(
        &self,
        ctx: crate::conflict_resolution::PendingConflictContext,
    ) {
        self.pending_conflict_contexts
            .lock()
            .unwrap()
            .insert(ctx.payload.id, ctx);
    }

    /// Crate-internal: consume the stashed
    /// [`PendingConflictContext`](crate::conflict_resolution::PendingConflictContext)
    /// for `id`, returning `None` if no such id is stashed.
    pub(crate) fn take_pending_conflict_context(
        &self,
        id: i64,
    ) -> Option<crate::conflict_resolution::PendingConflictContext> {
        self.pending_conflict_contexts.lock().unwrap().remove(&id)
    }

    /// Crate-internal: borrow the stashed-context map under its mutex
    /// without consuming any entry. Used by
    /// [`crate::conflict_resolution::reveal_conflict_local_field`] /
    /// `_remote_field` to read the per-side vault for a peek-reveal —
    /// the stash stays in place so subsequent reveal calls (and the
    /// eventual `apply_conflict_resolution`) still see it.
    pub(crate) fn pending_conflict_contexts_lock(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<i64, crate::conflict_resolution::PendingConflictContext>>
    {
        self.pending_conflict_contexts.lock().unwrap()
    }

    /// Apply a user-resolved [`keepass_merge::Resolution`] to a
    /// previously-stashed conflict.
    ///
    /// `id` is the synthetic id from the
    /// [`crate::events::ChangeEvent::ConflictDetected`] event (and
    /// the matching [`ConflictPayload::id`] field) that surfaced the
    /// conflict via [`Engine::reconcile_with_disk`]. `resolution`
    /// carries the user's per-field, per-attachment, per-icon and
    /// delete-vs-edit decisions. See the [`keepass_merge::Resolution`]
    /// docs for the validation contract.
    ///
    /// On success the resolved vault has been applied to `SQLite`
    /// inside a single transaction, the common ancestor has been
    /// refreshed to the disk bytes the original reconcile observed,
    /// and a [`crate::events::ChangeEvent::ExternalChangeMerged`]
    /// event has fired (with an empty conflict residue, since
    /// resolution clears the stash).
    ///
    /// The stash is consumed by this call: a second call with the
    /// same `id` returns [`EngineError::NotFound`]. A retry needs a
    /// fresh `reconcile_with_disk` because the caller's mental model
    /// of the conflict shape may be stale by then.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] if no conflict is stashed under
    ///   `id` (typo, already-consumed, or evicted by engine drop).
    /// - [`EngineError::ResolutionMismatch`] if the resolution
    ///   doesn't cover the stashed conflict's buckets — `keepass-
    ///   merge`'s read-only validation pass fired before any mutation.
    /// - [`EngineError::Ingest`] / [`EngineError::Sqlite`] for
    ///   apply-step failures; `SQLite` rolls back and the engine
    ///   state is unchanged. The stash is still consumed in this
    ///   case — see the type-level docs.
    pub fn apply_conflict_resolution(
        &mut self,
        id: i64,
        resolution: &keepass_merge::Resolution,
    ) -> Result<(), EngineError> {
        crate::conflict_resolution::apply_conflict_resolution(self, id, resolution)
    }

    /// Discard a stashed conflict — both the peek-side
    /// [`ConflictPayload`] mirror and the internal resolution context
    /// — for `id` without resolving it.
    ///
    /// Both the live ([`Self::reconcile_with_disk`]) and held
    /// ([`Self::held_conflict_payload`]) paths stash a payload plus a
    /// context (two in-memory [`Vault`](keepass_core::model::Vault)s —
    /// sizeable on a big vault) keyed by `id`.
    /// [`Self::apply_conflict_resolution`] consumes both; but if the
    /// user opens the resolver and dismisses it without resolving
    /// ("Resolve Later"), nothing consumes the stash and it lingers
    /// until the engine is dropped (vault lock). Repeated open/dismiss
    /// orphans one stash per round. This drops both halves for `id` so
    /// a dismissed resolver doesn't leak them.
    ///
    /// Idempotent and infallible: an unknown / already-consumed `id`
    /// is a no-op. The derived held-conflict badge set
    /// ([`Self::entries_with_parked_conflict`]) is **untouched** — the
    /// conflict is still real, just not currently open in a resolver;
    /// a fresh [`Self::held_conflict_payload`] rebuilds the stash on
    /// demand.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned —
    /// see [`Self::last_self_write`] for the same caveat.
    pub fn discard_conflict(&self, id: i64) {
        // Same order `apply_conflict_resolution` consumes them: drop
        // the context, then the peek-side payload mirror. Both are
        // plain map removals; a missing id is a no-op on each.
        self.take_pending_conflict_context(id);
        self.discard_pending_conflict_payload(id);
    }

    /// Reveal a single field on the **local** side of a stashed
    /// conflict as plaintext.
    ///
    /// Companion to [`Self::pending_conflict`] for the resolver UI's
    /// hover-reveal: the public [`ConflictPayload`] carries field-level
    /// diffs but redacts protected values; this method lets a frontend
    /// fetch the cleartext for one field on one side on demand.
    ///
    /// Both sides of the stashed conflict are full
    /// [`keepass_core::model::Vault`]s with protected fields already
    /// unwrapped (the local vault is produced by
    /// [`Self::project_to_vault`], which decrypts the
    /// `entry_protected` rows under the field-protector session key;
    /// the remote vault is produced by
    /// [`keepass_core::kdbx::Kdbx::vault_with_unwrapped_protected`],
    /// which does the same on the disk side). No session-key
    /// acquisition happens here — the cleartext sits on the stashed
    /// [`keepass_core::model::Entry`] ready to read. Plaintext crosses
    /// the boundary in a [`SecretString`] so it zeroes on drop.
    ///
    /// `field_name == "Password"` reads the canonical password slot;
    /// any other name reads from the entry's `custom_fields`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "conflict_payload"`) if
    ///   no conflict is stashed under `conflict_id` (typo, already
    ///   consumed by [`Self::apply_conflict_resolution`], or evicted
    ///   by engine drop).
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   with `entry_uuid` exists in the local-side vault.
    /// - [`EngineError::NotFound`] (`entity = "custom_field"`) if the
    ///   entry exists but doesn't carry a custom field named
    ///   `field_name` (and `field_name != "Password"`).
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned —
    /// see [`Self::last_self_write`] for the same caveat.
    pub fn reveal_conflict_local_field(
        &self,
        conflict_id: i64,
        entry_uuid: Uuid,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::conflict_resolution::reveal_conflict_local_field(
            self,
            conflict_id,
            entry_uuid,
            field_name,
        )
    }

    /// Reveal a single field on the **remote** side of a stashed
    /// conflict as plaintext.
    ///
    /// Sibling of [`Self::reveal_conflict_local_field`]; reads from
    /// the stash's remote-side vault. See that method's docs for the
    /// full contract.
    ///
    /// # Errors
    ///
    /// Same shape as [`Self::reveal_conflict_local_field`] but `entry`
    /// / `custom_field` `NotFound`s refer to the remote-side vault.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned.
    pub fn reveal_conflict_remote_field(
        &self,
        conflict_id: i64,
        entry_uuid: Uuid,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::conflict_resolution::reveal_conflict_remote_field(
            self,
            conflict_id,
            entry_uuid,
            field_name,
        )
    }

    /// Crate-internal: re-ingest a merged [`Kdbx`] into `SQLite`.
    /// The single-transaction discipline lives in
    /// [`crate::ingest::ingest`]; the reconcile path uses this so
    /// failure rolls back cleanly without firing events.
    pub(crate) fn ingest_merged(&mut self, kdbx: &Kdbx<Unlocked>) -> Result<(), EngineError> {
        let _outcome = crate::ingest::ingest(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            kdbx,
        )?;
        Ok(())
    }

    /// Crate-internal: re-ingest an in-memory [`Vault`] without
    /// round-tripping through a fresh KDBX envelope. Used by paths
    /// (e.g. parked-conflict marker cleanup) that mutate the
    /// projected vault and want to land the changes in `SQLite`
    /// without holding the composite key.
    pub(crate) fn ingest_vault(
        &mut self,
        vault: &keepass_core::model::Vault,
    ) -> Result<(), EngineError> {
        let _outcome = crate::ingest::ingest_vault(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            vault,
        )?;
        Ok(())
    }

    /// Ingest one peer's vault as owner-tagged conflict rows — the
    /// multi-peer owner-rows store (Phase 2,
    /// `_project-management/sync-multipeer-store.md` §9).
    ///
    /// For each entry the peer holds that we also hold, runs the
    /// keepass-merge `classify` brain (item granularity) and either advances
    /// our local entry (one-sided / non-overlapping peer edit), stores the
    /// peer's value as an `owner`-keyed conflict row (genuine conflict, held
    /// open — local is left untouched), or does nothing (agreement). Purely
    /// additive: writes only the `conflict_*` tables plus any single advanced
    /// local entry, and never clears the vault tables.
    ///
    /// `owner` is an opaque peer/device identifier the sync layer supplies;
    /// the same string must be reused across that peer's pulls so its rows
    /// refresh in place. The returned [`crate::ingest::IngestPeerOutcome`]'s
    /// `auto_merged` bucket tells the caller whether the local side changed
    /// (and so must be saved). Not yet wired to the live reconcile path —
    /// Phase 4 repoints the sync reconcile here.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if projecting the local vault fails, or if any
    /// `SQLite` write / field-seal during the per-entry classification fails
    /// (the whole pass runs in one transaction, so a failure rolls back).
    pub fn ingest_peer(
        &mut self,
        owner: &str,
        peer: &keepass_core::model::Vault,
    ) -> Result<crate::ingest::IngestPeerOutcome, EngineError> {
        let local = self.project_to_vault()?;
        crate::ingest::ingest_peer(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            owner,
            &local,
            peer,
        )
    }

    /// Owner-rows badge query (Phase 3): every entry UUID that carries at
    /// least one stored peer conflict row.
    ///
    /// The owner-rows replacement for the legacy `held_conflicts` JSON-array
    /// kv. Not yet wired to the FFI badge — Phase 4 repoints
    /// `entries_with_parked_conflict` here as part of the atomic switch.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the underlying `SQLite` query fails.
    pub fn parked_conflict_uuids_from_rows(&self) -> Result<Vec<Uuid>, EngineError> {
        crate::conflict_rows::parked_conflict_uuids(&self.conn)
    }

    /// One-shot: did `(observed_mtime, observed_size)` come from our own
    /// most recent [`Engine::save_to_kdbx`]?
    ///
    /// Returns `true` and clears the stored signature if it matches
    /// exactly. Returns `false` (and leaves state unchanged) if there's
    /// no signature stored, or if either component diverges.
    ///
    /// Intended for the Phase 4 file-watcher integration: when the
    /// watcher fires on a change to the KDBX path, it stats the file
    /// and asks "was that me?". If yes, the spurious external-change
    /// notification is suppressed. If no, the watcher proceeds with
    /// the merge / reload flow.
    ///
    /// Equality on [`SystemTime`] is exact (no fuzzy comparison). The
    /// signature is captured immediately post-rename via
    /// [`std::fs::Metadata::modified`]; a watcher that stats with the
    /// same call should observe bit-identical timestamps. Any precision
    /// mismatch (e.g. watcher truncates to seconds while engine keeps
    /// nanoseconds) is a bug we want to surface, not paper over with a
    /// tolerance window.
    ///
    /// Unlike the Swift counterpart (`consumePendingSelfWriteSignature`
    /// on `DatabaseDocument`), this method takes the pre-observed
    /// `(mtime, size)` directly rather than re-statting the file — the
    /// caller already has the stat result from its watcher event, so we
    /// avoid a redundant syscall and the API stays IO-free. Also note
    /// no 5-second TTL: the Swift version clears the signature on a
    /// timer to bound the race window; the Rust side leaves TTL
    /// (if needed) to the caller, since the engine has no async
    /// runtime to schedule the clear on.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal shared-state `Mutex` is poisoned
    /// — see [`Engine::last_self_write`] for the same caveat.
    pub fn consume_self_write_signature(
        &mut self,
        observed_mtime: SystemTime,
        observed_size: u64,
    ) -> bool {
        let expected = SelfWriteSignature {
            mtime: observed_mtime,
            size: observed_size,
        };
        let mut guard = self.shared.lock().unwrap();
        if guard.last_self_write == Some(expected) {
            guard.last_self_write = None;
            true
        } else {
            false
        }
    }
}
