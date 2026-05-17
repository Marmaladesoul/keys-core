//! Change-event bus types.
//!
//! Phase 4.2 introduces a single observer trait that the engine calls
//! synchronously after every successful mutation transaction. Variants
//! are always-plural — a single-row mutation carries a 1-element vec,
//! and a bulk mutation carries many — so consumers only have to handle
//! one shape per kind of change.
//!
//! The observer is invoked on the mutation thread. Implementations must
//! be cheap; a frontend that wants async fan-out should adapt inside
//! its observer impl (e.g. by pushing to a channel).

use uuid::Uuid;

/// Change event emitted by [`crate::Engine`] after a successful
/// mutation transaction.
///
/// Variants are always plural: a single-row mutation carries a 1-element
/// vec; bulk mutations (e.g. [`crate::Engine::ingest_from_kdbx`]) carry
/// many. That keeps observer impls from having to branch on cardinality.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ChangeEvent {
    /// One or more entries were inserted.
    EntriesAdded(Vec<Uuid>),
    /// One or more entries were updated in-place (title, url, password,
    /// custom fields, attachments — anything that bumps `modified_at`).
    EntriesUpdated(Vec<Uuid>),
    /// An entry's `last_used_at` was bumped via a read-touch flow
    /// (`AutoFill` fulfilment, in-app password reveal). Distinct from
    /// [`Self::EntriesUpdated`] because nothing else on the entry
    /// changed — in particular `modified_at` is NOT bumped, so listeners
    /// should treat this as a benign last-access notification and avoid
    /// re-rendering full entry detail. Fired by
    /// [`crate::Engine::touch_entry`].
    EntryTouched {
        /// The entry whose `last_used_at` was bumped.
        uuid: Uuid,
    },
    /// One or more entries were hard-deleted. Carries the pre-delete
    /// group uuid for each so observers can invalidate group-scoped
    /// caches.
    EntriesDeleted(Vec<EntryDeletionInfo>),
    /// One or more entries changed group. Carries both endpoints.
    EntriesMoved(Vec<EntryMove>),
    /// One or more entries were soft-recycled.
    EntriesRecycled(Vec<Uuid>),
    /// One or more recycled entries were restored.
    EntriesRestored(Vec<Uuid>),
    /// One or more groups were inserted.
    GroupsAdded(Vec<Uuid>),
    /// One or more groups were updated in-place.
    GroupsUpdated(Vec<Uuid>),
    /// One or more groups were hard-deleted. Carries the pre-delete
    /// parent uuid for each (the root group has `previous_parent =
    /// None`).
    GroupsDeleted(Vec<GroupDeletionInfo>),
    /// One or more groups changed parent.
    GroupsMoved(Vec<GroupMove>),
    /// Sibling groups under a common parent were reordered in place.
    /// Carries every uuid whose `sort_order` was rewritten, in the new
    /// order. The frontend can either re-fetch [`crate::Engine::group_tree`]
    /// or reuse this list directly to update its in-memory order.
    GroupsReordered(Vec<Uuid>),
    /// One or more groups were soft-recycled.
    GroupsRecycled(Vec<Uuid>),
    /// One or more recycled groups were restored.
    GroupsRestored(Vec<Uuid>),
    /// A single protected field on a single entry changed value.
    /// Field-level granularity is preserved here because reveal-cache
    /// invalidation is per-field.
    ProtectedFieldChanged {
        /// The entry whose protected field changed.
        entry_uuid: Uuid,
        /// The field name (`"Password"` for the canonical slot).
        field_name: String,
    },
    /// The attachment set changed on one or more entries.
    AttachmentsChanged(Vec<Uuid>),
    /// The tag set changed on one or more entries.
    TagsChanged(Vec<Uuid>),
    /// A new smart folder was created. Carries the assigned row id.
    SmartFolderCreated(i64),
    /// An existing smart folder was updated.
    SmartFolderUpdated(i64),
    /// A smart folder was deleted.
    SmartFolderDeleted(i64),
    /// A successful [`crate::Engine::save_to_kdbx`] write completed.
    SaveCompleted,
    /// External KDBX changes were merged into `SQLite`. Carries the
    /// aggregate counts of what was applied; the engine's `SQLite`
    /// mirror has already been updated when this fires.
    ExternalChangeMerged {
        /// Counts of merge mutations applied to `SQLite`.
        applied: crate::reconcile::MergeStats,
    },
    /// A merge conflict was detected and requires user resolution.
    /// `SQLite` state was **not** mutated; the engine has stashed the
    /// payload (keyed by [`ConflictPayload::id`]) for a later
    /// `apply_conflict_resolution` call (task 4.7).
    ConflictDetected(ConflictPayload),
    /// One or more meta scalars were updated. Carries the setting-row
    /// keys whose value just changed (e.g.
    /// `"meta.history_max_items"`), so observers can subscribe to a
    /// specific subset rather than re-reading every meta value on each
    /// emission.
    MetaUpdated {
        /// Setting keys whose value just changed.
        keys: Vec<String>,
    },
    /// The vault was locked. Not wired yet — reserved for a future
    /// explicit lock path.
    VaultLocked,
    /// The vault was unlocked — i.e. [`crate::Engine::open`] returned
    /// successfully.
    VaultUnlocked,
}

/// Carried by [`ChangeEvent::EntriesDeleted`].
#[derive(Debug, Clone)]
pub struct EntryDeletionInfo {
    /// The deleted entry's uuid.
    pub uuid: Uuid,
    /// The group the entry was in immediately before deletion.
    pub previous_group: Uuid,
}

/// Carried by [`ChangeEvent::EntriesMoved`].
#[derive(Debug, Clone)]
pub struct EntryMove {
    /// The entry that moved.
    pub uuid: Uuid,
    /// The group the entry was in before the move.
    pub from_group: Uuid,
    /// The group the entry is in after the move.
    pub to_group: Uuid,
}

/// Carried by [`ChangeEvent::GroupsDeleted`].
#[derive(Debug, Clone)]
pub struct GroupDeletionInfo {
    /// The deleted group's uuid.
    pub uuid: Uuid,
    /// The parent the group was attached to before deletion. `None`
    /// only for the root group (which the engine refuses to delete in
    /// practice, but the type still permits it).
    pub previous_parent: Option<Uuid>,
}

/// Carried by [`ChangeEvent::GroupsMoved`].
#[derive(Debug, Clone)]
pub struct GroupMove {
    /// The group that moved.
    pub uuid: Uuid,
    /// The parent the group had before the move.
    pub from_parent: Uuid,
    /// The parent the group has after the move.
    pub to_parent: Uuid,
}

/// Conflict surface for an external-change merge that requires user
/// resolution before any state lands in `SQLite`.
///
/// Produced by [`crate::Engine::reconcile_with_disk`] when the
/// underlying `keepass-merge` run reports per-entry conflicts (both
/// sides edited the same field differently against the per-entry
/// history ancestor) or `delete vs edit` conflicts. The shape mirrors
/// `keepass-merge`'s own conflict types so the frontend resolver UI
/// can render and round-trip them verbatim.
///
/// The engine stashes one payload per outstanding conflict run under
/// [`Self::id`]; the frontend later echoes the id back to
/// `apply_conflict_resolution` (task 4.7) to identify which run is
/// being resolved.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConflictPayload {
    /// Synthetic id assigned by the engine for this conflict run.
    /// The frontend echoes this back to `apply_conflict_resolution`
    /// (task 4.7).
    pub id: i64,
    /// Per-entry field / attachment / icon conflicts surfaced by the
    /// merge. Mirrors `keepass_merge::EntryConflict` verbatim — each
    /// entry carries the local + remote `Entry` snapshots plus a
    /// pre-computed list of field / attachment / icon deltas.
    pub entry_conflicts: Vec<keepass_merge::EntryConflict>,
    /// Per-entry `delete-vs-edit` conflicts. Each id corresponds to
    /// an entry one side tombstoned and the other side edited; the
    /// frontend picks `KeepLocal` or `AcceptRemoteDelete`.
    pub delete_edit_conflicts: Vec<keepass_core::model::EntryId>,
}

/// Parent [`keepass_core::model::GroupId`] of one entry as observed
/// on each side of a stashed conflict.
///
/// Produced by
/// [`crate::Engine::pending_conflict_parent_groups`]. `None` on a
/// side means the entry isn't reachable through any known group on
/// that side — typically an in-flight group-tree change where one
/// side has tombstoned the entry's parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryParentGroups {
    /// Parent on the local-side projection at reconcile time.
    pub local: Option<keepass_core::model::GroupId>,
    /// Parent on the remote-side (disk) projection at reconcile time.
    pub remote: Option<keepass_core::model::GroupId>,
}

/// Receives [`ChangeEvent`]s from an [`crate::Engine`].
///
/// Implementations must be `Send + Sync` because the engine holds the
/// observer behind an [`std::sync::Arc`] and may be moved between
/// threads. [`on_event`](DataChangeObserver::on_event) is called
/// synchronously on the thread that performed the mutation — keep it
/// cheap, and adapt to async dispatch (e.g. via a channel) inside the
/// impl if a frontend needs it.
pub trait DataChangeObserver: Send + Sync + std::fmt::Debug {
    /// Handle a single change event. Called on the mutation thread,
    /// after the transaction has committed.
    fn on_event(&self, event: ChangeEvent);
}
