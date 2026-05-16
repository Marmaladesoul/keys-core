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
    /// External KDBX changes were merged in. Reserved for Phase 4.6/4.7;
    /// the exact shape of [`ConflictPayload`] will firm up there.
    ExternalChangeMerged {
        /// Uuids of entries / groups successfully merged.
        applied: Vec<Uuid>,
        /// Conflicts that required surfacing.
        conflicts: Vec<ConflictPayload>,
    },
    /// A merge conflict was detected. Reserved for Phase 4.6/4.7.
    ConflictDetected(ConflictPayload),
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

/// Opaque placeholder for merge-conflict payloads. The full shape will
/// land alongside Phase 4.6/4.7 (external-change merge); for 4.2 / 4.3
/// the type exists so the variants that reference it compile, but no
/// emission path currently constructs one.
#[derive(Debug, Clone)]
pub struct ConflictPayload {
    /// Synthetic id assigned by the engine for a given merge outcome.
    /// The eventual shape may replace this with a richer key.
    pub merge_outcome_id: i64,
    /// Human-readable summary of the conflict. Replaced by a structured
    /// representation when the merge path lands.
    pub description: String,
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
