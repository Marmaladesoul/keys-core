//! [`VaultDataChangeObserver`] — foreign-implementable change-event sink.
//!
//! Mirrors [`keys_engine::DataChangeObserver`]. The engine fires events
//! synchronously on the mutation thread after a successful commit;
//! frontends should keep [`VaultDataChangeObserver::on_event`] cheap
//! (push to a channel / set a dirty flag) and adapt to async dispatch
//! inside the impl if needed.
//!
//! Big payloads (the full `ConflictPayload`) cross by opaque id —
//! [`ChangeEvent::ConflictDetected`] carries the id; the frontend
//! fetches richer detail via [`crate::Engine::pending_conflict`]
//! (peek-only) and later hands a resolution back to
//! [`crate::Engine::apply_conflict_resolution`]. Matches the maintainer's
//! 2026-05-16 "big payload = opaque id + accessor" decision.

use std::sync::Arc;

use keys_engine::{
    ChangeEvent as EngChangeEvent, DataChangeObserver as EngObserver, EntryDeletionInfo, EntryMove,
    GroupDeletionInfo, GroupMove,
};

use crate::engine_types::MergeStats;

/// Foreign-implemented change-event sink.
#[uniffi::export(with_foreign)]
pub trait VaultDataChangeObserver: Send + Sync {
    fn on_event(&self, event: ChangeEvent);
}

/// Wire-friendly mirror of [`keys_engine::ChangeEvent`]. Uuid lists
/// cross inline as `Vec<String>`; the rich `ConflictPayload` is
/// reduced to its id (frontends use the engine accessors for the
/// full payload).
#[derive(uniffi::Enum, Debug, Clone)]
pub enum ChangeEvent {
    EntriesAdded {
        uuids: Vec<String>,
    },
    EntriesUpdated {
        uuids: Vec<String>,
    },
    EntriesDeleted {
        entries: Vec<EntryDeletion>,
    },
    EntriesMoved {
        moves: Vec<EntryMoveInfo>,
    },
    EntriesRecycled {
        uuids: Vec<String>,
    },
    EntriesRestored {
        uuids: Vec<String>,
    },
    GroupsAdded {
        uuids: Vec<String>,
    },
    GroupsUpdated {
        uuids: Vec<String>,
    },
    GroupsDeleted {
        groups: Vec<GroupDeletion>,
    },
    GroupsMoved {
        moves: Vec<GroupMoveInfo>,
    },
    GroupsReordered {
        uuids: Vec<String>,
    },
    GroupsRecycled {
        uuids: Vec<String>,
    },
    GroupsRestored {
        uuids: Vec<String>,
    },
    ProtectedFieldChanged {
        entry_uuid: String,
        field_name: String,
    },
    AttachmentsChanged {
        uuids: Vec<String>,
    },
    TagsChanged {
        uuids: Vec<String>,
    },
    SmartFolderCreated {
        id: i64,
    },
    SmartFolderUpdated {
        id: i64,
    },
    SmartFolderDeleted {
        id: i64,
    },
    SaveCompleted,
    ExternalChangeMerged {
        applied: MergeStats,
    },
    ConflictDetected {
        id: i64,
    },
    VaultLocked,
    VaultUnlocked,
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct EntryDeletion {
    pub uuid: String,
    pub previous_group_uuid: String,
}

impl From<EntryDeletionInfo> for EntryDeletion {
    fn from(d: EntryDeletionInfo) -> Self {
        Self {
            uuid: d.uuid.to_string(),
            previous_group_uuid: d.previous_group.to_string(),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct GroupDeletion {
    pub uuid: String,
    pub previous_parent_uuid: Option<String>,
}

impl From<GroupDeletionInfo> for GroupDeletion {
    fn from(d: GroupDeletionInfo) -> Self {
        Self {
            uuid: d.uuid.to_string(),
            previous_parent_uuid: d.previous_parent.map(|u| u.to_string()),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct EntryMoveInfo {
    pub uuid: String,
    pub from_group_uuid: String,
    pub to_group_uuid: String,
}

impl From<EntryMove> for EntryMoveInfo {
    fn from(m: EntryMove) -> Self {
        Self {
            uuid: m.uuid.to_string(),
            from_group_uuid: m.from_group.to_string(),
            to_group_uuid: m.to_group.to_string(),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct GroupMoveInfo {
    pub uuid: String,
    pub from_parent_uuid: String,
    pub to_parent_uuid: String,
}

impl From<GroupMove> for GroupMoveInfo {
    fn from(m: GroupMove) -> Self {
        Self {
            uuid: m.uuid.to_string(),
            from_parent_uuid: m.from_parent.to_string(),
            to_parent_uuid: m.to_parent.to_string(),
        }
    }
}

impl From<EngChangeEvent> for ChangeEvent {
    fn from(e: EngChangeEvent) -> Self {
        let uuid_vec = |v: Vec<uuid::Uuid>| v.into_iter().map(|u| u.to_string()).collect();
        match e {
            EngChangeEvent::EntriesAdded(u) => Self::EntriesAdded { uuids: uuid_vec(u) },
            EngChangeEvent::EntriesUpdated(u) => Self::EntriesUpdated { uuids: uuid_vec(u) },
            EngChangeEvent::EntriesDeleted(d) => Self::EntriesDeleted {
                entries: d.into_iter().map(Into::into).collect(),
            },
            EngChangeEvent::EntriesMoved(m) => Self::EntriesMoved {
                moves: m.into_iter().map(Into::into).collect(),
            },
            EngChangeEvent::EntriesRecycled(u) => Self::EntriesRecycled { uuids: uuid_vec(u) },
            EngChangeEvent::EntriesRestored(u) => Self::EntriesRestored { uuids: uuid_vec(u) },
            EngChangeEvent::GroupsAdded(u) => Self::GroupsAdded { uuids: uuid_vec(u) },
            EngChangeEvent::GroupsUpdated(u) => Self::GroupsUpdated { uuids: uuid_vec(u) },
            EngChangeEvent::GroupsDeleted(g) => Self::GroupsDeleted {
                groups: g.into_iter().map(Into::into).collect(),
            },
            EngChangeEvent::GroupsMoved(m) => Self::GroupsMoved {
                moves: m.into_iter().map(Into::into).collect(),
            },
            EngChangeEvent::GroupsReordered(u) => Self::GroupsReordered { uuids: uuid_vec(u) },
            EngChangeEvent::GroupsRecycled(u) => Self::GroupsRecycled { uuids: uuid_vec(u) },
            EngChangeEvent::GroupsRestored(u) => Self::GroupsRestored { uuids: uuid_vec(u) },
            EngChangeEvent::ProtectedFieldChanged {
                entry_uuid,
                field_name,
            } => Self::ProtectedFieldChanged {
                entry_uuid: entry_uuid.to_string(),
                field_name,
            },
            EngChangeEvent::AttachmentsChanged(u) => {
                Self::AttachmentsChanged { uuids: uuid_vec(u) }
            }
            EngChangeEvent::TagsChanged(u) => Self::TagsChanged { uuids: uuid_vec(u) },
            EngChangeEvent::SmartFolderCreated(id) => Self::SmartFolderCreated { id },
            EngChangeEvent::SmartFolderUpdated(id) => Self::SmartFolderUpdated { id },
            EngChangeEvent::SmartFolderDeleted(id) => Self::SmartFolderDeleted { id },
            EngChangeEvent::SaveCompleted => Self::SaveCompleted,
            EngChangeEvent::ExternalChangeMerged { applied } => Self::ExternalChangeMerged {
                applied: applied.into(),
            },
            EngChangeEvent::ConflictDetected(p) => Self::ConflictDetected { id: p.id },
            EngChangeEvent::VaultLocked => Self::VaultLocked,
            EngChangeEvent::VaultUnlocked => Self::VaultUnlocked,
            // `#[non_exhaustive]` upstream catch-all. Future variants
            // collapse to `SaveCompleted` (a conservative "something
            // happened, re-fetch" signal) rather than panicking.
            other => {
                let _ = other;
                Self::SaveCompleted
            }
        }
    }
}

/// Engine-side `DataChangeObserver` impl that forwards every event to
/// the foreign [`VaultDataChangeObserver`].
pub(crate) struct BridgeObserver {
    pub(crate) inner: Arc<dyn VaultDataChangeObserver>,
}

impl std::fmt::Debug for BridgeObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BridgeObserver(<foreign>)")
    }
}

impl EngObserver for BridgeObserver {
    fn on_event(&self, event: EngChangeEvent) {
        self.inner.on_event(event.into());
    }
}
