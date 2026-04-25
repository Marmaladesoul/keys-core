//! Coarse observer callbacks for vault mutations.
//!
//! Frontends register a single [`VaultObserver`] per [`crate::Vault`]
//! via [`crate::Vault::set_observer`]. The vault fires one
//! [`VaultChange`] per mutating method call, **after** the in-memory
//! state change is applied and **before** the FFI method returns.
//!
//! Events are coarse on purpose: they carry the affected UUID (or
//! nothing for global events) so frontends know what to re-fetch,
//! not the new value. Payload-bearing events are deferred —
//! re-fetching is the `SwiftUI` `@Observable`-driven model.
//!
//! ## Reentrancy
//!
//! Observer dispatch happens **outside** the held vault mutex. An
//! observer's `on_change` may call back into the vault (e.g.
//! `list_entries`, `get_entry`) without deadlocking. The observer
//! `Arc` is cloned under its own brief lock, then the lock is
//! dropped before `on_change` runs.

/// One observer per [`crate::Vault`]. Trait implementations live on
/// the binding side; uniffi's `with_foreign` exports the trait
/// across the FFI for foreign types to implement.
#[uniffi::export(with_foreign)]
pub trait VaultObserver: Send + Sync {
    /// Called once per mutating method, after the state change
    /// applies and before the method returns.
    fn on_change(&self, change: VaultChange);
}

/// Coarse event variants. Each carries enough information for the
/// frontend to know what to re-fetch.
///
/// `BulkMerge` is defined for slice 7.5 (`merge_external`) but does
/// not fire from any current method. The variant exists so binding
/// regeneration doesn't break when merge lands.
#[derive(uniffi::Enum, Debug, Clone)]
#[non_exhaustive]
pub enum VaultChange {
    /// An entry's content changed (create, update, move, protected-
    /// field set/clear, history restore, history-record delete,
    /// import).
    EntryModified { uuid: String },
    /// An entry was removed from the user-visible primary view.
    /// Hard delete and recycle-bin both fire this — recycle-bin
    /// views re-fetch via `list_entries(Some(bin_uuid))`.
    EntryDeleted { uuid: String },
    /// A group's identity, contents, or relationship to the tree
    /// changed (create, update, delete, move, recycle, empty-bin).
    GroupChanged { uuid: String },
    /// A bulk merge applied many changes. Fires from
    /// `merge_external` (slice 7.5) instead of per-record events.
    BulkMerge,
    /// A `save()` completed.
    Saved,
    /// `lock()` was called. The observer is cleared after this
    /// event, so no further events reach this handle.
    Locked,
}
