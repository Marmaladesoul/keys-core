//! Slice 7.5 — external-merge FFI surface.
//!
//! [`MergeOutcome`] is the opaque carrier produced by
//! [`crate::Vault::merge_external`] and consumed (single-use) by the
//! upcoming `Vault::apply_merge_outcome` in slice 7.5b. Frontends never
//! inspect the raw upstream `keepass_merge::MergeOutcome` — they read
//! the display-side accessors below to drive the conflict resolver UI,
//! then hand the same handle back for application.
//!
//! ## Design
//!
//! The carrier holds three `Mutex<Option<…>>` slots:
//!
//! - `inner` — the upstream merge outcome itself (rich, non-cloneable
//!   field types). Read by every accessor in 7.5a; consumed by
//!   `apply_merge_outcome` in 7.5b.
//! - `local` — a clone of the local model vault taken at merge time.
//!   Walked to source the local-side parent group of each conflict.
//!   7.5b will use this to drive the apply step against a stable
//!   pre-merge snapshot of the local side.
//! - `remote` — the freshly-opened other vault, stashed at merge time
//!   so 7.5b's apply step doesn't have to re-open the file. Walked
//!   read-only by 7.5a's accessors to surface the remote-side parent
//!   group for conflict Records.
//!
//! All three `Option`s are always `Some` in 7.5a (the carrier is
//! never consumed). The `Option<…>` shape is in place so 7.5b can
//! land `take()` semantics without a Record rewrite or binding break.
//!
//! ## Group-uuid resolution for conflict Records
//!
//! Upstream `EntryConflict.local: Entry` doesn't carry a parent
//! [`GroupId`]. Each `EntryConflictFfi` walks the local and remote
//! vault snapshots to find the parent on each side. If the two sides
//! disagree (a group-tree structural change), the local-side parent
//! wins on both Records — matches v0.1's "group-tree LWW
//! reconciliation" posture documented in `MERGE_BACKLOG.md`.
//!
//! For [`DeleteEditConflictFfi`], the entry is alive in the local
//! tree at merge time (delete-edit means local has it, remote
//! tombstoned it) so the local-side parent is unambiguous.

// Every accessor holds `inner.lock().expect(..)`. Documenting the same
// structurally-impossible mutex-poisoning panic on every method would be
// more noise than signal — same posture as `vault.rs`.
#![allow(clippy::missing_panics_doc)]

use std::sync::Mutex;

use keepass_core::model::{EntryId, Group as KcGroup, GroupId, Vault as KcVault};
use keepass_merge::{FieldDeltaKind as KmFieldDeltaKind, MergeOutcome as KmOutcome};

use crate::dto::Entry;
use crate::error::VaultError;

/// Opaque carrier for one merge run.
///
/// Created by [`crate::Vault::merge_external`]; consumed (single-use)
/// by `Vault::apply_merge_outcome` in slice 7.5b. The single-use
/// contract is enforced by the `Mutex<Option<…>>` slots — every
/// accessor returns [`VaultError::NotFound`] once the carrier has
/// been consumed (post-7.5b).
#[derive(uniffi::Object)]
#[non_exhaustive]
pub struct MergeOutcome {
    pub(crate) inner: Mutex<Option<KmOutcome>>,
    pub(crate) local: Mutex<Option<KcVault>>,
    pub(crate) remote: Mutex<Option<KcVault>>,
}

impl std::fmt::Debug for MergeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let consumed = self
            .inner
            .lock()
            .expect("MergeOutcome mutex poisoned")
            .is_none();
        f.debug_struct("MergeOutcome")
            .field("consumed", &consumed)
            .finish_non_exhaustive()
    }
}

#[uniffi::export]
impl MergeOutcome {
    /// Bucket counts for every classification a v0.1 merge can
    /// produce. Drives the resolver's "23 conflicts" header without
    /// forcing a full Record clone of every entry.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`] if the carrier has already been
    /// consumed by `apply_merge_outcome` (post-7.5b). Never returns
    /// an error in 7.5a — the carrier is read-only.
    pub fn summary(&self) -> Result<MergeSummary, VaultError> {
        let guard = self.inner.lock().expect("MergeOutcome mutex poisoned");
        let outcome = guard.as_ref().ok_or(VaultError::NotFound)?;
        Ok(MergeSummary {
            disk_only_count: u32_from(outcome.disk_only_changes.len()),
            local_only_count: u32_from(outcome.local_only_changes.len()),
            entry_conflict_count: u32_from(outcome.entry_conflicts.len()),
            added_on_disk_count: u32_from(outcome.added_on_disk.len()),
            deleted_on_disk_count: u32_from(outcome.deleted_on_disk.len()),
            local_deletions_pending_sync_count: u32_from(
                outcome.local_deletions_pending_sync.len(),
            ),
            delete_edit_conflict_count: u32_from(outcome.delete_edit_conflicts.len()),
        })
    }

    /// `true` iff there are no caller-driven conflicts of either kind
    /// — i.e. `entry_conflicts` and `delete_edit_conflicts` are both
    /// empty. The Swift caller skips the resolver UI and calls
    /// `apply_merge_outcome` with an empty resolution directly.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`] if the carrier has already been
    /// consumed.
    pub fn is_auto_applicable(&self) -> Result<bool, VaultError> {
        let guard = self.inner.lock().expect("MergeOutcome mutex poisoned");
        let outcome = guard.as_ref().ok_or(VaultError::NotFound)?;
        Ok(outcome.entry_conflicts.is_empty() && outcome.delete_edit_conflicts.is_empty())
    }

    /// Full conflict list for the resolver UI. Each conflict carries
    /// both pre-merge sides plus the pre-computed `field_deltas` so
    /// the Swift side doesn't re-diff.
    ///
    /// The `local` Record's `group_uuid` is the local-side parent;
    /// the `remote` Record's `group_uuid` is the remote-side parent.
    /// If only one side has the entry under a known parent (a
    /// group-tree structural change in flight), the missing side
    /// falls back to the other side's parent — surfacing group-tree
    /// conflicts is reserved for v0.2 per `MERGE_BACKLOG.md`.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`] if the carrier has already been
    /// consumed.
    pub fn entry_conflicts(&self) -> Result<Vec<EntryConflictFfi>, VaultError> {
        let inner_guard = self.inner.lock().expect("MergeOutcome mutex poisoned");
        let outcome = inner_guard.as_ref().ok_or(VaultError::NotFound)?;
        let local_guard = self.local.lock().expect("MergeOutcome mutex poisoned");
        let local_vault = local_guard.as_ref().ok_or(VaultError::NotFound)?;
        let remote_guard = self.remote.lock().expect("MergeOutcome mutex poisoned");
        let remote_vault = remote_guard.as_ref().ok_or(VaultError::NotFound)?;

        let mut out = Vec::with_capacity(outcome.entry_conflicts.len());
        for conflict in &outcome.entry_conflicts {
            let local_parent = find_entry_parent(&local_vault.root, conflict.entry_id);
            let remote_parent = find_entry_parent(&remote_vault.root, conflict.entry_id);
            // Local side wins on disagreement; either side fills in if the
            // other can't find the entry (in-flight group-tree change).
            let local_pid = local_parent
                .or(remote_parent)
                .unwrap_or(GroupId(uuid::Uuid::nil()));
            let remote_pid = remote_parent
                .or(local_parent)
                .unwrap_or(GroupId(uuid::Uuid::nil()));

            out.push(EntryConflictFfi {
                entry_uuid: conflict.entry_id.0.to_string(),
                local: Entry::from_entry(&conflict.local, local_pid),
                remote: Entry::from_entry(&conflict.remote, remote_pid),
                field_deltas: conflict
                    .field_deltas
                    .iter()
                    .map(|d| FieldDeltaFfi {
                        key: d.key.clone(),
                        kind: FieldDeltaKindFfi::from(d.kind),
                    })
                    .collect(),
            });
        }
        Ok(out)
    }

    /// Delete-vs-edit conflicts. Each carries the local-side entry's
    /// state at merge time so the Swift UI can render "External
    /// deleted X, you edited X" with the entry's title for context
    /// without a follow-up `get_entry` call.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`] if the carrier has already been
    /// consumed.
    pub fn delete_edit_conflicts(&self) -> Result<Vec<DeleteEditConflictFfi>, VaultError> {
        let inner_guard = self.inner.lock().expect("MergeOutcome mutex poisoned");
        let outcome = inner_guard.as_ref().ok_or(VaultError::NotFound)?;
        let local_guard = self.local.lock().expect("MergeOutcome mutex poisoned");
        let local_vault = local_guard.as_ref().ok_or(VaultError::NotFound)?;

        let mut out = Vec::with_capacity(outcome.delete_edit_conflicts.len());
        for entry_id in &outcome.delete_edit_conflicts {
            // The local entry is alive in the local vault snapshot at
            // merge time — that's the definition of delete-edit.
            let parent = find_entry_parent(&local_vault.root, *entry_id)
                .unwrap_or(GroupId(uuid::Uuid::nil()));
            let local =
                find_entry_in(&local_vault.root, *entry_id).map(|e| Entry::from_entry(e, parent));
            // If we can't find it locally, the merge crate produced a
            // delete-edit conflict for an entry that's not in our local
            // tree — that's a contract violation we surface as None so
            // the binding side can still see the count without crashing.
            // In practice this branch is unreachable.
            out.push(DeleteEditConflictFfi {
                entry_uuid: entry_id.0.to_string(),
                local,
            });
        }
        Ok(out)
    }
}

/// Bucket counts for a [`MergeOutcome`]. See
/// [`MergeOutcome::summary`].
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct MergeSummary {
    pub disk_only_count: u32,
    pub local_only_count: u32,
    pub entry_conflict_count: u32,
    pub added_on_disk_count: u32,
    pub deleted_on_disk_count: u32,
    pub local_deletions_pending_sync_count: u32,
    pub delete_edit_conflict_count: u32,
}

/// One entry-level conflict surfaced by the merge.
///
/// `local` and `remote` carry the full pre-merge entry state for the
/// resolver UI. `field_deltas` is the pre-computed list of differing
/// keys so the binding side doesn't re-diff.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryConflictFfi {
    pub entry_uuid: String,
    pub local: Entry,
    pub remote: Entry,
    pub field_deltas: Vec<FieldDeltaFfi>,
}

/// Per-field difference between the two sides of an
/// [`EntryConflictFfi`].
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct FieldDeltaFfi {
    pub key: String,
    pub kind: FieldDeltaKindFfi,
}

/// Classification of a [`FieldDeltaFfi`].
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldDeltaKindFfi {
    /// The field exists only on the local side.
    LocalOnly,
    /// The field exists only on the remote side.
    RemoteOnly,
    /// Both sides have the field but the values differ.
    BothDiffer,
}

impl From<KmFieldDeltaKind> for FieldDeltaKindFfi {
    fn from(k: KmFieldDeltaKind) -> Self {
        match k {
            KmFieldDeltaKind::LocalOnly => Self::LocalOnly,
            KmFieldDeltaKind::RemoteOnly => Self::RemoteOnly,
            KmFieldDeltaKind::BothDiffer => Self::BothDiffer,
            other => panic!(
                "unmapped keepass_merge::FieldDeltaKind variant in keys-ffi facade: {other:?}"
            ),
        }
    }
}

/// A delete-vs-edit conflict — the local side edited an entry the
/// remote side tombstoned.
///
/// `local` is the local-side entry state at merge time
/// (`Some` whenever the local vault still contains the entry, which
/// is the merge crate's contract for this bucket; `None` is reserved
/// for an upstream contract violation). The Swift UI renders the
/// entry title from this Record so the user can answer "keep mine vs
/// accept the deletion" with the entry visible.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct DeleteEditConflictFfi {
    pub entry_uuid: String,
    pub local: Option<Entry>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn u32_from(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn find_entry_parent(group: &KcGroup, target: EntryId) -> Option<GroupId> {
    if group.entries.iter().any(|e| e.id == target) {
        return Some(group.id);
    }
    group
        .groups
        .iter()
        .find_map(|child| find_entry_parent(child, target))
}

fn find_entry_in(group: &KcGroup, target: EntryId) -> Option<&keepass_core::model::Entry> {
    if let Some(e) = group.entries.iter().find(|e| e.id == target) {
        return Some(e);
    }
    group
        .groups
        .iter()
        .find_map(|child| find_entry_in(child, target))
}
