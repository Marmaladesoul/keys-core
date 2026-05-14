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

use std::collections::HashMap;
use std::sync::Mutex;

use keepass_core::model::{EntryId, Group as KcGroup, GroupId, Vault as KcVault};
use keepass_merge::{
    AttachmentChoice as KmAttachmentChoice, AttachmentDeltaKind as KmAttachmentDeltaKind,
    ConflictSide as KmConflictSide, DeleteEditChoice as KmDeleteEditChoice,
    FieldDeltaKind as KmFieldDeltaKind, MergeOutcome as KmOutcome, Resolution as KmResolution,
};
use uuid::Uuid;

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
                attachment_deltas: conflict
                    .attachment_deltas
                    .iter()
                    .map(|d| AttachmentDeltaFfi {
                        name: d.name.clone(),
                        kind: AttachmentDeltaKindFfi::from(d.kind),
                        local_sha256_hex: d.local_sha256.map(hex_encode),
                        remote_sha256_hex: d.remote_sha256.map(hex_encode),
                        local_size_bytes: d.local_size,
                        remote_size_bytes: d.remote_size,
                    })
                    .collect(),
                icon_delta: conflict.icon_delta.as_ref().map(|d| IconDeltaFfi {
                    local_custom_icon_uuid: d.local_custom_icon_uuid.map(|u| u.to_string()),
                    remote_custom_icon_uuid: d.remote_custom_icon_uuid.map(|u| u.to_string()),
                }),
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
    /// Attachment-level conflicts that need caller resolution. Each
    /// delta carries enough metadata (size + SHA-256 prefix per side)
    /// for the resolver UI to render rows without dereferencing the
    /// binary pool. Auto-resolvable attachment merges (byte-identical,
    /// or 3-way classifier has a clear winner) ride through the
    /// auto-merge path and don't appear here.
    pub attachment_deltas: Vec<AttachmentDeltaFfi>,
    /// Icon-level conflict when the two sides have a visible
    /// `custom_icon_uuid` divergence the merge classifier couldn't
    /// auto-resolve against the LCA. `None` when icons match or the
    /// classifier picked a winner (in which case the entry routes
    /// through the auto-merge buckets instead). Mirrors
    /// `keepass_merge::EntryConflict::icon_delta`.
    pub icon_delta: Option<IconDeltaFfi>,
}

/// Per-entry icon difference between the two sides of an
/// [`EntryConflictFfi`]. Mirrors `keepass_merge::IconDelta`.
///
/// `local_custom_icon_uuid` / `remote_custom_icon_uuid` are the
/// custom-icon UUIDs at conflict time, or `None` when that side has
/// no custom icon set. The Swift resolver UI renders each side's
/// icon preview from these UUIDs (looking up in `Meta::custom_icons`)
/// and offers a keep-local / keep-remote toggle.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct IconDeltaFfi {
    pub local_custom_icon_uuid: Option<String>,
    pub remote_custom_icon_uuid: Option<String>,
}

/// Per-attachment difference between the two sides of an
/// [`EntryConflictFfi`]. Mirrors [`keepass_merge::AttachmentDelta`].
///
/// `local_sha256_hex` / `remote_sha256_hex` are hex-encoded so the
/// FFI surface is `Option<String>` (uniffi handles fixed-size byte
/// arrays awkwardly across the boundary). Bindings can render the
/// first 8 chars for a "did the bytes change?" affordance.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct AttachmentDeltaFfi {
    pub name: String,
    pub kind: AttachmentDeltaKindFfi,
    pub local_sha256_hex: Option<String>,
    pub remote_sha256_hex: Option<String>,
    pub local_size_bytes: Option<u64>,
    pub remote_size_bytes: Option<u64>,
}

/// Classification of an [`AttachmentDeltaFfi`] by which side(s) hold
/// the attachment.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachmentDeltaKindFfi {
    /// Only on local; ancestor differed (or absent), so not auto-
    /// resolvable.
    LocalOnly,
    /// Only on remote; ancestor differed (or absent).
    RemoteOnly,
    /// Both sides hold it but the bytes differ; ancestor doesn't
    /// match either side cleanly.
    BothDiffer,
}

impl From<KmAttachmentDeltaKind> for AttachmentDeltaKindFfi {
    fn from(k: KmAttachmentDeltaKind) -> Self {
        match k {
            KmAttachmentDeltaKind::LocalOnly => Self::LocalOnly,
            KmAttachmentDeltaKind::RemoteOnly => Self::RemoteOnly,
            KmAttachmentDeltaKind::BothDiffer => Self::BothDiffer,
            other => panic!(
                "unmapped keepass_merge::AttachmentDeltaKind variant in keys-ffi facade: {other:?}"
            ),
        }
    }
}

fn hex_encode(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("writing to a String never fails");
    }
    s
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
// Resolution carriers (slice 7.5b)
// ---------------------------------------------------------------------------

/// Caller's resolution choices for the conflict buckets of a
/// [`MergeOutcome`].
///
/// Built by the Swift conflict-resolver UI from user input, then handed
/// to [`crate::Vault::apply_merge_outcome`]. Empty maps are valid when
/// the corresponding outcome buckets are also empty — that's the
/// auto-applicable path.
///
/// Flat `Vec<...>` rather than nested `HashMap<EntryId, ...>` because
/// uniffi 0.28 handles `HashMap<String, T>` cleanly but nested
/// non-string-keyed maps are dicey across the FFI; the marshal layer
/// rebuilds the upstream `HashMap` shape internally.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct ResolutionFfi {
    /// One entry per [`EntryConflictFfi`] with a non-empty
    /// `field_deltas`. Inner `field_choices` has one entry per field
    /// key in that conflict's `field_deltas`.
    pub entry_field_choices: Vec<EntryFieldChoiceFfi>,
    /// One entry per [`EntryConflictFfi`] with a non-empty
    /// `attachment_deltas`. Inner `attachment_choices` has one entry
    /// per attachment name in that conflict's `attachment_deltas`.
    pub entry_attachment_choices: Vec<EntryAttachmentChoiceFfi>,
    /// One entry per [`EntryConflictFfi`] with `icon_delta.is_some()`.
    pub entry_icon_choices: Vec<EntryIconChoiceFfi>,
    /// One entry per [`DeleteEditConflictFfi`].
    pub delete_edit_choices: Vec<DeleteEditChoiceEntryFfi>,
}

impl ResolutionFfi {
    /// Empty resolution — valid only when the outcome has no
    /// conflicts. Mirrors `EntryPatch::empty` / `GroupPatch::empty`.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
    }

    /// Construct a resolution from caller-built choice lists.
    /// Required because `#[non_exhaustive]` blocks struct-literal
    /// construction outside the crate (Swift bindings synthesise
    /// their own init).
    #[must_use]
    pub fn new(
        entry_field_choices: Vec<EntryFieldChoiceFfi>,
        entry_attachment_choices: Vec<EntryAttachmentChoiceFfi>,
        entry_icon_choices: Vec<EntryIconChoiceFfi>,
        delete_edit_choices: Vec<DeleteEditChoiceEntryFfi>,
    ) -> Self {
        Self {
            entry_field_choices,
            entry_attachment_choices,
            entry_icon_choices,
            delete_edit_choices,
        }
    }
}

impl EntryIconChoiceFfi {
    /// Construct an entry-icon-choice carrier. Required because
    /// `#[non_exhaustive]` blocks struct-literal construction outside
    /// the crate.
    #[must_use]
    pub fn new(entry_uuid: impl Into<String>, side: ConflictSideFfi) -> Self {
        Self {
            entry_uuid: entry_uuid.into(),
            side,
        }
    }
}

impl EntryFieldChoiceFfi {
    /// Construct an entry-field-choice carrier. Required because
    /// `#[non_exhaustive]` blocks struct-literal construction
    /// outside the crate.
    #[must_use]
    pub fn new(entry_uuid: impl Into<String>, field_choices: Vec<FieldChoiceFfi>) -> Self {
        Self {
            entry_uuid: entry_uuid.into(),
            field_choices,
        }
    }
}

impl FieldChoiceFfi {
    /// Construct a field-choice. Required because `#[non_exhaustive]`
    /// blocks struct-literal construction outside the crate.
    #[must_use]
    pub fn new(key: impl Into<String>, side: ConflictSideFfi) -> Self {
        Self {
            key: key.into(),
            side,
        }
    }
}

impl EntryAttachmentChoiceFfi {
    /// Construct an entry-attachment-choice carrier. Required
    /// because `#[non_exhaustive]` blocks struct-literal construction
    /// outside the crate.
    #[must_use]
    pub fn new(
        entry_uuid: impl Into<String>,
        attachment_choices: Vec<AttachmentChoiceFfi>,
    ) -> Self {
        Self {
            entry_uuid: entry_uuid.into(),
            attachment_choices,
        }
    }
}

impl AttachmentChoiceFfi {
    /// Construct a per-attachment choice carrier.
    #[must_use]
    pub fn new(name: impl Into<String>, choice: AttachmentChoiceKindFfi) -> Self {
        Self {
            name: name.into(),
            choice,
        }
    }
}

impl DeleteEditChoiceEntryFfi {
    /// Construct a delete-edit choice carrier. Required because
    /// `#[non_exhaustive]` blocks struct-literal construction
    /// outside the crate.
    #[must_use]
    pub fn new(entry_uuid: impl Into<String>, choice: DeleteEditChoiceFfi) -> Self {
        Self {
            entry_uuid: entry_uuid.into(),
            choice,
        }
    }
}

/// Per-entry resolution for one [`EntryConflictFfi`].
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryFieldChoiceFfi {
    pub entry_uuid: String,
    pub field_choices: Vec<FieldChoiceFfi>,
}

/// Per-field winner inside an [`EntryFieldChoiceFfi`].
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct FieldChoiceFfi {
    pub key: String,
    pub side: ConflictSideFfi,
}

/// Per-entry attachment-resolution carrier. One element per
/// [`EntryConflictFfi`] with a non-empty `attachment_deltas`.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryAttachmentChoiceFfi {
    pub entry_uuid: String,
    pub attachment_choices: Vec<AttachmentChoiceFfi>,
}

/// Per-attachment choice inside an [`EntryAttachmentChoiceFfi`].
/// `name` matches the corresponding [`AttachmentDeltaFfi::name`].
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct AttachmentChoiceFfi {
    pub name: String,
    pub choice: AttachmentChoiceKindFfi,
}

/// Per-entry icon choice carrier. One element per [`EntryConflictFfi`]
/// with `icon_delta.is_some()`.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryIconChoiceFfi {
    pub entry_uuid: String,
    pub side: ConflictSideFfi,
}

/// Caller's choice for a single conflicting attachment. Mirrors
/// [`keepass_merge::AttachmentChoice`].
///
/// `KeepBoth` is validation-rejected by the merge crate for any
/// non-`BothDiffer` delta — the absent side has no bytes to keep.
/// The optional `keep_both_rename_override` lets the caller pin the
/// renamed slot for the remote-side attachment in a `KeepBoth`
/// outcome; `None` falls through to the merge crate's default
/// pattern (`"<stem> (remote).<ext>"`, with counter suffix on
/// collision).
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachmentChoiceKindFfi {
    /// Take local's bytes (or, for `RemoteOnly`, accept local's
    /// absent state — drop the attachment).
    KeepLocal,
    /// Take remote's bytes (or, for `LocalOnly`, accept remote's
    /// absent state — drop the attachment).
    KeepRemote,
    /// Both sides edited; keep both, renaming the remote-side one.
    /// Only valid for `BothDiffer` deltas; any other kind is rejected
    /// at apply time.
    KeepBoth {
        /// Override the default rename pattern; `None` uses the
        /// `"<stem> (remote).<ext>"` default.
        rename_override: Option<String>,
    },
}

impl From<AttachmentChoiceKindFfi> for KmAttachmentChoice {
    fn from(c: AttachmentChoiceKindFfi) -> Self {
        match c {
            AttachmentChoiceKindFfi::KeepLocal => Self::KeepLocal,
            AttachmentChoiceKindFfi::KeepRemote => Self::KeepRemote,
            AttachmentChoiceKindFfi::KeepBoth { rename_override } => {
                Self::KeepBoth { rename_override }
            }
        }
    }
}

/// Per-entry resolution for one [`DeleteEditConflictFfi`].
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct DeleteEditChoiceEntryFfi {
    pub entry_uuid: String,
    pub choice: DeleteEditChoiceFfi,
}

/// Caller's choice for a single conflicting field.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConflictSideFfi {
    Local,
    Remote,
}

impl From<ConflictSideFfi> for KmConflictSide {
    fn from(s: ConflictSideFfi) -> Self {
        match s {
            ConflictSideFfi::Local => Self::Local,
            ConflictSideFfi::Remote => Self::Remote,
        }
    }
}

/// Caller's choice for a delete-vs-edit conflict.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteEditChoiceFfi {
    KeepLocal,
    AcceptRemoteDelete,
}

impl From<DeleteEditChoiceFfi> for KmDeleteEditChoice {
    fn from(c: DeleteEditChoiceFfi) -> Self {
        match c {
            DeleteEditChoiceFfi::KeepLocal => Self::KeepLocal,
            DeleteEditChoiceFfi::AcceptRemoteDelete => Self::AcceptRemoteDelete,
        }
    }
}

/// Translate a [`ResolutionFfi`] into the upstream
/// [`keepass_merge::Resolution`] shape. UUID-parse failures surface as
/// [`VaultError::Merge`] — they're caller-error class, not
/// entry-lookup misses.
pub(crate) fn resolution_ffi_to_km(resolution: &ResolutionFfi) -> Result<KmResolution, VaultError> {
    let mut entry_field_choices: HashMap<EntryId, HashMap<String, KmConflictSide>> = HashMap::new();
    for efc in &resolution.entry_field_choices {
        let id = parse_entry_id(&efc.entry_uuid)?;
        let inner = entry_field_choices.entry(id).or_default();
        for fc in &efc.field_choices {
            inner.insert(fc.key.clone(), fc.side.into());
        }
    }
    let mut entry_attachment_choices: HashMap<EntryId, HashMap<String, KmAttachmentChoice>> =
        HashMap::new();
    for eac in &resolution.entry_attachment_choices {
        let id = parse_entry_id(&eac.entry_uuid)?;
        let inner = entry_attachment_choices.entry(id).or_default();
        for ac in &eac.attachment_choices {
            inner.insert(ac.name.clone(), ac.choice.clone().into());
        }
    }
    let mut entry_icon_choices: HashMap<EntryId, KmConflictSide> = HashMap::new();
    for eic in &resolution.entry_icon_choices {
        let id = parse_entry_id(&eic.entry_uuid)?;
        entry_icon_choices.insert(id, eic.side.into());
    }
    let mut delete_edit_choices: HashMap<EntryId, KmDeleteEditChoice> = HashMap::new();
    for dec in &resolution.delete_edit_choices {
        let id = parse_entry_id(&dec.entry_uuid)?;
        delete_edit_choices.insert(id, dec.choice.into());
    }

    let mut r = KmResolution::default();
    r.entry_field_choices = entry_field_choices;
    r.entry_attachment_choices = entry_attachment_choices;
    r.entry_icon_choices = entry_icon_choices;
    r.delete_edit_choices = delete_edit_choices;
    Ok(r)
}

fn parse_entry_id(s: &str) -> Result<EntryId, VaultError> {
    Uuid::parse_str(s)
        .map(EntryId)
        .map_err(|_| VaultError::Merge(format!("invalid uuid in resolution: {s:?}")))
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
