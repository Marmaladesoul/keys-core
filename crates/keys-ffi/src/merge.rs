//! Conflict-resolution FFI Records — the shared vocabulary between the
//! engine's conflict payload ([`crate::ConflictPayloadFfi`]) and the
//! resolution a frontend hands back
//! (`Engine::apply_conflict_resolution`).
//!
//! [`EntryConflictFfi`] / [`DeleteEditConflictFfi`] carry both pre-merge
//! sides plus pre-computed deltas so the binding side doesn't re-diff;
//! [`ResolutionFfi`] and its per-entry choice Records express the user's
//! decisions, mapped onto `keepass-merge`'s resolution types by
//! [`resolution_ffi_to_km`].

use std::collections::HashMap;

use keepass_core::model::{Entry as KcEntry, EntryId, GroupId};
use keepass_merge::{
    AttachmentChoice as KmAttachmentChoice, AttachmentDeltaKind as KmAttachmentDeltaKind,
    ConflictSide as KmConflictSide, DeleteEditChoice as KmDeleteEditChoice,
    FieldDeltaKind as KmFieldDeltaKind, Resolution as KmResolution,
};
use uuid::Uuid;

use crate::error::VaultError;

/// One entry-level conflict surfaced by the merge.
///
/// `local` and `remote` carry the full pre-merge entry state for the
/// resolver UI. `field_deltas` is the pre-computed list of differing
/// keys so the binding side doesn't re-diff.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryConflictFfi {
    pub entry_uuid: String,
    pub local: ConflictEntrySnapshotFfi,
    pub remote: ConflictEntrySnapshotFfi,
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
    /// A future `keepass_merge::AttachmentDeltaKind` variant that this
    /// build of the FFI facade doesn't yet recognise. Surfaced rather
    /// than panicked across the FFI boundary so consumers can prompt
    /// the user to update Keys instead of crashing on an unknown
    /// classification.
    Unknown,
}

impl From<KmAttachmentDeltaKind> for AttachmentDeltaKindFfi {
    fn from(k: KmAttachmentDeltaKind) -> Self {
        match k {
            KmAttachmentDeltaKind::LocalOnly => Self::LocalOnly,
            KmAttachmentDeltaKind::RemoteOnly => Self::RemoteOnly,
            KmAttachmentDeltaKind::BothDiffer => Self::BothDiffer,
            other => {
                debug_assert!(
                    false,
                    "unmapped keepass_merge::AttachmentDeltaKind variant in keys-ffi facade: {other:?}"
                );
                Self::Unknown
            }
        }
    }
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
    /// A future `keepass_merge::FieldDeltaKind` variant that this
    /// build of the FFI facade doesn't yet recognise. Surfaced rather
    /// than panicked across the FFI boundary so consumers can prompt
    /// the user to update Keys instead of crashing on an unknown
    /// classification.
    Unknown,
}

impl From<KmFieldDeltaKind> for FieldDeltaKindFfi {
    fn from(k: KmFieldDeltaKind) -> Self {
        match k {
            KmFieldDeltaKind::LocalOnly => Self::LocalOnly,
            KmFieldDeltaKind::RemoteOnly => Self::RemoteOnly,
            KmFieldDeltaKind::BothDiffer => Self::BothDiffer,
            other => {
                debug_assert!(
                    false,
                    "unmapped keepass_merge::FieldDeltaKind variant in keys-ffi facade: {other:?}"
                );
                Self::Unknown
            }
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
    pub local: Option<ConflictEntrySnapshotFfi>,
}

/// A pre-merge snapshot of one side of a conflicting entry — the display
/// metadata the resolver UI renders while the user chooses a side.
///
/// Deliberately lean: it carries only what the resolver shows (identity,
/// the visible text/appearance fields, and custom-field *names*), not the
/// full engine read model. Protected values never cross here (custom
/// fields with `is_protected` carry an empty `value`); the resolver fetches
/// per-side plaintext on demand through the engine's
/// `reveal_conflict_local_field` / `reveal_conflict_remote_field`. Built
/// directly from the `keepass-core` model entry the merge crate hands back
/// for each side.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct ConflictEntrySnapshotFfi {
    pub uuid: String,
    pub group_uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    /// User-defined custom fields in source declaration order. Protected
    /// fields appear with `is_protected = true` and an empty `value`.
    pub custom_fields: Vec<ConflictCustomFieldFfi>,
    /// Built-in `KeePass` icon index (0–68); `custom_icon_uuid` overrides
    /// it for rendering when set.
    pub icon_id: u32,
    /// Hyphenated-lowercase UUID into the vault's custom-icon pool, or
    /// `None` for a built-in icon.
    pub custom_icon_uuid: Option<String>,
    /// `<ForegroundColor>` — `"#RRGGBB"`; empty string means default.
    pub foreground_color: String,
    /// `<BackgroundColor>` — `"#RRGGBB"`; empty string means default.
    pub background_color: String,
    /// `<OverrideURL>`; empty string means none.
    pub override_url: String,
    /// Whether the entry carries an expiry at all.
    pub expires: bool,
    /// `<ExpiryTime>` as Unix-epoch milliseconds; `None` when absent. Only
    /// meaningful when `expires` is `true`.
    pub expiry_time_ms: Option<i64>,
}

/// A custom field on a [`ConflictEntrySnapshotFfi`]. Protected fields carry
/// their name with an empty `value` — plaintext is fetched on demand
/// through the engine's per-side conflict reveal.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct ConflictCustomFieldFfi {
    pub name: String,
    /// Empty when `is_protected == true`; the on-disk value otherwise.
    pub value: String,
    pub is_protected: bool,
}

impl ConflictEntrySnapshotFfi {
    /// Shape a `keepass-core` model entry (one side of a conflict, as the
    /// merge crate hands it back) plus its resolved parent group into a
    /// display snapshot. Protected custom-field values are blanked here —
    /// they never cross the boundary at snapshot time.
    pub(crate) fn from_model(entry: &KcEntry, group_uuid: GroupId) -> Self {
        let custom_fields = entry
            .custom_fields
            .iter()
            .map(|f| ConflictCustomFieldFfi {
                name: f.key.clone(),
                value: if f.protected {
                    String::new()
                } else {
                    f.value.clone()
                },
                is_protected: f.protected,
            })
            .collect();
        Self {
            uuid: entry.id.0.to_string(),
            group_uuid: group_uuid.0.to_string(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            tags: entry.tags.clone(),
            custom_fields,
            icon_id: entry.icon_id,
            custom_icon_uuid: entry.custom_icon_uuid.map(|u| u.to_string()),
            foreground_color: entry.foreground_color.clone(),
            background_color: entry.background_color.clone(),
            override_url: entry.override_url.clone(),
            expires: entry.times.expires,
            expiry_time_ms: entry.times.expiry_time.map(|t| t.timestamp_millis()),
        }
    }
}

// ---------------------------------------------------------------------------
// Resolution carriers (slice 7.5b)
// ---------------------------------------------------------------------------

/// Caller's resolution choices for the conflict buckets of a
/// [`crate::ConflictPayloadFfi`].
///
/// Built by the Swift conflict-resolver UI from user input, then handed
/// to `Engine::apply_conflict_resolution`. Empty maps are valid when the
/// corresponding conflict buckets are also empty — that's the
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

#[cfg(test)]
mod delta_kind_mapping_tests {
    //! Pin every currently-known `KmFieldDeltaKind` / `KmAttachmentDeltaKind`
    //! variant to its FFI counterpart. The wildcard arm degrades to
    //! the new `Unknown` variant rather than panicking across the FFI
    //! boundary; CI catches a new upstream variant via the
    //! `debug_assert!` inside that arm.
    use super::*;

    #[test]
    fn field_delta_local_only_round_trips() {
        assert_eq!(
            FieldDeltaKindFfi::from(KmFieldDeltaKind::LocalOnly),
            FieldDeltaKindFfi::LocalOnly,
        );
    }

    #[test]
    fn field_delta_remote_only_round_trips() {
        assert_eq!(
            FieldDeltaKindFfi::from(KmFieldDeltaKind::RemoteOnly),
            FieldDeltaKindFfi::RemoteOnly,
        );
    }

    #[test]
    fn field_delta_both_differ_round_trips() {
        assert_eq!(
            FieldDeltaKindFfi::from(KmFieldDeltaKind::BothDiffer),
            FieldDeltaKindFfi::BothDiffer,
        );
    }

    #[test]
    fn attachment_delta_local_only_round_trips() {
        assert_eq!(
            AttachmentDeltaKindFfi::from(KmAttachmentDeltaKind::LocalOnly),
            AttachmentDeltaKindFfi::LocalOnly,
        );
    }

    #[test]
    fn attachment_delta_remote_only_round_trips() {
        assert_eq!(
            AttachmentDeltaKindFfi::from(KmAttachmentDeltaKind::RemoteOnly),
            AttachmentDeltaKindFfi::RemoteOnly,
        );
    }

    #[test]
    fn attachment_delta_both_differ_round_trips() {
        assert_eq!(
            AttachmentDeltaKindFfi::from(KmAttachmentDeltaKind::BothDiffer),
            AttachmentDeltaKindFfi::BothDiffer,
        );
    }

    #[test]
    fn unknown_variant_exists_as_safe_fallback() {
        // Structural assertion only: the wildcard arm needs a target
        // and `Unknown` is it. We can't construct an
        // "unknown future upstream variant" to drive the fallthrough,
        // so the per-variant pins above are what makes a new upstream
        // variant landing without a test addition visible in CI.
        let _: AttachmentDeltaKindFfi = AttachmentDeltaKindFfi::Unknown;
        let _: FieldDeltaKindFfi = FieldDeltaKindFfi::Unknown;
    }
}
