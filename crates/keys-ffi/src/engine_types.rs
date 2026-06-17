//! Wire-friendly mirrors of the [`keys_engine`] model + event types.
//!
//! Conversion is one-way (engine → FFI) for reads, two-way (FFI ↔
//! engine) for mutations. UUIDs cross as canonical lowercase strings;
//! `Duration` crosses as integer seconds (uniffi has no native
//! `Duration`); `SecretString` collapses to `String` at the FFI
//! boundary (uniffi can't preserve zeroize-on-drop into Swift `String`).
//!
//! **Predicate FFI shape (the maintainer 2026-05-16):** the engine's
//! [`keys_engine::Predicate::Unknown`] variant — which carries an
//! arbitrary [`serde_json::Value`] from a newer producer — is **not
//! exposed** as a constructable arm here. Frontends can't usefully
//! build one, and the only consumer that ever produces it (the smart-
//! folder JSON decoder) won't round-trip through this enum. If a
//! caller fetches a smart folder containing an `Unknown` node, the
//! `evaluable` flag will be `false` and the predicate-bearing methods
//! will surface [`crate::EngineError::NotEvaluable`] — the caller never
//! needs to inspect the variant directly.

// Per-method `# Errors` doc would be a copy of EngineError's variants;
// the enum carries that info.
#![allow(clippy::missing_errors_doc)]
// All the FFI-mirror types name engine types whose docs use bare
// terms like `update_entry`, `SQLite`, `IconRef`. Backticking each one
// in every doc comment would be noise; the originals are clear.
#![allow(clippy::doc_markdown)]

use std::time::Duration;

use keys_engine as eng;
use uuid::Uuid;

use crate::engine_error::EngineError;

// ────────────────────────────────────────────────────────────────────────
// Pagination
// ────────────────────────────────────────────────────────────────────────

/// Page window for paginated listing methods.
#[derive(uniffi::Record, Debug, Clone, Copy)]
pub struct Page {
    /// Number of rows to skip before the first returned row.
    pub offset: u64,
    /// Maximum number of rows to return. Pass [`u64::MAX`] for "no limit".
    pub limit: u64,
}

impl From<Page> for eng::Pagination {
    fn from(p: Page) -> Self {
        Self {
            offset: p.offset,
            limit: p.limit,
        }
    }
}

/// `(mtime, size)` signature of the KDBX file whose contents the
/// engine's SQLite mirror currently corresponds to. See
/// [`crate::Engine::kdbx_state_signature`].
#[derive(uniffi::Record, Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdbxStateSignatureFfi {
    /// `modified` timestamp of the KDBX file, in milliseconds since the
    /// Unix epoch.
    pub mtime_ms: i64,
    /// Byte length of the KDBX file.
    pub byte_count: u64,
}

impl From<eng::KdbxStateSignature> for KdbxStateSignatureFfi {
    fn from(s: eng::KdbxStateSignature) -> Self {
        Self {
            mtime_ms: s.mtime_ms,
            byte_count: s.byte_count,
        }
    }
}

/// Blob-pool stats returned by [`crate::Engine::attachment_blob_stats`].
/// Uniffi can't return a tuple from a method elegantly, so this is the
/// FFI carrier.
#[derive(uniffi::Record, Debug, Clone, Copy)]
pub struct AttachmentBlobStats {
    /// Number of rows in the content-addressed `attachment_blob` pool.
    pub count: u64,
    /// Sum of the pool rows' payload sizes, in bytes.
    pub bytes: u64,
}

/// `(tag_name, count)` pair returned by
/// [`crate::Engine::tag_usage_counts`]. Uniffi can't return a tuple
/// from a method elegantly, so this is the FFI carrier.
#[derive(uniffi::Record, Debug, Clone)]
pub struct TagUsageCount {
    /// Tag name as stored in the `tag` table.
    pub name: String,
    /// Number of entries referencing this tag, including recycle-bin
    /// entries.
    pub count: u64,
}

// ────────────────────────────────────────────────────────────────────────
// Enums
// ────────────────────────────────────────────────────────────────────────

/// Scope of an [`crate::Engine::search`] query.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchScope {
    /// Title + username + url + notes + tags.
    #[default]
    AnyField,
    /// Title only.
    TitleOnly,
    /// Notes only.
    NotesOnly,
}

impl From<SearchScope> for eng::SearchScope {
    fn from(s: SearchScope) -> Self {
        match s {
            SearchScope::AnyField => Self::AnyField,
            SearchScope::TitleOnly => Self::TitleOnly,
            SearchScope::NotesOnly => Self::NotesOnly,
        }
    }
}

/// Password strength bucket. See [`keys_engine::StrengthBucket`].
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthBucket {
    VeryWeak,
    Weak,
    Reasonable,
    Strong,
    VeryStrong,
}

impl From<eng::StrengthBucket> for StrengthBucket {
    fn from(b: eng::StrengthBucket) -> Self {
        match b {
            eng::StrengthBucket::VeryWeak => Self::VeryWeak,
            eng::StrengthBucket::Weak => Self::Weak,
            eng::StrengthBucket::Reasonable => Self::Reasonable,
            eng::StrengthBucket::Strong => Self::Strong,
            eng::StrengthBucket::VeryStrong => Self::VeryStrong,
        }
    }
}

impl From<StrengthBucket> for eng::StrengthBucket {
    fn from(b: StrengthBucket) -> Self {
        match b {
            StrengthBucket::VeryWeak => Self::VeryWeak,
            StrengthBucket::Weak => Self::Weak,
            StrengthBucket::Reasonable => Self::Reasonable,
            StrengthBucket::Strong => Self::Strong,
            StrengthBucket::VeryStrong => Self::VeryStrong,
        }
    }
}

/// Password strength result: raw character-class entropy plus the
/// derived bucket. Mirrors [`keys_engine::Strength`].
///
/// Used by callers that want to show live strength on an unsaved
/// password (e.g. the password generator preview), where querying the
/// engine's persisted `password_strength_bucket` column isn't an
/// option because the entry doesn't exist yet.
#[derive(uniffi::Record, Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    /// `len * log2(pool_size)` in bits. Zero for empty password.
    pub entropy_bits: f64,
    /// Discrete bucket derived from `entropy_bits` per the engine's
    /// fixed boundaries.
    pub bucket: StrengthBucket,
}

impl From<eng::Strength> for Strength {
    fn from(s: eng::Strength) -> Self {
        Self {
            entropy_bits: s.entropy_bits,
            bucket: s.bucket.into(),
        }
    }
}

/// Reference to an entry/group icon. UUIDs cross as strings.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum IconRef {
    /// Built-in icon index (0–68).
    Builtin { index: u32 },
    /// Custom icon UUID (canonical lowercase string form).
    Custom { uuid: String },
}

impl From<eng::IconRef> for IconRef {
    fn from(i: eng::IconRef) -> Self {
        match i {
            eng::IconRef::Builtin(idx) => Self::Builtin { index: idx },
            eng::IconRef::Custom(u) => Self::Custom {
                uuid: u.to_string(),
            },
        }
    }
}

impl TryFrom<IconRef> for eng::IconRef {
    type Error = EngineError;

    fn try_from(i: IconRef) -> Result<Self, EngineError> {
        Ok(match i {
            IconRef::Builtin { index } => Self::Builtin(index),
            IconRef::Custom { uuid } => Self::Custom(parse_uuid(&uuid, "icon_uuid")?),
        })
    }
}

// ────────────────────────────────────────────────────────────────────────
// VaultState
// ────────────────────────────────────────────────────────────────────────

/// Lifecycle/health classification for the engine. Mirrors
/// [`keys_engine::VaultState`] + [`keys_engine::DisconnectReason`] flattened
/// into one wire-friendly enum.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum VaultState {
    Active,
    DisconnectedFileMissing,
    DisconnectedFileUnreadable { reason: String },
    DisconnectedNetworkUnavailable,
    DisconnectedOther { reason: String },
    ReadOnly,
    Error,
}

impl From<eng::VaultState> for VaultState {
    fn from(s: eng::VaultState) -> Self {
        use eng::{DisconnectReason as R, VaultState as S};
        match s {
            S::Active => Self::Active,
            S::Disconnected {
                reason: R::FileMissing,
            } => Self::DisconnectedFileMissing,
            S::Disconnected {
                reason: R::FileUnreadable(r),
            } => Self::DisconnectedFileUnreadable { reason: r },
            S::Disconnected {
                reason: R::NetworkUnavailable,
            } => Self::DisconnectedNetworkUnavailable,
            S::Disconnected {
                reason: R::Other(r),
            } => Self::DisconnectedOther { reason: r },
            S::ReadOnly => Self::ReadOnly,
            // `#[non_exhaustive]` — `Error` plus any future unknown
            // variant collapses to `Error` (the most conservative
            // "writes are not safe" signal).
            other => {
                let _ = other;
                Self::Error
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Records — read shapes
// ────────────────────────────────────────────────────────────────────────

/// Custom-field metadata (name + protected flag). Values fetched via
/// reveal API.
#[derive(uniffi::Record, Debug, Clone)]
pub struct CustomFieldRef {
    pub name: String,
    pub is_protected: bool,
}

impl From<eng::CustomFieldRef> for CustomFieldRef {
    fn from(c: eng::CustomFieldRef) -> Self {
        Self {
            name: c.name,
            is_protected: c.is_protected,
        }
    }
}

/// Attachment metadata (name + byte size). Bytes fetched on demand.
#[derive(uniffi::Record, Debug, Clone)]
pub struct AttachmentRef {
    pub name: String,
    pub size: u64,
}

impl From<eng::AttachmentRef> for AttachmentRef {
    fn from(a: eng::AttachmentRef) -> Self {
        Self {
            name: a.name,
            size: a.size,
        }
    }
}

/// Lightweight entry row for listing UIs.
#[derive(uniffi::Record, Debug, Clone)]
pub struct EngineEntrySummary {
    pub uuid: String,
    pub group_uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub url_host: String,
    /// Notes field (plain text). Surfaced on the summary so the entry
    /// list can drive client-side "notes-only" search-scope narrowing
    /// without a per-row reveal round-trip.
    pub notes: String,
    /// Created-at timestamp, ms since Unix epoch. Powers
    /// "sort by creation date" + date-section headers in the list.
    pub created_at: i64,
    pub modified_at: i64,
    /// Last-accessed timestamp, ms since Unix epoch. Powers
    /// "sort by last access" + Recently-Used section in the list.
    pub accessed_at: i64,
    pub last_used_at: Option<i64>,
    pub password_strength_bucket: Option<StrengthBucket>,
    pub password_entropy: Option<f64>,
    pub attachment_count: u32,
    pub icon: IconRef,
    /// `true` when the entry carries a TOTP secret — either via an
    /// `otpauth://` URL or a custom field named `otp` / `TOTP` /
    /// `OTPAuth` / `TOTP Seed`. Precomputed on the engine side; the
    /// AutoFill OTP-picker mode filters on this without per-row
    /// field-name inspection.
    pub has_totp: bool,
}

impl From<eng::EntrySummary> for EngineEntrySummary {
    fn from(e: eng::EntrySummary) -> Self {
        Self {
            uuid: e.uuid.to_string(),
            group_uuid: e.group_uuid.to_string(),
            title: e.title,
            username: e.username,
            url: e.url,
            url_host: e.url_host,
            notes: e.notes,
            created_at: e.created_at,
            modified_at: e.modified_at,
            accessed_at: e.accessed_at,
            last_used_at: e.last_used_at,
            password_strength_bucket: e.password_strength_bucket.map(Into::into),
            password_entropy: e.password_entropy,
            attachment_count: e.attachment_count,
            icon: e.icon.into(),
            has_totp: e.has_totp,
        }
    }
}

/// Full entry row for the detail pane.
#[derive(uniffi::Record, Debug, Clone)]
pub struct EntryFull {
    pub uuid: String,
    pub group_uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub url_host: String,
    pub notes: String,
    pub created_at: i64,
    pub modified_at: i64,
    pub accessed_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub is_recycled: bool,
    pub password_strength_bucket: Option<StrengthBucket>,
    pub password_entropy: Option<f64>,
    pub icon: IconRef,
    pub custom_fields: Vec<CustomFieldRef>,
    pub tags: Vec<String>,
    pub attachments: Vec<AttachmentRef>,
    pub history_count: u32,
    /// Per-entry `<CustomData>` items. Carries Keys-namespaced
    /// extensions like `keys.history_tombstones.v1`. Sorted by `key`.
    pub custom_data: Vec<CustomDataItemFfi>,
}

/// Wire-friendly mirror of [`keys_engine::CustomDataItemRef`].
#[derive(uniffi::Record, Debug, Clone)]
pub struct CustomDataItemFfi {
    pub key: String,
    pub value: String,
    pub last_modified_at: Option<i64>,
}

impl From<eng::CustomDataItemRef> for CustomDataItemFfi {
    fn from(c: eng::CustomDataItemRef) -> Self {
        Self {
            key: c.key,
            value: c.value,
            last_modified_at: c.last_modified_at,
        }
    }
}

impl From<eng::EntryFull> for EntryFull {
    fn from(e: eng::EntryFull) -> Self {
        Self {
            uuid: e.uuid.to_string(),
            group_uuid: e.group_uuid.to_string(),
            title: e.title,
            username: e.username,
            url: e.url,
            url_host: e.url_host,
            notes: e.notes,
            created_at: e.created_at,
            modified_at: e.modified_at,
            accessed_at: e.accessed_at,
            last_used_at: e.last_used_at,
            expires_at: e.expires_at,
            is_recycled: e.is_recycled,
            password_strength_bucket: e.password_strength_bucket.map(Into::into),
            password_entropy: e.password_entropy,
            icon: e.icon.into(),
            custom_fields: e.custom_fields.into_iter().map(Into::into).collect(),
            tags: e.tags,
            attachments: e.attachments.into_iter().map(Into::into).collect(),
            history_count: e.history_count,
            custom_data: e.custom_data.into_iter().map(Into::into).collect(),
        }
    }
}

/// Group-tree node. Reconstruct tree shape from `parent_uuid`.
#[derive(uniffi::Record, Debug, Clone)]
pub struct GroupNode {
    pub uuid: String,
    pub parent_uuid: Option<String>,
    pub name: String,
    pub icon: IconRef,
    pub entry_count_direct: u32,
    pub is_recycle_bin: bool,
    /// Position within the parent group's child list. Lower = earlier.
    pub sort_order: u32,
}

impl From<eng::GroupNode> for GroupNode {
    fn from(g: eng::GroupNode) -> Self {
        Self {
            uuid: g.uuid.to_string(),
            parent_uuid: g.parent_uuid.map(|u| u.to_string()),
            name: g.name,
            icon: g.icon.into(),
            entry_count_direct: g.entry_count_direct,
            is_recycle_bin: g.is_recycle_bin,
            sort_order: g.sort_order,
        }
    }
}

/// Historic snapshot of an entry.
///
/// Mirrors `EntryFull`'s structural shape minus things that don't
/// exist in a snapshot (`uuid`, `group_uuid`, `is_recycled`,
/// `history_count`) and minus protected-field plaintext (still
/// fetched via `reveal_history_field`).
#[derive(uniffi::Record, Debug, Clone)]
pub struct HistoricEntry {
    pub history_index: u32,
    pub title: String,
    pub username: String,
    pub url: String,
    pub url_host: String,
    pub notes: String,
    pub icon: IconRef,
    pub created_at: i64,
    pub modified_at: i64,
    pub accessed_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub password_strength_bucket: Option<StrengthBucket>,
    pub password_entropy: Option<f64>,
    pub custom_fields: Vec<CustomFieldRef>,
    pub tags: Vec<String>,
    pub attachments: Vec<AttachmentRef>,
    /// Per-snapshot `<CustomData>` items. Carries the parked-conflict
    /// marker (`keys.field_conflict.v1`) for the resolver UI to key
    /// off. Sorted by `key`.
    pub custom_data: Vec<CustomDataItemFfi>,
}

impl From<eng::HistoricEntry> for HistoricEntry {
    fn from(h: eng::HistoricEntry) -> Self {
        Self {
            history_index: h.history_index,
            title: h.title,
            username: h.username,
            url: h.url,
            url_host: h.url_host,
            notes: h.notes,
            icon: h.icon.into(),
            created_at: h.created_at,
            modified_at: h.modified_at,
            accessed_at: h.accessed_at,
            last_used_at: h.last_used_at,
            expires_at: h.expires_at,
            password_strength_bucket: h.password_strength_bucket.map(Into::into),
            password_entropy: h.password_entropy,
            custom_fields: h.custom_fields.into_iter().map(Into::into).collect(),
            tags: h.tags,
            attachments: h.attachments.into_iter().map(Into::into).collect(),
            custom_data: h.custom_data.into_iter().map(Into::into).collect(),
        }
    }
}

/// Persisted smart folder row.
#[derive(uniffi::Record, Debug, Clone)]
pub struct SmartFolder {
    pub id: i64,
    pub name: String,
    pub predicate: Predicate,
    pub version: u32,
    pub evaluable: bool,
    pub created_at: i64,
    pub modified_at: i64,
}

impl From<eng::SmartFolder> for SmartFolder {
    fn from(s: eng::SmartFolder) -> Self {
        Self {
            id: s.id,
            name: s.name,
            predicate: Predicate::from(&s.predicate),
            version: s.version,
            evaluable: s.evaluable,
            created_at: s.created_at,
            modified_at: s.modified_at,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Records — mutation shapes
// ────────────────────────────────────────────────────────────────────────

/// One custom field on a freshly-created entry.
#[derive(uniffi::Record, Debug, Clone)]
pub struct NewCustomField {
    pub name: String,
    /// Plaintext. For `protected = true` it'll be AES-GCM-sealed.
    pub value: String,
    pub protected: bool,
}

impl From<NewCustomField> for eng::NewCustomField {
    fn from(c: NewCustomField) -> Self {
        Self {
            name: c.name,
            value: secrecy::SecretString::from(c.value),
            protected: c.protected,
        }
    }
}

/// Field values for create_entry.
#[derive(uniffi::Record, Debug, Clone)]
pub struct NewEntryFields {
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    /// Canonical Password slot — plaintext at the FFI boundary;
    /// AES-GCM-sealed by the engine before it lands in SQLite.
    pub password: String,
    pub icon: IconRef,
    pub custom_fields: Vec<NewCustomField>,
    pub tags: Vec<String>,
}

impl TryFrom<NewEntryFields> for eng::NewEntryFields {
    type Error = EngineError;

    fn try_from(f: NewEntryFields) -> Result<Self, EngineError> {
        Ok(Self {
            title: f.title,
            username: f.username,
            url: f.url,
            notes: f.notes,
            password: secrecy::SecretString::from(f.password),
            icon: f.icon.try_into()?,
            custom_fields: f.custom_fields.into_iter().map(Into::into).collect(),
            tags: f.tags,
        })
    }
}

/// Patch shape for update_entry. Each field is `Option` — `None` = leave
/// alone, `Some(value)` = set. `expires_at` is `Option<Option<i64>>`
/// (outer = leave alone, inner None = clear, inner Some = set).
#[derive(uniffi::Record, Debug, Clone, Default)]
pub struct EntryUpdate {
    pub title: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// New password plaintext.
    pub password: Option<String>,
    pub icon: Option<IconRef>,
    pub expires_at: Option<Option<i64>>,
}

impl TryFrom<EntryUpdate> for eng::EntryUpdate {
    type Error = EngineError;

    fn try_from(u: EntryUpdate) -> Result<Self, EngineError> {
        Ok(Self {
            title: u.title,
            username: u.username,
            url: u.url,
            notes: u.notes,
            password: u.password.map(secrecy::SecretString::from),
            icon: u.icon.map(eng::IconRef::try_from).transpose()?,
            expires_at: u.expires_at,
        })
    }
}

/// Full desired entry state for `save_entry`. Unlike [`EntryUpdate`]'s
/// patch shape, every field is the complete post-save value. The engine
/// applies the whole entry in one transaction with exactly one history
/// snapshot — the editor's single "Save" funnel. `custom_fields` is a
/// replace-all set (protected + non-protected, excluding the canonical
/// Password slot); `tags` is applied with set-semantics.
#[derive(uniffi::Record, Debug, Clone)]
pub struct EntrySave {
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    /// Canonical Password slot plaintext; AES-GCM-sealed by the engine.
    pub password: String,
    pub icon: IconRef,
    /// Expiry, ms since Unix epoch; `None` = no expiry.
    pub expires_at: Option<i64>,
    /// Full custom-field set (replace-all). Excludes Password.
    pub custom_fields: Vec<NewCustomField>,
    pub tags: Vec<String>,
}

impl TryFrom<EntrySave> for eng::EntrySave {
    type Error = EngineError;

    fn try_from(s: EntrySave) -> Result<Self, EngineError> {
        Ok(Self {
            title: s.title,
            username: s.username,
            url: s.url,
            notes: s.notes,
            password: secrecy::SecretString::from(s.password),
            icon: s.icon.try_into()?,
            expires_at: s.expires_at,
            custom_fields: s.custom_fields.into_iter().map(Into::into).collect(),
            tags: s.tags,
        })
    }
}

/// Field values for create_group.
#[derive(uniffi::Record, Debug, Clone)]
pub struct NewGroupFields {
    pub name: String,
    pub notes: String,
    pub icon: IconRef,
}

impl TryFrom<NewGroupFields> for eng::NewGroupFields {
    type Error = EngineError;

    fn try_from(f: NewGroupFields) -> Result<Self, EngineError> {
        Ok(Self {
            name: f.name,
            notes: f.notes,
            icon: f.icon.try_into()?,
        })
    }
}

/// Patch shape for update_group.
#[derive(uniffi::Record, Debug, Clone, Default)]
pub struct GroupUpdate {
    pub name: Option<String>,
    pub notes: Option<String>,
    pub icon: Option<IconRef>,
    pub expires_at: Option<Option<i64>>,
}

impl TryFrom<GroupUpdate> for eng::GroupUpdate {
    type Error = EngineError;

    fn try_from(u: GroupUpdate) -> Result<Self, EngineError> {
        Ok(Self {
            name: u.name,
            notes: u.notes,
            icon: u.icon.map(eng::IconRef::try_from).transpose()?,
            expires_at: u.expires_at,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────
// Predicate FFI mirror
// ────────────────────────────────────────────────────────────────────────

/// Smart-folder predicate AST — FFI mirror of [`keys_engine::Predicate`].
///
/// `Unknown` is deliberately absent — see the module-level docs.
/// `Duration` fields cross as `duration_secs: i64` (uniffi has no
/// native `Duration`).
#[derive(uniffi::Enum, Debug, Clone)]
pub enum Predicate {
    And {
        predicates: Vec<Predicate>,
    },
    Or {
        predicates: Vec<Predicate>,
    },
    /// Logical NOT. `predicates` must contain exactly one element;
    /// any other count is rejected as
    /// [`EngineError::NotEvaluable`] at conversion time. Modelled as
    /// `Vec` rather than `Box<Predicate>` because uniffi can't lower
    /// recursive `Box<EnumVariant>` shapes across the FFI.
    Not {
        predicates: Vec<Predicate>,
    },
    TitleContains {
        substring: String,
    },
    UrlContains {
        substring: String,
    },
    UsernameContains {
        substring: String,
    },
    UrlHostEquals {
        host: String,
    },
    TagEquals {
        tag: String,
    },
    TagHasAny {
        tags: Vec<String>,
    },
    TagHasAll {
        tags: Vec<String>,
    },
    ModifiedWithin {
        duration_secs: i64,
    },
    ModifiedBefore {
        timestamp_ms: i64,
    },
    Expired,
    ExpiringWithin {
        duration_secs: i64,
    },
    StrengthBelow {
        bucket: StrengthBucket,
    },
    EntropyBelow {
        bits: f64,
    },
    Duplicates,
    Group {
        uuid: String,
    },
    /// Surfaces an engine-side `Predicate::Unknown` node (from a
    /// newer producer). Not constructable from the frontend — used
    /// only as a marker when reading a persisted smart folder.
    /// Predicate-bearing methods will refuse to evaluate it with
    /// [`crate::EngineError::NotEvaluable`].
    UnknownVariant,
}

impl From<&eng::Predicate> for Predicate {
    fn from(p: &eng::Predicate) -> Self {
        use eng::Predicate as P;
        match p {
            P::And { predicates } => Self::And {
                predicates: predicates.iter().map(Into::into).collect(),
            },
            P::Or { predicates } => Self::Or {
                predicates: predicates.iter().map(Into::into).collect(),
            },
            P::Not { predicate } => Self::Not {
                predicates: vec![predicate.as_ref().into()],
            },
            P::TitleContains { substring } => Self::TitleContains {
                substring: substring.clone(),
            },
            P::UrlContains { substring } => Self::UrlContains {
                substring: substring.clone(),
            },
            P::UsernameContains { substring } => Self::UsernameContains {
                substring: substring.clone(),
            },
            P::UrlHostEquals { host } => Self::UrlHostEquals { host: host.clone() },
            P::TagEquals { tag } => Self::TagEquals { tag: tag.clone() },
            P::TagHasAny { tags } => Self::TagHasAny { tags: tags.clone() },
            P::TagHasAll { tags } => Self::TagHasAll { tags: tags.clone() },
            P::ModifiedWithin { duration } => Self::ModifiedWithin {
                duration_secs: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            },
            P::ModifiedBefore { timestamp_ms } => Self::ModifiedBefore {
                timestamp_ms: *timestamp_ms,
            },
            P::Expired => Self::Expired,
            P::ExpiringWithin { duration } => Self::ExpiringWithin {
                duration_secs: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            },
            P::StrengthBelow { bucket } => Self::StrengthBelow {
                bucket: (*bucket).into(),
            },
            P::EntropyBelow { bits } => Self::EntropyBelow { bits: *bits },
            P::Duplicates => Self::Duplicates,
            P::Group { uuid } => Self::Group {
                uuid: uuid.to_string(),
            },
            // `Unknown(_)` plus any future non-exhaustive variant
            // collapses to `UnknownVariant` — neither is constructable
            // or evaluable from the FFI side.
            other => {
                let _ = other;
                Self::UnknownVariant
            }
        }
    }
}

impl TryFrom<Predicate> for eng::Predicate {
    type Error = EngineError;

    fn try_from(p: Predicate) -> Result<Self, EngineError> {
        Ok(match p {
            Predicate::And { predicates } => Self::And {
                predicates: predicates
                    .into_iter()
                    .map(Self::try_from)
                    .collect::<Result<_, _>>()?,
            },
            Predicate::Or { predicates } => Self::Or {
                predicates: predicates
                    .into_iter()
                    .map(Self::try_from)
                    .collect::<Result<_, _>>()?,
            },
            Predicate::Not { mut predicates } => {
                if predicates.len() != 1 {
                    return Err(EngineError::NotEvaluable);
                }
                Self::Not {
                    predicate: Box::new(Self::try_from(predicates.remove(0))?),
                }
            }
            Predicate::TitleContains { substring } => Self::TitleContains { substring },
            Predicate::UrlContains { substring } => Self::UrlContains { substring },
            Predicate::UsernameContains { substring } => Self::UsernameContains { substring },
            Predicate::UrlHostEquals { host } => Self::UrlHostEquals { host },
            Predicate::TagEquals { tag } => Self::TagEquals { tag },
            Predicate::TagHasAny { tags } => Self::TagHasAny { tags },
            Predicate::TagHasAll { tags } => Self::TagHasAll { tags },
            Predicate::ModifiedWithin { duration_secs } => Self::ModifiedWithin {
                duration: secs_to_duration(duration_secs),
            },
            Predicate::ModifiedBefore { timestamp_ms } => Self::ModifiedBefore { timestamp_ms },
            Predicate::Expired => Self::Expired,
            Predicate::ExpiringWithin { duration_secs } => Self::ExpiringWithin {
                duration: secs_to_duration(duration_secs),
            },
            Predicate::StrengthBelow { bucket } => Self::StrengthBelow {
                bucket: bucket.into(),
            },
            Predicate::EntropyBelow { bits } => Self::EntropyBelow { bits },
            Predicate::Duplicates => Self::Duplicates,
            Predicate::Group { uuid } => Self::Group {
                uuid: parse_uuid(&uuid, "group_uuid")?,
            },
            Predicate::UnknownVariant => return Err(EngineError::NotEvaluable),
        })
    }
}

fn secs_to_duration(secs: i64) -> Duration {
    // Negative → zero, matching the engine's "duration is always
    // forward-looking" assumption.
    Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

// ────────────────────────────────────────────────────────────────────────
// MergeResult / MergeStats — reconcile_with_disk outcome
// ────────────────────────────────────────────────────────────────────────

/// Outcome of a successful [`crate::Engine::reconcile_with_disk`] call.
///
/// `Conflict` carries the synthetic id only — the full payload is
/// fetched separately via [`crate::Engine::pending_conflict`], which
/// gives the resolver UI a peek-only view of the stashed payload
/// keyed by id. Matches the maintainer's 2026-05-16 "big payload = opaque id +
/// accessor" decision.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum MergeResult {
    NoChange,
    Merged { applied: MergeStats },
    Conflict { id: i64 },
}

impl From<eng::MergeResult> for MergeResult {
    fn from(r: eng::MergeResult) -> Self {
        match r {
            eng::MergeResult::NoChange => Self::NoChange,
            eng::MergeResult::Merged { applied } => Self::Merged {
                applied: applied.into(),
            },
            eng::MergeResult::Conflict(p) => Self::Conflict { id: p.id },
            // `#[non_exhaustive]` upstream — collapse to `NoChange`.
            other => {
                let _ = other;
                Self::NoChange
            }
        }
    }
}

/// Outcome of a successful
/// [`crate::Engine::reconcile_with_disk_park_conflicts`] call.
///
/// Slice 5b's non-blocking replacement for [`MergeResult::Conflict`]:
/// conflicts are parked into the merged vault's history rather than
/// stashed for a modal. The third variant carries a list of entry
/// UUIDs the resolver UI uses to render its review list.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum ParkConflictsResultFfi {
    NoChange,
    Applied {
        applied: MergeStats,
        parked: ParkedConflictsSummaryFfi,
    },
}

impl From<eng::ParkConflictsResult> for ParkConflictsResultFfi {
    fn from(r: eng::ParkConflictsResult) -> Self {
        match r {
            eng::ParkConflictsResult::NoChange => Self::NoChange,
            eng::ParkConflictsResult::Applied { applied, parked } => Self::Applied {
                applied: applied.into(),
                parked: parked.into(),
            },
            other => {
                let _ = other;
                Self::NoChange
            }
        }
    }
}

/// Wire-friendly mirror of [`keys_engine::ParkedConflictsSummary`].
#[derive(uniffi::Record, Debug, Clone, Default, PartialEq, Eq)]
pub struct ParkedConflictsSummaryFfi {
    pub entries_with_parked_conflict: Vec<String>,
    pub entries_restored_from_deletion: Vec<String>,
    pub attachments_kept_both: Vec<String>,
}

impl From<eng::ParkedConflictsSummary> for ParkedConflictsSummaryFfi {
    fn from(s: eng::ParkedConflictsSummary) -> Self {
        Self {
            entries_with_parked_conflict: s.entries_with_parked_conflict,
            entries_restored_from_deletion: s.entries_restored_from_deletion,
            attachments_kept_both: s.attachments_kept_both,
        }
    }
}

/// Aggregate counts of merge mutations applied to SQLite.
#[derive(uniffi::Record, Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeStats {
    pub entries_added: u64,
    pub entries_updated: u64,
    pub entries_deleted: u64,
    pub entries_moved: u64,
    pub groups_added: u64,
    pub groups_updated: u64,
    pub groups_deleted: u64,
    pub groups_moved: u64,
    /// Entries whose history was pruned by a propagated history-snapshot
    /// deletion (`keys.history_tombstones.v1`). Typically the live entry is
    /// `InSync`, so this is the only non-zero count for a history scrub.
    pub history_pruned: u64,
}

impl From<eng::MergeStats> for MergeStats {
    fn from(s: eng::MergeStats) -> Self {
        Self {
            entries_added: s.entries_added as u64,
            entries_updated: s.entries_updated as u64,
            entries_deleted: s.entries_deleted as u64,
            entries_moved: s.entries_moved as u64,
            groups_added: s.groups_added as u64,
            groups_updated: s.groups_updated as u64,
            groups_deleted: s.groups_deleted as u64,
            groups_moved: s.groups_moved as u64,
            history_pruned: s.history_pruned as u64,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// ConflictPayload — peek-only mirror of [`keys_engine::ConflictPayload`]
// ────────────────────────────────────────────────────────────────────────

/// Wire-friendly mirror of [`keys_engine::ConflictPayload`].
///
/// Produced by [`crate::Engine::pending_conflict`] as a peek-only
/// snapshot of the stash. The frontend renders the resolver UI from
/// these records, then calls [`crate::Engine::apply_conflict_resolution`]
/// with the matching `id` and a caller-built
/// [`crate::ResolutionFfi`] to land the merge.
///
/// `entry_conflicts` and `delete_edit_conflicts` reuse the slice-7.5
/// [`crate::EntryConflictFfi`] / [`crate::DeleteEditConflictFfi`]
/// shapes — same field deltas, same parent-group resolution
/// (local-side wins on disagreement; either side fills in if the
/// other can't find the entry).
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct ConflictPayloadFfi {
    /// Synthetic id — echo back to
    /// [`crate::Engine::apply_conflict_resolution`].
    pub id: i64,
    /// Per-entry field / attachment / icon conflicts.
    pub entry_conflicts: Vec<crate::merge::EntryConflictFfi>,
    /// Per-entry delete-vs-edit conflicts.
    pub delete_edit_conflicts: Vec<crate::merge::DeleteEditConflictFfi>,
}

/// Read-only facts about the encrypted database envelope and the
/// content-addressed attachment pool, packaged for the frontend's
/// "database properties" Info-tab. Mirror of
/// [`keys_engine::DatabaseMetadata`].
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EngineDatabaseMetadata {
    /// Generator string written into the KDBX `Meta` block — e.g.
    /// `"Keys"`, `"KeePassXC"`. Empty if never set.
    pub generator: String,
    /// Display label for the outer cipher — `"AES-256-CBC"`,
    /// `"ChaCha20"`, `"Twofish-CBC"`, or `"Unknown"`.
    pub cipher_display: String,
    /// Single-line KDF display — e.g.
    /// `"Argon2id (64 MB · 2 iter · 4 threads)"`,
    /// `"AES-KDF (6,000,000 rounds)"`, or `"Unknown KDF"`.
    pub kdf_display: String,
    /// Distinct attachment blobs in the content-addressed pool.
    pub attachment_total_count: u32,
    /// Sum of attachment-blob sizes, in bytes.
    pub attachment_total_bytes: u64,
}

impl From<eng::DatabaseMetadata> for EngineDatabaseMetadata {
    fn from(m: eng::DatabaseMetadata) -> Self {
        Self {
            generator: m.generator,
            cipher_display: m.cipher_display,
            kdf_display: m.kdf_display,
            attachment_total_count: m.attachment_total_count,
            attachment_total_bytes: m.attachment_total_bytes,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────

/// Parse a canonical lowercase UUID string. Errors map to
/// [`EngineError::NotFound`] with `entity` set to the supplied label —
/// "the caller's view of this is that the thing they named doesn't
/// exist", which is the same surface for "UUID malformed" and "UUID
/// well-formed but no row".
pub(crate) fn parse_uuid(s: &str, entity: &'static str) -> Result<Uuid, EngineError> {
    Uuid::parse_str(s).map_err(|_| EngineError::NotFound {
        entity: entity.to_owned(),
    })
}
