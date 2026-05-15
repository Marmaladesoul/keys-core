//! Public-surface data types returned by the query API.
//!
//! These shapes are what frontends — directly or via `keys-ffi` — receive
//! when listing entries, fetching a single entry, walking the group tree,
//! or evaluating smart folders. They are deliberately lightweight: the
//! "summary" shape holds only what the entry list / sidebar / `AutoFill`
//! suggestion UI needs; the "full" shape adds the rest of the entry row
//! for the detail pane. Protected field values are not modelled here —
//! callers reveal them on demand via [`crate::Engine::reveal_password`],
//! [`crate::Engine::reveal_custom_field`], and
//! [`crate::Engine::reveal_history_field`].
//!
//! All timestamps are `i64` milliseconds since the Unix epoch (UTC), per
//! the schema doc's "timestamp convention" section.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Page window for paginated listing methods.
///
/// `offset` rows are skipped; up to `limit` rows are returned. Use
/// [`Pagination::all`] when the caller really does want every row
/// (e.g. small group listings, smart folder evaluation for badge
/// counts where the caller wants the IDs too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    /// Number of rows to skip before the first returned row.
    pub offset: u64,
    /// Maximum number of rows to return.
    pub limit: u64,
}

impl Pagination {
    /// A page that returns every available row.
    ///
    /// `offset = 0`, `limit = u64::MAX`. Cheap to construct; the SQL
    /// layer maps these onto `LIMIT -1 OFFSET 0` (`SQLite` convention
    /// for "no limit") when it sees `u64::MAX`.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            offset: 0,
            limit: u64::MAX,
        }
    }
}

/// Password strength bucket, derived from a Zxcvbn-style entropy estimate.
///
/// Ordering of variants is from weakest to strongest. The
/// `password_strength_bucket` column on `entry` stores the
/// `repr(u8)` discriminant.
///
/// No upstream Rust source exists for the bucket names today; Swift's
/// `PasswordStrength` enum uses the same five-bucket split with these
/// names, so the migration preserves them verbatim.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrengthBucket {
    /// Trivially guessable.
    VeryWeak = 0,
    /// Guessable with limited effort.
    Weak = 1,
    /// Resistant to casual guessing; weak vs. an online attacker with rate-limit bypass.
    Reasonable = 2,
    /// Resistant to most online attacks; weak vs. a determined offline attacker.
    Strong = 3,
    /// Resistant to offline attacks with current hardware.
    VeryStrong = 4,
}

/// Reference to an entry / group icon.
///
/// KDBX stores icons either as a built-in index (0–68) into `KeePass`'s
/// stock icon set or as a custom-icon UUID that resolves to a PNG blob
/// in the database's icon pool. The engine surfaces both as
/// [`IconRef`]; the frontend chooses how to render. Custom icon blob
/// retrieval is a separate Phase 3+ task (`Engine::custom_icon_bytes`,
/// not in this stubs PR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IconRef {
    /// Index into `KeePass`'s built-in icon set. `0` is the default.
    Builtin(u32),
    /// Custom icon UUID; resolves to a PNG blob in the icon pool.
    Custom(Uuid),
}

/// Reference to an entry's custom field — name and protected flag only.
///
/// The actual value is fetched via
/// [`crate::Engine::reveal_custom_field`] when the user requests it.
/// Non-protected custom fields are still served via reveal for
/// surface uniformity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomFieldRef {
    /// Field name as it appears in the entry.
    pub name: String,
    /// Whether the value is `<Protected>true</Protected>` in KDBX.
    pub is_protected: bool,
}

/// Reference to an entry attachment — name and size only.
///
/// Bytes are fetched on demand via
/// [`crate::Engine::attachment_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// Attachment filename as recorded in KDBX.
    pub name: String,
    /// Size in bytes of the stored blob.
    pub size: u64,
}

/// Lightweight entry row for listing UIs (entry list, sidebar counts,
/// `AutoFill` suggestions).
///
/// Carries everything the entry list, sidebar, or `AutoFill` suggestion
/// row needs to render without revealing protected fields. The detail
/// pane fetches the rest via [`crate::Engine::entry`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntrySummary {
    /// Entry UUID (KDBX canonical lowercase form when stringified).
    pub uuid: Uuid,
    /// Parent group UUID.
    pub group_uuid: Uuid,
    /// Entry title.
    pub title: String,
    /// Username field.
    pub username: String,
    /// URL field (raw, as the user entered it).
    pub url: String,
    /// Parsed host of `url` — populated by ingest for `AutoFill` lookup.
    pub url_host: String,
    /// Last-modified time, ms since Unix epoch (UTC).
    pub modified_at: i64,
    /// Last-used time, ms since Unix epoch (UTC); `None` until first use.
    pub last_used_at: Option<i64>,
    /// Password strength bucket; `None` if not yet computed.
    pub password_strength_bucket: Option<StrengthBucket>,
    /// Password entropy in bits; `None` if not yet computed.
    ///
    /// `f64` (not `f32`) because the entropy estimator works with
    /// fractional bits to many decimal places and `f32` precision
    /// would visibly bucket-edge-flip entries near the thresholds.
    pub password_entropy: Option<f64>,
    /// Number of attachments on this entry.
    pub attachment_count: u32,
    /// Icon reference.
    pub icon: IconRef,
}

/// Full entry row for the detail pane.
///
/// Superset of [`EntrySummary`]. Protected field values are still not
/// included — call [`crate::Engine::reveal_password`] et al.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryFull {
    /// Entry UUID.
    pub uuid: Uuid,
    /// Parent group UUID.
    pub group_uuid: Uuid,
    /// Entry title.
    pub title: String,
    /// Username field.
    pub username: String,
    /// URL field.
    pub url: String,
    /// Parsed host of `url`.
    pub url_host: String,
    /// Notes field (plain text).
    pub notes: String,
    /// Created-at timestamp, ms since Unix epoch.
    pub created_at: i64,
    /// Last-modified timestamp, ms since Unix epoch.
    pub modified_at: i64,
    /// Last-accessed timestamp, ms since Unix epoch.
    pub accessed_at: i64,
    /// Last-used timestamp; `None` until first use.
    pub last_used_at: Option<i64>,
    /// Expiry timestamp; `None` = no expiry.
    pub expires_at: Option<i64>,
    /// `true` if the entry is in the recycle bin.
    pub is_recycled: bool,
    /// Password strength bucket; `None` if not yet computed.
    pub password_strength_bucket: Option<StrengthBucket>,
    /// Password entropy in bits; `None` if not yet computed.
    pub password_entropy: Option<f64>,
    /// Icon reference.
    pub icon: IconRef,
    /// Custom-field metadata (values fetched via reveal API).
    pub custom_fields: Vec<CustomFieldRef>,
    /// Tags applied to the entry.
    pub tags: Vec<String>,
    /// Attachment metadata (bytes fetched via
    /// [`crate::Engine::attachment_bytes`]).
    pub attachments: Vec<AttachmentRef>,
    /// Number of history snapshots available via
    /// [`crate::Engine::history`].
    pub history_count: u32,
}

/// Flat group-tree node. Tree shape is reconstructed by callers from
/// `parent_uuid` references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupNode {
    /// Group UUID.
    pub uuid: Uuid,
    /// Parent group UUID. `None` for the root group.
    pub parent_uuid: Option<Uuid>,
    /// Display name.
    pub name: String,
    /// Icon reference.
    pub icon: IconRef,
    /// Count of entries directly in this group (not recursive).
    pub entry_count_direct: u32,
    /// `true` if this is the database's recycle bin group.
    pub is_recycle_bin: bool,
}

/// One historical snapshot of an entry, as exposed by
/// [`crate::Engine::history`].
///
/// Carries the non-protected snapshot fields plus the names of any
/// custom fields that existed at that point, so callers know what to
/// pass to [`crate::Engine::reveal_history_field`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoricEntry {
    /// Index within the entry's history list. `0` is the oldest
    /// snapshot; `history_count - 1` is the most recent. Stable
    /// within a session; not guaranteed stable across ingest.
    pub history_index: u32,
    /// Title at the time of this snapshot.
    pub title: String,
    /// Username at the time of this snapshot.
    pub username: String,
    /// URL at the time of this snapshot.
    pub url: String,
    /// Modified-at timestamp of the snapshot.
    pub modified_at: i64,
    /// Names of custom fields that existed in this snapshot. Values
    /// fetched via [`crate::Engine::reveal_history_field`].
    pub custom_field_names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_all_returns_full_range() {
        let p = Pagination::all();
        assert_eq!(p.offset, 0);
        assert_eq!(p.limit, u64::MAX);
    }
}
