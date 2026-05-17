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

use secrecy::SecretString;
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
    /// Notes field (plain text).
    ///
    /// Carried on the summary so the entry-list UI can run client-side
    /// "notes-only" search-scope narrowing without re-fetching each row
    /// via [`crate::Engine::entry`]. Full entry detail still goes
    /// through `Engine::entry`.
    pub notes: String,
    /// Created-at timestamp, ms since Unix epoch (UTC). On the summary
    /// to power "sort by creation date" + date-section headers in the
    /// entry list.
    pub created_at: i64,
    /// Last-modified time, ms since Unix epoch (UTC).
    pub modified_at: i64,
    /// Last-accessed timestamp, ms since Unix epoch (UTC). On the
    /// summary to power "sort by last access" + Recently-Used sections
    /// in the entry list.
    pub accessed_at: i64,
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
    /// Parsed host of `url` at the time of the snapshot. Empty when
    /// the URL was empty or unparseable.
    pub url_host: String,
    /// Notes (plain text) at the time of this snapshot.
    pub notes: String,
    /// Icon reference at the time of this snapshot.
    pub icon: IconRef,
    /// Created-at timestamp from the snapshot. Mirrors the entry's
    /// own creation time; preserved per-snapshot for completeness.
    pub created_at: i64,
    /// Modified-at timestamp of the snapshot.
    pub modified_at: i64,
    /// Last-accessed timestamp at the time of the snapshot.
    pub accessed_at: i64,
    /// Last-used proxy (mirrors `accessed_at` when non-zero); `None`
    /// when the snapshot had never been used.
    pub last_used_at: Option<i64>,
    /// Expiry timestamp at snapshot time; `None` when not set.
    pub expires_at: Option<i64>,
    /// Password strength bucket at snapshot time; `None` if it
    /// wasn't recorded (older JSON or empty password).
    pub password_strength_bucket: Option<StrengthBucket>,
    /// Password entropy bits at snapshot time; `None` when missing.
    pub password_entropy: Option<f64>,
    /// Custom-field metadata at snapshot time. Values fetched via
    /// [`crate::Engine::reveal_history_field`]. Sorted by `name`.
    pub custom_fields: Vec<CustomFieldRef>,
    /// Tags applied at snapshot time.
    pub tags: Vec<String>,
    /// Attachment metadata at snapshot time. Bytes fetched via
    /// [`crate::Engine::attachment_bytes`] — note: snapshot
    /// attachments share the same content-addressed pool as the
    /// live entry, so the most recent versions are what come back.
    pub attachments: Vec<AttachmentRef>,
}

/// A persisted smart-folder row from the `smart_folder` table.
///
/// Smart folders pair a human-readable [`name`](Self::name) with a
/// [`Predicate`](crate::predicate::Predicate) tree that describes which
/// entries the folder should match. The
/// [`evaluable`](Self::evaluable) flag is precomputed at write time
/// from
/// [`Predicate::is_evaluable`](crate::predicate::Predicate::is_evaluable)
/// so the sidebar UI doesn't have to walk the tree to know whether
/// running the folder is going to succeed. `version` is the rule-4
/// emergency escape hatch from the predicate-versioning rules;
/// defaults to `1` for every folder this binary writes.
///
/// Timestamps are `i64` milliseconds since the Unix epoch (UTC), per
/// the schema doc's "timestamp convention" section.
#[derive(Debug, Clone, PartialEq)]
pub struct SmartFolder {
    /// Row id assigned by `SQLite` on insert.
    pub id: i64,
    /// Display name as the user authored it.
    pub name: String,
    /// Decoded predicate tree.
    pub predicate: crate::predicate::Predicate,
    /// Predicate document version — matches the `version` column on
    /// the row. New folders are version `1`; rule-4 future
    /// restructures bump this.
    pub version: u32,
    /// Whether this binary can evaluate the folder. Mirrors
    /// `predicate.is_evaluable()` at write time; persisted to avoid
    /// re-walking the tree at list time. A `false` value here
    /// implies the predicate contains at least one
    /// [`Predicate::Unknown`](crate::predicate::Predicate::Unknown)
    /// node.
    pub evaluable: bool,
    /// Creation timestamp, ms since Unix epoch.
    pub created_at: i64,
    /// Last-modified timestamp, ms since Unix epoch.
    pub modified_at: i64,
}

/// Initial value of a single custom field on a freshly-created entry.
///
/// Mirrors the keepass-core `CustomField` shape but takes a
/// [`SecretString`] for the value when `protected = true`. Non-protected
/// custom fields carry a plain `String` to keep call sites readable —
/// the engine never wraps non-protected values, so a `SecretString` for
/// them would be misleading ceremony.
#[derive(Debug)]
pub struct NewCustomField {
    /// Field name as it will appear in KDBX.
    pub name: String,
    /// Plaintext value. For `protected = true` this lands AES-GCM-sealed
    /// in `entry_protected`; for `protected = false` it lands as-is in
    /// `entry_custom_field`.
    pub value: SecretString,
    /// `true` → `entry_protected`; `false` → `entry_custom_field`.
    pub protected: bool,
}

/// Field values for [`crate::Engine::create_entry`].
///
/// All fields are mandatory because the engine refuses to invent
/// defaults silently. Pass empty strings for empty slots. The canonical
/// `Password` slot lives in `password`; protected custom fields go in
/// `custom_fields` with `protected = true`.
#[derive(Debug)]
pub struct NewEntryFields {
    /// Entry title.
    pub title: String,
    /// Username field.
    pub username: String,
    /// URL field (raw, as the user enters it).
    pub url: String,
    /// Notes field (plaintext).
    pub notes: String,
    /// Canonical Password slot. Stored AES-GCM-sealed in
    /// `entry_protected` under `field_name = "Password"`.
    pub password: SecretString,
    /// Icon reference.
    pub icon: IconRef,
    /// Custom fields. Protected entries land in `entry_protected`;
    /// non-protected in `entry_custom_field`.
    pub custom_fields: Vec<NewCustomField>,
    /// Tags. Deduplicated and trimmed by the engine before insert.
    pub tags: Vec<String>,
}

/// Patch shape for [`crate::Engine::update_entry`].
///
/// Every field is `Option<T>`. `None` means "leave alone"; `Some(value)`
/// means "set to this value". Clearing a string field to empty is
/// expressed as `Some(String::new())`. A richer
/// `Patch<T> { Keep, Set(T), Clear }` enum is not warranted today — none
/// of the entry columns distinguish "empty" from "absent".
#[derive(Debug, Default)]
pub struct EntryUpdate {
    /// New title.
    pub title: Option<String>,
    /// New username.
    pub username: Option<String>,
    /// New URL. Triggers `url_host` recomputation.
    pub url: Option<String>,
    /// New notes.
    pub notes: Option<String>,
    /// New password. Triggers strength / entropy / fingerprint
    /// recomputation and re-wrapping of the canonical Password slot.
    pub password: Option<SecretString>,
    /// New icon.
    pub icon: Option<IconRef>,
    /// New expiry. `Some(None)` clears expiry; `Some(Some(ms))` sets;
    /// `None` leaves alone.
    pub expires_at: Option<Option<i64>>,
}

/// Field values for [`crate::Engine::create_group`].
#[derive(Debug)]
pub struct NewGroupFields {
    /// Display name.
    pub name: String,
    /// Notes.
    pub notes: String,
    /// Icon reference.
    pub icon: IconRef,
}

/// Patch shape for [`crate::Engine::update_group`].
#[derive(Debug, Default)]
pub struct GroupUpdate {
    /// New display name.
    pub name: Option<String>,
    /// New notes.
    pub notes: Option<String>,
    /// New icon.
    pub icon: Option<IconRef>,
    /// New expiry. `Some(None)` clears; `Some(Some(ms))` sets.
    pub expires_at: Option<Option<i64>>,
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
