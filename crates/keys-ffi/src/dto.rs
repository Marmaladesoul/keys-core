//! FFI-safe data-transfer objects for the read surface.
//!
//! Mirrors [`keepass_core::model`] types onto uniffi `Record`s. Conversions
//! live alongside their record so the read-method bodies in [`crate::vault`]
//! stay focused on tree-walking and locking.
//!
//! ## Slice 3 invariants enforced here
//!
//! - **No protected-field plaintext crosses the boundary.** Conversions
//!   mark every protected field as `revealed: false` with `value: None`.
//!   Slice 4 will add the per-field reveal call; until then a `Some(...)`
//!   on `ProtectedField.value` from a read path is a bug.
//! - **UUIDs are hyphenated lowercase** at the boundary in every direction.
//!   `uuid::Uuid::Display` already does this; we just call `to_string()`.

use chrono::{DateTime, Utc};
use keepass_core::model::{
    CustomField as KcCustomField, Entry as KcEntry, Group as KcGroup, GroupId,
};

/// KDBX canonical key for the always-protected password field.
pub(crate) const PASSWORD_FIELD_NAME: &str = "Password";

/// Lightweight projection of an [`Entry`] for list views — title +
/// identifying metadata, no notes, no custom fields, no protected values.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntrySummary {
    pub uuid: String,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub last_modified_ms: i64,
    pub group_uuid: String,
}

impl EntrySummary {
    pub(crate) fn from_entry(entry: &KcEntry, group_uuid: GroupId) -> Self {
        Self {
            uuid: entry.id.0.to_string(),
            title: entry.title.clone(),
            username: opt_string(&entry.username),
            url: opt_string(&entry.url),
            tags: entry.tags.clone(),
            last_modified_ms: ts_ms(entry.times.last_modification_time),
            group_uuid: group_uuid.0.to_string(),
        }
    }
}

/// Full entry record returned by `get_entry`. Protected fields appear with
/// `value: None` — slice 4 adds the per-field reveal API.
///
/// `get_entry` returns recycled entries verbatim; filtering recycle-bin
/// entries from the UI is the frontend's concern (call
/// `list_entries(Some(recycle_bin_uuid))` to enumerate them).
///
/// ## Editor-field surface
///
/// `icon_id`, `custom_icon_uuid`, `foreground_color`, `background_color`,
/// `override_url`, `expires`, and `expiry_time_ms` round-trip the
/// equivalent KDBX `<IconID>` / `<CustomIconUUID>` / `<ForegroundColor>` /
/// `<BackgroundColor>` / `<OverrideURL>` / `<Expires>` / `<ExpiryTime>`
/// XML elements. Empty strings on the colour / override fields mean
/// "client default" — KDBX's own absence representation. `expiry_time_ms`
/// is `None` when the source XML had no `<ExpiryTime>` element; it's
/// only meaningful when `expires` is `true` (KDBX may carry a stale
/// timestamp on `expires == false` entries from third-party writers).
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct Entry {
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub group_uuid: String,
    pub custom_fields: Vec<CustomField>,
    pub protected_fields: Vec<ProtectedField>,
    pub created_ms: i64,
    pub last_modified_ms: i64,
    pub last_access_ms: i64,
    /// Index into `KeePass`'s built-in icon set (0–68). Defaults to `0`
    /// for missing `<IconID>`. Overridden by `custom_icon_uuid` when both
    /// are set; both still round-trip so by-id renderers don't lose the
    /// user's pick.
    pub icon_id: u32,
    /// Hyphenated lowercase UUID into the vault's custom-icon pool, or
    /// `None` for a built-in icon. Bytes available via [`crate::Vault::custom_icon`].
    pub custom_icon_uuid: Option<String>,
    /// `<ForegroundColor>` — `"#RRGGBB"` hex; empty string means default.
    pub foreground_color: String,
    /// `<BackgroundColor>` — `"#RRGGBB"` hex; empty string means default.
    pub background_color: String,
    /// `<OverrideURL>` — per-entry URL-scheme override; empty string
    /// means use the client default.
    pub override_url: String,
    /// `<Expires>` — whether the entry has an expiration at all.
    pub expires: bool,
    /// `<ExpiryTime>` as Unix-epoch milliseconds. `None` when no
    /// `<ExpiryTime>` element was present. Only meaningful when
    /// [`Self::expires`] is `true`.
    pub expiry_time_ms: Option<i64>,
}

impl Entry {
    pub(crate) fn from_entry(entry: &KcEntry, group_uuid: GroupId) -> Self {
        let mut custom_fields = Vec::new();
        let mut protected_fields = vec![ProtectedField {
            name: PASSWORD_FIELD_NAME.to_owned(),
            revealed: false,
            value: None,
        }];

        for field in &entry.custom_fields {
            if field.protected {
                protected_fields.push(ProtectedField::from_protected(field));
            } else {
                custom_fields.push(CustomField::from(field.clone()));
            }
        }

        Self {
            uuid: entry.id.0.to_string(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            tags: entry.tags.clone(),
            group_uuid: group_uuid.0.to_string(),
            custom_fields,
            protected_fields,
            created_ms: ts_ms(entry.times.creation_time),
            last_modified_ms: ts_ms(entry.times.last_modification_time),
            last_access_ms: ts_ms(entry.times.last_access_time),
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

/// A non-protected custom field. KDBX deduplicates by `name` per entry,
/// so the binding side can map this to `[String: String]` losslessly.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct CustomField {
    pub name: String,
    pub value: String,
}

impl CustomField {
    /// Construct a `CustomField` from name + value. Required because
    /// `#[non_exhaustive]` blocks struct-literal construction outside
    /// the crate (Swift bindings synthesise their own init).
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl From<KcCustomField> for CustomField {
    fn from(field: KcCustomField) -> Self {
        Self {
            name: field.key,
            value: field.value,
        }
    }
}

/// A protected custom field or the always-protected `Password`. From
/// [`get_entry`](crate::Vault::get_entry) `revealed` is always `false` and
/// `value` is always `None` — slice 4 adds the reveal API. The fields are
/// kept on this record so the binding contract doesn't break when the
/// reveal path lands.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct ProtectedField {
    pub name: String,
    pub revealed: bool,
    pub value: Option<String>,
}

impl ProtectedField {
    fn from_protected(field: &KcCustomField) -> Self {
        debug_assert!(field.protected, "ProtectedField from non-protected field");
        Self {
            name: field.key.clone(),
            revealed: false,
            value: None,
        }
    }
}

/// A node in the vault's group tree, flattened for FFI consumption.
/// `parent_uuid == None` marks the root. Reconstruct the tree by joining
/// on `parent_uuid` / `child_group_uuids`.
///
/// `icon_id` and `custom_icon_uuid` round-trip the same way as on
/// [`Entry`] — see that record's editor-field doc for the same caveats.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct Group {
    pub uuid: String,
    pub name: String,
    pub parent_uuid: Option<String>,
    pub child_group_uuids: Vec<String>,
    pub entry_uuids: Vec<String>,
    pub icon_id: u32,
    pub custom_icon_uuid: Option<String>,
}

impl Group {
    pub(crate) fn from_group(group: &KcGroup, parent: Option<GroupId>) -> Self {
        Self {
            uuid: group.id.0.to_string(),
            name: group.name.clone(),
            parent_uuid: parent.map(|p| p.0.to_string()),
            child_group_uuids: group.groups.iter().map(|g| g.id.0.to_string()).collect(),
            entry_uuids: group.entries.iter().map(|e| e.id.0.to_string()).collect(),
            icon_id: group.icon_id,
            custom_icon_uuid: group.custom_icon_uuid.map(|u| u.to_string()),
        }
    }
}

/// Staging type for [`crate::Vault::create_entry`]. Carries every
/// field the frontend can set at creation time **except protected
/// fields** — those go through `set_protected_field` after the entry
/// is created. Two FFI calls but no protected plaintext crosses the
/// boundary in a DTO that didn't strictly need it.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryCreate {
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub group_uuid: String,
    /// Only unprotected fields by design. Seed protected fields
    /// (Password, OTP, custom protected) via `set_protected_field`
    /// after `create_entry` returns.
    pub custom_fields: Vec<CustomField>,
}

impl EntryCreate {
    /// Minimal constructor: title + parent group, everything else
    /// empty / default. Required because `#[non_exhaustive]` blocks
    /// struct-literal construction outside the crate.
    #[must_use]
    pub fn new(title: impl Into<String>, group_uuid: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            username: String::new(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            group_uuid: group_uuid.into(),
            custom_fields: Vec::new(),
        }
    }
}

/// Sparse patch for [`crate::Vault::update_entry`].
///
/// `None` on a field means "leave alone". `Some(value)` means "replace".
/// `Some(vec![])` on `tags` or `custom_fields` clears that list — same
/// whole-list-replacement semantics, no separate "clear flag".
///
/// Protected fields are deliberately absent: they're updated via
/// `set_protected_field` / `clear_protected_field`. An unprotected-list
/// replacement of `custom_fields` never touches the entry's protected
/// fields.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryPatch {
    pub title: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<Vec<CustomField>>,
}

impl EntryPatch {
    /// All-`None` patch — a no-op when passed to `update_entry`.
    /// Required because `#[non_exhaustive]` blocks struct-literal
    /// construction outside the crate; callers mutate the fields they
    /// care about after constructing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            title: None,
            username: None,
            url: None,
            notes: None,
            tags: None,
            custom_fields: None,
        }
    }
}

/// Sparse patch for [`crate::Vault::update_group`].
///
/// Same `Option<T>` semantics as [`EntryPatch`] — `None` leaves the
/// field alone; `Some(value)` replaces it. Only the fields the macOS
/// surface uses today; richer setters (icon, expanded, auto-type)
/// land in a follow-up if a frontend needs them.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct GroupPatch {
    pub name: Option<String>,
    pub notes: Option<String>,
}

impl GroupPatch {
    /// All-`None` patch — a no-op when passed to `update_group`.
    /// Required because `#[non_exhaustive]` blocks struct-literal
    /// construction outside the crate.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            name: None,
            notes: None,
        }
    }
}

/// One attachment on an entry, projected for list views — name +
/// payload metadata, no bytes. Bytes-getter is
/// [`crate::Vault::entry_attachment_bytes`].
///
/// `sha256_hex` is computed over the fully-decoded payload (post-
/// decompression on KDBX3, post-decrypt on KDBX4). Identical payloads
/// across attachments produce identical hashes — KDBX deduplicates
/// payload storage but not the per-entry references; this lets a
/// frontend de-duplicate display itself if it wants.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryAttachment {
    /// User-visible filename, from the entry's `<Binary><Key>` element.
    pub name: String,
    /// Decoded payload size in bytes.
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 of the decoded payload bytes.
    pub sha256_hex: String,
}

/// A single entry-history snapshot — the no-plaintext summary
/// returned from `entry_history`.
///
/// `protected_field_names` carries the **names** of every protected
/// field present on this snapshot ("Password" plus any protected
/// custom-field keys). Plaintext values stay inside the vault until
/// the snapshot is restored via `restore_entry_from_history` and then
/// revealed via `reveal_field`.
///
/// **Ordering.** `entry_history` returns records in keepass-core's
/// on-disk order, oldest first. Frontends rendering "newest first"
/// reverse the list themselves.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct HistoryRecord {
    pub modified_ms: i64,
    pub title: String,
    pub username: String,
    pub protected_field_names: Vec<String>,
}

impl HistoryRecord {
    pub(crate) fn from_entry(snapshot: &KcEntry) -> Self {
        let mut names = vec![PASSWORD_FIELD_NAME.to_owned()];
        names.extend(
            snapshot
                .custom_fields
                .iter()
                .filter(|c| c.protected)
                .map(|c| c.key.clone()),
        );
        Self {
            modified_ms: ts_ms(snapshot.times.last_modification_time),
            title: snapshot.title.clone(),
            username: snapshot.username.clone(),
            protected_field_names: names,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Empty strings on `keepass-core` entries (`username`, `url`) become
/// `None` in [`EntrySummary`] so list views can render "no value" without
/// substring-checking. The full [`Entry`] record keeps the empty strings
/// verbatim — round-tripping the field's existence matters at the
/// detail-view level.
fn opt_string(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

fn ts_ms(t: Option<DateTime<Utc>>) -> i64 {
    t.map_or(0, |dt| dt.timestamp_millis())
}
