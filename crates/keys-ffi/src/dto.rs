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
    Binary as KcBinary, CustomField as KcCustomField, Entry as KcEntry, Group as KcGroup, GroupId,
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
    /// Every user-defined custom field on the entry, in source XML
    /// declaration order. Protected and non-protected fields share
    /// this single ordered array so frontends can render them
    /// interleaved as `KeePass` does. Distinguish per element via
    /// [`CustomField::is_protected`]; reveal protected plaintext via
    /// [`crate::Vault::reveal_field`].
    ///
    /// Excludes the always-protected `Password` slot — that's surfaced
    /// separately as [`Self::password_field`] because there's exactly
    /// one per entry and it's structurally distinct from user-defined
    /// custom fields.
    pub custom_fields: Vec<CustomField>,
    /// The always-present `Password` slot. KDBX entries have exactly
    /// one Password per entry; surfacing it as a singleton here makes
    /// that constraint explicit rather than masquerading inside a
    /// `Vec`. Reveal plaintext via [`crate::Vault::reveal_field`] with
    /// [`PASSWORD_FIELD_NAME`].
    pub password_field: ProtectedField,
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
        // Walk `entry.custom_fields` in source XML declaration order
        // and surface every element through the unified array.
        // Protected vs non-protected is per-element via
        // `CustomField::is_protected`; the Password slot is separate.
        let custom_fields: Vec<CustomField> = entry
            .custom_fields
            .iter()
            .cloned()
            .map(CustomField::from)
            .collect();

        let password_field = ProtectedField {
            name: PASSWORD_FIELD_NAME.to_owned(),
            revealed: false,
            value: None,
        };

        Self {
            uuid: entry.id.0.to_string(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            tags: entry.tags.clone(),
            group_uuid: group_uuid.0.to_string(),
            custom_fields,
            password_field,
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

/// A user-defined custom field on an entry. KDBX deduplicates by
/// `name` per entry, but the on-disk representation preserves source
/// declaration order — this DTO mirrors that. Protected fields surface
/// here too with `is_protected = true` and `value` empty; reveal
/// plaintext via [`crate::Vault::reveal_field`].
///
/// The always-present Password slot is **not** here — see
/// [`Entry::password_field`].
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct CustomField {
    pub name: String,
    /// Empty when `is_protected == true` — protected plaintext is
    /// fetched via [`crate::Vault::reveal_field`], not surfaced in
    /// the read DTO. Contains the on-disk value when the field is
    /// non-protected.
    pub value: String,
    /// `<Value Protected="True" />` on the source XML element. When
    /// true, `value` is empty by design and frontends should fetch
    /// plaintext on demand.
    pub is_protected: bool,
}

impl CustomField {
    /// Construct a non-protected `CustomField` from name + value.
    /// Required because `#[non_exhaustive]` blocks struct-literal
    /// construction outside the crate (Swift bindings synthesise
    /// their own init). Sets `is_protected = false`; see
    /// [`Self::new_protected`] for the protected variant.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            is_protected: false,
        }
    }

    /// Construct a protected `CustomField` from name only. The
    /// plaintext doesn't cross the FFI boundary at construction time;
    /// frontends fetch via [`crate::Vault::reveal_field`].
    #[must_use]
    pub fn new_protected(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: String::new(),
            is_protected: true,
        }
    }
}

impl From<KcCustomField> for CustomField {
    fn from(field: KcCustomField) -> Self {
        // Protected fields surface here too, with empty `value` —
        // plaintext is fetched on demand via `Vault::reveal_field`.
        // Non-protected fields carry their on-disk value directly.
        let value = if field.protected {
            String::new()
        } else {
            field.value
        };
        Self {
            name: field.key,
            value,
            is_protected: field.protected,
        }
    }
}

/// The always-present `Password` slot on an [`Entry`]. KDBX entries
/// have exactly one Password per entry, distinct from user-defined
/// custom fields (those surface via [`CustomField`] with
/// `is_protected = true`).
///
/// From [`get_entry`](crate::Vault::get_entry) `revealed` is always
/// `false` and `value` is always `None` — slice 4 adds the reveal
/// API. The fields are kept on this record so the binding contract
/// doesn't break when the reveal path lands.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct ProtectedField {
    pub name: String,
    pub revealed: bool,
    pub value: Option<String>,
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
/// Protected fields are deliberately absent from this patch surface:
/// they're updated via `set_protected_field` / `clear_protected_field`.
/// `custom_fields` here only carries the **unprotected** subset — entries
/// with `is_protected = true` in the supplied list are silently dropped
/// during apply (the read DTO surfaces protected fields too, but this
/// write surface ignores them). An unprotected-list replacement never
/// touches the entry's protected fields.
///
/// ## Editor-field surface (slice 4A)
///
/// `icon_id`, `custom_icon_uuid`, `foreground_color`, `background_color`,
/// `override_url`, `expires`, `expiry_time_ms`, and `auto_type` round-trip
/// the equivalent KDBX entry-level XML elements. All carry single-`Option`
/// "set or leave alone" semantics:
///
/// - **Colour / override-URL fields** (`foreground_color`, `background_color`,
///   `override_url`) follow the read-side empty-string-as-default
///   convention. `None` leaves the field alone; `Some("")` clears the
///   per-entry value (client falls back to its default); `Some("#rrggbb")`
///   sets it explicitly.
/// - **Truly nullable fields** (`custom_icon_uuid`, `expiry_time_ms`)
///   can only be SET via this patch. To CLEAR them, call the named
///   methods [`crate::Vault::clear_entry_custom_icon`] /
///   [`crate::Vault::clear_entry_expiry`] — those are the only ways to
///   round-trip the source-XML "no element" representation through the
///   FFI boundary cleanly. The patch shape stays homogeneous (single
///   `Option<T>` everywhere) at the cost of a separate clear call per
///   nullable field, which is the rarer of the two operations.
/// - **Expiry is set-only via `expiry_time_ms`.** Setting `Some(ms)`
///   enables `expires` and stamps the deadline together (matching the
///   upstream `Entry`'s coupled-state semantics). To CLEAR expiry,
///   call [`crate::Vault::clear_entry_expiry`]; the patch shape
///   doesn't expose a `expires: Option<bool>` field because the rare
///   uncoupled states (expires=true with no time, or expires=false
///   with stale time) only arise from third-party writers and aren't
///   states the Keys app should produce.
/// - **`auto_type`** replaces the whole `<AutoType>` block in one shot.
///   Per-association edits are uncommon; whole-block replacement matches
///   how slice-2's read path consumes the value.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct EntryPatch {
    pub title: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<Vec<CustomField>>,
    /// `None` leaves alone; `Some(id)` sets the built-in icon index.
    pub icon_id: Option<u32>,
    /// `None` leaves alone; `Some(uuid)` points at a custom-icon-table
    /// entry. To clear (return to a built-in icon), call
    /// [`crate::Vault::clear_entry_custom_icon`].
    pub custom_icon_uuid: Option<String>,
    /// `None` leaves alone. `Some("")` clears the per-entry colour
    /// (client falls back to its default — matches read-side
    /// empty-string convention). `Some("#rrggbb")` sets explicitly.
    pub foreground_color: Option<String>,
    /// `None` leaves alone. `Some("")` clears the per-entry colour
    /// (client falls back to its default). `Some("#rrggbb")` sets
    /// explicitly.
    pub background_color: Option<String>,
    /// `None` leaves alone. `Some("")` clears the override (entry's
    /// `URL` opens via the client default). `Some(value)` sets a
    /// per-entry URL-scheme override.
    pub override_url: Option<String>,
    /// `None` leaves alone; `Some(ms)` sets the deadline AND enables
    /// `expires` together (the upstream `Entry::set_expiry` API
    /// couples them — there's no granular split). To CLEAR expiry,
    /// call [`crate::Vault::clear_entry_expiry`].
    pub expiry_time_ms: Option<i64>,
    /// `None` leaves alone; `Some(at)` replaces the `<AutoType>`
    /// block outright (per-association merge isn't a slice-4 goal —
    /// dogfooding can flag if it's needed).
    pub auto_type: Option<AutoType>,
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
            icon_id: None,
            custom_icon_uuid: None,
            foreground_color: None,
            background_color: None,
            override_url: None,
            expiry_time_ms: None,
            auto_type: None,
        }
    }
}

/// Sparse patch for [`crate::Vault::update_group`].
///
/// Same `Option<T>` semantics as [`EntryPatch`] — `None` leaves the
/// field alone; `Some(value)` replaces it. Group icons follow the
/// same shape as entry icons: built-in `icon_id` is non-nullable,
/// `custom_icon_uuid` is set-only via the patch with a named clear
/// method on `Vault` (`clear_group_custom_icon`) for the rare
/// clear-to-nil case. Richer setters (expanded, auto-type config)
/// land in a follow-up if a frontend needs them.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct GroupPatch {
    pub name: Option<String>,
    pub notes: Option<String>,
    /// `None` leaves alone; `Some(id)` sets the built-in icon index.
    pub icon_id: Option<u32>,
    /// `None` leaves alone; `Some(uuid)` points at a custom-icon-table
    /// entry. To clear (return to a built-in icon), call
    /// [`crate::Vault::clear_group_custom_icon`].
    pub custom_icon_uuid: Option<String>,
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
            icon_id: None,
            custom_icon_uuid: None,
        }
    }
}

/// Per-entry auto-type configuration. Mirrors `keepass-core`'s
/// [`AutoType`](keepass_core::model::AutoType) onto the FFI.
///
/// `enabled` defaults to `true` for entries with no `<AutoType>`
/// block (`KeePass`'s permissive convention; this conversion preserves
/// it so the absence of a block looks the same as an explicit
/// "enabled, defaults" block on the wire).
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct AutoType {
    pub enabled: bool,
    /// `<DataTransferObfuscation>` — delivery method. `0` is straight
    /// keystroke stream; non-zero values are KeePass-specific
    /// obfuscation strategies. Frontends that don't implement
    /// obfuscation should fall back to `0` semantics.
    pub data_transfer_obfuscation: u32,
    /// `<DefaultSequence>` — fallback macro when no association
    /// matches. Empty means "inherit from the parent group".
    pub default_sequence: String,
    /// `<Association>` — per-window override macros, in source order.
    pub associations: Vec<AutoTypeAssociation>,
}

/// One `<Association>` inside an [`AutoType`] block.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct AutoTypeAssociation {
    /// `<Window>` — glob pattern matched against the foreground
    /// window's title.
    pub window: String,
    /// `<KeystrokeSequence>` — macro to play for this window match.
    pub keystroke_sequence: String,
}

impl AutoTypeAssociation {
    /// Construct a per-window override. Required because the type
    /// is `#[non_exhaustive]` (no struct-literal construction
    /// outside the crate).
    #[must_use]
    pub fn new(window: impl Into<String>, keystroke_sequence: impl Into<String>) -> Self {
        Self {
            window: window.into(),
            keystroke_sequence: keystroke_sequence.into(),
        }
    }
}

impl Default for AutoType {
    fn default() -> Self {
        Self {
            enabled: true,
            data_transfer_obfuscation: 0,
            default_sequence: String::new(),
            associations: Vec::new(),
        }
    }
}

impl AutoType {
    /// Construct a fresh `AutoType` block — defaults: enabled, no
    /// obfuscation, no default sequence, no per-window associations.
    /// Required because the type is `#[non_exhaustive]` (no struct-
    /// literal construction outside the crate); callers mutate the
    /// fields they care about after construction.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn from_auto_type(at: &keepass_core::model::AutoType) -> Self {
        Self {
            enabled: at.enabled,
            data_transfer_obfuscation: at.data_transfer_obfuscation,
            default_sequence: at.default_sequence.clone(),
            associations: at
                .associations
                .iter()
                .map(|a| AutoTypeAssociation {
                    window: a.window.clone(),
                    keystroke_sequence: a.keystroke_sequence.clone(),
                })
                .collect(),
        }
    }

    /// Convert an FFI `AutoType` into the model's. Used by
    /// [`crate::Vault::update_entry`] when applying an `auto_type`
    /// patch field. Goes through `AutoType::new()` because the model
    /// type is `#[non_exhaustive]` (no struct-literal construction
    /// outside the crate). Consumes `self` to avoid cloning the
    /// association strings — the patch's `auto_type` value is owned
    /// and discarded after apply, so consuming is the right shape.
    pub(crate) fn into_auto_type(self) -> keepass_core::model::AutoType {
        let mut at = keepass_core::model::AutoType::new();
        at.enabled = self.enabled;
        at.data_transfer_obfuscation = self.data_transfer_obfuscation;
        at.default_sequence = self.default_sequence;
        at.associations = self
            .associations
            .into_iter()
            .map(|a| keepass_core::model::AutoTypeAssociation::new(a.window, a.keystroke_sequence))
            .collect();
        at
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

/// A single entry-history snapshot — the full read surface of an
/// historical entry version, sans plaintext for protected fields.
///
/// Plaintext for protected fields stays inside the vault until the
/// snapshot is restored via `restore_entry_from_history` and then
/// revealed via `reveal_field`. `custom_fields` surfaces protected
/// fields as elements with `is_protected = true` and `value` empty,
/// matching the convention used on [`Entry::custom_fields`].
/// `protected_field_names` is retained as a convenience for callers
/// that just want a quick name list without filtering `custom_fields`.
///
/// **Ordering.** `entry_history` returns records in keepass-core's
/// on-disk order, oldest first. Frontends rendering "newest first"
/// reverse the list themselves.
///
/// **Shape parity with [`Entry`].** This record mirrors `Entry`'s
/// fields except `uuid` (snapshots inherit the parent entry's UUID)
/// and `group_uuid` (history snapshots don't carry group context).
/// `attachments` resolves names + sizes + hashes through the vault's
/// binary pool at call time, identical to [`Entry`]'s attachment
/// projection — payload bytes are fetched via
/// [`crate::Vault::entry_attachment_bytes`] only when needed.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct HistoryRecord {
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    /// Every user-defined custom field on the snapshot, in source
    /// XML declaration order. Same shape as [`Entry::custom_fields`]:
    /// protected fields appear with `is_protected = true` and empty
    /// `value`.
    pub custom_fields: Vec<CustomField>,
    pub attachments: Vec<EntryAttachment>,
    pub created_ms: i64,
    pub modified_ms: i64,
    pub last_access_ms: i64,
    pub icon_id: u32,
    pub custom_icon_uuid: Option<String>,
    pub foreground_color: String,
    pub background_color: String,
    pub override_url: String,
    pub expires: bool,
    pub expiry_time_ms: Option<i64>,
    pub auto_type: AutoType,
    /// Names of every protected field on this snapshot — `Password`
    /// plus any protected custom-field keys. Convenience accessor;
    /// equivalent to filtering `custom_fields` for `is_protected` and
    /// prepending `Password`.
    pub protected_field_names: Vec<String>,
}

impl HistoryRecord {
    pub(crate) fn from_entry(snapshot: &KcEntry, binaries: &[KcBinary]) -> Self {
        let mut names = vec![PASSWORD_FIELD_NAME.to_owned()];
        names.extend(
            snapshot
                .custom_fields
                .iter()
                .filter(|c| c.protected)
                .map(|c| c.key.clone()),
        );

        let custom_fields: Vec<CustomField> = snapshot
            .custom_fields
            .iter()
            .cloned()
            .map(CustomField::from)
            .collect();

        // Resolve attachments through the vault's binary pool. Out-of-
        // range refs (corrupt vault) are skipped — history snapshots
        // are read-only display surface; surfacing an error here would
        // block the whole history list for an issue the user can't act
        // on. Same conservative posture as [`Entry`]'s skip-empty-name
        // filter.
        let attachments: Vec<EntryAttachment> = snapshot
            .attachments
            .iter()
            .filter_map(|att| {
                let bin = binaries.get(att.ref_id as usize)?;
                Some(EntryAttachment {
                    name: att.name.clone(),
                    size_bytes: bin.data.len() as u64,
                    sha256_hex: crate::vault::sha256_hex(&bin.data),
                })
            })
            .collect();

        Self {
            title: snapshot.title.clone(),
            username: snapshot.username.clone(),
            url: snapshot.url.clone(),
            notes: snapshot.notes.clone(),
            tags: snapshot.tags.clone(),
            custom_fields,
            attachments,
            created_ms: ts_ms(snapshot.times.creation_time),
            modified_ms: ts_ms(snapshot.times.last_modification_time),
            last_access_ms: ts_ms(snapshot.times.last_access_time),
            icon_id: snapshot.icon_id,
            custom_icon_uuid: snapshot.custom_icon_uuid.map(|u| u.to_string()),
            foreground_color: snapshot.foreground_color.clone(),
            background_color: snapshot.background_color.clone(),
            override_url: snapshot.override_url.clone(),
            expires: snapshot.times.expires,
            expiry_time_ms: snapshot.times.expiry_time.map(|t| t.timestamp_millis()),
            auto_type: AutoType::from_auto_type(&snapshot.auto_type),
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

/// Summary statistics for the vault's binary (attachment) pool.
///
/// Counts and bytes are over the *unique* binaries in the pool — every
/// `Binary` is content-hash-deduped at import time by keepass-core, so
/// two entries referencing the same payload contribute one row of
/// `count` and one copy of `total_bytes`.
#[derive(uniffi::Record, Debug, Clone)]
#[non_exhaustive]
pub struct AttachmentPoolStats {
    /// Number of distinct binaries in the pool.
    pub count: u32,
    /// Sum of `data.len()` across every pool row, in bytes.
    pub total_bytes: u64,
}
