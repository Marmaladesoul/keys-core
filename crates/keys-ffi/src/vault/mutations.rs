//! `Vault` mutation methods exposed via `UniFFI` — entry / group CRUD,
//! recycle bin, settings, custom-data, custom icons, attachments,
//! history mutations, and the save / rekey persistence ops.
//!
//! Every method runs against the unlocked `Kdbx` inside the `Mutex`,
//! commits via `Kdbx::save_to_path` (or `save_to_bytes`), and on
//! success fires a `VaultChange` via `Vault::fire` so registered
//! observers see the change.

#![allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]

use std::io::Write;

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::model::{Binary, CustomFieldValue, HistoryPolicy, NewEntry, NewGroup};
use keepass_merge::{TombstoneReason, add_history_tombstone, prune_history_with_tombstones};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::dto::{
    AttachmentPoolStats, AutoType, Entry, EntryAttachment, EntryCreate, EntryPatch, GroupPatch,
    HistoryRecord, PASSWORD_FIELD_NAME,
};
use crate::error::{VaultError, model_err_to_vault_err};
use crate::observer::VaultChange;

use super::{
    Vault, find_entry, find_group, format_kdf_params, format_with_thousands, parse_entry_id,
    parse_group_id, parse_icon_uuid, sha256_hex, timestamp_ms_to_utc, walk_entries,
};

#[uniffi::export]
impl Vault {
    /// Sparse patch of a single protected field. Set-or-insert
    /// semantics: if no field with that name exists, one is created;
    /// otherwise the existing field's value is replaced and its
    /// `protected` flag re-asserted.
    ///
    /// Goes through [`keepass_core::kdbx::Kdbx::edit_entry`] with
    /// `HistoryPolicy::Snapshot`, so a credential change always lands
    /// in entry history and bumps `last_modified_ms`.
    ///
    /// `new_value` crosses the boundary as `String`. Same binding-side
    /// zeroing responsibility as [`Self::reveal_field`].
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if no entry matches `entry_uuid`.
    pub fn set_protected_field(
        &self,
        entry_uuid: String,
        field_name: String,
        new_value: String,
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let secret = SecretString::from(new_value);

        let result = kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            if field_name == PASSWORD_FIELD_NAME {
                editor.set_password(secret);
            } else {
                editor.set_custom_field(field_name, CustomFieldValue::Protected(secret));
            }
        });
        drop(guard);
        result.map_err(model_err_to_vault_err)?;
        self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
        Ok(())
    }

    /// Remove a protected field from the entry.
    ///
    /// Distinct from `set_protected_field(_, _, "")` for protected
    /// custom fields — clearing removes the field's `<String>` element
    /// entirely.
    ///
    /// **`Password` is structural in KDBX** — there is no on-disk
    /// representation for "absent password". Clearing the password
    /// slot is therefore equivalent to setting it to the empty string;
    /// frontends and the disk format treat the two identically.
    ///
    /// Passing the key of an unprotected custom field yields
    /// [`VaultError::FieldNotFound`] — this method is the
    /// protected-field-clear path; unprotected fields go through the
    /// (slice-5) entry-mutation API.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if no entry matches `entry_uuid`.
    /// [`VaultError::FieldNotFound`] if no protected field by
    /// `field_name` exists on the entry (Password excepted — it is
    /// always clearable per the doc above).
    pub fn clear_protected_field(
        &self,
        entry_uuid: String,
        field_name: String,
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;

        // Pre-check the protected-only invariant before taking the
        // mutable borrow for `edit_entry`. The read borrow is dropped
        // before the mutation, so the borrow-checker is happy.
        let is_password = field_name == PASSWORD_FIELD_NAME;
        if !is_password {
            let (_g, entry) = find_entry(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;
            let exists_protected = entry
                .custom_fields
                .iter()
                .any(|c| c.key == field_name && c.protected);
            if !exists_protected {
                return Err(VaultError::FieldNotFound);
            }
        }

        let result = kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            if is_password {
                editor.set_password(SecretString::from(String::new()));
            } else {
                editor.remove_custom_field(&field_name);
            }
        });
        drop(guard);
        result.map_err(model_err_to_vault_err)?;
        self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
        Ok(())
    }

    // -------------------------------------------------------------------
    // Entry CRUD (slice 5)
    // -------------------------------------------------------------------

    /// Insert a new entry under `group_uuid`. Library generates the
    /// new UUID; protected fields seeded via subsequent
    /// `set_protected_field` calls (the workflow keeps protected
    /// plaintext out of the create DTO entirely).
    ///
    /// Custom fields on the create DTO are inserted as **unprotected**
    /// — protected custom fields go through `set_protected_field` after
    /// creation. No history snapshot at creation (there's no prior
    /// state to snapshot).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `group_uuid` doesn't match a group.
    pub fn create_entry(&self, entry: EntryCreate) -> Result<String, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let parent = parse_group_id(&entry.group_uuid)?;

        let template = NewEntry::new(entry.title)
            .username(entry.username)
            .url(entry.url)
            .notes(entry.notes)
            .tags(entry.tags);
        let new_id = kdbx
            .add_entry(parent, template)
            .map_err(model_err_to_vault_err)?;

        if !entry.custom_fields.is_empty() {
            kdbx.edit_entry(new_id, HistoryPolicy::NoSnapshot, |editor| {
                // Drop protected entries from the create payload —
                // protected custom fields are seeded via
                // `set_protected_field` after create. The CustomField
                // DTO carries `is_protected` so the read path can
                // round-trip; on the write path we honour the
                // existing "Plain only" contract.
                for cf in entry.custom_fields.into_iter().filter(|c| !c.is_protected) {
                    editor.set_custom_field(cf.name, CustomFieldValue::Plain(cf.value));
                }
            })
            .map_err(model_err_to_vault_err)?;
        }

        let new_uuid = new_id.0.to_string();
        drop(guard);
        self.fire(&VaultChange::EntryModified {
            uuid: new_uuid.clone(),
        });
        Ok(new_uuid)
    }

    /// Sparse update of an existing entry's unprotected fields. `None`
    /// on a patch field leaves it alone; `Some(value)` replaces it.
    /// `tags: Some(vec![])` and `custom_fields: Some(vec![])` clear
    /// those lists wholesale — same whole-list-replacement semantics.
    ///
    /// Protected fields (`Password`, protected custom fields) are not
    /// touched by this method — they go through `set_protected_field`
    /// / `clear_protected_field`. A `custom_fields` replacement only
    /// touches the entry's *unprotected* custom fields; protected
    /// custom fields survive intact.
    ///
    /// History snapshot taken via `HistoryPolicy::Snapshot`;
    /// `last_modified_ms` advances.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match an entry.
    pub fn update_entry(&self, uuid: String, patch: EntryPatch) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;

        // If the patch replaces custom_fields, peek the current
        // unprotected keys before taking the mutable borrow — the
        // edit closure removes them and inserts the new list.
        // Protected custom fields are filtered out of the peek and
        // therefore preserved.
        let unprotected_keys_to_clear: Option<Vec<String>> = if patch.custom_fields.is_some() {
            let (_g, entry) = find_entry(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;
            Some(
                entry
                    .custom_fields
                    .iter()
                    .filter(|c| !c.protected)
                    .map(|c| c.key.clone())
                    .collect(),
            )
        } else {
            None
        };

        // Resolve the custom-icon UUID outside the edit closure so a
        // malformed patch surfaces as `VaultError::InvalidUuid` rather
        // than panicking inside the editor closure.
        let custom_icon_uuid = match patch.custom_icon_uuid.as_ref() {
            Some(s) => Some(parse_icon_uuid(s)?),
            None => None,
        };
        // Decode the expiry timestamp once for the same reason.
        let expiry_dt: Option<DateTime<Utc>> = match patch.expiry_time_ms {
            Some(ms) => Some(timestamp_ms_to_utc(ms)?),
            None => None,
        };

        kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            if let Some(t) = patch.title {
                editor.set_title(t);
            }
            if let Some(u) = patch.username {
                editor.set_username(u);
            }
            if let Some(u) = patch.url {
                editor.set_url(u);
            }
            if let Some(n) = patch.notes {
                editor.set_notes(n);
            }
            if let Some(tags) = patch.tags {
                editor.set_tags(tags);
            }
            if let (Some(new_list), Some(to_clear)) =
                (patch.custom_fields, unprotected_keys_to_clear)
            {
                for key in to_clear {
                    editor.remove_custom_field(&key);
                }
                // Drop protected entries from the patch — see
                // EntryPatch's doc comment. Protected fields are
                // updated via `set_protected_field` separately.
                for cf in new_list.into_iter().filter(|c| !c.is_protected) {
                    editor.set_custom_field(cf.name, CustomFieldValue::Plain(cf.value));
                }
            }
            // Editor-field surface (slice 4A): all single-`Option`
            // semantics — `None` = leave alone, `Some(v)` = set.
            // The colour / override-URL fields treat `Some("")` as
            // "clear to client default" per the read-side empty-
            // string convention; the entry editor's setters take a
            // `String` directly so the empty case round-trips
            // without a separate clear path.
            if let Some(id) = patch.icon_id {
                editor.set_icon_id(id);
            }
            if patch.custom_icon_uuid.is_some() {
                editor.set_custom_icon(custom_icon_uuid);
            }
            if let Some(c) = patch.foreground_color {
                editor.set_foreground_color(c);
            }
            if let Some(c) = patch.background_color {
                editor.set_background_color(c);
            }
            if let Some(u) = patch.override_url {
                editor.set_override_url(u);
            }
            // Expiry: `Some(ms)` sets the deadline AND enables the
            // expires flag together (mirrors keepass-core's
            // `set_expiry(Option<DateTime>)` API). Clearing expiry
            // is the `Vault::clear_entry_expiry` named-method path.
            if let Some(at) = expiry_dt {
                editor.set_expiry(Some(at));
            }
            if let Some(at) = patch.auto_type {
                editor.set_auto_type(at.into_auto_type());
            }
        })
        .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::EntryModified { uuid: uuid.clone() });
        Ok(())
    }

    /// Hard delete: removes the entry and records a tombstone in
    /// `<DeletedObjects>` so a later merge can distinguish "deleted
    /// here" from "never seen". Slice 6's `recycle_entry` is the
    /// soft-delete path.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match an entry.
    pub fn delete_entry(&self, uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;
        kdbx.delete_entry(target).map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::EntryDeleted { uuid });
        Ok(())
    }

    /// Stamp `last_access_ms` only — no `last_modified_ms` bump and
    /// no history snapshot. Intended for read-touch flows (AutoFill
    /// fulfilment, in-app password reveal).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match an entry.
    #[allow(clippy::doc_markdown)]
    pub fn touch_entry(&self, uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;
        kdbx.touch_entry(target).map_err(model_err_to_vault_err)
    }

    /// Clear an entry's `last_access_time`, returning the field to
    /// `None`. Intended for the Keys-app menu action that wipes a
    /// stale last-access stamp (e.g. after `AutoFill` touched an entry
    /// that shouldn't have shown up in recents).
    ///
    /// Thin wrapper over [`keepass_core::kdbx::Kdbx::clear_entry_last_access`]
    /// — the symmetric inverse of [`Self::touch_entry`], with the
    /// same no-side-effects contract: no `last_modification_time`
    /// bump, no history snapshot, no `Meta::settings_changed` stamp,
    /// no binary-pool GC, and (matching `touch_entry`) no observer
    /// event.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match an entry.
    pub fn clear_entry_last_access(&self, uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;
        kdbx.clear_entry_last_access(target)
            .map_err(model_err_to_vault_err)
    }

    /// Clear an entry's `custom_icon_uuid`, returning it to a
    /// built-in icon. The patch shape on
    /// [`crate::dto::EntryPatch::custom_icon_uuid`] is set-only
    /// (single `Option<String>`); this is the named clear path that
    /// preserves the homogeneous patch surface without nested
    /// `Option<Option<String>>` ergonomics. See `#R32` / `#I70`.
    ///
    /// Equivalent to `editor.set_custom_icon(None)` inside an
    /// `edit_entry` closure with `HistoryPolicy::Snapshot`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match an entry.
    pub fn clear_entry_custom_icon(&self, uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;
        kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            editor.set_custom_icon(None);
        })
        .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::EntryModified { uuid: uuid.clone() });
        Ok(())
    }

    /// Clear an entry's expiry **completely** — disables the
    /// `expires` flag and removes the stored deadline together. The
    /// patch shape exposes only `expiry_time_ms: Option<i64>` (set
    /// the deadline; implies enabled); this is the named clear path
    /// for the coupled-clear case so the patch surface stays
    /// homogeneous. See `#R32` / `#I70`.
    ///
    /// Equivalent to `editor.set_expiry(None)` inside an
    /// `edit_entry` closure with `HistoryPolicy::Snapshot`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match an entry.
    pub fn clear_entry_expiry(&self, uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;
        kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            editor.set_expiry(None);
        })
        .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::EntryModified { uuid: uuid.clone() });
        Ok(())
    }

    /// Move an entry to `new_group_uuid`. A move to the entry's
    /// current parent is **not** a no-op at the data level — it
    /// stamps `location_changed` and sets `previous_parent_group =
    /// Some(same)` so the user's "I moved this" intent is recorded.
    /// Frontends that want UI-level "no change" detection do it
    /// themselves before calling.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if either `uuid` or `new_group_uuid`
    /// doesn't resolve.
    pub fn move_entry(&self, uuid: String, new_group_uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;
        let new_parent = parse_group_id(&new_group_uuid)?;
        kdbx.move_entry(target, new_parent)
            .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::EntryModified { uuid });
        Ok(())
    }

    // -------------------------------------------------------------------
    // Group mutation (slice 6)
    // -------------------------------------------------------------------

    /// Insert a new group under `parent_uuid`. `None` parents the
    /// group at the root.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `parent_uuid` doesn't match a
    /// group.
    pub fn create_group(
        &self,
        name: String,
        parent_uuid: Option<String>,
    ) -> Result<String, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let parent = match parent_uuid {
            Some(s) => parse_group_id(&s)?,
            None => kdbx.vault().root.id,
        };
        let new_id = kdbx
            .add_group(parent, NewGroup::new(name))
            .map_err(model_err_to_vault_err)?;
        let new_uuid = new_id.0.to_string();
        drop(guard);
        self.fire(&VaultChange::GroupChanged {
            uuid: new_uuid.clone(),
        });
        Ok(new_uuid)
    }

    /// Sparse update of a group's metadata. `None` on a patch field
    /// leaves it alone; `Some(value)` replaces it.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match a group.
    pub fn update_group(&self, uuid: String, patch: GroupPatch) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_group_id(&uuid)?;
        // Decode the custom-icon UUID outside the edit closure so a
        // malformed patch surfaces as `VaultError::NotFound` rather
        // than panicking inside the editor closure.
        let custom_icon_uuid = match patch.custom_icon_uuid.as_ref() {
            Some(s) => Some(parse_icon_uuid(s)?),
            None => None,
        };
        kdbx.edit_group(target, |editor| {
            if let Some(n) = patch.name {
                editor.set_name(n);
            }
            if let Some(n) = patch.notes {
                editor.set_notes(n);
            }
            if let Some(id) = patch.icon_id {
                editor.set_icon_id(id);
            }
            if patch.custom_icon_uuid.is_some() {
                editor.set_custom_icon(custom_icon_uuid);
            }
        })
        .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::GroupChanged { uuid });
        Ok(())
    }

    /// Clear a group's `custom_icon_uuid`, returning it to a built-in
    /// icon. Mirrors [`Self::clear_entry_custom_icon`] for the group
    /// surface — patch shape on
    /// [`crate::dto::GroupPatch::custom_icon_uuid`] is set-only;
    /// this is the named clear path so the patch surface stays
    /// homogeneous without nested `Option<Option<String>>`
    /// ergonomics.
    ///
    /// Equivalent to `editor.set_custom_icon(None)` inside an
    /// `edit_group` closure.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match a group.
    pub fn clear_group_custom_icon(&self, uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_group_id(&uuid)?;
        kdbx.edit_group(target, |editor| {
            editor.set_custom_icon(None);
        })
        .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::GroupChanged { uuid });
        Ok(())
    }

    /// Hard delete of a group and every entry / sub-group it
    /// contains. Records `<DeletedObjects>` tombstones for the
    /// removed records so a later merge can distinguish "deleted
    /// here" from "never seen".
    ///
    /// Slice 6's `recycle_group` is the soft-delete path.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match a group, or
    /// if it identifies the root group (which can't be deleted).
    pub fn delete_group(&self, uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_group_id(&uuid)?;
        kdbx.delete_group(target).map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::GroupChanged { uuid });
        Ok(())
    }

    /// Move a group under `new_parent_uuid`. A move that would make
    /// the group a descendant of itself fails through the
    /// `CircularMove → NotFound` mapping in
    /// `model_err_to_vault_err`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if either `uuid` or `new_parent_uuid`
    /// doesn't resolve, or the move would create a cycle.
    pub fn move_group(&self, uuid: String, new_parent_uuid: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_group_id(&uuid)?;
        let new_parent = parse_group_id(&new_parent_uuid)?;
        kdbx.move_group(target, new_parent)
            .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::GroupChanged { uuid });
        Ok(())
    }

    /// Move `group_uuid` under `new_parent_uuid`, inserting at
    /// `position` among the destination's existing children.
    /// Out-of-range positions clamp to the end (matches typical drag-
    /// and-drop reorder UIs). Same-parent moves act as sibling
    /// reorders relative to the post-removal list.
    ///
    /// Thin pass-through to keepass-core's
    /// [`keepass_core::kdbx::Kdbx::move_group_to_position`]; same bookkeeping
    /// (`previous_parent_group`, `location_changed`) and error
    /// semantics (`CannotDeleteRoot`, `GroupNotFound`, `CircularMove`)
    /// as [`Self::move_group`].
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if either `group_uuid` or
    /// `new_parent_uuid` doesn't resolve, or the move would create
    /// a cycle.
    pub fn move_group_to_position(
        &self,
        group_uuid: String,
        new_parent_uuid: String,
        position: u32,
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_group_id(&group_uuid)?;
        let new_parent = parse_group_id(&new_parent_uuid)?;
        kdbx.move_group_to_position(target, new_parent, position as usize)
            .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::GroupChanged { uuid: group_uuid });
        Ok(())
    }

    // -------------------------------------------------------------------
    // Recycle bin (slice 6)
    // -------------------------------------------------------------------

    /// Soft-delete an entry into the recycle-bin group.
    ///
    /// Returns `Ok(Some(uuid))` with the recycle-bin group's UUID
    /// when the entry was moved there. Returns `Ok(None)` when the
    /// recycle bin is **disabled** at the vault meta level — the
    /// underlying `keepass-core` call falls through to a hard delete
    /// in that mode, so the resulting state matches `delete_entry`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match an entry.
    pub fn recycle_entry(&self, uuid: String) -> Result<Option<String>, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;
        let bin = kdbx.recycle_entry(target).map_err(model_err_to_vault_err)?;
        let bin_uuid = bin.map(|gid| gid.0.to_string());
        drop(guard);
        // Recycle is "gone from primary view" regardless of whether the
        // bin was enabled (disabled-bin path falls through to hard delete).
        self.fire(&VaultChange::EntryDeleted { uuid });
        Ok(bin_uuid)
    }

    /// Soft-delete a group (and its descendants) into the recycle-
    /// bin group. See [`Self::recycle_entry`] for the disabled-bin
    /// fall-through semantics.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` doesn't match a group.
    pub fn recycle_group(&self, uuid: String) -> Result<Option<String>, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_group_id(&uuid)?;
        let bin = kdbx.recycle_group(target).map_err(model_err_to_vault_err)?;
        let bin_uuid = bin.map(|gid| gid.0.to_string());
        drop(guard);
        self.fire(&VaultChange::GroupChanged { uuid });
        Ok(bin_uuid)
    }

    /// Permanently delete every entry and group inside the recycle-
    /// bin group. Returns the count of removed records.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn empty_recycle_bin(&self) -> Result<u64, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        // Capture the bin uuid (if set) before mutating, so the
        // GroupChanged event carries it. None when no recycle bin is
        // configured — emit a generic GroupChanged with an empty uuid
        // is misleading, so we skip the event in that edge case.
        let bin_uuid = kdbx.vault().meta.recycle_bin_uuid.map(|g| g.0.to_string());
        let n = kdbx.empty_recycle_bin().map_err(model_err_to_vault_err)?;
        drop(guard);
        if let Some(uuid) = bin_uuid {
            self.fire(&VaultChange::GroupChanged { uuid });
        }
        Ok(n as u64)
    }

    /// Configure the vault's recycle-bin policy. `enabled` toggles
    /// soft-delete for `recycle_entry` / `recycle_group`;
    /// `group_uuid` selects which group acts as the bin (or `None`
    /// to clear the reference).
    ///
    /// `keepass-core` preserves both pieces of state independently —
    /// passing `enabled = false` with `group_uuid = Some(...)`
    /// remembers the bin reference for when the user toggles back on.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `group_uuid` doesn't match a
    /// group.
    pub fn set_recycle_bin(
        &self,
        enabled: bool,
        group_uuid: Option<String>,
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let group = match group_uuid {
            Some(s) => {
                let id = parse_group_id(&s)?;
                if find_group(&kdbx.vault().root, id).is_none() {
                    return Err(VaultError::NotFound);
                }
                Some(id)
            }
            None => None,
        };
        kdbx.set_recycle_bin(enabled, group);
        Ok(())
    }

    // -------------------------------------------------------------------
    // Meta setters (slice 6)
    // -------------------------------------------------------------------

    /// Set the database display name (the `<DatabaseName>` element
    /// of `<Meta>`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn set_database_name(&self, name: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        kdbx.set_database_name(name);
        Ok(())
    }

    /// Set the database description (`<DatabaseDescription>`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn set_database_description(&self, description: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        kdbx.set_database_description(description);
        Ok(())
    }

    /// Set the default username for newly created entries
    /// (`<DefaultUserName>`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn set_default_username(&self, username: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        kdbx.set_default_username(username);
        Ok(())
    }

    /// Set the database accent colour (`<Color>`). Pass-through —
    /// no validation. Frontends are expected to constrain to
    /// `"#RRGGBB"` if they care; other clients may write `"#RGB"`,
    /// named colours, etc., and rejecting at the facade would break
    /// vaults written by them on the next save.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn set_color(&self, hex: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        kdbx.set_color(hex);
        Ok(())
    }

    /// Set the per-entry history-snapshot count cap
    /// (`<HistoryMaxItems>`). Negative values mean unlimited; this
    /// matches `keepass-core`'s convention and matches what other
    /// `KeePass` clients write. Truncation runs automatically on
    /// `edit_entry` and `restore_entry_from_history` per the
    /// configured policy — there's no separate `trim_entry_history`
    /// surface needed.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn set_history_max_items(&self, max: i32) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        kdbx.set_history_max_items(max);
        Ok(())
    }

    /// Set the per-entry history-snapshot byte-budget cap
    /// (`<HistoryMaxSize>`). Negative values mean unlimited.
    /// Truncation runs automatically on `edit_entry` and
    /// `restore_entry_from_history` per the configured policy.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn set_history_max_size(&self, max: i64) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        kdbx.set_history_max_size(max);
        Ok(())
    }

    // -------------------------------------------------------------------
    // Meta readers
    // -------------------------------------------------------------------

    /// Read the database display name (`<DatabaseName>`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn database_name(&self) -> Result<String, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(kdbx.vault().meta.database_name.clone())
    }

    /// Read the database description (`<DatabaseDescription>`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn database_description(&self) -> Result<String, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(kdbx.vault().meta.database_description.clone())
    }

    /// Read the default username for newly created entries
    /// (`<DefaultUserName>`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn default_username(&self) -> Result<String, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(kdbx.vault().meta.default_username.clone())
    }

    /// Read the per-entry history-snapshot count cap
    /// (`<HistoryMaxItems>`). Negative values mean unlimited.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn history_max_items(&self) -> Result<i32, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(kdbx.vault().meta.history_max_items)
    }

    /// Read the per-entry history-snapshot byte-budget cap
    /// (`<HistoryMaxSize>`). Negative values mean unlimited.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn history_max_size(&self) -> Result<i64, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(kdbx.vault().meta.history_max_size)
    }

    /// The `<Generator>` string from `Meta` — identifies the writer
    /// that produced the file (e.g. `KeePassXC`, `KeePass2`). Used by
    /// the Keys-app Info tab to show "what wrote this file".
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn generator(&self) -> Result<String, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(kdbx.vault().meta.generator.clone())
    }

    /// Display string for the outer cipher — `"AES-256-CBC"`,
    /// `"ChaCha20"`, or `"Unknown"` for a cipher UUID this build
    /// doesn't recognise.
    ///
    /// Read-only; the cipher is fixed at vault-creation time and not
    /// mutable via this surface today (keepass-core's `replace_vault`
    /// is the closest equivalent and Keys-app doesn't expose it).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn cipher_display(&self) -> Result<String, VaultError> {
        use keepass_core::format::KnownCipher;
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let label = match kdbx.outer_header().cipher_id.well_known() {
            Some(KnownCipher::Aes256Cbc) => "AES-256-CBC",
            Some(KnownCipher::ChaCha20) => "ChaCha20",
            _ => "Unknown",
        };
        Ok(label.to_owned())
    }

    /// Display string for the KDF parameters, formatted on a single
    /// line for the Keys-app Info tab. Examples:
    ///
    /// - `"Argon2id (64 MB · 2 iter · 4 threads)"`
    /// - `"Argon2d (64 MB · 1 iter · 2 threads)"`
    /// - `"AES-KDF (6,000,000 rounds)"`
    /// - `"Unknown KDF"` for unparseable or absent blobs (KDBX3 with
    ///   no parsed `VarDictionary`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn kdf_display(&self) -> Result<String, VaultError> {
        use keepass_core::format::KdfParams;
        use keepass_core::format::var_dictionary::VarDictionary;
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let header = kdbx.outer_header();

        // KDBX3 stores AES-KDF rounds + seed in their own outer-header
        // fields, not in `KdfParameters`. KDBX4 stores everything in the
        // VarDictionary blob. Cover both shapes so the row is meaningful
        // on a v3 vault too.
        if let Some(blob) = header.kdf_parameters.as_ref() {
            if let Ok(dict) = VarDictionary::parse(blob)
                && let Ok(params) = KdfParams::from_var_dictionary(&dict)
            {
                return Ok(format_kdf_params(&params));
            }
        }
        if let Some(rounds) = header.transform_rounds {
            let formatted = format_with_thousands(rounds);
            return Ok(format!("AES-KDF ({formatted} rounds)"));
        }
        Ok("Unknown KDF".to_owned())
    }

    /// Summary stats for the vault's binary pool (attachments + any
    /// embedded images). Each unique payload contributes one to
    /// `count` and one copy of its bytes to
    /// `total_bytes` — keepass-core content-deduplicates the pool at
    /// import time, so two entries referencing the same file pay for
    /// one row, not two.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn attachment_pool_stats(&self) -> Result<AttachmentPoolStats, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let pool = &kdbx.vault().binaries;
        Ok(AttachmentPoolStats {
            count: u32::try_from(pool.len()).unwrap_or(u32::MAX),
            total_bytes: pool.iter().map(|b| b.data.len() as u64).sum(),
        })
    }

    /// Read the recycle-bin group's UUID, if the vault has one
    /// configured. `Ok(None)` means no recycle bin is set; this is
    /// independent of `recycle_bin_enabled` — KDBX vaults can have a
    /// recycle bin configured-but-disabled, or enabled-but-pointing-
    /// at-no-group (in which case soft-delete creates one on first use).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn recycle_bin_group_uuid(&self) -> Result<Option<String>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(kdbx.vault().meta.recycle_bin_uuid.map(|g| g.0.to_string()))
    }

    /// Borrow the raw bytes for the custom icon identified by `uuid`,
    /// returning `Ok(None)` when no such icon is in the vault's pool.
    /// Bytes are opaque (typically PNG, but format-defined by whatever
    /// client wrote them) — callers are responsible for image decoding.
    ///
    /// Thin pass-through to keepass-core's `Vault::custom_icon`; copies
    /// the borrowed slice into an owned `Vec<u8>` for the FFI boundary.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `uuid` is not a valid UUID string.
    pub fn custom_icon_image(&self, uuid: String) -> Result<Option<Vec<u8>>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let icon_uuid = parse_icon_uuid(&uuid)?;
        Ok(kdbx.vault().custom_icon(icon_uuid).map(<[u8]>::to_vec))
    }

    /// Return the UUID of the group that directly contains `child_uuid`,
    /// or `Ok(None)` if `child_uuid` is the root or doesn't match any
    /// group. Mirrors keepass-core's `Vault::group_parent`.
    ///
    /// O(N) in the total group count — the model doesn't store parent
    /// links, so this walks the tree from the root.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `child_uuid` isn't a valid UUID.
    pub fn group_parent_uuid(&self, child_uuid: String) -> Result<Option<String>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let child = parse_group_id(&child_uuid)?;
        Ok(kdbx.vault().group_parent(child).map(|g| g.0.to_string()))
    }

    /// Every descendant of `group_uuid`, depth-first, as UUID strings.
    /// `group_uuid` itself is **not** included. Useful for validating a
    /// candidate group move (the destination must not be a descendant
    /// of the moved group) or enumerating refs across a whole subtree.
    ///
    /// Returns UUIDs only — to materialise each `Group`, follow up with
    /// [`Self::list_groups`] (or a per-UUID accessor in future). Keeps
    /// the FFI surface lean and matches `Self::list_groups`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `group_uuid` isn't a valid UUID or
    /// doesn't match a group in the vault.
    pub fn all_subgroup_uuids(&self, group_uuid: String) -> Result<Vec<String>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_group_id(&group_uuid)?;
        let group = find_group(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;
        Ok(group
            .all_subgroups()
            .into_iter()
            .map(|g| g.id.0.to_string())
            .collect())
    }

    /// Every entry across every group, depth-first from the root, as
    /// the full [`Entry`] read DTO (protected fields appear with
    /// `value: None` — reveal via [`Self::reveal_field`]). Recycled
    /// entries are included verbatim; recycle-bin filtering is the
    /// frontend's job via [`Self::recycle_bin_enabled`] +
    /// [`Self::recycle_bin_group_uuid`].
    ///
    /// Mirror of keepass-core's `Vault::all_entries`, projected
    /// through the FFI `Entry` shape so each record carries its
    /// `group_uuid`. The thin shape returned by
    /// [`Self::list_entries`] (None) is `EntrySummary`; this is the
    /// full record, suitable as a flat replacement for downstream
    /// `database.allEntries` mirrors.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn all_entries(&self) -> Result<Vec<Entry>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let mut out = Vec::new();
        walk_entries(&kdbx.vault().root, &mut |group_id, entry| {
            out.push(Entry::from_entry(entry, group_id));
        });
        Ok(out)
    }

    /// Read the meta-level recycle-bin enabled flag. Independent of
    /// [`Self::recycle_bin_group_uuid`] — KDBX vaults can have a
    /// recycle bin configured-but-disabled, or enabled-but-pointing-
    /// at-no-group (in which case soft-delete creates one on first
    /// use). Mirrors keepass-core's `Vault::recycle_bin_enabled`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn recycle_bin_enabled(&self) -> Result<bool, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(kdbx.vault().recycle_bin_enabled())
    }

    // -------------------------------------------------------------------
    // Attachments
    // -------------------------------------------------------------------

    /// List the attachments referenced by an entry. Returns name +
    /// size + SHA-256 hash for each; the bytes themselves stay in the
    /// vault until [`Self::entry_attachment_bytes`] is called.
    ///
    /// Order matches the on-disk `<Binary>` element order on the entry.
    /// References that point at a `Vault::binaries` index that no
    /// longer exists (corrupt vault) yield a [`VaultError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an entry,
    /// or if any attachment's `ref_id` is out of range for the vault's
    /// binary pool.
    pub fn entry_attachments(
        &self,
        entry_uuid: String,
    ) -> Result<Vec<EntryAttachment>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let (_, entry) = find_entry(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;
        let binaries = &kdbx.vault().binaries;
        let mut out = Vec::with_capacity(entry.attachments.len());
        for att in &entry.attachments {
            let bin = binaries
                .get(att.ref_id as usize)
                .ok_or(VaultError::NotFound)?;
            out.push(EntryAttachment {
                name: att.name.clone(),
                size_bytes: bin.data.len() as u64,
                sha256_hex: sha256_hex(&bin.data),
            });
        }
        Ok(out)
    }

    /// Fetch the decoded payload bytes of a named attachment.
    ///
    /// `name` is the user-visible filename from
    /// [`Self::entry_attachments`]. If an entry has multiple
    /// attachments with the same name (KDBX permits it; clients
    /// rarely produce it), the first match in `<Binary>` order wins.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an
    /// entry, no attachment by `name` exists on the entry, or the
    /// attachment's `ref_id` is out of range.
    pub fn entry_attachment_bytes(
        &self,
        entry_uuid: String,
        name: String,
    ) -> Result<Vec<u8>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let (_, entry) = find_entry(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;
        let att = entry
            .attachments
            .iter()
            .find(|a| a.name == name)
            .ok_or(VaultError::NotFound)?;
        let bin = kdbx
            .vault()
            .binaries
            .get(att.ref_id as usize)
            .ok_or(VaultError::NotFound)?;
        Ok(bin.data.clone())
    }

    /// Fetch the decoded payload bytes of a named attachment on a
    /// historical snapshot, without first restoring the snapshot.
    ///
    /// `history_index` is the snapshot's position in the `Vec`
    /// returned by [`Self::entry_history`] (oldest-first). `name` is
    /// the user-visible filename from the snapshot's attachment list
    /// (also surfaced on `HistoryRecord.attachments` per slice 8B).
    /// If a snapshot has multiple attachments with the same name
    /// (KDBX permits it; clients rarely produce it), the first match
    /// in `<Binary>` order wins.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an
    /// entry, no attachment by `name` exists on the snapshot, or the
    /// attachment's `ref_id` is out of range for the vault's binary
    /// pool.
    /// [`VaultError::IndexOutOfRange`] if `history_index` is
    /// beyond the snapshot list's bounds.
    pub fn entry_history_attachment_bytes(
        &self,
        entry_uuid: String,
        history_index: u32,
        name: String,
    ) -> Result<Vec<u8>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let (_, entry) = find_entry(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;
        let snapshot = entry
            .history
            .get(history_index as usize)
            .ok_or(VaultError::IndexOutOfRange)?;
        let att = snapshot
            .attachments
            .iter()
            .find(|a| a.name == name)
            .ok_or(VaultError::NotFound)?;
        let bin = kdbx
            .vault()
            .binaries
            .get(att.ref_id as usize)
            .ok_or(VaultError::NotFound)?;
        Ok(bin.data.clone())
    }

    /// Attach a binary to an entry. The vault's binary pool dedups by
    /// SHA-256: identical bytes attached to two different entries
    /// share a single pool slot. The pool entry is created (or
    /// reused) at the end of `edit_entry`; refcount-based GC drops
    /// orphans on save. The attachment is added unprotected — the
    /// upstream `Entry::attach` API takes a `protected` flag too,
    /// but slice-2 / slice-4 frontends always read attachments via
    /// `entry_attachment_bytes` which doesn't distinguish protection
    /// status, so the FFI exposes only the unprotected path. Add a
    /// `protected` parameter in a follow-up if a frontend ever needs
    /// it.
    ///
    /// Replacing an existing attachment with the same `name` is
    /// idempotent: the existing reference is replaced and the old
    /// pool entry GC'd if no other entry references it.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an entry.
    pub fn add_entry_attachment(
        &self,
        entry_uuid: String,
        name: String,
        bytes: Vec<u8>,
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            // Idempotent by name: detach any existing attachment
            // with the same name first so the FFI surface always
            // represents "this entry has at most one attachment
            // called X." The upstream `attach` API doesn't dedup
            // by name (KDBX permits duplicate names by spec), but
            // frontend semantics expect "attach replaces same-
            // named existing." Both attachments reference the same
            // pool slot via SHA-256 dedup at the pool level, so
            // the saved bytes are unchanged either way; this is
            // a per-entry name uniqueness contract.
            let _ = editor.detach(&name);
            editor.attach(name, bytes, /* protected = */ false);
        })
        .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
        Ok(())
    }

    /// Remove an entry attachment by filename. Returns `true` if a
    /// matching attachment was removed, `false` if the entry had no
    /// such attachment (which is **not** an error — UI flows that
    /// race a "delete attachment" click against another edit can
    /// surface this without forcing the host to call another method
    /// to check first).
    ///
    /// Pool GC: the binary the detached attachment pointed at stays
    /// alive if another entry still references it; otherwise it's
    /// dropped at the end of `edit_entry` by refcount.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an entry.
    pub fn remove_entry_attachment(
        &self,
        entry_uuid: String,
        name: String,
    ) -> Result<bool, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let mut removed = false;
        kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            removed = editor.detach(&name);
        })
        .map_err(model_err_to_vault_err)?;
        drop(guard);
        if removed {
            self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
        }
        Ok(removed)
    }

    // -------------------------------------------------------------------
    // Auto-type
    // -------------------------------------------------------------------

    /// Read the per-entry auto-type configuration.
    ///
    /// KDBX entries with a missing `<AutoType>` block decode to
    /// [`AutoType`]'s defaults (`enabled = true`, no obfuscation,
    /// empty default sequence, no associations) — `KeePass`'s
    /// permissive convention. This method always returns a populated
    /// record; the absence of an `<AutoType>` block in the source
    /// XML is invisible to callers.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an entry.
    pub fn entry_auto_type(&self, entry_uuid: String) -> Result<AutoType, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let (_, entry) = find_entry(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;
        Ok(AutoType::from_auto_type(&entry.auto_type))
    }

    // -------------------------------------------------------------------
    // Custom icons (slice 6)
    // -------------------------------------------------------------------

    /// Add a custom icon to the vault's icon pool. Returns the new
    /// icon's UUID for use on entries / groups via
    /// `set_custom_icon` (out-of-scope until a slice exposes the
    /// icon field on `EntryPatch` / `GroupPatch`).
    ///
    /// `data` is the raw image bytes (PNG / JPEG, decoder is the
    /// frontend's call). KDBX doesn't constrain encoding; the bytes
    /// round-trip verbatim.
    ///
    /// **Save-time GC.** `keepass-core`'s save pipeline drops icons
    /// not referenced by any entry / group. Until a future slice
    /// exposes a `set_custom_icon` setter on `EntryPatch` /
    /// `GroupPatch`, an icon added by this method is always orphan
    /// and won't survive a save+reopen. The in-memory state is
    /// authoritative until that slice lands.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn add_custom_icon(&self, data: Vec<u8>) -> Result<String, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let id = kdbx.add_custom_icon(data);
        Ok(id.to_string())
    }

    /// Remove a custom icon from the pool. Returns `true` if an
    /// icon with that UUID was removed, `false` if no such icon
    /// existed.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `icon_uuid` is not a parseable
    /// UUID string (a parseable UUID that doesn't match any icon
    /// returns `Ok(false)`).
    pub fn remove_custom_icon(&self, icon_uuid: String) -> Result<bool, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let id = Uuid::parse_str(&icon_uuid).map_err(|_| VaultError::NotFound)?;
        Ok(kdbx.remove_custom_icon(id))
    }

    /// Look up a custom icon's bytes by UUID. Returns `Ok(None)`
    /// if no icon with that UUID is in the pool (parseable-but-
    /// missing); returns [`VaultError::NotFound`] if the string
    /// isn't a valid UUID.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `icon_uuid` doesn't parse as
    /// a UUID.
    pub fn custom_icon(&self, icon_uuid: String) -> Result<Option<Vec<u8>>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let id = Uuid::parse_str(&icon_uuid).map_err(|_| VaultError::NotFound)?;
        Ok(kdbx.custom_icon(id).map(<[u8]>::to_vec))
    }

    // -------------------------------------------------------------------
    // Save + rekey (slice 7)
    //
    // `merge_external` is deferred to its own slice — `keepass-merge`
    // is currently a stub crate (14 lines of doc-comment ending in
    // "Implementation pending"). See PROGRESS.md `#R13` for the
    // escalation.
    // -------------------------------------------------------------------

    /// Persist the vault to the path it was opened from.
    ///
    /// Atomic-write loop: serialise via [`keepass_core::kdbx::Kdbx::save_to_bytes`],
    /// write to a sibling tempfile in the destination's parent directory,
    /// `fsync`, then `rename(2)` over the destination via
    /// [`tempfile::NamedTempFile::persist`]. POSIX guarantees the rename
    /// is atomic on the same filesystem; `tempfile 3.20+` extends this to
    /// Windows.
    ///
    /// **Why the atomic loop lives at the FFI facade.** `keepass-core`
    /// only exposes `save_to_bytes` — there's no `save_to_path` helper
    /// today. If keepass-core grows one, this method collapses to one
    /// call.
    ///
    /// No "save as" — frontends use [`Self::save_to_bytes`] plus their
    /// own file-write for arbitrary-path saves. That keeps file-picker
    /// UX in the binding layer where it belongs.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::Io`] if any filesystem step fails (parent dir
    /// missing, permission denied, fsync failure).
    /// [`VaultError::WrongKey`] for any crypto-class failure during
    /// re-encryption (matches the open-side collapse posture).
    pub fn save(&self) -> Result<(), VaultError> {
        let bytes = self.save_to_bytes()?;
        // Same parent directory keeps `persist` to a single rename(2).
        let parent = self
            .path
            .parent()
            .ok_or_else(|| VaultError::Io("save path has no parent directory".to_owned()))?;
        let mut tmp =
            tempfile::NamedTempFile::new_in(parent).map_err(|e| VaultError::Io(e.to_string()))?;
        tmp.write_all(&bytes)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        tmp.flush().map_err(|e| VaultError::Io(e.to_string()))?;
        tmp.as_file_mut()
            .sync_all()
            .map_err(|e| VaultError::Io(e.to_string()))?;
        tmp.persist(&self.path)
            .map_err(|e| VaultError::Io(e.error.to_string()))?;
        self.fire(&VaultChange::Saved);
        Ok(())
    }

    /// Serialise the in-memory vault to encrypted KDBX bytes without
    /// touching disk. Useful for the `AutoFill` keychain-cache snapshot
    /// flow and for tests that need round-trip verification.
    ///
    /// The output is loadable by [`Vault::new`] and produces a vault
    /// model byte-identical to the in-memory one (unknown-XML
    /// preservation included).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::WrongKey`] for any crypto-class failure during
    /// re-encryption.
    pub fn save_to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        kdbx.save_to_bytes().map_err(VaultError::from)
    }

    /// Re-derive the master key from `new_password` and rotate the
    /// vault's outer-header seeds + encryption IV. **In-memory only**
    /// — the next [`Self::save`] (or [`Self::save_to_bytes`]) writes
    /// the rekeyed envelope. Reopen with the new password works after
    /// save; reopen with the old one returns
    /// [`VaultError::WrongKey`].
    ///
    /// `new_password` is wrapped in a [`SecretString`] immediately and
    /// hashed into a [`CompositeKey`] inside this call; the boundary
    /// `String` doesn't outlive the rekey. Binding-side zeroing of the
    /// caller's copy is the frontend's responsibility — same posture as
    /// [`Self::new`].
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::WrongKey`] for any crypto-class failure (the
    /// `Kdbx::rekey` documentation calls `Error::Crypto` from rekey
    /// "effectively unreachable", but if it fires it's a
    /// `WrongKey` for collapse consistency).
    pub fn rekey(&self, new_password: String) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let secret = SecretString::from(new_password);
        let composite = CompositeKey::from_password(secret.expose_secret().as_bytes());
        kdbx.rekey(&composite).map_err(VaultError::from)
    }

    // -------------------------------------------------------------------
    // History + cross-vault import/export (slice 8)
    // -------------------------------------------------------------------

    /// List the entry's history snapshots, oldest first.
    ///
    /// Each [`HistoryRecord`] carries a no-plaintext summary —
    /// `protected_field_names` is the set of names of every protected
    /// field on that snapshot, never the values. To recover a
    /// snapshot's plaintext, restore via
    /// [`Self::restore_entry_from_history`] then reveal via
    /// [`Self::reveal_field`].
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an
    /// entry.
    pub fn entry_history(&self, entry_uuid: String) -> Result<Vec<HistoryRecord>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let vault = kdbx.vault();
        let (_g, entry) = find_entry(&vault.root, target).ok_or(VaultError::NotFound)?;
        let binaries = vault.binaries.as_slice();
        Ok(entry
            .history
            .iter()
            .map(|snap| HistoryRecord::from_entry(snap, binaries))
            .collect())
    }

    /// Restore the entry to the state captured by history snapshot
    /// `index`. The pre-restore state is itself snapshotted into the
    /// entry's history (via `HistoryPolicy::Snapshot`) so the restore
    /// is undoable through a subsequent `restore_entry_from_history`
    /// call against the new top-of-history record.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an
    /// entry. [`VaultError::IndexOutOfRange`] if `index >=
    /// entry_history(entry_uuid).len()`.
    pub fn restore_entry_from_history(
        &self,
        entry_uuid: String,
        index: u32,
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        kdbx.restore_entry_from_history(target, index as usize, HistoryPolicy::Snapshot)
            .map_err(model_err_to_vault_err)?;
        drop(guard);
        self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
        Ok(())
    }

    /// Remove the history record at `index`. The live entry is
    /// untouched — deleting a history record is itself not a content
    /// edit (so `HistoryPolicy::NoSnapshot`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an
    /// entry. [`VaultError::IndexOutOfRange`] if the index isn't in
    /// `0..entry.history.len()` (normalised from
    /// [`keepass_core::model::EntryEditor::remove_history_at`]'s `bool`
    /// return).
    pub fn delete_history_at(&self, entry_uuid: String, index: u32) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let now = Utc::now();
        let outcome: Result<(), HistoryDeleteError> = kdbx
            .edit_entry(target, HistoryPolicy::NoSnapshot, |editor| {
                // Capture the record being tombstoned + the pool view
                // before we cross the mutable-borrow line.
                let record = editor
                    .history()
                    .get(index as usize)
                    .cloned()
                    .ok_or(HistoryDeleteError::IndexOutOfRange)?;
                let binaries: Vec<Binary> = editor.binaries().to_vec();
                add_history_tombstone(
                    editor.entry_mut(),
                    &record,
                    &binaries,
                    TombstoneReason::UserDelete,
                    None,
                    now,
                )
                .map_err(HistoryDeleteError::Tombstone)
            })
            .map_err(model_err_to_vault_err)?;
        drop(guard);
        match outcome {
            Ok(()) => {
                self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
                Ok(())
            }
            Err(HistoryDeleteError::IndexOutOfRange) => Err(VaultError::IndexOutOfRange),
            // Malformed pre-existing tombstone JSON is the only failure
            // mode for add_history_tombstone — surface as a generic
            // VaultError so frontends don't need a new variant for a
            // case that should be impossible on healthy vaults.
            Err(HistoryDeleteError::Tombstone(e)) => Err(VaultError::Unexpected(format!(
                "history tombstone write failed: {e}"
            ))),
        }
    }

    /// Trim the entry's history list to the current vault-wide
    /// `history_max_items` / `history_max_size` policy. Returns the
    /// number of snapshots removed.
    ///
    /// Trimming is a bookkeeping operation: the live entry's
    /// `last_modification_time` is **not** stamped, and
    /// `meta.settings_changed` is **not** touched. Each evicted
    /// record is tombstoned with [`TombstoneReason::QuotaTrim`] so
    /// the deletion survives subsequent merges with un-trimmed
    /// peers.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an
    /// entry.
    pub fn trim_entry_history(&self, entry_uuid: String) -> Result<u32, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let max_items = kdbx.vault().meta.history_max_items;
        let max_size = kdbx.vault().meta.history_max_size;
        let now = Utc::now();
        let removed: u32 = kdbx
            .edit_entry(target, HistoryPolicy::NoSnapshot, |editor| {
                let binaries: Vec<Binary> = editor.binaries().to_vec();
                prune_history_with_tombstones(
                    editor.entry_mut(),
                    max_items,
                    max_size,
                    &binaries,
                    TombstoneReason::QuotaTrim,
                    None,
                    now,
                )
                // Malformed pre-existing tombstone JSON is the only
                // way this fails; for the API contract we surface as
                // zero pruned (same shape as the prior implementation
                // on a no-op call).
                .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX))
            })
            .map_err(model_err_to_vault_err)?;
        drop(guard);
        if removed > 0 {
            self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
        }
        Ok(removed)
    }
}

/// Inner error type used to thread `add_history_tombstone` failures
/// through the `edit_entry` closure (whose return type is squeezed
/// between us and the closure caller). `delete_history_at` maps
/// every variant back to a [`VaultError`] at its boundary.
enum HistoryDeleteError {
    IndexOutOfRange,
    Tombstone(keepass_merge::TombstoneError),
}
