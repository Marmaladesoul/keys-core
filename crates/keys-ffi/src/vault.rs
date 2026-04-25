//! [`Vault`] — the FFI handle that collapses `keepass-core`'s typestate
//! (`Sealed → HeaderRead → Unlocked`) into a single constructor and exposes
//! the lifecycle methods Phase 2 slice 2 requires.

// uniffi-exported methods take owned `String` even when they only borrow —
// it's the natural FFI shape and matches the spec IDL.
#![allow(clippy::needless_pass_by_value)]
// Every method in this file holds `inner.lock().expect(..)`. Documenting
// the same structurally-impossible mutex-poisoning panic on every method
// would be more noise than signal.
#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{
    CustomFieldValue, Entry as KcEntry, EntryId, Group as KcGroup, GroupId, HistoryPolicy,
    NewEntry, NewGroup,
};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::dto::{
    Entry, EntryCreate, EntryPatch, EntrySummary, Group, GroupPatch, PASSWORD_FIELD_NAME,
};
use crate::error::{VaultError, model_err_to_vault_err};

/// An opened KDBX vault.
///
/// Lifecycle: an instance is either unlocked-and-usable or
/// locked-and-poisoned-permanently. There is no re-unlock path —
/// frontends reconstruct a new `Vault` if they need to unlock again.
/// This matches `keepass-core`'s typestate (no `relock_then_unlock`
/// on `Kdbx<Unlocked>`).
#[derive(Debug, uniffi::Object)]
#[non_exhaustive]
pub struct Vault {
    /// `Some` while unlocked, `None` after [`Self::lock`]. The `Mutex`
    /// satisfies uniffi's `Send + Sync` requirement; it does **not** make
    /// the FFI re-entrant — every method that needs the unlocked state
    /// holds the lock for its full duration.
    pub(crate) inner: Mutex<Option<Kdbx<Unlocked>>>,
    /// Retained outside the `Mutex` so [`Self::path`] returns the
    /// constructor path even after `lock()` clears the inner state.
    path: PathBuf,
}

#[uniffi::export]
impl Vault {
    /// Open a vault from `path`, deriving the composite key from
    /// `password`.
    ///
    /// Wrong password and corrupt ciphertext both surface as
    /// [`VaultError::WrongKey`] — see [`crate::VaultError`] for the
    /// error-collapse discipline. "Not a KDBX file" surfaces as
    /// [`VaultError::Format`]. Filesystem failures surface as
    /// [`VaultError::Io`].
    ///
    /// The boundary `password` `String` lives only as long as this
    /// constructor call; it's wrapped in a [`SecretString`] immediately,
    /// hashed into a [`CompositeKey`], and dropped. Binding-side zeroing
    /// of the original `String` is the frontend's responsibility — no FFI
    /// can promise it.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Io`] if `path` can't be read,
    /// [`VaultError::Format`] if the file isn't a KDBX file, and
    /// [`VaultError::WrongKey`] for any other failure (wrong password,
    /// corrupt vault, malformed inner XML).
    #[uniffi::constructor]
    pub fn new(path: String, password: String) -> Result<Arc<Self>, VaultError> {
        let path_buf = PathBuf::from(&path);
        let secret = SecretString::from(password);
        let composite = CompositeKey::from_password(secret.expose_secret().as_bytes());
        let kdbx = Kdbx::open(&path_buf)?.read_header()?.unlock(&composite)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(kdbx)),
            path: path_buf,
        }))
    }

    /// Drop the unlocked vault state. Idempotent — locking an
    /// already-locked vault is `Ok(())`. `SwiftUI`'s auto-timer,
    /// explicit, and on-quit lock paths can all fire without
    /// coordinating.
    ///
    /// The signature returns `Result` to match the spec IDL (`[Throws]`)
    /// and leave room for slice 7's save-on-lock without a binding break.
    /// At this slice the only failure mode would be mutex poisoning,
    /// which is structurally impossible (the writers don't panic).
    ///
    /// # Errors
    ///
    /// Currently never returns an error. Reserved for slice-7 save-on-lock.
    ///
    /// # Panics
    ///
    /// Panics if the inner [`Mutex`] is poisoned. Structurally impossible
    /// — no method on `Vault` panics while holding the lock.
    pub fn lock(&self) -> Result<(), VaultError> {
        *self.inner.lock().expect("Vault mutex poisoned") = None;
        Ok(())
    }

    /// The path passed to [`Self::new`]. Non-throwing — survives
    /// [`Self::lock`].
    #[must_use]
    pub fn path(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// `true` if [`Self::lock`] has been called on this instance.
    /// Non-throwing — survives lock.
    ///
    /// # Panics
    ///
    /// Panics if the inner [`Mutex`] is poisoned. See [`Self::lock`].
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.inner.lock().expect("Vault mutex poisoned").is_none()
    }

    /// Enumerate entries in `group_uuid` (direct children only) or — when
    /// `None` — every entry across every group, depth-first.
    ///
    /// Order is structural (tree traversal), not value-based; the
    /// frontend sorts.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked,
    /// [`VaultError::NotFound`] if `group_uuid` doesn't match a group.
    pub fn list_entries(
        &self,
        group_uuid: Option<String>,
    ) -> Result<Vec<EntrySummary>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let root = &kdbx.vault().root;

        match group_uuid {
            None => {
                let mut out = Vec::new();
                walk_entries(root, &mut |group_id, entry| {
                    out.push(EntrySummary::from_entry(entry, group_id));
                });
                Ok(out)
            }
            Some(uuid_str) => {
                let target = parse_group_id(&uuid_str)?;
                let group = find_group(root, target).ok_or(VaultError::NotFound)?;
                Ok(group
                    .entries
                    .iter()
                    .map(|e| EntrySummary::from_entry(e, group.id))
                    .collect())
            }
        }
    }

    /// Flat list of every group in the vault, depth-first from the root.
    /// Each [`Group`] carries `parent_uuid` and child UUIDs so the
    /// caller can reconstruct the tree.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn list_groups(&self) -> Result<Vec<Group>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let mut out = Vec::new();
        walk_groups(&kdbx.vault().root, None, &mut out);
        Ok(out)
    }

    /// Fetch a single entry by UUID. Recycled entries are returned
    /// verbatim — recycle-bin filtering is the frontend's job.
    /// Protected fields appear with `value: None`; slice 4 adds the
    /// per-field reveal API.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked,
    /// [`VaultError::NotFound`] if `uuid` doesn't match an entry.
    pub fn get_entry(&self, uuid: String) -> Result<Entry, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&uuid)?;
        find_entry(&kdbx.vault().root, target)
            .map(|(group_id, entry)| Entry::from_entry(entry, group_id))
            .ok_or(VaultError::NotFound)
    }

    /// Case-insensitive substring search across `title`, `username`,
    /// `url`, `notes`, and each tag. Walks every entry depth-first;
    /// no index. Returns matches in tree order.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    pub fn search(&self, query: String) -> Result<Vec<EntrySummary>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let needle = query.to_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        walk_entries(&kdbx.vault().root, &mut |group_id, entry| {
            if entry_matches(entry, &needle) {
                out.push(EntrySummary::from_entry(entry, group_id));
            }
        });
        Ok(out)
    }

    /// Reveal the plaintext of a single protected field.
    ///
    /// `field_name` is the canonical KDBX key — `"Password"` for the
    /// structural password slot, or the verbatim key of any protected
    /// custom field. Case-sensitive (matches the on-disk XML).
    ///
    /// Slice 3's [`Self::get_entry`] returns every protected field
    /// with `value: None`; this method is the only path that produces
    /// plaintext across the FFI. The plaintext crosses as a `String`
    /// because uniffi has no native `SecretString`-aware lift —
    /// **binding-side zeroing is the frontend's responsibility**.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if no entry matches `entry_uuid`.
    /// [`VaultError::FieldNotFound`] if the entry has no protected
    /// field by `field_name` (passing the key of an unprotected
    /// custom field also yields `FieldNotFound` — unprotected values
    /// are reachable via `get_entry`).
    pub fn reveal_field(
        &self,
        entry_uuid: String,
        field_name: String,
    ) -> Result<String, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let (_group_id, entry) =
            find_entry(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;

        if field_name == PASSWORD_FIELD_NAME {
            return Ok(entry.password.clone());
        }
        entry
            .custom_fields
            .iter()
            .find(|c| c.protected && c.key == field_name)
            .map(|c| c.value.clone())
            .ok_or(VaultError::FieldNotFound)
    }

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

        kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            if field_name == PASSWORD_FIELD_NAME {
                editor.set_password(secret);
            } else {
                editor.set_custom_field(field_name, CustomFieldValue::Protected(secret));
            }
        })
        .map_err(model_err_to_vault_err)
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

        kdbx.edit_entry(target, HistoryPolicy::Snapshot, |editor| {
            if is_password {
                editor.set_password(SecretString::from(String::new()));
            } else {
                editor.remove_custom_field(&field_name);
            }
        })
        .map_err(model_err_to_vault_err)?;
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
                for cf in entry.custom_fields {
                    editor.set_custom_field(cf.name, CustomFieldValue::Plain(cf.value));
                }
            })
            .map_err(model_err_to_vault_err)?;
        }

        Ok(new_id.0.to_string())
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
                for cf in new_list {
                    editor.set_custom_field(cf.name, CustomFieldValue::Plain(cf.value));
                }
            }
        })
        .map_err(model_err_to_vault_err)?;
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
        kdbx.delete_entry(target).map_err(model_err_to_vault_err)
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
            .map_err(model_err_to_vault_err)
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
        Ok(new_id.0.to_string())
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
        kdbx.edit_group(target, |editor| {
            if let Some(n) = patch.name {
                editor.set_name(n);
            }
            if let Some(n) = patch.notes {
                editor.set_notes(n);
            }
        })
        .map_err(model_err_to_vault_err)
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
        kdbx.delete_group(target).map_err(model_err_to_vault_err)
    }

    /// Move a group under `new_parent_uuid`. A move that would make
    /// the group a descendant of itself fails through the
    /// `CircularMove → NotFound` mapping in
    /// [`crate::error::model_err_to_vault_err`].
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
            .map_err(model_err_to_vault_err)
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
        Ok(bin.map(|gid| gid.0.to_string()))
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
        Ok(bin.map(|gid| gid.0.to_string()))
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
        let n = kdbx.empty_recycle_bin().map_err(model_err_to_vault_err)?;
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
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_group_id(s: &str) -> Result<GroupId, VaultError> {
    Uuid::parse_str(s)
        .map(GroupId)
        .map_err(|_| VaultError::NotFound)
}

fn parse_entry_id(s: &str) -> Result<EntryId, VaultError> {
    Uuid::parse_str(s)
        .map(EntryId)
        .map_err(|_| VaultError::NotFound)
}

fn walk_entries<'a>(group: &'a KcGroup, visit: &mut dyn FnMut(GroupId, &'a KcEntry)) {
    for entry in &group.entries {
        visit(group.id, entry);
    }
    for child in &group.groups {
        walk_entries(child, visit);
    }
}

fn walk_groups(group: &KcGroup, parent: Option<GroupId>, out: &mut Vec<Group>) {
    out.push(Group::from_group(group, parent));
    for child in &group.groups {
        walk_groups(child, Some(group.id), out);
    }
}

fn find_group(group: &KcGroup, target: GroupId) -> Option<&KcGroup> {
    if group.id == target {
        return Some(group);
    }
    group
        .groups
        .iter()
        .find_map(|child| find_group(child, target))
}

fn find_entry(group: &KcGroup, target: EntryId) -> Option<(GroupId, &KcEntry)> {
    if let Some(entry) = group.entries.iter().find(|e| e.id == target) {
        return Some((group.id, entry));
    }
    group
        .groups
        .iter()
        .find_map(|child| find_entry(child, target))
}

fn entry_matches(entry: &KcEntry, needle: &str) -> bool {
    let haystacks: [&str; 4] = [&entry.title, &entry.username, &entry.url, &entry.notes];
    if haystacks.iter().any(|s| s.to_lowercase().contains(needle)) {
        return true;
    }
    entry.tags.iter().any(|t| t.to_lowercase().contains(needle))
}
