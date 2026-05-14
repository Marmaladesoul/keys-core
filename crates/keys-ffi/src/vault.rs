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

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeZone, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{
    CustomFieldValue, Entry as KcEntry, EntryId, Group as KcGroup, GroupId, HistoryPolicy,
    NewEntry, NewGroup,
};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::dto::{
    AttachmentPoolStats, AutoType, Entry, EntryAttachment, EntryCreate, EntryPatch, EntrySummary,
    Group, GroupPatch, HistoryRecord, PASSWORD_FIELD_NAME,
};
use crate::error::{VaultError, model_err_to_vault_err};
use crate::merge::{MergeOutcome, ResolutionFfi, resolution_ffi_to_km};
use crate::observer::{VaultChange, VaultObserver};
use crate::portable::PortableEntry;
use crate::protector::{VaultFieldProtector, bridge as bridge_protector};

/// An opened KDBX vault.
///
/// Lifecycle: an instance is either unlocked-and-usable or
/// locked-and-poisoned-permanently. There is no re-unlock path —
/// frontends reconstruct a new `Vault` if they need to unlock again.
/// This matches `keepass-core`'s typestate (no `relock_then_unlock`
/// on `Kdbx<Unlocked>`).
#[derive(uniffi::Object)]
#[non_exhaustive]
pub struct Vault {
    /// `Some` while unlocked, `None` after [`Self::lock`]. The `Mutex`
    /// satisfies uniffi's `Send + Sync` requirement; it does **not** make
    /// the FFI re-entrant — every method that needs the unlocked state
    /// holds the lock for its full duration.
    inner: Mutex<Option<Kdbx<Unlocked>>>,
    /// Retained outside the `Mutex` so [`Self::path`] returns the
    /// constructor path even after `lock()` clears the inner state.
    path: PathBuf,
    /// One observer per vault (slice 9). `Arc` is cloned under the
    /// brief observer lock at fire time, then the lock drops before
    /// `on_change` runs — so observer callbacks may reenter the
    /// vault without deadlocking.
    observer: Mutex<Option<Arc<dyn VaultObserver>>>,
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
    pub fn new(
        path: String,
        password: String,
        field_protector: Option<Arc<dyn VaultFieldProtector>>,
    ) -> Result<Arc<Self>, VaultError> {
        let path_buf = PathBuf::from(&path);
        let secret = SecretString::from(password);
        let composite = CompositeKey::from_password(secret.expose_secret().as_bytes());
        let bridged = bridge_protector(field_protector);
        let kdbx = Kdbx::open(&path_buf)?
            .read_header()?
            .unlock_with_protector(&composite, bridged)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(kdbx)),
            path: path_buf,
            observer: Mutex::new(None),
        }))
    }

    /// Create a fresh KDBX4 vault at `path`, encrypted with `password`,
    /// titled `database_name`. The path is written atomically (sibling
    /// tempfile + `rename(2)`); if the file already exists, it's
    /// overwritten. Returns an unlocked `Vault` handle ready for
    /// mutations or immediate use.
    ///
    /// Defaults are baked in upstream
    /// ([`keepass_core::kdbx::Kdbx::<Unlocked>::create_empty_v4`]):
    /// AES-256-CBC outer cipher, Argon2d KDF (2 iter × 64 `MiB` × 8
    /// threads — matches contemporary `KeePass` / `KeePassXC` defaults),
    /// `GZip` compression, `ChaCha20` inner stream, random seeds +
    /// salts + inner-stream key from `OsRng`. The cost is one full Argon2
    /// round at create-time (~1s on contemporary hardware at these
    /// settings); `password` is wrapped in a [`SecretString`]
    /// immediately and dropped after the KDF call.
    ///
    /// Companion to [`Self::new`] for frontends that need to create a
    /// new vault file on first launch / "new vault" UI flows. The
    /// resulting vault opens via [`Self::new`] (verified by the
    /// upstream round-trip tests).
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] if the path's parent directory is missing or
    /// the write fails. [`VaultError::WrongKey`] for any crypto-class
    /// failure during the initial save (effectively impossible at the
    /// defaults baked in upstream — surfaced as a typed error rather
    /// than a panic).
    #[uniffi::constructor]
    pub fn create_empty(
        path: String,
        password: String,
        database_name: String,
        field_protector: Option<Arc<dyn VaultFieldProtector>>,
    ) -> Result<Arc<Self>, VaultError> {
        let path_buf = PathBuf::from(&path);
        let secret = SecretString::from(password);
        let composite = CompositeKey::from_password(secret.expose_secret().as_bytes());
        let bridged = bridge_protector(field_protector);

        // Build the unlocked vault, derive the transformed key against
        // the freshly-generated KDF params.
        let kdbx = Kdbx::<keepass_core::kdbx::Unlocked>::create_empty_v4_with_protector(
            &composite,
            database_name,
            bridged,
        )?;

        // Initial save via the same atomic-write pattern as `Self::save`.
        let bytes = kdbx.save_to_bytes()?;
        let parent = path_buf.parent().ok_or_else(|| {
            VaultError::Io("create_empty path has no parent directory".to_owned())
        })?;
        let mut tmp =
            tempfile::NamedTempFile::new_in(parent).map_err(|e| VaultError::Io(e.to_string()))?;
        tmp.write_all(&bytes)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        tmp.flush().map_err(|e| VaultError::Io(e.to_string()))?;
        tmp.as_file_mut()
            .sync_all()
            .map_err(|e| VaultError::Io(e.to_string()))?;
        tmp.persist(&path_buf)
            .map_err(|e| VaultError::Io(e.error.to_string()))?;

        Ok(Arc::new(Self {
            inner: Mutex::new(Some(kdbx)),
            path: path_buf,
            observer: Mutex::new(None),
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
        // Fire `Locked` to the current observer, then clear it so no
        // post-lock events can reach a stale handle. Per the spec
        // invariant: `Locked` is the final event for this Vault.
        self.fire(&VaultChange::Locked);
        *self.observer.lock().expect("Vault observer mutex poisoned") = None;
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
            // Goes through the protector when one is installed;
            // returns the in-model plaintext otherwise.
            return Ok(kdbx.reveal_password(target)?);
        }
        // Confirm the field exists and is protected before delegating;
        // matches the legacy `FieldNotFound` posture (unprotected
        // custom fields are reachable via `get_entry`).
        let protected_exists = entry
            .custom_fields
            .iter()
            .any(|c| c.protected && c.key == field_name);
        if !protected_exists {
            return Err(VaultError::FieldNotFound);
        }
        kdbx.reveal_custom_field(target, &field_name)?
            .ok_or(VaultError::FieldNotFound)
    }

    /// Reveal the plaintext of a single protected field on a
    /// historical snapshot, without first restoring the snapshot.
    ///
    /// `history_index` is the snapshot's position in the `Vec`
    /// returned by [`Self::entry_history`] (oldest-first). `field_name`
    /// follows the same canonical-KDBX-key convention as
    /// [`Self::reveal_field`] — `"Password"` for the structural slot
    /// or the verbatim key of any protected custom field.
    ///
    /// Same SE / plaintext-as-String contract as [`Self::reveal_field`]
    /// — no upstream caching, caller responsible for prompt discard.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if no entry matches `entry_uuid`.
    /// [`VaultError::IndexOutOfRange`] if `history_index` is
    /// beyond the snapshot list's bounds.
    /// [`VaultError::FieldNotFound`] if the snapshot has no
    /// protected field by `field_name` (passing the key of an
    /// unprotected custom field also yields `FieldNotFound` —
    /// unprotected values are reachable via [`Self::entry_history`]'s
    /// returned `HistoryRecord`).
    pub fn reveal_history_field(
        &self,
        entry_uuid: String,
        history_index: u32,
        field_name: String,
    ) -> Result<String, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let (_group_id, entry) =
            find_entry(&kdbx.vault().root, target).ok_or(VaultError::NotFound)?;
        let snapshot = entry
            .history
            .get(history_index as usize)
            .ok_or(VaultError::IndexOutOfRange)?;

        if field_name == PASSWORD_FIELD_NAME {
            return Ok(snapshot.password.clone());
        }
        snapshot
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
    /// [`Kdbx::move_group_to_position`]; same bookkeeping
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
        let removed = kdbx
            .edit_entry(target, HistoryPolicy::NoSnapshot, |editor| {
                editor.remove_history_at(index as usize)
            })
            .map_err(model_err_to_vault_err)?;
        drop(guard);
        if removed {
            self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
            Ok(())
        } else {
            Err(VaultError::IndexOutOfRange)
        }
    }

    /// Trim the entry's history list to the current vault-wide
    /// `history_max_items` / `history_max_size` policy. Returns the
    /// number of snapshots removed.
    ///
    /// Trimming is a bookkeeping operation: the live entry's
    /// `last_modification_time` is **not** stamped, and
    /// `meta.settings_changed` is **not** touched. Mirrors
    /// [`keepass_core::kdbx::Kdbx::trim_entry_history`].
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
        let removed = kdbx
            .trim_entry_history(target)
            .map_err(model_err_to_vault_err)?;
        drop(guard);
        if removed > 0 {
            self.fire(&VaultChange::EntryModified { uuid: entry_uuid });
        }
        Ok(removed)
    }

    /// Snapshot the entry plus all its history, attachments, and
    /// referenced custom icons into an opaque carrier suitable for
    /// import into a different vault.
    ///
    /// The returned [`PortableEntry`] is **single-use**: pass it to
    /// [`Self::import_entry`] exactly once. A second `import_entry`
    /// on the same handle returns [`VaultError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `entry_uuid` doesn't match an
    /// entry.
    pub fn export_entry(&self, entry_uuid: String) -> Result<Arc<PortableEntry>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        let target = parse_entry_id(&entry_uuid)?;
        let portable = kdbx.export_entry(target).map_err(model_err_to_vault_err)?;
        Ok(Arc::new(PortableEntry::new(portable)))
    }

    /// Insert a previously-exported entry under `group_uuid`. The
    /// imported entry receives a freshly-minted UUID — cross-vault
    /// duplication of the source UUID would set up merge conflicts
    /// the API exists to avoid.
    ///
    /// **The carrier is consumed by this call.** A second
    /// `import_entry` on the same `portable` handle returns
    /// [`VaultError::NotFound`] — see [`PortableEntry`]'s
    /// single-use note.
    ///
    /// Returns the new entry's UUID.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `group_uuid` doesn't match a
    /// group, or if `portable` has already been imported.
    pub fn import_entry(
        &self,
        portable: Arc<PortableEntry>,
        group_uuid: String,
    ) -> Result<String, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let parent = parse_group_id(&group_uuid)?;
        let inner = portable.take()?;
        let new_id = kdbx
            .import_entry(parent, inner, /*mint_new_uuid*/ true)
            .map_err(model_err_to_vault_err)?;
        let new_uuid = new_id.0.to_string();
        drop(guard);
        self.fire(&VaultChange::EntryModified {
            uuid: new_uuid.clone(),
        });
        Ok(new_uuid)
    }

    /// Insert a previously-exported entry under `group_uuid`, restored
    /// to live with the caller-supplied `target_uuid` rather than a
    /// freshly-minted one. Intended for **cross-vault move-undo**:
    /// the forward move bounces the entry through a new UUID; undoing
    /// it through plain [`Self::import_entry`] would mint *another*
    /// new UUID, so external references pinned to the pre-move UUID
    /// (`AutoFill` record identifiers, bookmarks, links) break across
    /// the round-trip. This variant lets undo restore the original
    /// identity directly.
    ///
    /// Tombstones in the destination vault matching `target_uuid` are
    /// cleared as part of the import; without this step, a downstream
    /// merge against another vault would consume the tombstone and
    /// re-delete the freshly-restored entry. See
    /// [`keepass_core::kdbx::Kdbx::import_entry_with_uuid`] for the
    /// underlying semantics.
    ///
    /// **The carrier is consumed by this call**, same as
    /// [`Self::import_entry`]. Fires `EntryModified` for `target_uuid`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if `group_uuid` doesn't match a group,
    /// if `target_uuid` doesn't parse as a UUID, if `portable` has
    /// already been imported, **or** if `target_uuid` is already in
    /// use as a live entry in the destination vault (keepass-core's
    /// `DuplicateUuid` collapses to `NotFound` at the FFI boundary
    /// today; the destination is untouched on this failure).
    pub fn import_entry_with_uuid(
        &self,
        portable: Arc<PortableEntry>,
        group_uuid: String,
        target_uuid: String,
    ) -> Result<String, VaultError> {
        let mut guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
        let parent = parse_group_id(&group_uuid)?;
        let target = parse_entry_id(&target_uuid)?;
        let inner = portable.take()?;
        let new_id = kdbx
            .import_entry_with_uuid(parent, inner, target)
            .map_err(model_err_to_vault_err)?;
        let new_uuid = new_id.0.to_string();
        drop(guard);
        self.fire(&VaultChange::EntryModified {
            uuid: new_uuid.clone(),
        });
        Ok(new_uuid)
    }

    // -------------------------------------------------------------------
    // External merge (slice 7.5a)
    // -------------------------------------------------------------------

    /// Run a three-way merge against the KDBX file at `other_path`,
    /// unlocked with `other_password`. Returns an opaque
    /// [`MergeOutcome`] handle the binding side reads to drive the
    /// conflict resolver UI before handing back to
    /// `apply_merge_outcome` (slice 7.5b).
    ///
    /// **Read-only.** This method does not mutate the local vault and
    /// does not fire the `BulkMerge` observer event — both happen in
    /// `apply_merge_outcome` once the caller has resolved any
    /// conflicts. Reading the same `Vault` after `merge_external`
    /// returns the pre-merge state.
    ///
    /// The local vault is cloned at merge time so the merge runs
    /// outside the vault mutex; the clone is stashed on the returned
    /// [`MergeOutcome`] for slice 7.5b's apply step. Two full deep
    /// clones per call (local + remote); acceptable at v0.1 since
    /// `merge_external` fires once per external-change event.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if this vault has been locked.
    /// [`VaultError::Io`] if `other_path` can't be read.
    /// [`VaultError::Format`] if `other_path` isn't a KDBX file.
    /// [`VaultError::WrongKey`] if `other_password` doesn't unlock
    /// the other file (or any other crypto-class failure during the
    /// other-side open).
    pub fn merge_external(
        &self,
        other_path: String,
        other_password: String,
    ) -> Result<Arc<MergeOutcome>, VaultError> {
        // Lock-check first so a locked self short-circuits before we
        // burn crypto work unlocking the other side.
        //
        // The local clone goes through `vault_with_unwrapped_protected`
        // rather than `vault().clone()` so any protected-field
        // plaintext wrapped out by the FieldProtector (Secure Enclave
        // on macOS) is spliced back into the clone before the merger
        // sees it. The remote side is opened below without a
        // protector, so its protected slots already carry plaintext;
        // matching the local side keeps the comparator symmetric.
        // Without this step the merger flags every protected custom
        // field as a conflict (empty-vs-plaintext per side).
        let local_vault = {
            let guard = self.inner.lock().expect("Vault mutex poisoned");
            let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
            kdbx.vault_with_unwrapped_protected()?
        };

        let other_path_buf = PathBuf::from(&other_path);
        let secret = SecretString::from(other_password);
        let composite = CompositeKey::from_password(secret.expose_secret().as_bytes());
        let other_kdbx = Kdbx::open(&other_path_buf)?
            .read_header()?
            .unlock(&composite)?;
        let remote_vault = other_kdbx.vault().clone();

        let outcome =
            keepass_merge::merge(&local_vault, &remote_vault).map_err(merge_err_to_vault_err)?;

        Ok(Arc::new(MergeOutcome {
            inner: Mutex::new(Some(outcome)),
            local: Mutex::new(Some(local_vault)),
            remote: Mutex::new(Some(remote_vault)),
        }))
    }

    /// Apply a [`MergeOutcome`] to this vault using `resolution`'s
    /// caller-driven choices for any conflict buckets, run a
    /// post-pass timestamp reconciliation, and fire the
    /// [`VaultChange::BulkMerge`] observer event.
    ///
    /// The `outcome` carrier is **consumed**: subsequent accessors on
    /// the same handle (and a second `apply_merge_outcome` call)
    /// return [`VaultError::NotFound`]. Mirrors `PortableEntry`'s
    /// single-use posture.
    ///
    /// **Lock-check is non-consuming.** Calling on a locked vault
    /// returns [`VaultError::Locked`] *without* taking the carrier;
    /// the caller can retry against a fresh `Vault`.
    /// **Resolution-translation is also non-consuming.** A UUID
    /// parse failure surfaces as [`VaultError::Merge`] before the
    /// carrier is touched.
    /// **Upstream resolution-validation errors *are* consuming.**
    /// `MergeError::UnknownEntryInResolution` /
    /// `UnknownFieldInResolution` /
    /// `MissingResolutionForConflict` surface as
    /// [`VaultError::Merge`] but the carrier is gone — the caller
    /// must re-`merge_external` to retry.
    ///
    /// **Staleness contract.** Behaviour is undefined if this
    /// `Vault` was mutated between the originating `merge_external`
    /// and this call. The Swift conflict resolver is modal, which
    /// makes such mutation structurally hard; we don't try to
    /// detect it.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::NotFound`] if the carrier has already been
    /// consumed by a prior `apply_merge_outcome`.
    /// [`VaultError::Merge`] if the resolution is inconsistent with
    /// the outcome (unknown / missing entry, unknown field key) or a
    /// UUID inside the resolution doesn't parse. See above for the
    /// consume-vs-non-consume posture across the variants.
    /// [`VaultError::WrongKey`] for any crypto-class failure
    /// surfaced through `MergeError::Model` (none expected at the
    /// merge step today; reserved for forward-compat).
    pub fn apply_merge_outcome(
        &self,
        outcome: Arc<MergeOutcome>,
        resolution: ResolutionFfi,
    ) -> Result<(), VaultError> {
        // Step 1: lock-check first — non-consuming.
        {
            let guard = self.inner.lock().expect("Vault mutex poisoned");
            if guard.is_none() {
                return Err(VaultError::Locked);
            }
        }

        // Step 2: translate resolution — non-consuming.
        let km_resolution = resolution_ffi_to_km(&resolution)?;

        // Step 3: take the carrier slots. Any None → already consumed.
        let mut inner_guard = outcome.inner.lock().expect("MergeOutcome mutex poisoned");
        let mut local_guard = outcome.local.lock().expect("MergeOutcome mutex poisoned");
        let mut remote_guard = outcome.remote.lock().expect("MergeOutcome mutex poisoned");
        let km_outcome = inner_guard.take().ok_or(VaultError::NotFound)?;
        let mut local_vault = local_guard.take().ok_or(VaultError::NotFound)?;
        let remote_vault = remote_guard.take().ok_or(VaultError::NotFound)?;
        drop(inner_guard);
        drop(local_guard);
        drop(remote_guard);

        // Steps 4-5: apply + reconcile timestamps on the local clone.
        keepass_merge::apply_merge(&mut local_vault, &remote_vault, &km_outcome, &km_resolution)
            .map_err(merge_err_to_vault_err)?;
        keepass_merge::reconcile_timestamps(&mut local_vault, &remote_vault);

        // Step 6: swap the merged vault into self.inner via the
        // upstream Kdbx::replace_vault.
        {
            let mut guard = self.inner.lock().expect("Vault mutex poisoned");
            let kdbx = guard.as_mut().ok_or(VaultError::Locked)?;
            kdbx.replace_vault(local_vault);
        }

        // Step 7: fire observer outside any lock.
        self.fire(&VaultChange::BulkMerge);
        Ok(())
    }

    // -------------------------------------------------------------------
    // Observer (slice 9)
    // -------------------------------------------------------------------

    /// Register `observer` for change notifications. Replaces any
    /// previously-registered observer — one observer per vault.
    pub fn set_observer(&self, observer: Arc<dyn VaultObserver>) {
        *self.observer.lock().expect("Vault observer mutex poisoned") = Some(observer);
    }

    /// Remove the currently-registered observer (if any). Subsequent
    /// mutations fire no events until a new observer is set.
    pub fn clear_observer(&self) {
        *self.observer.lock().expect("Vault observer mutex poisoned") = None;
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locked = self.is_locked();
        let has_observer = self
            .observer
            .lock()
            .expect("Vault observer mutex poisoned")
            .is_some();
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("locked", &locked)
            .field("has_observer", &has_observer)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Fire `change` to the current observer (if any) **outside**
    /// the inner mutex. Snapshots the observer `Arc` under the brief
    /// observer lock, drops the lock, then dispatches — so an
    /// observer that calls back into the vault doesn't deadlock.
    pub(crate) fn fire(&self, change: &VaultChange) {
        let observer = self
            .observer
            .lock()
            .expect("Vault observer mutex poisoned")
            .clone();
        if let Some(obs) = observer {
            obs.on_change(change.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Map [`keepass_merge::MergeError`] onto [`VaultError`].
///
/// `Model(_)` collapses through the existing `From<keepass_core::Error>`
/// (so wrong-key / I/O classify as their familiar variants). The three
/// resolution-validation variants surface as
/// [`VaultError::Merge`] — caller-error class, distinct from
/// [`VaultError::NotFound`]. Any unmapped future variant panics so a
/// merge-crate addition trips CI on the first run.
fn merge_err_to_vault_err(err: keepass_merge::MergeError) -> VaultError {
    match err {
        keepass_merge::MergeError::Model(e) => VaultError::from(e),
        e @ (keepass_merge::MergeError::UnknownEntryInResolution { .. }
        | keepass_merge::MergeError::UnknownFieldInResolution { .. }
        | keepass_merge::MergeError::MissingResolutionForConflict { .. }) => {
            VaultError::Merge(e.to_string())
        }
        other => panic!("unmapped keepass_merge::MergeError variant in keys-ffi facade: {other:?}"),
    }
}

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

/// Parse a custom-icon UUID string. Same shape as `parse_entry_id` /
/// `parse_group_id` — `NotFound` on malformed input matches the
/// downstream `set_custom_icon` semantics (referencing a non-existent
/// custom-icon UUID is a no-op on the model side).
fn parse_icon_uuid(s: &str) -> Result<Uuid, VaultError> {
    Uuid::parse_str(s).map_err(|_| VaultError::NotFound)
}

/// Convert Unix-epoch milliseconds into a `DateTime<Utc>`. Returns
/// [`VaultError::NotFound`] for out-of-range values rather than
/// panicking — same shape as the UUID parsers above (a malformed
/// patch surfaces as a clean error to the caller).
fn timestamp_ms_to_utc(ms: i64) -> Result<DateTime<Utc>, VaultError> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .ok_or(VaultError::NotFound)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
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

/// Format a parsed [`keepass_core::format::KdfParams`] as a single-line
/// display string. Argon2 variants render as
/// `"<name> (<mib> MB · <iter> iter · <threads> threads)"`; AES-KDF as
/// `"AES-KDF (<rounds> rounds)"` with thousands separators.
fn format_kdf_params(params: &keepass_core::format::KdfParams) -> String {
    use keepass_core::format::{Argon2Variant, KdfParams};
    match params {
        KdfParams::AesKdf { rounds, .. } => {
            let formatted = format_with_thousands(*rounds);
            format!("AES-KDF ({formatted} rounds)")
        }
        KdfParams::Argon2 {
            variant,
            memory_bytes,
            iterations,
            parallelism,
            ..
        } => {
            let name = match variant {
                Argon2Variant::Argon2d => "Argon2d",
                Argon2Variant::Argon2id => "Argon2id",
                _ => "Argon2",
            };
            let mib = memory_bytes / (1024 * 1024);
            format!("{name} ({mib} MB \u{00B7} {iterations} iter \u{00B7} {parallelism} threads)")
        }
        _ => "Unknown KDF".to_owned(),
    }
}

/// Format an integer with comma thousands separators, e.g. 6000000 → "6,000,000".
/// Used by [`Vault::kdf_display`]'s AES-KDF branch where the round count is
/// always a large integer.
fn format_with_thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*ch as char);
    }
    out
}
