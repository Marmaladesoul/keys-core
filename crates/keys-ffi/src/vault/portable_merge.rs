//! `Vault` portable-entry import/export — the cross-vault carrier flow
//! (`export_entry` / `import_entry` / `import_entry_with_uuid`).

#![allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]

use std::sync::Arc;

use crate::error::{VaultError, model_err_to_vault_err};
use crate::observer::VaultChange;
use crate::portable::PortableEntry;

use super::{Vault, parse_entry_id, parse_group_id};

#[uniffi::export]
impl Vault {
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
}
