//! `Vault` portable-entry import/export and external-merge methods —
//! the cross-vault carrier flow (`export_entry` / `import_entry` /
//! `import_entry_with_uuid`) plus the two-step merge handshake
//! (`merge_external` produces a `MergeOutcome`, `apply_merge_outcome`
//! consumes it with the caller's resolution).

#![allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::Kdbx;
use secrecy::{ExposeSecret, SecretString};

use crate::error::{VaultError, model_err_to_vault_err};
use crate::merge::{MergeOutcome, ResolutionFfi, resolution_ffi_to_km};
use crate::observer::VaultChange;
use crate::portable::PortableEntry;

use super::{Vault, merge_err_to_vault_err, parse_entry_id, parse_group_id};

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
}
