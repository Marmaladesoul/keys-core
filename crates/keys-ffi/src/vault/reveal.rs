//! `Vault` reveal methods exposed via `UniFFI` — fetch the cleartext
//! of a protected field or a historic snapshot field. The plaintext
//! crosses the FFI as a `String`; binding-side zeroing is the
//! frontend's responsibility (uniffi has no native `SecretString`-aware
//! lift).

#![allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]

use crate::dto::PASSWORD_FIELD_NAME;
use crate::error::VaultError;

use super::{Vault, find_entry, parse_entry_id};

#[uniffi::export]
impl Vault {
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
}
