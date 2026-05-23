//! `Vault` read-side query methods exposed via `UniFFI` — list entries,
//! list groups, get an entry by uuid, and full-vault search.
//! Reveal methods (which require the field protector) live in
//! `vault::reveal` next door.

#![allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]

use crate::dto::{Entry, EntrySummary, Group};
use crate::error::VaultError;

use super::{
    Vault, entry_matches, find_entry, find_group, parse_entry_id, parse_group_id, walk_entries,
    walk_groups,
};

#[uniffi::export]
impl Vault {
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
}
