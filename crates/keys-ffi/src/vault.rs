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
use keepass_core::model::{Entry as KcEntry, EntryId, Group as KcGroup, GroupId};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::dto::{Entry, EntrySummary, Group};
use crate::error::VaultError;

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
    inner: Mutex<Option<Kdbx<Unlocked>>>,
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
