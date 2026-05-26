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
use keepass_core::model::{Entry as KcEntry, EntryId, Group as KcGroup, GroupId};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::dto::Group;
use crate::error::VaultError;
use crate::observer::{VaultChange, VaultObserver};
use crate::protector::{VaultFieldProtector, bridge as bridge_protector};

// `impl Vault { ... }` blocks split across files by concern; each
// submodule contributes its slice of the public FFI method surface.
// The struct definition, lifecycle (`new` / `create_empty` / `lock` /
// `path` / `is_locked`), observer wiring (`set_observer` /
// `clear_observer` / `fire`), `Debug`, free helpers, the
// `merge_err_to_vault_err` mapping, and the unit-test module stay in
// `mod.rs` alongside the struct itself.
mod mutations;
mod portable_merge;
mod queries;
mod reveal;

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
    /// titled `database_name`. The path is written atomically
    /// (tempfile + `rename(2)`); if the file already exists, it's
    /// overwritten. Returns an unlocked `Vault` handle ready for
    /// mutations or immediate use.
    ///
    /// `temp_dir`, when supplied, is used as the directory for the
    /// atomic-write tempfile instead of `path`'s parent. Sandboxed
    /// macOS callers should pass `NSTemporaryDirectory()` here: the
    /// `NSSavePanel`-issued sandbox extension grants write to the
    /// chosen kdbx file but not arbitrary siblings in its parent
    /// directory, so the default sibling-tempfile path fails with
    /// EPERM. The override must live on the same filesystem volume
    /// as `path` (rename is not cross-volume atomic). Pass `None` on
    /// non-sandboxed platforms to keep the historical behaviour.
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
        temp_dir: Option<String>,
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
        let tmp_in = temp_dir.as_deref().map_or(parent, std::path::Path::new);
        let mut tmp =
            tempfile::NamedTempFile::new_in(tmp_in).map_err(|e| VaultError::Io(e.to_string()))?;
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
/// [`VaultError::NotFound`]. `MergeError` is `#[non_exhaustive]`
/// upstream; the wildcard arm degrades to [`VaultError::Unexpected`]
/// and `debug_assert!`s, so CI catches a new variant the first time a
/// test trips it without risking a UB panic across the FFI boundary in
/// release builds.
pub(super) fn merge_err_to_vault_err(err: keepass_merge::MergeError) -> VaultError {
    match err {
        keepass_merge::MergeError::Model(e) => VaultError::from(e),
        e @ (keepass_merge::MergeError::UnknownEntryInResolution { .. }
        | keepass_merge::MergeError::UnknownFieldInResolution { .. }
        | keepass_merge::MergeError::MissingResolutionForConflict { .. }
        | keepass_merge::MergeError::UnknownAttachmentInResolution { .. }
        | keepass_merge::MergeError::KeepBothNotPermittedForKind { .. }) => {
            VaultError::Merge(e.to_string())
        }
        other => {
            debug_assert!(
                false,
                "unmapped keepass_merge::MergeError variant in keys-ffi facade: {other:?}"
            );
            VaultError::Unexpected(format!("unmapped MergeError: {other}"))
        }
    }
}

pub(super) fn parse_group_id(s: &str) -> Result<GroupId, VaultError> {
    Uuid::parse_str(s)
        .map(GroupId)
        .map_err(|_| VaultError::NotFound)
}

pub(super) fn parse_entry_id(s: &str) -> Result<EntryId, VaultError> {
    Uuid::parse_str(s)
        .map(EntryId)
        .map_err(|_| VaultError::NotFound)
}

/// Parse a custom-icon UUID string. Same shape as `parse_entry_id` /
/// `parse_group_id` — `NotFound` on malformed input matches the
/// downstream `set_custom_icon` semantics (referencing a non-existent
/// custom-icon UUID is a no-op on the model side).
pub(super) fn parse_icon_uuid(s: &str) -> Result<Uuid, VaultError> {
    Uuid::parse_str(s).map_err(|_| VaultError::NotFound)
}

/// Convert Unix-epoch milliseconds into a `DateTime<Utc>`. Returns
/// [`VaultError::NotFound`] for out-of-range values rather than
/// panicking — same shape as the UUID parsers above (a malformed
/// patch surfaces as a clean error to the caller).
pub(super) fn timestamp_ms_to_utc(ms: i64) -> Result<DateTime<Utc>, VaultError> {
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

pub(super) fn walk_entries<'a>(group: &'a KcGroup, visit: &mut dyn FnMut(GroupId, &'a KcEntry)) {
    for entry in &group.entries {
        visit(group.id, entry);
    }
    for child in &group.groups {
        walk_entries(child, visit);
    }
}

pub(super) fn walk_groups(group: &KcGroup, parent: Option<GroupId>, out: &mut Vec<Group>) {
    out.push(Group::from_group(group, parent));
    for child in &group.groups {
        walk_groups(child, Some(group.id), out);
    }
}

pub(super) fn find_group(group: &KcGroup, target: GroupId) -> Option<&KcGroup> {
    if group.id == target {
        return Some(group);
    }
    group
        .groups
        .iter()
        .find_map(|child| find_group(child, target))
}

pub(super) fn find_entry(group: &KcGroup, target: EntryId) -> Option<(GroupId, &KcEntry)> {
    if let Some(entry) = group.entries.iter().find(|e| e.id == target) {
        return Some((group.id, entry));
    }
    group
        .groups
        .iter()
        .find_map(|child| find_entry(child, target))
}

pub(super) fn entry_matches(entry: &KcEntry, needle: &str) -> bool {
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
pub(super) fn format_kdf_params(params: &keepass_core::format::KdfParams) -> String {
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
pub(super) fn format_with_thousands(n: u64) -> String {
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

#[cfg(test)]
mod merge_err_to_vault_err_tests {
    //! Pin every currently-known `MergeError` variant to its intended
    //! `VaultError` collapse. The wildcard arm degrades to
    //! `VaultError::Unexpected` (with a `debug_assert!` so CI catches
    //! a new upstream variant the first time a test trips it) — that
    //! removes the FFI-UB hazard of the previous `panic!` while
    //! preserving the "forced code review on new variant" property.
    use super::*;
    use keepass_core::model::EntryId;
    use uuid::Uuid;

    #[test]
    fn model_inner_collapses_via_keepass_core_error() {
        let inner = keepass_core::Error::Format(keepass_core::format::FormatError::BadSignature1);
        let v = merge_err_to_vault_err(keepass_merge::MergeError::Model(inner));
        assert!(matches!(v, VaultError::Format));
    }

    #[test]
    fn unknown_entry_in_resolution_surfaces_as_merge() {
        let v = merge_err_to_vault_err(keepass_merge::MergeError::UnknownEntryInResolution {
            entry: EntryId(Uuid::nil()),
        });
        assert!(matches!(v, VaultError::Merge(_)));
    }

    #[test]
    fn unknown_field_in_resolution_surfaces_as_merge() {
        let v = merge_err_to_vault_err(keepass_merge::MergeError::UnknownFieldInResolution {
            entry: EntryId(Uuid::nil()),
            field: "Title".into(),
        });
        assert!(matches!(v, VaultError::Merge(_)));
    }

    #[test]
    fn missing_resolution_for_conflict_surfaces_as_merge() {
        let v = merge_err_to_vault_err(keepass_merge::MergeError::MissingResolutionForConflict {
            entry: EntryId(Uuid::nil()),
        });
        assert!(matches!(v, VaultError::Merge(_)));
    }

    #[test]
    fn unknown_attachment_in_resolution_surfaces_as_merge() {
        // Regression guard: this variant previously fell through to the
        // panic arm (UB across the FFI boundary).
        let v = merge_err_to_vault_err(keepass_merge::MergeError::UnknownAttachmentInResolution {
            entry: EntryId(Uuid::nil()),
            attachment: "attached.pdf".into(),
        });
        assert!(matches!(v, VaultError::Merge(_)));
    }

    #[test]
    fn keep_both_not_permitted_for_kind_surfaces_as_merge() {
        // Regression guard: also previously fell through to panic.
        let v = merge_err_to_vault_err(keepass_merge::MergeError::KeepBothNotPermittedForKind {
            entry: EntryId(Uuid::nil()),
            attachment: "x.bin".into(),
        });
        assert!(matches!(v, VaultError::Merge(_)));
    }
}
