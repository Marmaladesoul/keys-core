//! [`Engine`] — uniffi-facing wrapper around [`keys_engine::Engine`].
//!
//! Wraps the engine in a [`Mutex`] for FFI-side `&self`/`Send`/`Sync`
//! satisfaction (the engine itself takes `&self` for reads and `&mut
//! self` for mutations; the mutex serialises both). Reads land sync;
//! the four slow ops (`ingest_from_kdbx`, `save_to_kdbx`,
//! `reconcile_with_disk`, `apply_conflict_resolution`) are `async` and
//! dispatched onto a tokio multi-thread runtime.
//!
//! ## What's exposed
//!
//! Mirrors every public `Engine::*` method except the test-only /
//! `#[doc(hidden)]` ones. KDBX-handle-bearing methods
//! (`ingest_from_kdbx`, `save_to_kdbx`, `reconcile_with_disk`) take a
//! `kdbx_path: String` + `password: String` and open the kdbx in-method
//! — there's no FFI-side `Kdbx` Object to pass through (one could be
//! added later if call sites need to amortise the open cost; for now
//! each slow op opens fresh).
//!
//! ## What's deliberately NOT exposed
//!
//! - `Engine::project_to_vault` — needs the keepass-core `Vault` type
//!   on the wire, which we don't model at the FFI.
//! - `Engine::set_reconcile_trigger` / `clear_reconcile_trigger` —
//!   ReconcileTrigger is a Rust-only trait used by the file-watcher
//!   path; frontends drive reconcile directly via the async method.
//! - `Engine::consume_self_write_signature` — internal to the
//!   file-watcher path.
//! - `Engine::fingerprint` / `Engine::strength` — pure helpers that
//!   the FFI hasn't needed yet; trivial to add if a frontend asks.
//! - `Engine::last_self_write` / `last_saved_kdbx_bytes` — internal
//!   diagnostics.
//! - The `#[doc(hidden)]` test accessors.

// uniffi-exported methods take owned `String` even when they only borrow
// — matches the existing Vault pattern.
#![allow(clippy::needless_pass_by_value)]
// Every method holds `inner.lock().expect(..)`. Documenting the same
// structurally-impossible mutex-poisoning panic on every method would
// be more noise than signal — same posture as `vault.rs`.
#![allow(clippy::missing_panics_doc)]
// All methods return `Result<_, EngineError>` and the per-variant
// errors are documented on the enum itself; repeating them per
// method would be noise.
#![allow(clippy::missing_errors_doc)]
// Doc comments name FFI-side wire types (`SQLite`, `Kdbx`, etc.)
// freely; backticking each instance would be noise.
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::Kdbx;
use keys_engine as eng;
use secrecy::{ExposeSecret, SecretString};

use crate::db_key_provider::{BridgeDbKeyProvider, VaultDbKeyProvider};
use crate::engine_error::EngineError;
use crate::engine_file_watcher::{self, VaultFileWatcher};
use crate::engine_observer::{BridgeObserver, VaultDataChangeObserver};
use crate::engine_portable::EnginePortableEntry;
use crate::engine_types::{
    ConflictPayloadFfi, EngineDatabaseMetadata, EngineEntrySummary, EntryFull, EntrySave,
    EntryUpdate, GroupNode, GroupUpdate, HistoricEntry, IconRef, KdbxStateSignatureFfi,
    MergeResult, NewEntryFields, NewGroupFields, Page, ParkConflictsResultFfi, Predicate,
    SearchScope, SmartFolder, TagUsageCount, VaultState, parse_uuid,
};
use crate::merge::{
    AttachmentDeltaFfi, AttachmentDeltaKindFfi, DeleteEditConflictFfi, EntryConflictFfi,
    FieldDeltaFfi, FieldDeltaKindFfi, IconDeltaFfi, ResolutionFfi, resolution_ffi_to_km,
};
use crate::protector::{BridgeProtector, VaultFieldProtector};

/// FFI handle to a [`keys_engine::Engine`]. See module docs.
#[derive(uniffi::Object)]
pub struct Engine {
    inner: Mutex<Option<eng::Engine>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let open = self.inner.lock().expect("Engine mutex poisoned").is_some();
        f.debug_struct("Engine")
            .field("open", &open)
            .finish_non_exhaustive()
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Engine {
    /// Open (or create) the SQLCipher-encrypted SQLite database at `path`.
    ///
    /// `key_provider` is asked once for the 32-byte raw key.
    /// `field_protector` supplies session keys for AES-GCM (un)wrap of
    /// protected fields. `file_watcher`, when supplied, is registered
    /// for external-change events.
    ///
    /// # Errors
    ///
    /// - [`EngineError::KeyProvider`] if the provider can't materialise
    ///   a key.
    /// - [`EngineError::WrongKey`] if the supplied key doesn't decrypt
    ///   an existing database.
    /// - [`EngineError::Internal`] for any other engine open failure.
    #[uniffi::constructor]
    pub fn open(
        path: String,
        key_provider: Arc<dyn VaultDbKeyProvider>,
        field_protector: Arc<dyn VaultFieldProtector>,
        file_watcher: Option<Arc<dyn VaultFileWatcher>>,
    ) -> Result<Arc<Self>, EngineError> {
        let path_buf = PathBuf::from(path);
        let kp = BridgeDbKeyProvider::new(key_provider);
        let fp: Arc<dyn keepass_core::protector::FieldProtector> =
            Arc::new(BridgeProtector::new(field_protector));
        let watcher = engine_file_watcher::bridge(file_watcher);
        let inner = eng::Engine::open(&path_buf, &kp, fp, watcher)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(inner)),
        }))
    }

    /// Close the engine; subsequent method calls return
    /// [`EngineError::NotFound`] (`entity = "engine"`). Idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Internal`] if the underlying SQLite
    /// connection can't be finalised cleanly. The handle is dropped
    /// regardless.
    pub fn close(&self) -> Result<(), EngineError> {
        if let Some(eng) = self.inner.lock().expect("Engine mutex poisoned").take() {
            eng.close()?;
        }
        Ok(())
    }

    /// Current lifecycle/health state.
    pub fn state(&self) -> Result<VaultState, EngineError> {
        self.with_engine(|e| Ok(e.state().into()))
    }

    /// The `(mtime, size)` signature of the KDBX file whose contents the
    /// engine's SQLite mirror currently corresponds to, or `None` if
    /// no ingest / save has happened yet on this database.
    ///
    /// Recorded automatically after a successful `ingest_from_kdbx` or
    /// `save_to_kdbx` call. Persisted in the SQLite settings table so
    /// the value survives engine close + reopen.
    ///
    /// Frontends use this on unlock to skip re-ingest when the on-disk
    /// KDBX hasn't changed since the last sync (`stat` the file, build
    /// the same `(mtime_ms, byte_count)`, compare). Swift: take
    /// `FileManager.attributesOfItem(atPath:)`'s `.modificationDate`
    /// (`* 1000` for ms) and `.fileSizeKey`.
    pub fn kdbx_state_signature(&self) -> Result<Option<KdbxStateSignatureFfi>, EngineError> {
        self.with_engine(|e| Ok(e.kdbx_state_signature()?.map(Into::into)))
    }

    /// Hex-encoded SHA-256 digest of the vault's user-visible content
    /// (fields, locations, icons, group tree, recycle-bin state —
    /// history/timestamps/tombstones excluded). Equal digests ⇔
    /// converged replicas, for digests produced by the same build;
    /// never persist the value. See
    /// [`keys_engine::Engine::content_digest`] and the scope contract
    /// in `keepass_merge::digest`. Driving consumer is keyhole's
    /// sync-convergence assertions.
    ///
    /// **Treat the value as secret-adjacent.** Its preimage includes
    /// plaintext field values with no salt or KDF, so a leaked digest
    /// is an offline guessing oracle against a vault whose other
    /// contents are known. Compare in memory; never log it, write it
    /// to disk, or send it off-device.
    ///
    /// Walks the whole mirror (including unwrapping protected fields),
    /// so it is not free on large vaults — a test/diagnostics surface,
    /// not a per-frame one.
    pub fn content_digest(&self) -> Result<String, EngineError> {
        self.with_engine(|e| Ok(crate::merge::hex_encode(e.content_digest()?)))
    }

    // ────────────────────────────────────────────────────────────────────
    // Observers
    // ────────────────────────────────────────────────────────────────────

    /// Install the data-change observer. Replaces any prior observer.
    pub fn set_observer(
        &self,
        observer: Arc<dyn VaultDataChangeObserver>,
    ) -> Result<(), EngineError> {
        self.with_engine_mut(|e| {
            e.set_observer(Arc::new(BridgeObserver { inner: observer }));
            Ok(())
        })
    }

    /// Remove any installed data-change observer.
    pub fn clear_observer(&self) -> Result<(), EngineError> {
        self.with_engine_mut(|e| {
            e.clear_observer();
            Ok(())
        })
    }

    // ────────────────────────────────────────────────────────────────────
    // Reads
    // ────────────────────────────────────────────────────────────────────

    pub fn list_entries(
        &self,
        group_uuid: Option<String>,
        page: Page,
    ) -> Result<Vec<EngineEntrySummary>, EngineError> {
        let group = group_uuid
            .as_deref()
            .map(|s| parse_uuid(s, "group"))
            .transpose()?;
        self.with_engine(|e| {
            Ok(e.list_entries(group, page.into())?
                .into_iter()
                .map(Into::into)
                .collect())
        })
    }

    pub fn entry(&self, uuid: String) -> Result<Option<EntryFull>, EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine(|e| Ok(e.entry(u)?.map(Into::into)))
    }

    pub fn entry_count(&self, group_uuid: Option<String>) -> Result<u64, EngineError> {
        let group = group_uuid
            .as_deref()
            .map(|s| parse_uuid(s, "group"))
            .transpose()?;
        self.with_engine(|e| Ok(e.entry_count(group)?))
    }

    pub fn group_tree(&self) -> Result<Vec<GroupNode>, EngineError> {
        self.with_engine(|e| Ok(e.group_tree()?.into_iter().map(Into::into).collect()))
    }

    /// Return the parent group's UUID for `child_uuid` as a string, or
    /// `None` if `child_uuid` is the root group.
    ///
    /// Mirrors the legacy `Vault::group_parent_uuid(childUuid:)` shape
    /// so Swift call sites migrating off the in-memory `Vault` swap
    /// the receiver and otherwise leave the call unchanged.
    pub fn group_parent_uuid(&self, child_uuid: String) -> Result<Option<String>, EngineError> {
        let u = parse_uuid(&child_uuid, "group")?;
        self.with_engine(|e| Ok(e.group_parent_uuid(u)?.map(|p| p.to_string())))
    }

    /// `true` if `group_uuid` is at any depth inside the subtree
    /// rooted at `ancestor_uuid`. Not inclusive — a group is not its
    /// own descendant.
    pub fn is_descendant_of(
        &self,
        group_uuid: String,
        ancestor_uuid: String,
    ) -> Result<bool, EngineError> {
        let g = parse_uuid(&group_uuid, "group")?;
        let a = parse_uuid(&ancestor_uuid, "group")?;
        self.with_engine(|e| Ok(e.is_descendant_of(g, a)?))
    }

    pub fn list_tags(&self) -> Result<Vec<String>, EngineError> {
        self.with_engine(|e| Ok(e.list_tags()?))
    }

    /// See [`keys_engine::Engine::tag_usage_counts`].
    pub fn tag_usage_counts(&self) -> Result<Vec<TagUsageCount>, EngineError> {
        self.with_engine(|e| {
            Ok(e.tag_usage_counts()?
                .into_iter()
                .map(|(name, count)| TagUsageCount { name, count })
                .collect())
        })
    }

    // ── Meta surface ───────────────────────────────────────────────────

    /// See [`keys_engine::Engine::recycle_bin_uuid`].
    pub fn recycle_bin_uuid(&self) -> Result<Option<String>, EngineError> {
        self.with_engine(|e| Ok(e.recycle_bin_uuid()?))
    }

    /// See [`keys_engine::Engine::recycle_bin_enabled`].
    pub fn recycle_bin_enabled(&self) -> Result<bool, EngineError> {
        self.with_engine(|e| Ok(e.recycle_bin_enabled()?))
    }

    /// See [`keys_engine::Engine::history_max_items`].
    pub fn history_max_items(&self) -> Result<i32, EngineError> {
        self.with_engine(|e| Ok(e.history_max_items()?))
    }

    /// See [`keys_engine::Engine::database_metadata`]. Backs the
    /// Keys-Mac `DatabaseEditorView` properties pane (generator,
    /// cipher, KDF, attachment-pool stats) — final retirement of
    /// `DatabaseDocument.ffiVault` in Phase 6.17-I-3d.
    pub fn database_metadata(&self) -> Result<EngineDatabaseMetadata, EngineError> {
        self.with_engine(|e| Ok(e.database_metadata()?.into()))
    }

    /// See [`keys_engine::Engine::history_max_size`].
    pub fn history_max_size(&self) -> Result<i64, EngineError> {
        self.with_engine(|e| Ok(e.history_max_size()?))
    }

    /// See [`keys_engine::Engine::set_recycle_bin`]. `group_uuid` is
    /// the canonical lowercase UUID string of the bin group, or `None`
    /// to clear the bin designation. A malformed `group_uuid` surfaces
    /// as [`EngineError::NotFound`] with `entity = "group"`, mirroring
    /// every other engine-FFI parse path.
    pub fn set_recycle_bin(
        &self,
        enabled: bool,
        group_uuid: Option<String>,
    ) -> Result<(), EngineError> {
        let parsed = match group_uuid {
            Some(s) => Some(parse_uuid(&s, "group")?),
            None => None,
        };
        self.with_engine_mut(|e| Ok(e.set_recycle_bin(enabled, parsed)?))
    }

    /// See [`keys_engine::Engine::ensure_recycle_bin`]. Call once when a
    /// vault is first added so an enabled-but-binless vault gets its bin
    /// group created up front (before sync). Idempotent; returns the bin
    /// uuid if one exists/was created.
    pub fn ensure_recycle_bin(&self) -> Result<Option<String>, EngineError> {
        self.with_engine_mut(|e| Ok(e.ensure_recycle_bin()?))
    }

    /// See [`keys_engine::Engine::set_history_max_items`].
    pub fn set_history_max_items(&self, max: i32) -> Result<(), EngineError> {
        self.with_engine_mut(|e| Ok(e.set_history_max_items(max)?))
    }

    /// See [`keys_engine::Engine::set_history_max_size`].
    pub fn set_history_max_size(&self, max: i64) -> Result<(), EngineError> {
        self.with_engine_mut(|e| Ok(e.set_history_max_size(max)?))
    }

    /// See [`keys_engine::Engine::add_custom_icon`]. Returns the icon's
    /// UUID as a string (fresh on insert, the existing one on a
    /// SHA-256 dedup hit).
    pub fn add_custom_icon(&self, png_bytes: Vec<u8>) -> Result<String, EngineError> {
        self.with_engine_mut(|e| Ok(e.add_custom_icon(&png_bytes)?))
    }

    /// See [`keys_engine::Engine::clear_entry_custom_icon`]. Nulls the
    /// entry's `icon_custom_uuid` column; the blob in `meta_custom_icon`
    /// is left in place.
    pub fn clear_entry_custom_icon(&self, entry_uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.clear_entry_custom_icon(u)?))
    }

    /// See [`keys_engine::Engine::link_entry_custom_icon`]. Sets the
    /// entry's custom icon to a fetched favicon WITHOUT archiving a
    /// history snapshot or bumping `modified_at` — a favicon is cosmetic
    /// enrichment, not a user edit. The user-driven icon picker uses
    /// `update_entry` (which archives + bumps) instead.
    pub fn link_entry_custom_icon(
        &self,
        entry_uuid: String,
        icon_uuid: String,
    ) -> Result<(), EngineError> {
        let entry = parse_uuid(&entry_uuid, "entry")?;
        let icon = parse_uuid(&icon_uuid, "custom_icon")?;
        self.with_engine_mut(|e| Ok(e.link_entry_custom_icon(entry, icon)?))
    }

    /// See [`keys_engine::Engine::touch_entry`]. Bumps the entry's
    /// `last_used_at` to now without touching `modified_at`; emits the
    /// quiet `ChangeEvent::EntryTouched` event so listeners can avoid
    /// re-rendering full entry detail.
    pub fn touch_entry(&self, entry_uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.touch_entry(u)?))
    }

    /// See [`keys_engine::Engine::clear_entry_last_access`]. Sets the
    /// entry's `last_used_at` back to NULL; emits
    /// `ChangeEvent::EntriesUpdated` (this is a user-driven explicit
    /// clear from the entry detail editor).
    pub fn clear_entry_last_access(&self, entry_uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.clear_entry_last_access(u)?))
    }

    /// See [`keys_engine::Engine::custom_icon_bytes`]. Returns `None`
    /// if no icon with that UUID is in the pool.
    pub fn custom_icon_bytes(&self, uuid: String) -> Result<Option<Vec<u8>>, EngineError> {
        let u = parse_uuid(&uuid, "custom_icon")?;
        self.with_engine(|e| Ok(e.custom_icon_bytes(u)?))
    }

    pub fn search(
        &self,
        query: String,
        scope: SearchScope,
        page: Page,
    ) -> Result<Vec<EngineEntrySummary>, EngineError> {
        self.with_engine(|e| {
            Ok(e.search(&query, scope.into(), page.into())?
                .into_iter()
                .map(Into::into)
                .collect())
        })
    }

    /// See [`keys_engine::Engine::search_by_service`].
    pub fn search_by_service(
        &self,
        identifier: String,
        limit: u64,
    ) -> Result<Vec<EngineEntrySummary>, EngineError> {
        let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
        self.with_engine(|e| {
            Ok(e.search_by_service(&identifier, limit_usize)?
                .into_iter()
                .map(Into::into)
                .collect())
        })
    }

    // ── Smart folders ──────────────────────────────────────────────────

    pub fn list_smart_folders(&self) -> Result<Vec<SmartFolder>, EngineError> {
        self.with_engine(|e| {
            Ok(e.list_smart_folders()?
                .into_iter()
                .map(Into::into)
                .collect())
        })
    }

    pub fn smart_folder(&self, id: i64) -> Result<Option<SmartFolder>, EngineError> {
        self.with_engine(|e| Ok(e.smart_folder(id)?.map(Into::into)))
    }

    pub fn smart_folder_entries(
        &self,
        folder_id: i64,
        page: Page,
    ) -> Result<Vec<EngineEntrySummary>, EngineError> {
        self.with_engine(|e| {
            Ok(e.smart_folder_entries(folder_id, page.into())?
                .into_iter()
                .map(Into::into)
                .collect())
        })
    }

    pub fn smart_folder_count(&self, folder_id: i64) -> Result<u64, EngineError> {
        self.with_engine(|e| Ok(e.smart_folder_count(folder_id)?))
    }

    pub fn entries_matching(
        &self,
        predicate: Predicate,
        page: Page,
    ) -> Result<Vec<EngineEntrySummary>, EngineError> {
        let pred: eng::Predicate = predicate.try_into()?;
        self.with_engine(|e| {
            Ok(e.entries_matching(&pred, page.into())?
                .into_iter()
                .map(Into::into)
                .collect())
        })
    }

    pub fn count_matching(&self, predicate: Predicate) -> Result<u64, EngineError> {
        let pred: eng::Predicate = predicate.try_into()?;
        self.with_engine(|e| Ok(e.count_matching(&pred)?))
    }

    pub fn create_smart_folder(
        &self,
        name: String,
        predicate: Predicate,
    ) -> Result<i64, EngineError> {
        let pred: eng::Predicate = predicate.try_into()?;
        self.with_engine_mut(|e| Ok(e.create_smart_folder(&name, &pred)?))
    }

    pub fn update_smart_folder(
        &self,
        id: i64,
        name: String,
        predicate: Predicate,
    ) -> Result<(), EngineError> {
        let pred: eng::Predicate = predicate.try_into()?;
        self.with_engine_mut(|e| Ok(e.update_smart_folder(id, &name, &pred)?))
    }

    pub fn delete_smart_folder(&self, id: i64) -> Result<(), EngineError> {
        self.with_engine_mut(|e| Ok(e.delete_smart_folder(id)?))
    }

    // ── Reveal ─────────────────────────────────────────────────────────

    /// Reveal the canonical Password slot. Plaintext crosses as a
    /// `String` — the caller is responsible for clearing copies
    /// aggressively (uniffi can't preserve zeroize-on-drop into
    /// Swift/Kotlin strings).
    pub fn reveal_password(&self, uuid: String) -> Result<String, EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine(|e| Ok(e.reveal_password(u)?.expose_secret().to_owned()))
    }

    /// Reveal a custom field's plaintext. See [`Self::reveal_password`]
    /// for the lifetime caveat.
    pub fn reveal_custom_field(
        &self,
        uuid: String,
        field_name: String,
    ) -> Result<String, EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine(|e| {
            Ok(e.reveal_custom_field(u, &field_name)?
                .expose_secret()
                .to_owned())
        })
    }

    /// Read the value of a non-protected custom field. Counterpart to
    /// [`Self::reveal_custom_field`] for fields stored in plaintext in
    /// `entry_custom_field`. Returns `None` when no row matches
    /// `(uuid, field_name)` — either the field is protected (use
    /// `reveal_custom_field` instead) or doesn't exist.
    pub fn non_protected_custom_field(
        &self,
        uuid: String,
        field_name: String,
    ) -> Result<Option<String>, EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine(|e| Ok(e.non_protected_custom_field(u, &field_name)?))
    }

    /// Reveal a field on a historical snapshot.
    pub fn reveal_history_field(
        &self,
        uuid: String,
        history_index: u32,
        field_name: String,
    ) -> Result<String, EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine(|e| {
            Ok(e.reveal_history_field(u, history_index, &field_name)?
                .expose_secret()
                .to_owned())
        })
    }

    /// Reveal a single field on the local side of a stashed conflict.
    ///
    /// Companion to [`Self::pending_conflict`] for the resolver UI's
    /// hover-reveal: the peek payload carries field-level diffs but
    /// redacts protected values; this method lets the frontend fetch
    /// cleartext for one field on the local side on demand. Plaintext
    /// crosses as a `String` — uniffi can't preserve zeroize-on-drop
    /// into Swift/Kotlin strings, so the caller is responsible for
    /// clearing copies aggressively (same caveat as
    /// [`Self::reveal_password`]).
    pub fn reveal_conflict_local_field(
        &self,
        conflict_id: i64,
        entry_uuid: String,
        field_name: String,
    ) -> Result<String, EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine(|e| {
            Ok(e.reveal_conflict_local_field(conflict_id, u, &field_name)?
                .expose_secret()
                .to_owned())
        })
    }

    /// Reveal a single field on the remote side of a stashed conflict.
    ///
    /// Sibling of [`Self::reveal_conflict_local_field`]; reads from
    /// the remote-side vault in the stash. Same zeroize caveat applies.
    pub fn reveal_conflict_remote_field(
        &self,
        conflict_id: i64,
        entry_uuid: String,
        field_name: String,
    ) -> Result<String, EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine(|e| {
            Ok(e.reveal_conflict_remote_field(conflict_id, u, &field_name)?
                .expose_secret()
                .to_owned())
        })
    }

    // ── History ────────────────────────────────────────────────────────

    pub fn history(&self, uuid: String) -> Result<Vec<HistoricEntry>, EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine(|e| Ok(e.history(u)?.into_iter().map(Into::into).collect()))
    }

    // ── Attachments ────────────────────────────────────────────────────

    /// Fetch the raw bytes of a named attachment on an entry.
    ///
    /// Sync — attachment blobs are small enough (KDBX stores them
    /// inline) that the underlying SQLite read is sub-millisecond.
    /// Returns the content-addressed blob bytes; clients hash + cache
    /// out-of-band if they need to.
    pub fn attachment_bytes(
        &self,
        uuid: String,
        attachment_name: String,
    ) -> Result<Vec<u8>, EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine(|e| Ok(e.attachment_bytes(u, &attachment_name)?))
    }

    /// Fetch the bytes of an attachment as it existed in a specific
    /// history snapshot of an entry. See
    /// [`keys_engine::Engine::history_attachment_bytes`] for the full
    /// resolution chain.
    pub fn history_attachment_bytes(
        &self,
        uuid: String,
        history_index: u32,
        attachment_name: String,
    ) -> Result<Vec<u8>, EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine(|e| Ok(e.history_attachment_bytes(u, history_index, &attachment_name)?))
    }

    // ────────────────────────────────────────────────────────────────────
    // Mutations (sync — each is one transaction)
    // ────────────────────────────────────────────────────────────────────

    pub fn create_entry(
        &self,
        group_uuid: String,
        fields: NewEntryFields,
    ) -> Result<String, EngineError> {
        let g = parse_uuid(&group_uuid, "group")?;
        let f: eng::NewEntryFields = fields.try_into()?;
        self.with_engine_mut(|e| Ok(e.create_entry(g, f)?.to_string()))
    }

    pub fn update_entry(&self, uuid: String, update: EntryUpdate) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        let upd: eng::EntryUpdate = update.try_into()?;
        self.with_engine_mut(|e| Ok(e.update_entry(u, upd)?))
    }

    /// See [`keys_engine::Engine::save_entry`]. Applies the full desired
    /// entry state in ONE transaction with EXACTLY ONE history snapshot
    /// — the entry editor's single "Save" funnel, replacing the old
    /// sequence of per-field mutations that each archived their own
    /// snapshot. `custom_fields` is a replace-all set; `tags` is applied
    /// with set-semantics.
    pub fn save_entry(&self, uuid: String, save: EntrySave) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        let s: eng::EntrySave = save.try_into()?;
        self.with_engine_mut(|e| Ok(e.save_entry(u, s)?))
    }

    pub fn recycle_entry(&self, uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.recycle_entry(u)?))
    }

    pub fn restore_entry(&self, uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.restore_entry(u)?))
    }

    pub fn delete_entry(&self, uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.delete_entry(u)?))
    }

    pub fn move_entry(&self, uuid: String, new_group_uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        let g = parse_uuid(&new_group_uuid, "group")?;
        self.with_engine_mut(|e| Ok(e.move_entry(u, g)?))
    }

    pub fn set_protected_field(
        &self,
        uuid: String,
        field_name: String,
        plaintext: String,
    ) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        let pt = SecretString::from(plaintext);
        self.with_engine_mut(|e| Ok(e.set_protected_field(u, &field_name, pt)?))
    }

    pub fn set_non_protected_custom_field(
        &self,
        uuid: String,
        field_name: String,
        value: String,
    ) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.set_non_protected_custom_field(u, &field_name, &value)?))
    }

    pub fn remove_custom_field(&self, uuid: String, field_name: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.remove_custom_field(u, &field_name)?))
    }

    pub fn set_tags(&self, uuid: String, tags: Vec<String>) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.set_tags(u, tags)?))
    }

    pub fn attach_file(
        &self,
        uuid: String,
        name: String,
        bytes: Vec<u8>,
    ) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.attach_file(u, &name, bytes)?))
    }

    /// Add or replace an attachment by name. See
    /// [`keys_engine::Engine::set_attachment`] — content-addressed pool
    /// insert + per-entry link upsert, with a history snapshot first.
    pub fn set_attachment(
        &self,
        uuid: String,
        name: String,
        bytes: Vec<u8>,
    ) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.set_attachment(u, &name, &bytes)?))
    }

    pub fn remove_attachment(&self, uuid: String, name: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.remove_attachment(u, &name)?))
    }

    /// See [`keys_engine::Engine::delete_history_at`].
    pub fn delete_history_at(
        &self,
        entry_uuid: String,
        history_index: u32,
    ) -> Result<(), EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.delete_history_at(u, history_index)?))
    }

    /// See [`keys_engine::Engine::restore_entry_from_history`].
    pub fn restore_entry_from_history(
        &self,
        entry_uuid: String,
        history_index: u32,
    ) -> Result<(), EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.restore_entry_from_history(u, history_index)?))
    }

    /// See [`keys_engine::Engine::export_entry`]. Returns an opaque
    /// [`EnginePortableEntry`] handle the caller passes to
    /// [`Self::import_entry`] on the destination engine (or the same
    /// engine, for a within-database copy). The carrier is **single-use**
    /// — a second `import_entry` returns [`EngineError::Internal`].
    pub fn export_entry(
        &self,
        entry_uuid: String,
    ) -> Result<std::sync::Arc<EnginePortableEntry>, EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine(|e| {
            let portable = e.export_entry(u)?;
            Ok(std::sync::Arc::new(EnginePortableEntry::new(portable)))
        })
    }

    /// See [`keys_engine::Engine::import_entry`]. Consumes the carrier
    /// produced by [`Self::export_entry`] and returns the new entry's
    /// UUID. Custom-icon bytes (when present) are rehomed into the
    /// target engine's icon pool via SHA-256 dedup.
    pub fn import_entry(
        &self,
        portable: std::sync::Arc<EnginePortableEntry>,
        target_group_uuid: String,
    ) -> Result<String, EngineError> {
        let g = parse_uuid(&target_group_uuid, "group")?;
        let inner = portable.take()?;
        self.with_engine_mut(|e| Ok(e.import_entry(inner, g)?.to_string()))
    }

    pub fn create_group(
        &self,
        parent_uuid: String,
        fields: NewGroupFields,
    ) -> Result<String, EngineError> {
        let p = parse_uuid(&parent_uuid, "group")?;
        let f: eng::NewGroupFields = fields.try_into()?;
        self.with_engine_mut(|e| Ok(e.create_group(p, f)?.to_string()))
    }

    pub fn update_group(&self, uuid: String, update: GroupUpdate) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "group")?;
        let upd: eng::GroupUpdate = update.try_into()?;
        self.with_engine_mut(|e| Ok(e.update_group(u, upd)?))
    }

    pub fn recycle_group(&self, uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "group")?;
        self.with_engine_mut(|e| Ok(e.recycle_group(u)?))
    }

    pub fn restore_group(&self, uuid: String, new_parent_uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "group")?;
        let p = parse_uuid(&new_parent_uuid, "group")?;
        self.with_engine_mut(|e| Ok(e.restore_group(u, p)?))
    }

    pub fn delete_group(&self, uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "group")?;
        self.with_engine_mut(|e| Ok(e.delete_group(u)?))
    }

    pub fn move_group(&self, uuid: String, new_parent_uuid: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "group")?;
        let p = parse_uuid(&new_parent_uuid, "group")?;
        self.with_engine_mut(|e| Ok(e.move_group(u, p)?))
    }

    pub fn reorder_group(&self, uuid: String, new_position: u32) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "group")?;
        self.with_engine_mut(|e| Ok(e.reorder_group(u, new_position)?))
    }

    // ────────────────────────────────────────────────────────────────────
    // Slow ops (async — dispatched on tokio multi-thread runtime)
    // ────────────────────────────────────────────────────────────────────

    /// Ingest the KDBX file at `kdbx_path` (decrypted under `password`)
    /// into SQLite.
    ///
    /// Slow: full vault walk + AES-GCM wrap per protected field. Runs
    /// on the tokio runtime; the FFI side `await`s.
    pub async fn ingest_from_kdbx(
        &self,
        kdbx_path: String,
        password: String,
    ) -> Result<(), EngineError> {
        let path = PathBuf::from(kdbx_path);
        let pw = SecretString::from(password);
        let path_for_open = path.clone();
        let result = tokio::task::spawn_blocking(move || open_unlocked(&path_for_open, &pw))
            .await
            .map_err(|e| EngineError::Internal(format!("join: {e}")))??;
        self.with_engine_mut(|e| {
            e.ingest_from_kdbx(&result)?;
            // Record the post-ingest kdbx-state signature so the
            // frontend can skip re-ingest on a later unlock when the
            // on-disk KDBX hasn't changed. `save_to_kdbx` records the
            // same signature internally; only `ingest_from_kdbx` needs
            // the path threaded through here (the engine method
            // doesn't take one — kept that way to avoid churning every
            // existing call site).
            e.record_kdbx_state_signature(&path)?;
            Ok(())
        })
    }

    /// Project SQLite state into a KDBX at `kdbx_path` (the file at
    /// `kdbx_path` is used as the crypto envelope template — it must
    /// already exist and decrypt under `password`).
    ///
    /// `temp_dir`, when supplied, is used as the directory for the
    /// atomic-write tempfile instead of `kdbx_path`'s parent. macOS
    /// callers saving to iCloud Drive should pass
    /// `NSTemporaryDirectory()` here: the sandbox's security-scoped
    /// bookmark grants write to the kdbx file but not its surrounding
    /// folder, so the default sibling-tempfile path fails with EPERM.
    /// The override must live on the same filesystem volume as
    /// `kdbx_path` (rename is not cross-volume atomic). Pass `None`
    /// on non-sandboxed platforms to keep the historical behaviour.
    pub async fn save_to_kdbx(
        &self,
        kdbx_path: String,
        password: String,
        temp_dir: Option<String>,
    ) -> Result<(), EngineError> {
        let path = PathBuf::from(kdbx_path);
        let pw = SecretString::from(password);
        let temp_dir = temp_dir.map(PathBuf::from);
        let path_for_open = path.clone();
        let mut kdbx = tokio::task::spawn_blocking(move || open_unlocked(&path_for_open, &pw))
            .await
            .map_err(|e| EngineError::Internal(format!("join: {e}")))??;
        self.with_engine_mut(|e| Ok(e.save_to_kdbx(&path, &mut kdbx, temp_dir.as_deref())?))
    }

    /// Reconcile SQLite against the on-disk KDBX at `kdbx_path`.
    pub async fn reconcile_with_disk(
        &self,
        kdbx_path: String,
        password: String,
    ) -> Result<MergeResult, EngineError> {
        let path = PathBuf::from(kdbx_path);
        let pw = SecretString::from(password);
        // Build the composite key off-thread (cheap, but matches the
        // async-everywhere posture for slow ops).
        let composite = tokio::task::spawn_blocking(move || {
            CompositeKey::from_password(pw.expose_secret().as_bytes())
        })
        .await
        .map_err(|e| EngineError::Internal(format!("join: {e}")))?;
        self.with_engine_mut(|e| Ok(e.reconcile_with_disk(&path, &composite)?.into()))
    }

    /// Park-conflicts variant of [`Self::reconcile_with_disk`]. See
    /// [`keys_engine::Engine::reconcile_with_disk_park_conflicts`].
    ///
    /// Returned `ParkConflictsResultFfi::Applied` carries the
    /// per-bucket stats AND a parked-conflicts summary the frontend
    /// reads to drive UX (e.g. "we parked 3 conflicts — review when
    /// ready"). No `Conflict` variant: this method never blocks.
    pub async fn reconcile_with_disk_park_conflicts(
        &self,
        kdbx_path: String,
        password: String,
    ) -> Result<ParkConflictsResultFfi, EngineError> {
        let path = PathBuf::from(kdbx_path);
        let pw = SecretString::from(password);
        let composite = tokio::task::spawn_blocking(move || {
            CompositeKey::from_password(pw.expose_secret().as_bytes())
        })
        .await
        .map_err(|e| EngineError::Internal(format!("join: {e}")))?;
        self.with_engine_mut(|e| {
            Ok(
                e.reconcile_with_disk_park_conflicts(&path, &composite, chrono::Utc::now())?
                    .into(),
            )
        })
    }

    /// Per-device-key sync transport: ingest a fetched peer KDBX blob (written
    /// to a temp path) under the peer's `owner_id` (its device id), so multi-
    /// peer divergences land in distinct owner rows. Sibling of
    /// [`Self::reconcile_with_disk_park_conflicts`], which uses the FILE_OWNER
    /// sentinel for the disk-watcher path.
    pub async fn ingest_peer_kdbx(
        &self,
        owner_id: String,
        kdbx_path: String,
        password: String,
    ) -> Result<ParkConflictsResultFfi, EngineError> {
        let path = PathBuf::from(kdbx_path);
        let pw = SecretString::from(password);
        let composite = tokio::task::spawn_blocking(move || {
            CompositeKey::from_password(pw.expose_secret().as_bytes())
        })
        .await
        .map_err(|e| EngineError::Internal(format!("join: {e}")))?;
        self.with_engine_mut(|e| {
            Ok(e.ingest_peer_from_kdbx(&path, &composite, &owner_id)?
                .into())
        })
    }

    /// Build the rich conflict payload for the currently **held** (parked)
    /// conflicts and stash a context so they can be resolved through the same
    /// [`Self::apply_conflict_resolution`] entry point the live
    /// [`Self::reconcile_with_disk`] path uses.
    ///
    /// This is the resolver-open companion to
    /// [`Self::entries_with_parked_conflict`] (which only drives the badge):
    /// it returns the same icon-aware [`ConflictPayloadFfi`] the live path
    /// produces — per-entry field / icon / attachment deltas plus the stash
    /// `id` to echo back to [`Self::apply_conflict_resolution`]. The badge
    /// survives relaunch but the rich payload does not, so Keys-Mac calls
    /// this when the user opens the resolver. Returns `None` when no conflict
    /// remains (e.g. a peer resolved it and the resolution record has synced
    /// in). See [`keys_engine::Engine::held_conflict_payload`].
    pub async fn held_conflict_payload(
        &self,
        kdbx_path: String,
        password: String,
        entry_uuid: Option<String>,
    ) -> Result<Option<ConflictPayloadFfi>, EngineError> {
        let path = PathBuf::from(kdbx_path);
        let pw = SecretString::from(password);
        // Scope the resolution session to one entry (one-at-a-time resolver):
        // `None` lets the engine pick the first held entry. See
        // `keys_engine::Engine::held_conflict_payload`.
        let entry_filter = entry_uuid
            .as_deref()
            .map(|u| parse_uuid(u, "entry"))
            .transpose()?;
        let composite = tokio::task::spawn_blocking(move || {
            CompositeKey::from_password(pw.expose_secret().as_bytes())
        })
        .await
        .map_err(|e| EngineError::Internal(format!("join: {e}")))?;
        self.with_engine_mut(|e| {
            match e.held_conflict_payload(&path, &composite, entry_filter)? {
                Some(payload) => Ok(build_conflict_payload_ffi(e, payload.id)),
                None => Ok(None),
            }
        })
    }

    /// Return the UUIDs of every entry currently **held** in an unresolved
    /// sync conflict. Drives Keys-Mac's vault-tile warning triangle and the
    /// per-entry conflict badge. Reads the engine's derived held-conflict set
    /// (refreshed on each park reconcile); see
    /// [`keys_engine::Engine::entries_with_parked_conflict`].
    pub fn entries_with_parked_conflict(&self) -> Result<Vec<String>, EngineError> {
        self.with_engine(|e| {
            Ok(e.entries_with_parked_conflict()?
                .into_iter()
                .map(|u| u.to_string())
                .collect())
        })
    }

    /// Dismiss the held-conflict badge on `entry_uuid` locally (drop it from
    /// the derived held set) and clean up any legacy `keys.field_conflict.v1`
    /// history markers from older builds. Cross-peer convergence is driven by
    /// the resolution record [`Self::apply_conflict_resolution`] writes — not
    /// by this call. See
    /// [`keys_engine::Engine::clear_parked_conflict_marker`].
    pub fn clear_parked_conflict_marker(&self, entry_uuid: String) -> Result<u32, EngineError> {
        let u = parse_uuid(&entry_uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.clear_parked_conflict_marker(u, chrono::Utc::now())?))
    }

    /// Peek the stashed [`ConflictPayloadFfi`] for `id` without
    /// consuming it.
    ///
    /// The frontend calls this after receiving a
    /// `ChangeEvent::ConflictDetected { id }` observer notification (or
    /// after a `reconcile_with_disk` call that returned
    /// `MergeResult::Conflict { id }`) to render the resolver UI. The
    /// payload is a clone — repeated calls with the same `id` return
    /// the same data until [`Self::apply_conflict_resolution`]
    /// consumes the matching context, at which point this returns
    /// `None` for that id.
    ///
    /// Per-side parent group resolution mirrors the slice-7.5
    /// [`MergeOutcome::entry_conflicts`](crate::merge::MergeOutcome)
    /// surface: local-side wins on disagreement; either side fills in
    /// if the other can't find the entry under a known parent
    /// (in-flight group-tree change). When neither side can find the
    /// entry — a contract violation we don't expect in practice — the
    /// parent uuid falls back to the nil UUID.
    pub fn pending_conflict(&self, id: i64) -> Result<Option<ConflictPayloadFfi>, EngineError> {
        self.with_engine(|e| Ok(build_conflict_payload_ffi(e, id)))
    }

    /// Apply a user-resolved conflict.
    ///
    /// Marked `async` for symmetry with the other slow ops even though
    /// the body is currently sync — the validation pass + apply walk
    /// run in-thread. If a future refactor pushes the apply onto a
    /// blocking pool, this signature is already ready.
    #[allow(clippy::unused_async)]
    pub async fn apply_conflict_resolution(
        &self,
        id: i64,
        resolution: ResolutionFfi,
    ) -> Result<(), EngineError> {
        let km_resolution =
            resolution_ffi_to_km(&resolution).map_err(|e| EngineError::ResolutionMismatch {
                reason: e.to_string(),
            })?;
        self.with_engine_mut(|e| Ok(e.apply_conflict_resolution(id, &km_resolution)?))
    }

    /// Discard a stashed conflict by `id` without resolving it.
    ///
    /// The resolver-open path ([`Self::held_conflict_payload`]) and the
    /// live [`Self::reconcile_with_disk`] path both stash a rich payload
    /// plus a context (two in-memory vaults — sizeable on a big vault)
    /// keyed by `id`. [`Self::apply_conflict_resolution`] consumes that
    /// stash, but a resolver the user dismisses with "Resolve Later"
    /// never resolves — so Keys-Mac calls this on dismiss to drop the
    /// otherwise-orphaned stash (repeated open/dismiss would leak one
    /// per round until vault lock).
    ///
    /// Idempotent: an unknown / already-consumed `id` is a no-op. The
    /// held-conflict badge ([`Self::entries_with_parked_conflict`])
    /// stays put — the conflict is still real, just not open in a
    /// resolver, and a fresh `held_conflict_payload` rebuilds the stash.
    /// See [`keys_engine::Engine::discard_conflict`].
    ///
    /// # Errors
    ///
    /// [`EngineError::NotFound`] (`entity = "engine"`) if the vault is
    /// already locked — in which case the stash is gone anyway.
    pub fn discard_conflict(&self, id: i64) -> Result<(), EngineError> {
        self.with_engine(|e| {
            e.discard_conflict(id);
            Ok(())
        })
    }

    // ────────────────────────────────────────────────────────────────────
    // Internals
    // ────────────────────────────────────────────────────────────────────
}

impl Engine {
    fn with_engine<R>(
        &self,
        f: impl FnOnce(&eng::Engine) -> Result<R, EngineError>,
    ) -> Result<R, EngineError> {
        let guard = self.inner.lock().expect("Engine mutex poisoned");
        let eng = guard.as_ref().ok_or(EngineError::NotFound {
            entity: "engine".to_owned(),
        })?;
        f(eng)
    }

    fn with_engine_mut<R>(
        &self,
        f: impl FnOnce(&mut eng::Engine) -> Result<R, EngineError>,
    ) -> Result<R, EngineError> {
        let mut guard = self.inner.lock().expect("Engine mutex poisoned");
        let eng = guard.as_mut().ok_or(EngineError::NotFound {
            entity: "engine".to_owned(),
        })?;
        f(eng)
    }
}

// Silence the unused-import warning for IconRef — re-exported via
// engine_types.
#[allow(dead_code)]
fn _icon_ref_keepalive(_: IconRef) {}

/// Translate a peek of [`keys_engine::Engine::pending_conflict`] +
/// [`keys_engine::Engine::pending_conflict_parent_groups`] into the
/// wire-friendly [`ConflictPayloadFfi`]. `None` propagates from the
/// engine — either id is unknown or the matching context was already
/// consumed.
fn build_conflict_payload_ffi(engine: &eng::Engine, id: i64) -> Option<ConflictPayloadFfi> {
    use keepass_core::model::GroupId;

    let payload = engine.pending_conflict(id)?;
    // Both maps are populated atomically by the reconcile path; if the
    // payload is present, the parent-groups map is too. Defensive
    // fallback to an empty map keeps the FFI surface total even if a
    // future engine change drops that invariant.
    let parents = engine
        .pending_conflict_parent_groups(id)
        .unwrap_or_default();
    let nil_group = GroupId(uuid::Uuid::nil());

    let entry_conflicts = payload
        .entry_conflicts
        .iter()
        .map(|c| {
            let p = parents.get(&c.entry_id);
            let local_pid = p.and_then(|p| p.local.or(p.remote)).unwrap_or(nil_group);
            let remote_pid = p.and_then(|p| p.remote.or(p.local)).unwrap_or(nil_group);
            EntryConflictFfi {
                entry_uuid: c.entry_id.0.to_string(),
                local: crate::dto::Entry::from_entry(&c.local, local_pid),
                remote: crate::dto::Entry::from_entry(&c.remote, remote_pid),
                field_deltas: c
                    .field_deltas
                    .iter()
                    .map(|d| FieldDeltaFfi {
                        key: d.key.clone(),
                        kind: FieldDeltaKindFfi::from(d.kind),
                    })
                    .collect(),
                attachment_deltas: c
                    .attachment_deltas
                    .iter()
                    .map(|d| AttachmentDeltaFfi {
                        name: d.name.clone(),
                        kind: AttachmentDeltaKindFfi::from(d.kind),
                        local_sha256_hex: d.local_sha256.map(hex_encode_32),
                        remote_sha256_hex: d.remote_sha256.map(hex_encode_32),
                        local_size_bytes: d.local_size,
                        remote_size_bytes: d.remote_size,
                    })
                    .collect(),
                icon_delta: c.icon_delta.as_ref().map(|d| IconDeltaFfi {
                    local_custom_icon_uuid: d.local_custom_icon_uuid.map(|u| u.to_string()),
                    remote_custom_icon_uuid: d.remote_custom_icon_uuid.map(|u| u.to_string()),
                }),
            }
        })
        .collect();

    let delete_edit_conflicts = payload
        .delete_edit_conflicts
        .iter()
        .map(|entry_id| DeleteEditConflictFfi {
            entry_uuid: entry_id.0.to_string(),
            // The slice-7.5 [`MergeOutcome`] surface eagerly carries
            // the local-side entry snapshot here; the engine path
            // surfaces the uuid only and the frontend pulls the
            // entry via [`Self::entry`] when it wants title context.
            // Plumbing the snapshot through would require a third
            // engine accessor; future work if the resolver UI flow
            // turns out to need it inline.
            local: None,
        })
        .collect();
    let _ = nil_group; // silence unused when delete_edit branch is empty.

    Some(ConflictPayloadFfi {
        id: payload.id,
        entry_conflicts,
        delete_edit_conflicts,
    })
}

fn hex_encode_32(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("writing to a String never fails");
    }
    s
}

/// Open the KDBX file at `path`, unlocking under `password`. Pulled out
/// so the three async-slow-op methods can `spawn_blocking` it without
/// repeating the open dance.
fn open_unlocked(
    path: &std::path::Path,
    password: &SecretString,
) -> Result<Kdbx<keepass_core::kdbx::Unlocked>, EngineError> {
    let composite = CompositeKey::from_password(password.expose_secret().as_bytes());
    Kdbx::open(path)
        .and_then(keepass_core::kdbx::Kdbx::<keepass_core::kdbx::Sealed>::read_header)
        .and_then(|k| k.unlock(&composite))
        .map_err(|e| EngineError::Internal(format!("open kdbx: {e}")))
}
