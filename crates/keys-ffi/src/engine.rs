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
use crate::engine_types::{
    ConflictPayloadFfi, EngineEntrySummary, EntryFull, EntryUpdate, GroupNode, GroupUpdate,
    HistoricEntry, IconRef, MergeResult, NewEntryFields, NewGroupFields, Page, Predicate,
    SmartFolder, VaultState, parse_uuid,
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

    pub fn list_tags(&self) -> Result<Vec<String>, EngineError> {
        self.with_engine(|e| Ok(e.list_tags()?))
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

    /// See [`keys_engine::Engine::history_max_size`].
    pub fn history_max_size(&self) -> Result<i64, EngineError> {
        self.with_engine(|e| Ok(e.history_max_size()?))
    }

    /// See [`keys_engine::Engine::set_history_max_items`].
    pub fn set_history_max_items(&self, max: i32) -> Result<(), EngineError> {
        self.with_engine_mut(|e| Ok(e.set_history_max_items(max)?))
    }

    /// See [`keys_engine::Engine::set_history_max_size`].
    pub fn set_history_max_size(&self, max: i64) -> Result<(), EngineError> {
        self.with_engine_mut(|e| Ok(e.set_history_max_size(max)?))
    }

    pub fn search(
        &self,
        query: String,
        page: Page,
    ) -> Result<Vec<EngineEntrySummary>, EngineError> {
        self.with_engine(|e| {
            Ok(e.search(&query, page.into())?
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

    pub fn remove_attachment(&self, uuid: String, name: String) -> Result<(), EngineError> {
        let u = parse_uuid(&uuid, "entry")?;
        self.with_engine_mut(|e| Ok(e.remove_attachment(u, &name)?))
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
        let result = tokio::task::spawn_blocking(move || open_unlocked(&path, &pw))
            .await
            .map_err(|e| EngineError::Internal(format!("join: {e}")))??;
        self.with_engine_mut(|e| Ok(e.ingest_from_kdbx(&result)?))
    }

    /// Project SQLite state into a KDBX at `kdbx_path` (the file at
    /// `kdbx_path` is used as the crypto envelope template — it must
    /// already exist and decrypt under `password`).
    pub async fn save_to_kdbx(
        &self,
        kdbx_path: String,
        password: String,
    ) -> Result<(), EngineError> {
        let path = PathBuf::from(kdbx_path);
        let pw = SecretString::from(password);
        let path_for_open = path.clone();
        let mut kdbx = tokio::task::spawn_blocking(move || open_unlocked(&path_for_open, &pw))
            .await
            .map_err(|e| EngineError::Internal(format!("join: {e}")))??;
        self.with_engine_mut(|e| Ok(e.save_to_kdbx(&path, &mut kdbx)?))
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
