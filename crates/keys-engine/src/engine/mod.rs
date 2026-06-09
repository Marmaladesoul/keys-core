//! [`Engine`] — `SQLCipher`-backed `SQLite` handle.
//!
//! Holds an open [`rusqlite::Connection`] keyed via `PRAGMA key` using a
//! raw 32-byte key supplied by a [`KeyProvider`]. The engine never
//! derives a key from a passphrase — the input is already random bytes
//! sourced from the platform Keychain, so the raw-hex BLOB-literal
//! form (`PRAGMA key = "x'<hex>'"`) is used, bypassing `SQLCipher`'s
//! built-in PBKDF2 key derivation.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::FieldProtector;
use rusqlite::{Connection, OpenFlags};
use zeroize::Zeroizing;

use crate::error::EngineError;
use crate::events::{ChangeEvent, ConflictPayload, DataChangeObserver};
use crate::file_watcher::{FileWatcher, FileWatcherEvent, FileWatcherObserver};
use crate::fingerprint;
use crate::ingest;
use crate::key_provider::{DbKey, KeyProvider};
use crate::migrations;
use crate::projection;
use crate::reconcile::{self, MergeResult, ParkConflictsResult};
use crate::save::{self, SelfWriteSignature};
use crate::strength::{self, Strength};

// `impl Engine { ... }` blocks split across files by concern; each
// submodule contributes its slice of the engine's public method
// surface. The struct definition, lifecycle methods (`open` /
// `close` / `state` / observer + file-watcher wiring), persistence
// (`ingest_from_kdbx`, `save_to_kdbx`, signatures), and the small
// utility methods (`fingerprint`, `strength`, `emit`) stay here in
// `mod.rs` alongside the struct itself.
mod conflict;
mod mutations;
mod queries;
mod reveal;

/// Lifecycle / health classification for an [`Engine`].
///
/// Surfaced via [`Engine::state`]. The variants form a small state
/// machine intended to cover both the local-file world (Phase 4
/// file-watcher integration) and the future cloud-storage world
/// (vaults backed by a remote provider that can be offline).
///
/// Variants are deliberately `#[non_exhaustive]` because the set
/// will grow — e.g. a future `Syncing` state for in-flight cloud
/// replication. Callers should treat unknown variants as
/// "non-Active": writes are not safe, reads are best-effort.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultState {
    /// Engine fully operational. `SQLite` is open, and the underlying
    /// KDBX file (or remote backing store) is reachable. Writes are
    /// allowed.
    Active,
    /// `SQLite` is readable but the underlying KDBX file is missing or
    /// unreachable. Reads work; writes are gated. The exact reason
    /// is carried so UI can surface a useful message.
    Disconnected {
        /// Why the engine is disconnected — file missing, IO error,
        /// network unavailable for a cloud-backed vault, etc.
        reason: DisconnectReason,
    },
    /// Engine has been deliberately demoted to read-only — e.g. the
    /// user locked the vault but kept `SQLite` open for inspection.
    /// Reserved for a future explicit lock path; transitions don't
    /// wire in this PR.
    ReadOnly,
    /// Engine encountered an unrecoverable error. Caller must close
    /// and reopen.
    Error,
}

/// Why an [`Engine`] is in the [`VaultState::Disconnected`] state.
///
/// Variants are deliberately `#[non_exhaustive]` so cloud-storage
/// providers can add more without breaking matches.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisconnectReason {
    /// The KDBX file is missing from its expected on-disk path.
    FileMissing,
    /// The KDBX file is present but the engine couldn't read it
    /// (permissions, IO error, etc.). The payload is the diagnostic
    /// message.
    FileUnreadable(String),
    /// A cloud / remote backing store is currently unreachable.
    /// Reserved for the future cloud-storage work; not used by the
    /// local-file path.
    NetworkUnavailable,
    /// Anything else, with a diagnostic.
    Other(String),
}

/// `SQLCipher`-backed `SQLite` engine handle.
///
/// Construct via [`Engine::open`]. Drop via [`Engine::close`] (or just
/// let it fall out of scope — `Drop` on the inner [`Connection`] does
/// the same finalisation, but `close` lets callers observe any
/// finalisation error).
#[derive(Debug)]
pub struct Engine {
    conn: Connection,
    /// Per-vault HMAC key used to derive
    /// [`entry.password_fingerprint`](crate::fingerprint::fingerprint)
    /// values for duplicate-password detection. Generated on first
    /// open, persisted (encrypted at rest by `SQLCipher`) in the
    /// `setting` table under the `fingerprint_key` row, and reloaded
    /// on every subsequent open. Zeroed on drop.
    fingerprint_key: Zeroizing<[u8; 32]>,
    /// Session-key provider used by ingest (and the future reveal /
    /// mutation paths) to AES-GCM-wrap protected field plaintexts
    /// before they land in `entry_protected.wrapped_blob`.
    ///
    /// Same trait that `keepass-core::Kdbx::open` takes, so a single
    /// frontend-side implementation can drive both the in-memory
    /// kdbx wrap layer and the engine's persisted wrap. Stored as
    /// `Arc<dyn FieldProtector>` because the trait is also held by
    /// the unlocked Kdbx and by future per-thread reveal paths.
    field_protector: Arc<dyn FieldProtector>,
    /// Shared lifecycle / signature state that the optional
    /// [`FileWatcher`] observer needs read/write access to from another
    /// thread. The engine reads through this on every call; the file-
    /// watcher internal observer (when one is wired) takes the lock to
    /// flip `state` between `Active` and `Disconnected` and to consume
    /// the self-write signature.
    shared: Arc<Mutex<EngineShared>>,
    /// Optional change observer. Phase 4.2/4.3 — set via
    /// [`Engine::set_observer`], cleared via [`Engine::clear_observer`].
    /// When `Some`, mutation methods invoke
    /// [`DataChangeObserver::on_event`] **synchronously on the mutation
    /// thread** after the transaction commits. Observers must be cheap
    /// (e.g. push to a channel) — a frontend that wants async dispatch
    /// adapts inside its impl.
    observer: Option<Arc<dyn DataChangeObserver>>,
    /// Optional file watcher. When `Some`, the engine registers an
    /// internal [`FileWatcherObserver`] on it during
    /// [`Engine::open`] that translates [`FileWatcherEvent`]s into
    /// state transitions and (from task 4.6 onwards) into a trigger
    /// to call `reconcile_with_disk`. Kept on the struct so its
    /// lifetime is tied to the engine's — dropping the engine drops
    /// the watcher.
    file_watcher: Option<Arc<dyn FileWatcher>>,
    /// Active conflict payloads, keyed by [`ConflictPayload::id`].
    /// Stashed by [`Engine::reconcile_with_disk`] when the merge
    /// surfaces conflicts and consumed by `apply_conflict_resolution`
    /// (task 4.7). Held behind an [`Arc<Mutex<_>>`] so the trigger
    /// path (and future async resolution flows) can mutate it
    /// without taking the whole engine lock.
    pending_conflicts: Arc<Mutex<HashMap<i64, ConflictPayload>>>,
    /// Sibling stash of [`PendingConflictContext`] entries keyed by
    /// the same id. Holds the merge outcome, both pre-merge vaults,
    /// the already-unlocked disk [`Kdbx`], and the disk bytes —
    /// everything `apply_conflict_resolution` (task 4.7) needs to
    /// drive `keepass_merge::apply_merge` and re-ingest without
    /// re-running the merge or re-asking the caller for the
    /// composite key. Kept on a separate stash from
    /// [`Self::pending_conflicts`] because the context contains
    /// non-`Clone` types ([`Kdbx<Unlocked>`]) that the public payload
    /// (cloneable, FFI-friendly) deliberately doesn't.
    pending_conflict_contexts:
        Arc<Mutex<HashMap<i64, crate::conflict_resolution::PendingConflictContext>>>,
}

/// Optional callback the frontend installs so the engine's
/// file-watcher observer can drive a `reconcile_with_disk` call
/// without holding the composite key or vault path itself.
///
/// The watcher calls [`ReconcileTrigger::trigger`] on every
/// post-self-write-filter `ContentChanged` event. The implementation
/// dispatches to whatever long-running flow the frontend uses to
/// supply the composite key (typically a queued task on the UI
/// thread that hits the session store). Implementations must be
/// cheap — they're called from the watcher's internal thread.
///
/// Per the 2026-05-16 standing orders, the file-watcher path is
/// **silent on failure**: if the frontend's trigger returns an
/// error it should transition the engine state to
/// [`VaultState::Disconnected`] with
/// [`DisconnectReason::Other`] carrying the diagnostic, rather than
/// emitting a dedicated change event.
pub trait ReconcileTrigger: Send + Sync + std::fmt::Debug {
    /// Fire whatever flow the frontend uses to call
    /// [`Engine::reconcile_with_disk`].
    fn trigger(&self);
}

/// Shared engine state that's also written from a non-engine thread
/// (the file watcher's observer callback). Held inside an
/// `Arc<Mutex<…>>`, with the engine taking the lock for every read /
/// write. The lock scope is intentionally narrow — no SQL runs under
/// the lock, only field shuffling — so contention with the file
/// watcher's brief writes is negligible.
#[derive(Debug)]
struct EngineShared {
    /// Current lifecycle / health state. See [`VaultState`].
    state: VaultState,
    /// `(mtime, size)` of the most recent KDBX file written by
    /// [`Engine::save_to_kdbx`], or `None` if this engine has never
    /// written one. Consumed by [`Engine::consume_self_write_signature`]
    /// and by the internal file-watcher observer to distinguish our own
    /// writes from foreign edits.
    last_self_write: Option<SelfWriteSignature>,
    /// Number of `ContentChanged` events that survived the self-
    /// write filter. Bumped on every external change the watcher
    /// reports, regardless of whether a [`ReconcileTrigger`] is
    /// registered. Test-visible via
    /// [`Engine::pending_reconcile_calls_for_test`].
    pending_reconcile_calls: u64,
    /// Optional reconcile trigger installed via
    /// [`Engine::set_reconcile_trigger`]. The internal file-watcher
    /// observer fires it on every post-self-write-filter
    /// `ContentChanged` event.
    reconcile_trigger: Option<Arc<dyn ReconcileTrigger>>,
}

/// Internal [`FileWatcherObserver`] installed by [`Engine::open`] when a
/// `FileWatcher` is supplied. Translates file-watcher events into engine
/// state transitions and (from task 4.6 onwards) reconcile calls.
///
/// Self-write filtering happens here (engine-side filter, per the
/// 2026-05-16 decision): on `ContentChanged`, we stat the file and
/// compare against the engine's stored
/// [`SelfWriteSignature`](crate::SelfWriteSignature). If it matches, the
/// event is suppressed.
#[derive(Debug)]
struct EngineFileWatcherObserver {
    shared: Arc<Mutex<EngineShared>>,
}

impl FileWatcherObserver for EngineFileWatcherObserver {
    fn on_event(&self, event: FileWatcherEvent) {
        match event {
            FileWatcherEvent::ContentChanged { mtime, size } => {
                // Engine-side self-write filter. If the watcher reported
                // the post-event (mtime, size) and it matches our last
                // self-write signature, this `ContentChanged` is our
                // own atomic rename — suppress and consume the
                // signature. Cloud-provider watchers that can't observe
                // filesystem metadata pass `None`/`None`; in that case
                // we always proceed (no self-write can have happened on
                // a cloud-managed file from our process anyway).
                let mut guard = self.shared.lock().unwrap();
                if let (Some(mt), Some(sz), Some(sig)) = (mtime, size, guard.last_self_write) {
                    if mt == sig.mtime && sz == sig.size {
                        guard.last_self_write = None;
                        return;
                    }
                }
                guard.pending_reconcile_calls += 1;
                // Task 4.6: fire the frontend-registered reconcile
                // trigger, if any. The trigger is responsible for
                // gathering the composite key + vault path and
                // calling `Engine::reconcile_with_disk`. We clone the
                // Arc and drop the guard before invocation so the
                // trigger can re-enter the engine without deadlocking.
                let trigger = guard.reconcile_trigger.clone();
                drop(guard);
                if let Some(t) = trigger {
                    t.trigger();
                }
            }
            FileWatcherEvent::Unavailable { reason } => {
                let mut guard = self.shared.lock().unwrap();
                guard.state = VaultState::Disconnected {
                    reason: DisconnectReason::FileUnreadable(reason),
                };
            }
            FileWatcherEvent::Available => {
                let mut guard = self.shared.lock().unwrap();
                guard.state = VaultState::Active;
            }
            FileWatcherEvent::ConflictMarker { .. } => {
                // Reserved for future cloud-provider impls. No-op for
                // now — task 4.6's reconcile path will surface this via
                // a dedicated ChangeEvent variant.
            }
        }
    }
}

impl Engine {
    /// Open (or create) a `SQLCipher`-encrypted `SQLite` database at `path`.
    ///
    /// Asks `key_provider` for the 32-byte raw key once, applies it via
    /// `PRAGMA key`, then runs a sanity query against `sqlite_master`
    /// to validate the key. A wrong key surfaces as
    /// [`EngineError::WrongKey`].
    ///
    /// If `path` does not exist the file is created. Parent directories
    /// must already exist — the engine does not `mkdir -p`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::KeyProvider`] if the provider can't produce a key.
    /// - [`EngineError::WrongKey`] if the supplied key doesn't decrypt
    ///   the existing database.
    /// - [`EngineError::Sqlite`] for any other rusqlite-level failure.
    /// - [`EngineError::Io`] currently unused on this path but reserved.
    pub fn open(
        path: &Path,
        key_provider: &dyn KeyProvider,
        field_protector: Arc<dyn FieldProtector>,
        file_watcher: Option<Arc<dyn FileWatcher>>,
    ) -> Result<Self, EngineError> {
        let key = key_provider.acquire_db_key()?;

        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        apply_key(&conn, &key)?;
        drop(key);

        // Sanity-query `sqlite_master`. On an existing file with a
        // wrong key, `SQLCipher` returns `SQLITE_NOTADB` the moment it
        // tries to decrypt the first page. On a brand-new file the
        // master table is empty but legible — no error — and the run
        // through `apply_pending` below performs the first page write
        // that binds the chosen key to the file's encrypted header.
        match conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        }) {
            Ok(_) => {}
            Err(err) if is_wrong_key(&err) => return Err(EngineError::WrongKey),
            Err(err) => return Err(EngineError::Sqlite(err)),
        }

        // Enforce declared foreign-key constraints. SQLite ships with
        // FK enforcement OFF by default for legacy reasons; the engine
        // unconditionally opts in.
        conn.execute_batch("PRAGMA foreign_keys = ON")?;

        // Switch to write-ahead-log journalling. WAL is materially
        // better for concurrent reader+writer workloads — the AutoFill
        // case (extension reads the App Group SQLite while the main
        // app writes) is exactly the shape WAL is designed for.
        //
        // `journal_mode = WAL` is a persistent file-level setting: once
        // applied, the database stays in WAL mode until something flips
        // it back. Re-running this on every open is a no-op when the
        // file is already WAL, so the call is idempotent and cheap.
        //
        // Side-effect to be aware of when debugging: WAL mode creates
        // two sidecar files next to the main database
        // (`<base>.sqlite-wal` and `<base>.sqlite-shm`) — these appear
        // in the App Group container alongside `<sha256>.keys.sqlite`
        // and are part of the on-disk state. A pre-WAL rollback-journal
        // file (`<base>.sqlite-journal`) is dropped automatically on
        // the first WAL-mode write.
        conn.execute_batch("PRAGMA journal_mode = WAL")?;

        migrations::apply_pending(&mut conn)?;

        let fingerprint_key = ensure_fingerprint_key(&mut conn)?;

        let shared = Arc::new(Mutex::new(EngineShared {
            state: VaultState::Active,
            last_self_write: None,
            pending_reconcile_calls: 0,
            reconcile_trigger: None,
        }));

        // If a file watcher was supplied, register the engine's internal
        // observer on it now. The observer carries an `Arc` clone of
        // `shared`, so subsequent state transitions land on this engine's
        // state machine.
        if let Some(watcher) = file_watcher.as_ref() {
            let observer = Arc::new(EngineFileWatcherObserver {
                shared: Arc::clone(&shared),
            });
            watcher.set_observer(Some(observer));
        }

        let engine = Self {
            conn,
            fingerprint_key,
            field_protector,
            shared,
            observer: None,
            file_watcher,
            pending_conflicts: Arc::new(Mutex::new(HashMap::new())),
            pending_conflict_contexts: Arc::new(Mutex::new(HashMap::new())),
        };
        // Note: `VaultUnlocked` is *not* emitted here — no observer is
        // wired yet. Callers that want the event should set an observer
        // first and then emit it themselves, or we could fire after a
        // subsequent `set_observer`. The trait predates the open call,
        // so this is by design.
        Ok(engine)
    }

    /// Replace this engine's vault tables with the contents of `kdbx`.
    ///
    /// Walks groups → entries → history → attachments, `INSERTing` rows
    /// in a single transaction. Computes the strength bucket, entropy
    /// estimate, and HMAC fingerprint of every entry's password.
    /// AES-GCM-wraps every protected field plaintext under a session
    /// key fetched from this engine's [`FieldProtector`] and writes the
    /// blob to `entry_protected`. Splits the entry's tag list into
    /// distinct rows in `tag` / `entry_tag`. Content-addresses
    /// attachment bytes via SHA-256 into `attachment_blob`.
    ///
    /// Idempotent: the pre-walk step `DELETE`s every vault row, so a
    /// re-ingest produces the same final state regardless of what was
    /// there before. Schema (tables, indices, triggers, settings) is
    /// preserved.
    ///
    /// Phase 2.4 / 2.5 will land the reverse direction (projection +
    /// serialise). Mutation semantics — adding / editing / deleting a
    /// single entry without rewriting the whole table — are Phase 4.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Ingest`] wrapping an
    ///   [`crate::IngestError::Kdbx`] if the kdbx side refuses to
    ///   expose plaintext-protected vault contents.
    /// - [`EngineError::Ingest`] wrapping an
    ///   [`crate::IngestError::Wrap`] /
    ///   [`crate::IngestError::SessionKey`] if the wrap pass fails.
    /// - [`EngineError::Sqlite`] for transaction / INSERT failures.
    pub fn ingest_from_kdbx(&mut self, kdbx: &Kdbx<Unlocked>) -> Result<(), EngineError> {
        let outcome = ingest::ingest(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            kdbx,
        )?;
        // Bulk events — one per kind. Frontends rebuilding from scratch
        // react once per kind rather than per row.
        if !outcome.group_uuids.is_empty() {
            self.emit(ChangeEvent::GroupsAdded(outcome.group_uuids));
        }
        if !outcome.entry_uuids.is_empty() {
            self.emit(ChangeEvent::EntriesAdded(outcome.entry_uuids));
        }
        Ok(())
    }

    /// Project this engine's `SQLite` mirror back into a
    /// [`keepass_core::model::Vault`].
    ///
    /// Inverse of [`Engine::ingest_from_kdbx`]. Reads every group,
    /// entry, protected-field blob, attachment, tag, and history
    /// snapshot row inside a single read transaction; AES-GCM-unwraps
    /// protected blobs under this engine's
    /// [`keepass_core::protector::FieldProtector`] so the returned
    /// [`keepass_core::model::Vault`] carries plaintext on
    /// [`Entry::password`](keepass_core::model::Entry::password) and on
    /// each protected
    /// [`CustomField::value`](keepass_core::model::CustomField::value).
    /// That's the shape the upcoming serialise path (task 2.5)
    /// consumes, and the shape round-trip property tests (task 2.7)
    /// compare against.
    ///
    /// The projected vault carries the full `Meta` block (every
    /// scalar, `custom_icons`, `custom_data`, `memory_protection`,
    /// `unknown_xml`) and `deleted_objects` — all reconstituted from
    /// the migration-0003 persistence layer. The save path can install
    /// the projection on a fresh `Kdbx<Unlocked>` handle without losing
    /// any metadata.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Projection`] wrapping
    ///   [`crate::ProjectionError::Unwrap`] if a protected blob fails
    ///   AES-GCM open under the session key.
    /// - [`EngineError::Projection`] wrapping
    ///   [`crate::ProjectionError::SessionKey`] if the protector
    ///   refuses to release a session key.
    /// - [`EngineError::Projection`] wrapping
    ///   [`crate::ProjectionError::SchemaInvariant`] if the persisted
    ///   shape violates an invariant the projection relies on (e.g.
    ///   no root group).
    /// - [`EngineError::Sqlite`] for `SELECT` failures.
    pub fn project_to_vault(&self) -> Result<keepass_core::model::Vault, EngineError> {
        projection::project(&self.conn, &*self.field_protector)
    }

    /// Project the engine's `SQLite` mirror into a fresh
    /// [`keepass_core::model::Vault`], splice it into `kdbx`,
    /// re-encrypt under `kdbx`'s existing crypto envelope, and
    /// atomically write the resulting bytes to `path`.
    ///
    /// Records the post-write `(mtime, size)` on `self` as a
    /// [`SelfWriteSignature`], readable via
    /// [`Engine::last_self_write`]. Task 2.6 lands the consumer that
    /// matches an observed change against this signature so the
    /// watcher can suppress fires from our own writes.
    ///
    /// ## Meta preservation
    ///
    /// Since migration 0003, every
    /// [`keepass_core::model::Meta`] field is persisted in `SQLite`, so
    /// the projection reconstitutes the meta block in full. The live
    /// `kdbx` handle's vault contents (entries, groups, meta) are
    /// replaced wholesale by the projection — no splice required.
    ///
    /// ## Atomic write
    ///
    /// Bytes are written to a tempfile, flushed and `sync_all`'d, then
    /// `rename(2)`'d over `path`. The tempfile lives in `temp_dir` when
    /// supplied, otherwise in `path`'s parent directory. The parent
    /// directory is then `sync_all`'d on a best-effort basis to make
    /// the directory entry durable.
    ///
    /// Pass `Some(temp_dir)` when the caller can write the destination
    /// file but not arbitrary siblings of it — e.g. sandboxed macOS
    /// frontends saving to iCloud Drive, where the security-scoped
    /// bookmark grants write to the kdbx file only. The override must
    /// live on the same filesystem volume as `path` (rename is not
    /// cross-volume atomic). Pass `None` for non-sandboxed callers to
    /// keep the historical sibling-tempfile behaviour.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Projection`] if projection fails.
    /// - [`EngineError::Serialise`] if `keepass-core`'s `save_to_bytes`
    ///   rejects the spliced vault.
    /// - [`EngineError::Io`] for tempfile creation / write / rename /
    ///   stat failures.
    pub fn save_to_kdbx(
        &mut self,
        path: &Path,
        kdbx: &mut Kdbx<Unlocked>,
        temp_dir: Option<&Path>,
    ) -> Result<(), EngineError> {
        save::save(self, path, kdbx, temp_dir)?;
        self.emit(ChangeEvent::SaveCompleted);
        Ok(())
    }

    /// The `(mtime, size)` of the most recent KDBX file this engine
    /// wrote, or `None` if no save has happened yet on this handle.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal shared-state `Mutex` is poisoned
    /// — i.e. another thread (the file-watcher observer callback)
    /// previously panicked while holding the lock. In normal use this
    /// cannot happen.
    #[must_use]
    pub fn last_self_write(&self) -> Option<SelfWriteSignature> {
        self.shared.lock().unwrap().last_self_write
    }

    /// Current lifecycle / health state of this engine.
    ///
    /// In this PR the only transition wired in is
    /// "`Engine::open` succeeded → [`VaultState::Active`]". The other
    /// variants (`Disconnected`, `ReadOnly`, `Error`) are part of the
    /// forward-design surface and start being driven from Phase 4
    /// onwards (file-watcher events, explicit lock, unrecoverable
    /// errors).
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal shared-state `Mutex` is poisoned
    /// — see [`Engine::last_self_write`] for the same caveat.
    #[must_use]
    pub fn state(&self) -> VaultState {
        self.shared.lock().unwrap().state.clone()
    }

    /// Borrow the [`FileWatcher`] this engine was opened with, if any.
    /// Test-only accessor; useful for asserting observer wiring and for
    /// driving synthetic events from a test-side watcher implementation.
    #[doc(hidden)]
    #[must_use]
    pub fn file_watcher(&self) -> Option<&Arc<dyn FileWatcher>> {
        self.file_watcher.as_ref()
    }

    /// Test-only: snapshot of how many `ContentChanged` events made it
    /// past self-write filtering. Will be replaced by a real
    /// `reconcile_with_disk` call in task 4.6.
    #[doc(hidden)]
    #[must_use]
    pub fn pending_reconcile_calls_for_test(&self) -> u64 {
        self.shared.lock().unwrap().pending_reconcile_calls
    }

    /// Crate-internal setter used by [`crate::save::save`] to record
    /// the signature after a successful atomic write.
    pub(crate) fn set_last_self_write(&mut self, signature: SelfWriteSignature) {
        self.shared.lock().unwrap().last_self_write = Some(signature);
    }

    /// The raw KDBX bytes of the most recent
    /// [`Engine::save_to_kdbx`] write — the *common ancestor* for a
    /// future external-change 3-way merge (task 4.4).
    ///
    /// Returns `Ok(None)` if this engine has never successfully saved
    /// a KDBX (fresh database, or a freshly reopened database whose
    /// previous handle never made it to the save path). Otherwise the
    /// bytes are byte-identical to what the last `save_to_kdbx` wrote
    /// to disk and can be fed straight into
    /// [`keepass_core::kdbx::Kdbx::open`] for re-parsing.
    ///
    /// Persisted in the `setting` table under key
    /// `last_saved_kdbx_bytes`, so the value survives engine
    /// close + reopen. `SQLCipher` provides encryption-at-rest; the
    /// bytes themselves are the raw post-KDBX-encryption ciphertext
    /// (which is already internally compressed by KDBX), no extra
    /// wrapping applied.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn last_saved_kdbx_bytes(&self) -> Result<Option<Vec<u8>>, EngineError> {
        match self.conn.query_row(
            "SELECT value FROM setting WHERE key = 'last_saved_kdbx_bytes'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(EngineError::Sqlite(err)),
        }
    }

    /// Crate-internal setter used by [`crate::save::save`] to persist
    /// the just-written KDBX bytes as the common ancestor for the
    /// next 3-way merge (task 4.4). INSERT OR REPLACE so subsequent
    /// saves overwrite the row in place.
    pub(crate) fn set_last_saved_kdbx_bytes(&mut self, bytes: &[u8]) -> Result<(), EngineError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO setting(key, value) VALUES ('last_saved_kdbx_bytes', ?1)",
            rusqlite::params![bytes],
        )?;
        Ok(())
    }

    /// The `(mtime, size)` of the KDBX file whose contents this engine's
    /// `SQLite` mirror currently corresponds to, or `None` if neither
    /// [`Engine::ingest_from_kdbx`] nor [`Engine::save_to_kdbx`] has
    /// been paired with a [`Engine::record_kdbx_state_signature`] call
    /// on this database yet.
    ///
    /// Used by Keys-Mac on unlock: stat the KDBX file and compare; if
    /// the signature matches, skip `ingest_from_kdbx` (the 1–4s
    /// wall-clock dominator on big vaults) because `SQLite` is already
    /// in sync with disk.
    ///
    /// Persisted in the `setting` table (keys
    /// `kdbx_state_signature_mtime_ms`, `kdbx_state_signature_byte_count`)
    /// so the value survives engine close + reopen. Distinct from
    /// [`Engine::last_self_write`]: that one is consumed by the
    /// file-watcher self-write suppression and would lose its meaning
    /// if shared with the ingest path.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn kdbx_state_signature(&self) -> Result<Option<crate::KdbxStateSignature>, EngineError> {
        let mtime_ms: Option<i64> = match self.conn.query_row(
            "SELECT value FROM setting WHERE key = 'kdbx_state_signature_mtime_ms'",
            [],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(err) => return Err(EngineError::Sqlite(err)),
        };
        let byte_count: Option<i64> = match self.conn.query_row(
            "SELECT value FROM setting WHERE key = 'kdbx_state_signature_byte_count'",
            [],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(err) => return Err(EngineError::Sqlite(err)),
        };
        match (mtime_ms, byte_count) {
            (Some(mtime_ms), Some(byte_count)) => Ok(Some(crate::KdbxStateSignature {
                mtime_ms,
                // SQLite stores INTEGER as i64; size always fits but
                // we coerce defensively.
                byte_count: u64::try_from(byte_count).unwrap_or(0),
            })),
            _ => Ok(None),
        }
    }

    /// Record the `(mtime, size)` of the KDBX file at `path` as the
    /// signature corresponding to the engine's current `SQLite` state.
    ///
    /// Frontends should call this after a successful
    /// [`Engine::ingest_from_kdbx`]. [`Engine::save_to_kdbx`] calls it
    /// automatically (the save path already has the file path on hand).
    ///
    /// # Errors
    ///
    /// - [`EngineError::Io`] if `path` can't be stat'd or its mtime
    ///   can't be read.
    /// - [`EngineError::Sqlite`] on persistence failure.
    pub fn record_kdbx_state_signature(
        &mut self,
        path: &std::path::Path,
    ) -> Result<(), EngineError> {
        let sig = crate::KdbxStateSignature::from_path(path)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO setting(key, value) VALUES ('kdbx_state_signature_mtime_ms', ?1)",
            rusqlite::params![sig.mtime_ms],
        )?;
        // Store as i64 — SQLite has no native u64. Sizes up to
        // i64::MAX (8 exabytes) fit; KDBX files in practice are <100MB.
        let byte_count_i64 = i64::try_from(sig.byte_count).unwrap_or(i64::MAX);
        tx.execute(
            "INSERT OR REPLACE INTO setting(key, value) VALUES ('kdbx_state_signature_byte_count', ?1)",
            rusqlite::params![byte_count_i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Reconcile the engine's `SQLite` state against the current
    /// on-disk KDBX file at `kdbx_path`.
    ///
    /// Reads and parses the disk bytes via
    /// [`keepass_core::kdbx::Kdbx::open_from_bytes`] under
    /// `composite_key` and this engine's field protector. Projects
    /// the engine's current state to a [`Vault`](keepass_core::model::Vault),
    /// runs a two-way merge via
    /// [`keepass_merge::merge`] (each entry's `<History>` list acts
    /// as the per-entry common ancestor; the engine's
    /// `last_saved_kdbx_bytes` is the vault-level baseline), and:
    ///
    /// - If the two states are already equivalent, returns
    ///   [`MergeResult::NoChange`] and refreshes
    ///   `last_saved_kdbx_bytes` to the disk bytes.
    /// - If the merge produced conflicts, stashes the
    ///   [`ConflictPayload`] for later resolution and returns
    ///   [`MergeResult::Conflict`]. `SQLite` is **not** mutated.
    ///   The engine also emits a
    ///   [`ChangeEvent::ConflictDetected`] for any installed
    ///   observer.
    /// - Otherwise applies the merge in a single transaction (via
    ///   the existing ingest path) and returns
    ///   [`MergeResult::Merged`]. The engine emits a
    ///   [`ChangeEvent::ExternalChangeMerged`].
    ///
    /// Atomicity: the `SQLite` write path holds a single transaction.
    /// A failure mid-write rolls back; the engine state is
    /// unchanged. The merge step itself runs against an immutable
    /// projection — failure there returns an error without touching
    /// `SQLite`.
    ///
    /// Composite-key handling: the engine doesn't store the
    /// composite key. Callers pass it on each reconcile so frontends
    /// can keep it in their own session store.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Io`] if the disk file can't be read.
    /// - [`EngineError::Serialise`] wrapping any
    ///   [`keepass_core::Error`] / merge-pass failure.
    /// - [`EngineError::Sqlite`] / [`EngineError::Ingest`] for
    ///   apply-step failures.
    pub fn reconcile_with_disk(
        &mut self,
        kdbx_path: &Path,
        composite_key: &CompositeKey,
    ) -> Result<MergeResult, EngineError> {
        reconcile::reconcile_with_disk(self, kdbx_path, composite_key)
    }

    /// Park-conflicts variant of [`Self::reconcile_with_disk`].
    ///
    /// Where the legacy method bails out with
    /// [`MergeResult::Conflict`] when the three-way merge surfaces
    /// genuine "both sides edited the same field" conflicts, this
    /// variant calls
    /// [`keepass_merge::apply_merge_park_conflicts`] — the
    /// non-conflicting parts are applied as usual, and each
    /// conflicting entry's remote-side snapshot is pushed into
    /// local's `<History>` with a `keys.field_conflict.v1` marker
    /// attached. Sync never blocks. The user reviews via Keys-Mac's
    /// `ConflictResolverView` at their leisure.
    ///
    /// `now` stamps the marker (`FieldConflictMarker::at`). Inject
    /// it so the call stays a pure function — frontends typically
    /// pass `chrono::Utc::now()`.
    ///
    /// # Errors
    ///
    /// Same shape as [`Self::reconcile_with_disk`]: IO, KDBX
    /// open/parse, merge, ingest. Per the upstream
    /// `apply_merge_park_conflicts` contract the synthesised
    /// resolution is valid by construction, so no resolution-class
    /// `MergeError` reaches the engine path.
    pub fn reconcile_with_disk_park_conflicts(
        &mut self,
        kdbx_path: &Path,
        composite_key: &CompositeKey,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ParkConflictsResult, EngineError> {
        reconcile::reconcile_with_disk_park_conflicts(self, kdbx_path, composite_key, now)
    }

    /// Per-device-key sync transport: ingest a fetched peer KDBX blob under the
    /// peer's `owner` device id (vs the `FILE_OWNER` sentinel that
    /// [`Self::reconcile_with_disk_park_conflicts`] uses for the disk-watcher
    /// path). Distinct owners → distinct conflict rows → multi-peer `N`-way
    /// resolution. Same park-conflicts owner-rows engine underneath.
    ///
    /// # Errors
    ///
    /// Same shape as [`Self::reconcile_with_disk_park_conflicts`]: IO, KDBX
    /// open/parse/unlock, and ingest errors.
    pub fn ingest_peer_from_kdbx(
        &mut self,
        kdbx_path: &Path,
        composite_key: &CompositeKey,
        owner: &str,
    ) -> Result<ParkConflictsResult, EngineError> {
        reconcile::ingest_peer_from_kdbx(self, kdbx_path, composite_key, owner)
    }

    /// Build the rich conflict payload for the currently **held** (parked)
    /// conflicts and stash a context so they can be resolved through the same
    /// [`Self::apply_conflict_resolution`] entry point the live
    /// [`Self::reconcile_with_disk`] path uses.
    ///
    /// This is the resolver-open companion to the badge query
    /// [`Self::entries_with_parked_conflict`]. "Theirs" is reconstructed from
    /// the owner (`conflict_*`) rows the park reconcile wrote — not from the
    /// disk file — so it works even when the peer blob has been discarded (the
    /// iroh case) or the disk bytes have become the baseline. It merges
    /// local-vs-(reconstructed-theirs) to rebuild the rich payload and stash
    /// it, mutating no `SQLite` state.
    ///
    /// Returns `None` when no entry carries a parked owner row, or the merge
    /// surfaces no conflict (e.g. a peer resolved it and the values have since
    /// converged). `kdbx_path` / `composite_key` are unused — retained for
    /// FFI-signature stability.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Projection`] / [`EngineError::Sqlite`] on read failure;
    ///   [`EngineError::Serialise`] on a merge failure.
    pub fn held_conflict_payload(
        &mut self,
        kdbx_path: &Path,
        composite_key: &CompositeKey,
        entry_filter: Option<uuid::Uuid>,
    ) -> Result<Option<ConflictPayload>, EngineError> {
        reconcile::held_conflict_payload(self, kdbx_path, composite_key, entry_filter)
    }

    /// Return the UUIDs of every entry that currently carries at least one
    /// stored peer conflict (`conflict_*`) row — the owner-rows badge query.
    ///
    /// Drives the vault-tile warning triangle in Keys-Mac: any
    /// non-empty result means the vault has entries awaiting user
    /// review via the conflict resolver. Returned UUIDs sort
    /// ascending for stable rendering.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Sqlite`] on storage failure.
    pub fn entries_with_parked_conflict(&self) -> Result<Vec<uuid::Uuid>, EngineError> {
        reconcile::entries_with_parked_conflict(self)
    }

    /// Dismiss the held-conflict badge on `entry_uuid` by dropping its owner
    /// (`conflict_*`) rows across every peer.
    ///
    /// Called by Keys-Mac's conflict resolver after the user resolves an
    /// entry (and as the local "dismiss badge" half). Clearing the rows drops
    /// the entry from the owner-rows badge query immediately. Cross-peer
    /// convergence is driven separately by the `keys.conflict_resolutions.v1`
    /// record that [`Self::apply_conflict_resolution`] writes.
    ///
    /// Idempotent: a no-op (returns 0) on entries with no stored conflict
    /// rows. `now` is unused — retained for FFI-signature stability.
    ///
    /// Returns the number of `conflict_entry` rows removed.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Sqlite`] on storage failure.
    pub fn clear_parked_conflict_marker(
        &mut self,
        entry_uuid: uuid::Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, EngineError> {
        reconcile::clear_parked_conflict_marker(self, entry_uuid, now)
    }

    /// Install a [`ReconcileTrigger`] so the file-watcher path can
    /// drive [`Engine::reconcile_with_disk`] indirectly when an
    /// external KDBX change is detected. Replaces any previously
    /// installed trigger; pass `None` (via [`Engine::clear_reconcile_trigger`])
    /// to disable the auto-trigger path.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal shared-state `Mutex` is
    /// poisoned — see [`Engine::last_self_write`] for the same caveat.
    pub fn set_reconcile_trigger(&mut self, trigger: Arc<dyn ReconcileTrigger>) {
        self.shared.lock().unwrap().reconcile_trigger = Some(trigger);
    }

    /// Remove any installed [`ReconcileTrigger`]. Subsequent file-
    /// watcher events still bump the internal counter but do not fan
    /// out to a frontend callback.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal shared-state `Mutex` is
    /// poisoned — see [`Engine::last_self_write`] for the same caveat.
    pub fn clear_reconcile_trigger(&mut self) {
        self.shared.lock().unwrap().reconcile_trigger = None;
    }

    /// HMAC-SHA-256 a plaintext under this vault's persistent
    /// fingerprint key.
    ///
    /// The returned 32 bytes are deterministic for a given (vault,
    /// plaintext) pair across reopens, but differ across vaults
    /// because each vault has its own random fingerprint key. Intended
    /// for populating the `entry.password_fingerprint` column and for
    /// duplicate-password queries.
    #[must_use]
    pub fn fingerprint(&self, plaintext: &[u8]) -> [u8; 32] {
        fingerprint::fingerprint(&self.fingerprint_key, plaintext)
    }

    /// Estimate the strength of a password.
    ///
    /// Pure function — no engine state is touched. Exposed as a method
    /// for API symmetry with [`Engine::fingerprint`] so callers can
    /// drive both off a single handle. See [`crate::strength()`] for the
    /// algorithm.
    #[must_use]
    pub fn strength(&self, password: &str) -> Strength {
        strength::strength(password)
    }

    /// Close the underlying connection, finalising any pending work.
    ///
    /// Consumes `self`. On success the connection is gone. On failure
    /// the rusqlite-returned `(Connection, Error)` pair is collapsed
    /// into a plain [`EngineError::Sqlite`] — the half-closed
    /// connection is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] if `SQLite` can't finalise the
    /// connection cleanly.
    pub fn close(self) -> Result<(), EngineError> {
        self.conn
            .close()
            .map_err(|(_, err)| EngineError::Sqlite(err))
    }

    /// Install a [`DataChangeObserver`]. Replaces any previously
    /// installed observer. Subsequent successful mutations will invoke
    /// [`DataChangeObserver::on_event`] synchronously on the mutation
    /// thread.
    pub fn set_observer(&mut self, observer: Arc<dyn DataChangeObserver>) {
        self.observer = Some(observer);
    }

    /// Remove any installed observer. Subsequent mutations will not
    /// fire events until another observer is installed.
    pub fn clear_observer(&mut self) {
        self.observer = None;
    }

    /// Fire a [`ChangeEvent`] if an observer is installed; no-op
    /// otherwise. Always called after a successful commit by the
    /// mutation methods — never inside a transaction.
    pub(crate) fn emit(&self, event: ChangeEvent) {
        if let Some(observer) = &self.observer {
            observer.on_event(event);
        }
    }
}

/// Apply the raw 32-byte key via `PRAGMA key = "x'<hex>'"`.
///
/// The BLOB-literal form bypasses `SQLCipher`'s PBKDF2 derivation: the
/// supplied bytes are used directly as the raw 256-bit cipher key,
/// which is what we want — the input is already a random 32-byte key
/// from the platform Keychain.
///
/// rusqlite's [`Connection::pragma_update`] always quotes its argument
/// with single quotes, which would turn `x'…'` into `'x''…'''` — not
/// what `SQLCipher` wants. So we build the statement by hand. The hex
/// payload is constrained to `[0-9a-f]` by [`hex_encode`], so there's
/// no injection surface; even so, the hex string lives in a
/// [`Zeroizing`] buffer and is wiped as soon as the PRAGMA returns.
fn apply_key(conn: &Connection, key: &DbKey) -> Result<(), rusqlite::Error> {
    let hex = hex_encode(key.as_bytes());
    let mut stmt = Zeroizing::new(String::with_capacity(hex.len() + 18));
    stmt.push_str("PRAGMA key = \"x'");
    stmt.push_str(&hex);
    stmt.push_str("'\"");
    conn.execute_batch(&stmt)
}

/// Lowercase hex-encode 32 bytes. Wrapped in [`Zeroizing`] so the
/// formatted key string is wiped from memory after the PRAGMA runs.
fn hex_encode(bytes: &[u8; 32]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Load the per-vault fingerprint key from `setting`, generating and
/// persisting a fresh 32-byte random key if no row exists.
///
/// The key is stored in `setting.value` as a 32-byte BLOB. Encryption
/// at rest is provided by `SQLCipher`'s page-level encryption — no
/// extra layer is applied to the row itself.
///
/// # Errors
///
/// - [`EngineError::Random`] if the OS RNG fails on a first-open path.
/// - [`EngineError::Sqlite`] for read/write failures, or if a row
///   exists but its value isn't 32 bytes (indicates corruption).
fn ensure_fingerprint_key(conn: &mut Connection) -> Result<Zeroizing<[u8; 32]>, EngineError> {
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM setting WHERE key = 'fingerprint_key'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(Some)
        .or_else(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;

    if let Some(bytes) = existing {
        let mut buf = Zeroizing::new([0u8; 32]);
        if bytes.len() != 32 {
            // Corrupt / wrong-shape row. Surface as a SQLite-flavoured
            // error rather than panicking. A dedicated variant could
            // land later once we have a story for recovery.
            return Err(EngineError::Sqlite(
                rusqlite::Error::IntegralValueOutOfRange(
                    0,
                    i64::try_from(bytes.len()).unwrap_or(i64::MAX),
                ),
            ));
        }
        buf.copy_from_slice(&bytes);
        // Best-effort wipe of the rusqlite-allocated buffer.
        let mut bytes = bytes;
        bytes.fill(0);
        return Ok(buf);
    }

    let mut buf = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(buf.as_mut_slice())?;

    conn.execute(
        "INSERT INTO setting(key, value) VALUES ('fingerprint_key', ?1)",
        rusqlite::params![&buf[..]],
    )?;

    Ok(buf)
}

/// Recognise `SQLCipher`'s wrong-key signal.
///
/// `SQLCipher` returns extended error code 26 (`SQLITE_NOTADB`) with the
/// message "file is not a database" the first time an encrypted page
/// is read with an incorrect key. We match on the primary error code
/// since the extended-code mapping isn't stable across versions.
fn is_wrong_key(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::NotADatabase
    )
}

/// Walk `group` (and its descendants) looking for the parent
/// [`GroupId`](keepass_core::model::GroupId) of `target`. `None` if
/// the entry doesn't live anywhere in the subtree.
pub(super) fn find_entry_parent_group(
    group: &keepass_core::model::Group,
    target: keepass_core::model::EntryId,
) -> Option<keepass_core::model::GroupId> {
    if group.entries.iter().any(|e| e.id == target) {
        return Some(group.id);
    }
    group
        .groups
        .iter()
        .find_map(|child| find_entry_parent_group(child, target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_lowercases_all_bytes() {
        let bytes = [0xab; 32];
        let s = hex_encode(&bytes);
        assert_eq!(&*s, &"ab".repeat(32));
    }

    #[test]
    fn hex_encode_handles_zero_and_ff() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x00;
        bytes[1] = 0xff;
        bytes[2] = 0x10;
        bytes[3] = 0x0f;
        let s = hex_encode(&bytes);
        assert!(s.starts_with("00ff100f"));
        assert_eq!(s.len(), 64);
    }
}
