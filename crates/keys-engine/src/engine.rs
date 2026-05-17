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
use std::time::SystemTime;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::FieldProtector;
use rusqlite::{Connection, OpenFlags};
use secrecy::SecretString;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::EngineError;
use crate::events::{
    ChangeEvent, ConflictPayload, DataChangeObserver, EntryDeletionInfo, EntryMove,
    EntryParentGroups, GroupDeletionInfo, GroupMove,
};
use crate::file_watcher::{FileWatcher, FileWatcherEvent, FileWatcherObserver};
use crate::fingerprint;
use crate::ingest;
use crate::key_provider::{DbKey, KeyProvider};
use crate::migrations;
use crate::model::{
    EntryFull, EntrySummary, EntryUpdate, GroupNode, GroupUpdate, HistoricEntry, NewEntryFields,
    NewGroupFields, Pagination, SmartFolder,
};
use crate::mutations;
use crate::predicate::Predicate;
use crate::projection;
use crate::reconcile::{self, MergeResult};
use crate::save::{self, SelfWriteSignature};
use crate::strength::{self, Strength};

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
    /// Bytes are written to a sibling tempfile, flushed and
    /// `sync_all`'d, then `rename(2)`'d over `path`. The parent
    /// directory is then `sync_all`'d on a best-effort basis to make
    /// the directory entry durable.
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
    ) -> Result<(), EngineError> {
        save::save(self, path, kdbx)?;
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

    /// Peek a stashed conflict payload by `id` without consuming it.
    ///
    /// Frontends call this after receiving
    /// [`ChangeEvent::ConflictDetected`]
    /// to render the resolver UI, then later call
    /// [`Self::apply_conflict_resolution`] (which consumes the
    /// matching context) once the user has picked their per-field /
    /// per-attachment / per-icon / delete-vs-edit choices.
    ///
    /// Repeated calls with the same `id` return the same payload (a
    /// clone) until `apply_conflict_resolution` succeeds; from that
    /// point on this returns `None` for that id. A frontend that
    /// abandons the resolution (e.g. user closes the window) leaves
    /// the payload in the stash; a fresh
    /// [`Self::reconcile_with_disk`] produces a new
    /// [`ConflictPayload`] with a fresh id.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned —
    /// see [`Self::last_self_write`] for the same caveat. Not
    /// expected in practice.
    #[must_use]
    pub fn pending_conflict(&self, id: i64) -> Option<ConflictPayload> {
        self.pending_conflicts.lock().unwrap().get(&id).cloned()
    }

    /// For a stashed conflict `id`, return the parent
    /// [`GroupId`](keepass_core::model::GroupId) of every conflict
    /// entry as observed on each side at reconcile time.
    ///
    /// Conflict payloads in [`ConflictPayload::entry_conflicts`] hold
    /// the raw upstream [`keepass_merge::EntryConflict`], whose
    /// `local` / `remote` [`keepass_core::model::Entry`]s don't carry
    /// a parent group reference. The resolver UI needs to know where
    /// each side placed the entry so it can render the per-side
    /// "Group" line. The engine has both vaults stashed alongside the
    /// payload, so we resolve them here once and hand the table back.
    ///
    /// `None` if the id is unknown (no stash or already consumed).
    /// Inside the `Some` branch, the inner `HashMap` is keyed by every
    /// [`EntryId`](keepass_core::model::EntryId) that appears in
    /// either [`ConflictPayload::entry_conflicts`] or
    /// [`ConflictPayload::delete_edit_conflicts`]. The inner
    /// [`EntryParentGroups`] carries `Option<GroupId>` per side —
    /// `None` when that side doesn't carry the entry under any known
    /// parent (an in-flight group-tree change).
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned —
    /// see [`Self::last_self_write`] for the same caveat. Not
    /// expected in practice.
    #[must_use]
    pub fn pending_conflict_parent_groups(
        &self,
        id: i64,
    ) -> Option<std::collections::HashMap<keepass_core::model::EntryId, EntryParentGroups>> {
        use keepass_core::model::EntryId;
        let ctx_guard = self.pending_conflict_contexts.lock().unwrap();
        let ctx = ctx_guard.get(&id)?;
        let mut entry_ids: Vec<EntryId> = ctx
            .payload
            .entry_conflicts
            .iter()
            .map(|c| c.entry_id)
            .collect();
        entry_ids.extend(ctx.payload.delete_edit_conflicts.iter().copied());
        entry_ids.sort_by_key(|e| e.0);
        entry_ids.dedup();
        let mut out = std::collections::HashMap::with_capacity(entry_ids.len());
        for entry_id in entry_ids {
            out.insert(
                entry_id,
                EntryParentGroups {
                    local: find_entry_parent_group(&ctx.local_vault.root, entry_id),
                    remote: find_entry_parent_group(&ctx.remote_vault.root, entry_id),
                },
            );
        }
        Some(out)
    }

    /// Test-only: count of currently stashed conflict payloads.
    #[doc(hidden)]
    #[must_use]
    pub fn pending_conflict_count_for_test(&self) -> usize {
        self.pending_conflicts.lock().unwrap().len()
    }

    /// Crate-internal: return the engine's [`FieldProtector`] as an
    /// [`Arc`]. Used by [`crate::reconcile`] to feed the protector
    /// into a fresh [`Kdbx::unlock_with_protector`] call.
    pub(crate) fn field_protector_arc(&self) -> Arc<dyn FieldProtector> {
        Arc::clone(&self.field_protector)
    }

    /// Crate-internal: drop the peek-only [`ConflictPayload`] mirror
    /// for `id`. Called by `apply_conflict_resolution` so the public
    /// [`Self::pending_conflict`] surface stops returning the payload
    /// once the matching context has been consumed.
    pub(crate) fn discard_pending_conflict_payload(&self, id: i64) {
        self.pending_conflicts.lock().unwrap().remove(&id);
    }

    /// Crate-internal: stash a [`ConflictPayload`] so the eventual
    /// `apply_conflict_resolution` (task 4.7) can find it.
    pub(crate) fn stash_conflict_payload(&self, payload: ConflictPayload) {
        self.pending_conflicts
            .lock()
            .unwrap()
            .insert(payload.id, payload);
    }

    /// Crate-internal: stash the additional context
    /// [`Engine::apply_conflict_resolution`] needs alongside the
    /// public [`ConflictPayload`].
    pub(crate) fn stash_conflict_context(
        &self,
        ctx: crate::conflict_resolution::PendingConflictContext,
    ) {
        self.pending_conflict_contexts
            .lock()
            .unwrap()
            .insert(ctx.payload.id, ctx);
    }

    /// Crate-internal: consume the stashed
    /// [`PendingConflictContext`](crate::conflict_resolution::PendingConflictContext)
    /// for `id`, returning `None` if no such id is stashed.
    pub(crate) fn take_pending_conflict_context(
        &self,
        id: i64,
    ) -> Option<crate::conflict_resolution::PendingConflictContext> {
        self.pending_conflict_contexts.lock().unwrap().remove(&id)
    }

    /// Crate-internal: borrow the stashed-context map under its mutex
    /// without consuming any entry. Used by
    /// [`crate::conflict_resolution::reveal_conflict_local_field`] /
    /// `_remote_field` to read the per-side vault for a peek-reveal —
    /// the stash stays in place so subsequent reveal calls (and the
    /// eventual `apply_conflict_resolution`) still see it.
    pub(crate) fn pending_conflict_contexts_lock(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<i64, crate::conflict_resolution::PendingConflictContext>>
    {
        self.pending_conflict_contexts.lock().unwrap()
    }

    /// Apply a user-resolved [`keepass_merge::Resolution`] to a
    /// previously-stashed conflict.
    ///
    /// `id` is the synthetic id from the
    /// [`crate::events::ChangeEvent::ConflictDetected`] event (and
    /// the matching [`ConflictPayload::id`] field) that surfaced the
    /// conflict via [`Engine::reconcile_with_disk`]. `resolution`
    /// carries the user's per-field, per-attachment, per-icon and
    /// delete-vs-edit decisions. See the [`keepass_merge::Resolution`]
    /// docs for the validation contract.
    ///
    /// On success the resolved vault has been applied to `SQLite`
    /// inside a single transaction, the common ancestor has been
    /// refreshed to the disk bytes the original reconcile observed,
    /// and a [`crate::events::ChangeEvent::ExternalChangeMerged`]
    /// event has fired (with an empty conflict residue, since
    /// resolution clears the stash).
    ///
    /// The stash is consumed by this call: a second call with the
    /// same `id` returns [`EngineError::NotFound`]. A retry needs a
    /// fresh `reconcile_with_disk` because the caller's mental model
    /// of the conflict shape may be stale by then.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] if no conflict is stashed under
    ///   `id` (typo, already-consumed, or evicted by engine drop).
    /// - [`EngineError::ResolutionMismatch`] if the resolution
    ///   doesn't cover the stashed conflict's buckets — `keepass-
    ///   merge`'s read-only validation pass fired before any mutation.
    /// - [`EngineError::Ingest`] / [`EngineError::Sqlite`] for
    ///   apply-step failures; `SQLite` rolls back and the engine
    ///   state is unchanged. The stash is still consumed in this
    ///   case — see the type-level docs.
    pub fn apply_conflict_resolution(
        &mut self,
        id: i64,
        resolution: &keepass_merge::Resolution,
    ) -> Result<(), EngineError> {
        crate::conflict_resolution::apply_conflict_resolution(self, id, resolution)
    }

    /// Reveal a single field on the **local** side of a stashed
    /// conflict as plaintext.
    ///
    /// Companion to [`Self::pending_conflict`] for the resolver UI's
    /// hover-reveal: the public [`ConflictPayload`] carries field-level
    /// diffs but redacts protected values; this method lets a frontend
    /// fetch the cleartext for one field on one side on demand.
    ///
    /// Both sides of the stashed conflict are full
    /// [`keepass_core::model::Vault`]s with protected fields already
    /// unwrapped (the local vault is produced by
    /// [`Self::project_to_vault`], which decrypts the
    /// `entry_protected` rows under the field-protector session key;
    /// the remote vault is produced by
    /// [`keepass_core::kdbx::Kdbx::vault_with_unwrapped_protected`],
    /// which does the same on the disk side). No session-key
    /// acquisition happens here — the cleartext sits on the stashed
    /// [`keepass_core::model::Entry`] ready to read. Plaintext crosses
    /// the boundary in a [`SecretString`] so it zeroes on drop.
    ///
    /// `field_name == "Password"` reads the canonical password slot;
    /// any other name reads from the entry's `custom_fields`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "conflict_payload"`) if
    ///   no conflict is stashed under `conflict_id` (typo, already
    ///   consumed by [`Self::apply_conflict_resolution`], or evicted
    ///   by engine drop).
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   with `entry_uuid` exists in the local-side vault.
    /// - [`EngineError::NotFound`] (`entity = "custom_field"`) if the
    ///   entry exists but doesn't carry a custom field named
    ///   `field_name` (and `field_name != "Password"`).
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned —
    /// see [`Self::last_self_write`] for the same caveat.
    pub fn reveal_conflict_local_field(
        &self,
        conflict_id: i64,
        entry_uuid: Uuid,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::conflict_resolution::reveal_conflict_local_field(
            self,
            conflict_id,
            entry_uuid,
            field_name,
        )
    }

    /// Reveal a single field on the **remote** side of a stashed
    /// conflict as plaintext.
    ///
    /// Sibling of [`Self::reveal_conflict_local_field`]; reads from
    /// the stash's remote-side vault. See that method's docs for the
    /// full contract.
    ///
    /// # Errors
    ///
    /// Same shape as [`Self::reveal_conflict_local_field`] but `entry`
    /// / `custom_field` `NotFound`s refer to the remote-side vault.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal stash `Mutex` is poisoned.
    pub fn reveal_conflict_remote_field(
        &self,
        conflict_id: i64,
        entry_uuid: Uuid,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::conflict_resolution::reveal_conflict_remote_field(
            self,
            conflict_id,
            entry_uuid,
            field_name,
        )
    }

    /// Crate-internal: re-ingest a merged [`Kdbx`] into `SQLite`.
    /// The single-transaction discipline lives in
    /// [`crate::ingest::ingest`]; the reconcile path uses this so
    /// failure rolls back cleanly without firing events.
    pub(crate) fn ingest_merged(&mut self, kdbx: &Kdbx<Unlocked>) -> Result<(), EngineError> {
        let _outcome = crate::ingest::ingest(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            kdbx,
        )?;
        Ok(())
    }

    /// One-shot: did `(observed_mtime, observed_size)` come from our own
    /// most recent [`Engine::save_to_kdbx`]?
    ///
    /// Returns `true` and clears the stored signature if it matches
    /// exactly. Returns `false` (and leaves state unchanged) if there's
    /// no signature stored, or if either component diverges.
    ///
    /// Intended for the Phase 4 file-watcher integration: when the
    /// watcher fires on a change to the KDBX path, it stats the file
    /// and asks "was that me?". If yes, the spurious external-change
    /// notification is suppressed. If no, the watcher proceeds with
    /// the merge / reload flow.
    ///
    /// Equality on [`SystemTime`] is exact (no fuzzy comparison). The
    /// signature is captured immediately post-rename via
    /// [`std::fs::Metadata::modified`]; a watcher that stats with the
    /// same call should observe bit-identical timestamps. Any precision
    /// mismatch (e.g. watcher truncates to seconds while engine keeps
    /// nanoseconds) is a bug we want to surface, not paper over with a
    /// tolerance window.
    ///
    /// Unlike the Swift counterpart (`consumePendingSelfWriteSignature`
    /// on `DatabaseDocument`), this method takes the pre-observed
    /// `(mtime, size)` directly rather than re-statting the file — the
    /// caller already has the stat result from its watcher event, so we
    /// avoid a redundant syscall and the API stays IO-free. Also note
    /// no 5-second TTL: the Swift version clears the signature on a
    /// timer to bound the race window; the Rust side leaves TTL
    /// (if needed) to the caller, since the engine has no async
    /// runtime to schedule the clear on.
    ///
    /// # Panics
    ///
    /// Panics if the engine's internal shared-state `Mutex` is poisoned
    /// — see [`Engine::last_self_write`] for the same caveat.
    pub fn consume_self_write_signature(
        &mut self,
        observed_mtime: SystemTime,
        observed_size: u64,
    ) -> bool {
        let expected = SelfWriteSignature {
            mtime: observed_mtime,
            size: observed_size,
        };
        let mut guard = self.shared.lock().unwrap();
        if guard.last_self_write == Some(expected) {
            guard.last_self_write = None;
            true
        } else {
            false
        }
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

    // ────────────────────────────────────────────────────────────────────
    // Query API — Phase 1 task 1.5 stubs.
    //
    // Type signatures are stable from this point. Bodies land in
    // Phase 3 tasks 3.1–3.8. See `docs/query-surface.md` for the full
    // surface description and per-method semantics.
    // ────────────────────────────────────────────────────────────────────

    /// List entries, optionally filtered to a single group.
    ///
    /// `group = None` → all entries globally; `Some(uuid)` → entries
    /// whose `group_uuid` equals the supplied UUID. Results are
    /// paginated via `page`. Ordering is by `modified_at DESC` (most
    /// recently modified first); callers wanting other orderings get
    /// them via smart folders or later sort-aware variants.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn list_entries(
        &self,
        group: Option<Uuid>,
        page: Pagination,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::reads::list_entries(&self.conn, group, page)
    }

    /// Fetch a full entry by UUID.
    ///
    /// Returns `Ok(None)` if no entry with the given UUID exists.
    /// Returns `Ok(Some(_))` for both live and recycle-bin entries;
    /// `is_recycled` discriminates.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn entry(&self, uuid: Uuid) -> Result<Option<EntryFull>, EngineError> {
        crate::reads::entry(&self.conn, uuid)
    }

    /// Count entries, optionally filtered to a single group.
    ///
    /// `group = None` → total entry count; `Some(uuid)` → count of
    /// direct children of that group.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn entry_count(&self, group: Option<Uuid>) -> Result<u64, EngineError> {
        crate::reads::entry_count(&self.conn, group)
    }

    /// Return every unique tag name in use across the vault, sorted
    /// alphabetically. Empty if no entries are tagged.
    ///
    /// Backs the Swift-side tag list (Phase 6.13 retires the in-memory
    /// `TagListStore` in favour of this engine method). Mutations that
    /// can orphan a tag (`set_tags`, `delete_entry`, `delete_group`)
    /// run an in-transaction GC sweep, so the `tag` table is
    /// authoritative — no zombie filtering required here.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn list_tags(&self) -> Result<Vec<String>, EngineError> {
        crate::reads::list_tags(&self.conn)
    }

    /// Uuid of the recycle-bin group, or `None` if no bin exists.
    ///
    /// Sourced from the `group` table's `is_recycle_bin = 1` row — the
    /// authoritative location for the bin identity. Backs the Swift-side
    /// recycle-bin uuid accessor (Phase 6.17 retires the in-memory
    /// `Vault::recycleBinUuid()` shim in favour of this).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn recycle_bin_uuid(&self) -> Result<Option<String>, EngineError> {
        crate::meta::read_recycle_bin_uuid(&self.conn)
    }

    /// Whether the recycle-bin feature is enabled for this vault.
    ///
    /// Sourced from the explicit `meta.recycle_bin_enabled` setting row
    /// written by ingest. Falls back to "does a bin group exist?" for
    /// legacy DBs that predate that setting — matches the same
    /// derivation [`Engine::project_to_vault`] uses.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn recycle_bin_enabled(&self) -> Result<bool, EngineError> {
        crate::meta::read_recycle_bin_enabled(&self.conn)
    }

    /// Per-entry history retention count cap.
    ///
    /// Sourced from `setting` row `meta.history_max_items`. Returns the
    /// keepass-core default (`10`) when the row is absent — matches
    /// `Meta::default()`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure, or
    /// [`EngineError::Projection`] if the persisted blob is the wrong
    /// width.
    pub fn history_max_items(&self) -> Result<i32, EngineError> {
        crate::meta::read_history_max_items(&self.conn)
    }

    /// Per-entry history retention size cap in bytes.
    ///
    /// Sourced from `setting` row `meta.history_max_size`. Returns the
    /// keepass-core default (`6 * 1024 * 1024`) when the row is absent
    /// — matches `Meta::default()`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure, or
    /// [`EngineError::Projection`] if the persisted blob is the wrong
    /// width.
    pub fn history_max_size(&self) -> Result<i64, EngineError> {
        crate::meta::read_history_max_size(&self.conn)
    }

    /// Configure the recycle-bin policy. `enabled` toggles soft-delete
    /// for [`Engine::recycle_entry`] / `recycle_group`; `group_uuid`
    /// selects which group acts as the bin (or `None` to clear the
    /// reference — `recycle_entry` will lazily create a bin on first
    /// soft-delete if `enabled` is true and no bin is set).
    ///
    /// Mirrors `keepass_core::Kdbx::set_recycle_bin`: writes both
    /// fields exactly as supplied, in a single transaction. The schema
    /// invariant "at most one group has `is_recycle_bin = 1`" is
    /// upheld — if `group_uuid` is Some and a different group already
    /// holds the flag, that flag is cleared atomically with the new
    /// designation.
    ///
    /// Emits [`ChangeEvent::MetaUpdated`] carrying the
    /// `meta.recycle_bin_enabled` and `meta.recycle_bin_uuid` keys
    /// (the latter even though it isn't a real `setting` row — the
    /// designation lives on `group.is_recycle_bin`; the key is a bus
    /// identifier only).
    ///
    /// Backs the Keys-Mac fresh-vault creation flow
    /// (`WelcomeView.createVault`), which designates a brand-new bin
    /// group on the first save of a freshly minted vault. Phase 6.17-I
    /// retires the in-memory `Vault::set_recycle_bin` shim in favour
    /// of this engine method.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if `group_uuid`
    ///   is Some but no matching group row exists.
    /// - [`EngineError::Sqlite`] on write failure.
    pub fn set_recycle_bin(
        &mut self,
        enabled: bool,
        group_uuid: Option<Uuid>,
    ) -> Result<(), EngineError> {
        mutations::set_recycle_bin(&mut self.conn, enabled, group_uuid)?;
        self.emit(ChangeEvent::MetaUpdated {
            keys: vec![
                crate::meta::KEY_RECYCLE_BIN_ENABLED.to_string(),
                crate::meta::KEY_RECYCLE_BIN_UUID.to_string(),
            ],
        });
        Ok(())
    }

    /// Set the per-entry history retention count cap.
    ///
    /// Persists `meta.history_max_items` and emits
    /// [`ChangeEvent::MetaUpdated`] with that key.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on write failure.
    pub fn set_history_max_items(&mut self, max: i32) -> Result<(), EngineError> {
        crate::meta::write_history_max_items(&self.conn, max).map_err(EngineError::Sqlite)?;
        self.emit(ChangeEvent::MetaUpdated {
            keys: vec![crate::meta::KEY_HISTORY_MAX_ITEMS.to_string()],
        });
        Ok(())
    }

    /// Set the per-entry history retention size cap in bytes.
    ///
    /// Persists `meta.history_max_size` and emits
    /// [`ChangeEvent::MetaUpdated`] with that key.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on write failure.
    pub fn set_history_max_size(&mut self, max: i64) -> Result<(), EngineError> {
        crate::meta::write_history_max_size(&self.conn, max).map_err(EngineError::Sqlite)?;
        self.emit(ChangeEvent::MetaUpdated {
            keys: vec![crate::meta::KEY_HISTORY_MAX_SIZE.to_string()],
        });
        Ok(())
    }

    /// Register a PNG (or any image-format-of-the-frontend's-choosing)
    /// blob in the vault's custom-icon pool and return its UUID.
    ///
    /// Dedup-by-content-hash: if an existing icon already has the same
    /// SHA-256 as `png_bytes`, its UUID is returned and the pool is
    /// left unchanged. Matches `keepass-core`'s
    /// `Kdbx::add_custom_icon` semantics so the SQLite-backed engine
    /// and the in-memory `Vault` shim agree on UUIDs for the same
    /// bytes (load-bearing during the Phase 6.17 migration window).
    ///
    /// Emits [`ChangeEvent::MetaUpdated`] with key
    /// `"meta.custom_icons"` on a fresh insert. A dedup hit does NOT
    /// emit (nothing changed).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on write failure, or
    /// [`EngineError::Projection`] if a persisted UUID row fails to
    /// parse (corrupt DB).
    pub fn add_custom_icon(&mut self, png_bytes: &[u8]) -> Result<String, EngineError> {
        let (uuid, inserted) = crate::meta::add_custom_icon_dedup(&self.conn, png_bytes)?;
        if inserted {
            self.emit(ChangeEvent::MetaUpdated {
                keys: vec![crate::meta::KEY_CUSTOM_ICONS.to_string()],
            });
        }
        Ok(uuid.to_string())
    }

    /// Clear an entry's reference to a custom icon, restoring it to
    /// the built-in icon at `icon_index` (which is left unchanged).
    ///
    /// Does **not** delete the underlying icon blob from
    /// `meta_custom_icon` — other entries or groups may still
    /// reference it. Use [`Engine::add_custom_icon`] +
    /// `update_entry` if you want to swap icons; this method is for
    /// the "go back to default" UX.
    ///
    /// Emits [`ChangeEvent::EntriesUpdated`] with the supplied uuid
    /// (the same event the generic `update_entry` path fires) so
    /// observers don't need to learn a new variant for this one
    /// column.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   row matches the uuid.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn clear_entry_custom_icon(&mut self, entry_uuid: Uuid) -> Result<(), EngineError> {
        mutations::clear_entry_custom_icon(&mut self.conn, entry_uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![entry_uuid]));
        Ok(())
    }

    /// Bump an entry's `last_used_at` to now. Read-touch flow: nothing
    /// else on the entry changes (no `modified_at` bump, no history
    /// snapshot, no protected-field reseal). Intended for `AutoFill`
    /// fulfilment and in-app password reveal, both of which fire many
    /// times per session.
    ///
    /// Emits [`ChangeEvent::EntryTouched`] rather than
    /// [`ChangeEvent::EntriesUpdated`] — the latter is a heavy refresh
    /// signal that would force listeners (e.g. an open entry detail
    /// pane) to re-pull on every touch. `EntryTouched` is the quiet
    /// last-access channel; listeners that care about Recently-Used
    /// ordering subscribe to it explicitly.
    ///
    /// Mirrors the legacy `Vault::touch_entry` semantics so the Phase
    /// 6.17 Keys-Mac migration is a like-for-like swap.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   row matches the uuid.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn touch_entry(&mut self, entry_uuid: Uuid) -> Result<(), EngineError> {
        mutations::touch_entry(&mut self.conn, entry_uuid)?;
        self.emit(ChangeEvent::EntryTouched { uuid: entry_uuid });
        Ok(())
    }

    /// Clear an entry's `last_used_at`, returning the column to NULL.
    /// User-driven explicit reset from the entry detail editor (e.g.
    /// after `AutoFill` stamped an entry that shouldn't have shown up
    /// in Recently-Used).
    ///
    /// Like [`Engine::touch_entry`], does NOT bump `modified_at` and
    /// takes no history snapshot. Unlike `touch_entry`, this is a
    /// view-affecting user gesture, so it emits
    /// [`ChangeEvent::EntriesUpdated`] (entry detail panes refresh).
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   row matches the uuid.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn clear_entry_last_access(&mut self, entry_uuid: Uuid) -> Result<(), EngineError> {
        mutations::clear_entry_last_access(&mut self.conn, entry_uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![entry_uuid]));
        Ok(())
    }

    /// Fetch the raw bytes for a custom icon by UUID.
    ///
    /// Returns `Ok(None)` if no icon with that UUID is in the pool —
    /// callers should treat that as "icon no longer registered", not
    /// an error. Stale references can survive in caches /
    /// snapshots, and propagating a `NotFound` here would force
    /// every renderer to handle that case as an exception path.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn custom_icon_bytes(&self, uuid: Uuid) -> Result<Option<Vec<u8>>, EngineError> {
        crate::meta::read_custom_icon_bytes(&self.conn, uuid)
    }

    /// Return the full group tree as a flat list.
    ///
    /// Tree shape is reconstructed by the caller from each
    /// [`GroupNode`]'s `parent_uuid` reference; the root group has
    /// `parent_uuid = None`. Rows are ordered root-first then
    /// alphabetically by name (with `uuid` as a deterministic tie
    /// breaker), so callers can rely on a stable iteration order
    /// across runs of the same vault.
    ///
    /// `entry_count_direct` counts entries directly in each group.
    /// Regular groups exclude recycled entries; the recycle bin group
    /// itself includes its contents (so the bin's count is the number
    /// of items the user could empty).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn group_tree(&self) -> Result<Vec<GroupNode>, EngineError> {
        crate::reads::group_tree(&self.conn)
    }

    /// Return the parent group's UUID for `child_uuid`, or `Ok(None)`
    /// if `child_uuid` is the root group (which has no parent).
    ///
    /// Trivial single-row `SELECT` against `group.parent_uuid` — much
    /// cheaper than fetching the whole tree just to read one edge.
    /// Mirrors the legacy `Vault::group_parent` shape so consumer
    /// migration off the in-memory `Vault` is a direct call swap.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if no group
    ///   with `child_uuid` exists.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn group_parent_uuid(&self, child_uuid: Uuid) -> Result<Option<Uuid>, EngineError> {
        crate::reads::group_parent_uuid(&self.conn, child_uuid)
    }

    /// Return `true` if `group_uuid` is at any depth inside the subtree
    /// rooted at `ancestor_uuid`. **Not inclusive** — a group is not
    /// its own descendant, so `is_descendant_of(g, g)` returns `false`
    /// (provided `g` exists).
    ///
    /// Implementation walks `parent_uuid` up from `group_uuid` until
    /// it either hits `ancestor_uuid` (true), reaches the root with no
    /// match (false), or trips the defensive iteration cap (false —
    /// guards against a `parent_uuid` cycle in a malformed user vault).
    ///
    /// `ancestor_uuid` is not validated separately: if it doesn't
    /// match any group, the walk simply terminates at root with
    /// `false`, which is the natural answer.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if `group_uuid`
    ///   doesn't match any group row.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn is_descendant_of(
        &self,
        group_uuid: Uuid,
        ancestor_uuid: Uuid,
    ) -> Result<bool, EngineError> {
        crate::reads::is_descendant_of(&self.conn, group_uuid, ancestor_uuid)
    }

    /// Full-text search across title / username / URL / notes, with
    /// a tag-substring fallback.
    ///
    /// Backed by the FTS5 virtual table built in migration 0001.
    /// Primary hits are ranked by FTS5's `bm25` (lower = more
    /// relevant); a `UNION ALL` of `tag.name LIKE %query%` matches
    /// (de-duplicated against the FTS bucket) is appended after,
    /// alphabetised by title. Results are paginated by `page`.
    ///
    /// Empty / whitespace-only queries return an empty Vec without
    /// touching the database.
    ///
    /// FTS5 special characters in the query are handled by wrapping
    /// the input in a quoted phrase when needed — see
    /// `escape_fts5_query` in the `reads` module for details.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn search(&self, query: &str, page: Pagination) -> Result<Vec<EntrySummary>, EngineError> {
        crate::reads::search(&self.conn, query, page)
    }

    /// Find entries matching an `AutoFill` service identifier.
    ///
    /// Powers the `AutoFill` extension's lookup path: given a service
    /// identifier (typically a domain like `google.com` or a full URL
    /// like `https://accounts.google.com/signin`), return the entries
    /// most likely to match, in best-match-first order.
    ///
    /// # Matching tiers
    ///
    /// 1. Exact `url_host` match (case-insensitive).
    /// 2. eTLD+1 match — covers `accounts.google.com` finding
    ///    entries saved as `google.com` and vice versa. Uses a
    ///    hand-rolled two-label suffix list (no Public Suffix List
    ///    dependency in v1).
    /// 3. Substring match — the identifier appears anywhere inside
    ///    `entry.url`. Last-resort tier for unparseable URLs.
    ///
    /// Recycled entries are excluded. Results dedupe by uuid (best
    /// tier wins) and sort by tier, then `last_used_at` desc, then
    /// `modified_at` desc. Capped at `limit` rows.
    ///
    /// Empty / whitespace identifiers and `limit = 0` return an empty
    /// `Vec` without touching the database.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn search_by_service(
        &self,
        identifier: &str,
        limit: usize,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::reads::search_by_service(&self.conn, identifier, limit)
    }

    /// Evaluate a smart folder and return its matching entries.
    ///
    /// Looks the folder up by id, compiles its
    /// [`crate::predicate::Predicate`] to SQL via
    /// [`crate::predicate_sql::compile`], and runs the result against
    /// the entry table. Ordering and pagination semantics match
    /// [`Engine::list_entries`] (most-recently-modified first, `uuid`
    /// as a deterministic tie breaker).
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::NotEvaluable`] if the persisted predicate
    ///   contains a [`Predicate::Unknown`] node (i.e. the row's
    ///   `evaluable` column is `false`).
    /// - [`EngineError::Sqlite`] on any other query failure.
    pub fn smart_folder_entries(
        &self,
        folder_id: i64,
        page: Pagination,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::smart_folder::smart_folder_entries(&self.conn, folder_id, page)
    }

    /// Count entries matching a smart folder.
    ///
    /// Same evaluation rules as [`Engine::smart_folder_entries`];
    /// cheaper than fetching rows when the caller only needs the badge
    /// count.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::NotEvaluable`] if the folder is not evaluable.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn smart_folder_count(&self, folder_id: i64) -> Result<u64, EngineError> {
        crate::smart_folder::smart_folder_count(&self.conn, folder_id)
    }

    /// Evaluate an arbitrary [`Predicate`] and return matching entries.
    ///
    /// Direct-predicate variant of [`Engine::smart_folder_entries`].
    /// Intended for built-in smart folders (see
    /// [`crate::predicate_builtin`]) and any other call site that
    /// holds a predicate but no persisted `smart_folder` row.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotEvaluable`] if the predicate contains a
    ///   [`Predicate::Unknown`] node or an empty `And` / `Or` /
    ///   tag-set.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn entries_matching(
        &self,
        predicate: &Predicate,
        page: Pagination,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::smart_folder::entries_matching(&self.conn, predicate, page)
    }

    /// Count entries matching an arbitrary [`Predicate`].
    ///
    /// Direct-predicate variant of [`Engine::smart_folder_count`].
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotEvaluable`] if the predicate is not
    ///   evaluable.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn count_matching(&self, predicate: &Predicate) -> Result<u64, EngineError> {
        crate::smart_folder::count_matching(&self.conn, predicate)
    }

    /// List every smart folder, ordered by row id ascending (i.e.
    /// insertion order).
    ///
    /// Each row's `predicate_json` column is deserialised; an
    /// unknown discriminator in the stored JSON surfaces as
    /// [`Predicate::Unknown`] in the returned
    /// [`SmartFolder::predicate`], and the
    /// [`SmartFolder::evaluable`] flag mirrors what was written to
    /// the column (which itself mirrors
    /// [`Predicate::is_evaluable`](crate::predicate::Predicate::is_evaluable)
    /// at write time).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure, or a
    /// `FromSqlConversionFailure`-flavoured variant if a row's JSON
    /// is malformed for a known predicate variant.
    pub fn list_smart_folders(&self) -> Result<Vec<SmartFolder>, EngineError> {
        crate::smart_folder::list_all(&self.conn)
    }

    /// Fetch a single smart folder by id.
    ///
    /// Returns `Ok(None)` if no row with the given id exists.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure or malformed
    /// stored predicate JSON.
    pub fn smart_folder(&self, id: i64) -> Result<Option<SmartFolder>, EngineError> {
        crate::smart_folder::get_one(&self.conn, id)
    }

    /// Create a new smart folder; return the assigned row id.
    ///
    /// The folder's `evaluable` column is computed from
    /// [`Predicate::is_evaluable`] at write time — passing a tree
    /// containing [`Predicate::Unknown`] is legal but the resulting
    /// row will have `evaluable = false`
    /// and the upcoming evaluation path (task 3.8) will refuse to
    /// run it.
    ///
    /// `created_at` and `modified_at` are both set to the current
    /// wall-clock time in ms since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on `INSERT` failure or
    /// predicate JSON serialisation failure (only happens for
    /// non-finite `EntropyBelow.bits`).
    pub fn create_smart_folder(
        &mut self,
        name: &str,
        predicate: &Predicate,
    ) -> Result<i64, EngineError> {
        let id = crate::smart_folder::create(&mut self.conn, name, predicate)?;
        self.emit(ChangeEvent::SmartFolderCreated(id));
        Ok(id)
    }

    /// Update an existing smart folder's name and predicate.
    ///
    /// Rewrites `name`, `predicate_json`, the derived `evaluable`
    /// flag, and `modified_at`. The `version` and `created_at`
    /// columns are left untouched.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::Sqlite`] on `UPDATE` failure or predicate
    ///   JSON serialisation failure.
    pub fn update_smart_folder(
        &mut self,
        id: i64,
        name: &str,
        predicate: &Predicate,
    ) -> Result<(), EngineError> {
        crate::smart_folder::update(&mut self.conn, id, name, predicate)?;
        self.emit(ChangeEvent::SmartFolderUpdated(id));
        Ok(())
    }

    /// Delete a smart folder by id.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::Sqlite`] on `DELETE` failure.
    pub fn delete_smart_folder(&mut self, id: i64) -> Result<(), EngineError> {
        crate::smart_folder::delete(&mut self.conn, id)?;
        self.emit(ChangeEvent::SmartFolderDeleted(id));
        Ok(())
    }

    /// Test-only helper: compile `predicate` against `now_ms` and
    /// return the UUIDs of matching entries.
    ///
    /// Exists so the predicate-SQL compiler's integration test can
    /// run a compiled fragment against the real schema without 3.8's
    /// `Engine::smart_folder_entries` being in place yet. Hidden from
    /// the public docs to keep the surface clean; not intended for
    /// production callers — 3.8's `smart_folder_entries` is the
    /// real surface.
    #[doc(hidden)]
    pub fn compiled_predicate_uuids_for_test(
        &self,
        predicate: &Predicate,
        now_ms: i64,
    ) -> Result<Vec<Uuid>, EngineError> {
        let compiled = crate::predicate_sql::compile(predicate, now_ms).map_err(|e| {
            EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?;
        let sql = format!(
            "SELECT uuid FROM entry WHERE {} ORDER BY uuid ASC",
            compiled.where_sql
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(compiled.params), |r| {
                let s: String = r.get(0)?;
                Uuid::parse_str(&s).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Reveal the cleartext password for an entry.
    ///
    /// Fetches the wrapped blob from `entry_protected`, asks the
    /// field-protector callback for a fresh session key, and
    /// AES-GCM-opens in process. The result lives in a [`SecretString`]
    /// so it zeroes on drop.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "password"`) if the entry
    ///   has no `entry_protected` Password row.
    /// - [`EngineError::Reveal`] for session-key acquisition failure or
    ///   AES-GCM unwrap failure.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn reveal_password(&self, uuid: Uuid) -> Result<SecretString, EngineError> {
        crate::reveal::reveal_password(&self.conn, &*self.field_protector, uuid)
    }

    /// Reveal the cleartext value of a custom field on an entry.
    ///
    /// Symmetric with [`Engine::reveal_password`] but for arbitrary
    /// named protected fields recorded in `entry_protected`. Asking for
    /// `field_name = "Password"` is allowed — it routes through the
    /// same row [`Engine::reveal_password`] reads, so the two are
    /// equivalent for that name; [`Engine::reveal_password`] stays as
    /// the canonical entry point.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "custom_field"`) if no
    ///   `entry_protected` row matches `(uuid, field_name)`.
    /// - [`EngineError::Reveal`] for session-key acquisition failure or
    ///   AES-GCM unwrap failure.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn reveal_custom_field(
        &self,
        uuid: Uuid,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::reveal::reveal_custom_field(&self.conn, &*self.field_protector, uuid, field_name)
    }

    /// Reveal the cleartext value of a field in a historic snapshot of
    /// an entry.
    ///
    /// **Symmetric with the live-reveal paths.** Protected fields
    /// inside a history snapshot (the canonical `password` slot and any
    /// custom field with `protected: true`) are AES-GCM-sealed under
    /// the same session key as the live `entry_protected.wrapped_blob`
    /// rows, then base64-encoded into the snapshot JSON. This method
    /// deserialises the JSON, base64-decodes the wrapped bytes for the
    /// requested field, acquires a fresh session key via the
    /// [`keepass_core::protector::FieldProtector`], and AES-GCM-opens.
    /// Non-protected custom fields (`protected: false`) skip the unwrap
    /// and return the plaintext from the JSON directly — no session-key
    /// fetch in that case.
    ///
    /// `field_name = "Password"` reads the historic password;
    /// any other name reads from the snapshot's `custom_fields` map.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "history_snapshot"` or
    ///   `"history_field"`) if the snapshot or named field is missing.
    /// - [`EngineError::Reveal`] for session-key acquisition failure,
    ///   base64-decode failure, or AES-GCM unwrap failure; or wrapping
    ///   [`RevealError::Json`](crate::RevealError::Json) if the
    ///   `snapshot_json` is malformed.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn reveal_history_field(
        &self,
        uuid: Uuid,
        history_index: u32,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::reveal::reveal_history_field(
            &self.conn,
            &*self.field_protector,
            uuid,
            history_index,
            field_name,
        )
    }

    /// Fetch the bytes of an entry attachment by attachment name.
    ///
    /// Returns the raw blob from `attachment_blob` joined through
    /// `entry_attachment`. Conceptually a query method, so it lands in
    /// 3.1 alongside the rest of the entry-surface implementation.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "attachment"`) if no
    ///   `entry_attachment` row matches the `(uuid, attachment_name)`
    ///   pair. Covers both the missing-entry and missing-name cases.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn attachment_bytes(
        &self,
        uuid: Uuid,
        attachment_name: &str,
    ) -> Result<Vec<u8>, EngineError> {
        crate::reads::attachment_bytes(&self.conn, uuid, attachment_name)
    }

    /// Fetch the bytes of an attachment as it existed in a specific
    /// history snapshot of an entry.
    ///
    /// Resolves the snapshot's `attachments` list to find the named
    /// attachment's content-addressed SHA-256, then joins through
    /// `attachment_blob` for the raw bytes. The blob row survives even
    /// if later edits to the live entry replace or drop the attachment,
    /// so a snapshot's bytes remain retrievable as long as some entry
    /// (live or historical) still references that SHA.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "attachment"`) for every
    ///   miss along the chain: missing entry, missing history index,
    ///   missing attachment name in the snapshot, pre-widening snapshot
    ///   that didn't record the SHA-256, or dangling blob reference.
    /// - [`EngineError::Sqlite`] for query failure.
    /// - [`EngineError::Reveal`] (`Json`) if the snapshot JSON fails
    ///   to deserialise — shouldn't happen for engine-written rows.
    pub fn history_attachment_bytes(
        &self,
        uuid: Uuid,
        history_index: u32,
        attachment_name: &str,
    ) -> Result<Vec<u8>, EngineError> {
        crate::reads::history_attachment_bytes(&self.conn, uuid, history_index, attachment_name)
    }

    // ────────────────────────────────────────────────────────────────────
    // Mutation API — Phase 4 tasks 4.1 / 4.3.
    //
    // Every mutation runs inside a single transaction, refreshes the
    // relevant `modified_at`, and maintains derived columns. After the
    // commit returns, each method invokes [`Engine::emit`] with the
    // appropriate [`ChangeEvent`]; observers see events only for
    // successful mutations (failed mutations roll back and never emit).
    // ────────────────────────────────────────────────────────────────────

    /// Create a new entry in `group_uuid`. Returns the new entry's
    /// freshly-generated UUID.
    ///
    /// `created_at`, `modified_at`, and `accessed_at` are all set to the
    /// current wall-clock time. The canonical Password slot is
    /// AES-GCM-sealed under a fresh session key from the configured
    /// [`FieldProtector`] and stored in `entry_protected`. Protected
    /// custom fields take the same path; non-protected ones land in
    /// `entry_custom_field`. Tags are trimmed + de-duplicated before
    /// insert.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if no group with
    ///   `group_uuid` exists.
    /// - [`EngineError::Wrap`] / [`EngineError::SessionKey`] on wrap
    ///   failure.
    /// - [`EngineError::Sqlite`] on insert failure.
    pub fn create_entry(
        &mut self,
        group_uuid: Uuid,
        fields: NewEntryFields,
    ) -> Result<Uuid, EngineError> {
        let result = mutations::create_entry(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            group_uuid,
            fields,
        )?;
        self.emit(ChangeEvent::EntriesAdded(vec![result]));
        Ok(result)
    }

    /// Update an existing entry. Each field of `update` is `Option`:
    /// `None` leaves it alone, `Some(value)` writes it.
    ///
    /// Setting `password` re-wraps the canonical Password slot and
    /// refreshes `password_strength_bucket`, `password_entropy`, and
    /// `password_fingerprint`. Setting `url` refreshes `url_host`.
    /// `modified_at` is always bumped to now.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Wrap`] / [`EngineError::SessionKey`] on wrap
    ///   failure (only when `password` is updated).
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn update_entry(&mut self, uuid: Uuid, update: EntryUpdate) -> Result<(), EngineError> {
        mutations::update_entry(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            uuid,
            update,
        )?;
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Soft-delete an entry: set `is_recycled = 1` and move to the
    /// recycle bin group (if one exists).
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn recycle_entry(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        mutations::recycle_entry(&mut self.conn, uuid)?;
        self.emit(ChangeEvent::EntriesRecycled(vec![uuid]));
        Ok(())
    }

    /// Restore a recycled entry: clear `is_recycled`. The group does
    /// not move — callers decide whether to move it elsewhere.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn restore_entry(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        mutations::restore_entry(&mut self.conn, uuid)?;
        self.emit(ChangeEvent::EntriesRestored(vec![uuid]));
        Ok(())
    }

    /// Hard-delete an entry. Cascades remove all `entry_protected`,
    /// `entry_attachment`, `entry_custom_field`, `entry_history`, and
    /// `entry_tag` rows (per schema FK `ON DELETE CASCADE`).
    /// Attachment blobs in `attachment_blob` are content-addressed and
    /// shared; they're not garbage-collected here.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Sqlite`] on delete failure.
    pub fn delete_entry(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        let outcome = mutations::delete_entry(&mut self.conn, uuid)?;
        self.emit(ChangeEvent::EntriesDeleted(vec![EntryDeletionInfo {
            uuid,
            previous_group: outcome.previous_group,
        }]));
        Ok(())
    }

    /// Move an entry to a different group.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"` or `"group"`).
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn move_entry(&mut self, uuid: Uuid, new_group_uuid: Uuid) -> Result<(), EngineError> {
        let outcome = mutations::move_entry(&mut self.conn, uuid, new_group_uuid)?;
        self.emit(ChangeEvent::EntriesMoved(vec![EntryMove {
            uuid,
            from_group: outcome.from_group,
            to_group: outcome.to_group,
        }]));
        Ok(())
    }

    /// Set the value of a protected field (canonical `Password` slot
    /// or a named protected custom field). UPSERTs `entry_protected`.
    /// When `field_name == "Password"`, refreshes strength / entropy /
    /// fingerprint columns.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Wrap`] / [`EngineError::SessionKey`].
    pub fn set_protected_field(
        &mut self,
        uuid: Uuid,
        field_name: &str,
        plaintext: SecretString,
    ) -> Result<(), EngineError> {
        mutations::set_protected_field(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            uuid,
            field_name,
            plaintext,
        )?;
        self.emit(ChangeEvent::ProtectedFieldChanged {
            entry_uuid: uuid,
            field_name: field_name.to_owned(),
        });
        Ok(())
    }

    /// Set the value of a non-protected custom field. UPSERTs
    /// `entry_custom_field`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn set_non_protected_custom_field(
        &mut self,
        uuid: Uuid,
        field_name: &str,
        value: &str,
    ) -> Result<(), EngineError> {
        mutations::set_non_protected_custom_field(&mut self.conn, uuid, field_name, value)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Remove a custom field by name. Deletes from whichever of
    /// `entry_protected` / `entry_custom_field` the field lives in.
    /// No error if the field doesn't exist (idempotent removal).
    ///
    /// Refuses to delete the canonical `Password` slot — that would
    /// leave reveal callers with no row to read.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches,
    ///   or `entity = "custom_field"` if `field_name == "Password"`.
    /// - [`EngineError::Sqlite`].
    pub fn remove_custom_field(&mut self, uuid: Uuid, field_name: &str) -> Result<(), EngineError> {
        mutations::remove_custom_field(&mut self.conn, uuid, field_name)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Replace the entry's tags wholesale. Inputs are trimmed and
    /// de-duplicated.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn set_tags(&mut self, uuid: Uuid, tags: Vec<String>) -> Result<(), EngineError> {
        mutations::set_tags(&mut self.conn, uuid, tags)?;
        // Two events: the tag set changed (`TagsChanged`), and the
        // entry's `modified_at` was bumped (`EntriesUpdated`). Frontends
        // that only care about tag indices subscribe to the first;
        // entry-row observers subscribe to the second. Cheap to fire
        // both, no need to make the observer reason about overlap.
        self.emit(ChangeEvent::TagsChanged(vec![uuid]));
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Attach a file. Bytes are SHA-256 hashed and stored
    /// content-addressed in `attachment_blob`; the link row in
    /// `entry_attachment` upserts on `(entry_uuid, attachment_name)`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn attach_file(
        &mut self,
        uuid: Uuid,
        name: &str,
        bytes: Vec<u8>,
    ) -> Result<(), EngineError> {
        mutations::attach_file(&mut self.conn, uuid, name, bytes)?;
        self.emit(ChangeEvent::AttachmentsChanged(vec![uuid]));
        Ok(())
    }

    /// Remove an attachment by name. The underlying `attachment_blob`
    /// row is left in place (content-addressed and potentially shared).
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn remove_attachment(&mut self, uuid: Uuid, name: &str) -> Result<(), EngineError> {
        mutations::remove_attachment(&mut self.conn, uuid, name)?;
        self.emit(ChangeEvent::AttachmentsChanged(vec![uuid]));
        Ok(())
    }

    /// Create a new group under `parent_uuid`. Returns the new uuid.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if the parent
    ///   doesn't exist.
    /// - [`EngineError::Sqlite`].
    pub fn create_group(
        &mut self,
        parent_uuid: Uuid,
        fields: NewGroupFields,
    ) -> Result<Uuid, EngineError> {
        let uuid = mutations::create_group(&mut self.conn, parent_uuid, fields)?;
        self.emit(ChangeEvent::GroupsAdded(vec![uuid]));
        Ok(uuid)
    }

    /// Update an existing group. Patch shape: `None` leaves alone,
    /// `Some(value)` writes.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`).
    /// - [`EngineError::Sqlite`].
    pub fn update_group(&mut self, uuid: Uuid, update: GroupUpdate) -> Result<(), EngineError> {
        mutations::update_group(&mut self.conn, uuid, update)?;
        self.emit(ChangeEvent::GroupsUpdated(vec![uuid]));
        Ok(())
    }

    /// Soft-recycle a group: move it under the database's recycle bin
    /// group. KDBX UX is "move, not delete"; this matches that.
    ///
    /// If no recycle-bin group exists, returns
    /// [`EngineError::NotFound`] (`entity = "recycle_bin"`). The engine
    /// deliberately does not auto-create a bin — that's a frontend
    /// decision. Callers wanting hard removal use [`Engine::delete_group`].
    ///
    /// Direct child entries of this group are not touched; they're
    /// implicitly recycled by virtue of having a recycled ancestor.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"` or
    ///   `"recycle_bin"`).
    /// - [`EngineError::CycleDetected`] if the caller passes the bin's
    ///   own uuid.
    /// - [`EngineError::Sqlite`].
    pub fn recycle_group(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        mutations::recycle_group(&mut self.conn, uuid)?;
        // Only the group event fires — descendant entries and groups
        // are implicitly recycled by sitting under a recycled ancestor.
        // Frontends listening on group events know to re-query their
        // subtree views; emitting per-descendant events would force
        // every observer to consume them even when they don't care.
        self.emit(ChangeEvent::GroupsRecycled(vec![uuid]));
        Ok(())
    }

    /// Restore a recycled group by moving it to `new_parent_uuid`.
    /// KDBX itself doesn't track the original location, so the caller
    /// supplies the destination.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`).
    /// - [`EngineError::CycleDetected`] if the destination is the group
    ///   itself or a descendant.
    /// - [`EngineError::Sqlite`].
    pub fn restore_group(&mut self, uuid: Uuid, new_parent_uuid: Uuid) -> Result<(), EngineError> {
        mutations::restore_group(&mut self.conn, uuid, new_parent_uuid)?;
        // Same shape as recycle — emit only the group event. Descendant
        // recycle status is determined by ancestor walk, not a column,
        // so there's nothing to fan out per row.
        self.emit(ChangeEvent::GroupsRestored(vec![uuid]));
        Ok(())
    }

    /// Hard-delete a group and every descendant group + entry.
    ///
    /// The schema does not declare `ON DELETE CASCADE` on the group
    /// self-FK or on `entry.group_uuid`, so the engine walks the
    /// subtree itself. Entry child tables cascade off `entry`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`).
    /// - [`EngineError::Sqlite`].
    pub fn delete_group(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        let outcome = mutations::delete_group(&mut self.conn, uuid)?;
        // One combined `EntriesDeleted` and one combined `GroupsDeleted`
        // covering the entire cascade. Order: entries first, then
        // groups — leaves-up, mirroring the delete order inside the
        // transaction. Frontends get all the info in two events.
        if !outcome.deleted_entries.is_empty() {
            let entries = outcome
                .deleted_entries
                .into_iter()
                .map(|(uuid, previous_group)| EntryDeletionInfo {
                    uuid,
                    previous_group,
                })
                .collect();
            self.emit(ChangeEvent::EntriesDeleted(entries));
        }
        let groups = outcome
            .deleted_groups
            .into_iter()
            .map(|(uuid, previous_parent)| GroupDeletionInfo {
                uuid,
                previous_parent,
            })
            .collect();
        self.emit(ChangeEvent::GroupsDeleted(groups));
        Ok(())
    }

    /// Move a group to a new parent. Rejects cycles: the new parent
    /// cannot be the group itself or any descendant.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`).
    /// - [`EngineError::CycleDetected`].
    /// - [`EngineError::Sqlite`].
    pub fn move_group(&mut self, uuid: Uuid, new_parent_uuid: Uuid) -> Result<(), EngineError> {
        let outcome = mutations::move_group(&mut self.conn, uuid, new_parent_uuid)?;
        self.emit(ChangeEvent::GroupsMoved(vec![GroupMove {
            uuid,
            from_parent: outcome.from_parent,
            to_parent: outcome.to_parent,
        }]));
        Ok(())
    }

    /// Reorder `uuid` within its current parent's child list.
    /// `new_position` is the 0-based final index in the sibling
    /// sequence; values past the last index clamp to the end.
    ///
    /// Cross-parent moves use [`Engine::move_group`] instead — that
    /// path appends to the new parent. `reorder_group` only rewrites
    /// `sort_order` values; it never changes parentage.
    ///
    /// Emits [`ChangeEvent::GroupsReordered`] carrying the full ordered
    /// sibling list under the parent.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if no group
    ///   with that UUID exists or the target is the root group.
    /// - [`EngineError::Sqlite`].
    pub fn reorder_group(&mut self, uuid: Uuid, new_position: u32) -> Result<(), EngineError> {
        let outcome = mutations::reorder_group(&mut self.conn, uuid, new_position)?;
        self.emit(ChangeEvent::GroupsReordered(outcome.siblings_in_order));
        Ok(())
    }

    /// Return the historical snapshots of an entry.
    ///
    /// Ordered oldest-first (`history_index` ascending). Empty vector
    /// for entries that exist but have no history snapshots. Protected
    /// field values are not included; fetch via
    /// [`Engine::reveal_history_field`].
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   with that UUID exists.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn history(&self, uuid: Uuid) -> Result<Vec<HistoricEntry>, EngineError> {
        crate::reads::history(&self.conn, uuid)
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
fn find_entry_parent_group(
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
