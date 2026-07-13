//! `SQLite` → KDBX serialise — task 2.5.
//!
//! Projects the engine's `SQLite` mirror back into a fresh
//! [`Vault`](keepass_core::model::Vault), installs it on the supplied
//! [`Kdbx<Unlocked>`] handle, calls
//! [`Kdbx::save_to_bytes`](keepass_core::kdbx::Kdbx::save_to_bytes) to
//! re-encrypt under the existing crypto envelope, and atomically writes
//! the resulting bytes to disk.
//!
//! ## Meta preservation
//!
//! Since migration 0003 the projection reconstitutes the full
//! [`Meta`](keepass_core::model::Meta) block (every scalar field, the
//! custom-icons pool, custom-data items, memory-protection flags,
//! unknown-xml fragments) *and* `Vault::deleted_objects` from `SQLite`.
//! The save path no longer needs the live `Kdbx` handle to carry any
//! of these forward — `replace_vault(projected)` overwrites the
//! handle's vault wholesale and is sufficient.
//!
//! ## Atomic write
//!
//! Bytes go to a tempfile (`tempfile::NamedTempFile::new_in`) and are
//! flushed + `sync_all`'d before
//! [`NamedTempFile::persist`](tempfile::NamedTempFile::persist) renames
//! over the destination. The tempfile is created in the destination's
//! parent directory by default; callers that need to override this
//! (e.g. sandboxed macOS frontends saving to iCloud Drive, where the
//! security-scoped bookmark grants write access to the kdbx *file* but
//! not its surrounding folder) can pass an explicit `temp_dir` through
//! [`Engine::save_to_kdbx`]. Same-volume rename is still required for
//! atomicity; on darwin both iCloud Drive and `NSTemporaryDirectory()`
//! live on the user's home volume. The parent directory is then opened
//! and `sync_all`'d so the rename survives a power loss between the
//! file sync and a hypothetical follow-up crash. After the rename we
//! `stat` the destination to capture mtime + size for the self-write
//! signature.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};

use crate::engine::Engine;
use crate::error::EngineError;

/// `(mtime, size)` of the last KDBX file this engine wrote.
///
/// Recorded by [`Engine::save_to_kdbx`] after the atomic rename, and
/// (in task 2.6) consumed by the file watcher integration to suppress
/// spurious external-change fires from our own writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfWriteSignature {
    /// `modified` timestamp of the written file, as returned by the
    /// filesystem immediately after the rename.
    pub mtime: SystemTime,
    /// Byte length of the written file.
    pub size: u64,
}

/// `(mtime, size)` of the KDBX file whose contents the engine's
/// `SQLite` mirror currently corresponds to.
///
/// Recorded after a successful
/// [`Engine::ingest_from_kdbx`](crate::engine::Engine::ingest_from_kdbx)
/// (via [`Engine::record_kdbx_state_signature`](crate::engine::Engine::record_kdbx_state_signature))
/// and after a successful [`Engine::save_to_kdbx`](crate::engine::Engine::save_to_kdbx)
/// (automatic — the save path already has the path on hand). Persisted
/// in the `setting` table so the value survives engine close + reopen.
///
/// Distinct from [`SelfWriteSignature`]: that one is consumed by the
/// file-watcher self-write suppression on a single match (consume-on-match)
/// and would lose its meaning if shared with the ingest path. This
/// signature is a stable "what does my `SQLite` state correspond to on
/// disk?" indicator that Keys-Mac uses to skip re-ingest on unlock when
/// the on-disk KDBX hasn't changed since the last sync.
///
/// Shape mirrors `SelfWriteSignature` semantically but uses
/// `mtime_ms: i64` (milliseconds since Unix epoch) for cross-FFI
/// compatibility — Swift consumers compute the same value from
/// `FileManager`'s `modificationDate.timeIntervalSince1970 * 1000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdbxStateSignature {
    /// `modified` timestamp of the KDBX file at the moment the signature
    /// was recorded, in milliseconds since the Unix epoch.
    pub mtime_ms: i64,
    /// Byte length of the KDBX file.
    pub byte_count: u64,
}

/// The engine's persistence watermark pair — the "does the KDBX still
/// owe a write?" truth, owned below the seam (migration 0012).
///
/// `mutation_seq` advances (via `AFTER`-triggers, inside the mutating
/// transaction) whenever any projected vault content changes.
/// `persisted_seq` is the `mutation_seq` captured at the *start* of
/// the last successful persist or mirror↔disk correspondence point
/// (save, ingest, rebuild). A mutation landing while a persist is in
/// flight therefore stays strictly greater than `persisted_seq` and
/// can never be masked by that persist's completion.
///
/// Both values live in the `setting` table, so the answer survives
/// close + reopen: a process that crashed after a mutation but before
/// a save reopens visibly dirty, and the frontend's orchestrator
/// flushes instead of the KDBX silently lagging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistenceState {
    /// Monotonic content-change counter (trigger-maintained).
    pub mutation_seq: i64,
    /// `mutation_seq` at the start of the last successful persist.
    pub persisted_seq: i64,
}

impl PersistenceState {
    /// `true` when the mirror holds content the KDBX file has not been
    /// handed yet — i.e. a `save_to_kdbx` is owed.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.mutation_seq > self.persisted_seq
    }
}

impl KdbxStateSignature {
    /// Stat `path` and build a signature from its `(mtime, size)`.
    pub(crate) fn from_path(path: &Path) -> Result<Self, EngineError> {
        let meta = std::fs::metadata(path)?;
        let mtime = meta.modified()?;
        let mtime_ms = match mtime.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
            Err(e) => {
                // Pre-1970 mtime — clamp to negative ms.
                -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX)
            }
        };
        Ok(Self {
            mtime_ms,
            byte_count: meta.len(),
        })
    }
}

/// Engine-internal entry point. Called from
/// [`Engine::save_to_kdbx`](crate::engine::Engine::save_to_kdbx).
pub(crate) fn save(
    engine: &mut Engine,
    path: &Path,
    kdbx: &mut Kdbx<Unlocked>,
    temp_dir: Option<&Path>,
) -> Result<(), EngineError> {
    save_inner(engine, path, kdbx, temp_dir, None)
}

/// Re-keying entry point. Called from
/// [`Engine::rekey_to_kdbx`](crate::engine::Engine::rekey_to_kdbx).
///
/// Identical to [`save`] except that, after the `SQLite` mirror has
/// been projected onto `kdbx` and before serialisation, the handle's
/// crypto envelope is rotated to `new_key` via
/// [`Kdbx::rekey`](keepass_core::kdbx::Kdbx::rekey). The bytes written
/// to disk therefore open **only** under `new_key`; the key `kdbx` was
/// unlocked with no longer decrypts them.
pub(crate) fn save_rekeyed(
    engine: &mut Engine,
    path: &Path,
    kdbx: &mut Kdbx<Unlocked>,
    new_key: &CompositeKey,
    temp_dir: Option<&Path>,
) -> Result<(), EngineError> {
    save_inner(engine, path, kdbx, temp_dir, Some(new_key))
}

/// Shared body of [`save`] and [`save_rekeyed`].
///
/// The only difference between a plain save and a re-key is *where the
/// new ciphertext's key comes from*: a plain save re-encrypts under the
/// envelope `kdbx` already carries; a re-key rotates that envelope to
/// `rekey` first. Everything downstream — projection, atomic write,
/// signatures, blob GC — is identical, so it lives here once rather
/// than being copied into two near-identical functions.
fn save_inner(
    engine: &mut Engine,
    path: &Path,
    kdbx: &mut Kdbx<Unlocked>,
    temp_dir: Option<&Path>,
    rekey: Option<&CompositeKey>,
) -> Result<(), EngineError> {
    // 0. Snapshot the mutation watermark BEFORE projecting. The bytes
    //    we are about to write represent the mirror as of this instant;
    //    any mutation that lands after this point (should the engine
    //    ever admit one mid-save) must stay dirty past this persist.
    let seq_at_start = engine.persistence_state()?.mutation_seq;

    // 1. Project the SQLite mirror back to a Vault. After migration
    //    0003, the projection reconstitutes the full `Meta` and
    //    `deleted_objects` — no live-handle splice required.
    let projected = engine.project_to_vault()?;

    // 2. Install the projected vault on `kdbx`. The handle's previous
    //    vault contents (entries, groups, meta) are replaced wholesale.
    kdbx.replace_vault(projected);

    // 2b. Re-key path only: rotate the crypto envelope (fresh master
    //     seed, IV, and KDF salt/transform-seed; transformed key
    //     re-derived against `new_key`) so the bytes serialised next
    //     decrypt only under `new_key`. Applied *after* `replace_vault`
    //     so the `master_key_changed` / `settings_changed` meta stamps
    //     `rekey` writes land on the vault that actually gets
    //     serialised (the mirror picks them up on its next ingest from
    //     disk). The inner-stream key that protects field values is
    //     untouched — it's independent of the master key — so projected
    //     protected fields survive the rotation unchanged.
    if let Some(new_key) = rekey {
        kdbx.rekey(new_key)
            .map_err(|e| EngineError::Serialise(e.to_string()))?;
    }

    // 3. Serialise.
    let bytes = kdbx
        .save_to_bytes()
        .map_err(|e| EngineError::Serialise(e.to_string()))?;

    // 4. Atomic write.
    let signature = atomic_write(path, &bytes, temp_dir)?;

    // 5. Record signature.
    engine.set_last_self_write(signature);

    // 6. Record the kdbx-state signature so Keys-Mac can skip re-ingest
    //    on the next unlock if SQLite already matches the on-disk KDBX.
    //    Stored separately from the self-write signature because that
    //    one is consume-on-match (file-watcher suppression) — sharing
    //    would let an ingest's signature swallow a real subsequent
    //    external-change event. The same call advances the persistence
    //    watermark to the sequence snapshotted at step 0 — the file
    //    just written corresponds to the mirror as of save start, not
    //    as of now.
    engine.record_kdbx_correspondence(path, seq_at_start)?;

    // 7. Sweep the mirror's attachment blob pool — the mirror-side twin
    //    of keepass-core's save-time `gc_binaries_pool` for the file
    //    just written. Runs after the projection so the serialised
    //    state never references a row this removes (it only ever drops
    //    rows nothing references: no live link, no history snapshot, no
    //    parked-conflict root). A GC failure must not fail a save that
    //    already landed on disk — surfaced on stderr, never swallowed
    //    silently (the transaction rolls back, so a failed sweep just
    //    leaves the garbage for the next save).
    if let Err(e) = crate::mutations::gc_attachment_blobs(engine.conn_mut()) {
        eprintln!("keys-engine: attachment blob GC failed (save unaffected): {e}");
    }

    Ok(())
}

/// Write `bytes` to `path` atomically.
///
/// 1. Create a `NamedTempFile` in `temp_dir` (when supplied) or the
///    destination's parent directory.
/// 2. Write all bytes, flush, `sync_all`.
/// 3. `persist` (rename) over the destination — POSIX guarantees
///    atomicity for same-volume renames.
/// 4. Open the parent directory and `sync_all` so the directory entry
///    survives a power loss.
/// 5. Stat the destination for the self-write signature.
///
/// `temp_dir`, when supplied, must live on the same filesystem volume
/// as `path` — `rename(2)` is not cross-volume atomic and will fail
/// with `EXDEV`. The override exists so sandboxed callers whose
/// security-scoped bookmark covers only the kdbx file (not its parent
/// directory) can route the tempfile through a known-writable
/// sandbox-friendly location.
fn atomic_write(
    path: &Path,
    bytes: &[u8],
    temp_dir: Option<&Path>,
) -> Result<SelfWriteSignature, EngineError> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "save path has no parent directory",
        )
    })?;

    // `tempfile::NamedTempFile::new_in` picks a random suffix and
    // creates the file with O_CREAT|O_EXCL, so there's no collision
    // with concurrent saves.
    let tmp_in = temp_dir.unwrap_or(parent);
    let mut tmp = tempfile::NamedTempFile::new_in(tmp_in)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().flush()?;
    tmp.as_file_mut().sync_all()?;

    // `persist` does an `fs::rename` under the hood and returns the
    // PersistError on failure (which derefs to io::Error).
    tmp.persist(path).map_err(|e| e.error)?;

    // Fsync the parent directory so the rename is durable. On
    // platforms where opening a directory for read isn't permitted
    // (rare; Windows doesn't expose `sync_all` on directories the same
    // way), we tolerate the open failure — the rename has already
    // happened, the data is on disk, and a crash here is benign
    // relative to the atomicity guarantee callers actually need.
    if let Ok(dir) = File::open(parent) {
        // Ignore sync_all errors on the directory handle for the same
        // reason — best-effort durability hint.
        let _ = dir.sync_all();
    }

    // Stat for the signature.
    let meta = std::fs::metadata(path)?;
    let mtime = meta.modified()?;
    let size = meta.len();

    Ok(SelfWriteSignature { mtime, size })
}
