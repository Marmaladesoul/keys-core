//! `SQLite` → KDBX serialise — task 2.5.
//!
//! Splices the engine's projected [`Vault`] into an existing
//! [`Kdbx<Unlocked>`] handle, calls
//! [`Kdbx::save_to_bytes`](keepass_core::kdbx::Kdbx::save_to_bytes) to
//! re-encrypt under the existing crypto envelope, and atomically writes
//! the resulting bytes to disk.
//!
//! ## Meta preservation
//!
//! Projection only round-trips `recycle_bin_enabled` and
//! `recycle_bin_uuid` on [`Meta`](keepass_core::model::Meta); the v1
//! schema doesn't persist any other `Meta` field. To avoid clobbering
//! `database_name`, `custom_icons`, `custom_data`, `unknown_xml`, etc.,
//! this path **takes the existing `kdbx` handle's `meta` as the base**
//! and overlays only the two recycle-bin fields from projection. Same
//! treatment for `deleted_objects` — projection doesn't track
//! tombstones in v1, so we carry the existing handle's list forward.
//!
//! ## Atomic write
//!
//! Bytes go to a sibling tempfile (`tempfile::NamedTempFile::new_in`)
//! and are flushed + `sync_all`'d before
//! [`NamedTempFile::persist`](tempfile::NamedTempFile::persist) renames
//! over the destination. The parent directory is then opened and
//! `sync_all`'d so the rename survives a power loss between the file
//! sync and a hypothetical follow-up crash. After the rename we `stat`
//! the destination to capture mtime + size for the self-write
//! signature.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::Vault;

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

/// Engine-internal entry point. Called from
/// [`Engine::save_to_kdbx`](crate::engine::Engine::save_to_kdbx).
pub(crate) fn save(
    engine: &mut Engine,
    path: &Path,
    kdbx: &mut Kdbx<Unlocked>,
) -> Result<(), EngineError> {
    // 1. Project the SQLite mirror back to a Vault.
    let mut projected = engine.project_to_vault()?;

    // 2. Splice into kdbx, preserving Meta / DeletedObjects that the
    //    v1 schema doesn't track.
    splice_preserving_meta(kdbx, &mut projected);
    kdbx.replace_vault(projected);

    // 3. Serialise.
    let bytes = kdbx
        .save_to_bytes()
        .map_err(|e| EngineError::Serialise(e.to_string()))?;

    // 4. Atomic write.
    let signature = atomic_write(path, &bytes)?;

    // 5. Record signature.
    engine.set_last_self_write(signature);

    Ok(())
}

/// Carry forward `Meta` and `DeletedObjects` from `kdbx` onto
/// `projected`, overwriting only the two recycle-bin fields the
/// projection actually owns.
///
/// Why not just merge field-by-field? `Meta` is `#[non_exhaustive]`,
/// and the projection only ever sets `recycle_bin_enabled` /
/// `recycle_bin_uuid`. The simplest way to keep "carry everything else
/// forward" future-proof against new `Meta` fields is to take the
/// existing meta as the base and overlay the two we own.
fn splice_preserving_meta(kdbx: &Kdbx<Unlocked>, projected: &mut Vault) {
    let projected_recycle_uuid = projected.meta.recycle_bin_uuid;
    let projected_recycle_enabled = projected.meta.recycle_bin_enabled;

    projected.meta = kdbx.vault().meta.clone();
    projected.meta.recycle_bin_uuid = projected_recycle_uuid;
    projected.meta.recycle_bin_enabled = projected_recycle_enabled;

    // Projection has no tombstone column in the v1 schema. Carry the
    // existing handle's list forward verbatim so a save doesn't strip
    // them.
    projected
        .deleted_objects
        .clone_from(&kdbx.vault().deleted_objects);
}

/// Write `bytes` to `path` atomically.
///
/// 1. Create a sibling `NamedTempFile` in the parent directory.
/// 2. Write all bytes, flush, `sync_all`.
/// 3. `persist` (rename) over the destination — POSIX guarantees
///    atomicity.
/// 4. Open the parent directory and `sync_all` so the directory entry
///    survives a power loss.
/// 5. Stat the destination for the self-write signature.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<SelfWriteSignature, EngineError> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "save path has no parent directory",
        )
    })?;

    // `tempfile::NamedTempFile::new_in` picks a random suffix and
    // creates the file with O_CREAT|O_EXCL, so there's no collision
    // with concurrent saves.
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
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
