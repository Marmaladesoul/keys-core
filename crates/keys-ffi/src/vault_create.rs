//! Engine-generation vault creation — mint a fresh KDBX file on disk.
//!
//! [`create_vault`] is the production "new vault" entry point: it writes
//! a fresh, empty KDBX4 file (recycle bin pre-created and enabled) and
//! returns. It deliberately returns **no handle** — frontends open the
//! new vault through the same [`crate::Engine`] path they use for any
//! existing vault (`Engine::open` + `ingest_from_kdbx`, keyfile-aware
//! variants included), so creation adds no second lifecycle to the seam.
//! [`create_vault_deterministic`] is the test / fuzz variant with pinned
//! entity ids and timestamps.

// uniffi-exported functions take owned values even where a borrow would
// do — it's the natural FFI shape (see `vault/mod.rs`), and the mint core
// shares those signatures so the async wrappers can move args into
// `spawn_blocking` without re-cloning.
#![allow(clippy::needless_pass_by_value)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::DateTime;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{Clock, FixedClock, NewGroup, SeededUuids, UuidSource};
use secrecy::{ExposeSecret, SecretString};

use crate::engine_error::EngineError;
use crate::error::VaultError;
use crate::protector::{VaultFieldProtector, bridge as bridge_protector};

/// Create a fresh, empty KDBX4 vault file at `path`, keyed by `password`
/// plus an optional `keyfile`, titled `database_name`.
///
/// The file is written atomically (tempfile + `rename(2)`); an existing
/// file at `path` is **overwritten**, so callers that must not clobber an
/// existing vault guard the path themselves before calling (the GUI's
/// save panel and the keyhole driver's existence check both do). Keys
/// policy: the vault ships with the recycle bin enabled **and** the bin
/// group already created, so the first "Move to Trash" is recoverable —
/// and the bin's UUID is fixed before the vault is ever synced (no "two
/// peers each mint their own bin" race).
///
/// `keyfile`, when present, is the raw keyfile *file content* (a minted
/// `.keyx` from [`crate::generate_keyfile`], or a foreign 32-byte-binary /
/// hex / `.keyx` keyfile) mixed into the standard interoperable KDBX
/// composite `SHA-256(SHA-256(password) || keyfile_hash)`. The engine
/// keeps no copy — storing the keyfile (OS keychain on the GUI clients)
/// is the caller's job. A keyfile that cannot be reduced to 32 bytes
/// fails closed: no weaker password-only vault is written in its place.
///
/// `temp_dir`, when supplied, hosts the atomic-write tempfile instead of
/// `path`'s parent. Sandboxed macOS callers should pass
/// `NSTemporaryDirectory()`: a save-panel-issued sandbox extension grants
/// write to the chosen file but not arbitrary siblings in its parent, so
/// the default sibling-tempfile path fails with EPERM. The override must
/// live on the same filesystem volume as `path` (rename is not
/// cross-volume atomic). Pass `None` on non-sandboxed platforms.
///
/// Crypto defaults are baked in upstream
/// ([`keepass_core::kdbx::Kdbx::<Unlocked>::create_empty_v4`]): AES-256-CBC
/// outer cipher, Argon2d KDF (2 iter × 64 `MiB` × 8 threads — matches
/// contemporary `KeePass` / `KeePassXC` defaults), `GZip` compression,
/// `ChaCha20` inner stream, random seeds + salts from `OsRng`. The cost
/// is one full Argon2 round at create-time (~1s on contemporary
/// hardware), which is why this call is async: it runs on the tokio
/// runtime, off the caller's UI thread. `password` is wrapped in a
/// `SecretString` immediately and dropped after the KDF call.
///
/// Returns nothing on success: open the new vault through
/// [`crate::Engine::open`] + `ingest_from_kdbx` exactly as for an
/// existing vault.
///
/// # Errors
///
/// - [`EngineError::WrongKey`] if `keyfile` is present but malformed
///   (cannot be reduced to a 32-byte hash), or for any crypto-class
///   failure during the initial save (effectively impossible at the
///   defaults baked in upstream — surfaced as a typed error rather than
///   a panic).
/// - [`EngineError::Internal`] if the path's parent directory is missing
///   or the write fails.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_vault(
    path: String,
    password: String,
    keyfile: Option<Vec<u8>>,
    database_name: String,
    field_protector: Option<Arc<dyn VaultFieldProtector>>,
    temp_dir: Option<String>,
) -> Result<(), EngineError> {
    tokio::task::spawn_blocking(move || {
        mint_kdbx_file(
            path,
            password,
            keyfile,
            database_name,
            field_protector,
            temp_dir,
            None,
        )
        .map(|_| ())
        .map_err(vault_err_to_engine_err)
    })
    .await
    .map_err(|e| EngineError::Internal(format!("join: {e}")))?
}

/// Like [`create_vault`] but with the root group + recycle-bin UUIDs and
/// creation timestamps pinned, so a fresh vault is reproducible for
/// fuzzing / replay.
///
/// `uuid_seed` drives a seeded uuid source: the root id is
/// `from_u64_pair(uuid_seed, 0)`, the eager recycle bin is
/// `from_u64_pair(uuid_seed, 1)` — one coherent sequence, matching the
/// engine's seeded source so a vault created with seed `S` and then
/// mutated by an `Engine` seeded with `S` shares one id space. `clock_ms`
/// (epoch-milliseconds) pins every creation timestamp. The KDBX *bytes*
/// still vary run-to-run (master seed / IV / KDF salt are fresh OS
/// randomness), but the entity ids and timestamps that drive sync are
/// deterministic. Use one distinct `uuid_seed` per simulated device.
///
/// **Test / fuzz scaffolding only.** Production clients use
/// [`create_vault`]. Composes with `keyfile` exactly as [`create_vault`]
/// does.
///
/// # Errors
///
/// As [`create_vault`], plus [`EngineError::Internal`] if `clock_ms` is
/// not a representable UTC instant.
#[uniffi::export(async_runtime = "tokio")]
#[allow(clippy::too_many_arguments)]
pub async fn create_vault_deterministic(
    path: String,
    password: String,
    keyfile: Option<Vec<u8>>,
    database_name: String,
    field_protector: Option<Arc<dyn VaultFieldProtector>>,
    temp_dir: Option<String>,
    uuid_seed: u64,
    clock_ms: i64,
) -> Result<(), EngineError> {
    tokio::task::spawn_blocking(move || {
        mint_kdbx_file(
            path,
            password,
            keyfile,
            database_name,
            field_protector,
            temp_dir,
            Some((uuid_seed, clock_ms)),
        )
        .map(|_| ())
        .map_err(vault_err_to_engine_err)
    })
    .await
    .map_err(|e| EngineError::Internal(format!("join: {e}")))?
}

/// Map the mint core's [`VaultError`] onto the Engine generation's
/// [`EngineError`]: the fail-closed key-material class keeps its
/// actionable variant; everything else (I/O, serialise) is internal.
fn vault_err_to_engine_err(e: VaultError) -> EngineError {
    match e {
        VaultError::WrongKey => EngineError::WrongKey,
        other => EngineError::Internal(other.to_string()),
    }
}

/// Shared mint core: build the empty vault (eager recycle bin included),
/// derive the composite, and atomically write the KDBX file. Returns the
/// unlocked handle plus the resolved path for callers that keep working
/// on the fresh vault in-process (the legacy `Vault::create_empty*`
/// constructors delegate here until that façade is retired).
///
/// `deterministic` carries `(uuid_seed, clock_ms)` when the caller wants
/// pinned ids / timestamps, or `None` for the production path (random
/// ids, system clock).
pub(crate) fn mint_kdbx_file(
    path: String,
    password: String,
    keyfile: Option<Vec<u8>>,
    database_name: String,
    field_protector: Option<Arc<dyn VaultFieldProtector>>,
    temp_dir: Option<String>,
    deterministic: Option<(u64, i64)>,
) -> Result<(Kdbx<Unlocked>, PathBuf), VaultError> {
    let path_buf = PathBuf::from(&path);
    let secret = SecretString::from(password);
    // Password-only or password-plus-keyfile composite, per the standard
    // interoperable KDBX construction. A malformed keyfile fails closed
    // (no weak password-only vault is written in its place).
    let composite = crate::keyfile::composite_from_factors(
        secret.expose_secret().as_bytes(),
        keyfile.as_deref(),
    )
    .map_err(|_| VaultError::WrongKey)?;
    let bridged = bridge_protector(field_protector);

    // Build the unlocked vault, derive the transformed key against the
    // freshly-generated KDF params. The deterministic path injects a
    // FixedClock + SeededUuids and draws the eager bin's id from the
    // SAME source (second draw → from_u64_pair(seed, 1)) so root + bin
    // share one coherent seeded sequence.
    let (mut kdbx, bin_uuid) = if let Some((uuid_seed, clock_ms)) = deterministic {
        let fixed = DateTime::from_timestamp_millis(clock_ms).ok_or_else(|| {
            VaultError::Io(format!(
                "clock_ms {clock_ms} is not a representable UTC instant"
            ))
        })?;
        let clock: Box<dyn Clock> = Box::new(FixedClock(fixed));
        let uuids = SeededUuids::new(uuid_seed);
        let kdbx = Kdbx::<keepass_core::kdbx::Unlocked>::create_empty_v4_deterministic(
            &composite,
            database_name,
            bridged,
            clock,
            &uuids,
        )?;
        // Draw the eager bin's id from the SAME source (second draw →
        // from_u64_pair(seed, 1)) so root + bin share one sequence.
        let bin_uuid = uuids.next_uuid();
        (kdbx, Some(bin_uuid))
    } else {
        let kdbx = Kdbx::<keepass_core::kdbx::Unlocked>::create_empty_v4_with_protector(
            &composite,
            database_name,
            bridged,
        )?;
        (kdbx, None)
    };

    // Keys policy: new vaults ship with the recycle bin enabled AND the
    // bin group already created, so the first "Move to Trash" is
    // recoverable — and so the bin's UUID is fixed before the vault is
    // ever synced (no "two peers each mint their own bin" race). The group
    // matches keepass-core's `find_or_create_recycle_bin` (name + icon 43,
    // auto-type / search off); we just create it eagerly here instead of
    // lazily on first recycle.
    let root = kdbx.vault().root.id;
    let mut bin_template = NewGroup::new("Recycle Bin")
        .icon_id(43)
        .enable_auto_type(Some(false))
        .enable_searching(Some(false));
    if let Some(u) = bin_uuid {
        bin_template = bin_template.with_uuid(u);
    }
    let bin = kdbx
        .add_group(root, bin_template)
        .map_err(crate::error::model_err_to_vault_err)?;
    kdbx.set_recycle_bin(true, Some(bin));

    // Initial save via the same atomic-write pattern as `Vault::save`.
    let bytes = kdbx.save_to_bytes()?;
    let parent = path_buf
        .parent()
        .ok_or_else(|| VaultError::Io("create path has no parent directory".to_owned()))?;
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

    Ok((kdbx, path_buf))
}
