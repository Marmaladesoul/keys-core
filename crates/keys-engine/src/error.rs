//! Error type for [`Engine`](crate::Engine) operations.

use crate::key_provider::KeyProviderError;
use crate::migrations::MigrationError;

/// Errors surfaced specifically by [`crate::Engine::ingest_from_kdbx`].
///
/// Most ingest failures funnel through one of [`EngineError`]'s pre-
/// existing variants (`Sqlite` for transaction / INSERT failures,
/// `Random` for nonce generation hiccups). This enum names the few
/// failure modes that are specific to ingest: the
/// `vault_with_unwrapped_protected` call's [`keepass_core::Error`],
/// AES-GCM seal failures during the wrap pass, and JSON serialisation
/// of history snapshots.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum IngestError {
    /// `keepass-core` refused to expose a plaintext-protected vault.
    /// Usually surfaces a [`keepass_core::protector::FieldProtector`]
    /// failure inside the unwrap pass (Secure-Enclave auth, blob
    /// corruption, …).
    #[error("kdbx unwrap failed: {0}")]
    Kdbx(String),

    /// AES-GCM seal of a protected field failed under the supplied
    /// session key. Either the key length was wrong (cannot happen
    /// for a 32-byte [`keepass_core::protector::SessionKey`]) or the
    /// AEAD primitive itself rejected the operation.
    #[error("protected field wrap failed: {0}")]
    Wrap(String),

    /// The configured [`keepass_core::protector::FieldProtector`] could
    /// not produce the session key needed to wrap protected fields.
    #[error("session key unavailable: {0}")]
    SessionKey(String),

    /// `serde_json` failed to serialise a history snapshot into the
    /// `entry_history.snapshot_json` column. Practically impossible
    /// for the snapshot shape this crate writes, but plumbed through
    /// rather than panicking.
    #[error("history snapshot serialisation failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Errors surfaced by the engine.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// The supplied key did not decrypt the database. `SQLCipher` reports
    /// this as `SQLITE_NOTADB` ("file is not a database") on the first
    /// query that touches the encrypted header.
    #[error("wrong database key — supplied key does not decrypt this database")]
    WrongKey,

    /// The [`KeyProvider`](crate::KeyProvider) failed to materialise the
    /// database key.
    #[error("db key provider failed: {0}")]
    KeyProvider(#[from] KeyProviderError),

    /// An I/O error occurred (e.g. creating the parent directory).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A SQLite-level error from `rusqlite` that isn't a wrong-key
    /// signal.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A schema-migration error: the migration runner failed, or the
    /// database is at a schema version this binary doesn't know.
    #[error("migration error: {0}")]
    Migration(#[from] MigrationError),

    /// The OS RNG refused to produce randomness while the engine was
    /// trying to seed the per-vault fingerprint key. This is a hard
    /// failure on every platform we ship to and should be treated as
    /// fatal by callers.
    #[error("os rng failed: {0}")]
    Random(#[from] getrandom::Error),

    /// An ingest-pass failure — see [`IngestError`] for the specific
    /// failure mode.
    #[error("ingest failed: {0}")]
    Ingest(#[from] IngestError),

    /// A projection-pass failure — see [`ProjectionError`] for the
    /// specific failure mode.
    #[error("projection failed: {0}")]
    Projection(#[from] ProjectionError),

    /// `keepass-core`'s
    /// [`save_to_bytes`](keepass_core::kdbx::Kdbx::save_to_bytes)
    /// rejected the spliced vault — e.g. KDBX3 was asked for a
    /// KDBX4-only cipher, the inner-header parameters are missing, or
    /// the outer cipher isn't supported by the writer. Surfaces as a
    /// stringified message because [`keepass_core::Error`] isn't
    /// re-exported in a `From`-friendly shape.
    #[error("kdbx serialise failed: {0}")]
    Serialise(String),
}

/// Errors surfaced specifically by [`crate::Engine::project_to_vault`].
///
/// Projection is mostly a fan of `SELECT`s + an AES-GCM unwrap pass;
/// failure modes outside the `SQLite` layer fall into this enum.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ProjectionError {
    /// The configured [`keepass_core::protector::FieldProtector`] could
    /// not produce the session key needed to unwrap protected fields.
    #[error("session key unavailable: {0}")]
    SessionKey(String),

    /// AES-GCM open of a protected field blob failed under the
    /// supplied session key — either the wire shape is wrong, the tag
    /// doesn't verify, or the plaintext wasn't valid UTF-8.
    #[error("protected field unwrap failed: {0}")]
    Unwrap(String),

    /// A persisted shape violates an invariant we rely on (no root
    /// group, multiple root groups, attachment hash with wrong width,
    /// parent uuid that doesn't resolve, …). Means either a corrupt
    /// `SQLite` file or a producer that doesn't match this crate's
    /// ingest path.
    #[error("schema invariant violated: {0}")]
    SchemaInvariant(String),

    /// `serde_json` failed to deserialise a row from
    /// `entry_history.snapshot_json`. Surfaces a producer mismatch
    /// (a foreign writer emitted a different shape) or genuine
    /// corruption.
    #[error("history snapshot deserialisation failed: {0}")]
    Json(#[from] serde_json::Error),
}
