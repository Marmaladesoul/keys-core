//! Error type for [`Engine`](crate::Engine) operations.

use crate::key_provider::KeyProviderError;
use crate::migrations::MigrationError;

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
}
