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

    /// A reveal-pass failure — see [`RevealError`] for the specific
    /// failure mode.
    #[error("reveal failed: {0}")]
    Reveal(#[from] RevealError),

    /// The requested entity (entry, field, history snapshot, …) does
    /// not exist. Used by reveal paths and other lookup methods that
    /// have a "not found" failure mode distinct from a SQL-level error.
    ///
    /// `entity` is a short static label like `"password"`,
    /// `"custom_field"`, `"history_snapshot"`, or `"history_field"`
    /// — useful for telemetry / debug messages but not intended as a
    /// machine-readable taxonomy.
    #[error("not found: {entity}")]
    NotFound {
        /// Short static label naming the missing entity kind.
        entity: &'static str,
    },

    /// `keepass-core`'s
    /// [`save_to_bytes`](keepass_core::kdbx::Kdbx::save_to_bytes)
    /// rejected the spliced vault — e.g. KDBX3 was asked for a
    /// KDBX4-only cipher, the inner-header parameters are missing, or
    /// the outer cipher isn't supported by the writer. Surfaces as a
    /// stringified message because [`keepass_core::Error`] isn't
    /// re-exported in a `From`-friendly shape.
    #[error("kdbx serialise failed: {0}")]
    Serialise(String),

    /// The supplied predicate (or the predicate persisted in a smart
    /// folder) cannot be compiled to SQL — typically because it
    /// contains a [`Predicate::Unknown`](crate::Predicate::Unknown)
    /// node written by a newer client this binary doesn't know how
    /// to evaluate. Smart-folder read paths refuse to run rather than
    /// silently returning an empty or partial result.
    #[error("predicate is not evaluable by this binary")]
    NotEvaluable,

    /// A protected-field wrap failed during a mutation. AES-GCM seal
    /// rejected the call, typically because the session-key provider
    /// produced a key of the wrong length or the AEAD primitive itself
    /// errored.
    #[error("protected field wrap failed: {0}")]
    Wrap(String),

    /// The session-key provider refused to release a session key while
    /// a mutation needed to (un)wrap a protected blob.
    #[error("session key unavailable: {0}")]
    SessionKey(String),

    /// A group move would create a cycle (the new parent is the group
    /// itself, or one of its descendants).
    #[error("group move would create a cycle")]
    CycleDetected,

    /// A [`FileWatcher`](crate::FileWatcher) failed to initialise or run.
    /// Only produced on the explicit `NotifyFileWatcher::new` path; the
    /// engine itself never instantiates a watcher.
    #[error("file watcher error: {0}")]
    FileWatcher(#[from] crate::file_watcher::FileWatcherError),

    /// The caller-supplied [`keepass_merge::Resolution`] passed to
    /// [`crate::Engine::apply_conflict_resolution`] doesn't line up
    /// with the stashed [`crate::events::ConflictPayload`]: an unknown
    /// entry, an unknown field, a missing per-entry decision, or a
    /// `KeepBoth` on an attachment that isn't `BothDiffer`. The exact
    /// `keepass-merge` validation message is carried verbatim.
    #[error("resolution does not match stashed conflict: {reason}")]
    ResolutionMismatch {
        /// The validation diagnostic from `keepass-merge`.
        reason: String,
    },
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

/// Errors surfaced specifically by the reveal methods on
/// [`crate::Engine`] — [`crate::Engine::reveal_password`],
/// [`crate::Engine::reveal_custom_field`], and
/// [`crate::Engine::reveal_history_field`].
///
/// Lookup failures (no matching row) surface as
/// [`EngineError::NotFound`] rather than a variant on this enum, mirroring
/// the broader engine convention that "missing entity" is a query-shape
/// concern distinct from a crypto / decode failure.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum RevealError {
    /// The configured [`keepass_core::protector::FieldProtector`] could
    /// not produce the session key needed to unwrap the protected blob.
    #[error("session key unavailable: {0}")]
    SessionKey(String),

    /// AES-GCM open of the protected blob failed — either the wire
    /// shape is wrong, the tag doesn't verify, or the plaintext wasn't
    /// valid UTF-8.
    #[error("protected field unwrap failed: {0}")]
    Unwrap(String),

    /// `serde_json` failed to deserialise a history snapshot. Same
    /// producer-mismatch / corruption story as
    /// [`ProjectionError::Json`].
    #[error("history snapshot deserialisation failed: {0}")]
    Json(#[from] serde_json::Error),
}
