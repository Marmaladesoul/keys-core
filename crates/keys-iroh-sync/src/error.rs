//! Error type for the keys-iroh-sync transport library.
//!
//! `SyncError` is intentionally flat (one variant carrying a string).
//! The transport library is a thin wrapper over iroh — callers cannot
//! recover from "DERP unreachable" any differently from "doc ticket
//! malformed", so a structured error taxonomy would be cosmetic.
//! Higher-level Keys code that needs to surface specific failure modes
//! to the UI can inspect the message or wrap calls in its own typed
//! errors.

use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SyncError {
    #[error("{0}")]
    Generic(String),
}

impl From<anyhow::Error> for SyncError {
    fn from(e: anyhow::Error) -> Self {
        // `{e:#}` includes the full anyhow context chain. Without `#`
        // we'd lose everything below the topmost `.context(..)`.
        SyncError::Generic(format!("{e:#}"))
    }
}

impl From<std::io::Error> for SyncError {
    fn from(e: std::io::Error) -> Self {
        SyncError::Generic(format!("io: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, SyncError>;
