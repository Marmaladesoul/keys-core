//! [`VaultFieldProtector`] — the FFI-facing key-provider trait that
//! foreign code (Swift on the Secure Enclave; C# on DPAPI; etc.)
//! implements to keep protected-field plaintext out of the in-process
//! address space.
//!
//! Mirrors `keepass_core::protector::FieldProtector`. The two traits
//! exist in parallel because uniffi's `with_foreign` trait export
//! requires the trait to live in this crate — we can't re-export the
//! upstream trait as a uniffi trait. Adaptation happens via
//! [`BridgeProtector`] below.
//!
//! The trait surface is intentionally minimal: a single method that
//! returns a 32-byte AES-256 key. The frontend does whatever
//! platform-specific work it needs to materialise the key (e.g.
//! unwrap a Secure Enclave–wrapped blob via one IPC) and hands the
//! raw bytes across the FFI. keepass-core does its own AES-GCM
//! seal/open against the key in-process, with the bytes held briefly
//! in a `SessionKey` wrapper that zeroes on drop.
//!
//! Pre-rewrite (`#R?` — TBC) this trait carried per-field `wrap` /
//! `unwrap` callbacks. Profiling showed the per-field cross-language
//! hop + SE IPC dominated unlock and save time (~16 s for an 877-
//! entry vault). Collapsing to a single key-fetch per pass brings
//! that into the millisecond range.

use std::fmt::Debug;
use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError as CoreProtectorError, SessionKey};

/// Foreign-implemented session-key provider for protected-field wrap.
///
/// Pass an `Arc<dyn VaultFieldProtector>` to [`crate::Vault::new`] or
/// [`crate::Vault::create_empty`] to opt in. With a protector
/// installed, the unlocked vault holds protected-field plaintext only
/// as AES-GCM-wrapped bytes in an internal side table; reveal-side
/// accessors unwrap on demand by re-fetching the key.
///
/// Without a protector (the legacy `None` path), behaviour is
/// unchanged — protected plaintext lives in `String` fields exactly
/// as it did before this trait existed.
///
/// Implementations must be `Send + Sync`. They are expected to do
/// whatever platform-specific work is needed (e.g. SE IPC) on each
/// call; this FFI does not cache the returned bytes.
#[uniffi::export(with_foreign)]
pub trait VaultFieldProtector: Send + Sync {
    /// Return a fresh 32-byte AES-256 session key.
    ///
    /// Called once per bulk pass (unlock wrap, save unwrap, conflict
    /// merge) and once per single-field operation (reveal). Each call
    /// must produce key bytes equivalent to every other call's output
    /// (the same logical key) — otherwise wrapped blobs produced by a
    /// previous call won't open under a later call's key.
    ///
    /// The returned `Vec<u8>` MUST be exactly 32 bytes long. Any other
    /// length surfaces as [`VaultProtectorError::KeyUnavailable`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultProtectorError::KeyUnavailable`] if the
    /// underlying key material can't be produced (e.g. Secure Enclave
    /// auth failure).
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError>;
}

/// FFI-facing parallel of `keepass_core::protector::ProtectorError`.
///
/// Deliberately NOT `#[uniffi(flat_error)]`: this enum is the error
/// type for a `with_foreign` trait method, so uniffi must be able to
/// **lift** it (foreign-throws-to-Rust). `flat_error` enums can only
/// be lowered (Rust-throws-to-foreign); attempting to lift one panics
/// at runtime with "Can't lift flat errors". The Swift side still sees
/// a `KeyUnavailable(...)` case with the stringified detail — only
/// the wire representation differs.
#[derive(thiserror::Error, Debug, uniffi::Error)]
#[non_exhaustive]
pub enum VaultProtectorError {
    /// The implementation could not produce the session key.
    #[error("field protector key unavailable: {0}")]
    KeyUnavailable(String),
}

impl From<VaultProtectorError> for CoreProtectorError {
    fn from(err: VaultProtectorError) -> Self {
        match err {
            VaultProtectorError::KeyUnavailable(msg) => Self::KeyUnavailable(msg),
        }
    }
}

/// Adapter that lets a foreign-implemented [`VaultFieldProtector`]
/// satisfy keepass-core's [`FieldProtector`] trait.
///
/// `Debug` is required by the upstream trait but cannot be required
/// on a uniffi `with_foreign` trait, so we implement it manually with
/// a fixed string — it's only used for error context.
pub(crate) struct BridgeProtector {
    inner: Arc<dyn VaultFieldProtector>,
}

impl BridgeProtector {
    pub(crate) fn new(inner: Arc<dyn VaultFieldProtector>) -> Self {
        Self { inner }
    }
}

impl Debug for BridgeProtector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BridgeProtector(<foreign>)")
    }
}

impl FieldProtector for BridgeProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, CoreProtectorError> {
        let raw = self
            .inner
            .acquire_session_key()
            .map_err(CoreProtectorError::from)?;
        let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            CoreProtectorError::KeyUnavailable(format!(
                "session key must be 32 bytes; got {}",
                raw.len()
            ))
        })?;
        Ok(SessionKey::from_bytes(bytes))
    }
}

/// Build an `Arc<dyn FieldProtector>` (upstream trait object) from
/// an optional foreign protector.
pub(crate) fn bridge(
    protector: Option<Arc<dyn VaultFieldProtector>>,
) -> Option<Arc<dyn FieldProtector>> {
    protector.map(|p| Arc::new(BridgeProtector::new(p)) as Arc<dyn FieldProtector>)
}
