//! [`VaultFieldProtector`] — the FFI-facing wrap / unwrap trait that
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
//! The trait surface is intentionally minimal: bytes in, bytes out,
//! plus a flat-stringly error. uniffi's wire shape for trait methods
//! supports `Vec<u8>` and `Result<Vec<u8>, FlatError>` directly, so no
//! exotic encoding is needed.

use std::fmt::Debug;
use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError as CoreProtectorError};

/// Foreign-implemented wrap / unwrap layer for protected-field
/// plaintext.
///
/// Pass an `Arc<dyn VaultFieldProtector>` to [`crate::Vault::new`] or
/// [`crate::Vault::create_empty`] to opt in. With a protector
/// installed, the unlocked vault holds protected-field plaintext only
/// as wrapped bytes in an internal side table; reveal-side accessors
/// (`reveal_field`, `reveal_history_field`) unwrap on demand.
///
/// Without a protector (the legacy `None` path), behaviour is
/// unchanged — protected plaintext lives in `String` fields exactly
/// as it did before this trait existed.
///
/// Implementations must be `Send + Sync` so the protector can be
/// shared across threads alongside the unlocked vault. `wrap` and
/// `unwrap` must round-trip: `unwrap(wrap(x)) == x` for every `x`.
/// They need not be deterministic — implementations backed by a
/// per-call random nonce are fine, provided the wrapped output
/// decodes correctly.
#[uniffi::export(with_foreign)]
pub trait VaultFieldProtector: Send + Sync {
    /// Wrap `plaintext` into an opaque byte blob.
    ///
    /// # Errors
    ///
    /// Returns [`VaultProtectorError::Wrap`] if the underlying key is
    /// unavailable or the wrap operation otherwise fails.
    fn wrap(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, VaultProtectorError>;

    /// Unwrap a blob previously produced by [`Self::wrap`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultProtectorError::Unwrap`] if the blob is
    /// malformed, the underlying key is unavailable, or
    /// authentication fails.
    fn unwrap(&self, wrapped: Vec<u8>) -> Result<Vec<u8>, VaultProtectorError>;
}

/// FFI-facing parallel of `keepass_core::protector::ProtectorError`.
///
/// `flat_error` keeps the wire shape simple — Swift sees one variant
/// plus the stringified detail.
#[derive(thiserror::Error, Debug, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum VaultProtectorError {
    /// A [`VaultFieldProtector::wrap`] call failed.
    #[error("field protector wrap failed: {0}")]
    Wrap(String),

    /// A [`VaultFieldProtector::unwrap`] call failed.
    #[error("field protector unwrap failed: {0}")]
    Unwrap(String),
}

impl From<VaultProtectorError> for CoreProtectorError {
    fn from(err: VaultProtectorError) -> Self {
        match err {
            VaultProtectorError::Wrap(msg) => Self::Wrap(msg),
            VaultProtectorError::Unwrap(msg) => Self::Unwrap(msg),
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
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, CoreProtectorError> {
        self.inner.wrap(plaintext.to_vec()).map_err(Into::into)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, CoreProtectorError> {
        self.inner.unwrap(wrapped.to_vec()).map_err(Into::into)
    }
}

/// Build an `Arc<dyn FieldProtector>` (upstream trait object) from
/// an optional foreign protector.
pub(crate) fn bridge(
    protector: Option<Arc<dyn VaultFieldProtector>>,
) -> Option<Arc<dyn FieldProtector>> {
    protector.map(|p| Arc::new(BridgeProtector::new(p)) as Arc<dyn FieldProtector>)
}
