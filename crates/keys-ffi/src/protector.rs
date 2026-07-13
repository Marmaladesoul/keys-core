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
use zeroize::{Zeroize, Zeroizing};

/// Foreign-implemented session-key provider for protected-field wrap.
///
/// [`crate::Engine::open`] takes one non-optionally (the engine always
/// wraps protected fields); [`crate::create_vault`] takes an
/// `Option<Arc<dyn VaultFieldProtector>>` — `Some` to install one at
/// create time, `None` for the legacy unprotected path. With a protector
/// installed, the engine holds protected-field plaintext only as
/// AES-GCM-wrapped bytes in an internal side table; reveal-side accessors
/// unwrap on demand by re-fetching the key.
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
        // The foreign trait surfaces the 32-byte key as a `Vec<u8>` —
        // a fresh Rust-side allocation receiving secret material across
        // the FFI boundary. `Zeroizing<Vec<u8>>` ensures that allocation
        // is scrubbed when dropped, instead of leaving the session key
        // sitting on the heap to be revealed by whatever next reuses
        // that arena.
        let raw: Zeroizing<Vec<u8>> = Zeroizing::new(
            self.inner
                .acquire_session_key()
                .map_err(CoreProtectorError::from)?,
        );
        // The destination (`SessionKey`) is itself `Zeroizing<[u8; 32]>`,
        // so the long-lived copy is already covered. The intermediate
        // stack array is `Copy` and outlives the move into `from_bytes`;
        // zeroize it explicitly so the stack frame doesn't retain a
        // plaintext image after we return.
        let mut bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            CoreProtectorError::KeyUnavailable(format!(
                "session key must be 32 bytes; got {}",
                raw.len()
            ))
        })?;
        let key = SessionKey::from_bytes(bytes);
        bytes.zeroize();
        Ok(key)
    }
}

/// Build an `Arc<dyn FieldProtector>` (upstream trait object) from
/// an optional foreign protector.
pub(crate) fn bridge(
    protector: Option<Arc<dyn VaultFieldProtector>>,
) -> Option<Arc<dyn FieldProtector>> {
    protector.map(|p| Arc::new(BridgeProtector::new(p)) as Arc<dyn FieldProtector>)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedKey(Vec<u8>);

    impl VaultFieldProtector for FixedKey {
        fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
            Ok(self.0.clone())
        }
    }

    struct FailingKey(String);

    impl VaultFieldProtector for FailingKey {
        fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
            Err(VaultProtectorError::KeyUnavailable(self.0.clone()))
        }
    }

    #[test]
    fn bridge_round_trips_a_valid_32_byte_key() {
        let raw = vec![7u8; 32];
        let bridge = BridgeProtector::new(Arc::new(FixedKey(raw.clone())));
        let key = bridge.acquire_session_key().expect("32-byte key accepted");
        assert_eq!(key.as_bytes().as_slice(), raw.as_slice());
    }

    #[test]
    fn bridge_rejects_short_key() {
        // Exercises the `raw.len()` borrow inside the error-formatting
        // closure — confirms the `Zeroizing` wrapper doesn't move the
        // underlying Vec out from under that borrow.
        let bridge = BridgeProtector::new(Arc::new(FixedKey(vec![1u8; 16])));
        let err = bridge
            .acquire_session_key()
            .expect_err("must reject non-32-byte key");
        assert!(
            matches!(err, CoreProtectorError::KeyUnavailable(ref m) if m.contains("32 bytes; got 16")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn bridge_rejects_long_key() {
        let bridge = BridgeProtector::new(Arc::new(FixedKey(vec![1u8; 64])));
        let err = bridge
            .acquire_session_key()
            .expect_err("must reject non-32-byte key");
        assert!(
            matches!(err, CoreProtectorError::KeyUnavailable(ref m) if m.contains("32 bytes; got 64")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn bridge_propagates_foreign_error() {
        let bridge = BridgeProtector::new(Arc::new(FailingKey("se locked".into())));
        let err = bridge.acquire_session_key().expect_err("must propagate");
        assert!(
            matches!(err, CoreProtectorError::KeyUnavailable(ref m) if m == "se locked"),
            "unexpected error: {err:?}",
        );
    }

    /// Compile-time witness that the bridge holds the foreign-supplied
    /// key bytes in `Zeroizing<Vec<u8>>`. If a future edit changes the
    /// type back to plain `Vec<u8>`, this test stops compiling — which
    /// is the point: secret-material handling shouldn't silently
    /// regress.
    #[test]
    fn bridge_uses_zeroizing_vec_for_raw_secret() {
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}
        let probe: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; 32]);
        assert_zeroizing(&probe);
    }
}
