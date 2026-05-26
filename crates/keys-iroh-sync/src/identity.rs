//! Persistent endpoint identities.
//!
//! The spike generated a fresh `SecretKey` on every `bind()` — fine for
//! measurement, useless for production: an endpoint's NodeId is derived
//! from its SecretKey, so a fresh key per bind means peers can never
//! recognise the same device twice.
//!
//! Production callers (the Keys app) own identity storage — typically
//! one identity per (device, vault) tuple, wrapped in the platform
//! keychain. The library just accepts 32 raw bytes at bind time and
//! reconstructs the `SecretKey`. We never persist the key ourselves.
//!
//! Protections on the in-memory copy of the secret bytes:
//!
//! - **Custom `Debug`.** The derived `Debug` would print every byte of
//!   the secret key on any `{:?}` formatting. We override it to print
//!   a placeholder, so accidental `tracing::info!("config = {:?}",
//!   ..)` calls (or panics with default formatting) don't leak the
//!   key. `NodeConfig`'s `Debug` is similarly redacted via its own
//!   custom impl that delegates to ours.
//! - **Stack-copy zeroization.** The transient `[u8; 32]` arrays the
//!   library uses internally (in `generate` and `to_secret_key`) are
//!   wiped before the stack frame returns. The `Vec<u8>` heap
//!   allocation inside `Identity` itself is NOT zeroized — uniffi's
//!   `Record` derive requires the type to be moveable-out-of, which
//!   conflicts with `Drop`. Callers driving the Rust API directly
//!   who care about heap residency should call `secret_key_bytes
//!   .zeroize()` before dropping the `Identity`. Callers driving the
//!   FFI side hand their bytes to uniffi's marshaller and are
//!   responsible for clearing the source storage on their side
//!   (e.g. Swift `withUnsafeMutableBytes { $0.initializeMemory(...) }`).

use crate::error::{Result, SyncError};
use iroh::SecretKey;
use zeroize::Zeroize;

/// A 32-byte ed25519 secret key, the canonical iroh endpoint identity.
///
/// Callers should obtain bytes from secure storage (macOS Keychain,
/// iOS Keychain, Windows Credential Manager) and pass them in once at
/// bind time. The library does not retain the bytes after constructing
/// the in-memory `SecretKey`.
///
/// `Debug` is redacted to keep accidental log statements from
/// printing the key.
///
/// We deliberately do NOT implement `Drop` (or `ZeroizeOnDrop`) on
/// this type — uniffi's `Record` derive requires it to be move-able
/// out of, which conflicts with `Drop`. Stack copies of the secret
/// (in `generate` and `to_secret_key`) are wiped manually below;
/// callers who care about clearing the heap-resident `Vec<u8>` after
/// use should overwrite it themselves before dropping the `Identity`
/// (`secret_key_bytes.zeroize()` from the `zeroize` crate).
#[derive(Clone, uniffi::Record)]
pub struct Identity {
    pub secret_key_bytes: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print the byte length so logs are still useful for shape
        // debugging (e.g. spotting a 31-byte truncation) without
        // exposing any of the secret material itself.
        f.debug_struct("Identity")
            .field(
                "secret_key_bytes",
                &format_args!("<redacted {} bytes>", self.secret_key_bytes.len()),
            )
            .finish()
    }
}

impl Identity {
    /// Convenience: generate a brand-new identity. Useful for tests
    /// and for first-run flows where the caller has not yet derived a
    /// stable per-device key. Production callers should normally
    /// persist `secret_key_bytes` themselves.
    #[must_use]
    pub fn generate() -> Self {
        let mut sk_bytes = SecretKey::generate().to_bytes();
        let out = Self {
            secret_key_bytes: sk_bytes.to_vec(),
        };
        // Wipe the stack copy from `to_bytes()` before it's dropped
        // naturally. The Vec inside `out` is the only intended copy.
        sk_bytes.zeroize();
        out
    }

    pub(crate) fn to_secret_key(&self) -> Result<SecretKey> {
        let mut bytes: [u8; 32] = self.secret_key_bytes.as_slice().try_into().map_err(|_| {
            SyncError::Generic(format!(
                "secret_key_bytes must be 32 bytes, got {}",
                self.secret_key_bytes.len()
            ))
        })?;
        let sk = SecretKey::from_bytes(&bytes);
        // SecretKey::from_bytes derived an internal SigningKey and no
        // longer needs our stack array. Wipe it so it doesn't sit on
        // the stack until the next function frame happens to overwrite
        // those slots.
        bytes.zeroize();
        Ok(sk)
    }
}

/// Generate a fresh `Identity` (FFI entry point). Mirrors
/// `Identity::generate` for callers driving the library through uniffi.
#[must_use]
#[uniffi::export]
pub fn identity_generate() -> Identity {
    Identity::generate()
}
