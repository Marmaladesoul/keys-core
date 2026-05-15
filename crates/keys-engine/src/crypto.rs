//! AES-256-GCM unwrap helper shared between the projection path and
//! the reveal-on-demand path.
//!
//! Wire format: `nonce(12) || ciphertext || tag(16)`. This is the
//! inverse of [`crate::ingest::wrap_with_session_key`] and matches the
//! shape produced by `keepass_core::protector::seal_with_key`
//! (which is `pub(crate)` over there, so we can't reuse it directly).
//!
//! We don't expose a `wrap` here because the only writer is ingest;
//! lifting that would require lifting the OS-RNG dependency too. If a
//! future writer needs it, move `ingest::wrap_with_session_key` into
//! this module.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use keepass_core::protector::SessionKey;

/// AES-256-GCM open. Returns the decrypted plaintext on success.
///
/// The session key is borrowed (not cloned) and the caller is expected
/// to drop it immediately after the unwrap so its `Zeroizing` semantics
/// kick in promptly.
pub(crate) fn unwrap_with_session_key(
    session_key: &SessionKey,
    wrapped: &[u8],
) -> Result<Vec<u8>, String> {
    if wrapped.len() < 12 + 16 {
        return Err("wrapped blob too short".into());
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(session_key.as_bytes()).map_err(|e| e.to_string())?;
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())
}
