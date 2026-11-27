//! Secret bytes that stay put.
//!
//! A secret held inline in a struct is copied every time the struct moves,
//! and each place it moved from keeps the old bytes: `Zeroizing` and `Drop`
//! wipe only where the value ends up. Moving a boxed run state out of its
//! box, for instance, frees a heap block with the secrets still in it.
//!
//! [`Secret`] keeps its bytes in a heap allocation of their own. Moving a
//! `Secret`, or anything that owns one, moves a pointer; the bytes are
//! written in place and wiped in place when it drops. (What a secret is
//! computed from on the way in, a hash output on the stack, say, is the
//! computing code's to wipe.)

use zeroize::Zeroize;

/// `N` secret bytes in their own heap allocation, wiped on drop. Never
/// prints its contents.
pub(crate) struct Secret<const N: usize>(Box<[u8; N]>);

impl<const N: usize> Secret<N> {
    /// All zeros, for the caller to fill in place through [`Self::as_mut`].
    pub(crate) fn zeroed() -> Self {
        Self(Box::new([0u8; N]))
    }

    /// A copy of `bytes`. The caller still owns, and must wipe, the source.
    pub(crate) fn copy_of(bytes: &[u8; N]) -> Self {
        let mut secret = Self::zeroed();
        secret.0.copy_from_slice(bytes);
        secret
    }

    pub(crate) fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub(crate) fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Clone for Secret<N> {
    fn clone(&self) -> Self {
        Self::copy_of(&self.0)
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> std::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
