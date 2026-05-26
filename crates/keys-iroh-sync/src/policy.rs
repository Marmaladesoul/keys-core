//! Download policy for joined docs.
//!
//! When a node joins a doc it receives the entry log immediately, but
//! blob content downloads are subject to a per-doc policy. The receiver
//! decides which content to actually pull — see decision-doc §3 on the
//! "Bandwidth: whole-kdbx-per-push, per-client size policy" pattern.
//!
//! We expose a simplified wrapper over `iroh_docs::store::DownloadPolicy`
//! that is easy to construct over the FFI boundary. The key filter list
//! is a `Vec<Vec<u8>>` of exact-match key prefixes; that's the simplest
//! shape that round-trips cleanly through uniffi and covers every use
//! case we have in mind for PR-1.
//!
//! Future extensions (glob patterns, size predicates) can be added as
//! new variants without breaking existing callers.

use iroh_docs::store::{DownloadPolicy as IrohDownloadPolicy, FilterKind};

/// Caller-facing download policy. Maps onto `iroh_docs::store::DownloadPolicy`
/// at join time.
#[derive(Debug, Clone, Default, uniffi::Enum)]
pub enum DownloadPolicy {
    /// Download every blob referenced by every entry. Default behaviour
    /// (matches iroh-docs `EverythingExcept(vec![])`). Right for small
    /// fleet docs where every entry is cheap and necessary.
    #[default]
    Everything,
    /// Download nothing except blobs whose entry key starts with one of
    /// the given prefixes. Right for "only sync the manifest, defer
    /// vault bodies until explicitly requested".
    NothingExcept { key_prefixes: Vec<Vec<u8>> },
    /// Download everything except blobs whose entry key starts with one
    /// of the given prefixes. Right for "sync everything but skip the
    /// large media attachments".
    EverythingExcept { key_prefixes: Vec<Vec<u8>> },
}

impl DownloadPolicy {
    pub(crate) fn into_iroh(self) -> IrohDownloadPolicy {
        match self {
            // `EverythingExcept(vec![])` is iroh-docs' canonical
            // "everything" sentinel.
            Self::Everything => IrohDownloadPolicy::EverythingExcept(Vec::new()),
            Self::NothingExcept { key_prefixes } => IrohDownloadPolicy::NothingExcept(
                key_prefixes
                    .into_iter()
                    .map(|p| FilterKind::Prefix(p.into()))
                    .collect(),
            ),
            Self::EverythingExcept { key_prefixes } => IrohDownloadPolicy::EverythingExcept(
                key_prefixes
                    .into_iter()
                    .map(|p| FilterKind::Prefix(p.into()))
                    .collect(),
            ),
        }
    }
}
