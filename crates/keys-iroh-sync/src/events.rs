//! Doc event types and the FFI listener trait.
//!
//! The native Rust API exposes a `Stream<Item = Result<DocEvent>>` so
//! Rust callers (the integration test, future direct Rust consumers)
//! can wire events into their own runtime. The FFI surface exposes a
//! `DocEventListener` callback interface — uniffi async streams across
//! the FFI boundary are not yet first-class on every target we care
//! about, and a callback is what Swift / Kotlin / Win RT idiomatically
//! consume anyway.
//!
//! We deliberately do NOT re-export the raw `iroh_docs::engine::LiveEvent`
//! — that pulls iroh-internal types like `SignedEntry` into our public
//! API and bakes in transport details we want to keep behind the
//! library boundary.

use iroh_docs::engine::LiveEvent;

/// A doc lifecycle event. Translated from `iroh_docs::engine::LiveEvent`,
/// stripped of iroh-internal types so the surface stays FFI-friendly
/// and semver-stable when iroh-docs internals churn.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum DocEvent {
    /// An entry was inserted locally (via this node's `Author`).
    InsertLocal {
        key: Vec<u8>,
        hash_hex: String,
        size_bytes: u64,
    },
    /// An entry was received from a peer. `content_available` reflects
    /// whether the blob payload is already on disk; if false, the
    /// content is in-flight and a later `ContentReady` will confirm
    /// arrival.
    InsertRemote {
        from_node_id: String,
        key: Vec<u8>,
        hash_hex: String,
        size_bytes: u64,
        content_available: bool,
    },
    /// A blob's content has finished downloading and is now readable
    /// locally.
    ContentReady { hash_hex: String },
    /// All pending content from the last sync round has either arrived
    /// or failed. Always preceded by a `SyncFinished`.
    PendingContentReady,
    /// A swarm neighbour appeared.
    NeighborUp { node_id: String },
    /// A swarm neighbour went away.
    NeighborDown { node_id: String },
    /// A set-reconciliation sync round finished. The library exposes
    /// only the boolean outcome — the granular per-peer detail is
    /// iroh-internal and not worth threading through FFI.
    SyncFinished { success: bool },
}

impl DocEvent {
    pub(crate) fn from_live(event: LiveEvent) -> Self {
        use iroh_docs::ContentStatus;

        match event {
            LiveEvent::InsertLocal { entry } => Self::InsertLocal {
                key: entry.key().to_vec(),
                hash_hex: entry.content_hash().to_string(),
                size_bytes: entry.content_len(),
            },
            LiveEvent::InsertRemote {
                from,
                entry,
                content_status,
            } => Self::InsertRemote {
                from_node_id: from.to_string(),
                key: entry.key().to_vec(),
                hash_hex: entry.content_hash().to_string(),
                size_bytes: entry.content_len(),
                content_available: matches!(content_status, ContentStatus::Complete),
            },
            LiveEvent::ContentReady { hash } => Self::ContentReady {
                hash_hex: hash.to_string(),
            },
            LiveEvent::PendingContentReady => Self::PendingContentReady,
            LiveEvent::NeighborUp(node) => Self::NeighborUp {
                node_id: node.to_string(),
            },
            LiveEvent::NeighborDown(node) => Self::NeighborDown {
                node_id: node.to_string(),
            },
            LiveEvent::SyncFinished(sync) => Self::SyncFinished {
                success: sync.result.is_ok(),
            },
        }
    }
}

/// FFI listener trait. Implemented on the Swift / Kotlin / Win RT side
/// and registered via `IrohNode::subscribe_doc_events_listener`.
///
/// `on_event` runs on the tokio runtime that drives the doc subscription;
/// keep work short or post into a host queue. `on_closed` fires when the
/// subscription terminates (doc left, node shutdown, transport error).
#[uniffi::export(with_foreign)]
pub trait DocEventListener: Send + Sync {
    fn on_event(&self, event: DocEvent);
    fn on_closed(&self, reason: Option<String>);
}
