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
    /// A set-reconciliation sync round with one peer finished.
    /// `error` is `None` when the round succeeded; when it failed it
    /// carries iroh's one-line reason with every identifier, key or
    /// ticket in it removed, capped at a few lines of log. The entry
    /// counts and timings stay iroh-internal.
    SyncFinished {
        peer_node_id: String,
        error: Option<String>,
    },
}

/// The longest reason a failed [`DocEvent::SyncFinished`] carries, in
/// characters. iroh's reasons are one-line summaries; the cap keeps an
/// unexpectedly verbose one from flooding a caller's log.
const SYNC_ERROR_MAX_CHARS: usize = 160;

/// The shortest run of ASCII letters and digits [`redact_sync_error`]
/// treats as an identifier. Node ids, namespace ids, hashes and tickets
/// are all far longer; ordinary words in iroh's reasons are far shorter.
const REDACTED_TOKEN_MIN_CHARS: usize = 16;

/// What replaces each identifier [`redact_sync_error`] removes.
const REDACTED_TOKEN: &str = "…";

/// A failed round's reason, made safe for a caller's log: every run of
/// [`REDACTED_TOKEN_MIN_CHARS`] or more ASCII letters and digits — a
/// node id, namespace id, hash, key or ticket — is replaced by
/// [`REDACTED_TOKEN`], and the result is cut to
/// [`SYNC_ERROR_MAX_CHARS`]. The failing peer travels in its own field,
/// so nothing a caller needs is lost.
fn redact_sync_error(reason: &str) -> String {
    fn push_token(token: &mut String, out: &mut String) {
        if token.len() >= REDACTED_TOKEN_MIN_CHARS {
            out.push_str(REDACTED_TOKEN);
        } else {
            out.push_str(token);
        }
        token.clear();
    }

    let mut redacted = String::with_capacity(reason.len());
    let mut token = String::new();
    for c in reason.chars() {
        if c.is_ascii_alphanumeric() {
            token.push(c);
        } else {
            push_token(&mut token, &mut redacted);
            redacted.push(c);
        }
    }
    push_token(&mut token, &mut redacted);
    redacted.chars().take(SYNC_ERROR_MAX_CHARS).collect()
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
                peer_node_id: sync.peer.to_string(),
                error: sync.result.err().as_deref().map(redact_sync_error),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_keeps_the_reason_and_drops_identifiers() {
        let reason = "Aborted sync of Some(5a8c0d6e1f2b3a4c5d6e7f8091a2b3c4) with \
                      PublicKey(e13aab63f00dbeefcafe0123456789ab): NotFound";
        assert_eq!(
            redact_sync_error(reason),
            "Aborted sync of Some(…) with PublicKey(…): NotFound"
        );
    }

    #[test]
    fn redaction_leaves_a_plain_reason_alone() {
        assert_eq!(
            redact_sync_error("Failed to establish connection"),
            "Failed to establish connection"
        );
    }

    #[test]
    fn redaction_removes_a_ticket_and_caps_the_length() {
        let ticket = "docaaacb".repeat(40);
        let reason = format!("bad ticket {ticket} {}", "word ".repeat(100));
        let redacted = redact_sync_error(&reason);
        assert!(!redacted.contains("docaaacb"));
        assert!(redacted.starts_with("bad ticket … word"));
        assert_eq!(redacted.chars().count(), SYNC_ERROR_MAX_CHARS);
    }
}
