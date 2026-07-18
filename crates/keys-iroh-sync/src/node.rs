//! Production iroh node: persistent identity, persistent blob store,
//! multiple concurrent docs, configurable DERP relays, graceful shutdown.
//!
//! Compared to the spike (`IrohSandbox/sync-core/src/lib.rs`):
//!
//! - identity is supplied by the caller, not generated per bind;
//! - blob store is disk-backed (`FsStore`) rather than `MemStore`;
//! - docs are disk-backed (`Docs::persistent`) rather than `Docs::memory`;
//! - one node holds many docs (HashMap keyed by `NamespaceId`);
//! - DERP fallback list is caller-supplied with an N0 default;
//! - shutdown awaits in-flight router and endpoint shutdown rather
//!   than the spike's `drop(guard.take())` shortcut.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use futures_util::{FutureExt, StreamExt};
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, Watcher, endpoint::presets, protocol::Router};
use iroh_blobs::{ALPN as BLOBS_ALPN, BlobsProtocol, store::fs::FsStore};
use iroh_docs::{
    ALPN as DOCS_ALPN, DocTicket, NamespaceId, api::Doc, engine::LiveEvent, protocol::Docs,
};
use iroh_gossip::{ALPN as GOSSIP_ALPN, net::Gossip};
use n0_future::Stream;
use tokio::sync::Mutex;

use crate::error::{Result, SyncError};
use crate::events::DocEvent;
use crate::identity::Identity;
use crate::policy::DownloadPolicy;

/// The default deadline [`IrohNode::fetch_blob`] waits for content to
/// arrive before giving up; [`IrohNode::fetch_blob_with_deadline`] lets
/// a caller pick another bound per call. Callers block on that future,
/// so an unreachable publisher or a stalled transfer has to surface as
/// an error rather than hang the caller forever. Chosen to outlast a
/// slow first connection (relay registration + hole-punch) while still
/// failing inside a human's patience for a stuck transfer.
const FETCH_BLOB_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// How long [`IrohNode::fetch_blob`] will sit on the doc event stream
/// before re-reading blob status regardless.
///
/// The blob store is the authority on "is this content here yet?";
/// `ContentReady` is only a low-latency hint at it. Two gaps make this
/// tick load-bearing rather than belt-and-braces:
///
/// - The doc stream carries no download-progress events, so between the
///   entry arriving and the content completing, nothing wakes us. For
///   any blob that takes longer than this tick, this — not the event —
///   is what drives each re-check.
/// - `ContentReady` reaches only the namespace that queued the download
///   *first*: iroh-docs spawns one task per hash and that task captures
///   one namespace, so content pulled in under another joined doc that
///   references the same hash — or written locally — completes with no
///   `ContentReady` on this doc at all.
///
/// Sized to cut the wake-up rate hard versus a tight poll while keeping
/// a missed completion's worst-case latency well inside human patience.
const FETCH_BLOB_STATUS_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(2);

/// Configuration for constructing an `IrohNode`. Caller-owned so the
/// app (not the library) decides where on disk to keep state and which
/// DERP servers to prefer.
///
/// `Debug` is intentionally not derived: `identity.secret_key_bytes`
/// would otherwise round-trip through any `{:?}` log line. The custom
/// `Debug` impl below redacts the identity field while keeping the
/// rest visible.
#[derive(Clone, uniffi::Record)]
pub struct NodeConfig {
    /// 32-byte ed25519 secret key. Persistent across runs — same bytes
    /// → same NodeId. See [`Identity`].
    pub identity: Identity,
    /// Directory the blob store will use. Must exist and be writable.
    /// The store creates files under this directory; it does not
    /// manage the directory's lifecycle.
    pub blob_dir: String,
    /// Directory the doc store will use. Must exist and be writable.
    /// Separate from `blob_dir` so callers can put docs on faster
    /// storage (small entry logs) and blobs on bulk storage if they
    /// want — though pointing them at the same dir is fine.
    pub doc_dir: String,
    /// Custom DERP fallback list. iroh tries these in order during
    /// home-relay selection. Empty list = use N0's default DERPs (the
    /// `presets::N0` preset). Caller passes something like
    /// `["https://derp.keys.app", "https://use1-1.relay.iroh.network"]`
    /// when self-hosting a primary DERP with N0 fallback.
    pub relay_urls: Vec<String>,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("identity", &self.identity)
            .field("blob_dir", &self.blob_dir)
            .field("doc_dir", &self.doc_dir)
            .field("relay_urls", &self.relay_urls)
            .finish()
    }
}

/// The transport library's top-level handle. One per (device, app)
/// process; holds the endpoint, the three mounted protocols, the
/// persistent blob store, and every joined doc.
///
/// Async methods take `&self` — internal mutation goes through a
/// `Mutex` so callers can clone the `Arc` and dispatch from multiple
/// tasks without juggling `&mut`. The mutex is held briefly across the
/// HashMap mutation only, not across the long-running iroh calls.
#[derive(uniffi::Object)]
pub struct IrohNode {
    endpoint: Endpoint,
    router: Router,
    blobs_store: FsStore,
    docs: Docs,
    /// `Mutex<HashMap<...>>` not `RwLock<...>` because the contention
    /// shape is "occasional writes from join/leave, never-hot reads"
    /// and Mutex generates substantially less code through uniffi.
    joined: Mutex<HashMap<NamespaceId, Doc>>,
    /// `OnceCell::get_or_init` elects the first caller to run the
    /// teardown future; every concurrent or subsequent caller awaits
    /// the same init future and returns only after the work has
    /// actually completed. Idempotent and race-free, which matters
    /// for iOS: the background hook may invoke shutdown from multiple
    /// code paths and every caller's `await` must observe the
    /// shutdown as truly finished before the OS suspends the process.
    shutdown_cell: tokio::sync::OnceCell<()>,
}

/// One entry in a joined doc — key, content hash, content size. Cheap:
/// served from the local entry-log replica, no network. Callers use
/// this to apply receiver-side size policy before deciding which blobs
/// to actually fetch.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EntryInfo {
    pub key: Vec<u8>,
    pub hash_hex: String,
    pub size_bytes: u64,
}

#[uniffi::export(async_runtime = "tokio")]
impl IrohNode {
    /// Bind a fresh endpoint with the given identity, persistent
    /// stores, and DERP list. Waits for home-relay registration before
    /// returning, so a successful return means the node is ready to
    /// receive connections.
    #[uniffi::constructor]
    pub async fn bind(config: NodeConfig) -> Result<Arc<Self>> {
        let secret = config.identity.to_secret_key()?;

        let blob_dir = PathBuf::from(&config.blob_dir);
        let doc_dir = PathBuf::from(&config.doc_dir);

        // Caller owns directory lifecycle but we create the leaf if it
        // doesn't exist — saves every consumer writing the same
        // `create_dir_all` dance.
        tokio::fs::create_dir_all(&blob_dir)
            .await
            .with_context(|| format!("create blob_dir {}", blob_dir.display()))
            .map_err(SyncError::from)?;
        tokio::fs::create_dir_all(&doc_dir)
            .await
            .with_context(|| format!("create doc_dir {}", doc_dir.display()))
            .map_err(SyncError::from)?;

        let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
        if !config.relay_urls.is_empty() {
            let urls = config
                .relay_urls
                .iter()
                .map(|s| {
                    s.parse::<RelayUrl>()
                        .with_context(|| format!("invalid relay url: {s}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()
                .map_err(SyncError::from)?;
            let map: RelayMap = urls.into_iter().collect();
            builder = builder.relay_mode(RelayMode::Custom(map));
        }

        let endpoint = builder
            .bind()
            .await
            .context("bind endpoint")
            .map_err(SyncError::from)?;

        let blobs_store = FsStore::load(blob_dir)
            .await
            .context("load fs blob store")
            .map_err(SyncError::from)?;

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let docs = Docs::persistent(doc_dir)
            .spawn(endpoint.clone(), (*blobs_store).clone(), gossip.clone())
            .await
            .context("spawn docs")
            .map_err(SyncError::from)?;

        let router = Router::builder(endpoint.clone())
            .accept(BLOBS_ALPN, BlobsProtocol::new(&blobs_store, None))
            .accept(GOSSIP_ALPN, gossip)
            .accept(DOCS_ALPN, docs.clone())
            .spawn();

        // Wait for DERP registration but cap the wait at 30s. Without
        // a cap, an unreachable relay (network outage, captive portal,
        // misconfigured custom DERP list) hangs `bind()` indefinitely
        // — and the caller has no way to recover except killing the
        // process. 30s is generous compared to a working DERP (~1-3s)
        // and short enough that a stuck network surfaces as an error.
        if tokio::time::timeout(
            std::time::Duration::from_secs(30),
            endpoint.home_relay_status().initialized(),
        )
        .await
        .is_err()
        {
            // Clean up the half-bound endpoint before bailing —
            // leaving it live would leak QUIC sockets and a
            // background DERP-retry task.
            endpoint.close().await;
            return Err(SyncError::Generic(
                "DERP home-relay registration did not complete within 30s — \
                 check network reachability and the configured relay_urls"
                    .into(),
            ));
        }

        Ok(Arc::new(Self {
            endpoint,
            router,
            blobs_store,
            docs,
            joined: Mutex::new(HashMap::new()),
            shutdown_cell: tokio::sync::OnceCell::new(),
        }))
    }

    /// Join a doc described by `ticket` with the given download policy.
    /// Waits for the first sync round to complete so the entry log is
    /// actually populated before returning. Returns the doc's namespace
    /// id as a hex string — callers use this to refer back to the doc
    /// on subsequent `list_entries` / `fetch_blob` / `subscribe` calls.
    ///
    /// Caveat: iroh-docs accepts a `DownloadPolicy` only AFTER
    /// `import(ticket)` resolves, and its default policy is "download
    /// everything". So between `import` and `set_download_policy`
    /// there is a brief window (typically tens of milliseconds, but
    /// up to the first network RTT) during which content matching
    /// the default policy may begin downloading even if the caller
    /// asked for `NothingExcept`. If you need a strict guarantee that
    /// no content is fetched before policy lands, gate the join
    /// behind whatever upper-layer flag you have and don't expose
    /// the joined doc's entries to the rest of the app until your
    /// first `list_entries` confirms the expected shape.
    pub async fn join_doc(&self, ticket: String, policy: DownloadPolicy) -> Result<String> {
        let ticket: DocTicket = ticket
            .parse()
            .context("parse doc ticket")
            .map_err(SyncError::from)?;

        let doc = self
            .docs
            .api()
            .import(ticket)
            .await
            .context("import doc")
            .map_err(SyncError::from)?;

        doc.set_download_policy(policy.into_iroh())
            .await
            .context("set download policy")
            .map_err(SyncError::from)?;

        // Wait for the first sync round so the caller observes the
        // entry log on return, not 200ms later.
        let mut events = doc
            .subscribe()
            .await
            .context("subscribe for initial sync")
            .map_err(SyncError::from)?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match tokio::time::timeout_at(deadline, events.next()).await {
                Ok(Some(Ok(LiveEvent::SyncFinished(_)))) => break,
                Ok(Some(Ok(_))) => {} // ignore non-sync events while waiting
                Ok(Some(Err(e))) => {
                    return Err(SyncError::from(e.context("sync stream")));
                }
                Ok(None) => {
                    return Err(SyncError::Generic(
                        "doc event stream ended before initial sync".into(),
                    ));
                }
                Err(_) => {
                    return Err(SyncError::Generic(
                        "initial sync timed out after 30s".into(),
                    ));
                }
            }
        }

        let id = doc.id();
        self.joined.lock().await.insert(id, doc);
        Ok(id.to_string())
    }

    /// List every entry visible in the named doc. Reads from the local
    /// entry-log replica only — never touches the network.
    pub async fn list_entries(&self, doc_id: String) -> Result<Vec<EntryInfo>> {
        use iroh_docs::store::Query;
        let doc = self.get_doc(&doc_id).await?;
        let stream = doc
            .get_many(Query::all().build())
            .await
            .context("get_many")
            .map_err(SyncError::from)?;
        tokio::pin!(stream);
        let mut out = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry
                .context("entry stream item")
                .map_err(SyncError::from)?;
            out.push(EntryInfo {
                key: entry.key().to_vec(),
                hash_hex: entry.content_hash().to_string(),
                size_bytes: entry.content_len(),
            });
        }
        Ok(out)
    }

    /// Ensure a blob's content is downloaded locally, then return its
    /// bytes, waiting at most `FETCH_BLOB_DEADLINE` (60s) for the
    /// content to land. This is the fixed-deadline convenience form of
    /// [`Self::fetch_blob_with_deadline`]; see that method for the full
    /// semantics of `max_size_bytes`, the wait model, and the failure
    /// modes. A caller that needs a different bound — a longer wait for
    /// a large attachment on a slow link, or a shorter one to fail fast
    /// — calls [`Self::fetch_blob_with_deadline`] directly.
    pub async fn fetch_blob(
        &self,
        doc_id: String,
        hash_hex: String,
        max_size_bytes: u64,
    ) -> Result<Vec<u8>> {
        self.fetch_blob_with_deadline(doc_id, hash_hex, max_size_bytes, FETCH_BLOB_DEADLINE)
            .await
    }
}

// Deliberately not `#[uniffi::export]`: the `Duration` deadline is a
// native-Rust escape hatch for embedders that need a non-default wait
// bound. Keeping it off the uniffi surface holds the generated
// Swift/xcframework bindings — a separate FFI surface regenerated
// out-of-band with no CI — byte-stable, so `fetch_blob` above stays the
// exported 60s-default entry point. Promoting the deadline across the
// seam is a deliberate follow-up: add `#[uniffi::export]` here and
// regenerate the bindings with a Swift-harness test that proves it.
impl IrohNode {
    /// Ensure a blob's content is downloaded locally, then return its
    /// bytes. Blob discovery rides through the joined doc's swarm —
    /// the caller must have joined a doc that references this hash.
    /// `doc_id` selects which doc's peers to ask.
    ///
    /// `max_size_bytes` bounds what this call will read into **memory**:
    /// the fetch is rejected as soon as the store has validated a size
    /// over the cap, and again on completion, so a publisher that
    /// announces a tiny blob and ships a huge one cannot OOM the
    /// receiver. It does **not** bound what reaches **disk** — this call
    /// neither starts nor cancels the transfer (see below), so an
    /// over-cap blob still lands and is merely refused here. Only
    /// [`DownloadPolicy`] governs what is pulled down in the first
    /// place. Pass `0` for "no cap" only when the caller has already
    /// inspected the `EntryInfo.size_bytes` from `list_entries` and made
    /// a policy decision.
    ///
    /// Waits at most `deadline` for the content to land, then fails with
    /// a "did not complete within …" error. The deadline is a per-call
    /// property so an embedder can widen it for a large attachment on a
    /// slow link, or narrow it to fail fast, without a node-global
    /// setting; [`Self::fetch_blob`] is the 60s-default convenience form.
    /// This node never initiates the download itself — the joined doc's
    /// live engine queues it under the doc's [`DownloadPolicy`], and this
    /// call just waits for the result. Content the policy excludes will
    /// therefore never arrive, and the wait will time out.
    ///
    /// `FETCH_BLOB_STATUS_BACKSTOP` bounds the wait between status
    /// re-reads independently of `deadline`: the blob store, not the doc
    /// event stream, is the authority on completion (see that constant),
    /// so a completion that reaches this doc with no event still surfaces
    /// within a backstop tick rather than idling to the deadline.
    pub async fn fetch_blob_with_deadline(
        &self,
        doc_id: String,
        hash_hex: String,
        max_size_bytes: u64,
        deadline: std::time::Duration,
    ) -> Result<Vec<u8>> {
        use iroh_blobs::api::blobs::BlobStatus;

        // Doc id is required so we can fail fast on "you forgot to
        // join" rather than silently waiting out the deadline for
        // content that nobody is offering.
        let doc = self.get_doc(&doc_id).await?;

        let hash: iroh_blobs::Hash = hash_hex
            .parse()
            .context("parse blob hash")
            .map_err(SyncError::from)?;

        // Subscribe BEFORE the first status read, so the two together
        // cover every ordering: the subscription catches a completion
        // that happens from here on, and the status read catches one
        // that already happened. Checking first and subscribing second
        // would drop a blob completing in the gap into a full-deadline
        // wait for an event that had already fired.
        //
        // Events are only ever "go and look again" wake-ups — `status`
        // stays the authority. See `FETCH_BLOB_STATUS_BACKSTOP` for the
        // completions that reach this doc with no event at all; trusting
        // the event as the sole signal would strand those until the
        // deadline.
        let mut events = doc
            .subscribe()
            .await
            .context("subscribe doc events")
            .map_err(SyncError::from)?;

        let deadline_at = tokio::time::Instant::now() + deadline;
        loop {
            let status = self
                .blobs_store
                .status(hash)
                .await
                .context("blob status")
                .map_err(SyncError::from)?;
            // Reject as soon as the true size is known, without reading
            // the blob into memory. A partial entry carries a size only
            // once its last chunk has landed and bao-tree has validated
            // it — so this is "the size is now known and it's too big",
            // not a running byte count, and on a sequential download it
            // fires late rather than progressively. It is still worth
            // having: the size it reports is bao-tree-committed, so a
            // publisher cannot understate it without failing
            // verification.
            match status {
                BlobStatus::Partial {
                    size: Some(validated_size),
                } if max_size_bytes > 0 && validated_size > max_size_bytes => {
                    return Err(SyncError::Generic(format!(
                        "blob {hash_hex} has validated size {validated_size} bytes, exceeds max_size_bytes {max_size_bytes}"
                    )));
                }
                BlobStatus::Complete { size } => {
                    if max_size_bytes > 0 && size > max_size_bytes {
                        return Err(SyncError::Generic(format!(
                            "blob {hash_hex} completed at {size} bytes, exceeds max_size_bytes {max_size_bytes}"
                        )));
                    }
                    break;
                }
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline_at {
                return Err(SyncError::Generic(format!(
                    "blob {hash_hex} did not complete within {deadline:?} (status={status:?})"
                )));
            }

            // Wait for the doc to tell us something changed, rather
            // than spinning on `status`. Any event is a re-check
            // trigger; the backstop bounds the wait when no event is
            // coming, and the deadline caps the whole loop.
            let wake_by =
                (tokio::time::Instant::now() + FETCH_BLOB_STATUS_BACKSTOP).min(deadline_at);
            match tokio::time::timeout_at(wake_by, events.next()).await {
                // An event landed, the backstop/deadline elapsed, or a
                // single event failed to decode — all just mean "go and
                // re-read status". A decode failure is not ours to
                // escalate: iroh-docs keeps the subscription running
                // past it, and `status` is what actually answers the
                // question, so failing the fetch here would abandon a
                // blob that may already be complete on disk.
                Ok(Some(_)) | Err(_) => {}
                // The doc's event stream is gone (the doc was dropped,
                // or the node shut down), so nothing will queue this
                // download now. Fail rather than idle to the deadline.
                Ok(None) => {
                    return Err(SyncError::Generic(format!(
                        "doc {doc_id} event stream ended while waiting for blob {hash_hex}"
                    )));
                }
            }

            // Coalesce whatever else is already queued. Each event
            // would otherwise cost a redundant `status` round-trip, and
            // the doc hands each subscriber a bounded queue whose
            // sender the live actor *awaits* — so draining one event
            // per round-trip lets a busy sync back that actor up
            // against us. Nothing is lost: `status` is re-read below
            // regardless of how many events we collapse here.
            //
            // Terminates because the subscription is backed by an
            // in-process channel: it yields buffered items, then
            // `Pending` (drain stops) or a clean `None` (stream ended).
            // A transport that surfaced a *persistent* per-item error
            // as `Ready(Some(Err))` would spin here — not reachable
            // while the docs engine is in-process, but the assumption
            // to revisit if a remote docs client is ever introduced.
            while events.next().now_or_never().flatten().is_some() {}
        }

        // Stop subscribing before the read below. The doc hands each
        // subscriber a bounded queue and the live actor *awaits* on a
        // full one, so a subscriber that stops draining stalls the
        // actor for every namespace it serves — and `get_bytes` on a
        // large blob is exactly when we'd stop draining longest.
        // Dropping the receiver retires us from the actor's list.
        drop(events);

        let bytes = self
            .blobs_store
            .get_bytes(hash)
            .await
            .context("read complete blob")
            .map_err(SyncError::from)?;
        Ok(bytes.to_vec())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl IrohNode {
    /// Subscribe an FFI listener to events from one doc. Returns
    /// immediately after spawning the bridge task; the listener fires
    /// from a tokio worker until the doc is left or the node is shut
    /// down. Drop the returned subscription handle to cancel early.
    pub async fn subscribe_doc_events_listener(
        &self,
        doc_id: String,
        listener: Arc<dyn crate::events::DocEventListener>,
    ) -> Result<Arc<DocSubscription>> {
        let doc = self.get_doc(&doc_id).await?;
        let stream = doc
            .subscribe()
            .await
            .context("subscribe doc events")
            .map_err(SyncError::from)?;

        let handle = tokio::spawn(async move {
            tokio::pin!(stream);
            let mut closed_reason: Option<String> = None;
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => listener.on_event(DocEvent::from_live(ev)),
                    Err(e) => {
                        closed_reason = Some(format!("{e}"));
                        break;
                    }
                }
            }
            listener.on_closed(closed_reason);
        });

        Ok(Arc::new(DocSubscription {
            handle: Mutex::new(Some(handle)),
        }))
    }

    /// Create a brand-new doc on this node and join it. Returns the
    /// new doc's id (hex `NamespaceId`). Used by the device that
    /// originates a fleet doc / vault doc / friendship doc; receiver
    /// devices use `join_doc` with the ticket the originator shared.
    pub async fn create_doc(&self) -> Result<String> {
        let doc = self
            .docs
            .api()
            .create()
            .await
            .context("create doc")
            .map_err(SyncError::from)?;
        let id = doc.id();
        self.joined.lock().await.insert(id, doc);
        Ok(id.to_string())
    }

    /// Re-attach to a doc that this node already has on disk. Useful
    /// after a process restart: the persistent doc store survives, but
    /// the in-memory `joined` map starts empty, so any `list_entries`
    /// / `set_entry` / `subscribe` call would fail with "doc not
    /// joined" until the doc is re-imported.
    ///
    /// Returns `true` if the doc was found locally and added to the
    /// `joined` map (idempotent — re-opening an already-joined doc is
    /// a successful no-op). Returns `false` if no doc with that
    /// namespace exists in the persistent store, so the caller can
    /// decide whether to surface "I don't know this doc" to the user
    /// or fall through to `create_doc` / `join_doc(ticket)`.
    ///
    /// This is the resume primitive Keys clients use on app launch to
    /// re-activate sync sessions that were live in the previous run.
    ///
    /// Two iroh-docs API facts make this the complete resume path
    /// (verified against iroh-docs 0.99 source):
    ///
    /// 1. `DocsApi::open(namespace)` returns a `Doc` handle but does
    ///    NOT start live sync — it's purely "give me a handle to a
    ///    doc I already hold". Forgetting to follow it with
    ///    `start_sync` is why an earlier version of this method
    ///    resumed the replica but never reconnected to peers.
    /// 2. `Doc::start_sync(peers)` enables live sync AND merges in the
    ///    per-document "known useful peers" that iroh-docs persists in
    ///    its own redb store (the `sync-peers-1` table). Those peers
    ///    are recorded after every successful sync round and survive
    ///    restarts, so passing an empty `peers` vec is sufficient:
    ///    iroh pulls the stored peer set itself and rediscovers each
    ///    peer's current address via NodeId-based DNS/DERP lookup.
    ///
    /// So there's no need for the caller to persist or replay the
    /// join ticket — iroh already remembers who to talk to. We pass
    /// an empty peer list and let the library do the rest.
    ///
    /// Does not wait for a sync round (peers may be unreachable at
    /// launch; we don't want to hang startup). The caller subscribes
    /// to events afterward and observes the first `SyncFinished` as a
    /// connection signal.
    pub async fn open_existing_doc(&self, doc_id: String) -> Result<bool> {
        let namespace: NamespaceId = doc_id
            .parse()
            .context("parse doc id (NamespaceId)")
            .map_err(SyncError::from)?;
        // Already in the joined map? Idempotent success.
        if self.joined.lock().await.contains_key(&namespace) {
            return Ok(true);
        }
        let Some(doc) = self
            .docs
            .api()
            .open(namespace)
            .await
            .context("open existing doc")
            .map_err(SyncError::from)?
        else {
            return Ok(false);
        };
        // Enable live sync. Empty peer list — iroh-docs supplies the
        // persisted per-doc peers from its own store and handles
        // address rediscovery.
        doc.start_sync(Vec::new())
            .await
            .context("start sync on resumed doc")
            .map_err(SyncError::from)?;
        self.joined.lock().await.insert(namespace, doc);
        Ok(true)
    }

    /// Mint a ticket for a doc this node holds. `writable` selects
    /// `ShareMode::Write` vs `ShareMode::Read`. The ticket embeds the
    /// node's relay-and-direct address so a fresh peer can dial back
    /// without needing iroh-dns — appropriate for loopback tests and
    /// for the device-onboarding flow where the receiving device
    /// hasn't published any DNS records yet.
    pub async fn share_doc(&self, doc_id: String, writable: bool) -> Result<String> {
        let doc = self.get_doc(&doc_id).await?;
        let mode = if writable {
            iroh_docs::api::protocol::ShareMode::Write
        } else {
            iroh_docs::api::protocol::ShareMode::Read
        };
        let ticket = doc
            .share(
                mode,
                iroh_docs::api::protocol::AddrInfoOptions::RelayAndAddresses,
            )
            .await
            .context("share doc")
            .map_err(SyncError::from)?;
        Ok(ticket.to_string())
    }

    /// Write a single entry under this node's default author. The
    /// payload becomes a blob in the local store; peers will fetch it
    /// via the normal doc-content-sync path. Returns the content hash.
    pub async fn set_entry(&self, doc_id: String, key: Vec<u8>, value: Vec<u8>) -> Result<String> {
        let doc = self.get_doc(&doc_id).await?;
        let author = self
            .docs
            .api()
            .author_default()
            .await
            .context("default author")
            .map_err(SyncError::from)?;
        let hash = doc
            .set_bytes(author, key, value)
            .await
            .context("set_bytes")
            .map_err(SyncError::from)?;
        Ok(hash.to_string())
    }

    /// Gracefully shut the node down: stop accepting new connections,
    /// drain in-flight protocol handlers, close the endpoint, flush
    /// the blob store. Idempotent — subsequent calls return Ok
    /// immediately.
    ///
    /// iOS callers MUST await this before backgrounding (decision-doc
    /// §2d): quinn's suspended-socket EPIPE on iOS means leaving the
    /// endpoint live across a background transition breaks the next
    /// foreground bind.
    pub async fn shutdown(&self) -> Result<()> {
        // Idempotent + race-free: the OnceCell elects one caller to
        // run the teardown future, all concurrent callers await the
        // same future, and post-completion callers see the cached
        // result and return immediately. Either way every caller's
        // `await` resolves only after the work has finished.
        self.shutdown_cell
            .get_or_init(|| async {
                // Best-effort: log but don't abort if any step fails.
                // The caller can't usefully retry a partial shutdown,
                // and returning lets them proceed to drop the handle.
                if let Err(e) = self.router.shutdown().await {
                    tracing::warn!(error = ?e, "router shutdown error");
                }
                self.endpoint.close().await;
            })
            .await;
        Ok(())
    }
}

impl IrohNode {
    /// Native Rust API for subscribing to doc events as a `Stream`.
    /// Not exposed via uniffi (the FFI path uses the listener trait).
    pub async fn subscribe_doc_events(
        &self,
        doc_id: &str,
    ) -> Result<impl Stream<Item = Result<DocEvent>> + Send + Unpin + 'static> {
        let doc = self.get_doc(doc_id).await?;
        let stream = doc
            .subscribe()
            .await
            .context("subscribe doc events")
            .map_err(SyncError::from)?;
        Ok(Box::pin(stream.map(|item| {
            item.map(DocEvent::from_live)
                .map_err(|e| SyncError::Generic(format!("{e}")))
        })))
    }

    /// The endpoint's NodeId as a hex string. Useful in tests and for
    /// callers that want to log who they are.
    #[must_use]
    pub fn node_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    async fn get_doc(&self, doc_id: &str) -> Result<Doc> {
        let namespace: NamespaceId = doc_id
            .parse()
            .context("parse doc id (NamespaceId)")
            .map_err(SyncError::from)?;
        let map = self.joined.lock().await;
        map.get(&namespace).cloned().ok_or_else(|| {
            SyncError::Generic(format!("doc {doc_id} not joined — call join_doc first"))
        })
    }
}

/// Cancellable handle returned by `subscribe_doc_events_listener`.
/// Drop or call `cancel` to stop the listener early; otherwise it
/// runs until the doc is left or the node is shut down.
#[derive(uniffi::Object)]
pub struct DocSubscription {
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl DocSubscription {
    pub async fn cancel(&self) {
        if let Some(handle) = self.handle.lock().await.take() {
            handle.abort();
            // Ignore the JoinError — we expect Aborted.
            let _ = handle.await;
        }
    }
}

/// Return the node's own NodeId. Exposed as a free function because
/// uniffi-exposed `impl` blocks can only contain async methods (when
/// `async_runtime = "tokio"`); a sync getter doesn't fit there.
#[uniffi::export]
// uniffi needs `Arc<T>` by value across FFI boundaries; clippy would
// rather see `&Arc<T>`. The FFI shape wins.
#[allow(clippy::needless_pass_by_value)]
pub fn node_id(node: Arc<IrohNode>) -> String {
    node.node_id()
}
