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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures_util::{FutureExt, StreamExt};
use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayMap, RelayMode, RelayUrl, SecretKey, Watcher,
    address_lookup::PkarrResolver, endpoint::presets, protocol::Router,
};
use iroh_blobs::{
    ALPN as BLOBS_ALPN, BlobsProtocol,
    provider::events::{
        ConnectMode, EventMask, EventSender, ObserveMode, RequestMode, ThrottleMode,
    },
    store::{
        GcConfig,
        fs::{FsStore, options::Options as BlobStoreOptions},
    },
};
use iroh_docs::{
    ALPN as DOCS_ALPN, DocTicket, NamespaceId, PeerIdBytes,
    api::Doc,
    engine::{LiveEvent, Origin, ProtectCallbackHandler},
    protocol::Docs,
};
use iroh_gossip::{ALPN as GOSSIP_ALPN, net::Gossip};
use n0_future::{Stream, task::AbortOnDropHandle};
use tokio::sync::{Mutex, mpsc};

use crate::error::{Result, SyncError};
use crate::events::DocEvent;
use crate::identity::Identity;
use crate::policy::DownloadPolicy;

/// What the mounted blobs protocol will serve to a connecting peer:
/// reads (`get`, `get_many`, `observe`) only. Inbound `push` is
/// refused outright.
///
/// A push writes into our store on the peer's initiative, and any peer
/// that can dial us could send one — no doc membership required — to
/// fill the disk or plant content. The node has no use for it: blobs
/// arrive by our own fetch of content named in a doc we joined, under
/// that doc's [`DownloadPolicy`] (what a doc *writer* may name is a
/// separate trust boundary, governed there). Reads stay open to any
/// dialler, as before: they are content-addressed, so a peer must
/// already know a hash, and vault payloads are ciphertext.
///
/// Upstream's default mask also disables push, but we pin our own so
/// the posture is ours rather than inherited. A pinned mask is not the
/// whole guard: `iroh-blobs` 0.101.0 (since yanked) checked every
/// request kind against the `get` mode, so push was accepted whatever
/// the mask said. The `blobs_protocol_serves_fetch_but_refuses_push`
/// integration test is what catches that class on a dependency bump.
///
/// Written as a full struct literal (no `..` spread) on purpose: a
/// request kind added upstream then fails to compile here until
/// someone decides whether we serve it.
///
/// Every mode is `None` or `Disabled`, never an `Intercept*` variant.
/// The tracing sink this mask rides on (see [`IrohNode::bind`]) answers
/// every intercept with "allow", so switching a mode to intercept would
/// silently approve everything; that change needs a real decision
/// handler in place of the sink.
const BLOBS_PROVIDER_MASK: EventMask = EventMask {
    connected: ConnectMode::None,
    get: RequestMode::None,
    get_many: RequestMode::None,
    push: RequestMode::Disabled,
    observe: ObserveMode::None,
    throttle: ThrottleMode::None,
};

/// How often the blob store deletes content that no doc refers to any
/// more. Each save stores the vault file as a new blob and leaves the
/// one it replaced referred to by nothing, so without a sweep the store
/// grows by a whole vault file per save, for as long as the node is
/// used. What a sweep keeps: every hash in every doc this node holds
/// (iroh-docs hands the sweep that list), this node's own latest saves
/// (see [`own_head_tag`]), and content a download or a fetch holds.
/// The first sweep comes one interval after bind, and a mobile node
/// is shut down on every trip to the background, so the interval has
/// to be short enough to fall inside a typical foreground session. A
/// sweep lists the store's blobs and the docs' hashes, which for a
/// handful of vaults is cheap.
const BLOB_GC_INTERVAL: Duration = Duration::from_secs(60);

/// The blob store's database file inside `blob_dir`: the name
/// `FsStore::load` uses, so stores made before the sweep was switched
/// on open unchanged.
const BLOB_STORE_DB_FILE: &str = "blobs.db";

/// Prefix of the blob tags that hold this node's own latest saves; see
/// [`own_head_tag`].
const OWN_HEAD_TAG_PREFIX: &[u8] = b"keys-iroh-sync/own-head/";

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

/// How long [`IrohNode::fetch_blob_with_deadline`] leaves a still-incomplete
/// blob to the doc engine's own download before requesting it from the
/// doc's peers itself, and the spacing between such requests. Long enough
/// for a just-synced entry's queued download to land first, so the two
/// rarely overlap; short against the 60 s fetch deadline, so a download the
/// engine lost is recovered well inside it.
const MISSING_BLOB_REQUEST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a joined doc waits, after a failed round with a peer it owes
/// a sync round, before each re-dial in turn; once these are spent it
/// waits [`REDIAL_STEADY_INTERVAL`]. See [`watch_redial`].
///
/// The first step is short because the commonest gap is brief (a
/// relaunch, a network change, a lid opened); the steps then widen so a
/// peer that is gone for hours costs a dial every few minutes, not a
/// constant stream of them.
const REDIAL_BACKOFF: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(60),
];

/// The re-dial interval once [`REDIAL_BACKOFF`] is spent, for as long as
/// the doc still owes a peer a round.
const REDIAL_STEADY_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The delay before re-dial number `attempt` (counting from 0) of one
/// owed stretch.
fn redial_delay(attempt: usize) -> Duration {
    REDIAL_BACKOFF
        .get(attempt)
        .copied()
        .unwrap_or(REDIAL_STEADY_INTERVAL)
}

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
/// The tag prefix shared by every own-head tag of `namespace`, so
/// [`IrohNode::drop_doc`] can delete them together.
fn own_head_tag_prefix(namespace: NamespaceId) -> Vec<u8> {
    let mut prefix = OWN_HEAD_TAG_PREFIX.to_vec();
    prefix.extend_from_slice(namespace.as_bytes());
    prefix.push(b'/');
    prefix
}

/// The blob tag that holds this node's latest save under `key` in
/// `namespace`. A save is imported under this tag, replacing the
/// previous save's, so the content is held from the moment it is
/// written. The doc's own hold isn't enough on its own: iroh-blobs
/// takes the docs' list of hashes before it forgets which blobs were
/// written since the last sweep, so a save that lands between the two
/// would be in neither and be swept while the doc still names it. A
/// peer's content lost that way comes back from the peer; this node's
/// own save has nowhere to come back from.
fn own_head_tag(namespace: NamespaceId, key: &[u8]) -> Vec<u8> {
    let mut tag = own_head_tag_prefix(namespace);
    tag.extend_from_slice(key);
    tag
}

/// Undo what a failed join or resume of `doc` opened, so no handle
/// outlives the attempt: a leftover handle keeps the doc open in the
/// store until the node stops, and [`IrohNode::drop_doc`] can't delete
/// an open doc. `was_joined` says a joined entry already relies on the
/// doc syncing, in which case only the attempt's own handle is closed.
/// Best effort: the attempt's error is what the caller hears.
async fn release_failed_attempt(doc: &Doc, was_joined: bool) {
    if !was_joined && let Err(e) = doc.leave().await {
        tracing::warn!(doc = %doc.id().fmt_short(), error = ?e, "leaving a doc after a failed join");
    }
    if let Err(e) = doc.close().await {
        tracing::warn!(doc = %doc.id().fmt_short(), error = ?e, "closing a doc after a failed join");
    }
}

#[derive(uniffi::Object)]
pub struct IrohNode {
    endpoint: Endpoint,
    router: Router,
    blobs_store: FsStore,
    docs: Docs,
    /// `Mutex<HashMap<...>>` not `RwLock<...>` because the contention
    /// shape is "occasional writes from join/leave, never-hot reads"
    /// and Mutex generates substantially less code through uniffi.
    joined: Mutex<HashMap<NamespaceId, JoinedDoc>>,
    /// `OnceCell::get_or_init` elects the first caller to run the
    /// teardown future; every concurrent or subsequent caller awaits
    /// the same init future and returns only after the work has
    /// actually completed. Idempotent and race-free, which matters
    /// for iOS: the background hook may invoke shutdown from multiple
    /// code paths and every caller's `await` must observe the
    /// shutdown as truly finished before the OS suspends the process.
    shutdown_cell: tokio::sync::OnceCell<()>,
}

/// A doc this node has joined, with the task that re-dials its peers
/// while it owes one a sync round (see [`watch_redial`]). The task lives
/// exactly as long as the entry: replacing or dropping the entry aborts
/// it, and [`IrohNode::shutdown`] aborts it before tearing the node down.
struct JoinedDoc {
    doc: Doc,
    redial: AbortOnDropHandle<()>,
    /// Peers to stop re-dialling, handed to the re-dial task (see
    /// [`IrohNode::forget_peer`]).
    forget: mpsc::UnboundedSender<PublicKey>,
}

impl JoinedDoc {
    /// Start watching `doc` for owed rounds. Call it before the doc's
    /// first `start_sync`, so the watch sees every round's outcome —
    /// above all a resume's or a join's first rounds failing.
    async fn watch(doc: Doc) -> Result<Self> {
        let events = doc
            .subscribe()
            .await
            .context("subscribe for re-dial watch")
            .map_err(SyncError::from)?;
        let (forget, forgotten) = mpsc::unbounded_channel();
        let redial =
            AbortOnDropHandle::new(tokio::spawn(watch_redial(doc.clone(), events, forgotten)));
        Ok(Self {
            doc,
            redial,
            forget,
        })
    }
}

/// Keep re-dialling `doc`'s peers while the doc owes any of them a sync
/// round, on the [`REDIAL_BACKOFF`] schedule.
///
/// iroh-docs dials a doc's peers only when told to (`start_sync`: a
/// join, a resume, and — since every write calls it — a write). A round
/// that fails because the peer is unreachable is not retried, and the
/// gossip mesh has no neighbour to carry anything once the peer is back,
/// so a write made while the peer was away would wait for the next local
/// write or a restart. This task closes that gap without either peer
/// doing anything.
///
/// A peer is *owed* a round from the moment a round we dialled to it
/// fails until a round with it succeeds, in either direction. A failed
/// round the peer dialled leaves nothing owed: the peer keeps the debt,
/// and a remote cannot put itself on our dial list by failing a round.
/// A `NeighborUp` clears nothing on its own either: it only prompts
/// iroh-docs to run a round, whose outcome is what counts.
///
/// While any peer is owed, the doc re-runs `start_sync` with the owed
/// peers. Owed peers are named explicitly because iroh-docs persists a
/// peer only after a successful round, so a ticket peer unreachable at
/// join would otherwise not be dialled again in this run. `start_sync`
/// also re-joins the doc's persisted peers and runs a direct round with
/// each — cheap for a peer with nothing new, and the only dial iroh-docs
/// offers. A peer that never comes back (a retired device) costs one dial
/// every [`REDIAL_STEADY_INTERVAL`] while the node runs, until the caller
/// forgets it ([`IrohNode::forget_peer`]): a forgotten peer is never owed
/// a round, until a round with it succeeds. See [`RedialSet`].
///
/// Each delay runs from the latest failed round, not from the previous
/// re-dial: a dial to an absent peer can take tens of seconds to fail,
/// and iroh-docs drops a new dial to a peer while one is in flight, so a
/// clock started at the re-dial would spend the short steps on no-ops.
/// The re-dial also sets a timer of its own, so a re-dial that produces
/// no outcome at all is still followed by another. The schedule starts
/// over only once nothing is owed.
///
/// Driven by failed rounds, not by `NeighborDown`: an idle mesh closes
/// while both peers are up, and re-dialling on that would rebuild a mesh
/// that only closes again, for no delivery — a write already re-dials
/// on its own (see [`IrohNode::set_entry`]).
///
/// Ends when the doc's event stream does (the node shut down), or when
/// aborted; the in-flight re-dial is aborted with it.
async fn watch_redial(
    doc: Doc,
    mut events: impl Stream<Item = anyhow::Result<LiveEvent>> + Unpin,
    mut forgotten: mpsc::UnboundedReceiver<PublicKey>,
) {
    let mut peers = RedialSet::default();
    let mut attempt = 0;
    let mut next_redial: Option<tokio::time::Instant> = None;
    // Held only for its drop: aborting this task aborts the re-dial too.
    // Replacing it aborts the previous one, which by then has had at
    // least one backoff step to finish a single RPC.
    let mut _in_flight: Option<AbortOnDropHandle<()>> = None;
    loop {
        let redial_due = async {
            match next_redial {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            event = events.next() => match event {
                Some(Ok(LiveEvent::SyncFinished(sync))) => {
                    if peers.record_round(sync.peer, &sync.origin, sync.result.is_ok()) {
                        next_redial = Some(tokio::time::Instant::now() + redial_delay(attempt));
                    }
                }
                // Other events say nothing about whether a round got
                // through; a decode failure is one lost event on a stream
                // that carries on.
                Some(Ok(_) | Err(_)) => {}
                None => return,
            },
            Some(peer) = forgotten.recv() => peers.forget(peer),
            () = redial_due => {
                tracing::info!(
                    doc = %doc.id(),
                    owed = peers.owed.len(),
                    attempt,
                    "re-dialling peers owed a sync round"
                );
                // Not awaited here: the live actor awaits room in this
                // task's event queue, so waiting on its reply while not
                // draining that queue could deadlock both.
                let doc = doc.clone();
                let owed = peers.owed.iter().copied().map(EndpointAddr::new).collect();
                _in_flight = Some(AbortOnDropHandle::new(tokio::spawn(async move {
                    if let Err(e) = doc.start_sync(owed).await {
                        tracing::warn!(error = ?e, "re-dial of peers owed a round failed to start");
                    }
                })));
                attempt += 1;
                next_redial = Some(tokio::time::Instant::now() + redial_delay(attempt));
            },
        }
        if peers.owed.is_empty() {
            attempt = 0;
            next_redial = None;
        }
    }
}

/// Which of a doc's peers [`watch_redial`] owes a sync round, and which
/// the caller has told it to stop re-dialling.
#[derive(Debug, Default)]
struct RedialSet {
    /// Peers a round we dialled failed to reach, since the latest round
    /// with each that succeeded.
    owed: HashSet<PublicKey>,
    /// Peers the caller has forgotten ([`IrohNode::forget_peer`]) and no
    /// round has reached since.
    forgotten: HashSet<PublicKey>,
}

impl RedialSet {
    /// Account for one finished round with `peer`. Returns whether it left
    /// the peer owed, i.e. whether a re-dial should be scheduled.
    ///
    /// A round that succeeds in either direction settles the peer's debt
    /// and also un-forgets it: a peer that syncs again is live and in the
    /// doc, so a later failure with it is worth re-dialling.
    fn record_round(&mut self, peer: PublicKey, origin: &Origin, succeeded: bool) -> bool {
        if succeeded {
            self.owed.remove(&peer);
            self.forgotten.remove(&peer);
            return false;
        }
        match origin {
            Origin::Connect(_) if !self.forgotten.contains(&peer) => {
                self.owed.insert(peer);
                true
            }
            Origin::Connect(_) | Origin::Accept => false,
        }
    }

    /// Stop owing `peer` a round, and leave it un-owed by later failed
    /// rounds until one with it succeeds.
    fn forget(&mut self, peer: PublicKey) {
        self.owed.remove(&peer);
        self.forgotten.insert(peer);
    }
}

/// The builder every node's endpoint starts from: N0's relays, publishing
/// and DNS lookup, plus a pkarr lookup over HTTPS.
///
/// N0 resolves a peer's addressing (its home relay) only by plain
/// DNS outside browsers, through the system resolver. A resolver that
/// caches a negative answer for a peer's record — some home routers
/// keep NXDOMAIN for up to an hour, ignoring the zone's zero negative
/// TTL — leaves every NodeId-only dial to that peer failing with no
/// addressing information, while the peer that's still up has nothing
/// owed and never dials back. Also asking n0's pkarr relay over HTTPS
/// (the same server our record is published to) reaches the current
/// record without any intermediate cache. iroh runs both lookups and
/// merges what they find.
fn endpoint_builder(secret: SecretKey) -> iroh::endpoint::Builder {
    Endpoint::builder(presets::N0)
        .address_lookup(PkarrResolver::n0_dns())
        .secret_key(secret)
}

/// Short display forms of a doc's persisted peer ids, for logging.
fn short_peer_ids(peers: &[PeerIdBytes]) -> Vec<String> {
    peers
        .iter()
        .map(|bytes| match PublicKey::from_bytes(bytes) {
            Ok(key) => key.fmt_short().to_string(),
            Err(e) => format!("undecodable peer id ({e})"),
        })
        .collect()
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
        Self::bind_with_gc_interval(config, BLOB_GC_INTERVAL).await
    }

    /// Join a doc described by `ticket` with the given download policy.
    /// Waits for the first sync round to complete so the entry log is
    /// actually populated before returning. Returns the doc's namespace
    /// id as a hex string — callers use this to refer back to the doc
    /// on subsequent `list_entries` / `fetch_blob` / `subscribe` calls.
    ///
    /// The namespace is imported without syncing, and the policy and
    /// the event subscriptions are in place before the first round is
    /// started: no content is fetched under iroh-docs' default "download
    /// everything" policy, and no round finishes unobserved.
    pub async fn join_doc(&self, ticket: String, policy: DownloadPolicy) -> Result<String> {
        let DocTicket { capability, nodes } = ticket
            .parse()
            .context("parse doc ticket")
            .map_err(SyncError::from)?;

        let was_joined = self.joined.lock().await.contains_key(&capability.id());
        let doc = self
            .docs
            .api()
            .import_namespace(capability)
            .await
            .context("import doc")
            .map_err(SyncError::from)?;
        match self.finish_join(&doc, policy, nodes).await {
            Ok(joined) => {
                let id = doc.id();
                // A re-join replaces the entry; the doc handle the old
                // entry held is closed, or it would stay open for good.
                if let Some(old) = self.joined.lock().await.insert(id, joined)
                    && let Err(e) = old.doc.close().await
                {
                    tracing::warn!(doc = %id.fmt_short(), error = ?e, "closing the replaced doc handle");
                }
                Ok(id.to_string())
            }
            Err(e) => {
                release_failed_attempt(&doc, was_joined).await;
                Err(e)
            }
        }
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
    /// receiver. It does **not** bound what reaches **disk**: the doc
    /// engine's transfer runs on regardless, so an over-cap blob still
    /// lands and is merely refused here. Only [`DownloadPolicy`] governs
    /// what is pulled down in the first place — including the transfer
    /// this call may request itself (see below), which is aborted when the
    /// call returns. Pass `0` for "no cap" only when the caller has already
    /// inspected the `EntryInfo.size_bytes` from `list_entries` and made
    /// a policy decision.
    ///
    /// Waits at most `deadline` for the content to land, then fails with
    /// a "did not complete within …" error. The deadline is a per-call
    /// property so an embedder can widen it for a large attachment on a
    /// slow link, or narrow it to fail fast, without a node-global
    /// setting; [`Self::fetch_blob`] is the 60s-default convenience form.
    /// The joined doc's live engine normally queues the download under the
    /// doc's [`DownloadPolicy`], and this call waits for the result. A
    /// download the engine lost — one that failed, or content its author
    /// didn't yet have when the entry synced — is never retried by it, so
    /// once the blob is still incomplete after
    /// `MISSING_BLOB_REQUEST_INTERVAL`, this call requests it from the
    /// doc's peers itself, again at that interval while it stays
    /// incomplete. Only content the policy admits is requested (see
    /// `request_missing_blob`); excluded content never arrives, and its
    /// wait times out.
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

        // Hold the content for the length of the call: once a newer
        // entry replaces the one naming it, a sweep could otherwise
        // delete it between the status check and the read.
        let _hold = self
            .blobs_store
            .tags()
            .temp_tag(hash)
            .await
            .context("hold blob")
            .map_err(SyncError::from)?;
        let deadline_at = tokio::time::Instant::now() + deadline;
        // A transfer this call requested itself; dropping it (whichever way
        // the call returns) aborts it. The first request waits an interval,
        // so a download the engine has only just queued isn't duplicated.
        let mut requested: Option<AbortOnDropHandle<()>> = None;
        let mut next_request_at = tokio::time::Instant::now() + MISSING_BLOB_REQUEST_INTERVAL;
        loop {
            let status = self
                .blobs_store
                .status(hash)
                .await
                .context("blob status")
                .map_err(SyncError::from)?;
            let incomplete = !matches!(status, BlobStatus::Complete { .. });
            let request_live = requested.as_ref().is_some_and(|r| !r.is_finished());
            if incomplete && !request_live && tokio::time::Instant::now() >= next_request_at {
                next_request_at = tokio::time::Instant::now() + MISSING_BLOB_REQUEST_INTERVAL;
                requested = self.request_missing_blob(&doc, hash).await;
            }
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

    /// Request `hash` from `doc`'s peers: the recovery for a blob the doc
    /// engine lost. iroh-docs queues a doc's content downloads itself, but
    /// one that fails — or content its author didn't yet have when the
    /// entry synced — only lands in the engine's in-memory "missing" set:
    /// nothing retries it, and a restart forgets it.
    ///
    /// Only a hash named by an entry the doc's [`DownloadPolicy`] admits is
    /// requested, i.e. content the engine would have pulled down itself, so
    /// this adds no reach beyond the policy's.
    ///
    /// Best effort: returns the transfer (aborted when dropped), or `None`
    /// when there is nothing to request or the lookup failed — the caller
    /// keeps waiting either way, as it did before this recovery existed.
    async fn request_missing_blob(
        &self,
        doc: &Doc,
        hash: iroh_blobs::Hash,
    ) -> Option<AbortOnDropHandle<()>> {
        match self.admitted_providers(doc, hash).await {
            Ok(providers) if !providers.is_empty() => {
                tracing::debug!(
                    doc = %doc.id().fmt_short(),
                    %hash,
                    peers = providers.len(),
                    "requesting a missing blob from the doc's peers"
                );
                let downloader = self.blobs_store.downloader(&self.endpoint);
                let transfer = downloader.download(hash, providers);
                Some(AbortOnDropHandle::new(tokio::spawn(async move {
                    if let Err(e) = transfer.await {
                        tracing::debug!(error = ?e, "requested blob download failed");
                    }
                    // The downloader's actor serves the transfer only while
                    // a handle to it is alive.
                    drop(downloader);
                })))
            }
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(error = ?e, "could not look up peers for a missing blob");
                None
            }
        }
    }

    /// The doc's sync peers to ask for `hash` — empty unless an entry in
    /// the doc names `hash` and the doc's download policy admits it.
    async fn admitted_providers(
        &self,
        doc: &Doc,
        hash: iroh_blobs::Hash,
    ) -> Result<Vec<PublicKey>> {
        use iroh_docs::store::Query;

        let policy = doc
            .get_download_policy()
            .await
            .context("download policy")
            .map_err(SyncError::from)?;
        let entries = doc
            .get_many(Query::all().build())
            .await
            .context("get_many")
            .map_err(SyncError::from)?;
        tokio::pin!(entries);
        let mut admitted = false;
        while let Some(entry) = entries.next().await {
            let entry = entry
                .context("entry stream item")
                .map_err(SyncError::from)?;
            if entry.content_hash() == hash && policy.matches(&entry) {
                admitted = true;
                break;
            }
        }
        if !admitted {
            return Ok(Vec::new());
        }
        Ok(doc
            .get_sync_peers()
            .await
            .context("sync peers")
            .map_err(SyncError::from)?
            .unwrap_or_default()
            .iter()
            .filter_map(|bytes| PublicKey::from_bytes(bytes).ok())
            .collect())
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
        let joined = JoinedDoc::watch(doc).await?;
        self.joined.lock().await.insert(id, joined);
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
    /// connection signal. A peer the resume's rounds fail to reach is
    /// re-dialled on a backoff schedule until a round with it succeeds
    /// (see `watch_redial`).
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
        match Self::resume(&doc, namespace).await {
            Ok(joined) => {
                self.joined.lock().await.insert(namespace, joined);
                Ok(true)
            }
            Err(e) => {
                release_failed_attempt(&doc, false).await;
                Err(e)
            }
        }
    }

    /// Stop re-dialling `node_id` for `doc_id` after rounds with it fail —
    /// for a peer the caller knows is gone for good, such as a retired
    /// device. Without this, a peer a round we dialled failed to reach is
    /// re-dialled every few minutes for as long as the node runs.
    ///
    /// Only the re-dial stops. iroh-docs still runs a round with every
    /// peer in the doc's persisted peer list when a write (or a re-dial
    /// owed to another peer) starts one; such a round with a forgotten
    /// peer fails as before but leaves nothing owed. A round with the
    /// peer that succeeds, in either direction, un-forgets it.
    ///
    /// Holds for this run of the node only: a caller that wants a peer to
    /// stay forgotten repeats the call after each `open_existing_doc` of
    /// the doc. Idempotent. Errors if the doc isn't joined or `node_id`
    /// isn't a node id.
    pub async fn forget_peer(&self, doc_id: String, node_id: String) -> Result<()> {
        let peer: PublicKey = node_id
            .parse()
            .context("parse node id")
            .map_err(SyncError::from)?;
        self.with_joined(&doc_id, |joined| joined.forget.send(peer))
            .await?
            .context("re-dial watch for the doc has ended")
            .map_err(SyncError::from)
    }

    /// Stop syncing a doc but keep it: leave live sync and the doc's
    /// gossip swarm, and stop re-dialling its peers, so the node no
    /// longer exchanges entries for it. The entries, the capability and
    /// the content stay; `open_existing_doc` resumes the doc. Blob reads
    /// by hash are still answered (see `BLOBS_PROVIDER_MASK`).
    ///
    /// Idempotent: a doc that isn't joined isn't syncing. Errors if
    /// `doc_id` isn't a doc id or iroh-docs refuses the leave; the doc is
    /// no longer joined either way.
    pub async fn leave_doc(&self, doc_id: String) -> Result<()> {
        let namespace: NamespaceId = doc_id
            .parse()
            .context("parse doc id (NamespaceId)")
            .map_err(SyncError::from)?;
        let Some(doc) = self.take_joined(namespace).await else {
            return Ok(());
        };
        doc.leave()
            .await
            .context("leave doc")
            .map_err(SyncError::from)?;
        doc.close()
            .await
            .context("close doc")
            .map_err(SyncError::from)
    }

    /// Delete a doc from this node: stop syncing it and remove its
    /// entries, its namespace secret (the capability to write to it) and
    /// its persisted peers from the store. The blobs only it referred to
    /// go at the next blob sweep. For a doc the caller no longer wants on
    /// this device; peers keep their copies. Afterwards
    /// `open_existing_doc` of the id returns `false`.
    ///
    /// Idempotent: a doc this node doesn't hold is already gone. Errors
    /// if `doc_id` isn't a doc id or the store can't delete it; the doc
    /// is no longer joined either way. The caller doesn't resume or join
    /// the doc while the drop runs.
    pub async fn drop_doc(&self, doc_id: String) -> Result<()> {
        let namespace: NamespaceId = doc_id
            .parse()
            .context("parse doc id (NamespaceId)")
            .map_err(SyncError::from)?;
        // The joined entry's doc handle stays open for the drop to close;
        // a doc that isn't joined is opened first.
        if self.take_joined(namespace).await.is_none() {
            if !self.holds_doc(namespace).await? {
                return Ok(());
            }
            self.docs
                .api()
                .open(namespace)
                .await
                .context("open doc to drop")
                .map_err(SyncError::from)?;
        }
        self.docs
            .api()
            .drop_doc(namespace)
            .await
            .context("drop doc")
            .map_err(SyncError::from)?;
        self.blobs_store
            .tags()
            .delete_prefix(own_head_tag_prefix(namespace))
            .await
            .context("delete the doc's own-head tags")
            .map_err(SyncError::from)?;
        Ok(())
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
    ///
    /// After the write, the doc's known peers are re-dialled: a direct
    /// sync round with each, spawned in the background, so the write is
    /// delivered even when the live mesh has dropped its connections. That
    /// also makes a never-shared doc live (as sharing does). Delivery is
    /// best effort — an `Ok` means the entry is stored, not that a peer
    /// has it; a failed re-dial is logged, not returned. A peer the
    /// write's round fails to reach is re-dialled on a backoff schedule
    /// until a round with it succeeds (see `watch_redial`), so the
    /// write still reaches it once it is back.
    pub async fn set_entry(&self, doc_id: String, key: Vec<u8>, value: Vec<u8>) -> Result<String> {
        let doc = self.get_doc(&doc_id).await?;
        let author = self
            .docs
            .api()
            .author_default()
            .await
            .context("default author")
            .map_err(SyncError::from)?;
        let size = value.len() as u64;
        let tag = own_head_tag(doc.id(), &key);
        let hash = self
            .blobs_store
            .add_bytes(value)
            .with_named_tag(tag)
            .await
            .context("store entry content")
            .map_err(SyncError::from)?
            .hash;
        doc.set_hash(author, key, hash, size)
            .await
            .context("set_hash")
            .map_err(SyncError::from)?;
        // Deliver the write whatever state the live mesh is in. A local
        // insert travels to the doc's gossip neighbours — and there may be
        // none: an idle connection closes, both sides see `NeighborDown`,
        // and nothing re-dials, so the write would sit here until something
        // else restarted sync. `start_sync` on a live doc re-joins the doc's
        // persisted peers and runs a direct sync round with each (see
        // `open_existing_doc`), which delivers this write and restores the
        // mesh. A peer already mid-sync just aborts the extra round. The
        // write is already stored, so a failed re-dial must not read as a
        // failed write. A round that fails to reach a peer is retried by
        // the doc's re-dial watch.
        if let Err(e) = doc.start_sync(Vec::new()).await {
            tracing::warn!(error = ?e, "re-dial of known peers after a write failed");
        }
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
                // Stop re-dialling before the transport goes away, so no
                // re-dial races the teardown.
                for joined in self.joined.lock().await.values() {
                    joined.redial.abort();
                }
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
    /// The part of [`IrohNode::join_doc`] after the import: set the
    /// policy, watch for owed rounds, start sync and wait for the first
    /// round. On error the caller releases what this opened.
    async fn finish_join(
        &self,
        doc: &Doc,
        policy: DownloadPolicy,
        nodes: Vec<EndpointAddr>,
    ) -> Result<JoinedDoc> {
        doc.set_download_policy(policy.into_iroh())
            .await
            .context("set download policy")
            .map_err(SyncError::from)?;

        let joined = JoinedDoc::watch(doc.clone()).await?;
        // Wait for the first sync round so the caller observes the
        // entry log on return, not 200ms later.
        let mut events = doc
            .subscribe()
            .await
            .context("subscribe for initial sync")
            .map_err(SyncError::from)?;
        doc.start_sync(nodes)
            .await
            .context("start sync on joined doc")
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

        Ok(joined)
    }
}

impl IrohNode {
    /// The part of [`IrohNode::open_existing_doc`] after the open: watch
    /// for owed rounds and start sync. On error the caller releases what
    /// this opened.
    async fn resume(doc: &Doc, namespace: NamespaceId) -> Result<JoinedDoc> {
        let joined = JoinedDoc::watch(doc.clone()).await?;
        // Which peers the resume will dial — the first thing to know when
        // a resumed doc never reaches its peer. Diagnostic only, so a
        // failed lookup doesn't fail the resume, and the lookup is skipped
        // unless something will record it.
        if tracing::enabled!(tracing::Level::DEBUG) {
            match doc.get_sync_peers().await {
                Ok(peers) => tracing::debug!(
                    doc = %namespace.fmt_short(),
                    peers = ?short_peer_ids(&peers.unwrap_or_default()),
                    "resuming doc with persisted sync peers"
                ),
                Err(e) => tracing::debug!(
                    doc = %namespace.fmt_short(),
                    error = ?e,
                    "persisted sync peers unavailable"
                ),
            }
        }
        // Enable live sync. Empty peer list — iroh-docs supplies the
        // persisted per-doc peers from its own store and handles
        // address rediscovery.
        doc.start_sync(Vec::new())
            .await
            .context("start sync on resumed doc")
            .map_err(SyncError::from)?;
        Ok(joined)
    }
}

impl IrohNode {
    /// [`IrohNode::bind`] with the blob sweep on a given schedule, so a
    /// test can watch a sweep without waiting [`BLOB_GC_INTERVAL`].
    async fn bind_with_gc_interval(config: NodeConfig, gc_interval: Duration) -> Result<Arc<Self>> {
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

        let mut builder = endpoint_builder(secret);
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

        // The sweep asks the docs engine which content its docs still
        // refer to before each run; the handler is that engine's end of
        // the question.
        let (protect_handler, protect_cb) = ProtectCallbackHandler::new();
        let mut blob_options = BlobStoreOptions::new(&blob_dir);
        blob_options.gc = Some(GcConfig {
            interval: gc_interval,
            add_protected: Some(protect_cb),
        });
        let blobs_store = FsStore::load_with_opts(blob_dir.join(BLOB_STORE_DB_FILE), blob_options)
            .await
            .context("load fs blob store")
            .map_err(SyncError::from)?;

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let docs = Docs::persistent(doc_dir)
            .protect_handler(protect_handler)
            .spawn(endpoint.clone(), (*blobs_store).clone(), gossip.clone())
            .await
            .context("spawn docs")
            .map_err(SyncError::from)?;

        let router = Router::builder(endpoint.clone())
            .accept(
                BLOBS_ALPN,
                BlobsProtocol::new(
                    &blobs_store,
                    // A custom mask can only ride on a sender with a sink
                    // behind it. Every notification is off, so upstream's
                    // tracing sink sees nothing but connection-closed
                    // notices.
                    Some(EventSender::DEFAULT.tracing(BLOBS_PROVIDER_MASK)),
                ),
            )
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

    /// Take `namespace`'s joined entry out of the map, stop its re-dial
    /// watch and wait for it to end, so no re-dial reopens sync behind
    /// whatever the caller does next. Returns the entry's doc, whose
    /// handle is still open, or `None` if the doc isn't joined.
    async fn take_joined(&self, namespace: NamespaceId) -> Option<Doc> {
        let JoinedDoc { doc, redial, .. } = self.joined.lock().await.remove(&namespace)?;
        redial.abort();
        // An aborted task ends with a cancellation error: expected.
        let _ = redial.await;
        Some(doc)
    }

    /// Whether the doc store holds `namespace`, joined or not.
    async fn holds_doc(&self, namespace: NamespaceId) -> Result<bool> {
        let mut docs = self
            .docs
            .api()
            .list()
            .await
            .context("list docs")
            .map_err(SyncError::from)?;
        while let Some(doc) = docs.next().await {
            let (held, _) = doc.context("list docs").map_err(SyncError::from)?;
            if held == namespace {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn get_doc(&self, doc_id: &str) -> Result<Doc> {
        self.with_joined(doc_id, |joined| joined.doc.clone()).await
    }

    /// Run `f` on the joined doc `doc_id` names, under the map's lock.
    async fn with_joined<T>(&self, doc_id: &str, f: impl FnOnce(&JoinedDoc) -> T) -> Result<T> {
        let namespace: NamespaceId = doc_id
            .parse()
            .context("parse doc id (NamespaceId)")
            .map_err(SyncError::from)?;
        let map = self.joined.lock().await;
        // The short form: callers log this, and a full namespace id is
        // enough to ask a peer for the doc.
        map.get(&namespace).map(f).ok_or_else(|| {
            SyncError::Generic(format!(
                "doc {} not joined — call join_doc first",
                namespace.fmt_short()
            ))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// N0 brings a pkarr publisher and a DNS lookup; the HTTPS pkarr
    /// lookup must be there too, so a resolver caching a stale negative
    /// answer can't leave a peer unaddressable.
    #[tokio::test]
    async fn endpoint_resolves_peers_over_https_as_well_as_dns() {
        let endpoint = endpoint_builder(SecretKey::generate())
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind");
        assert_eq!(endpoint.address_lookup().expect("open").len(), 3);
        endpoint.close().await;
    }

    const DIALLED: Origin = Origin::Connect(iroh_docs::engine::SyncReason::DirectJoin);

    fn peer() -> PublicKey {
        SecretKey::generate().public()
    }

    #[test]
    fn a_failed_round_we_dialled_owes_the_peer_and_a_success_settles_it() {
        let mut peers = RedialSet::default();
        let p = peer();
        assert!(peers.record_round(p, &DIALLED, false));
        assert!(peers.owed.contains(&p));
        assert!(!peers.record_round(p, &Origin::Accept, true));
        assert!(peers.owed.is_empty());
    }

    #[test]
    fn a_failed_round_the_peer_dialled_owes_nothing() {
        let mut peers = RedialSet::default();
        assert!(!peers.record_round(peer(), &Origin::Accept, false));
        assert!(peers.owed.is_empty());
    }

    #[test]
    fn forgetting_a_peer_settles_its_debt_and_later_failures_owe_nothing() {
        let mut peers = RedialSet::default();
        let gone = peer();
        let other = peer();
        peers.record_round(gone, &DIALLED, false);
        peers.record_round(other, &DIALLED, false);

        peers.forget(gone);
        assert_eq!(peers.owed, HashSet::from([other]));
        assert!(!peers.record_round(gone, &DIALLED, false));
        assert_eq!(peers.owed, HashSet::from([other]));
    }

    #[test]
    fn a_forgotten_peer_that_syncs_again_is_owed_after_its_next_failure() {
        let mut peers = RedialSet::default();
        let p = peer();
        peers.forget(p);
        peers.record_round(p, &Origin::Accept, true);
        assert!(peers.record_round(p, &DIALLED, false));
        assert!(peers.owed.contains(&p));
    }

    async fn bind_test_node() -> (Arc<IrohNode>, tempfile::TempDir, tempfile::TempDir) {
        let blob_dir = tempfile::tempdir().expect("blob tempdir");
        let doc_dir = tempfile::tempdir().expect("doc tempdir");
        let node = bind_node_in(&blob_dir, &doc_dir, Identity::generate(), BLOB_GC_INTERVAL).await;
        (node, blob_dir, doc_dir)
    }

    /// Bind a node on given store directories with the blob sweep on a
    /// given schedule; binding twice on the same directories with the
    /// same identity brings "the same device" back.
    async fn bind_node_in(
        blob_dir: &tempfile::TempDir,
        doc_dir: &tempfile::TempDir,
        identity: Identity,
        gc_interval: Duration,
    ) -> Arc<IrohNode> {
        IrohNode::bind_with_gc_interval(
            NodeConfig {
                identity,
                blob_dir: blob_dir.path().to_string_lossy().into_owned(),
                doc_dir: doc_dir.path().to_string_lossy().into_owned(),
                relay_urls: vec![],
            },
            gc_interval,
        )
        .await
        .expect("bind")
    }

    /// A sweep schedule short enough to watch several sweeps in a test.
    const TEST_GC_INTERVAL: Duration = Duration::from_millis(100);

    /// How long a test waits for a sweep to delete something: many
    /// [`TEST_GC_INTERVAL`]s.
    const SWEEP_WAIT: Duration = Duration::from_secs(10);

    async fn holds_content(node: &IrohNode, hash: &str) -> bool {
        let hash: iroh_blobs::Hash = hash.parse().expect("hash");
        node.blobs_store
            .has(hash)
            .await
            .expect("blob store answers")
    }

    /// Wait up to [`SWEEP_WAIT`] for a sweep to delete `hash`.
    async fn swept(node: &IrohNode, hash: &str) -> bool {
        tokio::time::timeout(SWEEP_WAIT, async {
            while holds_content(node, hash).await {
                tokio::time::sleep(TEST_GC_INTERVAL).await;
            }
        })
        .await
        .is_ok()
    }

    /// Each save replaces the vault's blob; the replaced one is referred
    /// to by nothing and must be swept, or the store grows by a vault
    /// file per save. The current one must survive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_sweep_deletes_replaced_content_and_keeps_the_current() {
        let blob_dir = tempfile::tempdir().expect("blob tempdir");
        let doc_dir = tempfile::tempdir().expect("doc tempdir");
        let node = bind_node_in(&blob_dir, &doc_dir, Identity::generate(), TEST_GC_INTERVAL).await;
        let doc_id = node.create_doc().await.expect("create doc");
        let replaced = node
            .set_entry(doc_id.clone(), b"vault".to_vec(), b"first save".to_vec())
            .await
            .expect("first save");
        let current = node
            .set_entry(doc_id, b"vault".to_vec(), b"second save".to_vec())
            .await
            .expect("second save");

        assert!(
            swept(&node, &replaced).await,
            "the replaced content is swept"
        );
        assert!(
            holds_content(&node, &current).await,
            "the current content stays"
        );
        node.shutdown().await.expect("shutdown");
    }

    /// A doc held in the store but not opened this run (a vault not yet
    /// unlocked, say) still refers to its content, so no sweep may
    /// delete it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_sweep_keeps_content_of_a_doc_not_opened_this_run() {
        let blob_dir = tempfile::tempdir().expect("blob tempdir");
        let doc_dir = tempfile::tempdir().expect("doc tempdir");
        let identity = Identity::generate();
        let node = bind_node_in(&blob_dir, &doc_dir, identity.clone(), BLOB_GC_INTERVAL).await;
        let doc_id = node.create_doc().await.expect("create doc");
        let held = node
            .set_entry(
                doc_id.clone(),
                b"vault".to_vec(),
                b"saved last run".to_vec(),
            )
            .await
            .expect("save");
        node.shutdown().await.expect("shutdown");
        drop(node);

        let node = bind_node_in(&blob_dir, &doc_dir, identity, TEST_GC_INTERVAL).await;
        // A doc opened this run, saved twice, shows the sweeps running.
        let other = node.create_doc().await.expect("create doc");
        let replaced_here = node
            .set_entry(other.clone(), b"vault".to_vec(), b"first save".to_vec())
            .await
            .expect("save");
        node.set_entry(other, b"vault".to_vec(), b"second save".to_vec())
            .await
            .expect("save");
        assert!(swept(&node, &replaced_here).await, "sweeps are running");
        assert!(
            holds_content(&node, &held).await,
            "the unopened doc's content stays"
        );
        assert!(
            node.open_existing_doc(doc_id).await.expect("open"),
            "the doc is still held"
        );
        node.shutdown().await.expect("shutdown");
    }

    /// The hashes this node's own-head tags hold for `doc_id`.
    async fn own_head_hashes(node: &IrohNode, doc_id: &str) -> Vec<String> {
        let namespace: NamespaceId = doc_id.parse().expect("doc id");
        let mut tags = node
            .blobs_store
            .tags()
            .list_prefix(own_head_tag_prefix(namespace))
            .await
            .expect("list tags");
        let mut hashes = Vec::new();
        while let Some(tag) = tags.next().await {
            hashes.push(tag.expect("tag").hash.to_string());
        }
        hashes
    }

    /// A save is held by an own-head tag from the moment it is written,
    /// one tag per key that moves to each new save, and a drop takes the
    /// doc's tags with it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn own_saves_are_held_by_one_tag_per_key_until_the_doc_is_dropped() {
        let (node, _b, _d) = bind_test_node().await;
        let doc_id = node.create_doc().await.expect("create doc");
        node.set_entry(doc_id.clone(), b"vault".to_vec(), b"first save".to_vec())
            .await
            .expect("save");
        let latest = node
            .set_entry(doc_id.clone(), b"vault".to_vec(), b"second save".to_vec())
            .await
            .expect("save");
        assert_eq!(own_head_hashes(&node, &doc_id).await, vec![latest]);

        node.drop_doc(doc_id.clone()).await.expect("drop");
        assert_eq!(own_head_hashes(&node, &doc_id).await, Vec::<String>::new());
        node.shutdown().await.expect("shutdown");
    }

    /// Leaving a doc stops it being joined but keeps it: it resumes, and
    /// a resumed doc can still be dropped, so the leave closed exactly
    /// the handles it held. A second leave is a no-op.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_left_doc_is_kept_resumes_and_can_be_dropped() {
        let (node, _b, _d) = bind_test_node().await;
        let doc_id = node.create_doc().await.expect("create doc");
        let saved = node
            .set_entry(doc_id.clone(), b"vault".to_vec(), b"saved".to_vec())
            .await
            .expect("save");

        node.leave_doc(doc_id.clone()).await.expect("leave");
        assert!(
            node.set_entry(doc_id.clone(), b"vault".to_vec(), b"x".to_vec())
                .await
                .is_err(),
            "a left doc isn't joined"
        );
        node.leave_doc(doc_id.clone())
            .await
            .expect("a second leave is a no-op");
        assert!(holds_content(&node, &saved).await, "the content stays");

        assert!(
            node.open_existing_doc(doc_id.clone())
                .await
                .expect("resume")
        );
        node.drop_doc(doc_id.clone()).await.expect("drop");
        let namespace: NamespaceId = doc_id.parse().expect("doc id");
        assert!(!node.holds_doc(namespace).await.expect("list"));
        node.shutdown().await.expect("shutdown");
    }

    /// A doc joined twice from the same ticket can still be dropped: the
    /// re-join must not leave the first join's handle open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_doc_joined_twice_can_be_dropped() {
        let (publisher, _pb, _pd) = bind_test_node().await;
        let (subscriber, _sb, _sd) = bind_test_node().await;
        let body = async {
            let doc_id = share_one_entry(
                &publisher,
                &subscriber,
                b"vault",
                b"shared vault",
                true,
                DownloadPolicy::Everything,
            )
            .await;
            let ticket = publisher
                .share_doc(doc_id.clone(), true)
                .await
                .expect("share");
            subscriber
                .join_doc(ticket, DownloadPolicy::Everything)
                .await
                .expect("join again");
            subscriber.drop_doc(doc_id.clone()).await.expect("drop");
            let namespace: NamespaceId = doc_id.parse().expect("doc id");
            assert!(!subscriber.holds_doc(namespace).await.expect("list"));
        };
        tokio::time::timeout(Duration::from_secs(90), body)
            .await
            .expect("test finished in time");
        publisher.shutdown().await.expect("shutdown");
        subscriber.shutdown().await.expect("shutdown");
    }

    /// A join that fails (here the only peer is gone) releases what it
    /// opened, so the half-joined doc can still be dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_doc_whose_join_failed_can_be_dropped() {
        let (publisher, _pb, _pd) = bind_test_node().await;
        let (subscriber, _sb, _sd) = bind_test_node().await;
        let doc_id = publisher.create_doc().await.expect("create doc");
        let ticket = publisher
            .share_doc(doc_id.clone(), true)
            .await
            .expect("share");
        publisher.shutdown().await.expect("shutdown");

        let body = async {
            assert!(
                subscriber
                    .join_doc(ticket, DownloadPolicy::Everything)
                    .await
                    .is_err(),
                "the join fails with its only peer gone"
            );
            subscriber.drop_doc(doc_id.clone()).await.expect("drop");
            let namespace: NamespaceId = doc_id.parse().expect("doc id");
            assert!(!subscriber.holds_doc(namespace).await.expect("list"));
        };
        tokio::time::timeout(Duration::from_secs(90), body)
            .await
            .expect("test finished in time");
        subscriber.shutdown().await.expect("shutdown");
    }

    /// Dropping a doc deletes it and, at the next sweep, the content only
    /// it referred to, while another doc's content stays. A second drop
    /// of the same doc is a no-op.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn drop_doc_deletes_the_doc_and_its_content_only() {
        let blob_dir = tempfile::tempdir().expect("blob tempdir");
        let doc_dir = tempfile::tempdir().expect("doc tempdir");
        let node = bind_node_in(&blob_dir, &doc_dir, Identity::generate(), TEST_GC_INTERVAL).await;
        let dropped = node.create_doc().await.expect("create doc");
        let kept = node.create_doc().await.expect("create doc");
        let dropped_content = node
            .set_entry(
                dropped.clone(),
                b"vault".to_vec(),
                b"removed vault".to_vec(),
            )
            .await
            .expect("save");
        let kept_content = node
            .set_entry(kept.clone(), b"vault".to_vec(), b"kept vault".to_vec())
            .await
            .expect("save");

        node.drop_doc(dropped.clone()).await.expect("drop");
        let namespace: NamespaceId = dropped.parse().expect("doc id");
        assert!(
            !node.holds_doc(namespace).await.expect("list"),
            "the dropped doc is gone from the store"
        );
        assert!(swept(&node, &dropped_content).await, "its content is swept");
        assert!(
            holds_content(&node, &kept_content).await,
            "the other doc's content stays"
        );
        node.set_entry(kept, b"vault".to_vec(), b"kept vault, saved again".to_vec())
            .await
            .expect("the other doc still syncs");
        node.drop_doc(dropped)
            .await
            .expect("a second drop is a no-op");
        node.shutdown().await.expect("shutdown");
    }

    /// Join `subscriber` to a doc of `publisher`'s that holds one entry
    /// under `key` naming `payload`'s hash, and wait until the entry has
    /// synced. `with_content` decides whether the publisher holds the
    /// content at sync time.
    async fn share_one_entry(
        publisher: &IrohNode,
        subscriber: &IrohNode,
        key: &[u8],
        payload: &[u8],
        with_content: bool,
        policy: DownloadPolicy,
    ) -> String {
        let hash = iroh_blobs::Hash::new(payload);
        let doc_id = publisher.create_doc().await.expect("create_doc");
        if with_content {
            publisher
                .set_entry(doc_id.clone(), key.to_vec(), payload.to_vec())
                .await
                .expect("set_entry");
        } else {
            let author = publisher.docs.api().author_default().await.expect("author");
            publisher
                .get_doc(&doc_id)
                .await
                .expect("doc")
                .set_hash(author, key.to_vec(), hash, payload.len() as u64)
                .await
                .expect("set_hash");
        }
        let ticket = publisher
            .share_doc(doc_id.clone(), true)
            .await
            .expect("share");
        subscriber.join_doc(ticket, policy).await.expect("join");
        loop {
            let entries = subscriber.list_entries(doc_id.clone()).await.expect("list");
            if entries.iter().any(|e| e.hash_hex == hash.to_string()) {
                return doc_id;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// A blob the doc engine recorded as missing — here because its author
    /// didn't have the content when the entry synced — is never fetched by
    /// the engine afterwards. `fetch_blob` must request it from the doc's
    /// peers itself rather than wait out its deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fetch_requests_a_blob_the_doc_engine_recorded_as_missing() {
        let (publisher, _pb, _pd) = bind_test_node().await;
        let (subscriber, _sb, _sd) = bind_test_node().await;
        let payload = b"content that arrives after its entry".to_vec();
        let hash = iroh_blobs::Hash::new(&payload);

        let body = async {
            let doc_id = share_one_entry(
                &publisher,
                &subscriber,
                b"head",
                &payload,
                false,
                DownloadPolicy::Everything,
            )
            .await;
            // Only now does the publisher hold the content.
            publisher
                .blobs_store
                .add_bytes(payload.clone())
                .await
                .expect("add");
            subscriber
                .fetch_blob_with_deadline(doc_id, hash.to_string(), 0, Duration::from_secs(20))
                .await
        };
        let fetched = tokio::time::timeout(Duration::from_secs(60), body)
            .await
            .expect("test finished in time")
            .expect("fetch requests the blob from the doc's peers");
        assert_eq!(fetched, payload);
        publisher.shutdown().await.expect("shutdown");
        subscriber.shutdown().await.expect("shutdown");
    }

    /// How long a peer gets to pick up a lost blob after a round with a holder
    /// succeeds. Far longer than the transfer takes between local nodes.
    const LOST_BLOB_RECOVERY_WAIT: Duration = Duration::from_secs(30);
    /// How long a round between local nodes may take.
    const LOCAL_ROUND_WAIT: Duration = Duration::from_secs(30);
    /// How long the doc's event stream must stay silent before the rounds of
    /// the subscriber's join count as finished.
    const JOIN_ROUNDS_QUIET: Duration = Duration::from_secs(2);

    /// KNOWN GAP, red today. A successful round with a peer holding a blob the
    /// doc engine lost doesn't recover it: only a caller's `fetch_blob` does,
    /// or a neighbour announcing that it just finished downloading that blob.
    /// So a peer that only fetches and never reads keeps an entry without its
    /// content when the blob's holder comes back already holding it, and can't
    /// pass that content on. A transfer interrupted because its source went
    /// offline ends up here too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "known gap: a successful round doesn't recover a blob the doc engine lost"]
    async fn a_lost_blob_is_fetched_once_a_round_with_its_holder_succeeds() {
        let (publisher, _pb, _pd) = bind_test_node().await;
        let (subscriber, _sb, _sd) = bind_test_node().await;
        let payload = b"content that arrives after its entry".to_vec();
        let hash = iroh_blobs::Hash::new(&payload);

        let doc_id = share_one_entry(
            &publisher,
            &subscriber,
            b"head",
            &payload,
            false,
            DownloadPolicy::Everything,
        )
        .await;
        let mut events = subscriber
            .subscribe_doc_events(&doc_id)
            .await
            .expect("events");
        while tokio::time::timeout(JOIN_ROUNDS_QUIET, events.next())
            .await
            .is_ok()
        {}
        publisher
            .blobs_store
            .add_bytes(payload.clone())
            .await
            .expect("add");

        // A fresh round between them, as when the holder comes back.
        let subscriber_id: PublicKey = subscriber.node_id().parse().expect("node id");
        publisher
            .get_doc(&doc_id)
            .await
            .expect("doc")
            .start_sync(vec![EndpointAddr::new(subscriber_id)])
            .await
            .expect("start_sync");
        tokio::time::timeout(LOCAL_ROUND_WAIT, async {
            while let Some(event) = events.next().await {
                if matches!(
                    event.expect("event"),
                    DocEvent::SyncFinished { error: None, .. }
                ) {
                    return;
                }
            }
            panic!("the event stream ended");
        })
        .await
        .expect("a round with the holder succeeds");
        drop(events);

        let recovered = tokio::time::timeout(LOST_BLOB_RECOVERY_WAIT, async {
            while !matches!(
                subscriber.blobs_store.status(hash).await.expect("status"),
                iroh_blobs::api::blobs::BlobStatus::Complete { .. }
            ) {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .is_ok();
        publisher.shutdown().await.expect("shutdown");
        subscriber.shutdown().await.expect("shutdown");
        assert!(recovered, "the lost blob was never fetched");
    }

    /// The recovery request honours the doc's download policy: content the
    /// policy excludes is never pulled, even though a peer holds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fetch_never_requests_content_the_policy_excludes() {
        let (publisher, _pb, _pd) = bind_test_node().await;
        let (subscriber, _sb, _sd) = bind_test_node().await;
        let payload = b"content outside the subscriber's policy".to_vec();
        let hash = iroh_blobs::Hash::new(&payload);

        let body = async {
            let doc_id = share_one_entry(
                &publisher,
                &subscriber,
                b"excluded",
                &payload,
                true,
                DownloadPolicy::NothingExcept {
                    key_prefixes: vec![b"admitted".to_vec()],
                },
            )
            .await;
            subscriber
                .fetch_blob_with_deadline(
                    doc_id,
                    hash.to_string(),
                    0,
                    MISSING_BLOB_REQUEST_INTERVAL * 3,
                )
                .await
        };
        let fetched = tokio::time::timeout(Duration::from_secs(60), body)
            .await
            .expect("test finished in time");
        assert!(fetched.is_err(), "excluded content must not be fetched");
        let status = subscriber.blobs_store.status(hash).await.expect("status");
        assert!(
            matches!(status, iroh_blobs::api::blobs::BlobStatus::NotFound),
            "excluded content must not reach disk, got {status:?}"
        );
        publisher.shutdown().await.expect("shutdown");
        subscriber.shutdown().await.expect("shutdown");
    }
}
