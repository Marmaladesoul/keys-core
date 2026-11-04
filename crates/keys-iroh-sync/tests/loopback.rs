//! Loopback integration test for keys-iroh-sync.
//!
//! Spins up two nodes in one process (publisher + subscriber), the
//! publisher creates a doc, writes an entry with a payload, mints a
//! ticket, and the subscriber joins, lists entries, fetches the blob.
//!
//! This is the production-equivalent of the spike's `subscribe`
//! binary, run end-to-end inside `cargo test` so CI keeps it from
//! regressing.
//!
//! Notes on environment:
//!
//! - Both nodes go through N0's public DERP. CI Linux runners have
//!   outbound TCP/443 so this works there. Local laptop runs work
//!   too. Sandboxed environments without internet access will skip
//!   this test (see the `is_network_test_skipped` helper).
//!
//! - We bind to fresh tempdirs and brand-new identities every run —
//!   no persistent state survives. The library being persistent is
//!   exercised by the bind path itself loading an empty store cleanly.

use futures_util::StreamExt;
use iroh::{
    Endpoint,
    endpoint::{Connection, presets},
    protocol::Router,
};
use iroh_blobs::{
    BlobsProtocol, Hash,
    api::blobs::BlobStatus,
    get::request::get_blob,
    protocol::{ChunkRangesSeq, PushRequest},
    provider::events::{EventMask, EventSender, RequestMode},
    store::mem::MemStore,
};
use iroh_docs::DocTicket;
use keys_ffi::{
    Engine, IconRef, NewEntryFields, Page, ParkConflictsResultFfi, VaultDbKeyProvider,
    VaultDbKeyProviderError, VaultFieldProtector, VaultProtectorError, create_vault,
};
use keys_iroh_sync::{DocEvent, DownloadPolicy, Identity, IrohNode, NodeConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

/// Returns `true` when the test should be skipped — typically because
/// the runner has no outbound internet (e.g. some sandboxed CI shapes).
/// Honours `KEYS_IROH_SYNC_SKIP_NETWORK_TESTS=1` as an explicit override.
fn is_network_test_skipped() -> bool {
    std::env::var("KEYS_IROH_SYNC_SKIP_NETWORK_TESTS")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Install the test log subscriber. Idempotent, and every test calls it —
/// tests share a process, so relying on whichever ran first to install it
/// leaves a test run alone (`--exact`) with no diagnostics for a hang.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

async fn spin_up_node() -> (std::sync::Arc<IrohNode>, TempDir, TempDir) {
    let blob_dir = tempfile::tempdir().expect("blob tempdir");
    let doc_dir = tempfile::tempdir().expect("doc tempdir");
    let config = NodeConfig {
        identity: Identity::generate(),
        blob_dir: blob_dir.path().to_string_lossy().into_owned(),
        doc_dir: doc_dir.path().to_string_lossy().into_owned(),
        relay_urls: vec![],
    };
    let node = IrohNode::bind(config).await.expect("bind");
    (node, blob_dir, doc_dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publisher_subscriber_loopback() {
    if is_network_test_skipped() {
        eprintln!("skipping: KEYS_IROH_SYNC_SKIP_NETWORK_TESTS set");
        return;
    }

    init_tracing();

    // Cap the whole test at 90 s. The slow leg is DERP registration on
    // cold runners (~10-20 s). Anything beyond 90 s is a real hang.
    let body = async {
        let (publisher, _pb, _pd) = spin_up_node().await;
        let (subscriber, _sb, _sd) = spin_up_node().await;

        eprintln!("publisher node_id  = {}", publisher.node_id());
        eprintln!("subscriber node_id = {}", subscriber.node_id());

        // Publisher: create doc, write one entry.
        let doc_id = publisher.create_doc().await.expect("create_doc");
        let payload = b"hello from the publisher".to_vec();
        let hash = publisher
            .set_entry(doc_id.clone(), b"greeting".to_vec(), payload.clone())
            .await
            .expect("set_entry");

        // Mint a read-write ticket and hand it to the subscriber.
        let ticket = publisher
            .share_doc(doc_id.clone(), true)
            .await
            .expect("share_doc");

        let sub_doc_id = subscriber
            .join_doc(ticket, DownloadPolicy::Everything)
            .await
            .expect("join_doc");
        assert_eq!(
            sub_doc_id, doc_id,
            "subscriber's view of the doc id should match the publisher's"
        );

        // Entry log should reflect the one entry we wrote.
        let entries = subscriber
            .list_entries(sub_doc_id.clone())
            .await
            .expect("list_entries");
        assert_eq!(entries.len(), 1, "expected exactly one entry");
        assert_eq!(entries[0].key, b"greeting");
        assert_eq!(entries[0].hash_hex, hash);
        assert_eq!(entries[0].size_bytes, payload.len() as u64);

        // Fetch the blob over the wire. Cap at 1 MiB — well above
        // the test payload, well below "OOM the runner".
        let fetched = subscriber
            .fetch_blob(sub_doc_id, hash, 1024 * 1024)
            .await
            .expect("fetch_blob");
        assert_eq!(fetched, payload);

        // Graceful shutdown — exercises the production path. iOS
        // would be the strict caller here; on Linux/macOS this just
        // proves the await terminates.
        publisher.shutdown().await.expect("publisher shutdown");
        subscriber.shutdown().await.expect("subscriber shutdown");
    };

    tokio::time::timeout(Duration::from_secs(90), body)
        .await
        .expect("loopback test exceeded 90s — likely a hang, not a slow DERP");
}

/// `fetch_blob` on content that does not exist yet at call time.
///
/// The test above fetches an entry the subscriber already synced during
/// `join_doc`, so its blob is typically complete before `fetch_blob` is
/// even called — it proves the read path, not the wait. Here the
/// publisher writes the entry *after* the subscriber has joined, and
/// the subscriber asks for the hash immediately, before the entry has
/// reached it. In practice the first status read misses (propagation
/// costs a network round-trip), so the fetch returns only by waiting
/// for the doc to sync the entry in, queue the download, and signal
/// completion. The wait is exercised rather than strictly asserted:
/// there is no non-racy witness that the first read missed, so on an
/// improbably fast path this would degrade to the already-complete
/// read path that `publisher_subscriber_loopback` covers — acceptable,
/// since the two together still pin both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_blob_waits_for_content_written_after_join() {
    if is_network_test_skipped() {
        eprintln!("skipping: KEYS_IROH_SYNC_SKIP_NETWORK_TESTS set");
        return;
    }

    init_tracing();

    let body = async {
        let (publisher, _pb, _pd) = spin_up_node().await;
        let (subscriber, _sb, _sd) = spin_up_node().await;

        // Subscriber joins while the doc is still empty, so nothing
        // has been offered to it yet.
        let doc_id = publisher.create_doc().await.expect("create_doc");
        let ticket = publisher
            .share_doc(doc_id.clone(), true)
            .await
            .expect("share_doc");
        let sub_doc_id = subscriber
            .join_doc(ticket, DownloadPolicy::Everything)
            .await
            .expect("join_doc");
        assert!(
            subscriber
                .list_entries(sub_doc_id.clone())
                .await
                .expect("list_entries")
                .is_empty(),
            "doc should still be empty at join time"
        );

        // Only now does the content come into existence. The
        // subscriber learns the hash out-of-band (the test plays the
        // role of an upper layer that already knows what it wants),
        // so it can ask for the blob before the entry syncs to it.
        let payload = b"content that did not exist when the subscriber joined".to_vec();
        let hash = publisher
            .set_entry(doc_id.clone(), b"late-arrival".to_vec(), payload.clone())
            .await
            .expect("set_entry");

        let fetched = subscriber
            .fetch_blob(sub_doc_id, hash, 1024 * 1024)
            .await
            .expect("fetch_blob should wait for the late-written content");
        assert_eq!(fetched, payload);

        publisher.shutdown().await.expect("publisher shutdown");
        subscriber.shutdown().await.expect("subscriber shutdown");
    };

    tokio::time::timeout(Duration::from_secs(90), body)
        .await
        .expect("late-arrival fetch exceeded 90s — likely a hang, not a slow DERP");
}

/// `max_size_bytes` refuses an over-cap blob rather than reading it in.
///
/// This is the crate's only defence against a publisher that ships more
/// than the receiver agreed to hold in memory, so it gets a test that
/// pins it. One node, no peer and no network: the blob is written
/// locally, so it is already `Complete` when `fetch_blob` first reads
/// status and the cap decision is reached with no waiting and no race.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_blob_rejects_blob_over_max_size() {
    init_tracing();

    let (node, _b, _d) = spin_up_node().await;
    let doc_id = node.create_doc().await.expect("create_doc");
    let payload = vec![b'x'; 4096];
    let hash = node
        .set_entry(doc_id.clone(), b"oversized".to_vec(), payload.clone())
        .await
        .expect("set_entry");

    let err = node
        .fetch_blob(doc_id.clone(), hash.clone(), 1024)
        .await
        .expect_err("a 4096-byte blob must not be returned under a 1024-byte cap");
    // A locally-written blob is `Complete` the moment `set_entry`
    // returns, so this must be the post-completion branch specifically —
    // "completed at N bytes" — not the partial-size early reject. Assert
    // on that phrase so a regression that rerouted through the Partial
    // branch would be caught, not silently accepted.
    let msg = err.to_string();
    assert!(
        msg.contains("completed at") && msg.contains("exceeds max_size_bytes"),
        "expected the Complete-branch size-cap rejection, got: {msg}"
    );

    // `0` means "no cap" — the same blob comes back whole. This pins the
    // sentinel too, so a future tightening can't silently turn 0 into
    // "reject everything".
    let fetched = node
        .fetch_blob(doc_id, hash, 0)
        .await
        .expect("max_size_bytes = 0 means no cap");
    assert_eq!(fetched, payload);

    node.shutdown().await.expect("shutdown");
}

/// The caller-supplied deadline actually bounds the wait: a fetch for a
/// hash that never arrives fails with the "did not complete" error
/// inside our tiny deadline, not the 60s default. One node, no peer, so
/// nothing will ever queue the download — the only way out is the
/// deadline elapsing.
///
/// This is the branch a compile-time `const` deadline left untestable:
/// asserting it meant a 60s wall-clock wait. With the deadline
/// injectable it is deterministic and sub-second. No network — the store
/// simply never holds this hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_blob_with_deadline_times_out_on_missing_content() {
    init_tracing();

    let (node, _b, _d) = spin_up_node().await;
    let doc_id = node.create_doc().await.expect("create_doc");

    // A valid hash for content no node holds or will ever offer.
    let never_hash = iroh_blobs::Hash::new(b"content that never arrives").to_string();

    let deadline = Duration::from_millis(200);
    let started = tokio::time::Instant::now();
    let err = node
        .fetch_blob_with_deadline(doc_id, never_hash, 0, deadline)
        .await
        .expect_err("a hash that never arrives must time out, not resolve");
    let waited = started.elapsed();

    assert!(
        err.to_string().contains("did not complete within"),
        "expected the deadline-timeout error, got: {err}"
    );
    // The point of the injectable deadline: the wait is bounded by *our*
    // 200 ms, nowhere near the 60 s const. A generous ceiling keeps this
    // non-flaky on a loaded runner while still proving it isn't the const
    // path — which would sit here for a full minute.
    assert!(
        waited < Duration::from_secs(10),
        "fetch should return near the 200ms deadline, waited {waited:?}"
    );

    node.shutdown().await.expect("shutdown");
}

/// Shutting the node down mid-fetch ends the doc event stream, and the
/// parked `fetch_blob_with_deadline` fails fast on that rather than
/// idling to its deadline. This is the `Ok(None)` fast-fail branch:
/// reachable in practice only by racing shutdown against an in-flight
/// fetch, so the deadline is set long (30 s) to guarantee the
/// stream-ended branch is what returns — a deadline-timeout here would
/// be a test bug, not the path under test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_blob_fails_when_event_stream_ends_on_shutdown() {
    init_tracing();

    let (node, _b, _d) = spin_up_node().await;
    let doc_id = node.create_doc().await.expect("create_doc");
    let never_hash = iroh_blobs::Hash::new(b"awaited but never delivered").to_string();

    // Park the fetch on a hash that will never arrive. Long deadline and
    // `0` size cap so it genuinely waits — the only exits are the
    // 30 s deadline (which we won't reach) or the event stream ending.
    let fetch_node = node.clone();
    let fetch = tokio::spawn(async move {
        fetch_node
            .fetch_blob_with_deadline(doc_id, never_hash, 0, Duration::from_secs(30))
            .await
    });

    // Let the fetch subscribe and settle onto the event stream before we
    // pull the node out from under it.
    tokio::time::sleep(Duration::from_millis(300)).await;

    node.shutdown().await.expect("shutdown");

    let result = tokio::time::timeout(Duration::from_secs(10), fetch)
        .await
        .expect("fetch should return promptly once its stream ends, not hang")
        .expect("fetch task panicked");

    let err = result.expect_err("fetch must fail once its event stream ends");
    assert!(
        err.to_string().contains("event stream ended"),
        "expected the stream-ended error, got: {err}"
    );
}

/// How long the push-accepting control node gets to receive the pushed
/// blob. Generous for a few bytes between endpoints on one machine; if
/// it is ever exceeded the test fails loudly rather than mistaking a
/// slow push for a refused one.
const PUSH_LANDING_WINDOW: Duration = Duration::from_secs(10);

/// How often to re-read the control node's store while waiting.
const PUSH_LANDING_POLL: Duration = Duration::from_millis(50);

/// Push `hash` from `store` over `conn`. The pusher never learns whether
/// the receiver accepted, so the result says nothing and is dropped; the
/// receiving store is the only witness.
async fn push_blob(store: &MemStore, conn: &Connection, hash: Hash) {
    let _ = store
        .remote()
        .execute_push(conn.clone(), PushRequest::new(hash, ChunkRangesSeq::root()))
        .await;
}

/// A bare iroh-blobs node that *accepts* inbound pushes — the control
/// that proves a push actually works, so its absence on our node means
/// refusal.
async fn spawn_push_accepting_control() -> (Router, MemStore) {
    let store = MemStore::new();
    let endpoint = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("bind control");
    endpoint.online().await;
    let accepts_push = EventMask {
        push: RequestMode::None,
        ..EventMask::DEFAULT
    };
    let router = Router::builder(endpoint)
        .accept(
            iroh_blobs::ALPN,
            BlobsProtocol::new(&store, Some(EventSender::DEFAULT.tracing(accepts_push))),
        )
        .spawn();
    (router, store)
}

/// Wait until `store` holds `hash` in full, failing after
/// [`PUSH_LANDING_WINDOW`].
async fn wait_for_landed(store: &MemStore, hash: Hash) {
    let deadline = tokio::time::Instant::now() + PUSH_LANDING_WINDOW;
    loop {
        let status = store.blobs().status(hash).await.expect("blob status");
        if matches!(status, BlobStatus::Complete { .. }) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "push never landed on the push-accepting control within \
             {PUSH_LANDING_WINDOW:?} (status={status:?}) — the test can't \
             tell a refused push from one that never arrived"
        );
        tokio::time::sleep(PUSH_LANDING_POLL).await;
    }
}

/// The node's blobs protocol serves reads to a dialling peer but refuses
/// that peer's unsolicited push: the pushed blob never reaches the
/// node's store. The peer is a bare endpoint speaking only the blobs
/// ALPN — no doc membership — which is exactly the position of anyone
/// who has learned the node's address.
///
/// The pushing side gets no verdict back, so the test carries two
/// controls that keep it from passing vacuously:
///
/// - a fetch over the same connection proves the peer reached the
///   node's blobs handler at all;
/// - the same push, sent to a bare iroh-blobs node that *accepts*
///   pushes, must land there — so the push itself demonstrably works,
///   and by the time it has landed on the control, the node's earlier
///   copy has had at least as long.
///
/// Doc-driven fetches between two nodes (both running the same mask) are
/// covered by `publisher_subscriber_loopback`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_protocol_serves_fetch_but_refuses_push() {
    if is_network_test_skipped() {
        eprintln!("skipping: KEYS_IROH_SYNC_SKIP_NETWORK_TESTS set");
        return;
    }

    init_tracing();

    let body = async {
        let (node, _b, _d) = spin_up_node().await;
        let doc_id = node.create_doc().await.expect("create_doc");
        let served = b"content the node chose to hold".to_vec();
        let served_hash: Hash = node
            .set_entry(doc_id.clone(), b"served".to_vec(), served.clone())
            .await
            .expect("set_entry")
            .parse()
            .expect("parse served hash");
        // The ticket is just a convenient carrier for the node's dialable
        // address; the peer never joins the doc.
        let ticket: DocTicket = node
            .share_doc(doc_id.clone(), false)
            .await
            .expect("share_doc")
            .parse()
            .expect("parse ticket");
        let node_addr = ticket
            .nodes
            .into_iter()
            .next()
            .expect("ticket carries the node's address");
        let (control, control_store) = spawn_push_accepting_control().await;

        let peer_store = MemStore::new();
        let planted_hash = peer_store
            .add_bytes(b"content the node never asked for".to_vec())
            .await
            .expect("add planted blob to peer store")
            .hash;
        let peer = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("bind peer");
        let node_conn = peer
            .connect(node_addr, iroh_blobs::ALPN)
            .await
            .expect("peer connects to node's blobs protocol");
        let control_conn = peer
            .connect(control.endpoint().addr(), iroh_blobs::ALPN)
            .await
            .expect("peer connects to control's blobs protocol");

        let fetched = get_blob(node_conn.clone(), served_hash)
            .bytes()
            .await
            .expect("node serves a blob it holds");
        assert_eq!(fetched.as_ref(), served.as_slice());

        // Node first, control second: once the control holds the blob,
        // the node's copy has had at least as long to land.
        push_blob(&peer_store, &node_conn, planted_hash).await;
        push_blob(&peer_store, &control_conn, planted_hash).await;
        wait_for_landed(&control_store, planted_hash).await;

        // A zero deadline reads the node's store exactly once.
        let err = node
            .fetch_blob_with_deadline(doc_id, planted_hash.to_string(), 0, Duration::ZERO)
            .await
            .expect_err("a pushed blob must never land in the node's store");
        assert!(
            err.to_string().contains("status=NotFound"),
            "pushed blob left a trace in the node's store: {err}"
        );

        drop(node_conn);
        drop(control_conn);
        peer.close().await;
        control.shutdown().await.expect("control shutdown");
        node.shutdown().await.expect("shutdown");
    };

    tokio::time::timeout(Duration::from_secs(90), body)
        .await
        .expect("push-refusal test exceeded 90s");
}

/// How long a sync event stream must stay silent before the join's own
/// rounds count as finished.
const QUIET_PERIOD: Duration = Duration::from_secs(2);
/// How long a write may take to produce its sync round, and to reach the
/// peer.
const DELIVERY_WAIT: Duration = Duration::from_secs(30);

/// Every write runs a direct sync round with the doc's known peers, so it
/// is delivered whatever state the live gossip mesh is in. In the field
/// the mesh drops an idle connection (both sides see `NeighborDown` and
/// nothing re-dials), and a write that rode only the mesh stayed local
/// until a manual reconnect. That drop doesn't happen between two local
/// nodes, so this pins the recovery mechanism itself: once the join's own
/// rounds have quiesced, a write must produce a fresh successful sync
/// round on the writer, which a mesh-only write never does. The closing
/// delivery check is a sanity check only (between connected local nodes
/// the mesh would deliver the entry too).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_runs_a_sync_round_with_known_peers() {
    if is_network_test_skipped() {
        eprintln!("skipping: KEYS_IROH_SYNC_SKIP_NETWORK_TESTS set");
        return;
    }
    init_tracing();

    let body = async {
        let (writer, _wb, _wd) = spin_up_node().await;
        let (reader, _rb, _rd) = spin_up_node().await;
        let doc_id = writer.create_doc().await.expect("create_doc");
        writer
            .set_entry(doc_id.clone(), b"before".to_vec(), b"1".to_vec())
            .await
            .expect("first write");
        let mut events = writer.subscribe_doc_events(&doc_id).await.expect("events");
        let ticket = writer.share_doc(doc_id.clone(), true).await.expect("share");
        reader
            .join_doc(ticket, DownloadPolicy::Everything)
            .await
            .expect("join");

        // Let the join's rounds finish: the reader holds the first entry,
        // then the writer's event stream goes quiet.
        while !reader
            .list_entries(doc_id.clone())
            .await
            .expect("list")
            .iter()
            .any(|e| e.key == b"before")
        {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        while tokio::time::timeout(QUIET_PERIOD, events.next())
            .await
            .is_ok()
        {}

        writer
            .set_entry(doc_id.clone(), b"after".to_vec(), b"2".to_vec())
            .await
            .expect("second write");
        tokio::time::timeout(DELIVERY_WAIT, async {
            while let Some(event) = events.next().await {
                if matches!(
                    event.expect("event"),
                    DocEvent::SyncFinished { error: None, .. }
                ) {
                    return;
                }
            }
        })
        .await
        .expect("the write ran no sync round with the known peer");

        tokio::time::timeout(DELIVERY_WAIT, async {
            while !reader
                .list_entries(doc_id.clone())
                .await
                .expect("list")
                .iter()
                .any(|e| e.key == b"after")
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .expect("the write never reached the known peer");

        writer.shutdown().await.expect("writer shutdown");
        reader.shutdown().await.expect("reader shutdown");
    };

    tokio::time::timeout(Duration::from_secs(120), body)
        .await
        .expect("test exceeded 120s — likely a hang, not a slow DERP");
}

/// Bind a node with a given identity on given store directories, so a
/// test can bring "the same device" back after shutting it down.
async fn bind_node_at(
    identity: Identity,
    blob_dir: &std::path::Path,
    doc_dir: &std::path::Path,
) -> std::sync::Arc<IrohNode> {
    IrohNode::bind(NodeConfig {
        identity,
        blob_dir: blob_dir.to_string_lossy().into_owned(),
        doc_dir: doc_dir.to_string_lossy().into_owned(),
        relay_urls: vec![],
    })
    .await
    .expect("bind")
}

/// Copy a (shut-down) node's store directory, so several later nodes can
/// each start from the same on-disk state.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("create copy dir");
    for entry in std::fs::read_dir(from).expect("read store dir") {
        let entry = entry.expect("store dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy store file");
        }
    }
}

/// How long the writer's round with an absent peer may take to fail.
const ABSENT_PEER_FAILURE_WAIT: Duration = Duration::from_secs(90);
/// How long a returning peer may wait for a write it missed. Spans the
/// node's first re-dial delays (5 s, then 15 s after a re-dial that still
/// fails) with headroom, so the write must arrive on the short end of the
/// schedule, not the steady state.
const REDIAL_DELIVERY_WAIT: Duration = Duration::from_secs(120);

/// A writer whose write failed to reach its reader, which has since gone
/// away: the reader created the doc, the writer joined it, then the reader
/// shut down and the writer wrote.
///
/// [`Self::bring_back`] returns the reader holding the doc but with no
/// record of the writer: its doc store is a copy taken before it ever
/// synced with the writer, which leaves it no known peers to dial. So the
/// returning reader cannot heal the gap itself — only a dial from the
/// writer can deliver the write.
struct AbsentReader {
    writer: std::sync::Arc<IrohNode>,
    doc_id: String,
    reader_identity: Identity,
    reader_node_id: String,
    /// The reader's doc store from before it synced with the writer.
    pristine_docs: TempDir,
    /// The failed round's peer and reason.
    failed_round: (String, String),
    /// Store directories that must outlive the nodes using them.
    stores: Vec<TempDir>,
}

/// The key of the write made while the reader is away.
const WHILE_AWAY: &[u8] = b"while-away";

impl AbsentReader {
    async fn new() -> Self {
        // The reader creates the doc, then stops. Its store at this point
        // holds the doc and no peers; each later reader starts from a copy.
        let reader_identity = Identity::generate();
        let first_blobs = tempfile::tempdir().expect("blob tempdir");
        let first_docs = tempfile::tempdir().expect("doc tempdir");
        let reader = bind_node_at(
            reader_identity.clone(),
            first_blobs.path(),
            first_docs.path(),
        )
        .await;
        let reader_node_id = reader.node_id();
        let doc_id = reader.create_doc().await.expect("create_doc");
        reader.shutdown().await.expect("reader shutdown");
        drop(reader);
        let before_writer = tempfile::tempdir().expect("snapshot tempdir");
        let pristine_docs = tempfile::tempdir().expect("snapshot tempdir");
        copy_dir(first_docs.path(), before_writer.path());
        copy_dir(first_docs.path(), pristine_docs.path());

        // The writer joins while the reader is up, so the reader becomes
        // one of the writer's known peers for the doc.
        let reader_blobs = tempfile::tempdir().expect("blob tempdir");
        let reader = bind_node_at(
            reader_identity.clone(),
            reader_blobs.path(),
            before_writer.path(),
        )
        .await;
        assert!(
            reader
                .open_existing_doc(doc_id.clone())
                .await
                .expect("open"),
            "the reader's store holds the doc"
        );
        let ticket = reader.share_doc(doc_id.clone(), true).await.expect("share");
        let (writer, writer_blobs, writer_docs) = spin_up_node().await;
        writer
            .join_doc(ticket, DownloadPolicy::Everything)
            .await
            .expect("join");
        let mut events = writer.subscribe_doc_events(&doc_id).await.expect("events");

        // The reader goes away; the writer writes, and its round with the
        // reader fails.
        reader.shutdown().await.expect("reader shutdown");
        drop(reader);
        writer
            .set_entry(doc_id.clone(), WHILE_AWAY.to_vec(), b"1".to_vec())
            .await
            .expect("write while the reader is away");
        let failed_round = tokio::time::timeout(ABSENT_PEER_FAILURE_WAIT, async {
            while let Some(event) = events.next().await {
                if let DocEvent::SyncFinished {
                    peer_node_id,
                    error: Some(reason),
                } = event.expect("event")
                {
                    return (peer_node_id, reason);
                }
            }
            panic!("the writer's event stream ended");
        })
        .await
        .expect("the writer's round with the absent reader never failed");

        Self {
            writer,
            doc_id,
            reader_identity,
            reader_node_id,
            pristine_docs,
            failed_round,
            stores: vec![
                first_blobs,
                first_docs,
                before_writer,
                reader_blobs,
                writer_blobs,
                writer_docs,
            ],
        }
    }

    /// Bring the reader back, holding the doc but knowing no peers, and
    /// with nothing to write. Callable once.
    async fn bring_back(&mut self) -> std::sync::Arc<IrohNode> {
        let blobs = tempfile::tempdir().expect("blob tempdir");
        let reader = bind_node_at(
            self.reader_identity.clone(),
            blobs.path(),
            self.pristine_docs.path(),
        )
        .await;
        self.stores.push(blobs);
        assert!(
            reader
                .open_existing_doc(self.doc_id.clone())
                .await
                .expect("open"),
            "the returning reader's store holds the doc"
        );
        reader
    }
}

/// Whether `node` holds an entry under `key` in `doc_id`.
async fn holds_entry(node: &IrohNode, doc_id: &str, key: &[u8]) -> bool {
    node.list_entries(doc_id.to_owned())
        .await
        .expect("list")
        .iter()
        .any(|e| e.key == key)
}

/// Wait up to `wait` for `node` to hold every key in `keys` in `doc_id`.
async fn wait_for_entries(node: &IrohNode, doc_id: &str, keys: &[&[u8]], wait: Duration) -> bool {
    tokio::time::timeout(wait, async {
        loop {
            let entries = node.list_entries(doc_id.to_owned()).await.expect("list");
            if keys.iter().all(|key| entries.iter().any(|e| e.key == *key)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .is_ok()
}

/// A write made while its peer is unreachable reaches the peer once it is
/// back, with no further write and no restart on the writer: the writer
/// keeps re-dialling a peer it owes a sync round on a backoff schedule.
/// The failed round names the peer and says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_made_while_the_peer_is_away_reaches_it_once_back() {
    if is_network_test_skipped() {
        eprintln!("skipping: KEYS_IROH_SYNC_SKIP_NETWORK_TESTS set");
        return;
    }
    init_tracing();

    let body = async {
        let mut away = AbsentReader::new().await;
        let (peer, reason) = &away.failed_round;
        assert_eq!(
            peer, &away.reader_node_id,
            "the round failed with the reader"
        );
        assert!(!reason.is_empty(), "a failed round says why");
        assert!(
            !reason.contains(&away.reader_node_id) && !reason.contains(&away.doc_id),
            "the reason carries no full ids: {reason}"
        );

        let reader = away.bring_back().await;
        assert!(
            wait_for_entries(&reader, &away.doc_id, &[WHILE_AWAY], REDIAL_DELIVERY_WAIT).await,
            "the write never reached the returning reader"
        );

        away.writer.shutdown().await.expect("writer shutdown");
        reader.shutdown().await.expect("reader shutdown");
    };

    tokio::time::timeout(Duration::from_secs(300), body)
        .await
        .expect("test exceeded 300s — likely a hang, not a slow DERP");
}

/// How long a forgotten peer is left waiting for a write it missed. Spans
/// the node's first two re-dial delays (`REDIAL_BACKOFF` in `src/node.rs`:
/// 5 s, then 15 s) with headroom, so a re-dial would have reached the peer
/// well inside it. Retune this with that schedule.
const FORGOTTEN_PEER_WAIT: Duration = Duration::from_secs(45);

/// A peer the writer has forgotten is not re-dialled after a failed round,
/// so a write made while it was away stays undelivered until another
/// write dials it. The closing write proves the reader was reachable all
/// along, so the wait wasn't vacuous: a write still dials the doc's known
/// peers, forgotten or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forgotten_peer_is_not_redialled() {
    if is_network_test_skipped() {
        eprintln!("skipping: KEYS_IROH_SYNC_SKIP_NETWORK_TESTS set");
        return;
    }
    init_tracing();

    let body = async {
        let mut away = AbsentReader::new().await;
        away.writer
            .forget_peer(away.doc_id.clone(), away.reader_node_id.clone())
            .await
            .expect("forget the reader");

        let reader = away.bring_back().await;
        tokio::time::sleep(FORGOTTEN_PEER_WAIT).await;
        assert!(
            !holds_entry(&reader, &away.doc_id, WHILE_AWAY).await,
            "the writer re-dialled the peer it forgot"
        );

        let once_back: &[u8] = b"once-back";
        away.writer
            .set_entry(away.doc_id.clone(), once_back.to_vec(), b"2".to_vec())
            .await
            .expect("write once the reader is back");
        assert!(
            wait_for_entries(
                &reader,
                &away.doc_id,
                &[WHILE_AWAY, once_back],
                REDIAL_DELIVERY_WAIT
            )
            .await,
            "a write never reached the forgotten but reachable reader"
        );

        away.writer.shutdown().await.expect("writer shutdown");
        reader.shutdown().await.expect("reader shutdown");
    };

    // Its waits alone can reach 255 s (failure, forgotten wait, delivery).
    tokio::time::timeout(Duration::from_secs(360), body)
        .await
        .expect("test exceeded 360s — likely a hang, not a slow DERP");
}

// Store-and-forward: a peer that fetches what a doc names but never merges
// or publishes (a client whose vault is locked behaves this way) still
// carries heads between peers that are never online together.

/// The key each device publishes its whole-vault blob under.
fn vault_key(device: &str) -> Vec<u8> {
    format!("v1/vault/{device}").into_bytes()
}

/// How long a peer may take to deliver a head. Spans a first dial through a
/// relay and the blob transfer behind it.
const HEAD_DELIVERY_WAIT: Duration = Duration::from_secs(60);
/// How long two peers sharing a doc may take to meet over its gossip mesh.
const MESH_MEETING_WAIT: Duration = Duration::from_secs(60);
const HEAD_POLL: Duration = Duration::from_millis(250);
/// Larger than any vault these tests write.
const MAX_HEAD_BYTES: u64 = 16 * 1024 * 1024;
/// Caps a whole store-and-forward test. Its waits alone can reach 360 s,
/// though a healthy run takes far less.
const STORE_AND_FORWARD_TEST_CAP: Duration = Duration::from_secs(600);
/// More entries than any vault these tests write.
const ENTRY_PAGE_LIMIT: u64 = 100;

/// A device's on-disk transport state, which outlives any one run of its node.
struct Device {
    identity: Identity,
    blobs: TempDir,
    docs: TempDir,
}

impl Device {
    fn new() -> Self {
        Self {
            identity: Identity::generate(),
            blobs: tempfile::tempdir().expect("blob tempdir"),
            docs: tempfile::tempdir().expect("doc tempdir"),
        }
    }

    async fn start(&self) -> Arc<IrohNode> {
        bind_node_at(self.identity.clone(), self.blobs.path(), self.docs.path()).await
    }

    /// Run the node again after a shutdown and resume `doc_id`. It dials
    /// only the peers the doc store remembers.
    async fn resume(&self, doc_id: &str) -> Arc<IrohNode> {
        let node = self.start().await;
        assert!(
            node.open_existing_doc(doc_id.to_owned())
                .await
                .expect("open"),
            "the device's store holds the doc"
        );
        node
    }
}

/// Whether `node`'s store already holds `hash` in full. Looks only at the
/// local store and requests nothing, so it can't help the content along.
async fn holds_blob(node: &IrohNode, doc_id: &str, hash: &str) -> bool {
    match node
        .fetch_blob_with_deadline(doc_id.to_owned(), hash.to_owned(), 0, Duration::ZERO)
        .await
    {
        Ok(_) => true,
        Err(e) if e.to_string().contains("did not complete within") => false,
        Err(e) => panic!("reading the local store failed: {e}"),
    }
}

/// Wait for `node` to hold `key` at `hash` with its content, left entirely to
/// the transport: nothing here asks for the blob.
async fn wait_for_head(node: &IrohNode, doc_id: &str, key: &[u8], hash: &str) -> bool {
    tokio::time::timeout(HEAD_DELIVERY_WAIT, async {
        loop {
            let entries = node.list_entries(doc_id.to_owned()).await.expect("list");
            if entries.iter().any(|e| e.key == key && e.hash_hex == hash)
                && holds_blob(node, doc_id, hash).await
            {
                return;
            }
            tokio::time::sleep(HEAD_POLL).await;
        }
    })
    .await
    .is_ok()
}

/// Assert the transport alone delivers `head` to `node` under `key`, byte for
/// byte, by way of `route`.
async fn assert_head_arrives(
    node: &IrohNode,
    doc_id: &str,
    key: &[u8],
    (hash, head): (&str, &[u8]),
    route: &str,
) {
    assert!(
        wait_for_head(node, doc_id, key, hash).await,
        "the head never arrived through {route}"
    );
    let delivered = node
        .fetch_blob(doc_id.to_owned(), hash.to_owned(), MAX_HEAD_BYTES)
        .await
        .expect("read head");
    assert_eq!(delivered, head, "a different head arrived through {route}");
}

const VAULT_PASSWORD: &str = "test-password";
const DB_KEY: [u8; 32] = [0x42; 32];
const SESSION_KEY: [u8; 32] = [0x9c; 32];

struct FixedDbKey;
impl VaultDbKeyProvider for FixedDbKey {
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
        Ok(DB_KEY.to_vec())
    }
    fn delete_db_key(&self) -> Result<(), VaultDbKeyProviderError> {
        Ok(())
    }
}

struct FixedProtector;
impl VaultFieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
        Ok(SESSION_KEY.to_vec())
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Write a new, empty vault to `path`.
async fn new_vault_file(path: &Path) {
    create_vault(
        path_string(path),
        VAULT_PASSWORD.to_owned(),
        None,
        "store and forward".to_owned(),
        Some(Arc::new(FixedProtector)),
        None,
    )
    .await
    .expect("create_vault");
}

/// A device's replica of the vault: its file, and an engine bound to it.
struct Replica {
    dir: TempDir,
    kdbx: PathBuf,
    engine: Arc<Engine>,
}

impl Replica {
    /// A replica starting from a copy of the vault file at `vault`.
    async fn of(vault: &Path) -> Self {
        let dir = tempfile::tempdir().expect("replica tempdir");
        let kdbx = dir.path().join("vault.kdbx");
        std::fs::copy(vault, &kdbx).expect("copy vault");
        let engine = engine_over_file(&kdbx, &dir.path().join("mirror.db")).await;
        Self { dir, kdbx, engine }
    }

    /// Add an entry and save it to the file, returning the file's new bytes:
    /// what the device publishes as its head.
    async fn add_entry(&self, title: &str) -> Vec<u8> {
        let root = self
            .engine
            .group_tree()
            .expect("group_tree")
            .into_iter()
            .find(|g| g.parent_uuid.is_none())
            .expect("root group");
        self.engine
            .create_entry(
                root.uuid,
                NewEntryFields {
                    title: title.to_owned(),
                    username: String::new(),
                    url: String::new(),
                    notes: String::new(),
                    password: String::new(),
                    icon: IconRef::Builtin { index: 0 },
                    custom_fields: vec![],
                    tags: vec![],
                },
            )
            .expect("create_entry");
        self.save().await;
        std::fs::read(&self.kdbx).expect("read vault")
    }

    async fn save(&self) {
        self.engine
            .save_to_kdbx(
                path_string(&self.kdbx),
                VAULT_PASSWORD.to_owned(),
                Some(path_string(self.dir.path())),
            )
            .await
            .expect("save_to_kdbx");
    }

    /// Merge every other device's head in `doc_id` into this replica, under
    /// that device's owner id, and save. Asserts nothing was parked.
    async fn merge_heads(&self, node: &IrohNode, doc_id: &str) {
        let own_key = vault_key(&node.node_id());
        let prefix = vault_key("");
        let entries = node.list_entries(doc_id.to_owned()).await.expect("list");
        for head in entries
            .iter()
            .filter(|e| e.key.starts_with(&prefix) && e.key != own_key)
        {
            let bytes = node
                .fetch_blob(doc_id.to_owned(), head.hash_hex.clone(), MAX_HEAD_BYTES)
                .await
                .expect("fetch head");
            let blob = self.dir.path().join("peer-head.kdbx");
            std::fs::write(&blob, bytes).expect("write peer head");
            let owner = String::from_utf8(head.key[prefix.len()..].to_vec()).expect("owner id");
            let merged = self
                .engine
                .ingest_peer_kdbx(owner, path_string(&blob), VAULT_PASSWORD.to_owned(), None)
                .await
                .expect("ingest head");
            if let ParkConflictsResultFfi::Applied { parked, .. } = merged {
                assert!(
                    parked.entries_with_parked_conflict.is_empty(),
                    "disjoint edits must merge clean"
                );
                self.save().await;
            }
        }
    }

    /// The entry titles in the vault file itself, read through a fresh mirror
    /// so nothing this replica's engine remembers can answer for the file.
    async fn titles_on_disk(&self) -> Vec<String> {
        let dir = tempfile::tempdir().expect("reread tempdir");
        let engine = engine_over_file(&self.kdbx, &dir.path().join("reread.db")).await;
        let page = Page {
            offset: 0,
            limit: ENTRY_PAGE_LIMIT,
        };
        let mut titles: Vec<String> = engine
            .list_entries(None, page)
            .expect("list")
            .into_iter()
            .map(|e| e.title)
            .collect();
        titles.sort();
        titles
    }
}

async fn engine_over_file(kdbx: &Path, db: &Path) -> Arc<Engine> {
    let engine = Engine::open(
        path_string(db),
        Arc::new(FixedDbKey),
        Arc::new(FixedProtector),
        None,
    )
    .expect("open engine");
    engine
        .ingest_from_kdbx(path_string(kdbx), VAULT_PASSWORD.to_owned())
        .await
        .expect("ingest vault");
    engine
}

/// Wait until `events`' node has finished a successful round with `peer`,
/// which is what makes it remember `peer` as a peer of the doc.
async fn wait_for_round_with(
    events: &mut (impl futures_util::Stream<Item = keys_iroh_sync::Result<DocEvent>> + Unpin),
    peer: &str,
) {
    tokio::time::timeout(MESH_MEETING_WAIT, async {
        while let Some(event) = events.next().await {
            if matches!(
                event.expect("event"),
                DocEvent::SyncFinished { peer_node_id, error: None } if peer_node_id == peer
            ) {
                return;
            }
        }
        panic!("the event stream ended");
    })
    .await
    .expect("no round succeeded with the peer");
}

/// A peer holding a head it fetched but never merged serves that head to
/// another peer once its writer is offline, and heads travel the other way
/// too, so two writers that are never online together stay in step through
/// it. Each head arrives byte-exact and merges into a real vault file.
///
/// The fetch-only peer publishes one head while it can, then nothing: after
/// that it only runs its node, and no call on it can fetch anything (see
/// [`holds_blob`]). Each writer shuts down before the other returns, so the
/// fetch-only peer is the only peer either can reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_only_fetches_carries_heads_between_writers_never_online_together() {
    if is_network_test_skipped() {
        eprintln!("skipping: KEYS_IROH_SYNC_SKIP_NETWORK_TESTS set");
        return;
    }
    init_tracing();

    let body = async {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let vault = vault_dir.path().join("vault.kdbx");
        new_vault_file(&vault).await;
        let seed = std::fs::read(&vault).expect("read vault");
        let a_replica = Replica::of(&vault).await;
        let c_replica = Replica::of(&vault).await;

        let (a_device, b_device, c_device) = (Device::new(), Device::new(), Device::new());
        let a = a_device.start().await;
        let b = b_device.start().await;
        let c = c_device.start().await;
        let (a_id, b_id, c_id) = (a.node_id(), b.node_id(), c.node_id());

        // All three share the doc. The third peer joins through the writer's
        // ticket, so it can only learn of the fetch-only peer over the doc's
        // mesh.
        let doc_id = a.create_doc().await.expect("create_doc");
        let first_hash = a
            .set_entry(doc_id.clone(), vault_key(&a_id), seed.clone())
            .await
            .expect("first head");
        let ticket = a.share_doc(doc_id.clone(), true).await.expect("share");
        b.join_doc(ticket.clone(), DownloadPolicy::Everything)
            .await
            .expect("fetch-only peer joins");
        let mut b_events = b.subscribe_doc_events(&doc_id).await.expect("events");
        c.join_doc(ticket, DownloadPolicy::Everything)
            .await
            .expect("third peer joins");
        wait_for_round_with(&mut b_events, &c_id).await;
        drop(b_events);

        // The fetch-only peer publishes its one head. Its write dials the
        // third peer, so the third peer's own record of the round is seen
        // too: it is the one that must remember the fetch-only peer.
        let mut c_events = c.subscribe_doc_events(&doc_id).await.expect("events");
        b.set_entry(doc_id.clone(), vault_key(&b_id), seed.clone())
            .await
            .expect("fetch-only peer's one head");
        wait_for_round_with(&mut c_events, &b_id).await;
        drop(c_events);
        assert!(
            wait_for_head(&c, &doc_id, &vault_key(&a_id), &first_hash).await,
            "the third peer never fetched the writer's first head"
        );

        // The third peer goes away, the writer edits, and the fetch-only
        // peer fetches; then the writer goes away too.
        c.shutdown().await.expect("third peer shutdown");
        drop(c);
        let a_head = a_replica.add_entry("from-a").await;
        let a_hash = a
            .set_entry(doc_id.clone(), vault_key(&a_id), a_head.clone())
            .await
            .expect("writer's edit");
        assert!(
            wait_for_head(&b, &doc_id, &vault_key(&a_id), &a_hash).await,
            "the fetch-only peer never fetched the writer's head"
        );
        a.shutdown().await.expect("writer shutdown");
        drop(a);

        // The third peer returns with only the fetch-only peer to reach.
        let c = c_device.resume(&doc_id).await;
        assert_head_arrives(
            &c,
            &doc_id,
            &vault_key(&a_id),
            (&a_hash, &a_head),
            "the fetch-only peer, to the third peer",
        )
        .await;
        c_replica.merge_heads(&c, &doc_id).await;
        assert_eq!(c_replica.titles_on_disk().await, vec!["from-a"]);

        // The reverse: the third peer edits, the fetch-only peer fetches, the
        // third peer goes away and the first writer returns.
        let c_head = c_replica.add_entry("from-c").await;
        let c_hash = c
            .set_entry(doc_id.clone(), vault_key(&c_id), c_head.clone())
            .await
            .expect("third peer's edit");
        assert!(
            wait_for_head(&b, &doc_id, &vault_key(&c_id), &c_hash).await,
            "the fetch-only peer never fetched the third peer's head"
        );
        c.shutdown().await.expect("third peer shutdown");
        drop(c);

        let a = a_device.resume(&doc_id).await;
        assert_head_arrives(
            &a,
            &doc_id,
            &vault_key(&c_id),
            (&c_hash, &c_head),
            "the fetch-only peer, to the returning writer",
        )
        .await;
        a_replica.merge_heads(&a, &doc_id).await;
        assert_eq!(a_replica.titles_on_disk().await, vec!["from-a", "from-c"]);

        a.shutdown().await.expect("writer shutdown");
        b.shutdown().await.expect("fetch-only peer shutdown");
    };

    tokio::time::timeout(STORE_AND_FORWARD_TEST_CAP, body)
        .await
        .expect("test exceeded its cap — likely a hang, not a slow DERP");
}

/// A peer that has never synced can join through a fetch-only peer while the
/// doc's writer is offline, as long as its ticket names that peer: the
/// fetch-only peer's own ticket does, and so does the writer's capability
/// with its address list swapped. It is the address that counts, not who
/// minted the capability. A ticket naming only the offline writer reaches
/// nobody, since a ticket lists only the node that minted it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_peer_joins_through_a_fetch_only_peer_while_the_writer_is_offline() {
    if is_network_test_skipped() {
        eprintln!("skipping: KEYS_IROH_SYNC_SKIP_NETWORK_TESTS set");
        return;
    }
    init_tracing();

    let body = async {
        let (a, _ab, _ad) = spin_up_node().await;
        let (b, _bb, _bd) = spin_up_node().await;
        let doc_id = a.create_doc().await.expect("create_doc");
        let head = b"the writer's head".to_vec();
        let key = vault_key(&a.node_id());
        let hash = a
            .set_entry(doc_id.clone(), key.clone(), head.clone())
            .await
            .expect("writer's head");
        let writer_ticket = a.share_doc(doc_id.clone(), true).await.expect("share");
        b.join_doc(writer_ticket.clone(), DownloadPolicy::Everything)
            .await
            .expect("fetch-only peer joins");
        assert!(
            wait_for_head(&b, &doc_id, &key, &hash).await,
            "the fetch-only peer never fetched the writer's head"
        );
        a.shutdown().await.expect("writer shutdown");
        drop(a);

        let b_ticket = b.share_doc(doc_id.clone(), true).await.expect("share");
        let b_id: iroh::PublicKey = b.node_id().parse().expect("node id");
        let readdressed = |nodes: Vec<iroh::EndpointAddr>| {
            let mut ticket: DocTicket = writer_ticket.parse().expect("parse ticket");
            ticket.nodes = nodes;
            ticket.to_string()
        };
        let b_addr = b_ticket.parse::<DocTicket>().expect("parse ticket").nodes;
        assert_eq!(b_addr.len(), 1, "a ticket lists only its minter");
        assert_eq!(b_addr[0].id, b_id);

        for (route, ticket) in [
            ("the fetch-only peer's ticket", b_ticket),
            (
                "the writer's capability, addressed to it",
                readdressed(b_addr),
            ),
            (
                "the writer's capability, naming only its id",
                readdressed(vec![iroh::EndpointAddr::new(b_id)]),
            ),
        ] {
            let (newcomer, _nb, _nd) = spin_up_node().await;
            newcomer
                .join_doc(ticket, DownloadPolicy::Everything)
                .await
                .unwrap_or_else(|e| panic!("join through {route} failed: {e}"));
            assert_head_arrives(&newcomer, &doc_id, &key, (&hash, &head), route).await;

            // The capability is writable, so the newcomer is a full peer.
            let own_key = vault_key(&newcomer.node_id());
            let own_hash = newcomer
                .set_entry(doc_id.clone(), own_key.clone(), b"newcomer's head".to_vec())
                .await
                .expect("newcomer writes");
            assert!(
                wait_for_head(&b, &doc_id, &own_key, &own_hash).await,
                "the fetch-only peer never fetched the newcomer's head from {route}"
            );
            newcomer.shutdown().await.expect("newcomer shutdown");
        }

        let (stranded, _sb, _sd) = spin_up_node().await;
        let joined = stranded
            .join_doc(writer_ticket, DownloadPolicy::Everything)
            .await;
        // Reaching nobody, the join times out, or ends on a failed round
        // with nothing to come.
        match joined {
            Err(e) => assert!(
                e.to_string().contains("initial sync timed out"),
                "expected the join to time out, got: {e}"
            ),
            Ok(id) => assert!(
                !wait_for_head(&stranded, &id, &key, &hash).await,
                "a ticket naming only the offline writer delivered a head"
            ),
        }
        stranded.shutdown().await.expect("shutdown");
        b.shutdown().await.expect("fetch-only peer shutdown");
    };

    tokio::time::timeout(STORE_AND_FORWARD_TEST_CAP, body)
        .await
        .expect("test exceeded its cap — likely a hang, not a slow DERP");
}
