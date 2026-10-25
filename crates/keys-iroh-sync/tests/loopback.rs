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
use keys_iroh_sync::{DownloadPolicy, Identity, IrohNode, NodeConfig};
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
