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

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();

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
