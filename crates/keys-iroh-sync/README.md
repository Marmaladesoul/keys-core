# keys-iroh-sync

iroh-based sync transport for the Keys password manager.

This crate is the **transport library**, not the Keys app. It wraps
[`iroh`](https://crates.io/crates/iroh),
[`iroh-docs`](https://crates.io/crates/iroh-docs), and
[`iroh-blobs`](https://crates.io/crates/iroh-blobs) into a stable,
FFI-friendly Rust library that the Keys client applications embed for
device sync, fleet sync, and friendship sync.

## What's in scope

- Persistent endpoint identity (caller supplies bytes, library
  doesn't touch keychain or filesystem for keys).
- Persistent blob store + doc store, caller-chosen directories.
- Many concurrent docs per node, keyed by `NamespaceId`.
- Caller-supplied DERP fallback list (empty list = N0 defaults).
- Per-doc download policy (`Everything` / `NothingExcept` /
  `EverythingExcept`) set at join time.
- Event subscription via FFI callback interface or native Rust
  `Stream`.
- Graceful shutdown that awaits in-flight router and endpoint
  shutdown — required for iOS to avoid the quinn suspended-socket
  EPIPE on resume (see decision-doc §2d).

## What's out of scope

- **The People model, fleet docs, vault docs, friendship docs.**
  Those are higher-level constructs that live in the Keys app and
  layer on top of "many concurrent docs per node".
- **Identity storage.** Callers own the secret bytes and keep them
  in their platform keychain.
- **Platform binary builds.** xcframework / Windows DLL builds live
  in the consuming app's repo.

## Stability promise

- The Rust API on this crate follows semver. Breaking changes bump
  the minor while pre-1.0 and the major after 1.0.
- The FFI surface (uniffi-generated bindings) is part of the public
  API — bindings consumed by the client apps must regenerate
  on every minor bump.
- iroh itself is pre-1.0; we track its `rc.x` releases in lockstep
  and call out the iroh version in every changelog entry.

## Quick reference

```rust,no_run
use keys_iroh_sync::{DownloadPolicy, Identity, IrohNode, NodeConfig};

# async fn ex() -> Result<(), Box<dyn std::error::Error>> {
let node = IrohNode::bind(NodeConfig {
    identity: Identity::generate(),
    blob_dir: "/var/keys/blobs".into(),
    doc_dir: "/var/keys/docs".into(),
    relay_urls: vec![],  // empty = N0 defaults
}).await?;

let doc_id = node.create_doc().await?;
node.set_entry(doc_id.clone(), b"hello".to_vec(), b"world".to_vec()).await?;
let ticket = node.share_doc(doc_id.clone(), /* writable = */ true).await?;

// On the receiving node:
// let id = other_node.join_doc(ticket, DownloadPolicy::Everything).await?;
// let entries = other_node.list_entries(id).await?;

node.shutdown().await?;
# Ok(())
# }
```

## Tests

`tests/loopback.rs` runs a publisher↔subscriber sync end-to-end in
one process using N0's public DERP. Set
`KEYS_IROH_SYNC_SKIP_NETWORK_TESTS=1` to skip on runners without
outbound internet.
