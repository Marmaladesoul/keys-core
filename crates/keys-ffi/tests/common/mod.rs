//! Shared test-support for the `keys-ffi` integration tests.
//!
//! Every `vault_*.rs` integration test resolves its KDBX inputs through
//! [`fixture`], so the location of the fixture corpus lives in exactly
//! one place instead of being copy-pasted into each test binary.
//!
//! # Fixtures-path contract
//!
//! The corpus directory is taken from the `KEYS_TEST_FIXTURES_DIR`
//! environment variable when it is set. **That env var is the contract:**
//! point it at any checkout of the `keepass-core` fixtures and the tests
//! resolve against it, independent of where this repo sits on disk.
//!
//! When the var is unset, resolution falls back to a sibling `keepass-core`
//! checkout at `<crate>/../../../KeepassCore/tests/fixtures`, so a
//! conventional side-by-side local layout keeps working with zero
//! configuration. The relative path is only the *default* — set the env
//! var whenever the layout differs (CI, a non-sibling checkout, or a
//! relocated workspace), and on-disk placement stops mattering.

// `tests/common/mod.rs` is compiled afresh into every `vault_*.rs` test
// binary. Not every binary necessarily exercises every helper here, so
// silence dead-code for the items a given binary doesn't touch rather than
// fighting the workspace's `-D warnings`.
#![allow(dead_code)]

use std::path::PathBuf;

/// Root of the KDBX fixture corpus: `KEYS_TEST_FIXTURES_DIR` when set,
/// otherwise the sibling `keepass-core` checkout (see the module docs).
fn fixtures_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("KEYS_TEST_FIXTURES_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../KeepassCore/tests/fixtures")
}

/// Resolve a corpus-relative fixture path (e.g. `keepassxc/kdbx3-basic.kdbx`)
/// to an absolute path string suitable for `Vault::new`.
pub fn fixture(rel: &str) -> String {
    fixtures_dir().join(rel).to_string_lossy().into_owned()
}
