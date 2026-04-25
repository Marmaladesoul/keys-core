//! # keys-ffi
//!
//! Private FFI facade for the Keys password manager. Consumes the public
//! `keepass-core` and `keepass-merge` crates and exposes a uniffi-generated
//! API for consumption by the native Swift/SwiftUI and C#/WinUI 3
//! frontends.
//!
//! API shape is driven by Keys' UI needs and carries no stability
//! guarantee for external consumers — hence this crate remains
//! closed-source and is deliberately not published to crates.io.

#[allow(unused_imports)]
use keepass_merge as _;

mod dto;
mod error;
mod vault;

pub use dto::{CustomField, Entry, EntrySummary, Group, ProtectedField};
pub use error::VaultError;
pub use vault::Vault;

uniffi::setup_scaffolding!();

/// Smoke-test entry point exercised by the Swift harness from slice 1.
///
/// Stable through the rest of Phase 2 so the harness has a trivial
/// round-trip even after `Vault` lands.
#[uniffi::export]
#[must_use]
pub fn ping() -> String {
    "keys-ffi alive".to_owned()
}

#[cfg(test)]
mod tests {
    use super::ping;

    #[test]
    fn ping_returns_expected_string() {
        assert_eq!(ping(), "keys-ffi alive");
    }
}
