//! # keys-ffi
//!
//! Private FFI facade for the Keys password manager. Consumes the public
//! `keepass-core` and `keepass-merge` crates and exposes a uniffi-generated
//! API for consumption by the native Swift/SwiftUI and C#/WinUI 3 frontends.
//!
//! API shape is driven by Keys' UI needs and carries no stability guarantee
//! for external consumers — hence this crate remains closed-source and is
//! deliberately not published to crates.io.
//!
//! Slice 1: scaffolding only. Real surface (`Vault`, `Entry`, etc.) lands
//! in slices 2+ per `_localdocs/FFI_PHASE2.md`.

// Ensure the public crates link cleanly while the FFI surface is being defined.
#[allow(unused_imports)]
use keepass_core as _;
#[allow(unused_imports)]
use keepass_merge as _;

uniffi::setup_scaffolding!();

/// Smoke-test entry point exercised by the Swift harness in slice 1.
///
/// Replaced by real surface in slice 2; kept stable so the harness has a
/// trivial round-trip even after `Vault` lands.
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
