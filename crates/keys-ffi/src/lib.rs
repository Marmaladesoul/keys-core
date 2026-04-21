//! # keys-ffi
//!
//! Private FFI facade for the Keys password manager. Consumes the public
//! `keepass-core` and `keepass-merge` crates and exposes a uniffi-generated
//! API for consumption by the native Swift/SwiftUI and C#/WinUI 3 frontends.
//!
//! API shape is driven by Keys' UI needs and carries no stability guarantee
//! for external consumers — hence this crate remains closed-source and is
//! deliberately not published to crates.io.

// Ensure the public crates link cleanly while the FFI surface is being defined.
#[allow(unused_imports)]
use keepass_core as _;
#[allow(unused_imports)]
use keepass_merge as _;
