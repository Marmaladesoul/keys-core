//! keys-iroh-sync — iroh transport library for the Keys password manager.
//!
//! This crate wraps [`iroh`], [`iroh_docs`], and [`iroh_blobs`] into a
//! stable, FFI-friendly library that the Keys client applications embed
//! for device sync, fleet sync, and friendship sync.
//!
//! Library, not application:
//!
//! - The crate does not know about the People model, the fleet doc,
//!   vault docs, or friendship docs. Those concepts live in the Keys
//!   app and layer on top of "many concurrent docs per node".
//! - The crate does not own identity storage. Callers supply the
//!   ed25519 secret key bytes at bind time and hold them in their
//!   platform keychain.
//! - The crate does not build platform binaries. The xcframework /
//!   Windows DLL build pipelines live in the consuming app's repo.
//!
//! Stability promise:
//!
//! - The Rust API on this crate follows semver. Breaking changes bump
//!   the minor while pre-1.0 and the major after 1.0.
//! - The FFI surface (uniffi-generated bindings) is part of the public
//!   API — bindings consumed by the client apps must regenerate
//!   on every minor bump.
//! - iroh itself is pre-1.0; we track its rc.x releases in lockstep
//!   and call out the iroh version in every CHANGELOG entry.

// All fallible methods on the public API funnel through one error type
// (`SyncError::Generic(String)`) — a "# Errors" doc section on every
// function would say the same thing 20 times. Allow it crate-wide and
// document the error model once in the lib.rs preamble.
#![allow(clippy::missing_errors_doc)]
// iroh / DERP / NodeId / etc. are domain proper nouns. Wrapping them in
// backticks throughout the docs is line noise.
#![allow(clippy::doc_markdown)]

uniffi::setup_scaffolding!();

mod error;
mod events;
mod identity;
mod node;
mod policy;

pub use error::{Result, SyncError};
pub use events::{DocEvent, DocEventListener};
pub use identity::{Identity, identity_generate};
pub use node::{DocSubscription, EntryInfo, IrohNode, NodeConfig, node_id};
pub use policy::DownloadPolicy;
