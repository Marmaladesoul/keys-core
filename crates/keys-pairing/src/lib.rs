//! Code-authenticated pairing for Keys.
//!
//! Two devices (or two people's devices) prove to each other that they share
//! a six-digit code: one side shows it, the other types it, nobody compares.
//! The code is the password of a balanced PAKE, `CPace`
//! ([`CPACE_DRAFT`], ristretto255 with SHA-512), so it never crosses
//! the wire and one-way entry authenticates both ends. Explicit key
//! confirmation in both directions gates a [`VerifiedSession`] that carries
//! opaque payloads.
//!
//! Layers, bottom up:
//! - `cpace`: the PAKE itself, checked against the draft's test vectors.
//!   Private: its raw shares and intermediate key are only safe inside the
//!   exchange that confirms them.
//! - [`code`]: drawing and parsing the code.
//! - [`keys`]: the account and device key sets a pairing binds.
//! - `protocol`: the four-message exchange, transcript binding and key
//!   confirmation.
//! - [`session`]: the verified session's frames.
//! - [`sheet`]: the policy a client drives: one run per code, a run budget
//!   per sheet, code expiry and run timeouts.
//!
//! The transport (how messages travel, and which endpoint id the peer
//! authenticated as) and discovery are the caller's.

pub mod code;
mod cpace;
#[cfg(test)]
mod heap_watch;
pub mod keys;
mod protocol;
mod random;
mod secret;
pub mod session;
pub mod sheet;
mod wire;

pub use code::PairingCode;
pub use cpace::CPACE_DRAFT;
pub use keys::{AccountKeys, AccountPublicKeys, DeviceKeys, DevicePublicKeys, RecoverySecret};
pub use protocol::{Credentials, PROTOCOL_VERSION, PairingKind, RefuseReason, RunFailure};
pub use session::{SessionError, VerifiedSession};
pub use sheet::{
    Clock, CodeReason, DisplaySheet, DisplayStatus, Failure, ManualClock, Outcome, Response,
    SystemClock, TypeSheet, TypeStatus,
};

/// The unit tests run on an allocator that can watch what a thread frees
/// (see `heap_watch`).
#[cfg(test)]
#[global_allocator]
static TEST_ALLOCATOR: heap_watch::WatchingAllocator = heap_watch::WatchingAllocator;

/// Fuzzing builds only (`--cfg fuzzing`, which cargo-fuzz sets): from now on
/// this thread's random bytes are a fixed stream derived from `seed`, so a
/// fuzz input replays exactly. No other build has this function.
#[cfg(fuzzing)]
pub fn script_random_for_fuzzing(seed: &[u8]) {
    random::scripted::start(seed);
}

/// A transport endpoint id: the 32-byte public key the transport
/// authenticated the peer as.
pub type EndpointId = [u8; 32];

/// Errors from driving the pairing API. A failed run is not one of these: it
/// is an [`Outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
    /// The typed code is not exactly six ASCII digits.
    #[error("a pairing code is exactly six digits")]
    MalformedCode,
    /// The call doesn't apply to the sheet's current state.
    #[error("the pairing sheet is not in a state that allows this")]
    WrongState,
}
