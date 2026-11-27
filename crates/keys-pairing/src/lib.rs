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
//!   confirmation, and for a Person pairing the two signed key sets that
//!   follow inside the session.
//! - [`session`]: the verified session's frames.
//! - [`sheet`]: the policy a client drives: one run per code, a run budget
//!   per sheet, code expiry and run timeouts.
//!
//! Around the exchange, how two sides find each other. None of it is
//! trusted by the exchange, and none of it carries a secret:
//! - [`address`]: where an endpoint can be reached, and the sanitiser for
//!   names from unverified sources.
//! - [`link`]: the `keys://pair/…` links that carry an address or an invite
//!   as text.
//! - [`invite`]: Person invites, and the book that answers their knocks.
//! - [`greeting`]: the first message on a pairing connection (a knock, a
//!   call or an approach) and its answer.
//! - [`advert`]: what a device with an open sheet advertises on the local
//!   network.
//!
//! The transport itself (connections, and which endpoint id the peer
//! authenticated as) is the caller's; this crate fixes only the bytes.

pub mod address;
pub mod advert;
pub mod code;
mod cpace;
pub mod greeting;
#[cfg(test)]
mod heap_watch;
mod hex;
pub mod invite;
pub mod keys;
pub mod link;
mod protocol;
mod random;
mod secret;
pub mod session;
pub mod sheet;
mod wire;

pub use address::{AddressError, PairingAddress, sanitize_display_name};
pub use code::PairingCode;
pub use cpace::CPACE_DRAFT;
pub use greeting::{Greeting, KnockAnswer, MeetingAnswer};
pub use invite::{
    Invite, InviteBook, InviteError, InviteId, InviteRecord, IssueError, KnockOutcome,
};
pub use keys::{AccountKeys, AccountPublicKeys, DeviceKeys, DevicePublicKeys, RecoverySecret};
pub use link::{LinkError, PairingLink};
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

#[cfg(fuzzing)]
pub use protocol::key_set_is_accepted_for_fuzzing;

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
