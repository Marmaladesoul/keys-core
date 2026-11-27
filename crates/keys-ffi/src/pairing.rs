//! Pairing across the FFI: the [`keys_pairing`] sheets, keys and verified
//! session, as uniffi objects.
//!
//! The client owns the transport: it moves the opaque messages these objects
//! produce between the two devices, and tells each sheet and session which
//! endpoint id the transport authenticated each message as (never one read
//! out of the message). Everything else (the code, the run budget, expiry,
//! the exchange, key confirmation) happens behind this seam.
//!
//! **What a client must do, because nothing here can do it for it:**
//! - Carry each run on one ordered, reliable connection, a new one per run,
//!   and send a sheet's reply only to the sender of the message it answers.
//! - Never resubmit a code by itself, whatever the outcome (a "busy"
//!   refusal included: someone else's Hello may have used the code up). The
//!   person retypes.
//! - Open a new sheet after a dead end only on the person's say-so. The run
//!   budget lives in the sheet, so reopening automatically would undo it.
//! - Treat a displaying side as paired only at
//!   [`PairingDisplayStatus::Verified`], not at `VerifiedAwaitingPeer`.
//!
//! **Secrets that cross the seam**, as plain values the client must not log:
//! the displayed code ([`PairingDisplaySheet::shown_code`]), the typed code
//! ([`PairingTypeSheet::submit_code`]), and every session payload in the
//! clear ([`PairingSession::seal`], [`PairingSession::open`]). Rust can't
//! wipe the copies the foreign side holds.

// uniffi exports take owned arguments.
#![allow(clippy::needless_pass_by_value)]

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use keys_pairing as kp;

/// Errors from driving pairing objects. A run that fails is not one of these:
/// it's a [`PairingOutcomeFfi`].
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum PairingFfiError {
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
    /// A typed code is exactly six ASCII digits.
    #[error("a pairing code is exactly six digits")]
    MalformedCode,
    /// The call doesn't apply to the sheet's current state.
    #[error("the pairing sheet is not in a state that allows this")]
    WrongState,
    /// An endpoint id or public key was not 32 bytes.
    #[error("an endpoint id or public key must be 32 bytes")]
    InvalidKeyLength,
    /// A session frame was out of sequence or didn't authenticate; the
    /// session refuses everything from now on.
    #[error("the session frame was rejected")]
    FrameRejected,
    /// The message handed to a session didn't come from its peer. Nothing
    /// changed.
    #[error("the message is not from this session's peer")]
    SessionWrongSender,
    /// The message handed to a session isn't a session frame (a late
    /// exchange message, say). Nothing changed.
    #[error("the message is not a session frame")]
    SessionNotAFrame,
    /// The session has sent all the frames it can.
    #[error("the session has sent all the frames it can")]
    SessionExhausted,
    /// The payload handed to a session is too large for one frame. Nothing
    /// changed.
    #[error("the payload is too large for one session frame")]
    SessionPayloadTooLarge,
    /// The displaying side can't send until it has opened a frame from the
    /// typing side (which proves the typing side verified it).
    #[error("the session can't send until the other side has spoken")]
    SessionAwaitingPeer,
}

impl From<kp::PairingError> for PairingFfiError {
    fn from(error: kp::PairingError) -> Self {
        match error {
            kp::PairingError::Random => Self::Random,
            kp::PairingError::MalformedCode => Self::MalformedCode,
            kp::PairingError::WrongState => Self::WrongState,
        }
    }
}

impl From<kp::SessionError> for PairingFfiError {
    fn from(error: kp::SessionError) -> Self {
        match error {
            kp::SessionError::FrameRejected => Self::FrameRejected,
            kp::SessionError::WrongSender => Self::SessionWrongSender,
            kp::SessionError::NotAFrame => Self::SessionNotAFrame,
            kp::SessionError::Exhausted => Self::SessionExhausted,
            kp::SessionError::PayloadTooLarge => Self::SessionPayloadTooLarge,
            kp::SessionError::AwaitingPeer => Self::SessionAwaitingPeer,
        }
    }
}

fn key32(bytes: &[u8]) -> Result<[u8; 32], PairingFfiError> {
    bytes
        .try_into()
        .map_err(|_| PairingFfiError::InvalidKeyLength)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The pairing policy's numbers, as the engine sets them: for a client to
/// show ("you have N tries", a countdown), never to enforce.
#[derive(uniffi::Record, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingPolicy {
    /// Runs a sheet allows before it becomes a dead end.
    pub max_runs_per_sheet: u8,
    /// How long a displayed code stays usable.
    pub code_lifetime_ms: u64,
    /// How long each wait of a run may take before the run counts as failed.
    pub run_timeout_ms: u64,
}

/// The pairing policy's numbers.
#[uniffi::export]
#[must_use]
pub fn pairing_policy() -> PairingPolicy {
    PairingPolicy {
        max_runs_per_sheet: kp::sheet::MAX_RUNS_PER_SHEET,
        code_lifetime_ms: millis(kp::sheet::CODE_LIFETIME),
        run_timeout_ms: millis(kp::sheet::RUN_TIMEOUT),
    }
}

// ─── keys ───────────────────────────────────────────────────────────────────

/// An account's public key set: what a Person verifies.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PairingAccountPublicKeys {
    pub identity: Vec<u8>,
    pub recovery: Vec<u8>,
    pub encryption: Vec<u8>,
}

impl From<kp::AccountPublicKeys> for PairingAccountPublicKeys {
    fn from(keys: kp::AccountPublicKeys) -> Self {
        Self {
            identity: keys.identity.to_vec(),
            recovery: keys.recovery.to_vec(),
            encryption: keys.encryption.to_vec(),
        }
    }
}

/// A device's public key set.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PairingDevicePublicKeys {
    pub signing: Vec<u8>,
    pub relay: Vec<u8>,
    pub vault: Vec<u8>,
}

/// An account's keys. The private halves stay on the Rust side.
#[derive(uniffi::Object)]
pub struct PairingAccountKeys {
    inner: Arc<kp::AccountKeys>,
}

#[uniffi::export]
impl PairingAccountKeys {
    #[must_use]
    pub fn public_keys(&self) -> PairingAccountPublicKeys {
        self.inner.public_keys().into()
    }
}

/// The recovery secret, handed back once at account generation. Opaque for
/// now: how it is rendered as a recovery code for a person to write down is
/// not decided yet, so nothing reads it across the seam.
#[derive(uniffi::Object)]
pub struct PairingRecoverySecret {
    _inner: kp::RecoverySecret,
}

/// A freshly generated account.
#[derive(uniffi::Record)]
pub struct GeneratedPairingAccount {
    pub keys: Arc<PairingAccountKeys>,
    pub recovery_secret: Arc<PairingRecoverySecret>,
}

/// Generates a fresh account: identity, encryption and recovery keys.
///
/// # Errors
/// [`PairingFfiError::Random`] if the system random source fails.
#[uniffi::export]
pub fn generate_pairing_account() -> Result<GeneratedPairingAccount, PairingFfiError> {
    let (keys, recovery) = kp::AccountKeys::generate()?;
    Ok(GeneratedPairingAccount {
        keys: Arc::new(PairingAccountKeys {
            inner: Arc::new(keys),
        }),
        recovery_secret: Arc::new(PairingRecoverySecret { _inner: recovery }),
    })
}

/// One device's keys. The private halves stay on the Rust side.
#[derive(uniffi::Object)]
pub struct PairingDeviceKeys {
    inner: kp::DeviceKeys,
}

#[uniffi::export]
impl PairingDeviceKeys {
    /// Generates a fresh device key set.
    ///
    /// # Errors
    /// [`PairingFfiError::Random`] if the system random source fails.
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, PairingFfiError> {
        Ok(Arc::new(Self {
            inner: kp::DeviceKeys::generate()?,
        }))
    }

    #[must_use]
    pub fn public_keys(&self) -> PairingDevicePublicKeys {
        let keys = self.inner.public_keys();
        PairingDevicePublicKeys {
            signing: keys.signing.to_vec(),
            relay: keys.relay.to_vec(),
            vault: keys.vault.to_vec(),
        }
    }
}

// ─── credentials, clock, outcomes ───────────────────────────────────────────

/// What this side brings to a pairing.
#[derive(uniffi::Enum)]
pub enum PairingCredentials {
    /// Another of this account's devices.
    Device,
    /// Another person's account. `expected_peer_identity` is the identity
    /// key this side expects them to have (from an invite it holds), if any.
    Person {
        account: Arc<PairingAccountKeys>,
        expected_peer_identity: Option<Vec<u8>>,
    },
}

impl PairingCredentials {
    fn into_engine(self) -> Result<kp::Credentials, PairingFfiError> {
        Ok(match self {
            Self::Device => kp::Credentials::Device,
            Self::Person {
                account,
                expected_peer_identity,
            } => kp::Credentials::Person {
                account: Arc::clone(&account.inner),
                expected_peer_identity: expected_peer_identity.as_deref().map(key32).transpose()?,
            },
        })
    }
}

/// A clock that moves only when told to: test scaffolding, so the headless
/// driver can step a sheet past its code lifetime or run timeout. Built only
/// with the `pairing-test-clock` feature, which client builds leave off: a
/// sheet on this clock never expires a code or times a run out by itself.
#[cfg(feature = "pairing-test-clock")]
#[derive(uniffi::Object, Default)]
pub struct PairingTestClock {
    inner: Arc<kp::ManualClock>,
}

#[cfg(feature = "pairing-test-clock")]
#[uniffi::export]
impl PairingTestClock {
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn advance_ms(&self, ms: u64) {
        self.inner.advance(Duration::from_millis(ms));
    }
}

/// Why the displaying side is showing the code it is showing.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingCodeReason {
    Opened,
    Rerolled,
    Expired,
    RunFailed,
}

impl From<kp::CodeReason> for PairingCodeReason {
    fn from(reason: kp::CodeReason) -> Self {
        match reason {
            kp::CodeReason::Opened => Self::Opened,
            kp::CodeReason::Rerolled => Self::Rerolled,
            kp::CodeReason::Expired => Self::Expired,
            kp::CodeReason::RunFailed => Self::RunFailed,
        }
    }
}

/// Why a displaying side turned a message away without a run.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingRefuseReason {
    RunFailed,
    CodeExpired,
    Busy,
    DeadEnd,
    Unsupported,
}

impl From<kp::RefuseReason> for PairingRefuseReason {
    fn from(reason: kp::RefuseReason) -> Self {
        match reason {
            kp::RefuseReason::RunFailed => Self::RunFailed,
            kp::RefuseReason::CodeExpired => Self::CodeExpired,
            kp::RefuseReason::Busy => Self::Busy,
            kp::RefuseReason::DeadEnd => Self::DeadEnd,
            kp::RefuseReason::Unsupported => Self::Unsupported,
        }
    }
}

/// Why a run ended without verifying. Every one reads the same to the person
/// ("that code didn't work"); the distinction is for diagnostics.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingFailure {
    MalformedMessage,
    InvalidShare,
    ConfirmationFailed,
    InvalidPeerKeys,
    UnexpectedPeerIdentity,
    Random,
    RefusedByPeer,
    PeerDeadEnd,
    TimedOut,
    Abandoned,
}

impl From<kp::Failure> for PairingFailure {
    fn from(failure: kp::Failure) -> Self {
        match failure {
            kp::Failure::Exchange(run) => match run {
                kp::RunFailure::MalformedMessage => Self::MalformedMessage,
                kp::RunFailure::InvalidShare => Self::InvalidShare,
                kp::RunFailure::ConfirmationFailed => Self::ConfirmationFailed,
                kp::RunFailure::InvalidPeerKeys => Self::InvalidPeerKeys,
                kp::RunFailure::UnexpectedPeerIdentity => Self::UnexpectedPeerIdentity,
                kp::RunFailure::Random => Self::Random,
            },
            kp::Failure::RefusedByPeer => Self::RefusedByPeer,
            kp::Failure::PeerDeadEnd => Self::PeerDeadEnd,
            kp::Failure::TimedOut => Self::TimedOut,
            kp::Failure::Abandoned => Self::Abandoned,
        }
    }
}

/// What handling a message (or abandoning a run) meant.
#[derive(uniffi::Enum)]
pub enum PairingOutcomeFfi {
    /// The run goes on; send the reply.
    Continue,
    /// Turned away without a run; nothing spent.
    NoRun { reason: PairingRefuseReason },
    /// The run failed and its code is burnt.
    RunFailed {
        failure: PairingFailure,
        runs_left: u8,
    },
    /// The run failed and the sheet is spent.
    DeadEnd { failure: PairingFailure },
    /// This side verified the other and holds a session. On the typing
    /// side both confirmations have now verified. On the displaying side
    /// only the typing side's has: it is **not paired yet** (see
    /// [`PairingDisplayStatus::VerifiedAwaitingPeer`]).
    Verified { session: Arc<PairingSession> },
    /// The message isn't one this sheet answers from that sender, in its
    /// present state: on the typing side, anything not from the displaying
    /// endpoint, and anything but a refusal when no run is in flight (a late
    /// or duplicated message); on the displaying side, anything but a Hello
    /// from an endpoint that has no run in flight. Nothing changed; send
    /// nothing.
    Ignored,
}

impl From<kp::Outcome> for PairingOutcomeFfi {
    fn from(outcome: kp::Outcome) -> Self {
        match outcome {
            kp::Outcome::Continue => Self::Continue,
            kp::Outcome::NoRun(reason) => Self::NoRun {
                reason: reason.into(),
            },
            kp::Outcome::RunFailed { failure, runs_left } => Self::RunFailed {
                failure: failure.into(),
                runs_left,
            },
            kp::Outcome::DeadEnd { failure } => Self::DeadEnd {
                failure: failure.into(),
            },
            kp::Outcome::Verified(session) => Self::Verified {
                session: Arc::new(PairingSession {
                    inner: Mutex::new(*session),
                }),
            },
            kp::Outcome::Ignored => Self::Ignored,
        }
    }
}

/// A sheet's answer to a message: what to send back, if anything, and what
/// it means.
#[derive(uniffi::Record)]
pub struct PairingResponse {
    pub reply: Option<Vec<u8>>,
    pub outcome: PairingOutcomeFfi,
}

impl From<kp::Response> for PairingResponse {
    fn from(response: kp::Response) -> Self {
        Self {
            reply: response.reply,
            outcome: response.outcome.into(),
        }
    }
}

// ─── the displaying sheet ───────────────────────────────────────────────────

/// What a displaying sheet is doing. It never carries the code itself (see
/// [`PairingDisplaySheet::shown_code`]), so it is safe to log.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingDisplayStatus {
    /// Showing a code, usable for `expires_in_ms` more.
    ShowingCode {
        reason: PairingCodeReason,
        expires_in_ms: u64,
        runs_left: u8,
    },
    Running,
    /// This side verified the typing side and holds a session, but hasn't
    /// yet heard from the typing side on it. **Not paired yet**: if the
    /// typing side stays silent, give the pairing up.
    VerifiedAwaitingPeer,
    /// Both sides verified.
    Verified,
    DeadEnd,
}

/// The sheet on the side that shows the code.
#[derive(uniffi::Object)]
pub struct PairingDisplaySheet {
    inner: Mutex<kp::DisplaySheet>,
}

impl PairingDisplaySheet {
    fn open_with(
        credentials: PairingCredentials,
        own_endpoint: &[u8],
        clock: Arc<dyn kp::Clock>,
    ) -> Result<Arc<Self>, PairingFfiError> {
        let sheet =
            kp::DisplaySheet::open(credentials.into_engine()?, key32(own_endpoint)?, clock)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(sheet),
        }))
    }
}

#[uniffi::export]
impl PairingDisplaySheet {
    /// Opens a sheet on the endpoint `own_endpoint` and draws its first code.
    ///
    /// # Errors
    /// [`PairingFfiError::InvalidKeyLength`] for a malformed endpoint id or
    /// expected identity; [`PairingFfiError::Random`] if the random source
    /// fails.
    #[uniffi::constructor]
    pub fn open(
        credentials: PairingCredentials,
        own_endpoint: Vec<u8>,
    ) -> Result<Arc<Self>, PairingFfiError> {
        Self::open_with(credentials, &own_endpoint, Arc::new(kp::SystemClock::new()))
    }

    /// What the sheet is doing now. Replaces an expired code first, so poll
    /// this to keep the shown code current.
    ///
    /// # Errors
    /// [`PairingFfiError::Random`] if a replacement code can't be drawn.
    pub fn status(&self) -> Result<PairingDisplayStatus, PairingFfiError> {
        Ok(match lock(&self.inner).status()? {
            kp::DisplayStatus::ShowingCode {
                code: _,
                reason,
                expires_in,
                runs_left,
            } => PairingDisplayStatus::ShowingCode {
                reason: reason.into(),
                expires_in_ms: millis(expires_in),
                runs_left,
            },
            kp::DisplayStatus::Running => PairingDisplayStatus::Running,
            kp::DisplayStatus::VerifiedAwaitingPeer => PairingDisplayStatus::VerifiedAwaitingPeer,
            kp::DisplayStatus::Verified => PairingDisplayStatus::Verified,
            kp::DisplayStatus::DeadEnd => PairingDisplayStatus::DeadEnd,
        })
    }

    /// The code to show (six ASCII digits), or `None` when the sheet isn't
    /// showing one. Replaces an expired code first, like [`Self::status`].
    ///
    /// The code is the pairing's live secret: put it on screen and nowhere
    /// else. It is kept out of [`PairingDisplayStatus`] so that logging a
    /// status can't log it.
    ///
    /// # Errors
    /// [`PairingFfiError::Random`] if a replacement code can't be drawn.
    pub fn shown_code(&self) -> Result<Option<String>, PairingFfiError> {
        Ok(match lock(&self.inner).status()? {
            kp::DisplayStatus::ShowingCode { code, .. } => Some(code.digits().to_string()),
            _ => None,
        })
    }

    /// Why this sheet's most recent failed run failed, if one has. A run
    /// that times out is failed by whichever call next looks at the clock,
    /// [`Self::status`] included, and a status carries no reason: read it
    /// here.
    pub fn last_failure(&self) -> Option<PairingFailure> {
        lock(&self.inner).last_failure().map(Into::into)
    }

    /// "New Code": a local re-roll. Spends no run.
    ///
    /// # Errors
    /// [`PairingFfiError::WrongState`] unless the sheet is showing a code.
    pub fn new_code(&self) -> Result<(), PairingFfiError> {
        Ok(lock(&self.inner).new_code()?)
    }

    /// Handles a message from `peer`, the endpoint id the transport
    /// authenticated it as.
    ///
    /// # Errors
    /// [`PairingFfiError::InvalidKeyLength`] for a malformed endpoint id;
    /// [`PairingFfiError::Random`] if the random source fails.
    pub fn handle(
        &self,
        peer: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<PairingResponse, PairingFfiError> {
        Ok(lock(&self.inner).handle(key32(&peer)?, &message)?.into())
    }

    /// The run in flight is abandoned (its connection dropped, say). It counts
    /// as failed.
    ///
    /// # Errors
    /// [`PairingFfiError::WrongState`] if no run is in flight.
    pub fn abandon_run(&self) -> Result<PairingOutcomeFfi, PairingFfiError> {
        Ok(lock(&self.inner).abandon_run()?.into())
    }
}

#[cfg(feature = "pairing-test-clock")]
#[uniffi::export]
impl PairingDisplaySheet {
    /// [`Self::open`] on a [`PairingTestClock`]. Test scaffolding.
    ///
    /// # Errors
    /// As [`Self::open`].
    #[uniffi::constructor]
    pub fn open_with_test_clock(
        credentials: PairingCredentials,
        own_endpoint: Vec<u8>,
        clock: Arc<PairingTestClock>,
    ) -> Result<Arc<Self>, PairingFfiError> {
        Self::open_with(credentials, &own_endpoint, clock.inner.clone())
    }
}

// ─── the typing sheet ───────────────────────────────────────────────────────

/// What a typing sheet is doing.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingTypeStatus {
    AwaitingCode { runs_left: u8 },
    Running,
    Verified,
    DeadEnd,
}

/// The sheet on the side that types the code.
#[derive(uniffi::Object)]
pub struct PairingTypeSheet {
    inner: Mutex<kp::TypeSheet>,
}

impl PairingTypeSheet {
    fn open_with(
        credentials: PairingCredentials,
        own_endpoint: &[u8],
        display_endpoint: &[u8],
        clock: Arc<dyn kp::Clock>,
    ) -> Result<Arc<Self>, PairingFfiError> {
        let sheet = kp::TypeSheet::open(
            credentials.into_engine()?,
            key32(own_endpoint)?,
            key32(display_endpoint)?,
            clock,
        );
        Ok(Arc::new(Self {
            inner: Mutex::new(sheet),
        }))
    }
}

#[uniffi::export]
impl PairingTypeSheet {
    /// Opens a sheet on `own_endpoint` to pair with the displaying side at
    /// `display_endpoint`.
    ///
    /// # Errors
    /// [`PairingFfiError::InvalidKeyLength`] for a malformed endpoint id or
    /// expected identity.
    #[uniffi::constructor]
    pub fn open(
        credentials: PairingCredentials,
        own_endpoint: Vec<u8>,
        display_endpoint: Vec<u8>,
    ) -> Result<Arc<Self>, PairingFfiError> {
        Self::open_with(
            credentials,
            &own_endpoint,
            &display_endpoint,
            Arc::new(kp::SystemClock::new()),
        )
    }

    pub fn status(&self) -> PairingTypeStatus {
        match lock(&self.inner).status() {
            kp::TypeStatus::AwaitingCode { runs_left } => {
                PairingTypeStatus::AwaitingCode { runs_left }
            }
            kp::TypeStatus::Running => PairingTypeStatus::Running,
            kp::TypeStatus::Verified => PairingTypeStatus::Verified,
            kp::TypeStatus::DeadEnd => PairingTypeStatus::DeadEnd,
        }
    }

    /// Why this sheet's most recent failed run failed, if one has. A run
    /// that times out is failed by whichever call next looks at the clock,
    /// [`Self::status`] included, and a status carries no reason: read it
    /// here.
    pub fn last_failure(&self) -> Option<PairingFailure> {
        lock(&self.inner).last_failure().map(Into::into)
    }

    /// The person typed `code` (exactly six ASCII digits; strip any grouping
    /// first). Starts a run; returns the message to send.
    ///
    /// # Errors
    /// [`PairingFfiError::MalformedCode`], [`PairingFfiError::WrongState`]
    /// unless the sheet is waiting for a code, or
    /// [`PairingFfiError::Random`].
    pub fn submit_code(&self, code: String) -> Result<Vec<u8>, PairingFfiError> {
        let code = kp::PairingCode::parse(&zeroize::Zeroizing::new(code))?;
        Ok(lock(&self.inner).submit_code(code)?)
    }

    /// Handles a message from `peer`, the endpoint id the transport
    /// authenticated it as. A message from anyone but the displaying side
    /// this sheet was opened against is ignored.
    ///
    /// # Errors
    /// [`PairingFfiError::InvalidKeyLength`] for a malformed endpoint id.
    pub fn handle(
        &self,
        peer: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<PairingResponse, PairingFfiError> {
        Ok(lock(&self.inner).handle(key32(&peer)?, &message).into())
    }

    /// The run in flight is abandoned. It counts as failed.
    ///
    /// # Errors
    /// [`PairingFfiError::WrongState`] if no run is in flight.
    pub fn abandon_run(&self) -> Result<PairingOutcomeFfi, PairingFfiError> {
        Ok(lock(&self.inner).abandon_run()?.into())
    }
}

#[cfg(feature = "pairing-test-clock")]
#[uniffi::export]
impl PairingTypeSheet {
    /// [`Self::open`] on a [`PairingTestClock`]. Test scaffolding.
    ///
    /// # Errors
    /// As [`Self::open`].
    #[uniffi::constructor]
    pub fn open_with_test_clock(
        credentials: PairingCredentials,
        own_endpoint: Vec<u8>,
        display_endpoint: Vec<u8>,
        clock: Arc<PairingTestClock>,
    ) -> Result<Arc<Self>, PairingFfiError> {
        Self::open_with(
            credentials,
            &own_endpoint,
            &display_endpoint,
            clock.inner.clone(),
        )
    }
}

// ─── the verified session ───────────────────────────────────────────────────

/// What was paired.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingKindFfi {
    Device,
    Person,
}

/// A pairing's verified session: carries opaque payloads both ways.
#[derive(uniffi::Object)]
pub struct PairingSession {
    inner: Mutex<kp::VerifiedSession>,
}

#[uniffi::export]
impl PairingSession {
    pub fn kind(&self) -> PairingKindFfi {
        match lock(&self.inner).kind() {
            kp::PairingKind::Device => PairingKindFfi::Device,
            kp::PairingKind::Person => PairingKindFfi::Person,
        }
    }

    /// For a Person pairing, the other account's verified public keys.
    pub fn peer_account(&self) -> Option<PairingAccountPublicKeys> {
        lock(&self.inner).peer_account().map(Into::into)
    }

    /// Whether the other side is known to hold this session too. Always
    /// true on the typing side. On the displaying side it turns true when
    /// the first frame from the typing side opens: until then the displaying
    /// side can't tell a typing side that confirmed from one that never
    /// will, so treat the pairing as complete only once this is true.
    pub fn peer_confirmed(&self) -> bool {
        lock(&self.inner).peer_confirmed()
    }

    /// Seals `payload` as the next frame to send.
    ///
    /// # Errors
    /// [`PairingFfiError::SessionAwaitingPeer`] on the displaying side before
    /// it has opened a frame from the typing side;
    /// [`PairingFfiError::SessionExhausted`];
    /// [`PairingFfiError::SessionPayloadTooLarge`]; or
    /// [`PairingFfiError::FrameRejected`] if the session is spoilt.
    pub fn seal(&self, payload: Vec<u8>) -> Result<Vec<u8>, PairingFfiError> {
        let payload = zeroize::Zeroizing::new(payload);
        Ok(lock(&self.inner).seal(&payload)?)
    }

    /// Opens the next frame received, given `sender`, the endpoint id the
    /// transport authenticated it as.
    ///
    /// # Errors
    /// [`PairingFfiError::InvalidKeyLength`] for a malformed endpoint id.
    /// [`PairingFfiError::SessionWrongSender`] for a message from anyone but
    /// the session's peer and [`PairingFfiError::SessionNotAFrame`] for one
    /// that isn't a session frame: neither touches the session.
    /// [`PairingFfiError::FrameRejected`] for a frame from the peer that is
    /// anything but the next one, intact; after one such rejection the
    /// session refuses everything.
    pub fn open(&self, sender: Vec<u8>, frame: Vec<u8>) -> Result<Vec<u8>, PairingFfiError> {
        let plaintext = lock(&self.inner).open(key32(&sender)?, &frame)?;
        Ok(plaintext.to_vec())
    }
}
