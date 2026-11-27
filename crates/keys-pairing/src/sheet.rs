//! The pairing sheets: the policy around the exchange.
//!
//! A sheet is what a client has open while a pairing can happen; the
//! exchange runs only through an open sheet. The policy it enforces:
//!
//! - **One run per code.** The displaying side's code is consumed the moment
//!   a run starts with it, whatever the run's outcome. A failed run (a typo,
//!   an impostor's guess, a dropped connection, a tampered message) burns it,
//!   and the sheet shows a new one.
//! - **At most [`MAX_RUNS_PER_SHEET`] runs per sheet.** After that many
//!   failures the sheet is a dead end on that side and accepts nothing more.
//!   Each side counts its own failures. A displaying side that hits the dead
//!   end says so to the typing side, which then stops too.
//! - **Codes expire** after [`CODE_LIFETIME`] and are replaced. A Hello that
//!   reaches a code past its lifetime is refused without a run. Once the
//!   sheet has replaced the code (any [`DisplaySheet::status`] call does), a
//!   Hello typed from the old code meets the new one and fails as any wrong
//!   code does: a Hello can't say which code it was typed from without
//!   giving the code away.
//! - **Runs time out**: an unfinished run counts as failed. The code is typed
//!   before a run starts, so a run is machine-paced. Each wait is timed, for
//!   [`RUN_TIMEOUT`], on the side that is waiting and from the moment that
//!   wait began: the displaying side from the Hello to the Reply, the typing
//!   side from its Hello to the Share and then afresh from its Reply to the
//!   Confirm. In a Person pairing each side then waits once more, for the
//!   other's key set: the displaying side from its Confirm, the typing side
//!   from its own key set. No wait is measured across the two devices'
//!   clocks, so a slow first message can't make the typing side give up on
//!   a Confirm the displaying side sent in good time.
//! - **Nothing moves until both confirmations verify.** A side gets its
//!   [`VerifiedSession`] only once it has checked the other side's tag. The
//!   displaying side checks first, so it holds a session before it can know
//!   the typing side has one: its status says so
//!   ([`DisplayStatus::VerifiedAwaitingPeer`]) and its session won't send
//!   until the typing side has spoken.
//! - **A Person pairing verifies on the key sets, not on the code alone.**
//!   After the confirmations each side sends its account's signed key set
//!   inside the session, the typing side first, and a sheet reports the
//!   pairing verified (and hands over the session) only once it has checked
//!   the other side's. Until then the run is still in flight. A key set
//!   that doesn't check out fails the run like a wrong code. The displaying
//!   side sends its key set last, so here too it is "verified, awaiting
//!   peer" until the typing side's next frame.
//! - **A guess is counted once it is spent.** The typing side's Reply carries
//!   its confirmation tag, which lets whoever receives it test one guess at
//!   the code. So from the moment the Reply is sent, anything but the
//!   message the run is waiting for (a valid Confirm, then in a Person
//!   pairing a valid key set) counts as a failed run on the typing side,
//!   unauthenticated refusals included. Before the Reply, a refusal that says no run took
//!   place (the code had expired, the sheet was busy, the Hello wasn't
//!   understood) costs nothing. Everything else that ends a run counts on
//!   the side it ends on even before the Reply (a "run failed" refusal,
//!   garbage, a timeout, abandoning): the count errs towards giving up.
//! - **Each side listens only to its peer.** The displaying side pins a run
//!   to the endpoint that started it and answers nobody else except to turn
//!   a Hello away; the typing side ignores every message that isn't from the
//!   endpoint it was opened against.
//! - **If the random source fails** while a displaying sheet needs the code
//!   that follows a failed run, the sheet becomes a dead end: it keeps
//!   neither the run nor its code alive. If it fails while an expired code
//!   is being replaced, the call errors and the expired code stays unusable
//!   until a later call succeeds; if it fails on "New Code", the code that
//!   was showing stays.
//!
//! **What the transport must provide.** Each run travels on one ordered,
//! reliable connection to an authenticated endpoint; a new run uses a new
//! one, and a sheet's reply goes back only to the sender of the message it
//! answers. The messages carry no run number, so a duplicated or badly late
//! message that reaches a later run is taken as part of it. That can fail
//! runs, and so cost a pair of sheets their budget; it can never make one
//! succeed.
//!
//! **What an attacker in the middle gets.** One guess per run, counted. A
//! party the typing side was pointed at, standing between it and the real
//! displaying side, gets its guesses at one code from two places: the typing
//! side's Reply, and a run of its own against the real displaying side. Each
//! is counted on the sheet it was spent against.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use crate::code::PairingCode;
use crate::protocol::{
    Credentials, DisplayAwaitingReply, DisplayingKeyExchange, DisplayingStep, HelloRejection,
    MessageType, RefuseReason, RunFailure, TypeAwaitingConfirm, TypeAwaitingShare,
    TypingKeyExchange, TypingStep, decode_refuse, display_finish, display_share, encode_refuse,
    parse_hello, type_finish, type_hello, type_reply,
};
use crate::session::VerifiedSession;
use crate::{EndpointId, PairingError};

/// Runs a sheet allows before it becomes a dead end.
pub const MAX_RUNS_PER_SHEET: u8 = 3;
/// How long a displayed code stays usable.
pub const CODE_LIFETIME: Duration = Duration::from_mins(5);
/// How long a started run may take before it counts as failed.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// A monotonic clock, injectable so expiry and timeouts can be tested.
pub trait Clock: Send + Sync {
    /// Time elapsed since some fixed origin. Never less than an earlier
    /// reading.
    fn now(&self) -> Duration;
}

/// Elapsed time that counts a machine's sleep and never runs backwards.
///
/// The monotonic clock never goes backwards but, on some platforms, stops
/// while the machine sleeps, which would keep a code alive across a sleep.
/// The wall clock counts sleep but can be set, forwards or back. So time is
/// accumulated step by step: each reading adds the larger of the two clocks'
/// advances since the previous reading, and a wall clock that went backwards
/// adds nothing. A wall clock pushed forwards ends a code or run early; no
/// change to it can make one last longer than the monotonic clock allows.
#[derive(Debug, Default)]
struct ElapsedTime(Duration);

impl ElapsedTime {
    /// Adds one step. `wall_advance` is `None` if the wall clock went
    /// backwards since the previous reading.
    fn step(&mut self, monotonic_advance: Duration, wall_advance: Option<Duration>) -> Duration {
        let advance = wall_advance.map_or(monotonic_advance, |wall| wall.max(monotonic_advance));
        self.0 = self.0.saturating_add(advance);
        self.0
    }
}

struct SystemClockState {
    elapsed: ElapsedTime,
    last_monotonic: Instant,
    last_wall: SystemTime,
}

/// The real clock: time since the clock was made, never running backwards
/// whatever is done to the wall clock, and counting a sleep (unless the wall
/// clock is set back by the length of the sleep before the next reading).
pub struct SystemClock {
    state: Mutex<SystemClockState>,
}

impl SystemClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SystemClockState {
                elapsed: ElapsedTime::default(),
                last_monotonic: Instant::now(),
                last_wall: SystemTime::now(),
            }),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let monotonic = Instant::now();
        let wall = SystemTime::now();
        let monotonic_advance = monotonic.saturating_duration_since(state.last_monotonic);
        let wall_advance = wall.duration_since(state.last_wall).ok();
        state.last_monotonic = monotonic;
        state.last_wall = wall;
        state.elapsed.step(monotonic_advance, wall_advance)
    }
}

/// A clock that moves only when told to. For tests and the headless driver.
#[derive(Default)]
pub struct ManualClock {
    now: Mutex<Duration>,
}

impl ManualClock {
    pub fn advance(&self, by: Duration) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.saturating_add(by);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Why the displaying side is showing the code it is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeReason {
    /// The sheet's first code.
    Opened,
    /// The person asked for a new code.
    Rerolled,
    /// The previous code expired.
    Expired,
    /// The previous code was burnt by a failed run.
    RunFailed,
}

/// What a displaying sheet is doing.
#[derive(Debug)]
pub enum DisplayStatus {
    /// Showing a code, waiting for a run.
    ShowingCode {
        code: PairingCode,
        reason: CodeReason,
        expires_in: Duration,
        runs_left: u8,
    },
    /// A run is in flight; its code is already spent.
    Running,
    /// This side verified the typing side and handed out its session, but
    /// has not yet heard from the typing side on it, so it can't tell
    /// whether the typing side verified too. **Not yet paired.** If the
    /// typing side stays silent (this side's confirmation was lost, say, or
    /// in a Person pairing its key set was lost or refused), the client
    /// gives up on the pairing; the session can't send in this state.
    VerifiedAwaitingPeer,
    /// Both sides verified: the session has opened a frame from the typing
    /// side.
    Verified,
    /// The sheet is finished without a pairing: the run budget is spent, or
    /// the random source failed when a new code was needed. Start again
    /// over a trusted channel.
    DeadEnd,
}

/// What a typing sheet is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeStatus {
    /// Waiting for the person to type the code.
    AwaitingCode {
        runs_left: u8,
    },
    /// A run is in flight.
    Running,
    Verified,
    DeadEnd,
}

/// What happened when a sheet handled a message (or a call that ends a run).
#[derive(Debug)]
pub enum Outcome {
    /// The run goes on; send the reply.
    Continue,
    /// The message was turned away without a run, so nothing was spent.
    /// For a displaying side this is a refusal it sends. For a typing side
    /// it's a refusal it received: if a run was in flight the sheet is
    /// waiting for a code again, and otherwise nothing changed.
    NoRun(RefuseReason),
    /// The run failed and its code is burnt. The displaying side now shows a
    /// new code; the typing side should ask for it.
    RunFailed { failure: Failure, runs_left: u8 },
    /// The run failed and the sheet is spent.
    DeadEnd { failure: Failure },
    /// This side verified the other and holds a session. On the typing
    /// side everything has now verified. On the displaying side the typing
    /// side's part has, and its own last message is on its way; see
    /// [`DisplayStatus::VerifiedAwaitingPeer`].
    Verified(Box<VerifiedSession>),
    /// The message isn't one this sheet answers from that sender, in its
    /// present state: on the typing side, anything not from the displaying
    /// endpoint, and anything but a refusal when no run is in flight (a late
    /// or duplicated message); on the displaying side, anything but a Hello
    /// from an endpoint that has no run in flight. Nothing changed and
    /// nothing is sent.
    Ignored,
}

/// Why a run ended without verifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The exchange itself failed: a wrong code, a tampered or malformed
    /// message, or an identity that didn't check out.
    Exchange(RunFailure),
    /// The displaying side reported the run failed.
    RefusedByPeer,
    /// The displaying side reported its sheet is spent.
    PeerDeadEnd,
    /// The run didn't finish within [`RUN_TIMEOUT`].
    TimedOut,
    /// The client abandoned the run (the connection dropped, say).
    Abandoned,
}

/// A sheet's answer to a message: what to send back, if anything, and what
/// it means.
#[derive(Debug)]
pub struct Response {
    pub reply: Option<Vec<u8>>,
    pub outcome: Outcome,
}

impl Response {
    fn quiet(outcome: Outcome) -> Self {
        Self {
            reply: None,
            outcome,
        }
    }
}

/// Counts failed runs and says whether the sheet is now spent.
fn record_failure(failed_runs: &mut u8, failure: Failure) -> Outcome {
    *failed_runs = failed_runs.saturating_add(1);
    if *failed_runs >= MAX_RUNS_PER_SHEET {
        Outcome::DeadEnd { failure }
    } else {
        Outcome::RunFailed {
            failure,
            runs_left: MAX_RUNS_PER_SHEET - *failed_runs,
        }
    }
}

// ─── displaying side ────────────────────────────────────────────────────────

enum DisplayState {
    Showing {
        code: PairingCode,
        reason: CodeReason,
        issued_at: Duration,
    },
    /// A run is in flight with `peer`, waiting since `waiting_since` for
    /// its next message.
    Running {
        run: DisplayRun,
        peer: EndpointId,
        waiting_since: Duration,
    },
    /// The session is out. The flag is the session's own: true once it has
    /// opened a frame from the typing side.
    Verified {
        peer_confirmed: Arc<AtomicBool>,
    },
    DeadEnd,
}

/// What a displaying side's run in flight is waiting for.
enum DisplayRun {
    /// The Share is out: the typing side's Reply.
    AwaitingReply(Box<DisplayAwaitingReply>),
    /// A Person pairing whose Confirm is out: the typing side's key set.
    AwaitingPeerKeys(Box<DisplayingKeyExchange>),
}

/// The sheet on the side that shows the code: for a device pairing, the
/// device already in the account; for a Person pairing, the invite's opener.
pub struct DisplaySheet {
    credentials: Credentials,
    own_endpoint: EndpointId,
    clock: Arc<dyn Clock>,
    failed_runs: u8,
    last_failure: Option<Failure>,
    state: DisplayState,
}

impl DisplaySheet {
    /// Opens a sheet and draws its first code.
    ///
    /// # Errors
    /// [`PairingError::Random`] if the system random source fails.
    pub fn open(
        credentials: Credentials,
        own_endpoint: EndpointId,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PairingError> {
        let issued_at = clock.now();
        Ok(Self {
            credentials,
            own_endpoint,
            clock,
            failed_runs: 0,
            last_failure: None,
            state: DisplayState::Showing {
                code: PairingCode::generate()?,
                reason: CodeReason::Opened,
                issued_at,
            },
        })
    }

    /// Shows a fresh code. If none can be drawn the state is left as it was.
    fn show_new_code(&mut self, reason: CodeReason, now: Duration) -> Result<(), PairingError> {
        self.state = DisplayState::Showing {
            code: PairingCode::generate()?,
            reason,
            issued_at: now,
        };
        Ok(())
    }

    fn code_expired(&self, now: Duration) -> bool {
        matches!(&self.state, DisplayState::Showing { issued_at, .. }
            if now.saturating_sub(*issued_at) >= CODE_LIFETIME)
    }

    /// Replaces an expired code and fails a timed-out run. Returns the outcome
    /// of a run that timed out, if one did.
    fn refresh(&mut self, now: Duration) -> Result<Option<Outcome>, PairingError> {
        if self.code_expired(now) {
            self.show_new_code(CodeReason::Expired, now)?;
            return Ok(None);
        }
        match &self.state {
            DisplayState::Running { waiting_since, .. }
                if now.saturating_sub(*waiting_since) >= RUN_TIMEOUT =>
            {
                Ok(Some(self.fail_run(Failure::TimedOut, now)?))
            }
            _ => Ok(None),
        }
    }

    /// Counts a failed run and shows the next code, or ends the sheet.
    fn fail_run(&mut self, failure: Failure, now: Duration) -> Result<Outcome, PairingError> {
        self.last_failure = Some(failure);
        let outcome = record_failure(&mut self.failed_runs, failure);
        // The run and its code are gone before anything can fail: if no
        // replacement code can be drawn, the sheet stays a dead end.
        self.state = DisplayState::DeadEnd;
        if !matches!(outcome, Outcome::DeadEnd { .. }) {
            self.show_new_code(CodeReason::RunFailed, now)?;
        }
        Ok(outcome)
    }

    /// What the sheet is doing now, replacing an expired code first.
    ///
    /// # Errors
    /// [`PairingError::Random`] if a replacement code can't be drawn.
    pub fn status(&mut self) -> Result<DisplayStatus, PairingError> {
        let now = self.clock.now();
        self.refresh(now)?;
        let runs_left = MAX_RUNS_PER_SHEET - self.failed_runs;
        Ok(match &self.state {
            DisplayState::Showing {
                code,
                reason,
                issued_at,
            } => DisplayStatus::ShowingCode {
                code: code.clone(),
                reason: *reason,
                expires_in: CODE_LIFETIME.saturating_sub(now.saturating_sub(*issued_at)),
                runs_left,
            },
            DisplayState::Running { .. } => DisplayStatus::Running,
            DisplayState::Verified { peer_confirmed } => {
                if peer_confirmed.load(Ordering::Acquire) {
                    DisplayStatus::Verified
                } else {
                    DisplayStatus::VerifiedAwaitingPeer
                }
            }
            DisplayState::DeadEnd => DisplayStatus::DeadEnd,
        })
    }

    /// Fuzzing builds only (`--cfg fuzzing`): the code showing at this
    /// instant, without first settling an expired code or a timed-out run as
    /// [`Self::status`] does. Lets a fuzz harness know which code a run
    /// consumed without disturbing what it is testing.
    #[cfg(fuzzing)]
    #[must_use]
    pub fn shown_code_without_refresh_for_fuzzing(&self) -> Option<PairingCode> {
        match &self.state {
            DisplayState::Showing { code, .. } => Some(code.clone()),
            _ => None,
        }
    }

    /// Why this sheet's most recent failed run failed, if one has. A run
    /// that times out is failed by whichever call next looks at the clock,
    /// [`Self::status`] included, and only [`Self::handle`] and
    /// [`Self::abandon_run`] return an [`Outcome`]: this is how a client
    /// that polls the status learns what a lost run was lost to.
    #[must_use]
    pub fn last_failure(&self) -> Option<Failure> {
        self.last_failure
    }

    /// "New Code": replaces the shown code with a fresh one. A local re-roll;
    /// it spends no run.
    ///
    /// # Errors
    /// [`PairingError::WrongState`] unless the sheet is showing a code.
    pub fn new_code(&mut self) -> Result<(), PairingError> {
        let now = self.clock.now();
        self.refresh(now)?;
        match self.state {
            DisplayState::Showing { .. } => self.show_new_code(CodeReason::Rerolled, now),
            _ => Err(PairingError::WrongState),
        }
    }

    /// Handles a message from the endpoint `peer`, as the transport
    /// authenticated it.
    ///
    /// The sheet answers two things only: a Hello, from anyone (with a Share
    /// or a refusal), and whatever the peer of the run in flight sends next
    /// (taken as what the run is waiting for: its Reply, then in a Person
    /// pairing its key set). Everything else is [`Outcome::Ignored`].
    ///
    /// # Errors
    /// [`PairingError::Random`] if the system random source fails.
    pub fn handle(&mut self, peer: EndpointId, message: &[u8]) -> Result<Response, PairingError> {
        let now = self.clock.now();
        let is_hello = MessageType::of(message) == Some(MessageType::Hello);
        let expired_before = self.code_expired(now);
        let from_run_peer = matches!(&self.state, DisplayState::Running { peer: run_peer, .. } if *run_peer == peer);
        if let Some(timed_out) = self.refresh(now)? {
            return Ok(Self::after_timeout(timed_out, is_hello, from_run_peer));
        }
        match &self.state {
            DisplayState::Showing { .. } if is_hello => {
                self.handle_hello(peer, message, expired_before, now)
            }
            DisplayState::Running { .. } if is_hello => Ok(Self::refusal(RefuseReason::Busy)),
            DisplayState::Running { .. } if from_run_peer => self.handle_run_message(message, now),
            DisplayState::Verified { .. } | DisplayState::DeadEnd if is_hello => {
                Ok(Self::refusal(RefuseReason::DeadEnd))
            }
            _ => Ok(Response::quiet(Outcome::Ignored)),
        }
    }

    /// The answer to the message that found the run in flight timed out.
    /// The client always gets the timeout as the outcome. What goes back to
    /// the sender:
    /// - if the timeout spent the sheet, a Hello or the run's own peer is
    ///   told so;
    /// - otherwise a Hello, even the run's own peer trying again, is turned
    ///   away with no run of its own counted (the code it was typed from is
    ///   gone either way), and the run's own peer's late message is told the
    ///   run failed;
    /// - anyone else gets nothing.
    fn after_timeout(timed_out: Outcome, is_hello: bool, from_run_peer: bool) -> Response {
        let sheet_spent = matches!(timed_out, Outcome::DeadEnd { .. });
        let reason = if sheet_spent && (is_hello || from_run_peer) {
            Some(RefuseReason::DeadEnd)
        } else if is_hello {
            Some(RefuseReason::CodeExpired)
        } else if from_run_peer {
            Some(RefuseReason::RunFailed)
        } else {
            None
        };
        Response {
            reply: reason.map(encode_refuse),
            outcome: timed_out,
        }
    }

    fn refusal(reason: RefuseReason) -> Response {
        Response {
            reply: Some(encode_refuse(reason)),
            outcome: Outcome::NoRun(reason),
        }
    }

    /// A Hello while a code is showing.
    fn handle_hello(
        &mut self,
        peer: EndpointId,
        message: &[u8],
        expired_before: bool,
        now: Duration,
    ) -> Result<Response, PairingError> {
        if expired_before {
            return Ok(Self::refusal(RefuseReason::CodeExpired));
        }
        let hello = match parse_hello(message, self.credentials.kind()) {
            Ok(hello) => hello,
            Err(HelloRejection::Malformed | HelloRejection::Unsupported) => {
                return Ok(Self::refusal(RefuseReason::Unsupported));
            }
        };
        // The code is spent from here on, whatever happens to the run.
        let DisplayState::Showing { code, .. } =
            std::mem::replace(&mut self.state, DisplayState::DeadEnd)
        else {
            unreachable!("handle_hello is called only while a code is showing");
        };
        match display_share(
            self.credentials.clone(),
            self.own_endpoint,
            peer,
            &hello,
            &code,
        ) {
            Ok((run, share)) => {
                self.state = DisplayState::Running {
                    run: DisplayRun::AwaitingReply(Box::new(run)),
                    peer,
                    waiting_since: now,
                };
                Ok(Response {
                    reply: Some(share),
                    outcome: Outcome::Continue,
                })
            }
            Err(failure) => self.failed_run_response(Failure::Exchange(failure), now),
        }
    }

    /// The next message from the peer of the run in flight: what the run is
    /// waiting for, or something that fails the run for not being that.
    fn handle_run_message(
        &mut self,
        message: &[u8],
        now: Duration,
    ) -> Result<Response, PairingError> {
        let DisplayState::Running { run, peer, .. } =
            std::mem::replace(&mut self.state, DisplayState::DeadEnd)
        else {
            unreachable!("handle_run_message is called only while a run is in flight");
        };
        let step = match run {
            DisplayRun::AwaitingReply(run) => display_finish(*run, message),
            DisplayRun::AwaitingPeerKeys(keys) => keys
                .finish(message)
                .map(|(session, own_keys)| (DisplayingStep::Verified(session), own_keys)),
        };
        match step {
            Ok((DisplayingStep::Verified(session), reply)) => {
                self.state = DisplayState::Verified {
                    peer_confirmed: session.peer_confirmed_flag(),
                };
                Ok(Response {
                    reply: Some(reply),
                    outcome: Outcome::Verified(Box::new(session)),
                })
            }
            Ok((DisplayingStep::AwaitingPeerKeys(keys), confirm)) => {
                // A new wait starts with the Confirm: the typing side's key
                // set is timed from here.
                self.state = DisplayState::Running {
                    run: DisplayRun::AwaitingPeerKeys(Box::new(keys)),
                    peer,
                    waiting_since: now,
                };
                Ok(Response {
                    reply: Some(confirm),
                    outcome: Outcome::Continue,
                })
            }
            Err(failure) => self.failed_run_response(Failure::Exchange(failure), now),
        }
    }

    /// Fails the run and tells its peer.
    fn failed_run_response(
        &mut self,
        failure: Failure,
        now: Duration,
    ) -> Result<Response, PairingError> {
        let outcome = self.fail_run(failure, now)?;
        Ok(Response {
            reply: Some(encode_refuse(refusal_for(&outcome))),
            outcome,
        })
    }

    /// The client gave up on the run in flight (its connection dropped, say).
    /// The run counts as failed.
    ///
    /// # Errors
    /// [`PairingError::WrongState`] if no run is in flight;
    /// [`PairingError::Random`] if the next code can't be drawn (the sheet is
    /// then a dead end).
    pub fn abandon_run(&mut self) -> Result<Outcome, PairingError> {
        let now = self.clock.now();
        match self.state {
            DisplayState::Running { .. } => self.fail_run(Failure::Abandoned, now),
            _ => Err(PairingError::WrongState),
        }
    }
}

/// The refusal a displaying side sends after a run fails.
fn refusal_for(outcome: &Outcome) -> RefuseReason {
    match outcome {
        Outcome::DeadEnd { .. } => RefuseReason::DeadEnd,
        _ => RefuseReason::RunFailed,
    }
}

// ─── typing side ────────────────────────────────────────────────────────────

enum TypeState {
    AwaitingCode,
    /// Waiting for the Share since the Hello was made.
    AwaitingShare {
        run: Box<TypeAwaitingShare>,
        waiting_since: Duration,
    },
    /// Waiting for the Confirm since the Reply was made.
    AwaitingConfirm {
        run: Box<TypeAwaitingConfirm>,
        waiting_since: Duration,
    },
    /// A Person pairing: waiting for the displaying side's key set since
    /// this side's was sent.
    AwaitingPeerKeys {
        keys: Box<TypingKeyExchange>,
        waiting_since: Duration,
    },
    Verified,
    DeadEnd,
}

/// The sheet on the side that types the code: for a device pairing, the new
/// device; for a Person pairing, the inviter.
pub struct TypeSheet {
    credentials: Credentials,
    own_endpoint: EndpointId,
    display_endpoint: EndpointId,
    clock: Arc<dyn Clock>,
    failed_runs: u8,
    last_failure: Option<Failure>,
    state: TypeState,
}

impl TypeSheet {
    /// Opens a sheet to pair with the displaying side at `display_endpoint`.
    pub fn open(
        credentials: Credentials,
        own_endpoint: EndpointId,
        display_endpoint: EndpointId,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            credentials,
            own_endpoint,
            display_endpoint,
            clock,
            failed_runs: 0,
            last_failure: None,
            state: TypeState::AwaitingCode,
        }
    }

    fn fail_run(&mut self, failure: Failure) -> Outcome {
        self.last_failure = Some(failure);
        let outcome = record_failure(&mut self.failed_runs, failure);
        self.state = if matches!(outcome, Outcome::DeadEnd { .. }) {
            TypeState::DeadEnd
        } else {
            TypeState::AwaitingCode
        };
        outcome
    }

    /// Fails the run in flight if its current wait has run out of time.
    fn refresh(&mut self, now: Duration) -> Option<Outcome> {
        let waiting_since = match &self.state {
            TypeState::AwaitingShare { waiting_since, .. }
            | TypeState::AwaitingConfirm { waiting_since, .. }
            | TypeState::AwaitingPeerKeys { waiting_since, .. } => *waiting_since,
            _ => return None,
        };
        (now.saturating_sub(waiting_since) >= RUN_TIMEOUT).then(|| self.fail_run(Failure::TimedOut))
    }

    /// Why this sheet's most recent failed run failed, if one has. A run
    /// that times out is failed by whichever call next looks at the clock,
    /// [`Self::status`] included, and only [`Self::handle`] and
    /// [`Self::abandon_run`] return an [`Outcome`]: this is how a client
    /// that polls the status learns what a lost run was lost to.
    #[must_use]
    pub fn last_failure(&self) -> Option<Failure> {
        self.last_failure
    }

    pub fn status(&mut self) -> TypeStatus {
        let now = self.clock.now();
        self.refresh(now);
        match self.state {
            TypeState::AwaitingCode => TypeStatus::AwaitingCode {
                runs_left: MAX_RUNS_PER_SHEET - self.failed_runs,
            },
            TypeState::AwaitingShare { .. }
            | TypeState::AwaitingConfirm { .. }
            | TypeState::AwaitingPeerKeys { .. } => TypeStatus::Running,
            TypeState::Verified => TypeStatus::Verified,
            TypeState::DeadEnd => TypeStatus::DeadEnd,
        }
    }

    /// The person typed a code: starts a run with it and returns the Hello to
    /// send to the displaying side.
    ///
    /// # Errors
    /// [`PairingError::WrongState`] unless the sheet is waiting for a code;
    /// [`PairingError::Random`] if the system random source fails.
    pub fn submit_code(&mut self, code: PairingCode) -> Result<Vec<u8>, PairingError> {
        let now = self.clock.now();
        self.refresh(now);
        if !matches!(self.state, TypeState::AwaitingCode) {
            return Err(PairingError::WrongState);
        }
        let (run, hello) = type_hello(
            self.credentials.clone(),
            self.own_endpoint,
            self.display_endpoint,
            code,
        )
        .map_err(|_| PairingError::Random)?;
        self.state = TypeState::AwaitingShare {
            run: Box::new(run),
            waiting_since: now,
        };
        Ok(hello)
    }

    /// Handles a message from the endpoint `peer`, as the transport
    /// authenticated it. A message from anyone but the displaying side this
    /// sheet was opened against is ignored: the endpoint ids in the
    /// transcript are public, so without this check a third party could feed
    /// the sheet a Share of its own, or a refusal.
    pub fn handle(&mut self, peer: EndpointId, message: &[u8]) -> Response {
        if peer != self.display_endpoint {
            return Response::quiet(Outcome::Ignored);
        }
        let now = self.clock.now();
        if let Some(timed_out) = self.refresh(now) {
            return Response::quiet(timed_out);
        }
        if let Some(reason) = decode_refuse(message) {
            return self.handle_refuse(reason);
        }
        match std::mem::replace(&mut self.state, TypeState::DeadEnd) {
            TypeState::AwaitingShare { run, .. } => match type_reply(*run, message) {
                Ok((run, reply)) => {
                    // A new wait starts with the Reply: the Confirm is timed
                    // from here, not from the Hello.
                    self.state = TypeState::AwaitingConfirm {
                        run: Box::new(run),
                        waiting_since: now,
                    };
                    Response {
                        reply: Some(reply),
                        outcome: Outcome::Continue,
                    }
                }
                Err(failure) => Response::quiet(self.fail_run(Failure::Exchange(failure))),
            },
            TypeState::AwaitingConfirm { run, .. } => match type_finish(*run, message) {
                Ok(TypingStep::Verified(session)) => self.verified(session),
                Ok(TypingStep::AwaitingPeerKeys { own_keys, exchange }) => {
                    // The displaying side proved the code, so this side's
                    // key set goes out, inside the session. The displaying
                    // side's is timed from here.
                    self.state = TypeState::AwaitingPeerKeys {
                        keys: Box::new(exchange),
                        waiting_since: now,
                    };
                    Response {
                        reply: Some(own_keys),
                        outcome: Outcome::Continue,
                    }
                }
                Err(failure) => Response::quiet(self.fail_run(Failure::Exchange(failure))),
            },
            TypeState::AwaitingPeerKeys { keys, .. } => match keys.finish(message) {
                Ok(session) => self.verified(session),
                Err(failure) => Response::quiet(self.fail_run(Failure::Exchange(failure))),
            },
            idle_or_done => {
                // Nothing in flight: the message is late, duplicated or
                // stray, and answers no run of this sheet's.
                self.state = idle_or_done;
                Response::quiet(Outcome::Ignored)
            }
        }
    }

    fn verified(&mut self, session: VerifiedSession) -> Response {
        self.state = TypeState::Verified;
        Response::quiet(Outcome::Verified(Box::new(session)))
    }

    fn handle_refuse(&mut self, reason: RefuseReason) -> Response {
        let reply_sent = match self.state {
            TypeState::AwaitingShare { .. } => false,
            TypeState::AwaitingConfirm { .. } | TypeState::AwaitingPeerKeys { .. } => true,
            TypeState::AwaitingCode | TypeState::Verified | TypeState::DeadEnd => {
                return Response::quiet(Outcome::NoRun(reason));
            }
        };
        match reason {
            RefuseReason::DeadEnd => {
                self.state = TypeState::DeadEnd;
                self.last_failure = Some(Failure::PeerDeadEnd);
                Response::quiet(Outcome::DeadEnd {
                    failure: Failure::PeerDeadEnd,
                })
            }
            RefuseReason::RunFailed => Response::quiet(self.fail_run(Failure::RefusedByPeer)),
            RefuseReason::CodeExpired | RefuseReason::Busy | RefuseReason::Unsupported => {
                if reply_sent {
                    // The Reply is out, so a guess at the code is spent: a
                    // refusal can't hand it back, whatever reason it gives.
                    Response::quiet(self.fail_run(Failure::RefusedByPeer))
                } else {
                    // Turned away before the Reply: nothing spent, type the
                    // code again.
                    self.state = TypeState::AwaitingCode;
                    Response::quiet(Outcome::NoRun(reason))
                }
            }
        }
    }

    /// The client gave up on the run in flight. It counts as failed.
    ///
    /// # Errors
    /// [`PairingError::WrongState`] if no run is in flight.
    pub fn abandon_run(&mut self) -> Result<Outcome, PairingError> {
        match self.state {
            TypeState::AwaitingShare { .. }
            | TypeState::AwaitingConfirm { .. }
            | TypeState::AwaitingPeerKeys { .. } => Ok(self.fail_run(Failure::Abandoned)),
            _ => Err(PairingError::WrongState),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AccountKeys, AccountPublicKeys};

    const DISPLAY: EndpointId = [0xd1; 32];
    const TYPING: EndpointId = [0x71; 32];

    fn sheets(clock: &Arc<ManualClock>) -> (DisplaySheet, TypeSheet) {
        let clock: Arc<dyn Clock> = clock.clone();
        (
            DisplaySheet::open(Credentials::Device, DISPLAY, Arc::clone(&clock)).unwrap(),
            TypeSheet::open(Credentials::Device, TYPING, DISPLAY, clock),
        )
    }

    fn shown_code(display: &mut DisplaySheet) -> (PairingCode, CodeReason) {
        match display.status().unwrap() {
            DisplayStatus::ShowingCode { code, reason, .. } => (code, reason),
            other => panic!("not showing a code: {other:?}"),
        }
    }

    /// Runs `body` with this thread's random bytes scripted, so the codes
    /// it draws are the same every time. For tests that need two codes to
    /// differ: with real randomness they would collide once in a million
    /// runs.
    fn with_fixed_codes(body: impl FnOnce()) {
        crate::random::scripted::with_seed(b"keys-pairing sheet tests", body);
    }

    /// A code one digit off `code`. Built on the stack, so the freed-memory
    /// test can use it without leaving digits behind itself.
    fn wrong(code: &PairingCode) -> PairingCode {
        let mut digits = [0u8; crate::code::CODE_DIGITS];
        digits.copy_from_slice(code.prs());
        digits[0] = if digits[0] == b'9' {
            b'0'
        } else {
            digits[0] + 1
        };
        PairingCode::parse(std::str::from_utf8(&digits).unwrap()).unwrap()
    }

    /// Drives one run end to end; returns (display outcome, typing outcome).
    fn run(
        display: &mut DisplaySheet,
        typing: &mut TypeSheet,
        typed: PairingCode,
    ) -> (Outcome, Outcome) {
        let hello = typing.submit_code(typed).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        let Outcome::Continue = share.outcome else {
            let refusal = share.reply.unwrap();
            return (share.outcome, typing.handle(DISPLAY, &refusal).outcome);
        };
        let reply = typing.handle(DISPLAY, &share.reply.unwrap());
        let Outcome::Continue = reply.outcome else {
            return (Outcome::Continue, reply.outcome);
        };
        finish_run(display, typing, &reply.reply.unwrap())
    }

    /// Carries a run from the typing side's Reply to its end: the Confirm
    /// and, for a Person pairing, the two key sets. Returns (display
    /// outcome, typing outcome).
    fn finish_run(
        display: &mut DisplaySheet,
        typing: &mut TypeSheet,
        reply: &[u8],
    ) -> (Outcome, Outcome) {
        let mut from_display = display.handle(TYPING, reply).unwrap();
        let mut from_typing = typing.handle(DISPLAY, &from_display.reply.take().unwrap());
        if let Some(typing_keys) = from_typing.reply.take() {
            from_display = display.handle(TYPING, &typing_keys).unwrap();
            from_typing = typing.handle(DISPLAY, &from_display.reply.take().unwrap());
        }
        (from_display.outcome, from_typing.outcome)
    }

    /// A displaying and a typing sheet for a Person pairing between two
    /// fresh accounts, with what each side expects of the other's identity.
    fn person_sheets(
        clock: &Arc<ManualClock>,
        display_expects: impl FnOnce(&AccountPublicKeys) -> Option<[u8; 32]>,
        typing_expects: impl FnOnce(&AccountPublicKeys) -> Option<[u8; 32]>,
    ) -> (
        DisplaySheet,
        TypeSheet,
        AccountPublicKeys,
        AccountPublicKeys,
    ) {
        let displaying_account = Arc::new(AccountKeys::generate().unwrap().0);
        let typing_account = Arc::new(AccountKeys::generate().unwrap().0);
        let (display_keys, typing_keys) = (
            displaying_account.public_keys(),
            typing_account.public_keys(),
        );
        let display = DisplaySheet::open(
            Credentials::Person {
                account: displaying_account,
                expected_peer_identity: display_expects(&typing_keys),
            },
            DISPLAY,
            clock.clone() as Arc<dyn Clock>,
        )
        .unwrap();
        let typing = TypeSheet::open(
            Credentials::Person {
                account: typing_account,
                expected_peer_identity: typing_expects(&display_keys),
            },
            TYPING,
            DISPLAY,
            clock.clone() as Arc<dyn Clock>,
        );
        (display, typing, display_keys, typing_keys)
    }

    /// A Person run up to the point where the typing side has verified the
    /// Confirm and its key set is on its way: returns that key-set frame.
    fn person_run_to_typing_keys(display: &mut DisplaySheet, typing: &mut TypeSheet) -> Vec<u8> {
        let (code, _) = shown_code(display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        let reply = typing.handle(DISPLAY, &share.reply.unwrap());
        let confirm = display.handle(TYPING, &reply.reply.unwrap()).unwrap();
        // The code is proved to the displaying side, but a Person pairing
        // isn't verified until the key sets are.
        assert!(matches!(confirm.outcome, Outcome::Continue));
        assert!(matches!(display.status().unwrap(), DisplayStatus::Running));
        let keys = typing.handle(DISPLAY, &confirm.reply.unwrap());
        assert!(matches!(keys.outcome, Outcome::Continue));
        assert_eq!(typing.status(), TypeStatus::Running);
        keys.reply.unwrap()
    }

    #[test]
    fn the_right_code_verifies_both_sheets() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, reason) = shown_code(&mut display);
        assert_eq!(reason, CodeReason::Opened);
        let (d, t) = run(&mut display, &mut typing, code);
        let (Outcome::Verified(mut display_session), Outcome::Verified(mut typing_session)) =
            (d, t)
        else {
            panic!("both sides verify");
        };
        // The displaying side holds a session but hasn't heard from the
        // typing side on it: not paired yet, and it says so.
        assert!(matches!(
            display.status().unwrap(),
            DisplayStatus::VerifiedAwaitingPeer
        ));
        let frame = typing_session.seal(b"device keys").unwrap();
        display_session.open(TYPING, &frame).unwrap();
        assert!(matches!(display.status().unwrap(), DisplayStatus::Verified));
        assert_eq!(typing.status(), TypeStatus::Verified);
    }

    #[test]
    fn a_wrong_code_burns_it_and_a_new_one_works() {
        with_fixed_codes(|| {
            let clock = Arc::new(ManualClock::default());
            let (mut display, mut typing) = sheets(&clock);
            let (first, _) = shown_code(&mut display);
            let (d, t) = run(&mut display, &mut typing, wrong(&first));
            assert!(matches!(d, Outcome::RunFailed { runs_left: 2, .. }));
            assert!(matches!(
                t,
                Outcome::RunFailed {
                    runs_left: 2,
                    failure: Failure::RefusedByPeer
                }
            ));

            let (second, reason) = shown_code(&mut display);
            assert_eq!(reason, CodeReason::RunFailed);
            assert_ne!(first.digits(), second.digits());
            // The burnt code is useless now.
            let (d, _) = run(&mut display, &mut typing, first);
            assert!(matches!(d, Outcome::RunFailed { runs_left: 1, .. }));
            let (third, _) = shown_code(&mut display);
            let (d, t) = run(&mut display, &mut typing, third);
            assert!(matches!(d, Outcome::Verified(_)));
            assert!(matches!(t, Outcome::Verified(_)));
        });
    }

    #[test]
    fn three_failures_reach_the_dead_end_on_both_sides() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        for runs_left in [2, 1] {
            let (code, _) = shown_code(&mut display);
            let (d, t) = run(&mut display, &mut typing, wrong(&code));
            assert!(matches!(d, Outcome::RunFailed { runs_left: left, .. } if left == runs_left));
            assert!(matches!(t, Outcome::RunFailed { runs_left: left, .. } if left == runs_left));
        }
        let (code, _) = shown_code(&mut display);
        let (d, t) = run(&mut display, &mut typing, wrong(&code));
        assert!(matches!(d, Outcome::DeadEnd { .. }));
        assert!(matches!(t, Outcome::DeadEnd { .. }));
        assert!(matches!(display.status().unwrap(), DisplayStatus::DeadEnd));
        assert_eq!(typing.status(), TypeStatus::DeadEnd);
        assert!(matches!(
            typing.submit_code(code),
            Err(PairingError::WrongState)
        ));
        assert!(matches!(display.new_code(), Err(PairingError::WrongState)));
    }

    #[test]
    fn impostor_guesses_count_against_the_displaying_sheet() {
        with_fixed_codes(|| {
            let clock = Arc::new(ManualClock::default());
            let (mut display, mut typing) = sheets(&clock);
            let impostor_endpoint: EndpointId = [0x66; 32];
            for _ in 0..MAX_RUNS_PER_SHEET {
                let mut impostor = TypeSheet::open(
                    Credentials::Device,
                    impostor_endpoint,
                    DISPLAY,
                    clock.clone() as Arc<dyn Clock>,
                );
                let hello = impostor
                    .submit_code(PairingCode::parse("000000").unwrap())
                    .unwrap();
                let share = display.handle(impostor_endpoint, &hello).unwrap();
                let reply = impostor
                    .handle(DISPLAY, &share.reply.unwrap())
                    .reply
                    .unwrap();
                let _ = display.handle(impostor_endpoint, &reply).unwrap();
            }
            assert!(matches!(display.status().unwrap(), DisplayStatus::DeadEnd));
            // The genuine typer is now told the sheet is spent.
            let hello = typing
                .submit_code(PairingCode::parse("123456").unwrap())
                .unwrap();
            let refusal = display.handle(TYPING, &hello).unwrap();
            assert!(matches!(
                refusal.outcome,
                Outcome::NoRun(RefuseReason::DeadEnd)
            ));
            let t = typing.handle(DISPLAY, &refusal.reply.unwrap());
            assert!(matches!(
                t.outcome,
                Outcome::DeadEnd {
                    failure: Failure::PeerDeadEnd
                }
            ));
            // A client that only polls the status can read the reason too.
            assert_eq!(typing.status(), TypeStatus::DeadEnd);
            assert_eq!(typing.last_failure(), Some(Failure::PeerDeadEnd));
        });
    }

    #[test]
    fn an_expired_code_is_replaced_and_its_hello_refused_without_a_run() {
        with_fixed_codes(|| {
            let clock = Arc::new(ManualClock::default());
            let (mut display, mut typing) = sheets(&clock);
            let (old, _) = shown_code(&mut display);
            clock.advance(CODE_LIFETIME);
            let hello = typing.submit_code(old.clone()).unwrap();
            let refusal = display.handle(TYPING, &hello).unwrap();
            assert!(matches!(
                refusal.outcome,
                Outcome::NoRun(RefuseReason::CodeExpired)
            ));
            let t = typing.handle(DISPLAY, &refusal.reply.unwrap());
            assert!(matches!(
                t.outcome,
                Outcome::NoRun(RefuseReason::CodeExpired)
            ));
            assert_eq!(
                typing.status(),
                TypeStatus::AwaitingCode {
                    runs_left: MAX_RUNS_PER_SHEET
                }
            );

            let (new, reason) = shown_code(&mut display);
            assert_eq!(reason, CodeReason::Expired);
            assert_ne!(old.digits(), new.digits());
            let (d, _) = run(&mut display, &mut typing, new);
            assert!(matches!(d, Outcome::Verified(_)));
        });
    }

    #[test]
    fn status_reports_time_left_on_the_code() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, _) = sheets(&clock);
        clock.advance(Duration::from_secs(60));
        let DisplayStatus::ShowingCode { expires_in, .. } = display.status().unwrap() else {
            panic!("showing a code");
        };
        assert_eq!(
            Some(expires_in),
            CODE_LIFETIME.checked_sub(Duration::from_secs(60))
        );
    }

    #[test]
    fn new_code_rerolls_without_spending_a_run() {
        with_fixed_codes(|| {
            let clock = Arc::new(ManualClock::default());
            let (mut display, mut typing) = sheets(&clock);
            let (old, _) = shown_code(&mut display);
            display.new_code().unwrap();
            let (new, reason) = shown_code(&mut display);
            assert_eq!(reason, CodeReason::Rerolled);
            let DisplayStatus::ShowingCode { runs_left, .. } = display.status().unwrap() else {
                panic!("showing a code");
            };
            assert_eq!(runs_left, MAX_RUNS_PER_SHEET);
            let (d, _) = run(&mut display, &mut typing, old);
            assert!(matches!(d, Outcome::RunFailed { .. }));
            let _ = new;
        });
    }

    #[test]
    fn a_hello_this_sheet_cannot_run_costs_neither_the_code_nor_a_run() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, _) = shown_code(&mut display);
        let genuine = typing.submit_code(code.clone()).unwrap();
        // Byte 1 is the version and byte 2 the kind.
        let mut other_version = genuine.clone();
        other_version[1] ^= 0x7f;
        let mut other_kind = genuine.clone();
        other_kind[2] ^= 0x7f;
        let truncated = &genuine[..genuine.len() - 1];
        for hello in [&other_version[..], &other_kind[..], truncated] {
            let refusal = display.handle(TYPING, hello).unwrap();
            assert!(matches!(
                refusal.outcome,
                Outcome::NoRun(RefuseReason::Unsupported)
            ));
            assert!(refusal.reply.is_some());
        }
        // The same code is still showing, on a full budget, and it works.
        let DisplayStatus::ShowingCode {
            code: still_shown,
            reason,
            runs_left,
            ..
        } = display.status().unwrap()
        else {
            panic!("showing a code");
        };
        assert_eq!(still_shown.digits(), code.digits());
        assert_eq!(reason, CodeReason::Opened);
        assert_eq!(runs_left, MAX_RUNS_PER_SHEET);
        let share = display.handle(TYPING, &genuine).unwrap();
        assert!(matches!(share.outcome, Outcome::Continue));
    }

    #[test]
    fn a_failed_run_with_no_random_source_for_the_next_code_is_a_dead_end() {
        with_fixed_codes(|| {
            let clock = Arc::new(ManualClock::default());
            let (mut display, mut typing) = sheets(&clock);
            let (code, _) = shown_code(&mut display);
            let hello = typing.submit_code(wrong(&code)).unwrap();
            let share = display.handle(TYPING, &hello).unwrap();
            let reply = typing.handle(DISPLAY, &share.reply.unwrap()).reply.unwrap();

            crate::random::scripted::set_failing(true);
            assert!(matches!(
                display.handle(TYPING, &reply),
                Err(PairingError::Random)
            ));
            crate::random::scripted::set_failing(false);
            // Neither the failed run nor its code survives, though two runs
            // of the budget were left.
            assert!(matches!(display.status().unwrap(), DisplayStatus::DeadEnd));
            assert_eq!(
                display.last_failure(),
                Some(Failure::Exchange(RunFailure::ConfirmationFailed))
            );
        });
    }

    #[test]
    fn an_expired_code_stays_unusable_while_no_replacement_can_be_drawn() {
        with_fixed_codes(|| {
            let clock = Arc::new(ManualClock::default());
            let (mut display, mut typing) = sheets(&clock);
            let (old, _) = shown_code(&mut display);
            let hello = typing.submit_code(old.clone()).unwrap();
            clock.advance(CODE_LIFETIME);

            crate::random::scripted::set_failing(true);
            assert!(matches!(display.status(), Err(PairingError::Random)));
            // The Hello typed from the expired code starts no run meanwhile.
            assert!(matches!(
                display.handle(TYPING, &hello),
                Err(PairingError::Random)
            ));
            crate::random::scripted::set_failing(false);

            let (new, reason) = shown_code(&mut display);
            assert_eq!(reason, CodeReason::Expired);
            assert_ne!(old.digits(), new.digits());
            let DisplayStatus::ShowingCode { runs_left, .. } = display.status().unwrap() else {
                panic!("showing a code");
            };
            assert_eq!(runs_left, MAX_RUNS_PER_SHEET);
        });
    }

    #[test]
    fn new_code_with_no_random_source_keeps_the_code_that_was_showing() {
        with_fixed_codes(|| {
            let clock = Arc::new(ManualClock::default());
            let (mut display, mut typing) = sheets(&clock);
            let (old, _) = shown_code(&mut display);

            crate::random::scripted::set_failing(true);
            assert!(matches!(display.new_code(), Err(PairingError::Random)));
            crate::random::scripted::set_failing(false);

            let (still_shown, reason) = shown_code(&mut display);
            assert_eq!(still_shown.digits(), old.digits());
            assert_eq!(reason, CodeReason::Opened);
            let (d, _) = run(&mut display, &mut typing, old);
            assert!(matches!(d, Outcome::Verified(_)));
        });
    }

    #[test]
    fn a_stalled_run_times_out_as_a_failure() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        clock.advance(RUN_TIMEOUT);
        let reply = typing.handle(DISPLAY, &share.reply.unwrap());
        assert!(matches!(
            reply.outcome,
            Outcome::RunFailed {
                failure: Failure::TimedOut,
                ..
            }
        ));
        assert!(matches!(
            display.status().unwrap(),
            DisplayStatus::ShowingCode {
                reason: CodeReason::RunFailed,
                runs_left: 2,
                ..
            }
        ));
    }

    #[test]
    fn a_second_hello_during_a_run_is_turned_away() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let _share = display.handle(TYPING, &hello).unwrap();
        let other: EndpointId = [0x22; 32];
        let mut other_typer = TypeSheet::open(
            Credentials::Device,
            other,
            DISPLAY,
            clock.clone() as Arc<dyn Clock>,
        );
        let other_hello = other_typer
            .submit_code(PairingCode::parse("111111").unwrap())
            .unwrap();
        let busy = display.handle(other, &other_hello).unwrap();
        assert!(matches!(busy.outcome, Outcome::NoRun(RefuseReason::Busy)));
        // A Reply from someone other than the run's peer doesn't disturb
        // it, and gets no answer.
        let stray = display
            .handle(other, &[MessageType::Reply as u8; 97])
            .unwrap();
        assert!(matches!(stray.outcome, Outcome::Ignored));
        assert!(stray.reply.is_none());
        assert!(matches!(display.status().unwrap(), DisplayStatus::Running));
    }

    #[test]
    fn abandoning_a_run_counts_as_a_failure() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        display.handle(TYPING, &hello).unwrap();
        assert!(matches!(
            display.abandon_run().unwrap(),
            Outcome::RunFailed {
                failure: Failure::Abandoned,
                runs_left: 2
            }
        ));
        assert!(matches!(
            typing.abandon_run().unwrap(),
            Outcome::RunFailed {
                failure: Failure::Abandoned,
                runs_left: 2
            }
        ));
        assert!(matches!(
            display.abandon_run(),
            Err(PairingError::WrongState)
        ));
    }

    /// The typing side up to the point where its Reply is out.
    fn typing_side_after_its_reply(clock: &Arc<ManualClock>) -> TypeSheet {
        let (mut display, mut typing) = sheets(clock);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        let reply = typing.handle(DISPLAY, &share.reply.unwrap());
        assert!(matches!(reply.outcome, Outcome::Continue));
        assert!(reply.reply.is_some());
        typing
    }

    #[test]
    fn a_refusal_after_the_reply_costs_the_typing_side_a_run() {
        // The Reply lets its receiver test one guess, so no refusal, whatever
        // reason it claims, may hand the run back uncounted.
        for reason in [
            RefuseReason::Busy,
            RefuseReason::CodeExpired,
            RefuseReason::Unsupported,
            RefuseReason::RunFailed,
        ] {
            let clock = Arc::new(ManualClock::default());
            let mut typing = typing_side_after_its_reply(&clock);
            let refused = typing.handle(DISPLAY, &encode_refuse(reason));
            assert!(
                matches!(
                    refused.outcome,
                    Outcome::RunFailed {
                        failure: Failure::RefusedByPeer,
                        runs_left: 2
                    }
                ),
                "{reason:?} gave {:?}",
                refused.outcome
            );
        }
    }

    #[test]
    fn a_displaying_side_that_refuses_every_reply_dead_ends_the_typing_side() {
        let clock = Arc::new(ManualClock::default());
        let mut typing = TypeSheet::open(
            Credentials::Device,
            TYPING,
            DISPLAY,
            clock.clone() as Arc<dyn Clock>,
        );
        let mut last = None;
        for _ in 0..MAX_RUNS_PER_SHEET {
            // An impostor at the displaying endpoint: it answers each Hello
            // with a Share made from its own guess, collects the Reply, then
            // claims it was busy.
            let mut impostor =
                DisplaySheet::open(Credentials::Device, DISPLAY, clock.clone()).unwrap();
            let hello = typing
                .submit_code(PairingCode::parse("123456").unwrap())
                .unwrap();
            let share = impostor.handle(TYPING, &hello).unwrap();
            let reply = typing.handle(DISPLAY, &share.reply.unwrap());
            assert!(matches!(reply.outcome, Outcome::Continue));
            last = Some(typing.handle(DISPLAY, &encode_refuse(RefuseReason::Busy)));
        }
        assert!(matches!(
            last.unwrap().outcome,
            Outcome::DeadEnd {
                failure: Failure::RefusedByPeer
            }
        ));
        assert_eq!(typing.status(), TypeStatus::DeadEnd);
        assert!(matches!(
            typing.submit_code(PairingCode::parse("123456").unwrap()),
            Err(PairingError::WrongState)
        ));
    }

    #[test]
    fn a_refusal_before_the_reply_costs_nothing() {
        let clock = Arc::new(ManualClock::default());
        let (_display, mut typing) = sheets(&clock);
        typing
            .submit_code(PairingCode::parse("123456").unwrap())
            .unwrap();
        let refused = typing.handle(DISPLAY, &encode_refuse(RefuseReason::Busy));
        assert!(matches!(
            refused.outcome,
            Outcome::NoRun(RefuseReason::Busy)
        ));
        assert_eq!(
            typing.status(),
            TypeStatus::AwaitingCode {
                runs_left: MAX_RUNS_PER_SHEET
            }
        );
    }

    #[test]
    fn the_typing_side_ignores_everyone_but_its_displaying_side() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let stranger: EndpointId = [0x66; 32];
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap().reply.unwrap();

        // Waiting for the Share: a stranger's Share and a stranger's
        // dead-end refusal both bounce off.
        for message in [share.clone(), encode_refuse(RefuseReason::DeadEnd)] {
            let ignored = typing.handle(stranger, &message);
            assert!(matches!(ignored.outcome, Outcome::Ignored));
            assert!(ignored.reply.is_none());
        }
        assert_eq!(typing.status(), TypeStatus::Running);

        // Waiting for the Confirm: the same.
        let reply = typing.handle(DISPLAY, &share).reply.unwrap();
        let confirm = display.handle(TYPING, &reply).unwrap().reply.unwrap();
        for message in [confirm.clone(), encode_refuse(RefuseReason::RunFailed)] {
            assert!(matches!(
                typing.handle(stranger, &message).outcome,
                Outcome::Ignored
            ));
        }
        // The run is untouched: the real Confirm still verifies it.
        assert!(matches!(
            typing.handle(DISPLAY, &confirm).outcome,
            Outcome::Verified(_)
        ));
    }

    #[test]
    fn a_newcomer_is_not_charged_for_someone_elses_timed_out_run() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        display.handle(TYPING, &hello).unwrap();
        clock.advance(RUN_TIMEOUT);

        let newcomer_endpoint: EndpointId = [0x22; 32];
        let mut newcomer = TypeSheet::open(
            Credentials::Device,
            newcomer_endpoint,
            DISPLAY,
            clock.clone() as Arc<dyn Clock>,
        );
        let newcomer_hello = newcomer
            .submit_code(PairingCode::parse("111111").unwrap())
            .unwrap();
        let response = display.handle(newcomer_endpoint, &newcomer_hello).unwrap();
        // The displaying side's client learns its run timed out...
        assert!(matches!(
            response.outcome,
            Outcome::RunFailed {
                failure: Failure::TimedOut,
                runs_left: 2
            }
        ));
        // ...and the newcomer is turned away with nothing counted.
        let turned_away = newcomer.handle(DISPLAY, &response.reply.unwrap());
        assert!(matches!(
            turned_away.outcome,
            Outcome::NoRun(RefuseReason::CodeExpired)
        ));
        assert_eq!(
            newcomer.status(),
            TypeStatus::AwaitingCode {
                runs_left: MAX_RUNS_PER_SHEET
            }
        );
    }

    /// Two sheets on clocks of their own, so one side's time can pass
    /// without the other's.
    fn sheets_on_separate_clocks() -> (Arc<ManualClock>, Arc<ManualClock>, DisplaySheet, TypeSheet)
    {
        let display_clock = Arc::new(ManualClock::default());
        let typing_clock = Arc::new(ManualClock::default());
        let display = DisplaySheet::open(
            Credentials::Device,
            DISPLAY,
            display_clock.clone() as Arc<dyn Clock>,
        )
        .unwrap();
        let typing = TypeSheet::open(
            Credentials::Device,
            TYPING,
            DISPLAY,
            typing_clock.clone() as Arc<dyn Clock>,
        );
        (display_clock, typing_clock, display, typing)
    }

    #[test]
    fn silence_after_the_reply_costs_the_typing_side_a_run() {
        // The Reply is out (a guess is spent) and the Confirm never comes.
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        let reply = typing.handle(DISPLAY, &share.reply.unwrap());
        let confirm = display.handle(TYPING, &reply.reply.unwrap()).unwrap();
        let Outcome::Verified(mut display_session) = confirm.outcome else {
            panic!("the displaying side verified the typing side");
        };
        // The Confirm is lost.
        clock.advance(RUN_TIMEOUT);
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });
        // The displaying side holds a session nobody else has. It says it
        // isn't paired, and the session can't send.
        assert!(matches!(
            display.status().unwrap(),
            DisplayStatus::VerifiedAwaitingPeer
        ));
        assert_eq!(
            display_session.seal(b"bundle").err(),
            Some(crate::SessionError::AwaitingPeer)
        );
        // A retry is told the sheet is finished.
        let retry = typing
            .submit_code(PairingCode::parse("123456").unwrap())
            .unwrap();
        assert!(matches!(
            display.handle(TYPING, &retry).unwrap().outcome,
            Outcome::NoRun(RefuseReason::DeadEnd)
        ));
    }

    #[test]
    fn a_reply_that_arrives_after_the_timeout_is_not_evaluated() {
        let (display_clock, _typing_clock, mut display, mut typing) = sheets_on_separate_clocks();
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        let reply = typing.handle(DISPLAY, &share.reply.unwrap());
        // The Reply is right, but late.
        display_clock.advance(RUN_TIMEOUT);
        let late = display.handle(TYPING, &reply.reply.unwrap()).unwrap();
        assert!(matches!(
            late.outcome,
            Outcome::RunFailed {
                failure: Failure::TimedOut,
                runs_left: 2
            }
        ));
        // Its sender is told the run failed, and counts it: its guess was
        // spent when the Reply left.
        let told = typing.handle(DISPLAY, &late.reply.unwrap());
        assert!(matches!(
            told.outcome,
            Outcome::RunFailed {
                failure: Failure::RefusedByPeer,
                runs_left: 2
            }
        ));
    }

    #[test]
    fn the_same_peer_trying_again_after_a_timeout_is_not_charged_twice() {
        let (display_clock, typing_clock, mut display, mut typing) = sheets_on_separate_clocks();
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        // The Share is lost; both sides time the run out.
        display.handle(TYPING, &hello).unwrap();
        display_clock.advance(RUN_TIMEOUT);
        typing_clock.advance(RUN_TIMEOUT);
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });
        // The person types again before the displaying side has noticed.
        let again = typing
            .submit_code(PairingCode::parse("123456").unwrap())
            .unwrap();
        let response = display.handle(TYPING, &again).unwrap();
        assert!(matches!(
            response.outcome,
            Outcome::RunFailed {
                failure: Failure::TimedOut,
                runs_left: 2
            }
        ));
        let turned_away = typing.handle(DISPLAY, &response.reply.unwrap());
        assert!(matches!(
            turned_away.outcome,
            Outcome::NoRun(RefuseReason::CodeExpired)
        ));
        // One lost message, one run each.
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });
        assert!(matches!(
            display.status().unwrap(),
            DisplayStatus::ShowingCode { runs_left: 2, .. }
        ));
    }

    #[test]
    fn the_displaying_side_answers_only_a_hello_or_its_run_peer() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let stranger: EndpointId = [0x66; 32];
        let not_hellos: [Vec<u8>; 4] = [
            vec![MessageType::Reply as u8; 97],
            encode_refuse(RefuseReason::Busy),
            vec![MessageType::Frame as u8; 20],
            vec![],
        ];
        let assert_ignored = |display: &mut DisplaySheet, sender: EndpointId| {
            for message in &not_hellos {
                let response = display.handle(sender, message).unwrap();
                assert!(matches!(response.outcome, Outcome::Ignored));
                // Nothing goes back, so two sheets can't bounce refusals
                // off each other and the sheet reflects nothing.
                assert!(response.reply.is_none());
            }
        };

        // Showing a code.
        assert_ignored(&mut display, TYPING);
        let (code, _) = shown_code(&mut display);
        // A run in flight: a stranger's messages are ignored...
        let hello = typing.submit_code(code).unwrap();
        display.handle(TYPING, &hello).unwrap();
        assert_ignored(&mut display, stranger);
        assert!(matches!(display.status().unwrap(), DisplayStatus::Running));
        // ...while anything from the run's own peer that isn't a valid
        // Reply fails the run.
        let junk = display.handle(TYPING, &[0xee; 12]).unwrap();
        assert!(matches!(
            junk.outcome,
            Outcome::RunFailed {
                failure: Failure::Exchange(RunFailure::MalformedMessage),
                runs_left: 2
            }
        ));
    }

    #[test]
    fn a_person_pairing_verifies_through_the_sheets() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, display_keys, typing_keys) =
            person_sheets(&clock, |typer| Some(typer.identity), |_| None);
        let (code, _) = shown_code(&mut display);
        let (d, t) = run(&mut display, &mut typing, code);
        let (Outcome::Verified(mut d), Outcome::Verified(mut t)) = (d, t) else {
            panic!("both sides verify");
        };
        assert_eq!(d.peer_account(), Some(typing_keys));
        assert_eq!(t.peer_account(), Some(display_keys));
        // The displaying side sent its key set last, so it waits to hear
        // the typing side accepted it before it sends anything more.
        assert!(matches!(
            display.status().unwrap(),
            DisplayStatus::VerifiedAwaitingPeer
        ));
        assert!(d.seal(b"too early").is_err());
        let frame = t.seal(b"opening frame").unwrap();
        d.open(TYPING, &frame).unwrap();
        assert!(matches!(display.status().unwrap(), DisplayStatus::Verified));
        d.seal(b"answer").unwrap();
    }

    #[test]
    fn a_person_whose_identity_is_not_the_expected_one_fails_the_run_on_the_side_that_expected() {
        // The displaying side pinned an identity (from an invite) that the
        // typer doesn't have: its run fails when the typer's key set
        // arrives, and it sends no key set of its own.
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, ..) =
            person_sheets(&clock, |typer| Some(typer.encryption), |_| None);
        let typing_keys = person_run_to_typing_keys(&mut display, &mut typing);
        let refused = display.handle(TYPING, &typing_keys).unwrap();
        assert!(matches!(
            refused.outcome,
            Outcome::RunFailed {
                failure: Failure::Exchange(RunFailure::UnexpectedPeerIdentity),
                runs_left: 2
            }
        ));
        let told = typing.handle(DISPLAY, &refused.reply.unwrap());
        assert!(matches!(
            told.outcome,
            Outcome::RunFailed {
                failure: Failure::RefusedByPeer,
                runs_left: 2
            }
        ));

        // The typing side pinned one the displaying side doesn't have: the
        // displaying side has verified and waits, the typing side fails
        // its run, and the displaying side's session never gets to send.
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, ..) =
            person_sheets(&clock, |_| None, |displayer| Some(displayer.encryption));
        let typing_keys = person_run_to_typing_keys(&mut display, &mut typing);
        let accepted = display.handle(TYPING, &typing_keys).unwrap();
        let Outcome::Verified(mut display_session) = accepted.outcome else {
            panic!("the displaying side accepts the typing side's key set");
        };
        let refused = typing.handle(DISPLAY, &accepted.reply.unwrap());
        assert!(matches!(
            refused.outcome,
            Outcome::RunFailed {
                failure: Failure::Exchange(RunFailure::UnexpectedPeerIdentity),
                runs_left: 2
            }
        ));
        assert!(matches!(
            display.status().unwrap(),
            DisplayStatus::VerifiedAwaitingPeer
        ));
        assert!(display_session.seal(b"anything").is_err());
    }

    #[test]
    fn each_side_times_its_wait_for_the_others_key_set() {
        // The displaying side, from its Confirm.
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, ..) = person_sheets(&clock, |_| None, |_| None);
        let typing_keys = person_run_to_typing_keys(&mut display, &mut typing);
        clock.advance(RUN_TIMEOUT);
        let late = display.handle(TYPING, &typing_keys).unwrap();
        assert!(matches!(
            late.outcome,
            Outcome::RunFailed {
                failure: Failure::TimedOut,
                runs_left: 2
            }
        ));
        // The typing side, from its own key set: the same stretch of
        // silence has cost it the run too, its Reply having been spent.
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });
        assert_eq!(typing.last_failure(), Some(Failure::TimedOut));

        // Each wait just inside the timeout: the run verifies, though end
        // to end it took far longer than one timeout.
        let just_inside = RUN_TIMEOUT.checked_sub(Duration::from_millis(1)).unwrap();
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, ..) = person_sheets(&clock, |_| None, |_| None);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        clock.advance(just_inside);
        let share = display.handle(TYPING, &hello).unwrap();
        let reply = typing.handle(DISPLAY, &share.reply.unwrap());
        clock.advance(just_inside);
        let confirm = display.handle(TYPING, &reply.reply.unwrap()).unwrap();
        let typing_keys = typing.handle(DISPLAY, &confirm.reply.unwrap());
        clock.advance(just_inside);
        let display_keys = display.handle(TYPING, &typing_keys.reply.unwrap()).unwrap();
        assert!(matches!(display_keys.outcome, Outcome::Verified(_)));
        // The typing side has been waiting since it sent its key set, the
        // same stretch the displaying side just waited through.
        let done = typing.handle(DISPLAY, &display_keys.reply.unwrap());
        assert!(matches!(done.outcome, Outcome::Verified(_)));
    }

    #[test]
    fn any_refusal_while_waiting_for_the_key_set_costs_the_typing_side_a_run() {
        // The Reply is long gone by then, so a guess is spent: a refusal
        // that says "no run took place" can't hand it back.
        for reason in [
            RefuseReason::Busy,
            RefuseReason::CodeExpired,
            RefuseReason::Unsupported,
            RefuseReason::RunFailed,
        ] {
            let clock = Arc::new(ManualClock::default());
            let (mut display, mut typing, ..) = person_sheets(&clock, |_| None, |_| None);
            let _typing_keys = person_run_to_typing_keys(&mut display, &mut typing);
            let refused = typing.handle(DISPLAY, &encode_refuse(reason));
            assert!(
                matches!(
                    refused.outcome,
                    Outcome::RunFailed {
                        failure: Failure::RefusedByPeer,
                        runs_left: 2
                    }
                ),
                "{reason:?}"
            );
            assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });
        }
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, ..) = person_sheets(&clock, |_| None, |_| None);
        let _typing_keys = person_run_to_typing_keys(&mut display, &mut typing);
        let refused = typing.handle(DISPLAY, &encode_refuse(RefuseReason::DeadEnd));
        assert!(matches!(
            refused.outcome,
            Outcome::DeadEnd {
                failure: Failure::PeerDeadEnd
            }
        ));
    }

    #[test]
    fn giving_up_while_waiting_for_a_key_set_counts_as_a_failed_run() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, ..) = person_sheets(&clock, |_| None, |_| None);
        let _typing_keys = person_run_to_typing_keys(&mut display, &mut typing);
        for outcome in [
            display.abandon_run().unwrap(),
            typing.abandon_run().unwrap(),
        ] {
            assert!(matches!(
                outcome,
                Outcome::RunFailed {
                    failure: Failure::Abandoned,
                    runs_left: 2
                }
            ));
        }
        let (_, reason) = shown_code(&mut display);
        assert_eq!(reason, CodeReason::RunFailed);
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });
    }

    #[test]
    fn messages_out_of_place_in_the_key_set_wait_are_turned_away_or_fail_the_run() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, ..) = person_sheets(&clock, |_| None, |_| None);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        let reply = typing.handle(DISPLAY, &share.reply.unwrap()).reply.unwrap();
        let confirm = display.handle(TYPING, &reply).unwrap().reply.unwrap();
        let _typing_keys = typing.handle(DISPLAY, &confirm).reply.unwrap();

        // A Hello, even from the run's own peer: busy, and the run goes on.
        let busy = display.handle(TYPING, &hello).unwrap();
        assert!(matches!(busy.outcome, Outcome::NoRun(RefuseReason::Busy)));
        assert!(matches!(display.status().unwrap(), DisplayStatus::Running));
        // The Reply again, where the key set belongs: the run fails.
        let failed = display.handle(TYPING, &reply).unwrap();
        assert!(matches!(
            failed.outcome,
            Outcome::RunFailed {
                failure: Failure::Exchange(RunFailure::MalformedMessage),
                runs_left: 2
            }
        ));
        // The Confirm again, where the displaying side's key set belongs.
        let failed = typing.handle(DISPLAY, &confirm);
        assert!(matches!(
            failed.outcome,
            Outcome::RunFailed {
                failure: Failure::Exchange(RunFailure::MalformedMessage),
                runs_left: 2
            }
        ));
    }

    #[test]
    fn a_tampered_key_set_fails_the_run_and_a_refusal_then_costs_the_typing_side() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing, ..) = person_sheets(&clock, |_| None, |_| None);
        let mut typing_keys = person_run_to_typing_keys(&mut display, &mut typing);
        *typing_keys.last_mut().unwrap() ^= 1;
        let refused = display.handle(TYPING, &typing_keys).unwrap();
        assert!(matches!(
            refused.outcome,
            Outcome::RunFailed {
                failure: Failure::Exchange(RunFailure::InvalidPeerKeys),
                runs_left: 2
            }
        ));
        // The displaying side shows a new code; nothing of the old run is
        // left to answer.
        let (_, reason) = shown_code(&mut display);
        assert_eq!(reason, CodeReason::RunFailed);
        let told = typing.handle(DISPLAY, &refused.reply.unwrap());
        assert!(matches!(
            told.outcome,
            Outcome::RunFailed { runs_left: 2, .. }
        ));
    }

    #[test]
    fn elapsed_time_counts_sleep_and_never_runs_backwards() {
        const SECOND: Duration = Duration::from_secs(1);
        let mut elapsed = ElapsedTime::default();
        // Ordinary ticking: both clocks agree.
        assert_eq!(elapsed.step(SECOND, Some(SECOND)), SECOND);
        // A sleep: the monotonic clock barely moved, the wall clock did.
        assert_eq!(elapsed.step(SECOND, Some(600 * SECOND)), 601 * SECOND);
        // The wall clock is pushed an hour ahead: time jumps (things end
        // early)...
        assert_eq!(elapsed.step(SECOND, Some(3600 * SECOND)), 4201 * SECOND);
        // ...then corrected back: no step backwards, and no standing still
        // either, so nothing issued during the excursion outlives its time.
        assert_eq!(elapsed.step(SECOND, None), 4202 * SECOND);
        assert_eq!(elapsed.step(SECOND, Some(SECOND)), 4203 * SECOND);
    }

    #[test]
    fn the_system_clock_moves_forward() {
        let clock = SystemClock::new();
        let first = clock.now();
        std::thread::sleep(Duration::from_millis(5));
        let second = clock.now();
        assert!(second > first);
        assert!(second < Duration::from_secs(60));
    }

    #[test]
    fn the_confirm_is_timed_from_the_reply_not_from_the_hello() {
        // The first leg is slow: the Share reaches the typing side with
        // most of its first wait gone. The displaying side, whose own wait
        // began when the Hello arrived, gets the Reply in good time and
        // confirms. The Confirm must not be judged against a wait that
        // started back at the Hello.
        let (display_clock, typing_clock, mut display, mut typing) = sheets_on_separate_clocks();
        let almost = RUN_TIMEOUT.checked_sub(Duration::from_secs(1)).unwrap();
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        typing_clock.advance(almost);
        let reply = typing.handle(DISPLAY, &share.reply.unwrap());
        assert!(matches!(reply.outcome, Outcome::Continue));
        display_clock.advance(Duration::from_secs(5));
        let confirm = display.handle(TYPING, &reply.reply.unwrap()).unwrap();
        assert!(matches!(confirm.outcome, Outcome::Verified(_)));
        // Well past the Hello's deadline on the typing side's clock, well
        // within the Reply's.
        typing_clock.advance(Duration::from_secs(5));
        assert!(matches!(
            typing.handle(DISPLAY, &confirm.reply.unwrap()).outcome,
            Outcome::Verified(_)
        ));
    }

    #[test]
    fn each_wait_of_the_typing_side_still_times_out() {
        // Waiting for the Share.
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        // The Share is lost on its way back.
        display.handle(TYPING, &hello).unwrap();
        assert_eq!(typing.last_failure(), None);
        clock.advance(RUN_TIMEOUT);
        // The poll is what notices; the reason is there to be read.
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });
        assert_eq!(typing.last_failure(), Some(Failure::TimedOut));
        // The displaying side's run timed out too, and its poll says why
        // the code changed.
        assert!(matches!(
            display.status().unwrap(),
            DisplayStatus::ShowingCode {
                reason: CodeReason::RunFailed,
                runs_left: 2,
                ..
            }
        ));
        assert_eq!(display.last_failure(), Some(Failure::TimedOut));

        // Waiting for the Confirm: a full wait from the Reply, no more.
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap();
        typing.handle(DISPLAY, &share.reply.unwrap());
        clock.advance(RUN_TIMEOUT.checked_sub(Duration::from_secs(1)).unwrap());
        assert_eq!(typing.status(), TypeStatus::Running);
        clock.advance(Duration::from_secs(1));
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 1 });
    }

    #[test]
    fn a_late_or_stray_message_with_no_run_in_flight_is_ignored() {
        let clock = Arc::new(ManualClock::default());
        let (mut display, mut typing) = sheets(&clock);
        let (code, _) = shown_code(&mut display);
        let hello = typing.submit_code(code).unwrap();
        let share = display.handle(TYPING, &hello).unwrap().reply.unwrap();

        // The run times out on the typing side, noticed by a poll; then its
        // Share turns up. It answers no run: not a refusal, not a failure.
        clock.advance(RUN_TIMEOUT);
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });
        let late = typing.handle(DISPLAY, &share);
        assert!(matches!(late.outcome, Outcome::Ignored));
        assert!(late.reply.is_none());
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });

        // A duplicated Confirm after a pairing that verified: the same.
        let (code, _) = shown_code(&mut display);
        let (_, t) = run(&mut display, &mut typing, code);
        assert!(matches!(t, Outcome::Verified(_)));
        let duplicate = typing.handle(DISPLAY, &[MessageType::Confirm as u8; 65]);
        assert!(matches!(duplicate.outcome, Outcome::Ignored));
        assert_eq!(typing.status(), TypeStatus::Verified);
    }

    /// How a watched run ends.
    #[derive(Clone, Copy)]
    enum WatchedEnding {
        /// Both sides verify and exchange a frame each way.
        Verified,
        /// The typing side typed a wrong code: the displaying side fails
        /// the run on the Reply.
        WrongCode,
        /// Both sides abandon the run with the Reply still in flight.
        Abandoned,
        /// The sheets are simply dropped with the Reply still in flight.
        DroppedMidRun,
        /// The Confirm reaches the typing side and then both sides give up:
        /// in a Person pairing each is waiting for the other's key set,
        /// its session inside the sheet; in a device pairing both have
        /// verified, and the sessions are dropped unused.
        AbandonedAfterConfirm,
        /// The same, with the sheets simply dropped.
        DroppedAfterConfirm,
    }

    /// Runs one pairing with this thread's frees watched, registering the
    /// run's secrets as they come into being, and returns how many blocks
    /// were freed with one of them still inside. Registered: the code, the
    /// displaying side's scalar, the confirmation key (its first half),
    /// both session keys and, for a Person pairing, both accounts' identity
    /// seeds and encryption secrets. Not registered (nothing outside the
    /// call that computes them can reach them): K, the ISK and the typing
    /// side's scalar.
    fn secrets_left_in_freed_memory(person: bool, ending: WatchedEnding) -> usize {
        use crate::heap_watch;

        heap_watch::start();
        {
            let clock = Arc::new(ManualClock::default());
            let credentials = |person: bool| {
                if !person {
                    return Credentials::Device;
                }
                let account = Arc::new(AccountKeys::generate().unwrap().0);
                account.watch_secrets();
                Credentials::Person {
                    account,
                    expected_peer_identity: None,
                }
            };
            let mut display = DisplaySheet::open(
                credentials(person),
                DISPLAY,
                clock.clone() as Arc<dyn Clock>,
            )
            .unwrap();
            let mut typing = TypeSheet::open(
                credentials(person),
                TYPING,
                DISPLAY,
                clock as Arc<dyn Clock>,
            );
            let (code, _) = shown_code(&mut display);
            heap_watch::register(code.prs());
            let typed = match ending {
                WatchedEnding::WrongCode => wrong(&code),
                _ => code.clone(),
            };
            drop(code);

            let hello = typing.submit_code(typed).unwrap();
            let share = display.handle(TYPING, &hello).unwrap();
            let DisplayState::Running {
                run: DisplayRun::AwaitingReply(run),
                ..
            } = &display.state
            else {
                panic!("a run is in flight");
            };
            run.watch_secrets();

            let reply = typing.handle(DISPLAY, &share.reply.unwrap());
            let TypeState::AwaitingConfirm { run, .. } = &typing.state else {
                panic!("the Reply is out");
            };
            run.watch_secrets();

            match ending {
                WatchedEnding::Verified => {
                    let (Outcome::Verified(display_session), Outcome::Verified(typing_session)) =
                        finish_run(&mut display, &mut typing, &reply.reply.unwrap())
                    else {
                        panic!("both sides verify");
                    };
                    // Out of their boxes, as a caller is free to do.
                    let (mut display_session, mut typing_session) =
                        (*display_session, *typing_session);
                    let frame = typing_session.seal(b"device keys").unwrap();
                    display_session.open(TYPING, &frame).unwrap();
                    let frame = display_session.seal(b"bundle").unwrap();
                    typing_session.open(DISPLAY, &frame).unwrap();
                }
                WatchedEnding::WrongCode => {
                    let refused = display.handle(TYPING, &reply.reply.unwrap()).unwrap();
                    assert!(matches!(refused.outcome, Outcome::RunFailed { .. }));
                    let told = typing.handle(DISPLAY, &refused.reply.unwrap());
                    assert!(matches!(told.outcome, Outcome::RunFailed { .. }));
                }
                WatchedEnding::Abandoned => {
                    display.abandon_run().unwrap();
                    typing.abandon_run().unwrap();
                }
                WatchedEnding::DroppedMidRun => {}
                WatchedEnding::AbandonedAfterConfirm | WatchedEnding::DroppedAfterConfirm => {
                    let confirm = display.handle(TYPING, &reply.reply.unwrap()).unwrap();
                    let after_confirm = typing.handle(DISPLAY, &confirm.reply.unwrap());
                    assert_eq!(after_confirm.reply.is_some(), person);
                    if matches!(ending, WatchedEnding::AbandonedAfterConfirm) {
                        // Only a Person pairing still has a run in flight.
                        assert_eq!(display.abandon_run().is_ok(), person);
                        assert_eq!(typing.abandon_run().is_ok(), person);
                    }
                }
            }
        }
        heap_watch::finish()
    }

    #[test]
    fn no_registered_secret_of_a_run_is_left_in_freed_memory() {
        for person in [false, true] {
            for ending in [
                WatchedEnding::Verified,
                WatchedEnding::WrongCode,
                WatchedEnding::Abandoned,
                WatchedEnding::DroppedMidRun,
                WatchedEnding::AbandonedAfterConfirm,
                WatchedEnding::DroppedAfterConfirm,
            ] {
                assert_eq!(
                    secrets_left_in_freed_memory(person, ending),
                    0,
                    "a block was freed with a secret still in it (person: {person}, ending {})",
                    ending as u8
                );
            }
        }
    }
}
