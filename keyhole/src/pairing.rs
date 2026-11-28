//! `pair-keygen` and `pair-sim`: pairing driven through the `keys-ffi` seam.
//!
//! `pair-sim` stands up both sheets of a pairing in one process, carries
//! their messages between them, and plays the person reading the code off
//! one and typing it into the other. Flags script the ways a run goes wrong
//! (typos, an expired code, a stale code after a re-roll, an impostor's
//! guesses, a spliced connection, a tampered message, a stalled run, a pinned
//! identity that doesn't match) so scenarios can assert on the policy: one
//! run per code, the run budget, expiry and transcript binding.
//!
//! Output is one line per event, `side: what`, for scenarios to grep. The
//! code itself is never printed.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Result, bail};
use keys_ffi::{
    PairingAccountKeys, PairingCredentials, PairingDeviceKeys, PairingDisplaySheet,
    PairingDisplayStatus, PairingOutcomeFfi, PairingSession, PairingTestClock, PairingTypeSheet,
    PairingTypeStatus, generate_pairing_account, pairing_policy,
};

/// Endpoint ids for the simulated parties. Arbitrary, distinct 32-byte values.
const DISPLAY_ENDPOINT: [u8; 32] = [0xd1; 32];
const TYPING_ENDPOINT: [u8; 32] = [0x71; 32];
const IMPOSTOR_ENDPOINT: [u8; 32] = [0x66; 32];
const RELAY_ENDPOINT: [u8; 32] = [0xee; 32];
const STRANGER_ENDPOINT: [u8; 32] = [0x57; 32];
/// Wire forms of two refusals an attacker can forge (they are
/// unauthenticated): message type 5, then the reason (3 busy, 4 dead end).
const FORGED_REFUSE_BUSY: [u8; 2] = [5, 3];
const FORGED_REFUSE_DEAD_END: [u8; 2] = [5, 4];
/// The wire type byte of a Reply, for a stray one sent out of turn.
const REPLY_TYPE_BYTE: u8 = 3;
/// A Hello (type 1) of a protocol version no sheet runs, with a kind byte
/// and a 16-byte nonce after it.
const HELLO_OF_UNKNOWN_VERSION: [u8; 19] = {
    let mut hello = [0x55; 19];
    hello[0] = 1;
    hello[1] = 0xff;
    hello
};
/// A byte added to the end of a message that should end where it does.
const TRAILING_BYTE: u8 = 0;
/// How far inside the run timeout a "slow leg" lands, in milliseconds.
const SLOW_LEG_MARGIN_MS: u64 = 1;
/// A stray Confirm-typed message (type 4 and a 64-byte tag), as a late or
/// duplicated exchange message would look to a session.
const STRAY_CONFIRM: [u8; 65] = [4; 65];
/// A frame-typed message (type 6) that no session sealed.
const FORGED_FRAME: [u8; 41] = [6; 41];
/// Where the displaying side's share starts in a Share: after the type byte
/// and its 16-byte nonce.
const SHARE_POINT_OFFSET: usize = 1 + 16;
/// A bound on simulated attempts, comfortably above the sheet's run budget,
/// so a policy bug can't loop the driver forever.
const MAX_SIMULATED_ATTEMPTS: u32 = 10;
/// Leading bytes of a public key shown in a trace line.
const KEY_PREFIX_BYTES: usize = 4;
/// What the simulated typer types at a sheet that no longer shows a code.
const SPENT_SHEET_GUESS: &str = "000000";

/// What is being paired.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SimKind {
    Device,
    Person,
}

/// For a Person pairing: what identity the displaying side pins.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SimPin {
    /// No pin.
    None,
    /// The typing side's real identity.
    Right,
    /// Some other account's identity.
    Wrong,
}

/// Which message to corrupt on the first attempt.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SimTamper {
    /// The first payload byte of the Share: the displaying side's nonce.
    Share,
    /// The displaying side's share (its group element) inside the Share.
    SharePoint,
    /// The first payload byte of the Reply: the typing side's share.
    Reply,
    /// The first payload byte of the Confirm: the displaying side's tag.
    Confirm,
    /// Person pairings: the last byte of the typing side's key-set frame.
    KeySet,
    /// Person pairings: the last byte of the displaying side's key-set
    /// frame.
    DisplayKeySet,
    /// One more byte on the end of the Share.
    ShareTrailing,
    /// One more byte on the end of the Reply.
    ReplyTrailing,
}

/// An active attack on the exchange.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SimAttack {
    /// Whoever sits at the displaying endpoint takes each Reply (one guess
    /// at the code) and answers it with a forged "busy" refusal, hoping the
    /// typing side retypes for free. Every attempt.
    RefuseAfterReply,
    /// A third endpoint feeds the typing side a forged dead-end refusal and
    /// a copy of the Share in mid-run, and the displaying side a stray
    /// Reply and a Hello of its own. First attempt.
    Stranger,
    /// The first attempt's Reply, made with the right code, is withheld
    /// from the displaying side; on the second attempt the wire replays it
    /// in place of the fresh one.
    ReplayReply,
    /// The first attempt fails (a typo) and burns its code; on the second
    /// the typing side types that burnt code again.
    ReuseBurntCode,
    /// First attempt: a Reply before any Hello, a second Hello in mid-run,
    /// and the Share delivered a second time where the Confirm belongs.
    OutOfOrder,
    /// First attempt: the Confirm never reaches the typing side, which
    /// times the run out.
    DropConfirm,
    /// Before the first attempt, the displaying side is sent a Hello it
    /// can't run. The code it shows must survive.
    UnusableHello,
    /// Person pairings, first attempt: the displaying side's key set never
    /// reaches the typing side, which times the run out.
    DropKeySet,
}

/// What the wire remembers from the first attempt, for the attacks that
/// replay it.
#[derive(Default)]
struct Recorded {
    code: Option<String>,
    reply: Option<Vec<u8>>,
}

/// The script for one `pair-sim` run.
#[allow(clippy::struct_excessive_bools)] // independent scenario switches
pub struct SimScript {
    pub kind: SimKind,
    pub typos: u32,
    pub expire_before_typing: bool,
    pub expire_then_poll: bool,
    pub reroll_then_type_stale: bool,
    pub impostor_guesses: u32,
    pub relay: bool,
    pub pin: SimPin,
    pub type_pin: SimPin,
    pub stall: bool,
    pub slow_legs: bool,
    pub tamper: Option<SimTamper>,
    pub attack: Option<SimAttack>,
    pub payload: Option<String>,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// `pair-keygen`: a fresh account and device key set, public halves only.
pub fn keygen() -> Result<()> {
    let account = generate_pairing_account()?;
    let keys = account.keys.public_keys();
    println!("account identity {}", hex(&keys.identity));
    println!("account recovery {}", hex(&keys.recovery));
    println!("account encryption {}", hex(&keys.encryption));
    let device = PairingDeviceKeys::generate()?.public_keys();
    println!("device signing {}", hex(&device.signing));
    println!("device relay {}", hex(&device.relay));
    println!("device vault {}", hex(&device.vault));
    Ok(())
}

pub(crate) fn describe(outcome: &PairingOutcomeFfi) -> String {
    match outcome {
        PairingOutcomeFfi::Continue => "continue".to_owned(),
        PairingOutcomeFfi::NoRun { reason } => {
            format!("no-run reason={}", kebab(&format!("{reason:?}")))
        }
        PairingOutcomeFfi::RunFailed { failure, runs_left } => format!(
            "run-failed failure={} runs-left={runs_left}",
            kebab(&format!("{failure:?}"))
        ),
        PairingOutcomeFfi::DeadEnd { failure } => {
            format!("dead-end failure={}", kebab(&format!("{failure:?}")))
        }
        PairingOutcomeFfi::Verified { session } => {
            let peer = session.peer_account().map_or_else(String::new, |keys| {
                format!(" peer-identity={}", hex(&keys.identity[..KEY_PREFIX_BYTES]))
            });
            format!(
                "verified kind={}{peer}",
                kebab(&format!("{:?}", session.kind()))
            )
        }
        PairingOutcomeFfi::Ignored => "ignored".to_owned(),
    }
}

/// `ConfirmationFailed` → `confirmation-failed`.
fn kebab(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Reports the displaying sheet's status and returns the code it shows, if
/// it shows one. The code itself is never printed.
fn shown_code(display: &PairingDisplaySheet) -> Result<Option<String>> {
    match display.status()? {
        PairingDisplayStatus::ShowingCode {
            reason, runs_left, ..
        } => println!(
            "display: showing reason={} runs-left={runs_left}",
            kebab(&format!("{reason:?}"))
        ),
        PairingDisplayStatus::Running => println!("display: running"),
        PairingDisplayStatus::VerifiedAwaitingPeer => println!("display: verified-awaiting-peer"),
        PairingDisplayStatus::Verified => println!("display: verified"),
        PairingDisplayStatus::DeadEnd => println!("display: dead-end"),
    }
    Ok(display.shown_code()?)
}

/// Re-rolls the displaying side's code until it isn't `stale`. One time in
/// a million a fresh code equals the one it replaces, and a script that
/// then types the stale code would verify; a re-roll is free.
fn ensure_shown_code_differs(display: &PairingDisplaySheet, stale: &str) -> Result<()> {
    while display.shown_code()?.as_deref() == Some(stale) {
        display.new_code()?;
    }
    Ok(())
}

/// A code one digit off the real one: a typo, or a wrong guess.
pub(crate) fn wrong(code: &str) -> String {
    let mut digits = code.as_bytes().to_vec();
    if let Some(first) = digits.first_mut() {
        *first = if *first == b'9' { b'0' } else { *first + 1 };
    }
    String::from_utf8_lossy(&digits).into_owned()
}

fn flip_bit_at(message: &mut [u8], offset: usize) {
    if let Some(byte) = message.get_mut(offset) {
        *byte ^= 1;
    }
}

/// Flips a bit of the message's last byte. Says whether there was one.
fn flip_last_bit(message: &mut [u8]) -> bool {
    match message.last_mut() {
        Some(last) => {
            *last ^= 1;
            true
        }
        None => false,
    }
}

fn flip_first_payload_bit(message: &mut [u8]) {
    // Byte 0 is the message type; corrupt the first byte after it.
    flip_bit_at(message, 1);
}

/// One impostor guess against the displaying sheet, from a third endpoint.
fn impostor_guess(
    display: &PairingDisplaySheet,
    guess: &str,
    clock: &Arc<PairingTestClock>,
) -> Result<()> {
    let impostor = PairingTypeSheet::open_with_test_clock(
        PairingCredentials::Device,
        IMPOSTOR_ENDPOINT.to_vec(),
        DISPLAY_ENDPOINT.to_vec(),
        Arc::clone(clock),
    )?;
    let hello = impostor.submit_code(guess.to_owned())?;
    let share = display.handle(IMPOSTOR_ENDPOINT.to_vec(), hello)?;
    if let (PairingOutcomeFfi::Continue, Some(share)) = (&share.outcome, share.reply) {
        let reply = impostor.handle(DISPLAY_ENDPOINT.to_vec(), share)?;
        if let Some(reply) = reply.reply {
            let verdict = display.handle(IMPOSTOR_ENDPOINT.to_vec(), reply)?;
            println!("display: impostor {}", describe(&verdict.outcome));
            return Ok(());
        }
    }
    println!("display: impostor {}", describe(&share.outcome));
    Ok(())
}

struct Parties {
    display: Arc<PairingDisplaySheet>,
    typing: Arc<PairingTypeSheet>,
    /// The typing side's own account, for a Person pairing.
    typing_account: Option<Arc<PairingAccountKeys>>,
    display_account: Option<Arc<PairingAccountKeys>>,
}

fn open_parties(script: &SimScript, clock: &Arc<PairingTestClock>) -> Result<Parties> {
    let (display_credentials, typing_credentials, display_account, typing_account) = match script
        .kind
    {
        SimKind::Device => (
            PairingCredentials::Device,
            PairingCredentials::Device,
            None,
            None,
        ),
        SimKind::Person => {
            let displaying = generate_pairing_account()?.keys;
            let typing = generate_pairing_account()?.keys;
            // What a side pins of the other's identity.
            let pinned = |pin: SimPin, other: &PairingAccountKeys| -> Result<Option<Vec<u8>>> {
                Ok(match pin {
                    SimPin::None => None,
                    SimPin::Right => Some(other.public_keys().identity),
                    SimPin::Wrong => Some(generate_pairing_account()?.keys.public_keys().identity),
                })
            };
            (
                PairingCredentials::Person {
                    account: Arc::clone(&displaying),
                    expected_peer_identity: pinned(script.pin, &typing)?,
                },
                PairingCredentials::Person {
                    account: Arc::clone(&typing),
                    expected_peer_identity: pinned(script.type_pin, &displaying)?,
                },
                Some(displaying),
                Some(typing),
            )
        }
    };
    Ok(Parties {
        display: PairingDisplaySheet::open_with_test_clock(
            display_credentials,
            DISPLAY_ENDPOINT.to_vec(),
            Arc::clone(clock),
        )?,
        typing: PairingTypeSheet::open_with_test_clock(
            typing_credentials,
            TYPING_ENDPOINT.to_vec(),
            DISPLAY_ENDPOINT.to_vec(),
            Arc::clone(clock),
        )?,
        typing_account,
        display_account,
    })
}

/// How one attempt ended.
enum Attempt {
    Verified {
        display: Arc<PairingSession>,
        typing: Arc<PairingSession>,
    },
    Failed,
    DeadEnd,
}

fn ends(outcome: &PairingOutcomeFfi) -> Option<Attempt> {
    match outcome {
        PairingOutcomeFfi::DeadEnd { .. } => Some(Attempt::DeadEnd),
        PairingOutcomeFfi::Continue
        | PairingOutcomeFfi::Verified { .. }
        | PairingOutcomeFfi::Ignored => None,
        PairingOutcomeFfi::NoRun { .. } | PairingOutcomeFfi::RunFailed { .. } => {
            Some(Attempt::Failed)
        }
    }
}

/// Delivers a displaying-side reply to the typing side and reports it.
fn deliver_to_typing(
    parties: &Parties,
    reply: Option<Vec<u8>>,
) -> Result<Option<keys_ffi::PairingResponse>> {
    let Some(reply) = reply else {
        return Ok(None);
    };
    let response = parties.typing.handle(DISPLAY_ENDPOINT.to_vec(), reply)?;
    println!("type: {}", describe(&response.outcome));
    Ok(Some(response))
}

/// Person pairings: says whether any of the two accounts' public keys
/// appears, in the clear, in the exchange's messages. They must not: a key
/// set travels only inside the verified session.
fn report_account_keys_in_exchange(parties: &Parties, messages: &[&Vec<u8>]) {
    let accounts = [&parties.display_account, &parties.typing_account];
    let keys: Vec<Vec<u8>> = accounts
        .into_iter()
        .flatten()
        .flat_map(|account| {
            let keys = account.public_keys();
            [keys.identity, keys.recovery, keys.encryption]
        })
        .collect();
    if keys.is_empty() {
        return;
    }
    let leaked = messages.iter().any(|message| {
        keys.iter().any(|key| {
            message
                .windows(key.len())
                .any(|window| window == key.as_slice())
        })
    });
    println!(
        "wire: account-keys-in-exchange {}",
        if leaked { "LEAKED" } else { "none" }
    );
}

/// The last message of a run (the Confirm, or the displaying side's key
/// set) never arrives. Nothing arrives, so no outcome is returned: a status
/// poll is what fails the run, and each sheet says what it was lost to.
fn report_lost_message(
    parties: &Parties,
    clock: &Arc<PairingTestClock>,
    display_session: Option<&Arc<PairingSession>>,
) -> Result<()> {
    clock.advance_ms(pairing_policy().run_timeout_ms);
    println!("clock: past run timeout");
    let lost_run = match parties.typing.status() {
        PairingTypeStatus::AwaitingCode { runs_left } => {
            let failure = failure_name(parties.typing.last_failure());
            format!("lost-run failure={failure} runs-left={runs_left}")
        }
        other => format!("unexpected-status {other:?}"),
    };
    println!("type: {lost_run}");
    shown_code(&parties.display)?;
    // A displaying side still waiting (for a Person pairing's key set) has
    // lost its run too; one that had verified has not.
    if let Some(failure) = parties.display.last_failure() {
        println!("display: lost-run failure={}", failure_name(Some(failure)));
    }
    if let Some(display) = display_session {
        println!(
            "session: display peer-confirmed {}",
            if display.peer_confirmed() {
                "YES"
            } else {
                "no"
            }
        );
        println!(
            "session: display-sends-first {}",
            if display.seal(b"bundle".to_vec()).is_err() {
                "refused"
            } else {
                "ALLOWED"
            }
        );
    }
    Ok(())
}

/// Why a sheet's last failed run failed, as a trace word.
fn failure_name(failure: Option<keys_ffi::PairingFailure>) -> String {
    failure.map_or_else(
        || "NONE".to_owned(),
        |failure| kebab(&format!("{failure:?}")),
    )
}

/// Moves the clock to just inside the run timeout: a message that takes
/// nearly as long as a wait allows.
fn slow_leg(clock: &Arc<PairingTestClock>) {
    clock.advance_ms(pairing_policy().run_timeout_ms - SLOW_LEG_MARGIN_MS);
    println!("clock: just under run timeout");
}

/// The displaying side gives up on the run it still has in flight.
fn abandon_display_run(parties: &Parties) -> Result<()> {
    let outcome = parties.display.abandon_run()?;
    println!("display: abandoned {}", describe(&outcome));
    Ok(())
}

#[allow(clippy::too_many_lines)] // one linear script, step by step
fn attempt(
    parties: &Parties,
    script: &SimScript,
    clock: &Arc<PairingTestClock>,
    number: u32,
    code: &str,
    recorded: &mut Recorded,
) -> Result<Attempt> {
    let first = number == 0;
    let second = number == 1;
    // This attack needs a failed first attempt to burn a code: its typer
    // makes a typo.
    let attack_typo = first && script.attack == Some(SimAttack::ReuseBurntCode);
    let typed = if number < script.typos || attack_typo {
        wrong(code)
    } else if second && script.attack == Some(SimAttack::ReuseBurntCode) {
        let Some(burnt) = recorded.code.clone() else {
            bail!("no first attempt's code to retype");
        };
        ensure_shown_code_differs(&parties.display, &burnt)?;
        println!("type: retypes the burnt code");
        burnt
    } else {
        code.to_owned()
    };
    if first {
        // The code the first run consumes, whatever was typed.
        recorded.code = Some(code.to_owned());
    }
    if first && script.attack == Some(SimAttack::OutOfOrder) {
        let stray = parties
            .display
            .handle(TYPING_ENDPOINT.to_vec(), vec![REPLY_TYPE_BYTE])?;
        println!("display: reply-before-hello {}", describe(&stray.outcome));
    }
    if first && script.attack == Some(SimAttack::UnusableHello) {
        let refused = parties
            .display
            .handle(TYPING_ENDPOINT.to_vec(), HELLO_OF_UNKNOWN_VERSION.to_vec())?;
        println!("display: unusable-hello {}", describe(&refused.outcome));
        let kept = shown_code(&parties.display)?.as_deref() == Some(code);
        println!("display: code-kept {}", if kept { "yes" } else { "NO" });
    }
    if first && script.reroll_then_type_stale {
        parties.display.new_code()?;
        ensure_shown_code_differs(&parties.display, code)?;
        // The person types the code they read before the re-roll.
        println!("display: new-code");
    }
    if first && (script.expire_before_typing || script.expire_then_poll) {
        clock.advance_ms(pairing_policy().code_lifetime_ms);
        println!("clock: past code lifetime");
    }
    if first && script.expire_then_poll {
        // The sheet is on screen, so its status is polled: the expired code
        // is replaced before the stale one is typed.
        shown_code(&parties.display)?;
        ensure_shown_code_differs(&parties.display, code)?;
    }
    println!("type: submit");
    let hello = parties.typing.submit_code(typed)?;
    let seen = if script.relay {
        RELAY_ENDPOINT
    } else {
        TYPING_ENDPOINT
    };
    let share = parties.display.handle(seen.to_vec(), hello.clone())?;
    println!("display: {}", describe(&share.outcome));
    if let Some(end) = ends(&share.outcome) {
        deliver_to_typing(parties, share.reply)?;
        return Ok(end);
    }
    if first && script.attack == Some(SimAttack::OutOfOrder) {
        let again = parties.display.handle(seen.to_vec(), hello.clone())?;
        println!("display: second-hello {}", describe(&again.outcome));
    }
    let Some(mut share_message) = share.reply else {
        bail!("the displaying side started a run without a Share");
    };
    if first && script.tamper == Some(SimTamper::Share) {
        flip_first_payload_bit(&mut share_message);
        println!("wire: tampered share");
    }
    if first && script.tamper == Some(SimTamper::SharePoint) {
        flip_bit_at(&mut share_message, SHARE_POINT_OFFSET);
        println!("wire: tampered share point");
    }
    if first && script.tamper == Some(SimTamper::ShareTrailing) {
        share_message.push(TRAILING_BYTE);
        println!("wire: share with a trailing byte");
    }
    if first && script.stall {
        clock.advance_ms(pairing_policy().run_timeout_ms);
        println!("clock: past run timeout");
    }
    if first && script.slow_legs {
        slow_leg(clock);
    }
    let Some(reply) = deliver_to_typing(parties, Some(share_message.clone()))? else {
        bail!("no reply to deliver");
    };
    if let Some(end) = ends(&reply.outcome) {
        // The displaying side notices the stalled or abandoned run too.
        if first && script.stall {
            // No message arrives, so no outcome is returned: the status
            // poll is what fails the run, and the sheet says why.
            shown_code(&parties.display)?;
            println!(
                "display: lost-run failure={}",
                failure_name(parties.display.last_failure())
            );
        } else {
            abandon_display_run(parties)?;
        }
        return Ok(end);
    }
    let Some(mut reply_message) = reply.reply else {
        bail!("the typing side carried on without a Reply");
    };
    match script.attack {
        Some(SimAttack::RefuseAfterReply) => {
            // The Reply is in the attacker's hands; the genuine displaying
            // side never sees it.
            println!("wire: reply answered with a forged busy refusal");
            let refused = deliver_to_typing(parties, Some(FORGED_REFUSE_BUSY.to_vec()))?;
            abandon_display_run(parties)?;
            return Ok(refused
                .and_then(|response| ends(&response.outcome))
                .unwrap_or(Attempt::Failed));
        }
        Some(SimAttack::Stranger) if first => {
            for (what, message) in [
                ("dead-end refusal", FORGED_REFUSE_DEAD_END.to_vec()),
                ("share", share_message.clone()),
            ] {
                let response = parties.typing.handle(STRANGER_ENDPOINT.to_vec(), message)?;
                println!("type: stranger {what} {}", describe(&response.outcome));
            }
            // And into the displaying side, whose run is still in flight.
            for (what, message) in [("reply", vec![REPLY_TYPE_BYTE]), ("hello", hello.clone())] {
                let response = parties
                    .display
                    .handle(STRANGER_ENDPOINT.to_vec(), message)?;
                println!("display: stranger {what} {}", describe(&response.outcome));
            }
        }
        Some(SimAttack::OutOfOrder) if first => {
            println!("wire: share delivered again in place of the confirm");
            let end = deliver_to_typing(parties, Some(share_message))?
                .and_then(|response| ends(&response.outcome))
                .unwrap_or(Attempt::Failed);
            abandon_display_run(parties)?;
            return Ok(end);
        }
        Some(SimAttack::ReplayReply) if first => {
            // A Reply made with the right code, kept back for later.
            println!("wire: reply withheld");
            recorded.reply = Some(reply_message);
            abandon_display_run(parties)?;
            let outcome = parties.typing.abandon_run()?;
            println!("type: abandoned {}", describe(&outcome));
            return Ok(Attempt::Failed);
        }
        Some(SimAttack::ReplayReply) if second => {
            if let Some(old) = recorded.reply.take() {
                reply_message = old;
                println!("wire: replayed the first attempt's reply");
            }
        }
        _ => {}
    }
    if first && script.tamper == Some(SimTamper::Reply) {
        flip_first_payload_bit(&mut reply_message);
        println!("wire: tampered reply");
    }
    if first && script.tamper == Some(SimTamper::ReplyTrailing) {
        reply_message.push(TRAILING_BYTE);
        println!("wire: reply with a trailing byte");
    }
    let confirm = parties
        .display
        .handle(seen.to_vec(), reply_message.clone())?;
    println!("display: {}", describe(&confirm.outcome));
    let mut display_session = match &confirm.outcome {
        PairingOutcomeFfi::Verified { session } => Some(Arc::clone(session)),
        _ => None,
    };
    let mut confirm_message = confirm.reply;
    if let Some(answer) = &confirm_message {
        if ends(&confirm.outcome).is_none() {
            // The exchange is the same four messages, of the same lengths,
            // whatever is being paired.
            println!(
                "wire: exchange-lengths hello={} share={} reply={} confirm={}",
                hello.len(),
                share_message.len(),
                reply_message.len(),
                answer.len()
            );
        }
        // Whether the run went on or was refused here, nothing sent so far
        // may carry an account key.
        report_account_keys_in_exchange(parties, &[&hello, &share_message, &reply_message, answer]);
    }
    if first
        && script.tamper == Some(SimTamper::Confirm)
        && let Some(message) = confirm_message.as_mut()
    {
        flip_first_payload_bit(message);
        println!("wire: tampered confirm");
    }
    if first && script.attack == Some(SimAttack::DropConfirm) {
        println!("wire: confirm dropped");
        report_lost_message(parties, clock, display_session.as_ref())?;
        return Ok(Attempt::Failed);
    }
    if first && script.slow_legs {
        slow_leg(clock);
    }
    let Some(mut last) = deliver_to_typing(parties, confirm_message)? else {
        bail!("no confirmation to deliver");
    };
    // A Person pairing goes one more round, inside the session: the typing
    // side's key set, then the displaying side's (or its refusal).
    if let (PairingOutcomeFfi::Continue, Some(mut typing_keys)) =
        (&last.outcome, last.reply.clone())
    {
        if first && script.tamper == Some(SimTamper::KeySet) && flip_last_bit(&mut typing_keys) {
            println!("wire: tampered key set");
        }
        let answer = parties.display.handle(seen.to_vec(), typing_keys)?;
        println!("display: {}", describe(&answer.outcome));
        if let PairingOutcomeFfi::Verified { session } = &answer.outcome {
            display_session = Some(Arc::clone(session));
        }
        let mut display_keys = answer.reply;
        if first
            && script.tamper == Some(SimTamper::DisplayKeySet)
            && display_keys
                .as_mut()
                .is_some_and(|keys| flip_last_bit(keys))
        {
            println!("wire: tampered displaying side's key set");
        }
        if first && script.attack == Some(SimAttack::DropKeySet) {
            println!("wire: displaying side's key set dropped");
            report_lost_message(parties, clock, display_session.as_ref())?;
            return Ok(Attempt::Failed);
        }
        let Some(delivered) = deliver_to_typing(parties, display_keys)? else {
            bail!("no key set or refusal to deliver");
        };
        last = delivered;
    }
    match (display_session, &last.outcome) {
        (Some(display), PairingOutcomeFfi::Verified { session }) => Ok(Attempt::Verified {
            display,
            typing: Arc::clone(session),
        }),
        (Some(display), outcome) => {
            // The displaying side checked the typer's confirmation, but the
            // typer never accepted the displaying side's: its session must
            // still refuse to send.
            let refused = display.seal(b"bundle".to_vec()).is_err();
            println!(
                "session: display-sends-first {}",
                if refused { "refused" } else { "ALLOWED" }
            );
            shown_code(&parties.display)?;
            Ok(ends(outcome).unwrap_or(Attempt::Failed))
        }
        (None, PairingOutcomeFfi::Verified { .. }) => {
            bail!("the typing side verified a run the displaying side did not")
        }
        (None, outcome) => {
            // A Person pairing's displaying side is still waiting for a key
            // set if the typing side gave up first: its connection is gone,
            // so it gives up on the run too.
            if matches!(parties.display.status()?, PairingDisplayStatus::Running) {
                abandon_display_run(parties)?;
            }
            Ok(ends(outcome).unwrap_or(Attempt::Failed))
        }
    }
}

pub(crate) fn ok(flag: bool) -> &'static str {
    if flag { "ok" } else { "FAILED" }
}

/// What a session made of a message it should turn away untouched.
fn turned_away(result: &Result<Vec<u8>, keys_ffi::PairingFfiError>) -> &'static str {
    match result {
        Err(
            keys_ffi::PairingFfiError::SessionWrongSender
            | keys_ffi::PairingFfiError::SessionNotAFrame,
        ) => "ignored",
        Err(_) => "REJECTED",
        Ok(_) => "ACCEPTED",
    }
}

/// Sends `payload` both ways, typing side first, as both flows do. Before
/// the first genuine frame, the displaying side's session is shown a
/// stranger's forged frame and a stray exchange message from its own peer:
/// neither may touch it.
fn exchange_payload(
    display: &PairingSession,
    typing: &PairingSession,
    payload: &str,
) -> Result<()> {
    let early = display.seal(payload.as_bytes().to_vec());
    println!(
        "session: display-sends-first {}",
        if early.is_err() { "refused" } else { "ALLOWED" }
    );
    println!(
        "session: stranger-frame {}",
        turned_away(&display.open(STRANGER_ENDPOINT.to_vec(), FORGED_FRAME.to_vec()))
    );
    println!(
        "session: stray-exchange-message {}",
        turned_away(&display.open(TYPING_ENDPOINT.to_vec(), STRAY_CONFIRM.to_vec()))
    );
    let to_display = typing.seal(payload.as_bytes().to_vec())?;
    let received = display.open(TYPING_ENDPOINT.to_vec(), to_display.clone())?;
    println!(
        "session: type-to-display {}",
        ok(received == payload.as_bytes())
    );
    let to_typing = display.seal(payload.as_bytes().to_vec())?;
    let received = typing.open(DISPLAY_ENDPOINT.to_vec(), to_typing)?;
    println!(
        "session: display-to-type {}",
        ok(received == payload.as_bytes())
    );
    println!(
        "session: replay {}",
        if display.open(TYPING_ENDPOINT.to_vec(), to_display).is_err() {
            "rejected"
        } else {
            "ACCEPTED"
        }
    );
    // A rejected frame spoils the session: the next genuine frame is
    // refused too, and so is sending.
    let next = typing.seal(payload.as_bytes().to_vec())?;
    let refuses_all = display.open(TYPING_ENDPOINT.to_vec(), next).is_err()
        && display.seal(payload.as_bytes().to_vec()).is_err();
    println!(
        "session: after-rejection {}",
        if refuses_all {
            "refuses-everything"
        } else {
            "STILL-OPEN"
        }
    );
    Ok(())
}

fn report_person_keys(parties: &Parties, display: &PairingSession, typing: &PairingSession) {
    let (Some(display_account), Some(typing_account)) =
        (&parties.display_account, &parties.typing_account)
    else {
        return;
    };
    let matches = |seen: Option<keys_ffi::PairingAccountPublicKeys>,
                   actual: &PairingAccountKeys| {
        if seen == Some(actual.public_keys()) {
            "yes"
        } else {
            "no"
        }
    };
    println!(
        "display: peer-keys-match={}",
        matches(display.peer_account(), typing_account)
    );
    println!(
        "type: peer-keys-match={}",
        matches(typing.peer_account(), display_account)
    );
}

/// `pair-sim`: runs a scripted pairing between two in-process sheets.
pub fn simulate(script: &SimScript) -> Result<()> {
    let clock = PairingTestClock::new();
    let parties = open_parties(script, &clock)?;
    for _ in 0..script.impostor_guesses {
        let Some(code) = shown_code(&parties.display)? else {
            break;
        };
        impostor_guess(&parties.display, &wrong(&code), &clock)?;
    }
    let mut recorded = Recorded::default();
    for number in 0..MAX_SIMULATED_ATTEMPTS {
        // A sheet that has finished shows no code; the typer still tries
        // something, and is told the sheet accepts nothing more.
        let code = shown_code(&parties.display)?.unwrap_or_else(|| SPENT_SHEET_GUESS.to_owned());
        if let PairingTypeStatus::DeadEnd = parties.typing.status() {
            break;
        }
        match attempt(&parties, script, &clock, number, &code, &mut recorded)? {
            Attempt::Verified { display, typing } => {
                report_person_keys(&parties, &display, &typing);
                if let Some(payload) = &script.payload {
                    // Before the typing side's first frame the displaying
                    // sheet is only "verified, awaiting peer"; after it,
                    // "verified".
                    shown_code(&parties.display)?;
                    exchange_payload(&display, &typing, payload)?;
                    shown_code(&parties.display)?;
                }
                println!("result: verified");
                return Ok(());
            }
            Attempt::DeadEnd => break,
            Attempt::Failed => {}
        }
    }
    shown_code(&parties.display)?;
    let typing_status = match parties.typing.status() {
        PairingTypeStatus::AwaitingCode { runs_left } => {
            format!("awaiting-code runs-left={runs_left}")
        }
        PairingTypeStatus::Running => "running".to_owned(),
        PairingTypeStatus::Verified => "verified".to_owned(),
        PairingTypeStatus::DeadEnd => "dead-end".to_owned(),
    };
    println!("type: status {typing_status}");
    println!("result: not-verified");
    Ok(())
}
