//! The pairing exchange: one `CPace` run wrapped in four messages, with key
//! confirmation in both directions.
//!
//! Two roles. The **displaying** side made up the code and shows it; the
//! **typing** side is told the code and types it. The typing side opens the
//! run, because it is the one the person has just typed into:
//!
//! ```text
//!   typing (T)                                displaying (D)
//!   Hello   { version, kind, nonce_T }   ──▶
//!                                        ◀──  Share   { nonce_D, Y_D }
//!   Reply   { Y_T, tag_T }               ──▶
//!                                        ◀──  Confirm { tag_D }   (or Refuse)
//! ```
//!
//! `CPace` (draft-irtf-cfrg-cpace-21) runs initiator-responder with D as the
//! initiator: D's share is the first `CPace` message.
//!
//! - **PRS** is the six code digits.
//! - **CI** binds the protocol version, the pairing kind and both roles to the
//!   endpoint ids the transport authenticated:
//!   `lv_cat("keys-pairing", version, kind, "display", endpoint_D, "type", endpoint_T)`.
//!   Identities in CI with their roles is the draft's preferred placement
//!   (§10.1.1). A relay that splices two connections presents the wrong
//!   endpoint id to at least one side, so the two ends' CIs differ and so do
//!   their keys. The kind in CI is what keeps a device run from completing
//!   as a Person run: nothing else in the exchange differs between them.
//! - **sid** is `nonce_T || nonce_D`, one fresh random contribution from each
//!   side (§10.9).
//! - **AD** is empty, on both sides and for both kinds.
//!
//! **A Person pairing has one more step, inside the session.** Each side's
//! first frame of the verified session is its account's key set, the typing
//! side's first:
//!
//! ```text
//!   Frame 0 { identity, recovery, encryption, sig_T }   ──▶
//!                                        ◀──  Frame 0 { identity, recovery, encryption, sig_D }
//! ```
//!
//! The frame's plaintext is `lv_cat(identity, recovery, encryption, sig)`,
//! with `sig` the identity key's signature over
//! `lv_cat("keys-pairing person keys", role, CI, sid, Y_D, Y_T, identity, recovery, encryption)`.
//! The receiver checks the signature, the keys themselves and, if it was
//! given one, that the identity is the one it expected; only then does it
//! record the account, and only then does the displaying side send its own
//! key set. So an account's keys, and its signature over them, reach only a
//! party that has proved it knows the code: an endpoint that merely reaches
//! an open Person sheet learns nothing about whose it is. Both shares are
//! signed so that a key set can't be carried into another session whose sid
//! was made to match, and the role so that a side's own key set doesn't
//! verify when handed back to it. The typing side seals its key set only
//! after verifying the displaying side's confirmation; the displaying side
//! seals its own only after opening the typing side's.
//!
//! One consequence of the order: a typing side that expects a particular
//! identity can check it only after its own key set has gone, so a
//! displaying party that proved the code but isn't the expected account
//! does see the typing side's key set before the typing side fails the
//! run. The displaying side's expectation is checked before its key set
//! leaves. (It is the displaying side, the invite's opener, that normally
//! holds an expected identity.)
//!
//! **Key confirmation** follows §10.4: `mac_key = SHA-512("CPaceMac" || sid || ISK)`
//! and each side's tag is `HMAC-SHA-512(mac_key, lv_cat(Y, AD))` over the
//! message it sent. D checks T's tag before it sends its own, so a wrong code
//! is detected by the side that made it, and nothing from D proves anything to
//! a guesser. Each side holds a [`VerifiedSession`] only after it has checked
//! the other's tag and, in a Person pairing, the other's key set.
//!
//! Every failure of a run is final for that run: the caller burns the code.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::EndpointId;
use crate::code::PairingCode;
use crate::cpace::{CpaceParty, CpaceRole, ISK_BYTES, Isk, SHARE_BYTES, lv_cat};
use crate::keys::{
    AccountKeys, AccountPublicKeys, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, verify_signature,
};
use crate::secret::Secret;
use crate::session::{SESSION_KEY_BYTES, SessionError, SessionKeys, SessionRole, VerifiedSession};
use crate::wire::Reader;

/// The pairing protocol version. Bound into CI, so two sides that disagree
/// derive different keys; a displaying side refuses a Hello of any other
/// version outright. There is no negotiation and no fallback.
pub const PROTOCOL_VERSION: u8 = 1;
/// Length of each side's sid contribution.
pub const NONCE_BYTES: usize = 16;
/// Length of a key-confirmation tag (HMAC-SHA-512).
pub const TAG_BYTES: usize = 64;

const CI_LABEL: &[u8] = b"keys-pairing";
const ROLE_DISPLAY: &[u8] = b"display";
const ROLE_TYPE: &[u8] = b"type";
const PERSON_KEYS_LABEL: &[u8] = b"keys-pairing person keys";
/// The confirmation-key prefix from §10.4.
const CPACE_MAC_LABEL: &[u8] = b"CPaceMac";
const SESSION_KEY_LABEL: &[u8] = b"keys-pairing session key";
const DIRECTION_DISPLAY_TO_TYPE: &[u8] = b"display to type";
const DIRECTION_TYPE_TO_DISPLAY: &[u8] = b"type to display";
/// The exchange's associated data, for both sides and both kinds: none. The
/// draft's AD fields are still there, empty, so the transcript and the tags
/// are exactly the draft's.
const NO_ASSOCIATED_DATA: &[u8] = &[];
/// The single HKDF-Expand block counter (RFC 5869 §2.3, `T(1)`).
const HKDF_FIRST_BLOCK: u8 = 0x01;

/// What is being paired. Bound into CI, so a run of one kind can't complete
/// as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingKind {
    /// Another of the same account's devices.
    Device,
    /// Another person's account.
    Person,
}

impl PairingKind {
    pub(crate) fn wire(self) -> u8 {
        match self {
            Self::Device => 1,
            Self::Person => 2,
        }
    }

    pub(crate) fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Device),
            2 => Some(Self::Person),
            _ => None,
        }
    }
}

/// What this side brings to a pairing.
#[derive(Clone)]
pub enum Credentials {
    /// A device pairing. The device keys travel later, inside the verified
    /// session, so nothing is bound up front.
    Device,
    /// A Person pairing: this account's keys, whose public halves go to the
    /// other side with a signature once the code is proved, and optionally
    /// the identity key this side expects the other account to have (from
    /// an invite it holds).
    Person {
        account: Arc<AccountKeys>,
        expected_peer_identity: Option<[u8; PUBLIC_KEY_BYTES]>,
    },
}

impl Credentials {
    #[must_use]
    pub fn kind(&self) -> PairingKind {
        match self {
            Self::Device => PairingKind::Device,
            Self::Person { .. } => PairingKind::Person,
        }
    }
}

/// Why a run failed. To the person every one of these reads the same ("that
/// code didn't work"): a typo and an impostor's guess look alike to the
/// protocol. The distinction is for diagnostics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RunFailure {
    #[error("a message didn't parse")]
    MalformedMessage,
    #[error("the other side's share was not a valid group element")]
    InvalidShare,
    #[error("the other side's key confirmation didn't verify")]
    ConfirmationFailed,
    #[error("the other side's account keys or their signature didn't verify")]
    InvalidPeerKeys,
    #[error("the other side's account identity is not the one expected")]
    UnexpectedPeerIdentity,
    #[error("the system random source failed")]
    Random,
}

/// Wire tags for the exchange's five message types and the session's frames.
/// Tags 7 to 11 are taken by the connection's greetings (see `greeting`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MessageType {
    Hello = 1,
    Share = 2,
    Reply = 3,
    Confirm = 4,
    Refuse = 5,
    /// A verified session's frame (see `session`). Never an exchange message.
    Frame = 6,
}

impl MessageType {
    pub(crate) fn of(message: &[u8]) -> Option<Self> {
        match message.first()? {
            1 => Some(Self::Hello),
            2 => Some(Self::Share),
            3 => Some(Self::Reply),
            4 => Some(Self::Confirm),
            5 => Some(Self::Refuse),
            6 => Some(Self::Frame),
            _ => None,
        }
    }
}

/// Why a displaying side turned a run away. Sent unauthenticated, so it only
/// ever moves the typing side towards giving up, never towards trusting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// The run was attempted and failed: the code is burnt.
    RunFailed,
    /// The code had expired before the Hello arrived; no run took place.
    CodeExpired,
    /// Another run is already in flight; no run took place.
    Busy,
    /// The sheet accepts nothing more: its run budget is spent, or it has
    /// already verified a run.
    DeadEnd,
    /// The Hello's version or kind isn't what this sheet runs; no run took
    /// place.
    Unsupported,
}

impl RefuseReason {
    fn wire(self) -> u8 {
        match self {
            Self::RunFailed => 1,
            Self::CodeExpired => 2,
            Self::Busy => 3,
            Self::DeadEnd => 4,
            Self::Unsupported => 5,
        }
    }

    fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::RunFailed),
            2 => Some(Self::CodeExpired),
            3 => Some(Self::Busy),
            4 => Some(Self::DeadEnd),
            5 => Some(Self::Unsupported),
            _ => None,
        }
    }
}

pub(crate) fn encode_refuse(reason: RefuseReason) -> Vec<u8> {
    vec![MessageType::Refuse as u8, reason.wire()]
}

pub(crate) fn decode_refuse(message: &[u8]) -> Option<RefuseReason> {
    match message {
        [tag, reason] if *tag == MessageType::Refuse as u8 => RefuseReason::from_wire(*reason),
        _ => None,
    }
}

fn random_nonce() -> Result<[u8; NONCE_BYTES], RunFailure> {
    let mut nonce = [0u8; NONCE_BYTES];
    crate::random::fill(&mut nonce).map_err(|_| RunFailure::Random)?;
    Ok(nonce)
}

fn channel_identifier(kind: PairingKind, display: &EndpointId, typing: &EndpointId) -> Vec<u8> {
    lv_cat(&[
        CI_LABEL,
        &[PROTOCOL_VERSION],
        &[kind.wire()],
        ROLE_DISPLAY,
        display,
        ROLE_TYPE,
        typing,
    ])
}

fn session_id(nonce_t: &[u8; NONCE_BYTES], nonce_d: &[u8; NONCE_BYTES]) -> Vec<u8> {
    let mut sid = Vec::with_capacity(2 * NONCE_BYTES);
    sid.extend_from_slice(nonce_t);
    sid.extend_from_slice(nonce_d);
    sid
}

/// What an exchange fixed, for the key sets that follow it to be signed
/// against.
pub(crate) struct Transcript {
    ci: Vec<u8>,
    sid: Vec<u8>,
    display_share: [u8; SHARE_BYTES],
    typing_share: [u8; SHARE_BYTES],
}

/// What a Person's identity key signs: its key set, as one role of one
/// exchange. Each field is there for a reason a machine-checked model of the
/// protocol found by removing it (`formal/pairing`): without both shares, a
/// party at one end of two sessions can make their session ids equal and
/// carry a signed key set from one into the other; without the role, a
/// side's own key set verifies when reflected back at it.
fn person_keys_message(
    role: SessionRole,
    transcript: &Transcript,
    keys: &AccountPublicKeys,
) -> Vec<u8> {
    lv_cat(&[
        PERSON_KEYS_LABEL,
        role_label(role),
        &transcript.ci,
        &transcript.sid,
        &transcript.display_share,
        &transcript.typing_share,
        &keys.identity,
        &keys.recovery,
        &keys.encryption,
    ])
}

fn role_label(role: SessionRole) -> &'static [u8] {
    match role {
        SessionRole::Displaying => ROLE_DISPLAY,
        SessionRole::Typing => ROLE_TYPE,
    }
}

fn other_role(role: SessionRole) -> SessionRole {
    match role {
        SessionRole::Displaying => SessionRole::Typing,
        SessionRole::Typing => SessionRole::Displaying,
    }
}

/// Where the typing side stands once it has verified the displaying side's
/// confirmation.
pub(crate) enum TypingStep {
    /// A device pairing: the session is ready.
    Verified(VerifiedSession),
    /// A Person pairing: this side's key set is sealed (`own_keys`, to send
    /// now), and the displaying side's is awaited.
    AwaitingPeerKeys {
        own_keys: Vec<u8>,
        exchange: TypingKeyExchange,
    },
}

/// Where the displaying side stands once it has verified the typing side's
/// confirmation, or its key set.
pub(crate) enum DisplayingStep {
    /// The session is ready: a device pairing after the Reply, a Person
    /// pairing after the typing side's key set.
    Verified(VerifiedSession),
    /// A Person pairing after the Reply: the typing side's key set is
    /// awaited, and this side's own is not yet sealed.
    AwaitingPeerKeys(DisplayingKeyExchange),
}

/// The last step of a Person pairing: each side sends its signed key set as
/// its first frame of the session, the typing side first. Private to this
/// module: the two sides reach it only through [`TypingKeyExchange`] and
/// [`DisplayingKeyExchange`], each of which seals this side's key set once,
/// at the one point its role allows, and gives up the session only by way
/// of the other side's key set having been checked.
struct PersonKeyExchange {
    session: VerifiedSession,
    account: Arc<AccountKeys>,
    expected_peer_identity: Option<[u8; PUBLIC_KEY_BYTES]>,
    transcript: Transcript,
}

impl PersonKeyExchange {
    /// Seals this side's signed key set as the session's next frame.
    fn seal_own_keys(&mut self) -> Vec<u8> {
        let keys = self.account.public_keys();
        let message = person_keys_message(self.session.role(), &self.transcript, &keys);
        let signature = self.account.sign(&message);
        let key_set = lv_cat(&[&keys.identity, &keys.recovery, &keys.encryption, &signature]);
        // The typing side's session may always send, and seals this once,
        // from `type_finish`. The displaying side's may send once it has
        // opened the typing side's key set, which is where
        // `DisplayingKeyExchange::finish` calls this from.
        self.session
            .seal(&key_set)
            .expect("a session that has sent nothing seals its key set")
    }

    /// Opens the other side's key-set frame, checks the key set in it, and
    /// records the account on the session.
    fn open_peer_keys(&mut self, frame: &[u8]) -> Result<(), RunFailure> {
        let peer = self.session.peer();
        let key_set = self
            .session
            .open(peer, frame)
            .map_err(|error| match error {
                // Not a frame at all: an exchange message out of place, say.
                SessionError::NotAFrame | SessionError::WrongSender => RunFailure::MalformedMessage,
                // A frame that didn't authenticate, or wasn't the first.
                SessionError::FrameRejected => RunFailure::InvalidPeerKeys,
                SessionError::PayloadTooLarge
                | SessionError::Exhausted
                | SessionError::AwaitingPeer => {
                    unreachable!("{error:?} is an error of sealing, not of opening")
                }
            })?;
        let keys = check_key_set(
            &key_set,
            other_role(self.session.role()),
            &self.transcript,
            self.expected_peer_identity,
        )?;
        self.session.set_peer_account(keys);
        Ok(())
    }
}

/// Parses a key set (the plaintext of a key-set frame) and checks it: the
/// signature, as `signer_role` of this exchange; the keys themselves; and
/// the identity this side expected, if it expected one.
fn check_key_set(
    key_set: &[u8],
    signer_role: SessionRole,
    transcript: &Transcript,
    expected_identity: Option<[u8; PUBLIC_KEY_BYTES]>,
) -> Result<AccountPublicKeys, RunFailure> {
    let mut reader = Reader::new(key_set);
    let keys = AccountPublicKeys {
        identity: reader.lv_array::<PUBLIC_KEY_BYTES>()?,
        recovery: reader.lv_array::<PUBLIC_KEY_BYTES>()?,
        encryption: reader.lv_array::<PUBLIC_KEY_BYTES>()?,
    };
    let signature = reader.lv_array::<SIGNATURE_BYTES>()?;
    reader.finish()?;
    let message = person_keys_message(signer_role, transcript, &keys);
    if !verify_signature(&keys.identity, &message, &signature)
        || !keys.recovery_and_encryption_are_well_formed()
    {
        return Err(RunFailure::InvalidPeerKeys);
    }
    if expected_identity.is_some_and(|expected| expected != keys.identity) {
        return Err(RunFailure::UnexpectedPeerIdentity);
    }
    Ok(keys)
}

/// Fuzzing builds only (`--cfg fuzzing`): whether `key_set`, taken as the
/// plaintext of a typing side's key-set frame, is accepted against a fixed
/// transcript. A peer that knows the code chooses that plaintext freely, so
/// its parser and checks are fuzzed directly; nothing a fuzzer makes should
/// ever be accepted, since that takes a signature by the identity key the
/// key set itself names.
#[cfg(fuzzing)]
#[must_use]
pub fn key_set_is_accepted_for_fuzzing(key_set: &[u8]) -> bool {
    let transcript = Transcript {
        ci: channel_identifier(PairingKind::Person, &[0xd1; 32], &[0x7e; 32]),
        sid: vec![0x5d; 2 * NONCE_BYTES],
        display_share: [0x0d; SHARE_BYTES],
        typing_share: [0x07; SHARE_BYTES],
    };
    check_key_set(key_set, SessionRole::Typing, &transcript, None).is_ok()
}

/// The typing side of a Person pairing, its own key set already sealed (by
/// [`type_finish`], on verifying the displaying side's confirmation).
pub(crate) struct TypingKeyExchange(PersonKeyExchange);

impl TypingKeyExchange {
    /// Checks the displaying side's key set and returns the session.
    pub(crate) fn finish(mut self, frame: &[u8]) -> Result<VerifiedSession, RunFailure> {
        self.0.open_peer_keys(frame)?;
        Ok(self.0.session)
    }
}

/// The displaying side of a Person pairing, its Confirm sent and its own
/// key set not yet sealed.
pub(crate) struct DisplayingKeyExchange(PersonKeyExchange);

impl DisplayingKeyExchange {
    /// Checks the typing side's key set, and only then seals this side's.
    /// Returns the session and the frame to send. The session then waits to
    /// hear from the typing side again before it will send anything else:
    /// that next frame is what shows the typing side accepted this key set.
    pub(crate) fn finish(mut self, frame: &[u8]) -> Result<(VerifiedSession, Vec<u8>), RunFailure> {
        self.0.open_peer_keys(frame)?;
        let own_keys = self.0.seal_own_keys();
        self.0.session.await_peer_again();
        Ok((self.0.session, own_keys))
    }
}

type HmacSha512 = Hmac<Sha512>;

/// The §10.4 confirmation key: `SHA-512("CPaceMac" || sid || ISK)`.
fn confirmation_key(sid: &[u8], isk: &Isk) -> Secret<ISK_BYTES> {
    let mut hasher = Sha512::new();
    hasher.update(CPACE_MAC_LABEL);
    hasher.update(sid);
    hasher.update(isk.as_bytes());
    let mut key = Secret::zeroed();
    hasher.finalize_into(key.as_mut().into());
    key
}

/// The §10.4 tag computation, with no role label, exactly as the draft has
/// it. The two sides' tags differ because their shares differ, and a tag
/// can't be reflected because the displaying side's share is fixed before
/// the typing side's exists and the displaying side never sends its tag
/// first. Both rest on the message order: keep it.
fn confirmation_mac(mac_key: &[u8], share: &[u8]) -> HmacSha512 {
    let mut mac = HmacSha512::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&lv_cat(&[share, NO_ASSOCIATED_DATA]));
    mac
}

fn confirmation_tag(mac_key: &[u8], share: &[u8]) -> [u8; TAG_BYTES] {
    confirmation_mac(mac_key, share)
        .finalize()
        .into_bytes()
        .into()
}

/// Constant-time check of the other side's tag.
fn verify_confirmation(mac_key: &[u8], share: &[u8], tag: &[u8]) -> Result<(), RunFailure> {
    confirmation_mac(mac_key, share)
        .verify_slice(tag)
        .map_err(|_| RunFailure::ConfirmationFailed)
}

/// One direction's session key: HKDF-Expand (RFC 5869) with PRK = ISK (already
/// a uniform 64-byte hash output, so no Extract step) and one output block.
fn session_key(isk: &Isk, direction: &[u8]) -> Secret<SESSION_KEY_BYTES> {
    let mut mac = HmacSha512::new_from_slice(isk.as_bytes()).expect("HMAC accepts any key length");
    mac.update(&lv_cat(&[
        SESSION_KEY_LABEL,
        &[PROTOCOL_VERSION],
        direction,
    ]));
    mac.update(&[HKDF_FIRST_BLOCK]);
    let mut block = Zeroizing::new([0u8; ISK_BYTES]);
    hmac::digest::FixedOutput::finalize_into(mac, (&mut *block).into());
    let mut key = Secret::zeroed();
    key.as_mut().copy_from_slice(&block[..SESSION_KEY_BYTES]);
    key
}

fn session_keys(isk: &Isk, own_is_display: bool) -> SessionKeys {
    let display_to_type = session_key(isk, DIRECTION_DISPLAY_TO_TYPE);
    let type_to_display = session_key(isk, DIRECTION_TYPE_TO_DISPLAY);
    if own_is_display {
        SessionKeys {
            send: display_to_type,
            receive: type_to_display,
        }
    } else {
        SessionKeys {
            send: type_to_display,
            receive: display_to_type,
        }
    }
}

// ─── the typing side ────────────────────────────────────────────────────────

/// The typing side after sending Hello, waiting for Share.
pub(crate) struct TypeAwaitingShare {
    credentials: Credentials,
    own_endpoint: EndpointId,
    display_endpoint: EndpointId,
    code: PairingCode,
    nonce_t: [u8; NONCE_BYTES],
}

/// The typing side after sending Reply, waiting for Confirm.
pub(crate) struct TypeAwaitingConfirm {
    credentials: Credentials,
    display_endpoint: EndpointId,
    mac_key: Secret<ISK_BYTES>,
    keys: SessionKeys,
    kind: PairingKind,
    transcript: Transcript,
}

#[cfg(test)]
impl TypeAwaitingConfirm {
    /// Registers the run's confirmation key and both session keys with the
    /// freed-memory watch, by reference, so the test makes no copy of its
    /// own.
    pub(crate) fn watch_secrets(&self) {
        crate::heap_watch::register(self.mac_key.as_bytes());
        crate::heap_watch::register(self.keys.send.as_bytes());
        crate::heap_watch::register(self.keys.receive.as_bytes());
    }
}

#[cfg(test)]
impl DisplayAwaitingReply {
    /// Registers the run's secret scalar with the freed-memory watch.
    pub(crate) fn watch_secrets(&self) {
        self.cpace.watch_secrets();
    }
}

/// Opens a run on the typing side: returns its state and the Hello to send.
pub(crate) fn type_hello(
    credentials: Credentials,
    own_endpoint: EndpointId,
    display_endpoint: EndpointId,
    code: PairingCode,
) -> Result<(TypeAwaitingShare, Vec<u8>), RunFailure> {
    let nonce_t = random_nonce()?;
    let mut hello = vec![
        MessageType::Hello as u8,
        PROTOCOL_VERSION,
        credentials.kind().wire(),
    ];
    hello.extend_from_slice(&nonce_t);
    let state = TypeAwaitingShare {
        credentials,
        own_endpoint,
        display_endpoint,
        code,
        nonce_t,
    };
    Ok((state, hello))
}

/// The typing side's response to Share: runs its half of `CPace` and returns
/// the Reply, carrying its share and its confirmation tag.
pub(crate) fn type_reply(
    state: TypeAwaitingShare,
    share_message: &[u8],
) -> Result<(TypeAwaitingConfirm, Vec<u8>), RunFailure> {
    let TypeAwaitingShare {
        credentials,
        own_endpoint,
        display_endpoint,
        code,
        nonce_t,
    } = state;
    let mut reader = Reader::new(share_message);
    reader.expect_type(MessageType::Share)?;
    let nonce_d = reader.array::<NONCE_BYTES>()?;
    let display_share = reader.array::<SHARE_BYTES>()?;
    reader.finish()?;

    let kind = credentials.kind();
    let ci = channel_identifier(kind, &display_endpoint, &own_endpoint);
    let sid = session_id(&nonce_t, &nonce_d);

    let cpace = CpaceParty::start(code.prs(), &ci, &sid).map_err(|_| RunFailure::Random)?;
    let typing_share = *cpace.share();
    let isk = cpace
        .finish(
            CpaceRole::Responder,
            NO_ASSOCIATED_DATA,
            &display_share,
            NO_ASSOCIATED_DATA,
        )
        .map_err(|_| RunFailure::InvalidShare)?;
    let mac_key = confirmation_key(&sid, &isk);
    let tag = confirmation_tag(mac_key.as_bytes(), &typing_share);

    let mut reply = vec![MessageType::Reply as u8];
    reply.extend_from_slice(&typing_share);
    reply.extend_from_slice(&tag);
    let next = TypeAwaitingConfirm {
        credentials,
        display_endpoint,
        mac_key,
        keys: session_keys(&isk, false),
        kind,
        transcript: Transcript {
            ci,
            sid,
            display_share,
            typing_share,
        },
    };
    Ok((next, reply))
}

/// Checks the displaying side's tag and returns what the typing side then
/// holds: its session, with nothing yet sealed on it.
fn type_confirmed(
    state: TypeAwaitingConfirm,
    confirm_message: &[u8],
) -> Result<(VerifiedSession, Credentials, Transcript), RunFailure> {
    let mut reader = Reader::new(confirm_message);
    reader.expect_type(MessageType::Confirm)?;
    let tag = reader.array::<TAG_BYTES>()?;
    reader.finish()?;
    verify_confirmation(
        state.mac_key.as_bytes(),
        &state.transcript.display_share,
        &tag,
    )?;
    let session = VerifiedSession::new(
        SessionRole::Typing,
        state.kind,
        state.display_endpoint,
        state.keys,
    );
    Ok((session, state.credentials, state.transcript))
}

/// The typing side's last step of the exchange: checks the displaying side's
/// tag. Only now does it hold a session and, in a Person pairing, seal its
/// key set.
pub(crate) fn type_finish(
    state: TypeAwaitingConfirm,
    confirm_message: &[u8],
) -> Result<TypingStep, RunFailure> {
    let (session, credentials, transcript) = type_confirmed(state, confirm_message)?;
    Ok(match credentials {
        Credentials::Device => TypingStep::Verified(session),
        Credentials::Person {
            account,
            expected_peer_identity,
        } => {
            let mut exchange = PersonKeyExchange {
                session,
                account,
                expected_peer_identity,
                transcript,
            };
            // The displaying side has just proved it knows the code: only
            // now is this side's key set signed and sealed.
            let own_keys = exchange.seal_own_keys();
            TypingStep::AwaitingPeerKeys {
                own_keys,
                exchange: TypingKeyExchange(exchange),
            }
        }
    })
}

// ─── the displaying side ────────────────────────────────────────────────────

/// A Hello the displaying side has accepted for a run.
pub(crate) struct Hello {
    kind: PairingKind,
    nonce_t: [u8; NONCE_BYTES],
}

/// Why a Hello was turned away before any run started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelloRejection {
    Malformed,
    Unsupported,
}

pub(crate) fn parse_hello(
    message: &[u8],
    expected_kind: PairingKind,
) -> Result<Hello, HelloRejection> {
    let mut reader = Reader::new(message);
    reader
        .expect_type(MessageType::Hello)
        .map_err(|_| HelloRejection::Malformed)?;
    let version = reader.byte().map_err(|_| HelloRejection::Malformed)?;
    let kind_byte = reader.byte().map_err(|_| HelloRejection::Malformed)?;
    let nonce_t = reader
        .array::<NONCE_BYTES>()
        .map_err(|_| HelloRejection::Malformed)?;
    reader.finish().map_err(|_| HelloRejection::Malformed)?;
    let kind = PairingKind::from_wire(kind_byte).ok_or(HelloRejection::Malformed)?;
    if version != PROTOCOL_VERSION || kind != expected_kind {
        return Err(HelloRejection::Unsupported);
    }
    Ok(Hello { kind, nonce_t })
}

/// The displaying side after sending Share, waiting for Reply.
pub(crate) struct DisplayAwaitingReply {
    credentials: Credentials,
    typing_endpoint: EndpointId,
    cpace: CpaceParty,
    ci: Vec<u8>,
    sid: Vec<u8>,
    kind: PairingKind,
}

/// The displaying side's answer to an accepted Hello: starts `CPace` with the
/// code and returns the Share.
pub(crate) fn display_share(
    credentials: Credentials,
    own_endpoint: EndpointId,
    typing_endpoint: EndpointId,
    hello: &Hello,
    code: &PairingCode,
) -> Result<(DisplayAwaitingReply, Vec<u8>), RunFailure> {
    let nonce_d = random_nonce()?;
    let ci = channel_identifier(hello.kind, &own_endpoint, &typing_endpoint);
    let sid = session_id(&hello.nonce_t, &nonce_d);
    let cpace = CpaceParty::start(code.prs(), &ci, &sid).map_err(|_| RunFailure::Random)?;

    let mut share = vec![MessageType::Share as u8];
    share.extend_from_slice(&nonce_d);
    share.extend_from_slice(cpace.share());
    let state = DisplayAwaitingReply {
        credentials,
        typing_endpoint,
        cpace,
        ci,
        sid,
        kind: hello.kind,
    };
    Ok((state, share))
}

/// The displaying side's last step of the exchange: checks the typing side's
/// tag, and only if it holds returns the confirmed exchange and the Confirm
/// to send.
pub(crate) fn display_finish(
    state: DisplayAwaitingReply,
    reply_message: &[u8],
) -> Result<(DisplayingStep, Vec<u8>), RunFailure> {
    let mut reader = Reader::new(reply_message);
    reader.expect_type(MessageType::Reply)?;
    let typing_share = reader.array::<SHARE_BYTES>()?;
    let typing_tag = reader.array::<TAG_BYTES>()?;
    reader.finish()?;

    let display_share = *state.cpace.share();
    let isk = state
        .cpace
        .finish(
            CpaceRole::Initiator,
            NO_ASSOCIATED_DATA,
            &typing_share,
            NO_ASSOCIATED_DATA,
        )
        .map_err(|_| RunFailure::InvalidShare)?;
    let mac_key = confirmation_key(&state.sid, &isk);
    verify_confirmation(mac_key.as_bytes(), &typing_share, &typing_tag)?;

    let mut confirm = vec![MessageType::Confirm as u8];
    confirm.extend_from_slice(&confirmation_tag(mac_key.as_bytes(), &display_share));
    let session = VerifiedSession::new(
        SessionRole::Displaying,
        state.kind,
        state.typing_endpoint,
        session_keys(&isk, true),
    );
    let transcript = Transcript {
        ci: state.ci,
        sid: state.sid,
        display_share,
        typing_share,
    };
    let step = match state.credentials {
        Credentials::Device => DisplayingStep::Verified(session),
        Credentials::Person {
            account,
            expected_peer_identity,
        } => DisplayingStep::AwaitingPeerKeys(DisplayingKeyExchange(PersonKeyExchange {
            session,
            account,
            expected_peer_identity,
            transcript,
        })),
    };
    Ok((step, confirm))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISPLAY: EndpointId = [0xd1; 32];
    const TYPING: EndpointId = [0x71; 32];
    /// Seed of the scripted random stream behind the known-answer tests.
    const KNOWN_ANSWER_SEED: &[u8] = b"keys-pairing known-answer test v1";

    fn person(account: &Arc<AccountKeys>, expected: Option<[u8; 32]>) -> Credentials {
        Credentials::Person {
            account: Arc::clone(account),
            expected_peer_identity: expected,
        }
    }

    /// Runs the four messages between two sides and returns each side's
    /// result. `typed` is what the typing side was told; `display_sees` is
    /// the endpoint id the displaying side's transport reports for the typer.
    fn run(
        display_credentials: Credentials,
        typing_credentials: Credentials,
        code: &PairingCode,
        typed: &PairingCode,
        display_sees: EndpointId,
    ) -> (
        Result<VerifiedSession, RunFailure>,
        Result<VerifiedSession, RunFailure>,
    ) {
        let kind = display_credentials.kind();
        let (t1, hello) = type_hello(typing_credentials, TYPING, DISPLAY, typed.clone()).unwrap();
        let hello = parse_hello(&hello, kind).expect("hello accepted");
        let (d1, share) =
            display_share(display_credentials, DISPLAY, display_sees, &hello, code).unwrap();
        let (t2, reply) = match type_reply(t1, &share) {
            Ok(next) => next,
            Err(failure) => return (Err(RunFailure::ConfirmationFailed), Err(failure)),
        };
        match display_finish(d1, &reply) {
            Ok((display, confirm)) => match type_finish(t2, &confirm) {
                Ok(typing) => finish(display, typing),
                Err(failure) => (Err(RunFailure::ConfirmationFailed), Err(failure)),
            },
            Err(failure) => (Err(failure), Err(RunFailure::ConfirmationFailed)),
        }
    }

    /// Finishes an exchange both sides have confirmed: nothing more for a
    /// device pairing, the two key-set frames for a Person pairing.
    fn finish(
        display: DisplayingStep,
        typing: TypingStep,
    ) -> (
        Result<VerifiedSession, RunFailure>,
        Result<VerifiedSession, RunFailure>,
    ) {
        match (display, typing) {
            (DisplayingStep::Verified(display), TypingStep::Verified(typing)) => {
                (Ok(display), Ok(typing))
            }
            (
                DisplayingStep::AwaitingPeerKeys(display),
                TypingStep::AwaitingPeerKeys { own_keys, exchange },
            ) => match display.finish(&own_keys) {
                Ok((display, display_keys)) => (Ok(display), exchange.finish(&display_keys)),
                Err(failure) => (Err(failure), Err(RunFailure::ConfirmationFailed)),
            },
            _ => panic!("the two sides ran different kinds"),
        }
    }

    /// A Person exchange both sides have confirmed, with neither key set
    /// sealed yet: (displaying side, typing side). The typing side is the
    /// bare exchange, so a test can seal a key set of its own making as the
    /// session's first frame.
    fn person_exchanges(
        display: Credentials,
        typing: Credentials,
    ) -> (DisplayingKeyExchange, PersonKeyExchange) {
        let code = PairingCode::parse("314159").unwrap();
        let (t1, hello) = type_hello(typing, TYPING, DISPLAY, code.clone()).unwrap();
        let hello = parse_hello(&hello, PairingKind::Person).unwrap();
        let (d1, share) = display_share(display, DISPLAY, TYPING, &hello, &code).unwrap();
        let (t2, reply) = type_reply(t1, &share).unwrap();
        let (DisplayingStep::AwaitingPeerKeys(display), confirm) =
            display_finish(d1, &reply).unwrap()
        else {
            panic!("a Person exchange");
        };
        let (
            session,
            Credentials::Person {
                account,
                expected_peer_identity,
            },
            transcript,
        ) = type_confirmed(t2, &confirm).unwrap()
        else {
            panic!("a Person exchange");
        };
        let typing = PersonKeyExchange {
            session,
            account,
            expected_peer_identity,
            transcript,
        };
        (display, typing)
    }

    /// A key-set frame sealed by `sender`'s session, carrying `keys` signed
    /// by `signer` as `role` of `transcript`: what a peer that holds the
    /// session, but signs something other than it should, would send.
    fn key_set_frame(
        sender: &mut PersonKeyExchange,
        signer: &AccountKeys,
        role: SessionRole,
        transcript: &Transcript,
        keys: AccountPublicKeys,
    ) -> Vec<u8> {
        let signature = signer.sign(&person_keys_message(role, transcript, &keys));
        let key_set = lv_cat(&[&keys.identity, &keys.recovery, &keys.encryption, &signature]);
        sender.session.seal(&key_set).unwrap()
    }

    fn copy_of(transcript: &Transcript) -> Transcript {
        Transcript {
            ci: transcript.ci.clone(),
            sid: transcript.sid.clone(),
            display_share: transcript.display_share,
            typing_share: transcript.typing_share,
        }
    }

    fn two_accounts() -> (Arc<AccountKeys>, Arc<AccountKeys>) {
        (
            Arc::new(AccountKeys::generate().unwrap().0),
            Arc::new(AccountKeys::generate().unwrap().0),
        )
    }

    #[test]
    fn device_pairing_with_the_right_code_verifies_both_sides() {
        let code = PairingCode::generate().unwrap();
        let (display, typing) = run(
            Credentials::Device,
            Credentials::Device,
            &code,
            &code,
            TYPING,
        );
        let (mut display, mut typing) = (display.unwrap(), typing.unwrap());
        let frame = typing.seal(b"device keys").unwrap();
        assert_eq!(
            display.open(TYPING, &frame).unwrap().as_slice(),
            b"device keys"
        );
        let frame = display.seal(b"bundle").unwrap();
        assert_eq!(typing.open(DISPLAY, &frame).unwrap().as_slice(), b"bundle");
    }

    #[test]
    fn a_wrong_code_fails_on_the_displaying_side_first() {
        let code = PairingCode::parse("123456").unwrap();
        let typed = PairingCode::parse("123457").unwrap();
        let (display, _) = run(
            Credentials::Device,
            Credentials::Device,
            &code,
            &typed,
            TYPING,
        );
        assert_eq!(display.err(), Some(RunFailure::ConfirmationFailed));
    }

    #[test]
    fn a_spliced_endpoint_fails_even_with_the_right_code() {
        let code = PairingCode::generate().unwrap();
        let relay: EndpointId = [0xee; 32];
        let (display, _) = run(
            Credentials::Device,
            Credentials::Device,
            &code,
            &code,
            relay,
        );
        assert_eq!(display.err(), Some(RunFailure::ConfirmationFailed));
    }

    #[test]
    fn a_hello_of_the_other_kind_or_version_is_refused() {
        let code = PairingCode::generate().unwrap();
        let (_, hello) = type_hello(Credentials::Device, TYPING, DISPLAY, code).unwrap();
        assert!(matches!(
            parse_hello(&hello, PairingKind::Person),
            Err(HelloRejection::Unsupported)
        ));
        let mut newer = hello.clone();
        newer[1] = PROTOCOL_VERSION + 1;
        assert!(matches!(
            parse_hello(&newer, PairingKind::Device),
            Err(HelloRejection::Unsupported)
        ));
        assert!(matches!(
            parse_hello(&hello[..5], PairingKind::Device),
            Err(HelloRejection::Malformed)
        ));
    }

    #[test]
    fn person_pairing_exchanges_verified_account_keys() {
        let (a, _) = AccountKeys::generate().unwrap();
        let (b, _) = AccountKeys::generate().unwrap();
        let (a, b) = (Arc::new(a), Arc::new(b));
        let code = PairingCode::generate().unwrap();
        // The displaying side (the invite's opener) pins the inviter's identity.
        let (display, typing) = run(
            person(&b, Some(a.public_keys().identity)),
            person(&a, None),
            &code,
            &code,
            TYPING,
        );
        assert_eq!(display.unwrap().peer_account(), Some(a.public_keys()));
        assert_eq!(typing.unwrap().peer_account(), Some(b.public_keys()));
    }

    #[test]
    fn person_pairing_refuses_an_unexpected_identity() {
        let (a, _) = AccountKeys::generate().unwrap();
        let (b, _) = AccountKeys::generate().unwrap();
        let (impostor, _) = AccountKeys::generate().unwrap();
        let (a, b, impostor) = (Arc::new(a), Arc::new(b), Arc::new(impostor));
        let code = PairingCode::generate().unwrap();
        let (display, _) = run(
            person(&b, Some(a.public_keys().identity)),
            person(&impostor, None),
            &code,
            &code,
            TYPING,
        );
        assert_eq!(display.err(), Some(RunFailure::UnexpectedPeerIdentity));
    }

    /// One way of making a transcript a different exchange's.
    type Alteration = fn(&mut Transcript);

    #[test]
    fn a_key_set_signed_for_another_exchange_is_refused() {
        // The signature covers this exchange's channel identifier, session
        // id and both shares. A key set signed against a transcript that
        // differs in any one of them is refused, though it arrives inside
        // the right session.
        let (a, b) = two_accounts();
        let alterations: [(&str, Alteration); 4] = [
            ("channel identifier", |transcript| transcript.ci[0] ^= 1),
            ("session id", |transcript| transcript.sid[0] ^= 1),
            ("displaying side's share", |transcript| {
                transcript.display_share[0] ^= 1;
            }),
            ("typing side's share", |transcript| {
                transcript.typing_share[0] ^= 1;
            }),
        ];
        for (what, alter) in alterations {
            let (display, mut typing) = person_exchanges(person(&b, None), person(&a, None));
            let mut other = copy_of(&typing.transcript);
            alter(&mut other);
            let frame = key_set_frame(
                &mut typing,
                &a,
                SessionRole::Typing,
                &other,
                a.public_keys(),
            );
            assert_eq!(
                display.finish(&frame).err(),
                Some(RunFailure::InvalidPeerKeys),
                "signed against another {what}"
            );
        }
        // The same frame, signed against this exchange, is accepted.
        let (display, mut typing) = person_exchanges(person(&b, None), person(&a, None));
        let transcript = copy_of(&typing.transcript);
        let frame = key_set_frame(
            &mut typing,
            &a,
            SessionRole::Typing,
            &transcript,
            a.public_keys(),
        );
        let (session, _) = display.finish(&frame).unwrap();
        assert_eq!(session.peer_account(), Some(a.public_keys()));
    }

    #[test]
    fn a_sides_own_key_set_reflected_back_at_it_is_refused() {
        // The signature covers the signer's role. The displaying side's own
        // key set, signed as the displaying side, doesn't pass as the
        // typing side's: a side can't be made to record itself as its peer.
        let (a, b) = two_accounts();
        let (display, mut typing) = person_exchanges(person(&b, None), person(&a, None));
        let transcript = copy_of(&typing.transcript);
        let reflected = key_set_frame(
            &mut typing,
            &b,
            SessionRole::Displaying,
            &transcript,
            b.public_keys(),
        );
        assert_eq!(
            display.finish(&reflected).err(),
            Some(RunFailure::InvalidPeerKeys)
        );
    }

    #[test]
    fn a_key_set_frame_that_does_not_open_or_parse_is_refused() {
        let (a, b) = two_accounts();
        let exchanges = || person_exchanges(person(&b, None), person(&a, None));

        // A flipped bit in the sealed frame.
        let (display, mut typing) = exchanges();
        let mut frame = typing.seal_own_keys();
        *frame.last_mut().unwrap() ^= 1;
        assert_eq!(
            display.finish(&frame).err(),
            Some(RunFailure::InvalidPeerKeys)
        );

        // Something that isn't a frame at all: a second Confirm, say.
        let (display, _) = exchanges();
        let stray = [MessageType::Confirm as u8; 1 + TAG_BYTES];
        assert_eq!(
            display.finish(&stray).err(),
            Some(RunFailure::MalformedMessage)
        );

        // A frame the session opens, holding a key set with a byte too many.
        let (display, mut typing) = exchanges();
        let keys = a.public_keys();
        let signature = a.sign(&person_keys_message(
            SessionRole::Typing,
            &typing.transcript,
            &keys,
        ));
        let mut key_set = lv_cat(&[&keys.identity, &keys.recovery, &keys.encryption, &signature]);
        key_set.push(0);
        let frame = typing.session.seal(&key_set).unwrap();
        assert_eq!(
            display.finish(&frame).err(),
            Some(RunFailure::MalformedMessage)
        );
    }

    #[test]
    fn a_key_set_altered_after_signing_is_refused() {
        // Each of the three keys is under the signature: swap any one for
        // another account's and the key set no longer verifies.
        let (a, b) = two_accounts();
        let (genuine, other) = (a.public_keys(), b.public_keys());
        let altered = [
            AccountPublicKeys {
                identity: other.identity,
                ..genuine
            },
            AccountPublicKeys {
                recovery: other.recovery,
                ..genuine
            },
            AccountPublicKeys {
                encryption: other.encryption,
                ..genuine
            },
        ];
        for sent in altered {
            let (display, mut typing) = person_exchanges(person(&b, None), person(&a, None));
            let signature = a.sign(&person_keys_message(
                SessionRole::Typing,
                &typing.transcript,
                &genuine,
            ));
            let key_set = lv_cat(&[&sent.identity, &sent.recovery, &sent.encryption, &signature]);
            let frame = typing.session.seal(&key_set).unwrap();
            assert_eq!(
                display.finish(&frame).err(),
                Some(RunFailure::InvalidPeerKeys),
                "{sent:?}"
            );
        }
    }

    #[test]
    fn the_typing_side_refuses_a_key_set_signed_for_another_exchange_too() {
        let (a, b) = two_accounts();
        let (mut display, mut typing) = person_exchanges(person(&b, None), person(&a, None));
        let typing_keys = typing.seal_own_keys();
        display.0.open_peer_keys(&typing_keys).unwrap();
        // The displaying side holds the session and may now send, but signs
        // against a transcript whose typing-side share differs.
        let mut other = copy_of(&display.0.transcript);
        other.typing_share[0] ^= 1;
        let frame = key_set_frame(
            &mut display.0,
            &b,
            SessionRole::Displaying,
            &other,
            b.public_keys(),
        );
        assert_eq!(
            TypingKeyExchange(typing).finish(&frame).err(),
            Some(RunFailure::InvalidPeerKeys)
        );
    }

    #[test]
    fn a_key_set_that_is_not_exactly_four_fields_of_the_right_lengths_is_malformed() {
        let (a, _) = two_accounts();
        let transcript = Transcript {
            ci: channel_identifier(PairingKind::Person, &DISPLAY, &TYPING),
            sid: session_id(&[1; NONCE_BYTES], &[2; NONCE_BYTES]),
            display_share: [3; SHARE_BYTES],
            typing_share: [4; SHARE_BYTES],
        };
        let keys = a.public_keys();
        let signature = a.sign(&person_keys_message(
            SessionRole::Typing,
            &transcript,
            &keys,
        ));
        let key_set = lv_cat(&[&keys.identity, &keys.recovery, &keys.encryption, &signature]);
        let check = |key_set: &[u8]| check_key_set(key_set, SessionRole::Typing, &transcript, None);
        assert_eq!(check(&key_set), Ok(keys));

        // Cut short anywhere, or with anything after it.
        for len in 0..key_set.len() {
            assert_eq!(
                check(&key_set[..len]).err(),
                Some(RunFailure::MalformedMessage),
                "cut to {len} bytes"
            );
        }
        let mut longer = key_set.clone();
        longer.push(0);
        assert_eq!(check(&longer).err(), Some(RunFailure::MalformedMessage));
        // A field one byte short, with the length prefix to match.
        let short_identity = lv_cat(&[
            &keys.identity[1..],
            &keys.recovery,
            &keys.encryption,
            &signature,
        ]);
        assert_eq!(
            check(&short_identity).err(),
            Some(RunFailure::MalformedMessage)
        );
    }

    #[test]
    fn the_displaying_side_sends_its_key_set_only_after_checking_the_typing_sides() {
        let (a, b) = two_accounts();
        let (mut display, mut typing) = person_exchanges(person(&b, None), person(&a, None));
        // Before the typing side has spoken, the displaying side's session
        // seals nothing: its key set can't leave first.
        assert_eq!(
            display.0.session.seal(b"anything").err(),
            Some(SessionError::AwaitingPeer)
        );
        let typing_keys = typing.seal_own_keys();
        let (mut display, display_keys) = display.finish(&typing_keys).unwrap();
        // Its key set is out, and it can't yet tell whether the typing side
        // accepted it: back to not sending.
        assert!(!display.peer_confirmed());
        assert_eq!(
            display.seal(b"too early").err(),
            Some(SessionError::AwaitingPeer)
        );
        let mut typing = TypingKeyExchange(typing).finish(&display_keys).unwrap();
        let first = typing.seal(b"opening frame").unwrap();
        assert_eq!(
            display.open(TYPING, &first).unwrap().as_slice(),
            b"opening frame"
        );
        assert!(display.peer_confirmed());
        display.seal(b"answer").unwrap();
    }

    #[test]
    fn the_typing_side_refuses_an_unexpected_identity_too() {
        let (a, b) = two_accounts();
        let (someone_else, _) = two_accounts();
        let (display, typing) = run(
            person(&b, None),
            person(&a, Some(someone_else.public_keys().identity)),
            &PairingCode::parse("314159").unwrap(),
            &PairingCode::parse("314159").unwrap(),
            TYPING,
        );
        // The displaying side accepted the typing side's key set and sent
        // its own; the typing side refused that.
        assert!(display.is_ok());
        assert_eq!(typing.err(), Some(RunFailure::UnexpectedPeerIdentity));
    }

    #[test]
    fn exchange_messages_carry_nothing_after_their_fields() {
        // The exchange has no associated data, for either kind: a byte
        // after a Share's share or a Reply's tag is refused.
        let (a, _) = two_accounts();
        for credentials in [Credentials::Device, person(&a, None)] {
            let code = PairingCode::generate().unwrap();
            let (t1, hello) =
                type_hello(credentials.clone(), TYPING, DISPLAY, code.clone()).unwrap();
            let hello = parse_hello(&hello, credentials.kind()).unwrap();
            let (_, mut share) =
                display_share(credentials.clone(), DISPLAY, TYPING, &hello, &code).unwrap();
            assert_eq!(share.len(), 1 + NONCE_BYTES + SHARE_BYTES);
            share.push(0);
            assert_eq!(
                type_reply(t1, &share).err(),
                Some(RunFailure::MalformedMessage)
            );

            let (t1, hello) =
                type_hello(credentials.clone(), TYPING, DISPLAY, code.clone()).unwrap();
            let hello = parse_hello(&hello, credentials.kind()).unwrap();
            let (d1, share) = display_share(credentials, DISPLAY, TYPING, &hello, &code).unwrap();
            let (_, mut reply) = type_reply(t1, &share).unwrap();
            assert_eq!(reply.len(), 1 + SHARE_BYTES + TAG_BYTES);
            reply.push(0);
            assert_eq!(
                display_finish(d1, &reply).err(),
                Some(RunFailure::MalformedMessage)
            );
        }
    }

    #[test]
    fn tampering_with_any_message_fails_the_run() {
        let code = PairingCode::generate().unwrap();
        // Share: flip a bit in nonce_D, in Y_D.
        for index in [1, 1 + NONCE_BYTES] {
            let (t1, hello) =
                type_hello(Credentials::Device, TYPING, DISPLAY, code.clone()).unwrap();
            let hello = parse_hello(&hello, PairingKind::Device).unwrap();
            let (d1, mut share) =
                display_share(Credentials::Device, DISPLAY, TYPING, &hello, &code).unwrap();
            share[index] ^= 1;
            match type_reply(t1, &share) {
                Err(failure) => assert_eq!(failure, RunFailure::InvalidShare),
                Ok((_, reply)) => {
                    assert!(
                        display_finish(d1, &reply).is_err(),
                        "tampered byte {index} got through"
                    );
                }
            }
        }
        // Reply: flip a bit in Y_T and in the tag.
        for index in [1, 1 + SHARE_BYTES] {
            let (t1, hello) =
                type_hello(Credentials::Device, TYPING, DISPLAY, code.clone()).unwrap();
            let hello = parse_hello(&hello, PairingKind::Device).unwrap();
            let (d1, share) =
                display_share(Credentials::Device, DISPLAY, TYPING, &hello, &code).unwrap();
            let (_, mut reply) = type_reply(t1, &share).unwrap();
            reply[index] ^= 1;
            assert!(display_finish(d1, &reply).is_err());
        }
        // Confirm: flip a bit in the tag.
        let (t1, hello) = type_hello(Credentials::Device, TYPING, DISPLAY, code.clone()).unwrap();
        let hello = parse_hello(&hello, PairingKind::Device).unwrap();
        let (d1, share) =
            display_share(Credentials::Device, DISPLAY, TYPING, &hello, &code).unwrap();
        let (t2, reply) = type_reply(t1, &share).unwrap();
        let (_, mut confirm) = display_finish(d1, &reply).unwrap();
        confirm[1] ^= 1;
        assert_eq!(
            type_finish(t2, &confirm).err(),
            Some(RunFailure::ConfirmationFailed)
        );
    }

    #[test]
    fn refuse_round_trips() {
        for reason in [
            RefuseReason::RunFailed,
            RefuseReason::CodeExpired,
            RefuseReason::Busy,
            RefuseReason::DeadEnd,
            RefuseReason::Unsupported,
        ] {
            assert_eq!(decode_refuse(&encode_refuse(reason)), Some(reason));
        }
        assert_eq!(decode_refuse(&[MessageType::Refuse as u8, 0]), None);
    }

    #[test]
    fn person_keys_that_are_not_usable_keys_are_refused_even_when_signed() {
        let (a, b) = two_accounts();
        let good = a.public_keys();
        // u = 0 and u = 1 are X25519 points of small order; u = 2 is on the
        // twist. The Ed25519 identity point (y = 1) has order one.
        let mut one = [0u8; PUBLIC_KEY_BYTES];
        one[0] = 1;
        let mut two = [0u8; PUBLIC_KEY_BYTES];
        two[0] = 2;
        let unusable = [
            AccountPublicKeys {
                encryption: [0u8; PUBLIC_KEY_BYTES],
                ..good
            },
            AccountPublicKeys {
                encryption: one,
                ..good
            },
            AccountPublicKeys {
                encryption: two,
                ..good
            },
            AccountPublicKeys {
                recovery: one,
                ..good
            },
        ];
        for keys in unusable {
            let (display, mut typing) = person_exchanges(person(&b, None), person(&a, None));
            let transcript = copy_of(&typing.transcript);
            let frame = key_set_frame(&mut typing, &a, SessionRole::Typing, &transcript, keys);
            assert_eq!(
                display.finish(&frame).err(),
                Some(RunFailure::InvalidPeerKeys),
                "{keys:?}"
            );
        }
    }

    /// Both sides up to the point where the displaying side holds the
    /// typing side's Reply, for a device pairing with `code`.
    fn device_run_to_reply(code: &PairingCode) -> (DisplayAwaitingReply, Vec<u8>, Vec<u8>) {
        let (t1, hello) = type_hello(Credentials::Device, TYPING, DISPLAY, code.clone()).unwrap();
        let hello = parse_hello(&hello, PairingKind::Device).unwrap();
        let (d1, share) =
            display_share(Credentials::Device, DISPLAY, TYPING, &hello, code).unwrap();
        let (_t2, reply) = type_reply(t1, &share).unwrap();
        (d1, share, reply)
    }

    #[test]
    fn a_reply_from_another_run_with_the_same_code_fails() {
        // Two runs with one code can't happen through a sheet (a run burns
        // its code); here it isolates the sid binding. Same code, same
        // endpoints, fresh nonces: the first run's Reply must not complete
        // the second.
        let code = PairingCode::parse("314159").unwrap();
        let (_first_display, _, first_reply) = device_run_to_reply(&code);
        let (second_display, _, second_reply) = device_run_to_reply(&code);
        assert_ne!(first_reply, second_reply);
        assert_eq!(
            display_finish(second_display, &first_reply).err(),
            Some(RunFailure::ConfirmationFailed)
        );
    }

    #[test]
    fn a_share_swapped_for_another_valid_point_fails_confirmation() {
        // A flipped bit usually stops a share decoding. Here each share is
        // replaced by a different, perfectly valid group element (another
        // run's share): the run goes through the motions and the
        // confirmation catches it.
        let code = PairingCode::parse("314159").unwrap();
        let (_, other_share, other_reply) = device_run_to_reply(&code);
        let share_at = 1 + NONCE_BYTES;
        let other_display_point = &other_share[share_at..share_at + SHARE_BYTES];
        let other_typing_point = &other_reply[1..=SHARE_BYTES];

        // Y_D swapped in the Share: the typing side replies, and its tag
        // doesn't verify.
        let (t1, hello) = type_hello(Credentials::Device, TYPING, DISPLAY, code.clone()).unwrap();
        let hello = parse_hello(&hello, PairingKind::Device).unwrap();
        let (d1, mut share) =
            display_share(Credentials::Device, DISPLAY, TYPING, &hello, &code).unwrap();
        share[share_at..share_at + SHARE_BYTES].copy_from_slice(other_display_point);
        let (_t2, reply) = type_reply(t1, &share).expect("the swapped point is a valid one");
        assert_eq!(
            display_finish(d1, &reply).err(),
            Some(RunFailure::ConfirmationFailed)
        );

        // Y_T swapped in the Reply.
        let (d1, _, mut reply) = device_run_to_reply(&code);
        reply[1..=SHARE_BYTES].copy_from_slice(other_typing_point);
        assert_eq!(
            display_finish(d1, &reply).err(),
            Some(RunFailure::ConfirmationFailed)
        );
    }

    #[test]
    fn invalid_points_in_either_message_abort_the_run() {
        // Draft §9: inject invalid encodings and the neutral element where a
        // share belongs. The all-zero string is ristretto255's neutral
        // element; all-ones is not a valid encoding.
        let code = PairingCode::parse("314159").unwrap();
        for bad_share in [[0u8; SHARE_BYTES], [0xff; SHARE_BYTES]] {
            // In the Share, in place of Y_D: no Reply comes back.
            let (t1, hello) =
                type_hello(Credentials::Device, TYPING, DISPLAY, code.clone()).unwrap();
            let hello = parse_hello(&hello, PairingKind::Device).unwrap();
            let (_d1, mut share) =
                display_share(Credentials::Device, DISPLAY, TYPING, &hello, &code).unwrap();
            let share_at = 1 + NONCE_BYTES;
            share[share_at..share_at + SHARE_BYTES].copy_from_slice(&bad_share);
            assert_eq!(type_reply(t1, &share).err(), Some(RunFailure::InvalidShare));

            // In the Reply, in place of Y_T: no Confirm comes back.
            let (d1, _, mut reply) = device_run_to_reply(&code);
            reply[1..=SHARE_BYTES].copy_from_slice(&bad_share);
            assert_eq!(
                display_finish(d1, &reply).err(),
                Some(RunFailure::InvalidShare)
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            write!(out, "{byte:02x}").expect("writing to a String");
            out
        })
    }

    /// One full run with scripted randomness, every message and the first
    /// frame each way. Returns them as labelled hex lines.
    fn scripted_run(seed: &[u8], person_pairing: bool) -> Vec<(&'static str, String)> {
        crate::random::scripted::with_seed(seed, || {
            let (display_credentials, typing_credentials) = if person_pairing {
                let display = Arc::new(AccountKeys::generate().unwrap().0);
                let typing = Arc::new(AccountKeys::generate().unwrap().0);
                let pin = display.public_keys().identity;
                (person(&display, None), person(&typing, Some(pin)))
            } else {
                (Credentials::Device, Credentials::Device)
            };
            let code = PairingCode::parse("271828").unwrap();
            let kind = display_credentials.kind();
            let (t1, hello) =
                type_hello(typing_credentials, TYPING, DISPLAY, code.clone()).unwrap();
            let parsed = parse_hello(&hello, kind).unwrap();
            let (d1, share) =
                display_share(display_credentials, DISPLAY, TYPING, &parsed, &code).unwrap();
            let (t2, reply) = type_reply(t1, &share).unwrap();
            let (display, confirm) = display_finish(d1, &reply).unwrap();
            let typing = type_finish(t2, &confirm).unwrap();
            let mut messages = vec![
                ("hello", hex(&hello)),
                ("share", hex(&share)),
                ("reply", hex(&reply)),
                ("confirm", hex(&confirm)),
            ];
            let (mut display, mut typing) = match (display, typing) {
                (DisplayingStep::Verified(display), TypingStep::Verified(typing)) => {
                    (display, typing)
                }
                (
                    DisplayingStep::AwaitingPeerKeys(display),
                    TypingStep::AwaitingPeerKeys { own_keys, exchange },
                ) => {
                    let (display, display_keys) = display.finish(&own_keys).unwrap();
                    messages.push(("key set type to display", hex(&own_keys)));
                    messages.push(("key set display to type", hex(&display_keys)));
                    (display, exchange.finish(&display_keys).unwrap())
                }
                _ => panic!("the two sides ran different kinds"),
            };
            let frame_t = typing.seal(b"from the typing side").unwrap();
            display.open(TYPING, &frame_t).unwrap();
            let frame_d = display.seal(b"from the displaying side").unwrap();
            typing.open(DISPLAY, &frame_d).unwrap();
            messages.push(("frame type to display", hex(&frame_t)));
            messages.push(("frame display to type", hex(&frame_d)));
            messages
        })
    }

    #[test]
    #[ignore = "prints the known answers; run by hand when the protocol changes on purpose"]
    fn print_known_answers() {
        for (name, person_pairing) in [("device", false), ("person", true)] {
            for (label, value) in scripted_run(KNOWN_ANSWER_SEED, person_pairing) {
                println!("{name} {label}: {value}");
            }
        }
    }

    /// Known answers for one device run and one Person run, from the
    /// scripted random stream. They pin every label, field order and
    /// derivation in this module (CI, sid, the Person-key signature, the
    /// confirmation key and tags, the session keys and the frame format):
    /// an accidental change to any of them shows up here, and a second
    /// implementation has something to check itself against.
    ///
    /// They are this implementation's own output, not an outside
    /// authority's: they guard against drift, they don't prove the design.
    const DEVICE_KNOWN_ANSWERS: &[(&str, &str)] = &[
        ("hello", "01010117f54ab5ba19e4d3207ddd237571a235"),
        (
            "share",
            concat!(
                "0263bbd7c6b7f596400de1c9a078dcb0e0e0ef2abbc41280db223ce067c9661e",
                "057ef795d0bdc8b6371fc372a251e6b55c",
            ),
        ),
        (
            "reply",
            concat!(
                "03c616328d2545b53229fe74cd0dab804cd97aaa1bd1e623eb37d560bf426435",
                "3b50d044a1b97cc8949fd99358e006917bc616f0c271ab84edea2e63a47e6aba",
                "df0b744021b1975999afeb755ea7c8f589706d15ad85f931ea0f95df062f0854",
                "c3",
            ),
        ),
        (
            "confirm",
            concat!(
                "048e60fb927781c318c7ea1bcf2ae67ec51d24b387571e85e64f2e7270d5e8a6",
                "65641ee9a8f3252f4ee03668c5a454b339fe010e567978a770283fd1d2b041eb",
                "00",
            ),
        ),
        (
            "frame type to display",
            concat!(
                "060000000000000000b3184b036de4421f80c25260bdbde108c900f94ced269f9f",
                "888e1b10ff5cf47d6f234c50",
            ),
        ),
        (
            "frame display to type",
            concat!(
                "06000000000000000007ec0f82e91cc16491c404813d0dc376f7a714551158650b",
                "1c9cc166a32b3329bde369faeacd07cf",
            ),
        ),
    ];
    const PERSON_KNOWN_ANSWERS: &[(&str, &str)] = &[
        ("hello", "0101027a5db4edaa4e7cedf936c74c58006736"),
        (
            "share",
            concat!(
                "02b4a40434959d771e0dda939f975acf150e22b4926f3c9f622be2762611da30",
                "4ba47aee98b375d7620af869291817d864",
            ),
        ),
        (
            "reply",
            concat!(
                "03a4421f7f861a6897f2d38f965d18108802c2211d96b109a0d3b552c3d0162e",
                "22be382f46f20c6b66c645fee854ea06cabdd7d3d59a1eebdfe5b2399bb7b0cf",
                "fe0cdcd09106e1c2298290e10d61edb347f3fb151d96bc7f41aa8562ce59a703",
                "5b",
            ),
        ),
        (
            "confirm",
            concat!(
                "0400154a4ecc8f7fbea05eff03382e7e8acf0ad3a14f276f6c2f64e23d8658a2",
                "aed8ce64995caf53fc953ce05c349725e9f1e56d706a0f0fa57b15f74a1ad3b4",
                "ae",
            ),
        ),
        (
            "key set type to display",
            concat!(
                "060000000000000000f55c4094ebc05268a5d7e13db25eef57655dd6adf9f1d1",
                "baee4c78a32450cda6080ed8820db67b9d5835cdefd02e1dc3d5b52c824df57d",
                "8fd4dec4665afe100abc39b46b524641e4d35e2873d85b65d2a471ca64dd2973",
                "08fe03b64fd9efa753a93e3f396b32694d3694d514afe0c09a2361694d37ad55",
                "36d6d43778717f319c152491ae80f5c9dab00ade61f36c5bc12a28e47038767b",
                "e12ad9c43f2e74763757f871ac404df14c0776520d8dce019a86ab35bc",
            ),
        ),
        (
            "key set display to type",
            concat!(
                "060000000000000000981ba77452aae55562f3b8369785801b404d105a7a9abe",
                "dd1c9aa5085e36ecca874fe9c0a45b77dc0453bfff463cd476e588418d90ffff",
                "f1a6be6b957b861f9656d40992e381a511ea4a8732fa043dd5a20fc03b6245d5",
                "faca98eb94b2fbe781c656d685b503bfefefd56c22ca10bb60a10c4de6cbebf6",
                "8cb7dce6481ac6b3e290801249da1b251247de759dd3bfff262ac00e34167dd6",
                "2dea3a7c4de74a58784a5fb9bf8a846465b196258049a108508f3ca265",
            ),
        ),
        (
            "frame type to display",
            concat!(
                "060000000000000001e6457ff77d914265349419df197f106fa75de0374671fa",
                "44646226b6d9e1f68f79c45c3b",
            ),
        ),
        (
            "frame display to type",
            concat!(
                "060000000000000001ce6b02990a35350f4fa0a2ec01c9982f50a83dfe226f6c",
                "a584e1435bc757907115b118983b14a9e3",
            ),
        ),
    ];

    #[test]
    fn a_scripted_run_reproduces_the_known_answers() {
        for (person_pairing, expected) in
            [(false, DEVICE_KNOWN_ANSWERS), (true, PERSON_KNOWN_ANSWERS)]
        {
            let actual = scripted_run(KNOWN_ANSWER_SEED, person_pairing);
            assert_eq!(actual.len(), expected.len());
            for ((label, value), (expected_label, expected_value)) in actual.iter().zip(expected) {
                assert_eq!(label, expected_label);
                assert_eq!(value, expected_value, "{label} (person: {person_pairing})");
            }
        }
    }
}
