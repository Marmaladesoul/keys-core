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
//!                                        ◀──  Share   { nonce_D, Y_D, AD_D }
//!   Reply   { Y_T, tag_T, AD_T }         ──▶
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
//!   their keys.
//! - **sid** is `nonce_T || nonce_D`, one fresh random contribution from each
//!   side (§10.9).
//! - **AD** is empty for a device pairing. For a Person pairing it carries the
//!   side's account identity, recovery and encryption public keys and an
//!   identity-key signature over them, bound to this run's CI, sid and role
//!   and to the signer's own `CPace` share:
//!   `lv_cat(identity, recovery, encryption, sig)`, with `sig` over
//!   `lv_cat("keys-pairing person keys", role, CI, sid, identity, recovery, encryption, share)`.
//!   The receiver checks the signature against the share that arrived in
//!   the same message (and, if it was given one, that the identity is the
//!   one it expected) before it accepts the run (§10.1.1). Signing the
//!   share ties a key set to the one exchange it was made for by the
//!   signature itself, so that tie doesn't rest on the transport having
//!   authenticated the endpoint ids in CI.
//!   **AD is not confidential** (the draft says as much): a Person sheet's
//!   key set and signature go to whoever is at the other endpoint before
//!   that party has proved it knows the code. So an endpoint that reaches an
//!   open Person sheet learns which account is behind it, and holds a
//!   signature saying so, for the price of one burnt code. The signature
//!   can't be replayed (it covers role, both endpoints, kind, version, both
//!   nonces and the signer's share), and the keys are public values; what
//!   leaks is the link
//!   between an endpoint and an account.
//!
//! **Key confirmation** follows §10.4: `mac_key = SHA-512("CPaceMac" || sid || ISK)`
//! and each side's tag is `HMAC-SHA-512(mac_key, lv_cat(Y, AD))` over the
//! message it sent. D checks T's tag before it sends its own, so a wrong code
//! is detected by the side that made it, and nothing from D proves anything to
//! a guesser. Each side holds a [`VerifiedSession`] only after it has checked
//! the other's tag.
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
use crate::session::{SESSION_KEY_BYTES, SessionKeys, SessionRole, VerifiedSession};
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
    fn wire(self) -> u8 {
        match self {
            Self::Device => 1,
            Self::Person => 2,
        }
    }

    fn from_wire(byte: u8) -> Option<Self> {
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
    /// A Person pairing: this account's keys, whose public halves go into the
    /// transcript with a signature, and optionally the identity key this side
    /// expects the other account to have (from an invite it holds).
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

/// What a Person's identity key signs: its key set, for one role in one run,
/// beside the one `CPace` share (`share`, the signer's own) it travels with.
fn person_keys_message(
    role: &[u8],
    ci: &[u8],
    sid: &[u8],
    keys: &AccountPublicKeys,
    share: &[u8; SHARE_BYTES],
) -> Vec<u8> {
    lv_cat(&[
        PERSON_KEYS_LABEL,
        role,
        ci,
        sid,
        &keys.identity,
        &keys.recovery,
        &keys.encryption,
        share,
    ])
}

/// This side's AD: empty for a device pairing, the signed key set for a
/// Person pairing. `own_share` is the share this side sends with it.
fn own_ad(
    credentials: &Credentials,
    role: &[u8],
    ci: &[u8],
    sid: &[u8],
    own_share: &[u8; SHARE_BYTES],
) -> Vec<u8> {
    match credentials {
        Credentials::Device => Vec::new(),
        Credentials::Person { account, .. } => {
            let keys = account.public_keys();
            let signature = account.sign(&person_keys_message(role, ci, sid, &keys, own_share));
            lv_cat(&[&keys.identity, &keys.recovery, &keys.encryption, &signature])
        }
    }
}

/// Checks the other side's AD against what this side's credentials call for,
/// and returns the account keys it carried (Person pairings only).
/// `peer_share` is the share that arrived in the same message as `ad`.
fn check_peer_ad(
    credentials: &Credentials,
    peer_role: &[u8],
    ci: &[u8],
    sid: &[u8],
    peer_share: &[u8; SHARE_BYTES],
    ad: &[u8],
) -> Result<Option<AccountPublicKeys>, RunFailure> {
    match credentials {
        Credentials::Device => {
            if ad.is_empty() {
                Ok(None)
            } else {
                Err(RunFailure::MalformedMessage)
            }
        }
        Credentials::Person {
            expected_peer_identity,
            ..
        } => {
            let mut reader = Reader::new(ad);
            let keys = AccountPublicKeys {
                identity: reader.lv_array::<PUBLIC_KEY_BYTES>()?,
                recovery: reader.lv_array::<PUBLIC_KEY_BYTES>()?,
                encryption: reader.lv_array::<PUBLIC_KEY_BYTES>()?,
            };
            let signature = reader.lv_array::<SIGNATURE_BYTES>()?;
            reader.finish()?;
            let message = person_keys_message(peer_role, ci, sid, &keys, peer_share);
            if !verify_signature(&keys.identity, &message, &signature)
                || !keys.recovery_and_encryption_are_well_formed()
            {
                return Err(RunFailure::InvalidPeerKeys);
            }
            if expected_peer_identity.is_some_and(|expected| expected != keys.identity) {
                return Err(RunFailure::UnexpectedPeerIdentity);
            }
            Ok(Some(keys))
        }
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
/// it. The two sides' tags differ because their `(Y, AD)` differ, and a tag
/// can't be reflected because the displaying side's share is fixed before
/// the typing side's exists and the displaying side never sends its tag
/// first. Both rest on the message order: keep it.
fn confirmation_mac(mac_key: &[u8], share: &[u8], ad: &[u8]) -> HmacSha512 {
    let mut mac = HmacSha512::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&lv_cat(&[share, ad]));
    mac
}

fn confirmation_tag(mac_key: &[u8], share: &[u8], ad: &[u8]) -> [u8; TAG_BYTES] {
    confirmation_mac(mac_key, share, ad)
        .finalize()
        .into_bytes()
        .into()
}

/// Constant-time check of the other side's tag.
fn verify_confirmation(
    mac_key: &[u8],
    share: &[u8],
    ad: &[u8],
    tag: &[u8],
) -> Result<(), RunFailure> {
    confirmation_mac(mac_key, share, ad)
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
    display_endpoint: EndpointId,
    mac_key: Secret<ISK_BYTES>,
    display_share: [u8; SHARE_BYTES],
    display_ad: Vec<u8>,
    keys: SessionKeys,
    kind: PairingKind,
    peer_account: Option<AccountPublicKeys>,
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
    let display_ad = reader.rest().to_vec();

    let kind = credentials.kind();
    let ci = channel_identifier(kind, &display_endpoint, &own_endpoint);
    let sid = session_id(&nonce_t, &nonce_d);
    let peer_account = check_peer_ad(
        &credentials,
        ROLE_DISPLAY,
        &ci,
        &sid,
        &display_share,
        &display_ad,
    )?;

    let cpace = CpaceParty::start(code.prs(), &ci, &sid).map_err(|_| RunFailure::Random)?;
    let own_share = *cpace.share();
    let ad = own_ad(&credentials, ROLE_TYPE, &ci, &sid, &own_share);
    let isk = cpace
        .finish(CpaceRole::Responder, &ad, &display_share, &display_ad)
        .map_err(|_| RunFailure::InvalidShare)?;
    let mac_key = confirmation_key(&sid, &isk);
    let tag = confirmation_tag(mac_key.as_bytes(), &own_share, &ad);

    let mut reply = vec![MessageType::Reply as u8];
    reply.extend_from_slice(&own_share);
    reply.extend_from_slice(&tag);
    reply.extend_from_slice(&ad);
    let next = TypeAwaitingConfirm {
        display_endpoint,
        mac_key,
        display_share,
        display_ad,
        keys: session_keys(&isk, false),
        kind,
        peer_account,
    };
    Ok((next, reply))
}

/// The typing side's last step: checks the displaying side's tag. Only now
/// does it hold a session.
pub(crate) fn type_finish(
    state: TypeAwaitingConfirm,
    confirm_message: &[u8],
) -> Result<VerifiedSession, RunFailure> {
    let mut reader = Reader::new(confirm_message);
    reader.expect_type(MessageType::Confirm)?;
    let tag = reader.array::<TAG_BYTES>()?;
    reader.finish()?;
    verify_confirmation(
        state.mac_key.as_bytes(),
        &state.display_share,
        &state.display_ad,
        &tag,
    )?;
    Ok(VerifiedSession::new(
        SessionRole::Typing,
        state.kind,
        state.display_endpoint,
        state.keys,
        state.peer_account,
    ))
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
    own_ad: Vec<u8>,
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
    let ad = own_ad(&credentials, ROLE_DISPLAY, &ci, &sid, cpace.share());

    let mut share = vec![MessageType::Share as u8];
    share.extend_from_slice(&nonce_d);
    share.extend_from_slice(cpace.share());
    share.extend_from_slice(&ad);
    let state = DisplayAwaitingReply {
        credentials,
        typing_endpoint,
        cpace,
        ci,
        sid,
        own_ad: ad,
        kind: hello.kind,
    };
    Ok((state, share))
}

/// The displaying side's last step: checks the typing side's keys and tag,
/// and only if both hold returns the session and the Confirm to send.
pub(crate) fn display_finish(
    state: DisplayAwaitingReply,
    reply_message: &[u8],
) -> Result<(VerifiedSession, Vec<u8>), RunFailure> {
    let mut reader = Reader::new(reply_message);
    reader.expect_type(MessageType::Reply)?;
    let typing_share = reader.array::<SHARE_BYTES>()?;
    let typing_tag = reader.array::<TAG_BYTES>()?;
    let typing_ad = reader.rest().to_vec();

    let peer_account = check_peer_ad(
        &state.credentials,
        ROLE_TYPE,
        &state.ci,
        &state.sid,
        &typing_share,
        &typing_ad,
    )?;
    let own_share = *state.cpace.share();
    let isk = state
        .cpace
        .finish(
            CpaceRole::Initiator,
            &state.own_ad,
            &typing_share,
            &typing_ad,
        )
        .map_err(|_| RunFailure::InvalidShare)?;
    let mac_key = confirmation_key(&state.sid, &isk);
    verify_confirmation(mac_key.as_bytes(), &typing_share, &typing_ad, &typing_tag)?;

    let mut confirm = vec![MessageType::Confirm as u8];
    confirm.extend_from_slice(&confirmation_tag(
        mac_key.as_bytes(),
        &own_share,
        &state.own_ad,
    ));
    let session = VerifiedSession::new(
        SessionRole::Displaying,
        state.kind,
        state.typing_endpoint,
        session_keys(&isk, true),
        peer_account,
    );
    Ok((session, confirm))
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
            Ok((display_session, confirm)) => (Ok(display_session), type_finish(t2, &confirm)),
            Err(failure) => (Err(failure), Err(RunFailure::ConfirmationFailed)),
        }
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

    #[test]
    fn person_keys_with_a_signature_from_another_run_are_refused() {
        // A key set signed for one run can't be replayed into another: the
        // signature covers that run's CI and sid.
        let (a, _) = AccountKeys::generate().unwrap();
        let (b, _) = AccountKeys::generate().unwrap();
        let (a, b) = (Arc::new(a), Arc::new(b));
        let code = PairingCode::generate().unwrap();

        let (_, first_hello) = type_hello(person(&a, None), TYPING, DISPLAY, code.clone()).unwrap();
        let first_hello = parse_hello(&first_hello, PairingKind::Person).unwrap();
        let (_, first_share) =
            display_share(person(&b, None), DISPLAY, TYPING, &first_hello, &code).unwrap();
        let replayed_ad = &first_share[1 + NONCE_BYTES + SHARE_BYTES..];

        let (t1, second_hello) =
            type_hello(person(&a, None), TYPING, DISPLAY, code.clone()).unwrap();
        let second_hello = parse_hello(&second_hello, PairingKind::Person).unwrap();
        let (_, second_share) =
            display_share(person(&b, None), DISPLAY, TYPING, &second_hello, &code).unwrap();
        let mut forged = second_share[..1 + NONCE_BYTES + SHARE_BYTES].to_vec();
        forged.extend_from_slice(replayed_ad);
        assert_eq!(
            type_reply(t1, &forged).err(),
            Some(RunFailure::InvalidPeerKeys)
        );
    }

    #[test]
    fn a_device_run_refuses_person_ad() {
        let (a, _) = AccountKeys::generate().unwrap();
        let a = Arc::new(a);
        let code = PairingCode::generate().unwrap();
        let (t1, hello) = type_hello(Credentials::Device, TYPING, DISPLAY, code.clone()).unwrap();
        let hello = parse_hello(&hello, PairingKind::Device).unwrap();
        let (_, mut share) =
            display_share(person(&a, None), DISPLAY, TYPING, &hello, &code).unwrap();
        share.truncate(1 + NONCE_BYTES + SHARE_BYTES);
        share.push(0); // any trailing AD byte on a device run
        assert_eq!(
            type_reply(t1, &share).err(),
            Some(RunFailure::MalformedMessage)
        );
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
        let (account, _) = AccountKeys::generate().unwrap();
        let ci = channel_identifier(PairingKind::Person, &DISPLAY, &TYPING);
        let sid = session_id(&[1; NONCE_BYTES], &[2; NONCE_BYTES]);
        let verifier = person(&Arc::new(AccountKeys::generate().unwrap().0), None);
        let share = [7u8; SHARE_BYTES];
        let signed_ad = |keys: AccountPublicKeys| {
            let signature =
                account.sign(&person_keys_message(ROLE_DISPLAY, &ci, &sid, &keys, &share));
            lv_cat(&[&keys.identity, &keys.recovery, &keys.encryption, &signature])
        };
        let good = account.public_keys();
        assert_eq!(
            check_peer_ad(&verifier, ROLE_DISPLAY, &ci, &sid, &share, &signed_ad(good)),
            Ok(Some(good))
        );

        // u = 0 and u = 1 are X25519 points of small order; u = 2 is on the
        // twist. The Ed25519 identity point (y = 1) has order one.
        let mut one = [0u8; PUBLIC_KEY_BYTES];
        one[0] = 1;
        let mut two = [0u8; PUBLIC_KEY_BYTES];
        two[0] = 2;
        for encryption in [[0u8; PUBLIC_KEY_BYTES], one, two] {
            let bad = AccountPublicKeys { encryption, ..good };
            assert_eq!(
                check_peer_ad(&verifier, ROLE_DISPLAY, &ci, &sid, &share, &signed_ad(bad)),
                Err(RunFailure::InvalidPeerKeys),
                "encryption key {encryption:?}"
            );
        }
        let bad = AccountPublicKeys {
            recovery: one,
            ..good
        };
        assert_eq!(
            check_peer_ad(&verifier, ROLE_DISPLAY, &ci, &sid, &share, &signed_ad(bad)),
            Err(RunFailure::InvalidPeerKeys)
        );
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
    fn person_keys_beside_a_share_they_were_not_signed_with_are_refused() {
        // The signature covers the signer's own share. So a genuine key
        // set, in its own run, beside a different (perfectly valid) share
        // is refused at the signature check, before any confirmation.
        let (a, _) = AccountKeys::generate().unwrap();
        let (b, _) = AccountKeys::generate().unwrap();
        let (a, b) = (Arc::new(a), Arc::new(b));
        let code = PairingCode::parse("314159").unwrap();
        let (_, other_share, other_reply) = device_run_to_reply(&code);
        let share_at = 1 + NONCE_BYTES;
        let other_display_point = &other_share[share_at..share_at + SHARE_BYTES];
        let other_typing_point = &other_reply[1..=SHARE_BYTES];
        let run_to_share = || {
            let (t1, hello) = type_hello(person(&a, None), TYPING, DISPLAY, code.clone()).unwrap();
            let hello = parse_hello(&hello, PairingKind::Person).unwrap();
            let (d1, share) =
                display_share(person(&b, None), DISPLAY, TYPING, &hello, &code).unwrap();
            (t1, d1, share)
        };

        // Y_D swapped in the Share: the typing side sends no Reply.
        let (t1, _, mut share) = run_to_share();
        share[share_at..share_at + SHARE_BYTES].copy_from_slice(other_display_point);
        assert_eq!(
            type_reply(t1, &share).err(),
            Some(RunFailure::InvalidPeerKeys)
        );

        // Y_T swapped in the Reply: the displaying side sends no Confirm.
        let (t1, d1, share) = run_to_share();
        let (_t2, mut reply) = type_reply(t1, &share).unwrap();
        reply[1..=SHARE_BYTES].copy_from_slice(other_typing_point);
        assert_eq!(
            display_finish(d1, &reply).err(),
            Some(RunFailure::InvalidPeerKeys)
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
            let (mut display, confirm) = display_finish(d1, &reply).unwrap();
            let mut typing = type_finish(t2, &confirm).unwrap();
            let frame_t = typing.seal(b"from the typing side").unwrap();
            display.open(TYPING, &frame_t).unwrap();
            let frame_d = display.seal(b"from the displaying side").unwrap();
            typing.open(DISPLAY, &frame_d).unwrap();
            vec![
                ("hello", hex(&hello)),
                ("share", hex(&share)),
                ("reply", hex(&reply)),
                ("confirm", hex(&confirm)),
                ("frame type to display", hex(&frame_t)),
                ("frame display to type", hex(&frame_d)),
            ]
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
                "4ba47aee98b375d7620af869291817d86420dd63c6d7b7e175567d444f97de5f",
                "4dbd7aba6974e196b363c1a6d3171cd6eb0c201d7897bdb258ab3132016363fd",
                "1fc6055d0a49f23bf9836bd57964c296d09c02200ba32a278f02a045a49d969c",
                "52e4615a2271f2051e9ddfaba615aa04042db4754051d089cfceddaf66aa024d",
                "42f5fb34c90655a60863b61a2429337d65c17b209b92aef06735aae8c99fec1e",
                "e5bc767167d92db4a60ec095d6b0b5ff058a163307",
            ),
        ),
        (
            "reply",
            concat!(
                "03a4421f7f861a6897f2d38f965d18108802c2211d96b109a0d3b552c3d0162e",
                "22035f3f3c82c58f2ea9e275b18e37c9e76cf72e9d6f027a6d65bf15eb0f2c6e",
                "e7af11bcac56fcfcdd8c7d556ae7774793dd6b77e7c83def3b67d199882ce201",
                "f620f3f285a275422bd9c133ea728878803efbaba5cee8993d71f85b2cb495f3",
                "74ba2059c747c892791ac90117f1f10d9f5bf1ef0f30b7896cf60fc72e7a69ca",
                "d84a2a20844f8087d391fcd922cdd2e4558c6948f072b302c812a4948258cf0d",
                "0c2ac214409df47acb4064d7bbc0358c2d046416c515eee9061506b796ec4741",
                "a790c27970b1ccf03f0c2a8ea7d8e16a1fd1c912fe5398c82bdf76226261b065",
                "766be88d04",
            ),
        ),
        (
            "confirm",
            concat!(
                "049514afe36c9d85686fb30bbc551101af037c9ba7a9278faaa175df258d76e3",
                "7279f0a98bab6bd9e417b002bf89ca06e5d48d2c9519c1c1fb67b9e5e13df1e8",
                "6a",
            ),
        ),
        (
            "frame type to display",
            concat!(
                "060000000000000000a1a3be3d738ac3612fd9fdec458fbf940835d650e675e5",
                "f1dfeef6721b074fee040b171e",
            ),
        ),
        (
            "frame display to type",
            concat!(
                "0600000000000000003be315a06929c34963fb8b6ada8e8bc7057d3d71df6849",
                "ea1c7cd8adb7b1f14abde1f507ae12e1ed",
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
