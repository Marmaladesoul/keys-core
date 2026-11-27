//! The verified session: what a pairing produces once both key confirmations
//! have checked out. It carries opaque payloads (the pairing bundle, a
//! device's public keys, a friendship's bootstrap) in both directions.
//!
//! Each direction has its own AES-256-GCM key derived from the ISK. Frames
//! carry an explicit sequence number that is also the nonce, and a frame is
//! accepted only if it is exactly the next one expected: no replay, no
//! reordering, no gaps. A frame from the peer that fails to open spoils the
//! session. There is no end-of-stream marker: knowing that everything
//! expected has arrived is the payload protocol's business.
//!
//! **The session listens only to its peer.** It is pinned to the endpoint
//! the exchange ran with. A message from any other endpoint, or one that
//! isn't a frame at all (a late exchange message, say), is turned away
//! without touching the session, so nobody but the peer can spoil it.
//!
//! **The keys never move.** The session holds the two raw keys in wiped
//! allocations of their own and builds the cipher for each frame, dropping
//! it straight after. A stored cipher would be copied wherever the session
//! moved, and the `aes` crate's runtime-detected cipher is a union whose
//! unused half no `Drop` wipes.
//!
//! **The displaying side speaks second.** Each side holds a session only
//! after checking the other's key confirmation, but the displaying side
//! checks first and sends the last exchange message, so it can't know whether
//! its own confirmation reached the typing side intact. Until it has opened
//! one frame from the typing side, which proves the typing side verified it,
//! its session refuses to seal ([`SessionError::AwaitingPeer`]). So nothing
//! leaves either side before both confirmations have verified, by
//! construction rather than by caller discipline. In both flows the typing
//! side has something to send first anyway: a new device's public keys, or
//! an inviter's opening frame.
//!
//! **A Person pairing's first frame each way is not the client's.** The
//! exchange uses it for each side's signed key set (see `protocol`), before
//! the session is handed over, so the client's frames start at the second
//! sequence number. Having sent its key set last, the displaying side is
//! back to waiting: its session seals nothing more until the typing side's
//! next frame shows that key set was accepted.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use crate::EndpointId;
use crate::cpace::lv_cat;
use crate::keys::AccountPublicKeys;
use crate::protocol::{MessageType, PROTOCOL_VERSION, PairingKind};
use crate::secret::Secret;

/// Length of each direction's AES-256-GCM key.
pub(crate) const SESSION_KEY_BYTES: usize = 32;
/// Length of the frame type tag at the front of every frame.
const TYPE_BYTES: usize = 1;
/// Length of the explicit sequence number that follows the type tag.
const SEQUENCE_BYTES: usize = 8;
/// AES-GCM's nonce is 96 bits: four zero bytes, then the sequence number.
const NONCE_PADDING_BYTES: usize = 4;
const FRAME_LABEL: &[u8] = b"keys-pairing frame";

/// The two directions' keys, as derived by the protocol layer.
pub(crate) struct SessionKeys {
    pub(crate) send: Secret<SESSION_KEY_BYTES>,
    pub(crate) receive: Secret<SESSION_KEY_BYTES>,
}

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// From `open`: the frame, from the peer, was not the next one in
    /// sequence or didn't authenticate, and the session is spoilt from here
    /// on. From either call: the session was already spoilt.
    #[error("the frame was rejected")]
    FrameRejected,
    /// From `seal`: the payload is too large for one frame. Nothing changed.
    #[error("the payload is too large for one frame")]
    PayloadTooLarge,
    /// The message didn't come from this session's peer. Nothing changed.
    #[error("the message is not from this session's peer")]
    WrongSender,
    /// The message is not a session frame (a late exchange message, say).
    /// Nothing changed.
    #[error("the message is not a session frame")]
    NotAFrame,
    /// The sending sequence number is exhausted.
    #[error("the session has sent all the frames it can")]
    Exhausted,
    /// The displaying side may not send until it has opened a frame from the
    /// typing side since its own last message of the pairing: its
    /// confirmation or, in a Person pairing, its key set.
    #[error("the session can't send until the other side has spoken")]
    AwaitingPeer,
}

/// Which end of the pairing a session belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionRole {
    Displaying,
    Typing,
}

/// A pairing's verified session. Obtained only from a completed exchange.
pub struct VerifiedSession {
    kind: PairingKind,
    /// The endpoint the exchange ran with: the only sender it listens to.
    peer: EndpointId,
    send_key: Secret<SESSION_KEY_BYTES>,
    receive_key: Secret<SESSION_KEY_BYTES>,
    next_send: u64,
    next_receive: u64,
    spoilt: bool,
    role: SessionRole,
    /// Whether the other side has shown it accepted everything this side
    /// sent to establish the session. True from the start on the typing
    /// side, which receives the last such message; on the displaying side,
    /// set by a frame opened (and, in a Person pairing, cleared again when
    /// it sends its key set, until the typing side's next frame). Shared
    /// with the displaying sheet, so its status can tell the two apart.
    peer_confirmed: Arc<AtomicBool>,
    peer_account: Option<AccountPublicKeys>,
}

fn nonce_for(sequence: u64) -> Nonce<aes_gcm::aes::cipher::consts::U12> {
    let mut nonce = [0u8; NONCE_PADDING_BYTES + SEQUENCE_BYTES];
    nonce[NONCE_PADDING_BYTES..].copy_from_slice(&sequence.to_be_bytes());
    Nonce::from(nonce)
}

fn frame_aad(sequence: u64) -> Vec<u8> {
    lv_cat(&[FRAME_LABEL, &[PROTOCOL_VERSION], &sequence.to_be_bytes()])
}

/// The cipher for one frame. Built, used and dropped within one call.
fn cipher(key: &Secret<SESSION_KEY_BYTES>) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key.as_bytes()).expect("a 32-byte key")
}

impl std::fmt::Debug for VerifiedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedSession")
            .field("kind", &self.kind)
            .field("peer_account", &self.peer_account)
            .finish_non_exhaustive()
    }
}

impl VerifiedSession {
    pub(crate) fn new(
        role: SessionRole,
        kind: PairingKind,
        peer: EndpointId,
        keys: SessionKeys,
    ) -> Self {
        let SessionKeys { send, receive } = keys;
        Self {
            kind,
            role,
            peer,
            send_key: send,
            receive_key: receive,
            next_send: 0,
            next_receive: 0,
            spoilt: false,
            peer_confirmed: Arc::new(AtomicBool::new(role == SessionRole::Typing)),
            peer_account: None,
        }
    }

    pub(crate) fn role(&self) -> SessionRole {
        self.role
    }

    /// The endpoint this session listens to.
    pub(crate) fn peer(&self) -> EndpointId {
        self.peer
    }

    /// Records the other account's keys, once its signed key set has been
    /// checked (Person pairings).
    pub(crate) fn set_peer_account(&mut self, keys: AccountPublicKeys) {
        self.peer_account = Some(keys);
    }

    /// The displaying side has just sent its key set (Person pairings): it
    /// can't tell whether the typing side accepted it until the typing side
    /// speaks again, so until then the session is back to not sending.
    pub(crate) fn await_peer_again(&self) {
        self.peer_confirmed.store(false, Ordering::Release);
    }

    #[must_use]
    pub fn kind(&self) -> PairingKind {
        self.kind
    }

    /// For a Person pairing, the other account's verified public keys.
    #[must_use]
    pub fn peer_account(&self) -> Option<AccountPublicKeys> {
        self.peer_account
    }

    /// Whether the other side is known to hold this session too. Always
    /// true on the typing side, which checks the displaying side's last
    /// message (its confirmation, or in a Person pairing its key set) before
    /// it has a session at all. On the displaying side it turns true when
    /// the first frame the client is handed from the typing side opens:
    /// until then it can't tell a typing side that accepted that last
    /// message from one that never received it, or refused it.
    #[must_use]
    pub fn peer_confirmed(&self) -> bool {
        self.peer_confirmed.load(Ordering::Acquire)
    }

    /// The flag behind [`Self::peer_confirmed`], for the displaying sheet.
    pub(crate) fn peer_confirmed_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.peer_confirmed)
    }

    /// Seals `payload` as the next frame to send.
    ///
    /// # Errors
    /// [`SessionError::AwaitingPeer`] on the displaying side while it waits
    /// to hear from the typing side (see the variant), [`SessionError::Exhausted`] once
    /// every sequence number is used, [`SessionError::FrameRejected`] if the
    /// session is spoilt, and [`SessionError::PayloadTooLarge`] if the
    /// payload is more than one frame can carry.
    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, SessionError> {
        if self.spoilt {
            return Err(SessionError::FrameRejected);
        }
        if !self.peer_confirmed() {
            return Err(SessionError::AwaitingPeer);
        }
        let sequence = self.next_send;
        let next = sequence.checked_add(1).ok_or(SessionError::Exhausted)?;
        let aad = frame_aad(sequence);
        let ciphertext = cipher(&self.send_key)
            .encrypt(
                &nonce_for(sequence),
                Payload {
                    msg: payload,
                    aad: &aad,
                },
            )
            .map_err(|_| SessionError::PayloadTooLarge)?;
        // The sequence number is spent only once a frame exists for it.
        self.next_send = next;
        let mut frame = Vec::with_capacity(TYPE_BYTES + SEQUENCE_BYTES + ciphertext.len());
        frame.push(MessageType::Frame as u8);
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Opens the next frame received, given the endpoint the transport
    /// authenticated as its sender. The plaintext is wiped when the caller
    /// drops it.
    ///
    /// # Errors
    /// [`SessionError::WrongSender`] for a message from any endpoint but the
    /// peer, and [`SessionError::NotAFrame`] for one that isn't a session
    /// frame: neither touches the session. [`SessionError::FrameRejected`]
    /// for a frame from the peer that is anything but the next in sequence,
    /// intact; after one such rejection the session refuses everything.
    pub fn open(
        &mut self,
        sender: EndpointId,
        frame: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        if sender != self.peer {
            return Err(SessionError::WrongSender);
        }
        let Some((&type_byte, body)) = frame.split_first() else {
            return Err(SessionError::NotAFrame);
        };
        if type_byte != MessageType::Frame as u8 {
            return Err(SessionError::NotAFrame);
        }
        let opened = self.try_open(body);
        if opened.is_err() {
            self.spoilt = true;
        }
        opened
    }

    fn try_open(&mut self, body: &[u8]) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        if self.spoilt || body.len() < SEQUENCE_BYTES {
            return Err(SessionError::FrameRejected);
        }
        let (sequence, ciphertext) = body.split_at(SEQUENCE_BYTES);
        let sequence = u64::from_be_bytes(sequence.try_into().expect("eight bytes"));
        if sequence != self.next_receive {
            return Err(SessionError::FrameRejected);
        }
        let aad = frame_aad(sequence);
        let plaintext = cipher(&self.receive_key)
            .decrypt(
                &nonce_for(sequence),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| SessionError::FrameRejected)?;
        self.next_receive = sequence.checked_add(1).ok_or(SessionError::FrameRejected)?;
        self.peer_confirmed.store(true, Ordering::Release);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TYPING: EndpointId = [0x71; 32];
    const DISPLAYING: EndpointId = [0xd1; 32];
    const STRANGER: EndpointId = [0x57; 32];

    /// (typing side's session, displaying side's session).
    fn pair() -> (VerifiedSession, VerifiedSession) {
        let type_to_display = Secret::copy_of(&[0xab; SESSION_KEY_BYTES]);
        let display_to_type = Secret::copy_of(&[0xba; SESSION_KEY_BYTES]);
        let typing = VerifiedSession::new(
            SessionRole::Typing,
            PairingKind::Device,
            DISPLAYING,
            SessionKeys {
                send: type_to_display.clone(),
                receive: display_to_type.clone(),
            },
        );
        let displaying = VerifiedSession::new(
            SessionRole::Displaying,
            PairingKind::Device,
            TYPING,
            SessionKeys {
                send: display_to_type,
                receive: type_to_display,
            },
        );
        (typing, displaying)
    }

    #[test]
    fn the_displaying_side_sends_only_after_hearing_from_the_typing_side() {
        let (mut typing, mut displaying) = pair();
        assert!(typing.peer_confirmed());
        assert!(!displaying.peer_confirmed());
        assert_eq!(
            displaying.seal(b"bundle").err(),
            Some(SessionError::AwaitingPeer)
        );
        let keys = typing.seal(b"device keys").unwrap();
        displaying.open(TYPING, &keys).unwrap();
        assert!(displaying.peer_confirmed());
        let bundle = displaying.seal(b"bundle").unwrap();
        assert_eq!(
            typing.open(DISPLAYING, &bundle).unwrap().as_slice(),
            b"bundle"
        );
    }

    #[test]
    fn a_rejected_frame_does_not_unlock_the_displaying_side() {
        let (_, mut displaying) = pair();
        let mut forged = vec![MessageType::Frame as u8];
        forged.extend_from_slice(&[0u8; 40]);
        assert_eq!(
            displaying.open(TYPING, &forged).err(),
            Some(SessionError::FrameRejected)
        );
        assert!(!displaying.peer_confirmed());
        assert_eq!(
            displaying.seal(b"bundle").err(),
            Some(SessionError::FrameRejected)
        );
    }

    #[test]
    fn frames_round_trip_in_order() {
        let (mut typing, mut displaying) = pair();
        for payload in [&b"first"[..], b"", b"third"] {
            let frame = typing.seal(payload).unwrap();
            assert_eq!(displaying.open(TYPING, &frame).unwrap().as_slice(), payload);
        }
    }

    #[test]
    fn replayed_reordered_and_tampered_frames_spoil_the_session() {
        let (mut typing, mut displaying) = pair();
        let first = typing.seal(b"first").unwrap();
        displaying.open(TYPING, &first).unwrap();
        assert_eq!(
            displaying.open(TYPING, &first).err(),
            Some(SessionError::FrameRejected)
        );
        // Spoilt now, even for the genuine next frame.
        let second = typing.seal(b"second").unwrap();
        assert_eq!(
            displaying.open(TYPING, &second).err(),
            Some(SessionError::FrameRejected)
        );

        let (mut typing, mut displaying) = pair();
        let _skipped = typing.seal(b"first").unwrap();
        let second = typing.seal(b"second").unwrap();
        assert_eq!(
            displaying.open(TYPING, &second).err(),
            Some(SessionError::FrameRejected)
        );

        let (mut typing, mut displaying) = pair();
        let mut frame = typing.seal(b"first").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 1;
        assert_eq!(
            displaying.open(TYPING, &frame).err(),
            Some(SessionError::FrameRejected)
        );
    }

    #[test]
    fn a_frame_sealed_for_one_direction_does_not_open_in_the_other() {
        let (mut typing, mut displaying) = pair();
        let frame = typing.seal(b"to the displaying side").unwrap();
        displaying.open(TYPING, &frame).unwrap();
        // Reflected back at its sender, as if from the peer.
        assert_eq!(
            typing.open(DISPLAYING, &frame).err(),
            Some(SessionError::FrameRejected)
        );
    }

    #[test]
    fn only_the_peer_can_spoil_a_session() {
        let (mut typing, mut displaying) = pair();
        let frame = typing.seal(b"device keys").unwrap();

        // A stranger's junk, and even a stranger's copy of the genuine
        // frame, bounce off without a trace.
        let mut junk = vec![MessageType::Frame as u8];
        junk.extend_from_slice(&[0u8; 40]);
        for message in [&junk, &frame] {
            assert_eq!(
                displaying.open(STRANGER, message).err(),
                Some(SessionError::WrongSender)
            );
        }
        // So do messages from the peer that aren't frames: a late or
        // duplicated exchange message, or nothing at all.
        for message in [
            &[MessageType::Confirm as u8; 65][..],
            &[MessageType::Refuse as u8, 1],
            &[],
        ] {
            assert_eq!(
                displaying.open(TYPING, message).err(),
                Some(SessionError::NotAFrame)
            );
        }
        assert!(!displaying.peer_confirmed());
        // The session is untouched: the genuine frame still opens.
        assert_eq!(
            displaying.open(TYPING, &frame).unwrap().as_slice(),
            b"device keys"
        );
    }

    #[test]
    fn a_session_that_has_used_every_sequence_number_seals_nothing_more() {
        // The sequence number is the nonce: it must run out, never wrap.
        let (mut typing, _) = pair();
        typing.next_send = u64::MAX;
        assert_eq!(typing.seal(b"x").err(), Some(SessionError::Exhausted));
        assert_eq!(typing.next_send, u64::MAX);
        assert_eq!(typing.seal(b"x").err(), Some(SessionError::Exhausted));
    }

    #[test]
    fn a_frame_numbered_past_the_last_sequence_number_is_rejected() {
        let (mut typing, mut displaying) = pair();
        typing.next_send = u64::MAX - 1;
        displaying.next_receive = u64::MAX - 1;
        let last = typing.seal(b"last").unwrap();
        assert_eq!(displaying.open(TYPING, &last).unwrap().as_slice(), b"last");
        // A sender that wrapped back to sequence zero is refused: the
        // receiver's counter doesn't wrap with it.
        assert_eq!(displaying.next_receive, u64::MAX);
        typing.next_send = 0;
        let wrapped = typing.seal(b"again").unwrap();
        assert_eq!(
            displaying.open(TYPING, &wrapped).err(),
            Some(SessionError::FrameRejected)
        );
    }

    /// The encrypt-failure path proper needs a payload too large to build
    /// in a test (64 GiB); this covers the refusals that are reachable.
    #[test]
    fn a_refused_seal_spends_no_sequence_number() {
        let (mut typing, mut displaying) = pair();
        typing.spoilt = true;
        assert!(typing.seal(b"x").is_err());
        typing.spoilt = false;
        let frame = typing.seal(b"first").unwrap();
        assert_eq!(
            displaying.open(TYPING, &frame).unwrap().as_slice(),
            b"first"
        );
    }
}
